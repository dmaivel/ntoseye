//! [`Image`], a PE image mapped in guest memory together with the handles
//! that read it and resolve its symbols and types, and [`SymbolRef`].

use crate::arch::Arch;
use crate::{
    backend::phys::PhysMem,
    base::{
        error::{Error, Result},
        memory::{AddressSpace, MemoryOps},
        types::*,
    },
    nt::{
        layout::Types,
        pe::{
            HeaderPage, PeImage, headers::decode_headers, read_pe_header_page, read_pe_image,
            size_of_image,
        },
        symbols::SymbolStore,
    },
};
use pelite::PeView;
use std::ops::Range;
use std::sync::{Arc, Mutex, PoisonError};
use zerocopy::{FromBytes, IntoBytes};

pub struct SymbolRef<'a> {
    obj: &'a Image,
    rva: u32,
}

impl SymbolRef<'_> {
    pub fn address(&self) -> VirtAddr {
        self.obj.address_of(self.rva)
    }

    pub fn read<T>(&self) -> Result<T>
    where
        T: IntoBytes + FromBytes + Copy,
    {
        self.obj.memory().read(self.address())
    }

    /// The kernel pointer the symbol holds (a pointer-typed global).
    pub fn read_pointer(&self) -> Result<VirtAddr> {
        self.obj.memory().read_pointer(self.address())
    }
}

/// A PE image mapped into guest memory: ntoskrnl, a driver, or a user-mode
/// EXE/DLL. It carries the address space it is mapped in (`dtb`) and the
/// handles needed to read it and resolve its symbols and types, so navigation
/// methods don't take them as arguments. The handles are shared (`Arc`), not
/// borrowed; an `Image` can't borrow its `Target` siblings, but it can own
/// a refcounted handle to them.
pub struct Image {
    pub base_address: VirtAddr,
    dtb: Dtb,
    arch: Arch,
    /// AArch64 TTBR1 (kernel-space root). Equal to `dtb` for the kernel object
    /// and AMD64; process siblings keep the kernel root for kernel-VA reads.
    kernel_dtb: Dtb,
    /// Header page read at symbol load; nothing from the sections.
    headers: Option<Box<HeaderPage>>,
    /// Demand-read image shared across stack traces, so each block is
    /// fetched once per session.
    image: Mutex<Option<Arc<PeImage>>>,
    pub guid: Option<u128>,
    pub(super) phys: Arc<PhysMem>,
    symbols: Arc<SymbolStore>,
}

impl Image {
    pub fn new(
        phys: Arc<PhysMem>,
        symbols: Arc<SymbolStore>,
        dtb: Dtb,
        base_address: VirtAddr,
        arch: Arch,
    ) -> Self {
        Self {
            base_address,
            dtb,
            arch,
            kernel_dtb: dtb,
            headers: None,
            image: Mutex::new(None),
            guid: None,
            phys,
            symbols,
        }
    }

    pub fn arch(&self) -> Arch {
        self.arch
    }

    /// Where the PTE self-map starts: `MmPteBase`, or on AMD64 kernels
    /// without it (before Windows 10 1607 randomized the self-map) the
    /// fixed base, `0xfffff68000000000`.
    pub fn pte_base(&self) -> Result<VirtAddr> {
        const AMD64_FIXED_PTE_BASE: VirtAddr = VirtAddr(0xffff_f680_0000_0000);
        match self.symbol("MmPteBase") {
            Ok(symbol) => symbol.read_pointer(),
            Err(_) if self.arch == Arch::Amd64 => Ok(AMD64_FIXED_PTE_BASE),
            Err(error) => Err(error),
        }
    }

    pub fn load_symbols(mut self) -> Result<Self> {
        let symbols = Arc::clone(&self.symbols);
        self.guid = symbols.load_from_binary(&mut self, "ntoskrnl.exe")?;
        Ok(self)
    }

    /// Fallback symbol loader for triage dumps where the PE header page isn't
    /// in the dump.  Uses the module's TimeDateStamp + SizeOfImage from the
    /// triage driver list to download the PE from Microsoft's symbol server,
    /// extract the PDB GUID, and load the PDB.
    pub fn load_symbols_from_module_info(
        mut self,
        name: &str,
        time_date_stamp: u32,
        size_of_image: u32,
    ) -> Result<Self> {
        let symbols = Arc::clone(&self.symbols);
        self.guid = symbols.load_from_module_info(
            name,
            self.base_address,
            self.dtb,
            time_date_stamp,
            size_of_image,
        )?;
        Ok(self)
    }

    pub fn dtb(&self) -> Dtb {
        self.dtb
    }

    /// Mark this object's module as the kernel in the shared symbol store:
    /// type/enum layout lookups prefer it, and its address space is visible
    /// from every process. Call after [`load_symbols`](Self::load_symbols) so
    /// `guid` is populated.
    pub fn register_as_kernel(&self) {
        self.symbols.set_kernel(self.guid, self.dtb);
    }

    /// `SizeOfImage` of the module (0 until [`view`](Self::view) has run).
    pub fn binary_size(&self) -> usize {
        self.headers
            .as_deref()
            .and_then(|headers| PeView::from_bytes(headers).ok())
            .map_or(0, |view| size_of_image(&view) as usize)
    }

    pub fn address_of(&self, rva: impl Into<u64>) -> VirtAddr {
        self.base_address + rva.into()
    }

    /// The addresses the section named `name` is mapped at, from the header
    /// page read at symbol load, or else from the mapped image's own. `None`
    /// when the image has no such section or its headers cannot be read.
    pub fn section_range(&self, name: &str) -> Option<Range<VirtAddr>> {
        let image;
        let headers = match self.headers.as_deref() {
            Some(headers) => headers.as_ref(),
            None => {
                image = self.image()?;
                image.headers()
            }
        };
        let section = decode_headers(headers)
            .ok()?
            .sections
            .into_iter()
            .find(|section| section.name == name)?;
        let start = u64::from(section.virtual_address);
        Some(self.address_of(start)..self.address_of(start + u64::from(section.virtual_size)))
    }

    pub fn memory(&self) -> AddressSpace<'_, Arc<PhysMem>> {
        self.memory_in(self.dtb)
    }

    /// Like [`memory`](Self::memory), but rooted at `dtb`: another process's
    /// space, keeping this object's architecture and kernel root.
    pub fn memory_in(&self, dtb: Dtb) -> AddressSpace<'_, Arc<PhysMem>> {
        AddressSpace::for_arch(&self.phys, dtb, self.kernel_dtb, self.arch)
    }

    pub fn symbol<S>(&self, name: S) -> Result<SymbolRef<'_>>
    where
        S: Into<String>,
    {
        let name = name.into();

        let guid = self.guid.ok_or(Error::ExpectedSymbols)?;
        let rva = self
            .symbols
            .symbol_rva(guid, &name)?
            .ok_or(Error::SymbolNotFound(name))?;
        Ok(SymbolRef { obj: self, rva })
    }

    /// The module's headers, read once from guest memory. Directories past
    /// the headers are not in the view; see [`image`](Self::image) for those.
    pub fn view(&mut self) -> Option<PeView<'_>> {
        if self.headers.is_none() {
            let headers = read_pe_header_page(self.base_address, &self.memory()).ok()?;
            self.headers = Some(Box::new(headers));
        }

        PeView::from_bytes(self.headers.as_deref()?).ok()
    }

    /// The in-memory image (see [`read_pe_image`]), opened on first use and
    /// shared afterwards. `None` when the headers are unreadable; that is
    /// retried next time rather than cached.
    pub fn image(&self) -> Option<Arc<PeImage>> {
        let mut cached = self.image.lock().unwrap_or_else(PoisonError::into_inner);
        if cached.is_none() {
            let image = self.read_image().ok()?;
            *cached = Some(Arc::new(image));
        }
        cached.clone()
    }

    /// Read the mapped PE image in this object's address space.
    pub fn read_image(&self) -> Result<PeImage> {
        let (phys, dtb, kernel_dtb, arch) =
            (Arc::clone(&self.phys), self.dtb, self.kernel_dtb, self.arch);
        read_pe_image(self.base_address, move |address, buf| {
            AddressSpace::for_arch(&phys, dtb, kernel_dtb, arch).read_bytes(address, buf)
        })
    }

    /// Resolve this object's struct/type namespace, read in its own address
    /// space. Use [`types_in`](Self::types_in) to read the same types from a
    /// different `dtb` (e.g. ntoskrnl's kernel types against a process's space).
    /// The symbol store the image's symbols load into.
    pub fn symbols(&self) -> &Arc<SymbolStore> {
        &self.symbols
    }

    pub fn types(&self) -> Types<'_> {
        self.types_in(self.dtb)
    }

    /// Like [`types`](Self::types), but reads against `dtb` instead of this
    /// object's own, for kernel types navigated through a process's space.
    pub fn types_in(&self, dtb: Dtb) -> Types<'_> {
        Types::new(
            &self.symbols,
            self.guid,
            &self.phys,
            self.arch,
            self.kernel_dtb,
            dtb,
        )
    }
}
