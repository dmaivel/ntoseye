//! Host-side VTL1 discovery. VTL0's physical-memory service cannot read these
//! pages. Walk actual host RAM, never an NT-provided physical-memory map.

use std::collections::HashSet;
use std::sync::{
    Arc, PoisonError,
    atomic::{AtomicBool, Ordering},
};

use super::{
    Guest, Image, ModuleInfo,
    modules::module_info_from_record,
    trustlet_layout::{MAX_FUNCTION_BYTES, TrustletLayout},
};
use crate::{
    backend::MemoryOps,
    error::{Error, Result},
    memory::{AddressSpace, PAGE_SIZE, PFN_MASK},
    phys::PhysMem,
    symbols::SymbolStore,
    target::bounded_list_walk,
    types::{Arch, Dtb, PhysAddr, VirtAddr},
};

const NX: u64 = 1 << 63;
const SCAN_BYTES: usize = 2 * 1024 * 1024;
const MAX_ROOTS: usize = 4096;
const MAX_TABLES: usize = 16384;
const MAX_PROBES: usize = 1_048_576;

pub struct SecureKernel {
    pub image: Image,
    header_physical: PhysAddr,
}

#[derive(Debug, Clone)]
pub struct TrustletInfo {
    pub process: VirtAddr,
    pub pid: u64,
    pub name: String,
    pub dtb: Dtb,
    pub trustlet_id: u64,
}

fn interrupted(flag: &AtomicBool) -> Result<()> {
    if flag.load(Ordering::Relaxed) {
        Err(Error::SecureKernel("discovery interrupted".to_string()))
    } else {
        Ok(())
    }
}

fn entry(bytes: &[u8], index: usize) -> u64 {
    u64::from_le_bytes(bytes[index * 8..index * 8 + 8].try_into().unwrap())
}

fn self_map(page: &[u8], address: u64) -> Option<usize> {
    let mut found = None;
    for index in 256..512 {
        let value = entry(page, index);
        if value & 1 != 0 && value & PFN_MASK == address {
            if found.is_some() {
                return None;
            }
            found = Some(index);
        }
    }
    found
}

/// A bounded executable-ancestor walk. Header leaf pages can themselves be
/// NX, but no ancestor of the image's code can be. This excludes enormous
/// sparse data/self-map windows without discarding PE header pages.
struct ImageSearch<'a, B: MemoryOps<PhysAddr>> {
    phys: &'a B,
    memory: AddressSpace<'a, B>,
    interrupt: &'a AtomicBool,
    tables: usize,
    probes: usize,
}

impl<B: MemoryOps<PhysAddr>> ImageSearch<'_, B> {
    fn probe(&mut self, va: u64, pa: u64) -> Result<Option<VirtAddr>> {
        self.probes += 1;
        if self.probes > MAX_PROBES {
            return Err(Error::SecureKernel(
                "image search exceeded its page bound".to_string(),
            ));
        }
        if self.probes.is_multiple_of(1024) {
            interrupted(self.interrupt)?;
        }
        let mut mz = [0u8; 2];
        if self.phys.read_bytes(pa, &mut mz).is_err() || mz != *b"MZ" {
            return Ok(None);
        }
        let base = VirtAddr(va);
        let named = SymbolStore::codeview_pdb_path(&self.memory, base)
            .ok()
            .flatten()
            .is_some_and(|path| {
                path.rsplit(['\\', '/'])
                    .next()
                    .is_some_and(|name| name.eq_ignore_ascii_case("securekernel.pdb"))
            });
        Ok(named.then_some(base))
    }

    fn walk(&mut self, table: u64, level: u8, prefix: u64) -> Result<Option<VirtAddr>> {
        interrupted(self.interrupt)?;
        self.tables += 1;
        if self.tables > MAX_TABLES {
            return Err(Error::SecureKernel(
                "image search exceeded its table bound".to_string(),
            ));
        }
        let mut page = [0u8; PAGE_SIZE];
        if self.phys.read_bytes(table, &mut page).is_err() {
            return Ok(None);
        }
        let first = if level == 4 { 256 } else { 0 };
        for index in first..512 {
            let value = entry(&page, index);
            if value & 1 == 0 || (level > 1 && value & NX != 0) {
                continue;
            }
            let shift = 12 + 9 * (u32::from(level) - 1);
            let va = prefix | ((index as u64) << shift);
            let va = if level == 4 {
                va | 0xffff_0000_0000_0000
            } else {
                va
            };
            let pa = value & PFN_MASK;
            if level == 1 {
                if let Some(base) = self.probe(va, pa)? {
                    return Ok(Some(base));
                }
            } else if level < 4 && value & 0x80 != 0 {
                let size = 1u64 << shift;
                let pa = pa & !(size - 1);
                for offset in (0..size).step_by(PAGE_SIZE) {
                    if let Some(base) = self.probe(va + offset, pa + offset)? {
                        return Ok(Some(base));
                    }
                }
            } else if let Some(base) = self.walk(pa, level - 1, va)? {
                return Ok(Some(base));
            }
        }
        Ok(None)
    }
}

fn discover(
    phys: &PhysMem,
    nt_dtb: Dtb,
    nt_base: VirtAddr,
    interrupt: &AtomicBool,
) -> Result<(Dtb, VirtAddr)> {
    let runs = phys.ram_runs();
    if runs.is_empty() {
        return Err(Error::SecureKernel(
            "direct host RAM is required; KD-only memory and NT dumps do not expose VTL1"
                .to_string(),
        ));
    }
    let nt_header = AddressSpace::new(phys, nt_dtb)
        .virt_to_phys(nt_base)?
        .map(|translation| translation.address);
    let mut chunk = vec![0u8; SCAN_BYTES];
    let mut roots = Vec::new();
    // Roots that map NT's image are almost certainly NT process roots. Try
    // them only after the rest of RAM, rather than excluding them outright:
    // nothing guarantees VTL1 never maps that VA to the same frame.
    let mut nt_like = Vec::new();
    // The same upper-half PML4 entries recur in every process. Only try each
    // distinct set once (ignore access/dirty bits and the self reference).
    let mut tried = HashSet::new();
    for (start, length) in runs {
        let end = start.checked_add(length).ok_or(Error::InvalidRange)?;
        let mut address = start;
        while address < end {
            interrupted(interrupt)?;
            let count = usize::try_from((end - address).min(SCAN_BYTES as u64)).unwrap();
            phys.read_bytes(address, &mut chunk[..count])?;
            for (offset, page) in chunk[..count].as_chunks::<PAGE_SIZE>().0.iter().enumerate() {
                let dtb = address + (offset * PAGE_SIZE) as u64;
                let Some(slot) = self_map(page, dtb) else {
                    continue;
                };
                let mut key = [0u64; 256];
                for (i, value) in key.iter_mut().enumerate() {
                    let raw = entry(page, i + 256);
                    if i + 256 != slot && raw & 1 != 0 {
                        *value = raw & !0x60;
                    }
                }
                if !tried.insert(key) {
                    continue;
                }
                // SK and NT may randomly choose the same self-map slot; the
                // slot number alone is not an address-space identity.
                let maps_nt = nt_header.is_some()
                    && AddressSpace::new(phys, dtb)
                        .virt_to_phys(nt_base)
                        .ok()
                        .flatten()
                        .map(|t| t.address)
                        == nt_header;
                if maps_nt {
                    nt_like.push(dtb);
                } else {
                    roots.push(dtb);
                }
            }
            // Try new roots after each bulk read: boot-time roots tend to be
            // low in RAM, so a successful attach need not scan the entire VM.
            if let Some(found) = search_roots(phys, roots.drain(..), interrupt)? {
                return Ok(found);
            }
            if tried.len() >= MAX_ROOTS {
                return Err(Error::SecureKernel(
                    "too many distinct page-table candidates".to_string(),
                ));
            }
            address += count as u64;
        }
    }
    if let Some(found) = search_roots(phys, nt_like.into_iter(), interrupt)? {
        return Ok(found);
    }
    Err(Error::SecureKernel(
        "securekernel.exe not found in host RAM; VBS may not be running".to_string(),
    ))
}

fn search_roots(
    phys: &PhysMem,
    roots: impl Iterator<Item = Dtb>,
    interrupt: &AtomicBool,
) -> Result<Option<(Dtb, VirtAddr)>> {
    for dtb in roots {
        let mut search = ImageSearch {
            phys,
            memory: AddressSpace::new(phys, dtb),
            interrupt,
            tables: 0,
            probes: 0,
        };
        match search.walk(dtb, 4, 0) {
            Ok(Some(base)) => return Ok(Some((dtb, base))),
            Ok(None) => {}
            Err(error) if interrupt.load(Ordering::Relaxed) => return Err(error),
            // A candidate can be a non-SK root with vast mappings.
            Err(_) => {}
        }
    }
    Ok(None)
}

impl SecureKernel {
    fn load(
        phys: Arc<PhysMem>,
        symbols: Arc<SymbolStore>,
        nt_dtb: Dtb,
        nt_base: VirtAddr,
        interrupt: &AtomicBool,
    ) -> Result<Self> {
        let (root, base) = discover(&phys, nt_dtb, nt_base, interrupt)?;
        let mut image = Image::new(
            Arc::clone(&phys),
            Arc::clone(&symbols),
            root,
            base,
            Arch::Amd64,
        );
        image.guid = symbols.load_from_binary(&mut image, "securekernel.exe")?;
        let system = image
            .symbol("SkpsSystemDirectoryTableBase")?
            .read::<u64>()?
            & PFN_MASK;
        let translation = image
            .memory()
            .virt_to_phys(base)?
            .ok_or(Error::BadVirtualAddress(base))?;
        // Loader roots can retain an alias of the live image. SK records its
        // relocated canonical base, which must identify the same header page.
        let canonical_base = image.symbol("SkImageBase")?.read::<VirtAddr>()?;
        let canonical = AddressSpace::new(phys.as_ref(), system).virt_to_phys(canonical_base)?;
        if canonical.is_none_or(|t| t.address != translation.address) {
            return Err(Error::SecureKernel(format!(
                "system root {system:#x} does not map image {base:?} found under {root:#x} at PA {:#x}",
                translation.address
            )));
        }
        if root != system || base != canonical_base {
            symbols.invalidate_modules(root, &[base]);
            image = Image::new(
                phys,
                Arc::clone(&symbols),
                system,
                canonical_base,
                Arch::Amd64,
            );
            image.guid = symbols.load_from_binary(&mut image, "securekernel.exe")?;
        }
        symbols.set_secure_roots(system, []);
        Ok(Self {
            image,
            header_physical: translation.address,
        })
    }

    pub fn modules(&self, guest: &Guest) -> Result<Vec<ModuleInfo>> {
        let head = self.image.symbol("SkLoadedModuleList")?.address();
        let types = guest.ntoskrnl.types_in(self.image.dtb());
        let layout = types.layout("_KLDR_DATA_TABLE_ENTRY")?;
        let link_offset = layout.field_offset("InLoadOrderLinks")?;
        let memory = self.image.memory();
        let (links, termination) = bounded_list_walk(head, 1024, |address| memory.read(address));
        if let Some(reason) = termination.diagnostic() {
            return Err(Error::SecureKernel(reason));
        }
        let mut modules = Vec::with_capacity(links.len());
        for link in links {
            let address = VirtAddr(link.0.checked_sub(link_offset).ok_or(Error::InvalidRange)?);
            let record = types
                .struct_with_layout(Arc::clone(&layout), address)
                .prefetch();
            if let Some(module) = module_info_from_record(&record)? {
                modules.push(module);
            }
        }
        if !modules.iter().any(|m| {
            m.base_address == self.image.base_address
                && m.name.eq_ignore_ascii_case("securekernel.exe")
        }) {
            return Err(Error::SecureKernel(
                "module layout did not identify the secure kernel".to_string(),
            ));
        }
        Ok(modules)
    }

    /// A function's leading bytes, up to the first unreadable page.
    fn function_code(&self, name: &str) -> Result<(Vec<u8>, u64)> {
        let start = self.image.symbol(name)?.address();
        let memory = self.image.memory();
        let mut code = vec![0; MAX_FUNCTION_BYTES];
        let mut read = 0;
        while read < code.len() {
            let address = start + read as u64;
            let chunk = (PAGE_SIZE - (address.0 as usize & (PAGE_SIZE - 1))).min(code.len() - read);
            if memory
                .read_bytes(address, &mut code[read..read + chunk])
                .is_err()
            {
                break;
            }
            read += chunk;
        }
        if read == 0 {
            return Err(Error::BadVirtualAddress(start));
        }
        code.truncate(read);
        Ok((code, start.0))
    }

    /// Public SK PDBs omit the process type; recover the fields from the
    /// code that creates processes and switches to their address spaces.
    fn trustlet_layout(&self) -> Result<TrustletLayout> {
        let (select, select_ip) = self.function_code("SkeSelectProcessAddressSpace")?;
        let (initialize, initialize_ip) = self.function_code("SkpsInitializeProcess")?;
        let list = self.image.symbol("SkpsProcessList")?.address();
        TrustletLayout::derive((&select, select_ip), (&initialize, initialize_ip), list.0)
    }

    pub fn trustlets(&self, guest: &Guest) -> Result<Vec<TrustletInfo>> {
        let layout = self.trustlet_layout()?;
        let memory = self.image.memory();
        let system = self
            .image
            .symbol("PsIumSystemProcess")?
            .read::<VirtAddr>()?;
        if memory.read::<u64>(system + layout.dtb)? & PFN_MASK != self.image.dtb() {
            return Err(Error::SecureKernel(
                "system-process layout validation failed".to_string(),
            ));
        }
        let processes = guest.enumerate_processes()?;
        let head = self.image.symbol("SkpsProcessList")?.address();
        let (links, termination) = bounded_list_walk(head, 1024, |address| memory.read(address));
        if let Some(reason) = termination.diagnostic() {
            return Err(Error::SecureKernel(reason));
        }
        let mut result = Vec::with_capacity(links.len());
        let mut previous = head;
        for link in links {
            if memory.read::<VirtAddr>(link + 8u64)? != previous {
                return Err(Error::SecureKernel(
                    "trustlet list changed or has invalid backward links".to_string(),
                ));
            }
            previous = link;
            let process = VirtAddr(
                link.0
                    .checked_sub(layout.links)
                    .ok_or(Error::InvalidRange)?,
            );
            let pid: u64 = memory.read(process + layout.pid)?;
            let dtb = memory.read::<u64>(process + layout.dtb)? & PFN_MASK;
            let nt = processes.iter().find(|p| p.pid == pid).ok_or_else(|| {
                Error::SecureKernel("trustlet PID is not in the NT process list".to_string())
            })?;
            let root = AddressSpace::new(self.image.phys.as_ref(), dtb);
            if root
                .virt_to_phys(self.image.base_address)?
                .is_none_or(|t| t.address != self.header_physical)
            {
                return Err(Error::SecureKernel(
                    "trustlet root does not map the secure kernel".to_string(),
                ));
            }
            result.push(TrustletInfo {
                process,
                pid,
                dtb,
                name: nt.name.clone(),
                trustlet_id: memory.read(process + layout.trustlet_id)?,
            });
        }
        if memory.read::<VirtAddr>(head + 8u64)? != previous {
            return Err(Error::SecureKernel(
                "trustlet list tail changed during enumeration".to_string(),
            ));
        }
        Ok(result)
    }
}

impl Guest {
    pub fn cached_secure_kernel(&self) -> Option<Arc<SecureKernel>> {
        self.secure_kernel
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn secure_kernel(
        &self,
        phys: &Arc<PhysMem>,
        symbols: &Arc<SymbolStore>,
        interrupt: &AtomicBool,
    ) -> Result<Arc<SecureKernel>> {
        if self.ntoskrnl.arch() != Arch::Amd64 {
            return Err(Error::SecureKernel(
                "discovery currently requires AMD64".to_string(),
            ));
        }
        let mut cached = self
            .secure_kernel
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(secure) = cached.as_ref() {
            // A passive backend cannot observe reboot notifications. Reject a
            // stale scope instead of silently reading another boot's pages.
            let root = secure
                .image
                .symbol("SkpsSystemDirectoryTableBase")?
                .read::<u64>()?
                & PFN_MASK;
            if root != secure.image.dtb()
                || secure
                    .image
                    .memory()
                    .read::<u16>(secure.image.base_address)?
                    != 0x5a4d
            {
                return Err(Error::SecureKernel(
                    "secure kernel changed since discovery (guest rebooted?); restart the session to rediscover it"
                        .to_string(),
                ));
            }
            return Ok(Arc::clone(secure));
        }
        // NT records whether VSM started. Scanning all of RAM for a kernel
        // that never loaded takes seconds; kernels without the symbol scan.
        if let Ok(enabled) = self.ntoskrnl.symbol("VslVsmEnabled")
            && enabled.read::<u8>().is_ok_and(|value| value == 0)
        {
            return Err(Error::SecureKernel(
                "VBS is not running in the guest (nt!VslVsmEnabled is 0)".to_string(),
            ));
        }
        let secure = Arc::new(SecureKernel::load(
            Arc::clone(phys),
            Arc::clone(symbols),
            self.ntoskrnl.dtb(),
            self.ntoskrnl.base_address,
            interrupt,
        )?);
        *cached = Some(Arc::clone(&secure));
        Ok(secure)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Ram(Vec<u8>);
    impl MemoryOps<PhysAddr> for Ram {
        fn read_bytes(&self, address: PhysAddr, output: &mut [u8]) -> Result<()> {
            let start = usize::try_from(address).map_err(|_| Error::InvalidRange)?;
            let end = start.checked_add(output.len()).ok_or(Error::InvalidRange)?;
            output.copy_from_slice(self.0.get(start..end).ok_or(Error::InvalidRange)?);
            Ok(())
        }
        fn write_bytes(&self, _: PhysAddr, _: &[u8]) -> Result<()> {
            unreachable!()
        }
    }

    fn image_ram() -> Ram {
        let mut bytes = vec![0u8; 0x6000];
        for (offset, value) in [
            (0x1000 + 496 * 8, 0x2003u64),
            (0x2000, 0x3003),
            (0x3000, 0x4003),
            (0x4000 + 3 * 8, 0x5003 | NX),
        ] {
            bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        let image = &mut bytes[0x5000..];
        image[..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        image[0x80..0x84].copy_from_slice(b"PE\0\0");
        image[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        image[0x94..0x96].copy_from_slice(&240u16.to_le_bytes());
        image[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
        image[0x104..0x108].copy_from_slice(&16u32.to_le_bytes());
        image[0x138..0x13c].copy_from_slice(&0x300u32.to_le_bytes());
        image[0x13c..0x140].copy_from_slice(&28u32.to_le_bytes());
        image[0x30c..0x310].copy_from_slice(&2u32.to_le_bytes());
        image[0x310..0x314].copy_from_slice(&41u32.to_le_bytes());
        image[0x314..0x318].copy_from_slice(&0x340u32.to_le_bytes());
        image[0x340..0x344].copy_from_slice(b"RSDS");
        image[0x358..0x369].copy_from_slice(b"securekernel.pdb\0");
        Ram(bytes)
    }

    #[test]
    fn discovery_accepts_nx_headers_but_not_nx_ancestors_or_other_images() {
        let mut ram = image_ram();
        let interrupt = AtomicBool::new(false);
        let search = |ram: &Ram| {
            ImageSearch {
                phys: ram,
                memory: AddressSpace::new(ram, 0x1000),
                interrupt: &interrupt,
                tables: 0,
                probes: 0,
            }
            .walk(0x1000, 4, 0)
        };
        assert_eq!(search(&ram).unwrap(), Some(VirtAddr(0xffff_f800_0000_3000)));
        ram.0[0x53_58] = b'x';
        assert_eq!(search(&ram).unwrap(), None);
        ram.0[0x53_58] = b's';
        ram.0[0x2007] |= 0x80;
        assert_eq!(search(&ram).unwrap(), None);
        interrupt.store(true, Ordering::Relaxed);
        assert!(matches!(search(&ram), Err(Error::SecureKernel(_))));
    }
}
