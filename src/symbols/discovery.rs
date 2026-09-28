//! Finding a module's PDB: CodeView records read from guest memory or an image
//! file, download jobs built from them, and loading the PDB they name.

use super::cache::ModuleIdentity;
use super::download::download_job;
use super::{
    DownloadJob, LoadedModule, ModuleSymbolDiscovery, ModuleSymbolLoad, ModuleSymbolSource,
    ModuleSymbolStatus, PdbIdentity, SymbolStore,
};
use crate::{
    backend::MemoryOps,
    error::{Error, Result},
    guest::{Image, ModuleInfo},
    memory,
    pe::{
        headers::{self, DebugDirectoryEntry, read_debug_directory},
        read_pe_header_page, size_of_image,
    },
    types::{Arch, Dtb, PhysAddr, VirtAddr},
};
use dashmap::mapref::entry::Entry;
use indicatif::ProgressBar;
use memmap2::Mmap;
use pdb2::{FallibleIterator, TypeData};
use pelite::{
    PeFile, PeView, Wrap,
    image::{GUID, IMAGE_DIRECTORY_ENTRY_DEBUG},
    pe64::debug::CodeView,
};
use std::{
    borrow::Cow,
    fs::File,
    io::Cursor,
    path::Path,
    sync::{Arc, atomic::Ordering},
};

fn guid_to_u128(guid: GUID) -> u128 {
    let mut bytes = [0u8; 16];
    bytes[0..4].copy_from_slice(&guid.Data1.to_be_bytes());
    bytes[4..6].copy_from_slice(&guid.Data2.to_be_bytes());
    bytes[6..8].copy_from_slice(&guid.Data3.to_be_bytes());
    bytes[8..16].copy_from_slice(&guid.Data4);
    u128::from_be_bytes(bytes)
}

/// The pointer width a PDB's own pointer records state, for one whose DBI
/// header names no machine: the x86 ntdll WOW64 runs on ARM64 Windows is
/// such a build, and taken as 64-bit its nested 32-bit layouts come out
/// wrong. 8 when no record says.
fn pointer_size_from_types(pdb: &mut pdb2::PDB<'static, Cursor<&'static [u8]>>) -> u8 {
    let Ok(types) = pdb.type_information() else {
        return 8;
    };
    let mut iter = types.iter();
    while let Ok(Some(item)) = iter.next() {
        if let Ok(TypeData::Pointer(pointer)) = item.parse()
            && matches!(pointer.attributes.size(), 4 | 8)
        {
            return pointer.attributes.size();
        }
    }
    8
}

impl SymbolStore {
    fn read_debug_directory_location<B: MemoryOps<PhysAddr>>(
        memory: &memory::AddressSpace<'_, B>,
        base_address: VirtAddr,
    ) -> Result<Option<(u32, u32)>> {
        let header_buf = read_pe_header_page(base_address, memory)?;
        let view = PeView::from_bytes(&header_buf)?;
        Ok(view
            .data_directory()
            .get(IMAGE_DIRECTORY_ENTRY_DEBUG)
            .map(|entry| (entry.VirtualAddress, entry.Size)))
    }

    /// Reads `len` bytes at an RVA of the image mapped at `base_address`, for
    /// [`read_debug_directory`].
    fn image_reader<'m, B: MemoryOps<PhysAddr>>(
        memory: &'m memory::AddressSpace<'_, B>,
        base_address: VirtAddr,
    ) -> impl Fn(u32, usize, &str) -> Result<Cow<'static, [u8]>> + 'm {
        move |rva, len, _| {
            let mut bytes = vec![0u8; len];
            memory.read_bytes(base_address + u64::from(rva), &mut bytes)?;
            Ok(Cow::Owned(bytes))
        }
    }

    /// The debug directory entries of the image mapped at `base_address`.
    fn read_debug_entries<B: MemoryOps<PhysAddr>>(
        memory: &memory::AddressSpace<'_, B>,
        base_address: VirtAddr,
    ) -> Result<Vec<DebugDirectoryEntry>> {
        match Self::read_debug_directory_location(memory, base_address)? {
            Some((rva, size)) => {
                read_debug_directory(rva, size, Self::image_reader(memory, base_address))
            }
            None => Ok(Vec::new()),
        }
    }

    /// The PDB path in the RSDS CodeView record of the image mapped at
    /// `base_address`, or `None` when it carries none. Identifies an image by
    /// what it was built as, whatever the loader called it.
    pub fn codeview_pdb_path<B: MemoryOps<PhysAddr>>(
        memory: &memory::AddressSpace<'_, B>,
        base_address: VirtAddr,
    ) -> Result<Option<String>> {
        let read = Self::image_reader(memory, base_address);
        let entries = Self::read_debug_entries(memory, base_address)?;
        Ok(entries
            .iter()
            .find_map(|entry| match entry.read_codeview(&read) {
                Some(Ok(headers::CodeView::Rsds { path, .. })) => Some(path),
                _ => None,
            }))
    }

    pub fn read_c_string_lossy(bytes: &[u8]) -> String {
        let nul = bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.len());
        String::from_utf8_lossy(&bytes[..nul]).into_owned()
    }

    pub fn load_from_binary(&self, object: &mut Image, name: &str) -> Result<Option<u128>> {
        let view = object.view().ok_or(Error::ViewFailed)?;
        if name.eq_ignore_ascii_case("ntoskrnl.exe")
            && !matches!(view.file_header().Machine, 0x8664 | 0xaa64)
        {
            return Err(Error::UnsupportedArchitecture(format!(
                "kernel image {} (machine {:#06x})",
                name,
                view.file_header().Machine
            )));
        }

        if let Some((job, guid)) =
            self.extract_download_job_from_memory(&object.memory(), object.base_address)?
        {
            download_job(&job, ProgressBar::new(0))?;
            self.ensure_pdb_loaded(job.expected_identity().unwrap(), &job.path)?;

            let module_key = Self::module_key(object.dtb(), object.base_address);
            if !self.modules.contains_key(&module_key) {
                self.modules.insert(
                    module_key,
                    LoadedModule {
                        name: name.to_string(),
                        short_name: ModuleInfo::derive_short_name(name),
                        guid,
                        base_address: object.base_address,
                        size: object.binary_size().try_into().unwrap_or(u32::MAX),
                        dtb: object.dtb(),
                    },
                );
            }

            return Ok(Some(guid));
        }

        Ok(None)
    }

    /// Load symbols for a module using its image metadata (TimeDateStamp +
    /// SizeOfImage) when the PE header cannot be read from memory, as is common
    /// for ntoskrnl in triage dumps. Downloads the PE from Microsoft's
    /// symbol server, extracts the PDB GUID, downloads the PDB, and registers
    /// the module.
    pub fn load_from_module_info(
        &self,
        name: &str,
        base_address: VirtAddr,
        dtb: Dtb,
        time_date_stamp: u32,
        size_of_image: u32,
    ) -> Result<Option<u128>> {
        let image_job = Self::build_image_download_job(name, time_date_stamp, size_of_image)?;
        download_job(&image_job, ProgressBar::new(0))?;

        let Some((pdb_job, guid)) = self.extract_download_job_from_image_file(&image_job.path)?
        else {
            return Ok(None);
        };

        download_job(&pdb_job, ProgressBar::new(0))?;
        self.ensure_pdb_loaded(pdb_job.expected_identity().unwrap(), &pdb_job.path)?;

        let module_key = Self::module_key(dtb, base_address);
        if !self.modules.contains_key(&module_key) {
            self.modules.insert(
                module_key,
                LoadedModule {
                    name: name.to_string(),
                    short_name: ModuleInfo::derive_short_name(name),
                    guid,
                    base_address,
                    size: size_of_image,
                    dtb,
                },
            );
        }

        Ok(Some(guid))
    }

    pub fn extract_download_job<B: MemoryOps<PhysAddr>>(
        &self,
        backend: &B,
        dtb: Dtb,
        module: &ModuleInfo,
        arch: Arch,
    ) -> Result<ModuleSymbolDiscovery> {
        if let Some(reference) =
            ModuleIdentity::of(module).and_then(|identity| self.module_identities().get(&identity))
        {
            let (job, guid) =
                self.build_download_job(&reference.server_name, reference.guid, reference.age)?;
            return Ok(ModuleSymbolDiscovery::Ready {
                job,
                guid,
                source: ModuleSymbolSource::Identity,
            });
        }
        let (module_name, base_address) = (module.name.as_str(), module.base_address);
        // `dtb` is the root for the module's own VA half: the kernel root for
        // kernel modules and the process root for user modules.
        let addr_space = memory::AddressSpace::for_arch(backend, dtb, dtb, arch);
        match self.extract_download_job_from_memory(&addr_space, base_address) {
            Ok(Some((job, guid))) => Ok(ModuleSymbolDiscovery::Ready {
                job,
                guid,
                source: ModuleSymbolSource::Memory,
            }),
            Ok(None) => Self::plan_image_fallback(&addr_space, module_name, base_address),
            Err(Error::BadVirtualAddress(_))
            | Err(Error::AddressNotInDump(_))
            | Err(Error::PartialRead(_))
            | Err(Error::DebugInfo(_)) => {
                Self::plan_image_fallback(&addr_space, module_name, base_address)
            }
            Err(err) => Err(err),
        }
    }

    pub fn load_downloaded_pdb(&self, load: &ModuleSymbolLoad) -> Result<()> {
        let module_key = Self::module_key(load.dtb, load.module.base_address);
        if let Some(existing) = self.modules.get(&module_key) {
            // A job that outlived a reload/reattach of its module describes a
            // different image; finishing it would mark the wrong PDB loaded.
            if existing.guid != load.guid {
                return Err(Error::DebugInfo(format!(
                    "stale symbol job for {}: module was replaced",
                    load.module.name
                )));
            }
            self.set_module_symbol_status(
                load.dtb,
                load.module.base_address,
                ModuleSymbolStatus::Loaded,
            );
            self.set_module_symbol_source(load.dtb, load.module.base_address, load.source.clone());
            return Ok(());
        }

        self.ensure_pdb_loaded(load.job.expected_identity().unwrap(), &load.job.path)?;
        self.modules.insert(module_key, load.loaded_module());
        self.set_module_symbol_status(
            load.dtb,
            load.module.base_address,
            ModuleSymbolStatus::Loaded,
        );
        self.set_module_symbol_source(load.dtb, load.module.base_address, load.source.clone());
        self.load_generation.fetch_add(1, Ordering::AcqRel);

        Ok(())
    }

    fn download_job_from_debug<'a, P32, P64>(
        &self,
        debug: &Wrap<pelite::pe32::debug::Debug<'a, P32>, pelite::pe64::debug::Debug<'a, P64>>,
    ) -> Result<Option<(DownloadJob, u128)>>
    where
        P32: pelite::pe32::Pe<'a>,
        P64: pelite::pe64::Pe<'a>,
    {
        let mut first_error = None;

        for dir in debug.iter() {
            match dir.entry() {
                Ok(entry) => {
                    if let Some(CodeView::Cv70 {
                        image,
                        pdb_file_name,
                    }) = entry.as_code_view()
                    {
                        let pdb_path = pdb_file_name.to_string();
                        let (job, guid) = self.build_download_job(
                            &pdb_path,
                            guid_to_u128(image.Signature),
                            image.Age,
                        )?;
                        return Ok(Some((job, guid)));
                    }
                }
                Err(err) => {
                    if first_error.is_none() {
                        first_error = Some(err);
                    }
                }
            }
        }

        if let Some(err) = first_error {
            return Err(err.into());
        }

        Ok(None)
    }

    fn extract_download_job_from_memory<B: MemoryOps<PhysAddr>>(
        &self,
        memory: &memory::AddressSpace<'_, B>,
        base_address: VirtAddr,
    ) -> Result<Option<(DownloadJob, u128)>> {
        let read = Self::image_reader(memory, base_address);
        for entry in Self::read_debug_entries(memory, base_address)? {
            // An NB10 (PDB 2.0) record names no GUID to fetch the PDB by.
            if let Some(headers::CodeView::Rsds { guid, age, path }) =
                entry.read_codeview(&read).transpose()?
            {
                return self
                    .build_download_job(&path, guid_to_u128(guid), age)
                    .map(Some);
            }
        }
        Ok(None)
    }

    fn plan_image_fallback<B: MemoryOps<PhysAddr>>(
        memory: &memory::AddressSpace<'_, B>,
        module_name: &str,
        base_address: VirtAddr,
    ) -> Result<ModuleSymbolDiscovery> {
        let (time_date_stamp, size_of_image) = Self::read_image_lookup_info(memory, base_address)?;
        let image_job =
            Self::build_image_download_job(module_name, time_date_stamp, size_of_image)?;
        Ok(ModuleSymbolDiscovery::NeedsImage { image_job })
    }

    pub fn extract_download_job_from_image_file(
        &self,
        image_path: &Path,
    ) -> Result<Option<(DownloadJob, u128)>> {
        let file = File::open(image_path)?;
        let mmap = unsafe { Mmap::map(&file)? };
        let pe = PeFile::from_bytes(&mmap[..])?;
        let debug = pe.debug()?;
        self.download_job_from_debug(&debug)
    }

    /// The symbol-server image key of a mapped module: TimeDateStamp and
    /// SizeOfImage from its in-memory PE header.
    pub fn read_image_lookup_info<B: MemoryOps<PhysAddr>>(
        memory: &memory::AddressSpace<'_, B>,
        base_address: VirtAddr,
    ) -> Result<(u32, u32)> {
        let header_buf = read_pe_header_page(base_address, memory)?;
        let view = PeView::from_bytes(&header_buf)?;
        Ok((view.file_header().TimeDateStamp, size_of_image(&view)))
    }

    pub fn ensure_pdb_loaded(&self, expected: PdbIdentity, path: &Path) -> Result<()> {
        if let Some(age) = self.pdb_ages.get(&expected.guid) {
            let validation = expected
                .matches(PdbIdentity {
                    guid: expected.guid,
                    age: *age,
                })
                .map_err(Error::DebugInfo);
            drop(age);
            validation?;
            return self.ensure_index_built(expected.guid);
        }

        if !path.exists() {
            return Err(Error::PdbNotFound(path.to_path_buf()));
        }

        let file = File::open(path)?;
        let mmap = unsafe { Mmap::map(&file)? };
        let mmap = Arc::new(mmap);
        let mmap_slice: &[u8] = &mmap;

        let static_slice: &'static [u8] = unsafe { std::mem::transmute(mmap_slice) };
        let cursor = Cursor::new(static_slice);
        let mut pdb = pdb2::PDB::open(cursor)?;
        let info = pdb.pdb_information()?;
        let actual = PdbIdentity {
            guid: info.guid.as_u128(),
            age: info.age,
        };
        expected.matches(actual).map_err(Error::DebugInfo)?;
        let pointer_size = match pdb.debug_information().and_then(|dbi| dbi.machine_type()) {
            Ok(pdb2::MachineType::X86 | pdb2::MachineType::Arm | pdb2::MachineType::ArmNT) => 4,
            Ok(pdb2::MachineType::Unknown) | Err(_) => pointer_size_from_types(&mut pdb),
            _ => 8,
        };

        // One loader wins per guid; replacing an existing entry would unmap
        // pages the stored PDB's cursor still points into.
        match self.pdbs.entry(expected.guid) {
            Entry::Occupied(_) => {
                let matches = self
                    .pdb_ages
                    .get(&expected.guid)
                    .and_then(|age| {
                        expected
                            .matches(PdbIdentity {
                                guid: expected.guid,
                                age: *age,
                            })
                            .ok()
                    })
                    .is_some();
                if !matches {
                    return Err(Error::DebugInfo(
                        "a non-matching PDB won a concurrent load".to_string(),
                    ));
                }
            }
            Entry::Vacant(entry) => {
                self.mmaps.insert(expected.guid, mmap);
                self.pdb_ages.insert(expected.guid, actual.age);
                self.pdb_paths.insert(expected.guid, path.to_path_buf());
                self.pdb_pointer_sizes.insert(expected.guid, pointer_size);
                entry.insert(pdb.into());
            }
        }
        self.ensure_index_built(expected.guid)
    }
}
