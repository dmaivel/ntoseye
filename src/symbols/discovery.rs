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
    pe::{read_pe_header_page, size_of_image},
    types::{Arch, Dtb, PhysAddr, VirtAddr},
};
use dashmap::mapref::entry::Entry;
use indicatif::ProgressBar;
use memmap2::Mmap;
use pelite::{
    PeFile, PeView, Wrap,
    image::{
        GUID, IMAGE_DEBUG_CV_INFO_PDB70, IMAGE_DEBUG_DIRECTORY, IMAGE_DEBUG_TYPE_CODEVIEW,
        IMAGE_DIRECTORY_ENTRY_DEBUG,
    },
    pe64::debug::CodeView,
};
use std::{
    fs::File,
    io::Cursor,
    mem::size_of,
    path::Path,
    ptr,
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

/// Largest `IMAGE_DEBUG_DIRECTORY` array read from a guest image; real images
/// carry a few entries.
const MAX_DEBUG_DIRECTORY_BYTES: usize = 0x1000;

/// Largest CodeView record read from a guest image (a GUID, an age, and a
/// PDB path).
const MAX_CODEVIEW_BYTES: usize = 0x1000;

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

    fn read_debug_directory_entries<B: MemoryOps<PhysAddr>>(
        memory: &memory::AddressSpace<'_, B>,
        base_address: VirtAddr,
        debug_rva: u32,
        debug_size: u32,
    ) -> Result<Vec<IMAGE_DEBUG_DIRECTORY>> {
        if debug_size == 0 {
            return Ok(Vec::new());
        }

        let entry_size = size_of::<IMAGE_DEBUG_DIRECTORY>();
        if !(debug_size as usize).is_multiple_of(entry_size) {
            return Err(Error::DebugInfo(format!(
                "debug directory size {:#x} is not a multiple of {}",
                debug_size, entry_size
            )));
        }

        // A handful of entries at most in any real image; the field is guest
        // memory, so bound the allocation before trusting it.
        if debug_size as usize > MAX_DEBUG_DIRECTORY_BYTES {
            return Err(Error::DebugInfo(format!(
                "debug directory size {debug_size:#x} exceeds {MAX_DEBUG_DIRECTORY_BYTES:#x}"
            )));
        }
        let mut bytes = vec![0u8; debug_size as usize];
        memory.read_bytes(base_address + debug_rva as u64, &mut bytes)?;

        let mut entries = Vec::new();
        for chunk in bytes.chunks_exact(entry_size) {
            let entry =
                unsafe { ptr::read_unaligned(chunk.as_ptr() as *const IMAGE_DEBUG_DIRECTORY) };
            entries.push(entry);
        }

        Ok(entries)
    }

    fn read_codeview_from_memory<B: MemoryOps<PhysAddr>>(
        &self,
        memory: &memory::AddressSpace<'_, B>,
        base_address: VirtAddr,
        entry: &IMAGE_DEBUG_DIRECTORY,
    ) -> Result<(String, Option<(DownloadJob, u128)>)> {
        if entry.AddressOfRawData == 0 || entry.SizeOfData < 4 {
            return Err(Error::DebugInfo(
                "codeview entry is missing raw data".to_string(),
            ));
        }
        if entry.SizeOfData as usize > MAX_CODEVIEW_BYTES {
            return Err(Error::DebugInfo(format!(
                "codeview entry size {:#x} exceeds {MAX_CODEVIEW_BYTES:#x}",
                entry.SizeOfData
            )));
        }

        let mut bytes = vec![0u8; entry.SizeOfData as usize];
        memory.read_bytes(base_address + entry.AddressOfRawData as u64, &mut bytes)?;
        let signature = bytes
            .get(..4)
            .ok_or_else(|| Error::DebugInfo("codeview entry truncated".to_string()))?;

        match signature {
            b"RSDS" => {
                if bytes.len() < size_of::<IMAGE_DEBUG_CV_INFO_PDB70>() {
                    return Err(Error::DebugInfo("RSDS entry truncated".to_string()));
                }

                let image = unsafe {
                    ptr::read_unaligned(bytes.as_ptr() as *const IMAGE_DEBUG_CV_INFO_PDB70)
                };
                let path =
                    Self::read_c_string_lossy(&bytes[size_of::<IMAGE_DEBUG_CV_INFO_PDB70>()..]);
                let summary = format!("CodeView RSDS age={} path={}", image.Age, path);
                let job =
                    self.build_download_job(&path, guid_to_u128(image.Signature), image.Age)?;
                Ok((summary, Some(job)))
            }
            b"NB10" => {
                if bytes.len() < 16 {
                    return Err(Error::DebugInfo("NB10 entry truncated".to_string()));
                }
                let age = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
                let path = Self::read_c_string_lossy(&bytes[16..]);
                Ok((format!("CodeView NB10 age={} path={}", age, path), None))
            }
            _ => Err(Error::DebugInfo("unknown magic number".to_string())),
        }
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
        let Some((debug_rva, debug_size)) =
            Self::read_debug_directory_location(memory, base_address)?
        else {
            return Ok(None);
        };

        for entry in
            Self::read_debug_directory_entries(memory, base_address, debug_rva, debug_size)?
        {
            if entry.Type != IMAGE_DEBUG_TYPE_CODEVIEW {
                continue;
            }

            let (_, job) = self.read_codeview_from_memory(memory, base_address, &entry)?;
            if let Some(job) = job {
                return Ok(Some(job));
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

    fn ensure_pdb_loaded(&self, expected: PdbIdentity, path: &Path) -> Result<()> {
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
                self.pdb_pointer_sizes.insert(expected.guid, pointer_size);
                entry.insert(pdb.into());
            }
        }
        self.ensure_index_built(expected.guid)
    }
}
