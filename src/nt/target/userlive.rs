//! A target over a live Windows user-mode process: one process debugged
//! through a process server (the `dbgsrv` backend), its modules from the
//! process's own loader lists, and its threads.
//!
//! Like a user-mode minidump it is one address space with no kernel, and its
//! memory is keyed by virtual address: the root is
//! [`DTB_IDENTITY`](crate::base::memory::DTB_IDENTITY) and every read is
//! served by the process server. Unlike a dump it can be written, run, and
//! stopped, which is what the backend above it provides.

use crate::backend::phys::PhysMem;
use crate::backend::userlive::MemoryBasicInformation;
use crate::base::error::{Error, Result};
use crate::base::memory::{AddressSpace, DTB_IDENTITY, MemoryOps};
use crate::base::notice::Notice;
use crate::base::types::VirtAddr;
use crate::nt::guest::{Guest, ModuleInfo, UNKNOWN_MODULE_NAME};
use crate::nt::symbols::SymbolStore;
use crate::nt::target::Target;
use crate::nt::userdump::MemoryRegion;

/// One thread of the live process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveUserThread {
    pub tid: u32,
    /// The process server's handle to the thread, which its register calls
    /// name.
    pub handle: u64,
    /// The thread's `_TEB`, when the server names it.
    pub teb: Option<u64>,
    /// The address the thread's function starts at, when the server says.
    pub start_address: Option<u64>,
    /// The thread's description (`SetThreadDescription`), when it has one.
    pub name: Option<String>,
}

/// The live process a user-mode target inspects.
#[derive(Clone, Debug)]
pub struct LiveUserProcess {
    pub pid: u32,
    /// The process server's handle to the process.
    pub process_handle: u64,
    /// The process's `_PEB`, when the server names it.
    pub peb: Option<u64>,
    /// The process's modules, as its loader lists them; filled by
    /// [`Target::refresh_live_user_modules`].
    pub modules: Vec<ModuleInfo>,
    /// The image the process was created from, which is its only module until
    /// its loader fills the lists.
    pub image_base: Option<u64>,
    /// The file name of the command line this session created, if one was.
    pub image_hint: Option<String>,
    pub threads: Vec<LiveUserThread>,
    /// The thread selected for inspection (`~Ns`), by thread id.
    pub selected_tid: Option<u32>,
}

impl LiveUserProcess {
    /// The thread selected for inspection.
    pub fn thread(&self) -> Option<&LiveUserThread> {
        let tid = self.selected_tid?;
        self.threads.iter().find(|thread| thread.tid == tid)
    }

    /// The thread `tid` names.
    pub fn thread_by_id(&self, tid: u32) -> Option<&LiveUserThread> {
        self.threads.iter().find(|thread| thread.tid == tid)
    }
}

/// The `_PEB` fields the loader walk needs, at the offsets every 64-bit
/// Windows keeps them: the PEB's and loader data's own layouts are part of
/// the loader ABI (the same reason
/// [`walk_loader_list32`](crate::nt::guest::walk_loader_list32) uses fixed
/// 32-bit offsets), so a process can be listed before any symbols are loaded.
mod abi {
    /// `_PEB.Ldr`.
    pub const PEB_LDR: u64 = 0x18;
    /// `_PEB_LDR_DATA.InLoadOrderModuleList`.
    pub const LDR_IN_LOAD_ORDER: u64 = 0x10;
    /// `_LDR_DATA_TABLE_ENTRY.InLoadOrderLinks`.
    pub const ENTRY_IN_LOAD_ORDER_LINKS: u64 = 0x00;
    /// `_LDR_DATA_TABLE_ENTRY.DllBase`.
    pub const ENTRY_DLL_BASE: u64 = 0x30;
    /// `_LDR_DATA_TABLE_ENTRY.EntryPoint`.
    pub const ENTRY_ENTRY_POINT: u64 = 0x38;
    /// `_LDR_DATA_TABLE_ENTRY.SizeOfImage`.
    pub const ENTRY_SIZE_OF_IMAGE: u64 = 0x40;
    /// `_LDR_DATA_TABLE_ENTRY.FullDllName`, a `UNICODE_STRING`.
    pub const ENTRY_FULL_NAME: u64 = 0x48;
    /// `_LDR_DATA_TABLE_ENTRY.BaseDllName`, a `UNICODE_STRING`.
    pub const ENTRY_BASE_NAME: u64 = 0x58;
}

/// How many loader entries one walk may list before it gives up: a corrupt
/// list must not spin forever.
const MAX_LOADER_MODULES: usize = 1024;

/// One loader entry's fixed fields, read out of the process.
struct LoaderEntry {
    base: u64,
    entry_point: u64,
    size_of_image: u32,
}

/// A live `VirtualQuery` answer as the dump model records a region: the same
/// seven fields, under the names `!address` reports.
impl From<MemoryBasicInformation> for MemoryRegion {
    fn from(info: MemoryBasicInformation) -> Self {
        Self {
            base: info.base_address,
            allocation_base: info.allocation_base,
            allocation_protect: info.allocation_protect,
            size: info.region_size,
            state: info.state,
            protect: info.protect,
            kind: info.kind,
        }
    }
}

impl Target {
    /// Build a target over the live user-mode `process`, whose memory `phys`
    /// serves. No kernel is looked for, and the module list stays empty until
    /// [`Self::refresh_live_user_modules`] reads it from the process's own
    /// loader lists.
    pub fn with_live_user_process(
        phys: std::sync::Arc<crate::backend::phys::PhysMem>,
        process: LiveUserProcess,
    ) -> Result<Self> {
        if !phys.is_user_live() {
            return Err(Error::DebugInfo(
                "the memory source is not a live user-mode process".to_string(),
            ));
        }
        let mut target = Self::from_parts(
            phys,
            std::sync::Arc::new(SymbolStore::new()),
            None,
            None,
            Vec::new(),
        );
        target.user_live = Some(process);
        Ok(target)
    }

    /// The live process this target inspects, `None` for every other target.
    pub fn live_user_process(&self) -> Option<&LiveUserProcess> {
        self.user_live.as_ref()
    }

    /// The live process, for a caller that changes its module list or
    /// selection.
    pub fn live_user_process_mut(&mut self) -> Option<&mut LiveUserProcess> {
        self.user_live.as_mut()
    }

    /// Select the live thread a backend id names: the thread id in hex, as
    /// [`Self::user_live_backend_thread_id`] writes it. An id no thread has
    /// clears the selection.
    pub fn select_live_user_thread(&mut self, backend_id: &str) -> Option<u32> {
        let tid = u32::from_str_radix(backend_id, 16).ok();
        let process = self.user_live.as_mut()?;
        process.selected_tid = tid.filter(|tid| process.thread_by_id(*tid).is_some());
        process.selected_tid
    }

    /// The backend id of live thread `tid`: its id in hex, which is how
    /// WinDbg names a user-mode thread.
    pub fn user_live_backend_thread_id(tid: u32) -> String {
        format!("{tid:x}")
    }

    /// The live thread selected for inspection.
    pub fn user_live_thread(&self) -> Option<&LiveUserThread> {
        self.user_live.as_ref()?.thread()
    }

    /// Read the process's loader lists and start loading the symbols of what
    /// it loaded. A process whose `_PEB` the server did not name keeps the
    /// module list it has.
    ///
    /// Symbol files are fetched in the background (see
    /// [`Guest::load_module_symbols_or_fetch_later`]): attaching must not wait
    /// on the network for them, and `lm` lists the modules the loader walk
    /// found either way.
    pub fn refresh_live_user_modules(&mut self) -> Result<()> {
        let Some(process) = self.user_live.as_ref() else {
            return Err(Error::DebugInfo(
                "this target is not a live user-mode process".to_string(),
            ));
        };
        let arch = self
            .phys
            .user_live_arch()
            .ok_or_else(|| Error::DebugInfo("the memory source has no architecture".into()))?;
        // A process stopped at its creation has no loader list to walk: its
        // image is the one module it has.
        let peb = process.peb.filter(|peb| *peb != 0);
        let mut modules = match peb {
            Some(peb) => self.walk_live_loader_list(peb)?,
            None => Vec::new(),
        };
        if modules.is_empty()
            && let Some(image) = self.live_process_image()
        {
            modules.push(image);
        }
        if modules.is_empty() {
            return Err(Error::MissingPEB);
        }
        // The image's own debug directory names its PDB, which is what the
        // symbol store needs; the loader list only has to name the image.
        // The list is recorded whatever the symbols do: `lm` must list the
        // process's modules even when a PDB cannot be fetched.
        let report = Guest::load_module_symbols_or_fetch_later(
            &self.phys,
            &self.symbols,
            modules.clone(),
            DTB_IDENTITY,
            arch,
        );
        if report.failed_count() != 0 {
            self.notices.push(Notice::warning(format!(
                "{} of the live process's modules could not have their symbols loaded",
                report.failed_count()
            )));
        }
        if let Some(process) = self.user_live.as_mut() {
            process.modules = modules;
        }
        Ok(())
    }

    /// Walk `peb`'s `InLoadOrderModuleList`, naming each module from its
    /// `FullDllName` and its `BaseDllName`, without needing any symbols.
    fn walk_live_loader_list(&self, peb: u64) -> Result<Vec<ModuleInfo>> {
        let memory = self.context_memory();
        let ldr = memory.read::<u64>(VirtAddr(peb + abi::PEB_LDR))?;
        if ldr == 0 {
            return Ok(Vec::new());
        }
        let head = ldr + abi::LDR_IN_LOAD_ORDER;
        let mut modules = Vec::new();
        let mut link = memory.read::<u64>(VirtAddr(head))?;
        for _ in 0..MAX_LOADER_MODULES {
            if link == 0 || link == head {
                break;
            }
            let record = link - abi::ENTRY_IN_LOAD_ORDER_LINKS;
            let entry = self.read_loader_entry(&memory, record)?;
            if entry.base != 0 {
                let full_path = read_loader_string(&memory, record + abi::ENTRY_FULL_NAME);
                let base_name = read_loader_string(&memory, record + abi::ENTRY_BASE_NAME);
                let name = full_path
                    .as_deref()
                    .and_then(|path| path.rsplit(['\\', '/']).next())
                    .filter(|file| !file.is_empty())
                    .map(str::to_string)
                    .or_else(|| base_name.filter(|name| !name.is_empty()))
                    .unwrap_or_else(|| UNKNOWN_MODULE_NAME.to_string());
                let mut info = ModuleInfo::new(name, VirtAddr(entry.base), entry.size_of_image);
                if !full_path.as_deref().unwrap_or_default().is_empty() {
                    info.path = full_path;
                }
                if entry.entry_point != 0 {
                    info.entry_point = Some(VirtAddr(entry.entry_point));
                }
                modules.push(info);
            }
            link = memory.read::<u64>(VirtAddr(record + abi::ENTRY_IN_LOAD_ORDER_LINKS))?;
        }
        Ok(modules)
    }

    fn read_loader_entry(
        &self,
        memory: &AddressSpace<'_, PhysMem>,
        record: u64,
    ) -> Result<LoaderEntry> {
        let read = |at: u64| VirtAddr(record + at);
        Ok(LoaderEntry {
            base: memory.read::<u64>(read(abi::ENTRY_DLL_BASE))?,
            entry_point: memory.read::<u64>(read(abi::ENTRY_ENTRY_POINT))?,
            size_of_image: memory.read::<u32>(read(abi::ENTRY_SIZE_OF_IMAGE))?,
        })
    }

    /// The image a live process was created from, as a module: a process
    /// stopped at its creation has no loader list yet, and its image is still
    /// the one module it has.
    ///
    /// The name comes from the image's own `CodeView` record, which its mapped
    /// headers carry; a process whose command line this session created falls
    /// back to that file name, and a stripped image to the unknown marker.
    pub fn live_process_image(&self) -> Option<ModuleInfo> {
        let base = self.live_user_process()?.image_base?;
        let memory = self.context_memory();
        let characteristics = crate::nt::pe::read_pe_header_page(VirtAddr(base), &memory)
            .ok()
            .and_then(|headers| {
                let view = pelite::PeView::from_bytes(&headers[..]).ok()?;
                let characteristics = view.file_header().Characteristics;
                let pdb = view
                    .debug()
                    .ok()
                    .and_then(|debug| debug.pdb_file_name())
                    .and_then(|name| name.to_str().ok().map(str::to_string));
                let size = match view.optional_header() {
                    pelite::Wrap::T32(optional) => optional.SizeOfImage,
                    pelite::Wrap::T64(optional) => optional.SizeOfImage,
                };
                Some((
                    characteristics,
                    pdb.map(|pdb| crate::nt::pe::image_file_name(&pdb, characteristics)),
                    size,
                ))
            });
        let (name, size) = match characteristics {
            Some((_, Some(name), size)) => (name, size),
            Some((_, None, size)) => (
                self.live_user_process()?
                    .image_hint
                    .clone()
                    .unwrap_or_else(|| UNKNOWN_MODULE_NAME.to_string()),
                size,
            ),
            None => (
                self.live_user_process()?
                    .image_hint
                    .clone()
                    .unwrap_or_else(|| UNKNOWN_MODULE_NAME.to_string()),
                0,
            ),
        };
        Some(ModuleInfo::new(name, VirtAddr(base), size))
    }

    /// The module list a live process reports, as `lm` lists it.
    pub fn live_modules(&self) -> Option<&[ModuleInfo]> {
        self.user_live
            .as_ref()
            .map(|process| process.modules.as_slice())
    }

    /// The live process's address space, one region per `VirtualQuery`:
    /// The live process's address space, one region per `VirtualQuery`:
    /// the query's own answer, walked from the bottom of user space up.
    pub fn live_memory_regions(&self) -> Result<Vec<MemoryRegion>> {
        /// How many regions one walk may list: a process mapping every
        /// reservation separately still fits.
        const MAX_REGIONS: usize = 65_536;
        /// How many times an unqueryable address is stepped over before the
        /// walk gives up: a server that refuses a page must not end the
        /// listing of everything above it, and a server that refuses all of
        /// it must not spin.
        const MAX_SKIPS: usize = 4_096;
        /// The step taken over an address `VirtualQuery` refuses.
        const SKIP: u64 = 0x1000;

        let arch = self
            .phys
            .user_live_arch()
            .ok_or_else(|| Error::DebugInfo("this target is not a live process".into()))?;
        let mut regions = Vec::new();
        let mut address = 0u64;
        let mut skips = 0;
        while !arch.paging().is_kernel_address(VirtAddr(address)) {
            let query = match self.phys.user_live_query(address) {
                Some(Ok(query)) => query,
                // Nothing answers here: step over the page rather than
                // ending the listing of everything above it.
                Some(Err(_)) | None => {
                    skips += 1;
                    if skips > MAX_SKIPS {
                        break;
                    }
                    address = address.saturating_add(SKIP);
                    continue;
                }
            };
            let region = MemoryRegion::from(query);
            if region.size == 0 {
                break;
            }
            let next = region.base.saturating_add(region.size);
            regions.push(region);
            if next <= address {
                // A region that does not advance the walk would repeat it.
                break;
            }
            address = next;
            if regions.len() >= MAX_REGIONS {
                break;
            }
        }
        Ok(regions)
    }
}

/// The length, maximum length, and buffer of a `UNICODE_STRING` at
/// `address`. The buffer is a pointer, so it is as wide as the target's:
/// eight bytes on AMD64 and ARM64.
fn read_unicode_string_header(
    memory: &AddressSpace<'_, PhysMem>,
    address: u64,
) -> Result<(u16, u16, u64)> {
    let length = memory.read::<u16>(VirtAddr(address))?;
    let maximum = memory.read::<u16>(VirtAddr(address + 2))?;
    let buffer = if memory.arch().pointer_size() == 8 {
        memory.read::<u64>(VirtAddr(address + 8))?
    } else {
        u64::from(memory.read::<u32>(VirtAddr(address + 8))?)
    };
    Ok((length, maximum, buffer))
}

/// The string a `UNICODE_STRING` at `address` names, `None` when it is empty
/// or unreadable.
fn read_loader_string(memory: &AddressSpace<'_, PhysMem>, address: u64) -> Option<String> {
    let (length, maximum, buffer) = read_unicode_string_header(memory, address).ok()?;
    let length = length.min(maximum) as usize;
    if length == 0 || buffer == 0 {
        return None;
    }
    let mut bytes = vec![0u8; length & !1];
    memory.read_bytes(VirtAddr(buffer), &mut bytes).ok()?;
    let wide: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    Some(String::from_utf16_lossy(&wide))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use super::*;
    use crate::arch::Arch;
    use crate::backend::phys::PhysMem;
    use crate::backend::userlive::UserLiveMemory;

    /// A process address space as a sparse map of bytes: reads inside a
    /// mapped page succeed, anything else faults like an unmapped address.
    #[derive(Default)]
    struct FakeMemory {
        bytes: std::sync::Mutex<BTreeMap<u64, u8>>,
    }

    impl FakeMemory {
        fn put(&self, address: u64, bytes: &[u8]) {
            let mut map = self.bytes.lock().unwrap();
            for (offset, byte) in bytes.iter().enumerate() {
                map.insert(address + offset as u64, *byte);
            }
        }

        fn put_u16(&self, address: u64, value: u16) {
            self.put(address, &value.to_le_bytes());
        }

        fn put_u32(&self, address: u64, value: u32) {
            self.put(address, &value.to_le_bytes());
        }

        fn put_u64(&self, address: u64, value: u64) {
            self.put(address, &value.to_le_bytes());
        }

        /// A `UNICODE_STRING` at `address` naming `text`, whose characters
        /// live at `buffer`.
        fn put_unicode_string(&self, address: u64, buffer: u64, text: &str) {
            let wide: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
            self.put(buffer, &wide);
            self.put_u16(address, wide.len() as u16);
            self.put_u16(address + 2, wide.len() as u16 + 2);
            // `UNICODE_STRING.Buffer` is a pointer: eight bytes on the
            // 64-bit targets this walk supports.
            self.put_u64(address + 8, buffer);
        }
    }

    impl UserLiveMemory for FakeMemory {
        fn read(&self, _process: u64, address: u64, buf: &mut [u8]) -> Result<()> {
            let map = self.bytes.lock().unwrap();
            for (offset, byte) in buf.iter_mut().enumerate() {
                *byte = *map
                    .get(&(address + offset as u64))
                    .ok_or(Error::BadVirtualAddress(VirtAddr(address + offset as u64)))?;
            }
            Ok(())
        }

        fn write(&self, _process: u64, address: u64, buf: &[u8]) -> Result<()> {
            self.put(address, buf);
            Ok(())
        }

        fn query(&self, _process: u64, address: u64) -> Result<MemoryBasicInformation> {
            Ok(MemoryBasicInformation {
                base_address: address & !0xfff,
                allocation_base: address & !0xffff,
                allocation_protect: 0x04,
                partition_id: 0,
                reserved0: [0; 2],
                region_size: 0x1000,
                state: 0x1000,
                protect: 0x04,
                kind: 0x2_0000,
                reserved1: [0; 4],
            })
        }
    }

    const PEB: u64 = 0x1000;
    const LDR: u64 = 0x2000;
    const LDR_HEAD: u64 = LDR + 0x10;
    const ENTRY_BOOT: u64 = 0x3000;
    const ENTRY_NTDLL: u64 = 0x4000;
    const BOOT_BASE: u64 = 0x0040_0000;
    const NTDLL_BASE: u64 = 0x1000_0000;

    /// A process whose loader list holds the image and `ntdll.dll`, wired the
    /// way a 64-bit Windows keeps it.
    fn process() -> (Arc<FakeMemory>, Target) {
        let memory = Arc::new(FakeMemory::default());
        // PEB.Ldr.
        memory.put_u64(PEB + 0x18, LDR);
        // The list head, then each entry's forward link: the head points at
        // the first entry's InLoadOrderLinks, and the last entry back at the
        // head.
        memory.put_u64(LDR_HEAD, ENTRY_BOOT);
        memory.put_u64(ENTRY_BOOT, ENTRY_NTDLL);
        memory.put_u64(ENTRY_NTDLL, LDR_HEAD);
        for (entry, base, size, name, path, path_buffer, name_buffer) in [
            (
                ENTRY_BOOT,
                BOOT_BASE,
                0x2000u32,
                "boot.exe",
                "C:\\app\\boot.exe",
                0x5000u64,
                0x5200u64,
            ),
            (
                ENTRY_NTDLL,
                NTDLL_BASE,
                0x1f0000,
                "ntdll.dll",
                "C:\\Windows\\System32\\ntdll.dll",
                0x6000,
                0x6300,
            ),
        ] {
            memory.put_u64(entry + 0x30, base);
            memory.put_u64(entry + 0x38, base + 0x1000);
            memory.put_u32(entry + 0x40, size);
            memory.put_unicode_string(entry + 0x48, path_buffer, path);
            memory.put_unicode_string(entry + 0x58, name_buffer, name);
        }
        let phys = Arc::new(PhysMem::user_live(memory.clone(), 1, Arch::Amd64));
        let process = LiveUserProcess {
            pid: 0x1234,
            process_handle: 0x100,
            peb: Some(PEB),
            modules: Vec::new(),
            image_base: None,
            image_hint: None,
            threads: vec![LiveUserThread {
                tid: 0x5678,
                handle: 0x200,
                teb: Some(0x7ff0_1000),
                start_address: Some(BOOT_BASE + 0x1000),
                name: None,
            }],
            selected_tid: Some(0x5678),
        };
        let target = Target::with_live_user_process(phys, process).expect("a live target");
        (memory, target)
    }

    #[test]
    fn a_live_target_is_a_user_target_that_refuses_kernel_operations() {
        let (_memory, target) = process();
        assert_eq!(target.kind(), crate::nt::target::TargetKind::UserLive);
        assert!(target.is_user_target());
        assert!(matches!(
            target.require_kernel(),
            Err(Error::KernelRequired)
        ));
        assert!(target.user_dump().is_none());
        assert_eq!(
            target.live_user_process().map(|process| process.pid),
            Some(0x1234)
        );
        assert_eq!(
            target
                .user_live_thread()
                .and_then(|thread| thread.start_address),
            Some(BOOT_BASE + 0x1000)
        );
    }

    #[test]
    fn the_loader_walk_lists_the_image_and_ntdll() {
        let (_memory, mut target) = process();
        target.refresh_live_user_modules().expect("a module list");
        let modules = target.modules().expect("modules");
        assert_eq!(
            modules
                .iter()
                .map(|module| (module.name.as_str(), module.base_address.0))
                .collect::<Vec<_>>(),
            vec![("boot.exe", BOOT_BASE), ("ntdll.dll", NTDLL_BASE)]
        );
        assert_eq!(modules[0].path.as_deref(), Some("C:\\app\\boot.exe"));
        assert_eq!(modules[1].size, 0x1f0000);
        assert_eq!(target.user_modules().map(<[_]>::len), Some(2));
    }

    #[test]
    fn a_process_the_server_gives_no_peb_for_keeps_its_module_list() {
        let (_memory, mut target) = process();
        target.live_user_process_mut().expect("a live process").peb = None;
        assert!(matches!(
            target.refresh_live_user_modules(),
            Err(Error::MissingPEB)
        ));
        assert!(target.modules().expect("modules").is_empty());
    }

    #[test]
    fn selecting_a_live_thread_is_by_hex_id_and_an_unknown_id_clears_it() {
        let (_memory, mut target) = process();
        assert_eq!(target.select_live_user_thread("5678"), Some(0x5678));
        assert_eq!(target.select_live_user_thread("99"), None);
        assert!(target.user_live_thread().is_none());
    }

    /// A process stopped at its creation has no loader list yet: its image is
    /// the one module it has, named from the command line this session
    /// created when its own headers cannot be read.
    #[test]
    fn a_process_with_no_loader_list_lists_its_creation_image() {
        let (_memory, mut target) = process();
        {
            let live = target.live_user_process_mut().expect("a live process");
            live.peb = None;
            live.image_base = Some(0x0040_0000);
            live.image_hint = Some("boot.exe".to_string());
        }
        // No PEB means the loader lists are unreadable, which is the state a
        // creation stop leaves the process in.
        let _ = target.refresh_live_user_modules();
        let modules = target.modules().expect("modules");
        assert_eq!(modules.len(), 1, "{modules:?}");
        assert_eq!(modules[0].name, "boot.exe");
        assert_eq!(modules[0].base_address.0, 0x0040_0000);
    }

    #[test]
    fn a_virtual_query_walks_the_process_regions() {
        let (_memory, target) = process();
        let regions = target.live_memory_regions().expect("regions");
        // The walk ends where the architecture's user half does; every
        // query is a page in this fake, so it lists the pages up to it.
        assert!(!regions.is_empty());
        assert_eq!(regions[0].base, 0);
        assert_eq!(regions[0].state, 0x1000);
        assert!(regions.iter().all(|region| region.size == 0x1000));
    }
}
