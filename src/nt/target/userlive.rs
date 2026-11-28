//! A target over a live Windows user-mode process: one process debugged
//! through a process server (the `dbgsrv` backend), its modules from the
//! process's own loader lists, and its threads.
//!
//! Like a user-mode minidump it is one address space with no kernel, and its
//! memory is keyed by virtual address: the root is
//! [`DTB_IDENTITY`](crate::base::memory::DTB_IDENTITY) and every read is
//! served by the process server. Unlike a dump it can be written, run, and
//! stopped, which is what the backend above it provides.

use std::sync::Arc;

use crate::backend::phys::PhysMem;
use crate::backend::userlive::{
    LiveProcessState, LiveUserThread, MemoryBasicInformation, backend_thread_id,
};
use crate::base::error::{Error, Result};
use crate::base::memory::{DTB_IDENTITY, MemoryOps, PAGE_SIZE};
use crate::base::notice::Notice;
use crate::base::types::VirtAddr;
use crate::nt::guest::{
    Guest, ModuleInfo, PEB64_LDR_OFFSET, UNKNOWN_MODULE_NAME, walk_loader_list64,
};
use crate::nt::symbols::SymbolStore;
use crate::nt::target::Target;
use crate::nt::userdump::MemoryRegion;

/// The live process a user-mode target inspects: shared live metadata updated
/// by the backend as threads arrive and exit, plus the target's module list
/// and thread selection.
#[derive(Clone, Debug)]
pub struct LiveUserProcess {
    state: LiveProcessState,
    /// The process's modules, as its loader lists them; filled by
    /// [`Target::refresh_live_user_modules`].
    pub modules: Vec<ModuleInfo>,
    /// The thread selected for inspection (`~Ns`), by thread id.
    pub selected_tid: Option<u32>,
}

impl LiveUserProcess {
    pub fn new(state: LiveProcessState, selected_tid: Option<u32>) -> Self {
        Self {
            state,
            modules: Vec::new(),
            selected_tid,
        }
    }

    pub fn state(&self) -> &LiveProcessState {
        &self.state
    }

    pub fn pid(&self) -> u32 {
        self.state.with(|info| info.pid)
    }

    pub fn peb(&self) -> Option<u64> {
        self.state.with(|info| info.peb.filter(|peb| *peb != 0))
    }

    pub fn image_base(&self) -> Option<u64> {
        self.state.with(|info| info.image_base)
    }

    pub fn image_hint(&self) -> Option<String> {
        self.state.with(|info| info.image_hint.clone())
    }

    pub fn threads(&self) -> Vec<LiveUserThread> {
        self.state.with(|info| info.threads.clone())
    }

    pub fn thread_count(&self) -> usize {
        self.state.with(|info| info.threads.len())
    }

    /// The thread selected for inspection.
    pub fn thread(&self) -> Option<LiveUserThread> {
        let tid = self.selected_tid?;
        self.thread_by_id(tid)
    }

    /// The thread `tid` names.
    pub fn thread_by_id(&self, tid: u32) -> Option<LiveUserThread> {
        self.state.with(|info| info.thread_by_id(tid).cloned())
    }

    /// The thread a backend id names (see [`backend_thread_id`]).
    pub fn thread_by_backend_id(&self, backend_id: &str) -> Option<LiveUserThread> {
        self.state
            .with(|info| info.thread_by_backend_id(backend_id).cloned())
    }

    /// The place the thread a backend id names holds in the process's thread
    /// list, which is the number `~` selects it by.
    pub fn thread_index_by_backend_id(&self, backend_id: &str) -> Option<usize> {
        self.state
            .with(|info| info.thread_index_by_backend_id(backend_id))
    }
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
    pub fn with_live_user_process(phys: Arc<PhysMem>, process: LiveUserProcess) -> Result<Self> {
        if !phys.is_user_live() {
            return Err(Error::DebugInfo(
                "the memory source is not a live user-mode process".to_string(),
            ));
        }
        let mut target =
            Self::from_parts(phys, Arc::new(SymbolStore::new()), None, None, Vec::new());
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

    /// Select the live thread a backend id names; an id no thread has clears
    /// the selection.
    pub fn select_live_user_thread(&mut self, backend_id: &str) -> Option<u32> {
        let process = self.user_live.as_mut()?;
        process.selected_tid = process
            .thread_by_backend_id(backend_id)
            .map(|thread| thread.tid);
        process.selected_tid
    }

    /// The backend id of live thread `tid`, as WinDbg names a user-mode
    /// thread.
    pub fn user_live_backend_thread_id(tid: u32) -> String {
        backend_thread_id(tid)
    }

    /// The live thread selected for inspection.
    pub fn user_live_thread(&self) -> Option<LiveUserThread> {
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
        let mut modules = match process.peb() {
            Some(peb) => {
                let memory = self.context_memory();
                let ldr = memory.read::<u64>(VirtAddr(peb + PEB64_LDR_OFFSET))?;
                walk_loader_list64(&memory, ldr).0
            }
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

    /// The image a live process was created from, as a module: a process
    /// stopped at its creation has no loader list yet, and its image is still
    /// the one module it has.
    ///
    /// The name comes from the image's own `CodeView` record, falling back to
    /// the command line file name and then the unknown marker.
    pub fn live_process_image(&self) -> Option<ModuleInfo> {
        let process = self.live_user_process()?;
        let base = process.image_base()?;
        let memory = self.context_memory();
        let probed = crate::nt::pe::read_pe_header_page(VirtAddr(base), &memory)
            .ok()
            .and_then(|headers| {
                let view = pelite::PeView::from_bytes(&headers[..]).ok()?;
                let characteristics = view.file_header().Characteristics;
                let name = view
                    .debug()
                    .ok()
                    .and_then(|debug| debug.pdb_file_name())
                    .and_then(|pdb| pdb.to_str().ok())
                    .map(|pdb| crate::nt::pe::image_file_name(pdb, characteristics));
                let size = match view.optional_header() {
                    pelite::Wrap::T32(optional) => optional.SizeOfImage,
                    pelite::Wrap::T64(optional) => optional.SizeOfImage,
                };
                Some((name, size))
            });
        let (name, size) = probed.unwrap_or((None, 0));
        let name = name
            .or_else(|| process.image_hint())
            .unwrap_or_else(|| UNKNOWN_MODULE_NAME.to_string());
        Some(ModuleInfo::new(name, VirtAddr(base), size))
    }

    /// The module list a live process reports, as `lm` lists it.
    pub fn live_modules(&self) -> Option<&[ModuleInfo]> {
        self.user_live
            .as_ref()
            .map(|process| process.modules.as_slice())
    }

    /// The live process's address space, one region per `VirtualQuery`, walked
    /// from the bottom of user space up.
    pub fn live_memory_regions(&self) -> Result<Vec<MemoryRegion>> {
        /// How many regions one walk may list: a process mapping every
        /// reservation separately still fits.
        const MAX_REGIONS: usize = 65_536;
        /// How many times an unqueryable page is stepped over before the walk
        /// gives up.
        const MAX_SKIPS: usize = 4_096;

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
                // Step over an unqueryable page rather than ending the listing
                // of everything above it.
                Some(Err(_)) | None => {
                    skips += 1;
                    if skips > MAX_SKIPS {
                        break;
                    }
                    address = address.saturating_add(PAGE_SIZE as u64);
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use super::*;
    use crate::arch::Arch;
    use crate::backend::phys::PhysMem;
    use crate::backend::userlive::{LiveProcessInfo, UserLiveMemory};

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
            self.put_u64(address + 8, buffer);
        }
    }

    impl UserLiveMemory for FakeMemory {
        fn read(&self, address: u64, buf: &mut [u8]) -> Result<()> {
            let map = self.bytes.lock().unwrap();
            for (offset, byte) in buf.iter_mut().enumerate() {
                *byte = *map
                    .get(&(address + offset as u64))
                    .ok_or(Error::BadVirtualAddress(VirtAddr(address + offset as u64)))?;
            }
            Ok(())
        }

        fn write(&self, address: u64, buf: &[u8]) -> Result<()> {
            self.put(address, buf);
            Ok(())
        }

        fn query(&self, address: u64) -> Result<MemoryBasicInformation> {
            Ok(MemoryBasicInformation {
                base_address: address & !0xfff,
                allocation_base: address & !0xffff,
                allocation_protect: 0x04,
                partition_id: 0,
                reserved0: [0; 2],
                region_size: PAGE_SIZE as u64,
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
        memory.put_u64(PEB + PEB64_LDR_OFFSET, LDR);
        memory.put_u64(LDR_HEAD, ENTRY_BOOT);
        // Zero-fill each 0x68-byte `_LDR_DATA_TABLE_ENTRY` so single-read
        // walks read resident bytes for the whole record.
        memory.put(ENTRY_BOOT, &[0u8; 0x68]);
        memory.put(ENTRY_NTDLL, &[0u8; 0x68]);
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
        let phys = Arc::new(PhysMem::user_live(memory.clone(), Arch::Amd64));
        let state = LiveProcessState::new(LiveProcessInfo {
            pid: 0x1234,
            peb: Some(PEB),
            image_base: None,
            image_hint: None,
            threads: vec![LiveUserThread {
                tid: 0x5678,
                teb: Some(0x7ff0_1000),
                start_address: Some(BOOT_BASE + 0x1000),
                name: None,
            }],
        });
        let process = LiveUserProcess::new(state, Some(0x5678));
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
            target.live_user_process().map(LiveUserProcess::pid),
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
    fn live_user_pseudo_registers_report_process_and_selected_thread() {
        let (_memory, target) = process();
        assert_eq!(target.builtin_variable_value("pid"), Some(0x1234));
        assert_eq!(target.builtin_variable_value("tpid"), Some(0x1234));
        assert_eq!(target.builtin_variable_value("peb"), Some(PEB));
        assert_eq!(target.builtin_variable_value("tid"), Some(0x5678));
        assert_eq!(target.builtin_variable_value("teb"), Some(0x7ff0_1000));
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
        target
            .live_user_process()
            .expect("a live process")
            .state()
            .update(|info| info.peb = None);
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
        target
            .live_user_process()
            .expect("a live process")
            .state()
            .update(|info| {
                info.peb = None;
                info.image_base = Some(0x0040_0000);
                info.image_hint = Some("boot.exe".to_string());
            });
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
        assert!(!regions.is_empty());
        assert_eq!(regions[0].base, 0);
        assert_eq!(regions[0].state, 0x1000);
        assert!(regions.iter().all(|region| region.size == PAGE_SIZE as u64));
    }
}
