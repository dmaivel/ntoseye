//! The inspection scope: the attached process, context root, selected
//! thread and its registers, and the process and code bitness they imply.

use super::{
    AttachReport, CODE_BITNESS_AMD64, CODE_BITNESS_X86, Target, TargetSelection, ThreadInfo,
    lookup_register, process_matches,
};
use crate::{
    backend::MemoryOps,
    bugchecks::looks_like_kernel_pointer,
    error::{Error, Result},
    guest::{ModuleInfo, ModuleSymbolLoadReport, ProcessInfo},
    types::{Dtb, VirtAddr},
};

const COMPATIBILITY_MODE_CS: u64 = 0x23;
const WOW64_ADDRESS_LIMIT: u64 = 1 << 32;

fn decide_bitness(
    effmach: Option<u32>,
    cs: Option<u64>,
    is_wow64: bool,
    modules: &[ModuleInfo],
    address: VirtAddr,
) -> u32 {
    if let Some(effmach) = effmach {
        return if matches!(effmach, CODE_BITNESS_X86 | 0x14c) {
            CODE_BITNESS_X86
        } else {
            CODE_BITNESS_AMD64
        };
    }

    let is_user = !looks_like_kernel_pointer(address.0);
    if is_user && cs == Some(COMPATIBILITY_MODE_CS) {
        return CODE_BITNESS_X86;
    }

    if is_wow64 {
        if modules
            .iter()
            .any(|module| module.is_32bit && module.contains_address(address))
        {
            return CODE_BITNESS_X86;
        }
        if address.0 < WOW64_ADDRESS_LIMIT
            && !modules
                .iter()
                .any(|module| !module.is_32bit && module.contains_address(address))
        {
            return CODE_BITNESS_X86;
        }
    }

    CODE_BITNESS_AMD64
}

fn thread_owner_matches(thread: &ThreadInfo, process: &ProcessInfo) -> bool {
    match thread.eprocess {
        Some(eprocess) => eprocess == process.eprocess_va,
        None => thread.pid.is_some_and(|pid| pid == process.pid),
    }
}

fn select_thread_process_dtb(
    thread: &ThreadInfo,
    current: Option<&ProcessInfo>,
    processes: &[ProcessInfo],
    kernel_dtb: Dtb,
) -> Option<Dtb> {
    if thread.pid == Some(0) {
        return Some(kernel_dtb);
    }
    current
        .filter(|process| thread_owner_matches(thread, process))
        .or_else(|| {
            processes
                .iter()
                .find(|process| thread_owner_matches(thread, process))
        })
        .map(|process| process.dtb)
}

impl Target {
    /// The attached process, or `None` in the kernel scope.
    pub fn attached_process(&self) -> Option<&ProcessInfo> {
        self.process.as_ref()
    }

    /// Root of the module-list scope: the attached process's, else the
    /// kernel's (identity mapping when no kernel was found). It decides whose
    /// loader list [`Self::modules`] walks and whose symbols load; reads the
    /// user points at go through [`Self::current_dtb`] instead.
    pub fn process_dtb(&self) -> Dtb {
        if self.secure_root.is_some()
            && let Some(secure) = self.guest.as_ref().and_then(|g| g.cached_secure_kernel())
        {
            return secure.image.dtb();
        }
        self.process
            .as_ref()
            .map_or_else(|| self.kernel_dtb(), |process| process.dtb)
    }

    /// Root of the inspection address space every read the user points at
    /// goes through: the attached process's, else the halted thread's (or
    /// selected context's) process, else the kernel's.
    pub fn current_dtb(&self) -> Dtb {
        if let Some(root) = self.secure_root {
            return root;
        }
        match &self.process {
            Some(process) => process.dtb,
            None => self
                .context_dtb_override
                .unwrap_or_else(|| self.kernel_dtb()),
        }
    }

    pub fn attach(&mut self, pid: u64) -> Result<AttachReport> {
        let processes = self.guest()?.enumerate_processes()?;
        let process_info = processes
            .iter()
            .find(|p| p.pid == pid)
            .ok_or(Error::ProcessNotFound(pid))?
            .clone();

        self.attach_process_info(process_info)
    }

    pub fn attach_process_info(&mut self, process_info: ProcessInfo) -> Result<AttachReport> {
        let name = process_info.name.clone();
        let guest = self.guest.as_ref().ok_or(Error::NtoskrnlNotFound)?;

        // A kernel-only process (System, Registry, ...) has no PEB and so no
        // user modules; attaching still scopes its address space.
        let symbol_report =
            match guest.load_all_process_module_symbols(&self.phys, &self.symbols, &process_info) {
                Err(Error::MissingPEB) => ModuleSymbolLoadReport::default(),
                report => report?,
            };

        self.process = Some(process_info);
        self.secure_root = None;
        self.selected_frame = None;
        self.clear_context_dtb_override();
        self.clear_current_windows_thread_context();
        Ok(AttachReport {
            name,
            symbol_report,
        })
    }

    pub fn detach(&mut self) {
        self.secure_root = None;
        self.selected_frame = None;
        self.clear_context_dtb_override();
        self.clear_current_windows_thread_context();
        self.process = None;
    }

    /// Set the attached process aside, so inspection follows the selected
    /// frame's own root until [`Self::restore_attached_process`].
    pub fn take_attached_process(&mut self) -> Option<ProcessInfo> {
        self.process.take()
    }

    pub fn restore_attached_process(&mut self, process: Option<ProcessInfo>) {
        self.process = process;
    }

    /// Scope inspection to `info`'s address space without loading its module
    /// symbols, which [`Self::attach_process_info`] does. Memory, type, and
    /// kernel-symbol reads need only the page tables.
    pub fn enter_process_scope(&mut self, info: ProcessInfo) {
        self.detach();
        self.process = Some(info);
    }

    /// Move the selected inspection scope out, leaving the target detached
    /// with no frame, thread, or register overrides.
    pub fn take_selection(&mut self) -> TargetSelection {
        TargetSelection {
            process: self.process.take(),
            secure_root: self.secure_root.take(),
            context_dtb_override: self.context_dtb_override.take(),
            selected_frame: self.selected_frame.take(),
            windows_thread_selection: self.windows_thread_selection.take(),
            registers: self.registers.take(),
        }
    }

    /// Put back a scope taken with [`Self::take_selection`].
    pub fn restore_selection(&mut self, selection: TargetSelection) {
        self.process = selection.process;
        self.secure_root = selection.secure_root;
        self.context_dtb_override = selection.context_dtb_override;
        self.selected_frame = selection.selected_frame;
        self.windows_thread_selection = selection.windows_thread_selection;
        self.registers = selection.registers;
    }

    /// Follow a register-derived root (a halted thread's CR3/TTBR0, or a
    /// context record's) for inspection. A root that cannot reach the kernel
    /// is a KVA-shadow user root; it is replaced by its process's full
    /// `DirectoryTableBase`, so kernel reads keep working at user-mode stops.
    pub fn set_context_dtb_override(&mut self, dtb: Dtb) {
        let dtb = self.normalize_dtb(dtb);
        self.context_dtb_override = Some(self.full_root(dtb));
    }

    /// `dtb`, or the full root of the process whose KVA-shadow user root it
    /// is. The probe is a read, not a walk, so a backend that serves kernel
    /// reads itself (KD) keeps the root it was given.
    fn full_root(&self, dtb: Dtb) -> Dtb {
        let Some(guest) = &self.guest else {
            return dtb;
        };
        let Ok(process_list) = guest.ntoskrnl.symbol("PsActiveProcessHead") else {
            return dtb;
        };
        if self
            .address_space(dtb)
            .read::<u64>(process_list.address())
            .is_ok()
        {
            return dtb;
        }
        guest
            .process_for_user_root(dtb, self.arch().dtb_page_mask())
            .map_or(dtb, |process| process.dtb)
    }

    pub fn clear_context_dtb_override(&mut self) {
        self.context_dtb_override = None;
    }

    /// Strip everything the architecture's dtb register carries besides the
    /// page-table base frame: a PCID on AMD64, an ASID on ARM64.
    pub fn normalize_dtb(&self, dtb: u64) -> Dtb {
        dtb & self.arch().dtb_page_mask()
    }

    pub fn set_current_windows_thread_context(&mut self, thread: ThreadInfo) {
        self.selected_frame = None;
        self.windows_thread_selection = Some(thread);
    }

    pub fn set_parked_windows_thread(&mut self, thread: ThreadInfo) {
        self.selected_frame = None;
        self.windows_thread_selection = Some(thread);
        // A parked thread has no coherent register file. In particular, do not
        // let expressions reuse registers cached from the still-selected vCPU.
        self.registers = None;
    }

    pub fn clear_current_windows_thread_context(&mut self) {
        self.windows_thread_selection = None;
    }

    pub fn thread_process_dtb(&self, thread: &ThreadInfo) -> Option<Dtb> {
        // A known owning EPROCESS answers with one read; only a thread whose
        // process pointer was unreadable needs the list walk by pid.
        if thread.pid != Some(0)
            && let Some(eprocess) = thread.eprocess
            && let Some(process) = self
                .guest
                .as_ref()
                .and_then(|guest| guest.process_at(eprocess).ok())
            && process.dtb != 0
        {
            return Some(process.dtb);
        }
        let processes = self
            .guest
            .as_ref()
            .and_then(|guest| guest.enumerate_processes().ok())
            .unwrap_or_default();
        select_thread_process_dtb(thread, self.process.as_ref(), &processes, self.kernel_dtb())
    }

    /// The process whose page-table root is `cr3_masked`, including a
    /// KVA-shadow user root. The selected Windows thread's owner is checked
    /// first: at a stop that is almost always the answer and costs one
    /// EPROCESS read, where the fallback walks the process list.
    pub fn process_for_cr3(&self, cr3_masked: u64) -> Option<ProcessInfo> {
        let guest = self.guest.as_ref()?;
        let mask = self.arch().dtb_page_mask();
        if let Some(eprocess) = self
            .windows_thread_selection
            .as_ref()
            .and_then(|thread| thread.eprocess)
            && let Ok(process) = guest.process_at(eprocess)
            && (process.dtb & mask) == cr3_masked
        {
            return Some(process);
        }
        guest
            .enumerate_processes()
            .ok()?
            .into_iter()
            .find(|process| (process.dtb & mask) == cr3_masked)
            .or_else(|| guest.process_for_user_root(cr3_masked, mask))
    }

    /// Read a cached register in a case-insensitive manner. The cache is
    /// populated from either the live backend context or a selected frame, so
    /// expression evaluation does not need to know which one is active.
    pub fn register_value(&self, name: &str) -> Option<u64> {
        lookup_register(self.registers.as_ref()?, name)
    }

    /// Enumerate processes matching `filter` (see [`process_matches`]); `None`
    /// returns all. The shared list helper behind the SDK/MCP process filters.
    ///
    /// Falls back to the triage EPROCESS snapshot when the full linked-list
    /// walk is unavailable (e.g. triage dumps with limited memory).
    pub fn matching_processes(&self, filter: Option<&str>) -> Result<Vec<ProcessInfo>> {
        let procs = match self.guest().and_then(|g| g.enumerate_processes()) {
            Ok(p) if !p.is_empty() => p,
            Ok(_) => self.triage_process_list().unwrap_or_default(),
            Err(Error::NtoskrnlNotFound) => self.triage_process_list()?,
            Err(e) => return Err(e),
        };
        Ok(match filter {
            None => procs,
            Some(f) => procs
                .into_iter()
                .filter(|p| process_matches(p, f))
                .collect(),
        })
    }

    /// Extract a single-entry process list from the triage EPROCESS snapshot.
    fn triage_process_list(&self) -> Result<Vec<ProcessInfo>> {
        let info = self.phys.dmp_info().ok_or(Error::NtoskrnlNotFound)?;
        let proc_snap = info
            .triage_process_snapshot
            .as_deref()
            .ok_or(Error::NtoskrnlNotFound)?;

        let dtb = self.kernel_dtb();
        let eprocess_layout = self
            .symbols
            .find_type_across_modules(dtb, "_EPROCESS")
            .ok_or(Error::ExpectedSymbols)?;

        let pid = eprocess_layout
            .field_offset("UniqueProcessId")
            .ok()
            .and_then(|off| {
                let off = off as usize;
                if off + 8 <= proc_snap.len() {
                    proc_snap[off..off + 8]
                        .try_into()
                        .ok()
                        .map(u64::from_le_bytes)
                } else {
                    None
                }
            })
            .unwrap_or(0);

        let name = eprocess_layout
            .field_offset("ImageFileName")
            .ok()
            .and_then(|off| {
                let off = off as usize;
                if off + 15 <= proc_snap.len() {
                    let buf = &proc_snap[off..off + 15];
                    let end = buf.iter().position(|&c| c == 0).unwrap_or(15);
                    let s = String::from_utf8_lossy(&buf[..end]).to_string();
                    if s.is_empty() { None } else { Some(s) }
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "<unknown>".to_string());

        Ok(vec![ProcessInfo {
            pid,
            name,
            // The header CR3 is unusable in a triage dump (no page tables
            // captured); reads go through the identity mapping, so report
            // the DTB that actually resolves.
            dtb: self.kernel_dtb(),
            eprocess_va: VirtAddr(0),
            wow64_peb: None,
        }])
    }

    pub fn selected_process_info(&self) -> Result<ProcessInfo> {
        if let Some(process) = self.process.as_ref() {
            return Ok(process.clone());
        }

        let processes = self.matching_processes(None)?;
        if let Some(thread) = self.windows_thread_selection.as_ref()
            && let Some(process) = processes
                .iter()
                .find(|process| thread_owner_matches(thread, process))
        {
            return Ok(process.clone());
        }
        let dtb = self.current_dtb();
        processes
            .into_iter()
            .find(|process| process.dtb == dtb)
            .ok_or_else(|| {
                Error::DebugInfo(
                    "current process unavailable: select a process or halted Windows thread"
                        .to_string(),
                )
            })
    }

    /// Pointer width of data layouts in the current scope: 32 under
    /// `.effmach x86` (a WOW64 process's x86 structures), else 64.
    pub fn data_bitness(&self) -> u32 {
        match self.effmach {
            Some(CODE_BITNESS_X86 | 0x14c) => CODE_BITNESS_X86,
            _ => CODE_BITNESS_AMD64,
        }
    }

    /// Select x86 or AMD64 decoding for a code address in the current scope.
    /// Module enumeration is intentionally local to this query so one caller
    /// can reuse the result for every instruction in its decode window.
    pub fn code_bitness(&self, address: VirtAddr) -> u32 {
        if self.effmach.is_some() {
            return decide_bitness(self.effmach, None, false, &[], address);
        }

        let cs = if self
            .selected_frame
            .as_ref()
            .is_some_and(|frame| !frame.is_live())
        {
            None
        } else {
            self.register_value("cs")
        };
        if decide_bitness(None, cs, false, &[], address) == CODE_BITNESS_X86 {
            return CODE_BITNESS_X86;
        }

        let is_wow64 = self.process.as_ref().is_some_and(ProcessInfo::is_wow64);
        if !is_wow64 {
            return CODE_BITNESS_AMD64;
        }

        let modules = self.modules().unwrap_or_default();
        decide_bitness(None, cs, true, &modules, address)
    }
}

#[cfg(test)]
mod tests {
    use super::{decide_bitness, select_thread_process_dtb, thread_owner_matches};
    use crate::guest::{ModuleInfo, ProcessInfo};
    use crate::target::{CODE_BITNESS_AMD64, CODE_BITNESS_X86, sample_thread};
    use crate::types::VirtAddr;

    #[test]
    fn code_bitness_prefers_explicit_context_and_wow64_images() {
        let mut x86 = ModuleInfo::new("wow.dll".into(), VirtAddr(0x400000), 0x1000);
        x86.is_32bit = true;
        let x64 = ModuleInfo::new("native.dll".into(), VirtAddr(0x0000_7ff6_0000_0000), 0x1000);

        assert_eq!(
            decide_bitness(
                Some(CODE_BITNESS_AMD64),
                Some(0x23),
                true,
                &[x86.clone()],
                VirtAddr(0x400100),
            ),
            CODE_BITNESS_AMD64
        );
        assert_eq!(
            decide_bitness(None, Some(0x23), false, &[], VirtAddr(0x7fff_0000),),
            CODE_BITNESS_X86
        );
        assert_eq!(
            decide_bitness(None, None, true, &[x86], VirtAddr(0x400100)),
            CODE_BITNESS_X86
        );
        assert_eq!(
            decide_bitness(None, None, true, &[x64], VirtAddr(0x0000_7ff6_0000_0100)),
            CODE_BITNESS_AMD64
        );
        assert_eq!(
            decide_bitness(None, None, false, &[], VirtAddr(0x7fff_0000)),
            CODE_BITNESS_AMD64
        );
    }

    #[test]
    fn owning_process_selection_prefers_eprocess_identity() {
        let thread = sample_thread();
        let same_pid_wrong_process = ProcessInfo {
            pid: thread.pid.unwrap(),
            name: "reused.exe".into(),
            dtb: 0x1111_0000,
            eprocess_va: VirtAddr(0xffff_8000_0000_9999),
            wow64_peb: None,
        };
        let owner = ProcessInfo {
            pid: 0x99,
            name: "sample.exe".into(),
            dtb: 0x2222_0000,
            eprocess_va: thread.eprocess.unwrap(),
            wow64_peb: None,
        };
        assert!(!thread_owner_matches(&thread, &same_pid_wrong_process));
        assert!(thread_owner_matches(&thread, &owner));
        assert_eq!(
            select_thread_process_dtb(
                &thread,
                Some(&same_pid_wrong_process),
                &[same_pid_wrong_process.clone(), owner.clone()],
                0x3333_0000,
            ),
            Some(0x2222_0000)
        );
    }
}
