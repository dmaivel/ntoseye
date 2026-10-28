//! Process enumeration and lookup: the `_EPROCESS` span read, process
//! names, WOW64 PEBs, and mapping a user root back to its process.

use super::{Guest, ProcessInfo};
use crate::arch::Arch;
use crate::{
    base::{
        bytes::before_nul,
        error::{Error, Result},
        memory::MemoryOps,
        types::*,
    },
    nt::target::{ListCursor, links_back_to},
};
use std::collections::HashSet;

/// `EPROCESS.ImageFileName` capacity: the kernel keeps this many bytes of the
/// image name, unterminated when the name is at least this long.
const IMAGE_FILE_NAME_LEN: usize = 15;

/// Whether `name`, an `ImageFileName` up to its NUL, may be the start of a
/// longer one. The kernel keeps 14 bytes of the image name and a NUL in the
/// field's 15, so `fontdrvhost.exe` reads `fontdrvhost.ex`; a shorter name
/// is complete as is.
fn may_be_truncated(name: &[u8]) -> bool {
    name.len() >= IMAGE_FILE_NAME_LEN - 1
}

/// The `_EPROCESS` fields process enumeration needs, fetched with one read
/// covering their span instead of one request per field over the transport.
struct EprocessSpan {
    arch: Arch,
    start: u64,
    bytes: Vec<u8>,
    unique_process_id_offset: u64,
    dir_table_base_offset: u64,
    active_process_links_offset: u64,
    image_file_name_offset: u64,
    /// `WoW64Process`, absent from an x86 kernel's `_EPROCESS`.
    wow64_process_offset: Option<u64>,
}

impl EprocessSpan {
    fn new(guest: &Guest) -> Result<Self> {
        let eprocess = guest.ntoskrnl.types().layout("_EPROCESS")?;
        let arch = guest.ntoskrnl.arch();
        let pointer_size = arch.pointer_size();
        let kprocess = guest.ntoskrnl.types().layout("_KPROCESS")?;
        let unique_process_id_offset = eprocess.field_offset("UniqueProcessId")?;
        let dir_table_base_offset =
            eprocess.field_offset("Pcb")? + kprocess.field_offset("DirectoryTableBase")?;
        let active_process_links_offset = eprocess.field_offset("ActiveProcessLinks")?;
        let image_file_name_offset = eprocess.field_offset("ImageFileName")?;
        let wow64_process_offset = eprocess
            .field_offset("WoW64Process")
            .or_else(|_| eprocess.field_offset("Wow64Process"))
            .ok();
        let start = unique_process_id_offset
            .min(dir_table_base_offset)
            .min(active_process_links_offset)
            .min(image_file_name_offset)
            .min(wow64_process_offset.unwrap_or(u64::MAX));
        let end = (unique_process_id_offset + pointer_size)
            .max(dir_table_base_offset + pointer_size)
            .max(active_process_links_offset + pointer_size)
            .max(image_file_name_offset + IMAGE_FILE_NAME_LEN as u64)
            .max(wow64_process_offset.map_or(0, |offset| offset + pointer_size));
        Ok(Self {
            arch,
            start,
            bytes: vec![0u8; (end - start) as usize],
            unique_process_id_offset,
            dir_table_base_offset,
            active_process_links_offset,
            image_file_name_offset,
            wow64_process_offset,
        })
    }

    fn read(&mut self, memory: &impl MemoryOps<VirtAddr>, eprocess: VirtAddr) -> Result<()> {
        memory.read_bytes(eprocess + self.start, &mut self.bytes)
    }

    fn pointer_at(&self, offset: u64) -> VirtAddr {
        let start = (offset - self.start) as usize;
        self.arch.decode_pointer(&self.bytes[start..])
    }

    fn pid(&self) -> u64 {
        self.pointer_at(self.unique_process_id_offset).0
    }

    fn dtb(&self) -> Dtb {
        self.pointer_at(self.dir_table_base_offset).0 & !0xfff
    }

    fn active_process_links_flink(&self) -> VirtAddr {
        self.pointer_at(self.active_process_links_offset)
    }

    fn image_file_name(&self) -> &[u8] {
        let start = (self.image_file_name_offset - self.start) as usize;
        &self.bytes[start..start + IMAGE_FILE_NAME_LEN]
    }

    /// `_EPROCESS.WoW64Process`: null for a native process.
    fn wow64_process(&self) -> Option<VirtAddr> {
        self.wow64_process_offset
            .map(|offset| self.pointer_at(offset))
            .filter(|pointer| !pointer.is_zero())
    }
}

impl Guest {
    pub fn enumerate_processes(&self) -> Result<Vec<ProcessInfo>> {
        self.memoized(|memo| &mut memo.processes, || self.walk_processes())
    }

    fn walk_processes(&self) -> Result<Vec<ProcessInfo>> {
        let memory = self.ntoskrnl.memory();
        let mut span = EprocessSpan::new(self)?;

        let ps_initial_system_process = self
            .ntoskrnl
            .symbol("PsInitialSystemProcess")?
            .read_pointer()?;
        let ps_active_process_head = self
            .ntoskrnl
            .symbol("PsActiveProcessHead")
            .ok()
            .map(|s| s.address());

        let blink_offset = memory.arch().pointer_size();
        let mut processes = Vec::new();
        let mut reached = HashSet::new();
        let mut broken = None;

        // Cycle detection handles a corrupt list that loops; the cap handles
        // one that wanders through unrelated memory without repeating.
        const PROCESS_WALK_LIMIT: usize = 65_536;
        let mut cursor = ListCursor::from_first(ps_initial_system_process, PROCESS_WALK_LIMIT);
        while let Some(current_eprocess) = cursor.take_current() {
            if let Err(error) = span.read(&memory, current_eprocess) {
                broken = Some(error);
                break;
            }
            if span.dtb() == 0 {
                break;
            }
            reached.insert(current_eprocess + span.active_process_links_offset);
            processes.push(self.process_from_span(current_eprocess, &span));

            // PsActiveProcessHead is not embedded in an EPROCESS, so reaching
            // it ends the walk before the link becomes a record address.
            let flink = span.active_process_links_flink();
            if flink.is_zero() || Some(flink) == ps_active_process_head {
                break;
            }
            cursor.advance(Ok(flink - span.active_process_links_offset));
        }
        // A process that cannot be read ends the walk forward; the ones past
        // it are found backward from the list head, and only its is missing.
        if let Some(error) = broken {
            if let Some(head) = ps_active_process_head {
                let tail = links_back_to(head, &reached, PROCESS_WALK_LIMIT, |link| {
                    memory.read_pointer(link + blink_offset)
                });
                for link in tail.into_iter().rev() {
                    let eprocess = link - span.active_process_links_offset;
                    if span.read(&memory, eprocess).is_ok() && span.dtb() != 0 {
                        processes.push(self.process_from_span(eprocess, &span));
                    }
                }
            }
            if processes.is_empty() {
                return Err(error);
            }
        }

        Ok(processes)
    }

    /// The process whose `_EPROCESS` at `eprocess` `span` has just read.
    fn process_from_span(&self, eprocess: VirtAddr, span: &EprocessSpan) -> ProcessInfo {
        let dtb = span.dtb();
        ProcessInfo {
            pid: span.pid(),
            name: self.process_name_from_image_file_name(eprocess, dtb, span.image_file_name()),
            dtb,
            eprocess,
            wow64_peb: self.wow64_peb(dtb, span.wow64_process()),
        }
    }

    /// The process at `eprocess_va` without walking the process list: one
    /// EPROCESS span read plus the PEB walk only for a possibly truncated
    /// name.
    pub fn process_at(&self, eprocess_va: VirtAddr) -> Result<ProcessInfo> {
        let mut span = EprocessSpan::new(self)?;
        span.read(&self.ntoskrnl.memory(), eprocess_va)?;
        Ok(self.process_from_span(eprocess_va, &span))
    }

    /// Whether process `pid`, whose page-table root is `dtb`, has exited:
    /// it has left the active process list, or is still on it with
    /// `ExitTime` set, its threads gone and its user address space torn down
    /// or about to be. An error when the list or the process cannot be read,
    /// which says nothing either way; an empty list was not read either,
    /// since every system has its System process.
    pub fn process_exited(&self, pid: u64, dtb: Dtb) -> Result<bool> {
        let processes = self.enumerate_processes()?;
        if processes.is_empty() {
            return Ok(false);
        }
        let Some(process) = processes
            .into_iter()
            .find(|process| process.pid == pid && process.dtb == dtb)
        else {
            return Ok(true);
        };
        let exit_time: u64 = self
            .ntoskrnl
            .types()
            .struct_at("_EPROCESS", process.eprocess)?
            .read_field("ExitTime")?;
        Ok(exit_time != 0)
    }

    /// The process whose KVA-shadow user root is `user_root`
    /// (`_KPROCESS.UserDirectoryTableBase`), compared under `mask`. `None`
    /// when no process owns it or the kernel has no shadow roots.
    pub fn process_for_user_root(&self, user_root: Dtb, mask: u64) -> Option<ProcessInfo> {
        let user_root_offset = self.user_root_offset()?;
        let memory = self.ntoskrnl.memory();
        self.enumerate_processes()
            .ok()?
            .into_iter()
            .find(|process| {
                memory
                    .read_pointer(process.eprocess + user_root_offset)
                    .is_ok_and(|root| root.0 & mask == user_root)
            })
    }

    /// The KVA-shadow root user mode runs `process` on
    /// (`_KPROCESS.UserDirectoryTableBase`), masked with `mask`. `None` when
    /// the process has none (no KVA shadow) or the field is unreadable.
    pub fn user_root(&self, process: &ProcessInfo, mask: u64) -> Option<Dtb> {
        let root = self
            .ntoskrnl
            .memory()
            .read_pointer(process.eprocess + self.user_root_offset()?)
            .ok()?
            .0
            & mask;
        (root != 0).then_some(root)
    }

    fn user_root_offset(&self) -> Option<u64> {
        let types = self.ntoskrnl.types();
        Some(
            types.layout("_EPROCESS").ok()?.field_offset("Pcb").ok()?
                + types
                    .layout("_KPROCESS")
                    .ok()?
                    .field_offset("UserDirectoryTableBase")
                    .ok()?,
        )
    }

    /// The 32-bit PEB behind `_EPROCESS.WoW64Process`: since Windows 10 1511
    /// the pointer is to an `_EWOW64PROCESS` holding it, before that it was
    /// the PEB itself. Unreadable is reported as native rather than failing
    /// process enumeration.
    fn wow64_peb(&self, dtb: Dtb, wow64_process: Option<VirtAddr>) -> Option<VirtAddr> {
        let pointer = wow64_process?;
        let types = self.ntoskrnl.types_in(dtb);
        let peb = match types.struct_at("_EWOW64PROCESS", pointer) {
            Ok(ewow64) => ewow64.read_pointer("Peb").ok()?,
            Err(Error::StructNotFound(_)) => pointer,
            Err(_) => return None,
        };
        (!peb.is_zero()).then_some(peb)
    }

    /// Display name for the process at `eprocess_va` given its raw
    /// `EPROCESS.ImageFileName` bytes. The PEB loader list (a page-walked
    /// read of user memory) is consulted only for a name that may be
    /// truncated (see [`may_be_truncated`]).
    fn process_name_from_image_file_name(
        &self,
        eprocess_va: VirtAddr,
        dtb: Dtb,
        image_file_name: &[u8],
    ) -> String {
        let name = before_nul(image_file_name);
        if may_be_truncated(name)
            && dtb != 0
            && let Ok(full) = self.full_process_name(eprocess_va, dtb)
        {
            return full;
        }
        if name.is_empty() {
            return "<unknown>".to_string();
        }
        String::from_utf8_lossy(name).into_owned()
    }

    /// Display name for the process at `eprocess_va` without walking the
    /// process list: the `ImageFileName` read plus, only for a possibly
    /// truncated name, the process DTB and PEB walk.
    pub fn process_name_at(&self, eprocess_va: VirtAddr) -> Option<String> {
        let mut span = EprocessSpan::new(self).ok()?;
        span.read(&self.ntoskrnl.memory(), eprocess_va).ok()?;
        if span.image_file_name()[0] == 0 {
            return None;
        }
        Some(self.process_name_from_image_file_name(
            eprocess_va,
            span.dtb(),
            span.image_file_name(),
        ))
    }

    fn full_process_name(&self, eprocess_va: VirtAddr, dtb: Dtb) -> Result<String> {
        // The process dtb maps both the kernel _EPROCESS and the user-space PEB
        // it points at, so the whole walk reads through one address space:
        // ntoskrnl's kernel types viewed in the process's space.
        let eprocess = self
            .ntoskrnl
            .types_in(dtb)
            .struct_at("_EPROCESS", eprocess_va)?;

        let peb = eprocess.follow("Peb")?;
        let image_base = peb.read_pointer("ImageBaseAddress")?;
        if image_base.is_zero() {
            return Err(Error::MissingImageBase);
        }

        for record in peb.follow("Ldr")?.list(
            "InLoadOrderModuleList",
            "_LDR_DATA_TABLE_ENTRY",
            "InLoadOrderLinks",
        )? {
            let record = record?;
            let dll_base = record.read_pointer("DllBase")?;
            if dll_base == image_base {
                return record.unicode_string("BaseDllName");
            }
        }

        Err(Error::MissingImage)
    }
}

#[cfg(test)]
mod tests {
    use super::may_be_truncated;

    #[test]
    fn a_name_that_fills_the_field_may_be_truncated() {
        assert!(may_be_truncated(b"fontdrvhost.ex"));
        assert!(!may_be_truncated(b"svchost.exe"));
    }
}
