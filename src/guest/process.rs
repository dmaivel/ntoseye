//! Process enumeration and lookup: the `_EPROCESS` span read, process
//! names, WOW64 PEBs, and mapping a user root back to its process.

use super::{Guest, ProcessInfo};
use crate::{
    backend::MemoryOps,
    bytes::read_u64,
    error::{Error, Result},
    target::ListCursor,
    types::*,
};

/// `EPROCESS.ImageFileName` capacity: the kernel keeps this many bytes of the
/// image name, unterminated when the name is at least this long.
const IMAGE_FILE_NAME_LEN: usize = 15;

/// The `_EPROCESS` fields process enumeration needs, fetched with one read
/// covering their span instead of one request per field over the transport.
struct EprocessSpan {
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
        let end = (unique_process_id_offset + 8)
            .max(dir_table_base_offset + 8)
            .max(active_process_links_offset + 8)
            .max(image_file_name_offset + IMAGE_FILE_NAME_LEN as u64)
            .max(wow64_process_offset.map_or(0, |offset| offset + 8));
        Ok(Self {
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

    fn u64_at(&self, offset: u64) -> u64 {
        let start = (offset - self.start) as usize;
        read_u64(&self.bytes, start)
    }

    fn pid(&self) -> u64 {
        self.u64_at(self.unique_process_id_offset)
    }

    fn dtb(&self) -> Dtb {
        self.u64_at(self.dir_table_base_offset) & !0xfff
    }

    fn active_process_links_flink(&self) -> VirtAddr {
        VirtAddr(self.u64_at(self.active_process_links_offset))
    }

    fn image_file_name(&self) -> &[u8] {
        let start = (self.image_file_name_offset - self.start) as usize;
        &self.bytes[start..start + IMAGE_FILE_NAME_LEN]
    }

    /// `_EPROCESS.WoW64Process`: null for a native process.
    fn wow64_process(&self) -> Option<VirtAddr> {
        self.wow64_process_offset
            .map(|offset| VirtAddr(self.u64_at(offset)))
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

        let ps_initial_system_process: VirtAddr =
            self.ntoskrnl.symbol("PsInitialSystemProcess")?.read()?;
        let ps_active_process_head = self
            .ntoskrnl
            .symbol("PsActiveProcessHead")
            .ok()
            .map(|s| s.address());

        let mut processes = Vec::new();

        // Cycle detection handles a corrupt list that loops; the cap handles
        // one that wanders through unrelated memory without repeating.
        const PROCESS_WALK_LIMIT: usize = 65_536;
        let mut cursor = ListCursor::from_first(ps_initial_system_process, PROCESS_WALK_LIMIT);
        while let Some(current_eprocess) = cursor.take_current() {
            span.read(&memory, current_eprocess)?;
            let dtb = span.dtb();
            if dtb == 0 {
                break;
            }

            processes.push(ProcessInfo {
                pid: span.pid(),
                name: self.process_name_from_image_file_name(
                    current_eprocess,
                    dtb,
                    span.image_file_name(),
                ),
                dtb,
                eprocess_va: current_eprocess,
                wow64_peb: self.wow64_peb(dtb, span.wow64_process()),
            });

            // PsActiveProcessHead is not embedded in an EPROCESS, so reaching
            // it ends the walk before the link becomes a record address.
            let flink = span.active_process_links_flink();
            if flink.is_zero() || Some(flink) == ps_active_process_head {
                break;
            }
            cursor.advance(Ok(flink - span.active_process_links_offset));
        }

        Ok(processes)
    }

    /// The process at `eprocess_va` without walking the process list: one
    /// EPROCESS span read plus the PEB walk only for a possibly truncated
    /// name.
    pub fn process_at(&self, eprocess_va: VirtAddr) -> Result<ProcessInfo> {
        let mut span = EprocessSpan::new(self)?;
        span.read(&self.ntoskrnl.memory(), eprocess_va)?;
        let dtb = span.dtb();
        Ok(ProcessInfo {
            pid: span.pid(),
            name: self.process_name_from_image_file_name(eprocess_va, dtb, span.image_file_name()),
            dtb,
            eprocess_va,
            wow64_peb: self.wow64_peb(dtb, span.wow64_process()),
        })
    }

    /// The process whose KVA-shadow user root is `user_root`
    /// (`_KPROCESS.UserDirectoryTableBase`), compared under `mask`. `None`
    /// when no process owns it or the kernel has no shadow roots.
    pub fn process_for_user_root(&self, user_root: Dtb, mask: u64) -> Option<ProcessInfo> {
        let types = self.ntoskrnl.types();
        let user_root_offset = types.layout("_EPROCESS").ok()?.field_offset("Pcb").ok()?
            + types
                .layout("_KPROCESS")
                .ok()?
                .field_offset("UserDirectoryTableBase")
                .ok()?;
        let memory = self.ntoskrnl.memory();
        self.enumerate_processes()
            .ok()?
            .into_iter()
            .find(|process| {
                memory
                    .read::<u64>(process.eprocess_va + user_root_offset)
                    .is_ok_and(|root| root & mask == user_root)
            })
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
    /// `EPROCESS.ImageFileName` bytes. The kernel keeps only the first 15
    /// bytes of the image name, so the PEB loader list (a page-walked read of
    /// user memory) is consulted only when the field is full and may be
    /// truncated; every shorter name is complete as is.
    fn process_name_from_image_file_name(
        &self,
        eprocess_va: VirtAddr,
        dtb: Dtb,
        image_file_name: &[u8],
    ) -> String {
        let len = image_file_name
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(image_file_name.len());
        if len == IMAGE_FILE_NAME_LEN
            && dtb != 0
            && let Ok(full) = self.full_process_name(eprocess_va, dtb)
        {
            return full;
        }
        if len == 0 {
            return "<unknown>".to_string();
        }
        String::from_utf8_lossy(&image_file_name[..len]).to_string()
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
        let image_base: VirtAddr = peb.read_field("ImageBaseAddress")?;
        if image_base.is_zero() {
            return Err(Error::MissingImageBase);
        }

        for record in peb.follow("Ldr")?.list(
            "InLoadOrderModuleList",
            "_LDR_DATA_TABLE_ENTRY",
            "InLoadOrderLinks",
        )? {
            let record = record?;
            let dll_base: VirtAddr = record.read_field("DllBase")?;
            if dll_base == image_base {
                return record.unicode_string("BaseDllName");
            }
        }

        Err(Error::MissingImage)
    }
}
