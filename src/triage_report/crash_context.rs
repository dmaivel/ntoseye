use ntoseye_macros::record;

use crate::bytes::{c_string_lossy, get_u32, get_u64};
use crate::layout::TypeInfo;
use crate::target::Target;
use crate::time::filetime_to_iso;

/// The process and thread that crashed, as a triage dump recorded them: it
/// snapshots their `EPROCESS` and `ETHREAD` as raw bytes rather than as
/// mapped memory. A field is `None` if the dump does not record it.
#[record(impl)]
#[derive(Debug, Clone)]
pub struct TriageCrashInfo {
    pub process_name: Option<String>,
    pub process_id: Option<u64>,
    pub parent_process_id: Option<u64>,
    /// The process's exit status (NTSTATUS).
    pub exit_status: Option<i32>,
    /// When the process was created (FILETIME).
    pub create_time: Option<u64>,
    pub thread_id: Option<u64>,
    /// The thread's exit status (NTSTATUS).
    pub thread_exit_status: Option<i32>,
}

#[record]
impl TriageCrashInfo {
    /// When the process was created (ISO 8601 UTC). `None` if ntoseye cannot
    /// convert the recorded time.
    #[record(getter)]
    pub fn create_time_utc(&self) -> Option<String> {
        self.create_time.and_then(filetime_to_iso)
    }
}

impl TriageCrashInfo {
    /// The crashing process and thread a triage dump snapshots as raw
    /// `EPROCESS`/`ETHREAD` bytes, decoded with the kernel's type layouts.
    /// `None` when `target` is not a triage dump with a process snapshot or
    /// the kernel's symbols lack `_EPROCESS`.
    pub fn from_dump(target: &Target) -> Option<Self> {
        let info = target.phys.dmp_info()?;
        let proc_snap = info.triage_process_snapshot.as_deref()?;
        let dtb = target.kernel_dtb();

        let eprocess_layout = target.symbols.find_type_across_modules(dtb, "_EPROCESS")?;

        let process_name = eprocess_layout
            .field_offset("ImageFileName")
            .ok()
            .and_then(|off| {
                let off = off as usize;
                if off + 15 <= proc_snap.len() {
                    let s = c_string_lossy(&proc_snap[off..off + 15]);
                    if s.is_empty() { None } else { Some(s) }
                } else {
                    None
                }
            });

        let process_id = read_u64_field(proc_snap, &eprocess_layout, "UniqueProcessId");
        let parent_process_id =
            read_u64_field(proc_snap, &eprocess_layout, "InheritedFromUniqueProcessId");
        let exit_status = read_i32_field(proc_snap, &eprocess_layout, "ExitStatus");
        let create_time = read_u64_field(proc_snap, &eprocess_layout, "CreateTime");

        let (thread_id, thread_exit_status) = info
            .triage_thread_snapshot
            .as_deref()
            .and_then(|thread_snap| {
                let ethread_layout = target.symbols.find_type_across_modules(dtb, "_ETHREAD")?;
                let cid_off = ethread_layout.field_offset("Cid").ok()? as usize;
                let client_id_layout =
                    target.symbols.find_type_across_modules(dtb, "_CLIENT_ID")?;
                let ut_off = client_id_layout.field_offset("UniqueThread").ok()? as usize;
                let tid = get_u64(thread_snap, cid_off + ut_off);
                let exit_st = read_i32_field(thread_snap, &ethread_layout, "ExitStatus");
                Some((tid, exit_st))
            })
            .unwrap_or((None, None));

        Some(Self {
            process_name,
            process_id,
            parent_process_id,
            exit_status,
            create_time,
            thread_id,
            thread_exit_status,
        })
    }
}

fn read_u64_field(snap: &[u8], layout: &TypeInfo, field: &str) -> Option<u64> {
    get_u64(snap, layout.field_offset(field).ok()? as usize)
}

fn read_i32_field(snap: &[u8], layout: &TypeInfo, field: &str) -> Option<i32> {
    get_u32(snap, layout.field_offset(field).ok()? as usize).map(u32::cast_signed)
}
