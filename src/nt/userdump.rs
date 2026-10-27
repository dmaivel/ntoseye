//! Windows user-mode minidumps (`MDMP`), as `MiniDumpWriteDump`, Windows
//! Error Reporting, Task Manager, and procdump write them: one process's
//! threads, modules, and the parts of its address space the dump captured.
//!
//! A user dump has no kernel, no physical memory, and no page tables. Its
//! memory is a set of captured virtual ranges, served to the address space
//! directly (see [`UserDump::read_virtual`]); the target built over it lists
//! the dump's own modules and threads rather than discovering a kernel.

use std::fs::File;
use std::io::{ErrorKind, Read};
use std::path::Path;

use memmap2::Mmap;
use ntoseye_macros::record;

use crate::arch::Arch;
use crate::base::error::{Error, Result};
use crate::base::types::VirtAddr;
use crate::nt::guest::ModuleInfo;
use crate::nt::pe::headers::CodeView;
use crate::nt::target::mm::{memory_state_name, memory_type_name, page_protection_name};

pub mod backend;
pub mod parse;
#[cfg(test)]
mod tests;
pub mod write;

pub use backend::UserDumpBackend;
pub use parse::is_minidump;

/// `SystemInfoStream`: the machine and Windows version the process ran on.
#[derive(Debug, Clone)]
pub struct UserSystemInfo {
    pub processor_level: u16,
    pub processor_revision: u16,
    pub number_of_processors: u8,
    /// `VER_NT_WORKSTATION` (1), `VER_NT_DOMAIN_CONTROLLER` (2),
    /// `VER_NT_SERVER` (3).
    pub product_type: u8,
    pub major_version: u32,
    pub minor_version: u32,
    pub build_number: u32,
    /// The service-pack string (`CSDVersionRva`), when one is recorded.
    pub service_pack: Option<String>,
}

/// The process a user-mode minidump captured (`dbg.user_dump.process`).
#[record]
pub struct UserProcessInfo {
    /// The process id, when the dump records it.
    pub pid: Option<u32>,
    /// The executable's file name, from the first module the dump lists.
    pub name: Option<String>,
}

/// What the dump's thread-info stream (`ThreadInfoListStream`) records of
/// a thread: what the kernel knew of it.
#[record]
pub struct UserThreadTimes {
    /// The thread's exit status.
    #[record(hex)]
    pub exit_status: u32,
    /// When the thread started, as a FILETIME.
    pub create_time: u64,
    /// When the thread exited, as a FILETIME (0 while it runs).
    pub exit_time: u64,
    /// Kernel-mode time the thread had run, in 100 ns units.
    pub kernel_time: u64,
    /// User-mode time the thread had run, in 100 ns units.
    pub user_time: u64,
    /// The thread's start address.
    #[record(hex)]
    pub start_address: u64,
    /// The thread's processor affinity mask.
    #[record(hex)]
    pub affinity: u64,
}

/// The part of a thread's stack that a dump captured.
#[record]
#[derive(Copy)]
pub struct CapturedStack {
    #[record(hex)]
    pub start: u64,
    /// Its size in bytes.
    #[record(hex)]
    pub size: u64,
}

/// A thread of the captured process (`MINIDUMP_THREAD`), with what the
/// thread-info and thread-name streams add, matched by thread id.
#[record(impl)]
pub struct UserThreadInfo {
    /// The thread id.
    pub tid: u32,
    pub suspend_count: u32,
    pub priority_class: u32,
    pub priority: u32,
    /// The `_TEB` address, 0 when the dump records none.
    #[record(hex)]
    pub teb: u64,
    /// The captured stack, `None` when the dump holds none of it.
    pub stack: Option<CapturedStack>,
    /// The thread's raw CONTEXT at the dump, or why it is unusable.
    #[record(skip)]
    pub context: std::result::Result<Vec<u8>, String>,
    /// The thread's description (`SetThreadDescription`), when the dump
    /// records one.
    pub name: Option<String>,
    /// What the dump's thread-info stream records of the thread, when it
    /// has one.
    pub times: Option<UserThreadTimes>,
}

#[record]
impl UserThreadInfo {
    /// Why the thread's recorded context is unusable, or `None` when it is
    /// usable.
    #[record(getter)]
    pub fn context_error(&self) -> Option<String> {
        self.context.as_ref().err().cloned()
    }
}

/// A loaded module (`MINIDUMP_MODULE`).
#[derive(Debug, Clone)]
pub struct UserModule {
    pub base: u64,
    pub size: u32,
    pub checksum: u32,
    pub time_date_stamp: u32,
    /// The full path the loader recorded.
    pub path: String,
    /// File and product version from the module's `VS_FIXEDFILEINFO`.
    pub version: Option<(String, String)>,
    /// The module's CodeView record, which names its PDB whether or not the
    /// image's own pages are in the dump.
    pub codeview: Option<CodeView>,
}

/// A module the process had unloaded (`UnloadedModuleListStream`).
#[record]
#[derive(Debug, Clone)]
pub struct UnloadedModule {
    #[record(hex)]
    pub base: u64,
    #[record(hex)]
    pub size: u32,
    #[record(hex)]
    pub checksum: u32,
    #[record(hex)]
    pub time_date_stamp: u32,
    pub name: String,
}

/// The exception a user-mode minidump was written for (`ExceptionStream`).
#[record(impl)]
#[derive(Debug, Clone)]
pub struct UserException {
    /// The thread that raised it.
    pub thread_id: u32,
    /// The exception code (an NTSTATUS, or an application's own code).
    #[record(hex)]
    pub code: u32,
    #[record(hex)]
    pub flags: u32,
    /// The address of a chained `EXCEPTION_RECORD`, 0 for none.
    #[record(hex)]
    pub record: u64,
    /// Where the exception was raised.
    #[record(hex)]
    pub address: u64,
    #[record(hex)]
    pub parameters: Vec<u64>,
    /// The raw CONTEXT at the exception, or why it is unusable. It is stored
    /// in the dump file, not in the process's memory.
    #[record(skip)]
    pub context: std::result::Result<Vec<u8>, String>,
}

#[record]
impl UserException {
    /// The NTSTATUS name of `code`, when it is one ntoseye knows.
    #[record(getter)]
    pub fn code_name(&self) -> Option<&'static str> {
        crate::base::ntstatus::ntstatus_name(self.code)
    }

    /// Why the exception's CONTEXT is unusable, `None` when it is.
    #[record(getter)]
    pub fn context_error(&self) -> Option<String> {
        self.context.as_ref().err().cloned()
    }
}

/// What a user dump records besides its memory.
#[derive(Debug, Clone)]
pub struct UserDumpInfo {
    /// `MINIDUMP_HEADER.TimeDateStamp`: when the dump was written, in
    /// seconds since 1970 (UTC).
    pub time_date_stamp: u32,
    /// `MINIDUMP_TYPE` flags the dump was written with.
    pub flags: u64,
    pub arch: Arch,
    pub system: UserSystemInfo,
    pub process_id: Option<u32>,
    /// Process creation, in seconds since 1970 (UTC).
    pub process_create_time: Option<u32>,
    /// User-mode and kernel-mode time the process had run, in seconds, as
    /// `(user, kernel)`.
    pub process_cpu_times: Option<(u32, u32)>,
    /// The time zone the system was in when the dump was written.
    pub time_zone: Option<UserTimeZone>,
    /// `MINIDUMP_MISC_INFO_4.BuildString`.
    pub build_string: Option<String>,
    pub threads: Vec<UserThreadInfo>,
    pub modules: Vec<UserModule>,
    pub unloaded_modules: Vec<UnloadedModule>,
    pub exception: Option<UserException>,
    /// `HandleDataStream`, `None` when the dump has none.
    pub handles: Option<Vec<UserHandle>>,
    /// `MemoryInfoListStream`, sorted by base, `None` when the dump has none.
    pub regions: Option<Vec<MemoryRegion>>,
    /// `FunctionTableStream`: the dynamic function tables (code no module
    /// holds, such as JIT-compiled code) the process had registered.
    pub function_tables: Vec<FunctionTable>,
    /// What was dropped or cut short while parsing, and why.
    pub notes: Vec<String>,
}

/// `MINIDUMP_MISC_INFO_3.TimeZone`, with `TimeZoneId` choosing the bias in
/// effect when the dump was written.
#[derive(Debug, Clone)]
pub struct UserTimeZone {
    /// Minutes to add to local time to get UTC, daylight saving included
    /// when it was in effect.
    pub bias: i32,
    /// The zone's name for the period in effect (`StandardName` or
    /// `DaylightName`).
    pub name: String,
}

/// A handle the process held (`MINIDUMP_HANDLE_DESCRIPTOR` or
/// `MINIDUMP_HANDLE_DESCRIPTOR_2`), as the dump records it. The dump names
/// no object address.
#[record(impl)]
#[derive(Debug, Clone)]
pub struct UserHandle {
    #[record(hex)]
    pub handle: u64,
    pub type_name: Option<String>,
    pub object_name: Option<String>,
    /// `OBJ_*` attribute flags.
    #[record(hex)]
    pub attributes: u32,
    #[record(hex)]
    pub granted_access: u32,
    pub handle_count: u32,
    pub pointer_count: u32,
    /// What Windows reported of the object when the dump was written: a
    /// `MINIDUMP_HANDLE_DESCRIPTOR_2`'s object information, for the types
    /// it records any for. `None` when the dump records none.
    pub object_info: Option<HandleObjectInfo>,
}

#[record]
impl UserHandle {
    /// `attributes` as `OBJ_*` names.
    #[record(getter)]
    pub fn attribute_names(&self) -> Vec<String> {
        crate::nt::target::usermode::handles::handle_attribute_names(self.attributes)
    }
}

/// A handle's object, as the information class `NtQueryInformationThread`,
/// `NtQueryEvent` and the like return for its type reported it.
#[record]
#[derive(Debug, Clone)]
pub enum HandleObjectInfo {
    Thread(HandleThreadInfo),
    Process(HandleProcessInfo),
    Event(HandleEventInfo),
    Mutant(HandleMutantInfo),
    Semaphore(HandleSemaphoreInfo),
    Section(HandleSectionInfo),
    /// A kind of information ntoseye does not decode.
    Other(HandleOtherInfo),
}

/// A thread (`THREAD_BASIC_INFORMATION`).
#[record]
#[derive(Debug, Clone)]
pub struct HandleThreadInfo {
    /// `STATUS_PENDING` (0x103) while the thread runs.
    #[record(hex)]
    pub exit_status: u32,
    #[record(hex)]
    pub teb: u64,
    #[record(hex)]
    pub process_id: u64,
    #[record(hex)]
    pub thread_id: u64,
    #[record(hex)]
    pub affinity: u64,
    pub priority: i32,
    pub base_priority: i32,
}

/// A process (`PROCESS_BASIC_INFORMATION`).
#[record]
#[derive(Debug, Clone)]
pub struct HandleProcessInfo {
    /// `STATUS_PENDING` (0x103) while the process runs.
    #[record(hex)]
    pub exit_status: u32,
    #[record(hex)]
    pub peb: u64,
    #[record(hex)]
    pub affinity: u64,
    pub base_priority: i32,
    #[record(hex)]
    pub process_id: u64,
    #[record(hex)]
    pub parent_process_id: u64,
}

/// An event (`EVENT_BASIC_INFORMATION`).
#[record]
#[derive(Debug, Clone)]
pub struct HandleEventInfo {
    /// A notification event, which stays set until reset; otherwise a
    /// synchronization event, which a satisfied wait resets.
    pub manual_reset: bool,
    pub signaled: bool,
}

/// A mutant (`MUTANT_BASIC_INFORMATION`, and `MUTANT_OWNER_INFORMATION`
/// when the dump records the owner).
#[record]
#[derive(Debug, Clone)]
pub struct HandleMutantInfo {
    /// 1 when free; 0 or less when owned, by recursion depth.
    pub current_count: i32,
    pub owned_by_caller: bool,
    pub abandoned: bool,
    /// The owning thread's process and thread IDs, zero when free.
    #[record(hex)]
    pub owner_process_id: Option<u64>,
    #[record(hex)]
    pub owner_thread_id: Option<u64>,
}

/// A semaphore (`SEMAPHORE_BASIC_INFORMATION`).
#[record]
#[derive(Debug, Clone)]
pub struct HandleSemaphoreInfo {
    pub current_count: i32,
    pub maximum_count: i32,
}

/// A section (`SECTION_BASIC_INFORMATION`).
#[record]
#[derive(Debug, Clone)]
pub struct HandleSectionInfo {
    /// The base of a based section; 0 otherwise.
    #[record(hex)]
    pub base_address: u64,
    /// The `SEC_*` allocation attributes.
    #[record(hex)]
    pub attributes: u32,
    #[record(hex)]
    pub maximum_size: u64,
}

/// Object information of a kind ntoseye does not decode
/// (`MINIDUMP_HANDLE_OBJECT_INFORMATION_TYPE`).
#[record]
#[derive(Debug, Clone)]
pub struct HandleOtherInfo {
    pub kind: u32,
    /// Its size in bytes.
    pub size: u32,
}

/// `MINIDUMP_MEMORY_INFO`: one region of the address space, as
/// `VirtualQueryEx` reported it.
#[record(impl)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryRegion {
    #[record(hex)]
    pub base: u64,
    #[record(hex)]
    pub allocation_base: u64,
    #[record(hex)]
    pub allocation_protect: u32,
    #[record(hex)]
    pub size: u64,
    /// `MEM_COMMIT`, `MEM_RESERVE`, or `MEM_FREE`.
    #[record(hex)]
    pub state: u32,
    #[record(hex)]
    pub protect: u32,
    /// `MEM_IMAGE`, `MEM_MAPPED`, `MEM_PRIVATE`, or 0 for a free region.
    #[record(hex)]
    pub kind: u32,
}

#[record]
impl MemoryRegion {
    /// `allocation_protect` as `PAGE_*` names.
    #[record(getter)]
    pub fn allocation_protect_name(&self) -> String {
        page_protection_name(self.allocation_protect)
    }

    /// `MEM_COMMIT`, `MEM_RESERVE`, or `MEM_FREE`.
    #[record(getter)]
    pub fn state_name(&self) -> &'static str {
        memory_state_name(self.state)
    }

    /// `protect` as `PAGE_*` names; empty for a free or reserved region.
    #[record(getter)]
    pub fn protect_name(&self) -> String {
        page_protection_name(self.protect)
    }

    /// `MEM_IMAGE`, `MEM_MAPPED`, or `MEM_PRIVATE`; empty for a free region.
    #[record(getter)]
    pub fn kind_name(&self) -> &'static str {
        memory_type_name(self.kind)
    }
}

/// A dynamic function table (`MINIDUMP_FUNCTION_TABLE_DESCRIPTOR`): the
/// unwind entries for code at `minimum..maximum`, relative to `base`. The
/// entries' unwind data is in process memory, not in the stream.
#[derive(Debug, Clone)]
pub struct FunctionTable {
    pub minimum: u64,
    pub maximum: u64,
    pub base: u64,
    /// Sorted by `begin`.
    pub entries: Vec<DynamicFunction>,
}

/// An AMD64 `RUNTIME_FUNCTION` of a dynamic function table: offsets from
/// the table's base.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DynamicFunction {
    pub begin: u32,
    pub end: u32,
    pub unwind_data: u32,
}

/// A captured range of process memory and where its bytes are in the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryRange {
    pub start: u64,
    pub length: u64,
    pub offset: u64,
}

impl UserModule {
    /// The image's file name, the last component of its path.
    pub fn file_name(&self) -> &str {
        self.path.rsplit(['\\', '/']).next().unwrap_or(&self.path)
    }

    /// The module as the target lists it: named by its file name, with its
    /// path, timestamp, checksum, version, and CodeView record.
    pub fn to_module_info(&self) -> ModuleInfo {
        let mut info =
            ModuleInfo::new(self.file_name().to_string(), VirtAddr(self.base), self.size)
                .with_time_date_stamp(self.time_date_stamp)
                .with_checksum(self.checksum);
        info.path = Some(self.path.clone());
        if let Some((file, product)) = &self.version {
            info = info.with_version_info(file.clone(), product.clone());
        }
        info.codeview = self.codeview.clone();
        info
    }
}

impl UserDumpInfo {
    /// The process's image name, from the first module the dump lists (the
    /// executable).
    pub fn process_name(&self) -> Option<&str> {
        self.modules.first().map(UserModule::file_name)
    }

    /// The captured process, as far as the dump records it.
    pub fn process(&self) -> UserProcessInfo {
        UserProcessInfo {
            pid: self.process_id,
            name: self.process_name().map(str::to_string),
        }
    }

    /// `charmap.exe (PID 1234)`, as far as the dump records it.
    pub fn process_label(&self) -> String {
        let name = self.process_name().unwrap_or("process");
        match self.process_id {
            Some(pid) => format!("{name} (PID {pid})"),
            None => name.to_string(),
        }
    }

    pub fn thread(&self, tid: u32) -> Option<&UserThreadInfo> {
        self.threads.iter().find(|thread| thread.tid == tid)
    }

    /// The dynamic function covering `address`, with the base of its table:
    /// what unwinds code no module holds.
    pub fn dynamic_function(&self, address: u64) -> Option<(u64, DynamicFunction)> {
        self.function_tables
            .iter()
            .filter(|table| (table.minimum..table.maximum).contains(&address))
            .find_map(|table| {
                let offset = u32::try_from(address.checked_sub(table.base)?).ok()?;
                let index = table.entries.partition_point(|entry| entry.begin <= offset);
                let entry = table.entries.get(index.checked_sub(1)?)?;
                (offset < entry.end).then_some((table.base, *entry))
            })
    }

    /// The region of the memory-info list holding `address`.
    pub fn region(&self, address: u64) -> Option<&MemoryRegion> {
        let regions = self.regions.as_deref()?;
        let index = regions.partition_point(|region| region.base <= address);
        let region = regions.get(index.checked_sub(1)?)?;
        (address - region.base < region.size).then_some(region)
    }

    /// The index `~` lists `tid` at.
    pub fn thread_index(&self, tid: u32) -> Option<usize> {
        self.threads.iter().position(|thread| thread.tid == tid)
    }

    pub fn module_infos(&self) -> Vec<ModuleInfo> {
        self.modules
            .iter()
            .map(UserModule::to_module_info)
            .collect()
    }

    /// The backend's id for thread `tid`: `<pid>.<tid>` in hex, as WinDbg
    /// writes a user-mode thread id.
    pub fn backend_thread_id(&self, tid: u32) -> String {
        match self.process_id {
            Some(pid) => format!("{pid:x}.{tid:x}"),
            None => format!("{tid:x}"),
        }
    }

    /// The thread id a backend id names (see [`Self::backend_thread_id`]),
    /// when it names a thread of this dump's process.
    pub fn tid_for_backend_id(&self, id: &str) -> Option<u32> {
        let (pid, tid) = match id.split_once('.') {
            Some((pid, tid)) => (Some(u32::from_str_radix(pid, 16).ok()?), tid),
            None => (None, id),
        };
        if pid != self.process_id {
            return None;
        }
        u32::from_str_radix(tid, 16).ok()
    }

    /// The thread a backend id names (see [`Self::backend_thread_id`]).
    pub fn thread_for_backend_id(&self, id: &str) -> Option<&UserThreadInfo> {
        let tid = self.tid_for_backend_id(id)?;
        self.threads.iter().find(|thread| thread.tid == tid)
    }
}

/// A user-mode minidump: the parsed streams and the file holding the
/// captured memory.
pub struct UserDump {
    mmap: Mmap,
    info: UserDumpInfo,
    /// Disjoint and sorted by start.
    memory: Vec<MemoryRange>,
}

/// Whether the file at `path` starts with the minidump signature. A kernel
/// dump (`PAGEDU64`) or a file shorter than the signature is not one.
pub fn file_is_minidump(path: &Path) -> Result<bool> {
    let mut signature = [0u8; 4];
    match File::open(path)?.read_exact(&mut signature) {
        Ok(()) => Ok(is_minidump(&signature)),
        Err(error) if error.kind() == ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(error.into()),
    }
}

impl UserDump {
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path)?;
        // SAFETY: the file is opened read-only and the mapping is never
        // written; a dump changed underneath a session is not supported, as
        // for kernel dumps.
        let mmap = unsafe { Mmap::map(&file)? };
        Self::from_mmap(mmap)
    }

    pub fn from_mmap(mmap: Mmap) -> Result<Self> {
        let parsed = parse::parse(&mmap)?;
        Ok(Self {
            info: parsed.info,
            memory: parsed.memory,
            mmap,
        })
    }

    pub fn info(&self) -> &UserDumpInfo {
        &self.info
    }

    pub fn memory_ranges(&self) -> &[MemoryRange] {
        &self.memory
    }

    /// The captured range holding `address`.
    fn range_containing(&self, address: u64) -> Option<&MemoryRange> {
        let index = self.memory.partition_point(|range| range.start <= address);
        let range = self.memory.get(index.checked_sub(1)?)?;
        (address - range.start < range.length).then_some(range)
    }

    /// The start of the first captured range above `address`.
    fn next_range_after(&self, address: u64) -> Option<u64> {
        let index = self.memory.partition_point(|range| range.start <= address);
        self.memory.get(index).map(|range| range.start)
    }

    /// Read process memory at `address`. A read that reaches memory the dump
    /// did not capture fails with [`Error::NotCaptured`], naming the first
    /// missing address and where captured memory resumes; the bytes before
    /// the hole are in `buf`.
    pub fn read_virtual(&self, address: VirtAddr, buf: &mut [u8]) -> Result<()> {
        let mut done = 0usize;
        while done < buf.len() {
            let Some(at) = address.0.checked_add(done as u64) else {
                return Err(Error::NotCaptured {
                    address,
                    resumes: None,
                });
            };
            let missing = || Error::NotCaptured {
                address: VirtAddr(at),
                resumes: self.next_range_after(at).map(VirtAddr),
            };
            let range = self.range_containing(at).ok_or_else(missing)?;
            let within = at - range.start;
            let take = usize::try_from(range.length - within)
                .unwrap_or(usize::MAX)
                .min(buf.len() - done);
            let bytes = usize::try_from(range.offset + within)
                .ok()
                .and_then(|start| self.mmap.get(start..start.checked_add(take)?))
                .ok_or_else(missing)?;
            buf[done..done + take].copy_from_slice(bytes);
            done += take;
        }
        Ok(())
    }
}
