//! Triage of a Windows user-mode minidump: the exception the dump was
//! written for, decoded; the stack walked from the exception's context; and
//! the frame and module the failure is blamed on. None of the kernel
//! findings (bugcheck, verifier, WHEA, power, blackboxes) apply: a user dump
//! holds one process and no kernel.

use std::collections::HashMap;

use ntoseye_macros::record;

use super::culprit::{is_user_system_module, user_culprit_attribution};
use super::signature::user_failure_signature;
use super::{TRIAGE_BACKTRACE_LIMIT, TriageReport};
use crate::dmp::{DmpException, UnloadedDriver};
use crate::guest::ModuleInfo;
use crate::memory::MemoryOps;
use crate::ntstatus::ntstatus_name;
use crate::session::Session;
use crate::target::mm::{memory_state_name, memory_type_name, page_protection_name};
use crate::types::{Arch, VirtAddr};
use crate::unwind::{
    FrameSource, StackTrace, build_stacktrace_with_register_values, format_symbol,
    resolve_thread_trace_context,
};
use crate::userdump::{UserDumpInfo, UserException};

/// What `!analyze` reports for a user-mode minidump beyond the fields it
/// shares with a kernel report (the stack, the modules, the signature and
/// the culprit): the process, the exception decoded, and the frame the
/// failure is blamed on.
#[record]
#[derive(Debug, Clone)]
pub struct UserDumpTriage {
    pub process: UserProcessSummary,
    /// The exception the dump was written for; `None` when it records none.
    pub exception: Option<UserExceptionFinding>,
    /// The thread whose stack the report's `backtrace` is, and the context
    /// the walk started from. `None` if no thread is selected.
    pub stack_thread: Option<UserStackThread>,
    /// The general-purpose registers of the exception's context, in display
    /// order. Empty without an exception, or when its context is unusable.
    pub exception_registers: Vec<RegisterValue>,
}

/// A register of the exception's context.
#[record]
#[derive(Debug, Clone)]
pub struct RegisterValue {
    pub name: String,
    #[record(hex)]
    pub value: u64,
}

/// The captured process, as the dump's streams record it.
#[record(impl)]
#[derive(Debug, Clone)]
pub struct UserProcessSummary {
    /// The executable's file name, from the first module the dump lists.
    pub name: Option<String>,
    pub pid: Option<u32>,
    /// The architecture (see the `arch` property).
    #[record(skip)]
    pub arch: Arch,
    pub major_version: u32,
    pub minor_version: u32,
    pub build_number: u32,
    /// `MINIDUMP_MISC_INFO_4.BuildString`.
    pub build_string: Option<String>,
    /// When the dump was written, in seconds since 1970 (UTC).
    pub dump_time: u32,
    /// When the process was created, in seconds since 1970 (UTC).
    pub create_time: Option<u32>,
    /// User-mode and kernel-mode time the process had run, in seconds (see
    /// the `user_time_secs` and `kernel_time_secs` properties).
    #[record(skip)]
    pub cpu_times: Option<(u32, u32)>,
    pub threads: usize,
    pub modules: usize,
    pub unloaded_modules: usize,
    /// `None` when the dump has no handle stream.
    pub handles: Option<usize>,
}

#[record]
impl UserProcessSummary {
    /// `AMD64` or `ARM64`.
    #[record(getter, rename = "arch")]
    pub fn arch_name(&self) -> &'static str {
        self.arch.label()
    }

    /// When the dump was written (ISO 8601 UTC).
    #[record(getter)]
    pub fn dump_time_utc(&self) -> Option<String> {
        super::time::unix_time_to_iso(u64::from(self.dump_time))
    }

    /// When the process was created (ISO 8601 UTC).
    #[record(getter)]
    pub fn create_time_utc(&self) -> Option<String> {
        self.create_time
            .and_then(|time| super::time::unix_time_to_iso(u64::from(time)))
    }

    /// User-mode time the process had run, in seconds.
    #[record(getter)]
    pub fn user_time_secs(&self) -> Option<u32> {
        self.cpu_times.map(|(user, _)| user)
    }

    /// Kernel-mode time the process had run, in seconds.
    #[record(getter)]
    pub fn kernel_time_secs(&self) -> Option<u32> {
        self.cpu_times.map(|(_, kernel)| kernel)
    }
}

/// Where a report's stack was walked from: `exception_context` (the
/// exception's CONTEXT, as `.ecxr` selects it) or `thread_context` (the
/// selected thread's, as `k` walks it).
#[record]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserStackSource {
    /// The exception's CONTEXT, as `.ecxr` selects it.
    ExceptionContext,
    /// The selected thread's context, as `k` walks it.
    ThreadContext,
}

impl std::fmt::Display for UserStackSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ExceptionContext => "exception_context",
            Self::ThreadContext => "thread_context",
        })
    }
}

/// The thread a user dump report's stack belongs to.
#[record]
#[derive(Debug, Clone)]
pub struct UserStackThread {
    pub tid: u32,
    /// The thread's id as `~` lists it (`<pid>.<tid>` in hex).
    pub id: String,
    pub name: Option<String>,
    pub source: UserStackSource,
}

/// What kind of code an exception code is: `ntstatus`, `cpp_exception`,
/// `clr_exception`, `well_known`, `application_defined` (customer bit set,
/// no name), or `unknown`.
#[record]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserExceptionKind {
    /// An NTSTATUS, raised by the system or with its value.
    Ntstatus,
    /// A C++ `throw` (`_CxxThrowException`).
    CppException,
    /// A .NET exception the CLR raised.
    ClrException,
    /// A code a compiler, runtime, or debugging convention defines.
    WellKnown,
    /// A code with the customer bit set and no name: one the application
    /// chose.
    ApplicationDefined,
    Unknown,
}

impl std::fmt::Display for UserExceptionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Ntstatus => "ntstatus",
            Self::CppException => "cpp_exception",
            Self::ClrException => "clr_exception",
            Self::WellKnown => "well_known",
            Self::ApplicationDefined => "application_defined",
            Self::Unknown => "unknown",
        })
    }
}

/// One `ExceptionInformation` entry, with what it means for the code when
/// that is known.
#[record]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExceptionParameter {
    #[record(hex)]
    pub value: u64,
    /// What the entry is for the code (`access`, `address`, `ThrowInfo`,
    /// ...). `None` if the code defines no meaning.
    pub label: Option<&'static str>,
    /// The value decoded: an access type, a status name, a module.
    pub meaning: Option<String>,
}

/// What holds a code address: `kind` `module` (`name`, and `system` when
/// it is part of Windows or a language runtime), `dynamic_code` (no module;
/// a dynamic function table covers it, `table_start..table_end`), or
/// `unowned` (`region`: the memory, as the dump's memory-info list records
/// it).
#[record(tagged)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeOwner {
    /// A loaded module. `system` when it is part of Windows or a language
    /// runtime, which raise and dispatch exceptions on a caller's behalf.
    Module { name: String, system: bool },
    /// No module; a dynamic function table the process registered covers
    /// it, as for JIT-compiled code. The table covers
    /// `table_start..table_end`.
    DynamicCode { table_start: u64, table_end: u64 },
    /// No module and no dynamic function table. `region` describes the
    /// memory when the dump's memory-info list records it.
    Unowned { region: Option<String> },
}

/// A frame of the report's stack, as the analysis uses it.
#[record]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserFrame {
    /// The frame's index in the report's `backtrace`.
    pub index: usize,
    #[record(hex)]
    pub ip: u64,
    pub symbol: String,
    pub source: FrameSource,
    pub owner: CodeOwner,
}

/// The exception a user-mode minidump was written for, decoded.
#[record]
#[derive(Debug, Clone)]
pub struct UserExceptionFinding {
    #[record(hex)]
    pub code: u32,
    pub kind: UserExceptionKind,
    /// The code's name, or what kind of code it is when it has none.
    pub name: &'static str,
    #[record(hex)]
    pub flags: u32,
    /// The `EXCEPTION_*` flags set, with any unknown bits in hex.
    pub flag_names: Vec<String>,
    /// The address of a chained exception record, 0 for none.
    #[record(hex)]
    pub record: u64,
    #[record(hex)]
    pub address: u64,
    pub symbol: String,
    /// What holds the exception address: the faulting module.
    pub address_owner: CodeOwner,
    pub parameters: Vec<ExceptionParameter>,
    /// What the parameters say, in one line (`write to 0x10`).
    pub summary: Option<String>,
    pub thread_id: u32,
    /// The thread's id as `~` lists it.
    pub thread: String,
    pub thread_name: Option<String>,
    /// The index in the report's `backtrace` of the frame at the exception
    /// address; `None` when no frame is there.
    pub faulting_frame: Option<usize>,
    /// The first frame, from the faulting one outward, outside the system
    /// modules: the code the failure is blamed on. `None` when every frame
    /// is in a system module or there is no stack.
    pub blamed_frame: Option<UserFrame>,
    /// When the blamed frame is in no module, the first frame further out
    /// that a module holds: the module code that called into it.
    pub module_caller: Option<UserFrame>,
}

const EXCEPTION_FLAGS: [(u32, &str); 8] = [
    (0x01, "EXCEPTION_NONCONTINUABLE"),
    (0x02, "EXCEPTION_UNWINDING"),
    (0x04, "EXCEPTION_EXIT_UNWIND"),
    (0x08, "EXCEPTION_STACK_INVALID"),
    (0x10, "EXCEPTION_NESTED_CALL"),
    (0x20, "EXCEPTION_TARGET_UNWIND"),
    (0x40, "EXCEPTION_COLLIDED_UNWIND"),
    (0x80, "EXCEPTION_SOFTWARE_ORIGINATE"),
];

const CPP_EH_EXCEPTION: u32 = 0xE06D_7363;
const CLR_EXCEPTION: u32 = 0xE043_4352;
const CLR_EXCEPTION_V2: u32 = 0xE043_4F4D;
const MS_VC_EXCEPTION: u32 = 0x406D_1388;
const DELAY_LOAD_MODULE_NOT_FOUND: u32 = 0xC06D_007E;
const DELAY_LOAD_PROC_NOT_FOUND: u32 = 0xC06D_007F;
const DELPHI_EXCEPTION: u32 = 0x0EED_FADE;
const STATUS_GUARD_PAGE_VIOLATION: u32 = 0x8000_0001;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_IN_PAGE_ERROR: u32 = 0xC000_0006;
const STATUS_STOWED_EXCEPTION: u32 = 0xC000_027B;
const STATUS_STACK_BUFFER_OVERRUN: u32 = 0xC000_0409;
const DBG_PRINTEXCEPTION_C: u32 = 0x4001_0006;
const DBG_PRINTEXCEPTION_WIDE_C: u32 = 0x4001_000A;
/// The customer bit of an NTSTATUS-shaped code: the code is not Microsoft's.
const CUSTOMER_BIT: u32 = 0x2000_0000;

/// `__fastfail` codes (`FAST_FAIL_*` in winnt.h), by value.
const FAST_FAIL_CODES: &[(u64, &str)] = &[
    (0, "FAST_FAIL_LEGACY_GS_VIOLATION"),
    (1, "FAST_FAIL_VTGUARD_CHECK_FAILURE"),
    (2, "FAST_FAIL_STACK_COOKIE_CHECK_FAILURE"),
    (3, "FAST_FAIL_CORRUPT_LIST_ENTRY"),
    (4, "FAST_FAIL_INCORRECT_STACK"),
    (5, "FAST_FAIL_INVALID_ARG"),
    (6, "FAST_FAIL_GS_COOKIE_INIT"),
    (7, "FAST_FAIL_FATAL_APP_EXIT"),
    (8, "FAST_FAIL_RANGE_CHECK_FAILURE"),
    (9, "FAST_FAIL_UNSAFE_REGISTRY_ACCESS"),
    (10, "FAST_FAIL_GUARD_ICALL_CHECK_FAILURE"),
    (11, "FAST_FAIL_GUARD_WRITE_CHECK_FAILURE"),
    (12, "FAST_FAIL_INVALID_FIBER_SWITCH"),
    (13, "FAST_FAIL_INVALID_SET_OF_CONTEXT"),
    (14, "FAST_FAIL_INVALID_REFERENCE_COUNT"),
    (18, "FAST_FAIL_INVALID_JUMP_BUFFER"),
    (19, "FAST_FAIL_MRDATA_MODIFIED"),
    (20, "FAST_FAIL_CERTIFICATION_FAILURE"),
    (21, "FAST_FAIL_INVALID_EXCEPTION_CHAIN"),
    (22, "FAST_FAIL_CRYPTO_LIBRARY"),
    (23, "FAST_FAIL_INVALID_CALL_IN_DLL_CALLOUT"),
    (24, "FAST_FAIL_INVALID_IMAGE_BASE"),
    (25, "FAST_FAIL_DLOAD_PROTECTION_FAILURE"),
    (26, "FAST_FAIL_UNSAFE_EXTENSION_CALL"),
    (27, "FAST_FAIL_DEPRECATED_SERVICE_INVOKED"),
    (28, "FAST_FAIL_INVALID_BUFFER_ACCESS"),
    (29, "FAST_FAIL_INVALID_BALANCED_TREE"),
    (30, "FAST_FAIL_INVALID_NEXT_THREAD"),
    (31, "FAST_FAIL_GUARD_ICALL_CHECK_SUPPRESSED"),
    (32, "FAST_FAIL_APCS_DISABLED"),
    (33, "FAST_FAIL_INVALID_IDLE_STATE"),
    (34, "FAST_FAIL_MRDATA_PROTECTION_FAILURE"),
    (35, "FAST_FAIL_UNEXPECTED_HEAP_EXCEPTION"),
    (36, "FAST_FAIL_INVALID_LOCK_STATE"),
    (37, "FAST_FAIL_GUARD_JUMPTABLE"),
    (38, "FAST_FAIL_INVALID_LONGJUMP_TARGET"),
    (39, "FAST_FAIL_INVALID_DISPATCH_CONTEXT"),
    (40, "FAST_FAIL_INVALID_THREAD"),
    (41, "FAST_FAIL_INVALID_SYSCALL_NUMBER"),
    (42, "FAST_FAIL_INVALID_FILE_OPERATION"),
    (43, "FAST_FAIL_LPAC_ACCESS_DENIED"),
    (44, "FAST_FAIL_GUARD_SS_FAILURE"),
    (45, "FAST_FAIL_LOADER_CONTINUITY_FAILURE"),
    (46, "FAST_FAIL_GUARD_EXPORT_SUPPRESSION_FAILURE"),
    (47, "FAST_FAIL_INVALID_CONTROL_STACK"),
    (48, "FAST_FAIL_SET_CONTEXT_DENIED"),
    (49, "FAST_FAIL_INVALID_IAT"),
    (50, "FAST_FAIL_HEAP_METADATA_CORRUPTION"),
    (51, "FAST_FAIL_PAYLOAD_RESTRICTION_VIOLATION"),
    (52, "FAST_FAIL_LOW_LABEL_ACCESS_DENIED"),
    (53, "FAST_FAIL_ENCLAVE_CALL_FAILURE"),
    (54, "FAST_FAIL_UNHANDLED_LSS_EXCEPTON"),
    (55, "FAST_FAIL_ADMINLESS_ACCESS_DENIED"),
    (56, "FAST_FAIL_UNEXPECTED_CALL"),
    (57, "FAST_FAIL_CONTROL_INVALID_RETURN_ADDRESS"),
    (58, "FAST_FAIL_UNEXPECTED_HOST_BEHAVIOR"),
    (59, "FAST_FAIL_FLAGS_CORRUPTION"),
    (60, "FAST_FAIL_VEH_CORRUPTION"),
    (61, "FAST_FAIL_ETW_CORRUPTION"),
    (62, "FAST_FAIL_RIO_ABORT"),
    (63, "FAST_FAIL_INVALID_PFN"),
    (64, "FAST_FAIL_GUARD_ICALL_CHECK_FAILURE_XFG"),
    (65, "FAST_FAIL_CAST_GUARD"),
    (66, "FAST_FAIL_HOST_VISIBILITY_CHANGE"),
    (67, "FAST_FAIL_KERNEL_CET_SHADOW_STACK_ASSIST"),
    (68, "FAST_FAIL_PATCH_CALLBACK_FAILED"),
    (69, "FAST_FAIL_NTDLL_PATCH_FAILED"),
    (70, "FAST_FAIL_INVALID_FLS_DATA"),
];

/// The general-purpose registers `-v` shows from the exception's context.
const AMD64_REGISTERS: [&str; 18] = [
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp", "rip", "r8", "r9", "r10", "r11", "r12",
    "r13", "r14", "r15", "eflags",
];
const ARM64_EXTRA_REGISTERS: [&str; 5] = ["fp", "lr", "sp", "pc", "cpsr"];

/// The kind of an exception code and its name, or what it is when it has
/// no name.
pub fn user_exception_name(code: u32) -> (UserExceptionKind, &'static str) {
    match code {
        CPP_EH_EXCEPTION => (UserExceptionKind::CppException, "C++ exception"),
        CLR_EXCEPTION | CLR_EXCEPTION_V2 => (UserExceptionKind::ClrException, "CLR exception"),
        MS_VC_EXCEPTION => (
            UserExceptionKind::WellKnown,
            "MS_VC_EXCEPTION (a thread name for the debugger)",
        ),
        DELAY_LOAD_MODULE_NOT_FOUND => (
            UserExceptionKind::WellKnown,
            "delay-load failure: module not found",
        ),
        DELAY_LOAD_PROC_NOT_FOUND => (
            UserExceptionKind::WellKnown,
            "delay-load failure: procedure not found",
        ),
        DELPHI_EXCEPTION => (UserExceptionKind::WellKnown, "Delphi exception"),
        _ => match ntstatus_name(code) {
            Some(name) => (UserExceptionKind::Ntstatus, name),
            None if code & CUSTOMER_BIT != 0 => (
                UserExceptionKind::ApplicationDefined,
                "application-defined code (customer bit set), no standard name",
            ),
            None => (UserExceptionKind::Unknown, "unknown code"),
        },
    }
}

/// The `EXCEPTION_*` names of `flags`, with bits no flag names in hex.
pub fn exception_flag_names(flags: u32) -> Vec<String> {
    let mut names: Vec<String> = EXCEPTION_FLAGS
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, name)| (*name).to_string())
        .collect();
    let known = EXCEPTION_FLAGS.iter().fold(0, |all, (bit, _)| all | bit);
    if flags & !known != 0 {
        names.push(format!("{:#x}", flags & !known));
    }
    names
}

fn access_meaning(value: u64) -> &'static str {
    match value {
        0 => "read",
        1 => "write",
        8 => "execute (DEP)",
        _ => "unknown access",
    }
}

fn module_meaning(modules: &[ModuleInfo], address: u64) -> Option<String> {
    modules
        .iter()
        .find(|module| module.base_address.0 == address)
        .map(|module| module.name.clone())
        .or_else(|| {
            modules
                .iter()
                .find(|module| module.contains_address(VirtAddr(address)))
                .map(|module| format!("inside {}", module.name))
        })
}

fn parameter(value: u64, label: &'static str, meaning: Option<String>) -> ExceptionParameter {
    ExceptionParameter {
        value,
        label: Some(label),
        meaning,
    }
}

/// The parameters of exception `code`, labelled and decoded where the code
/// defines them, and what they say in one line.
pub fn decode_exception_parameters(
    code: u32,
    values: &[u64],
    modules: &[ModuleInfo],
) -> (Vec<ExceptionParameter>, Option<String>) {
    let at = |index: usize| values.get(index).copied();
    let mut parameters: Vec<ExceptionParameter> = values
        .iter()
        .map(|&value| ExceptionParameter {
            value,
            label: None,
            meaning: None,
        })
        .collect();
    let mut set = |index: usize, label: &'static str, meaning: Option<String>| {
        if let Some(slot) = parameters.get_mut(index) {
            *slot = parameter(slot.value, label, meaning);
        }
    };
    let summary = match code {
        STATUS_ACCESS_VIOLATION | STATUS_GUARD_PAGE_VIOLATION | STATUS_IN_PAGE_ERROR => {
            let access = at(0).map(access_meaning);
            set(0, "access", access.map(str::to_string));
            set(1, "address", None);
            let status = (code == STATUS_IN_PAGE_ERROR)
                .then(|| at(2))
                .flatten()
                .map(|status| {
                    let name = u32::try_from(status)
                        .ok()
                        .and_then(ntstatus_name)
                        .unwrap_or("unknown status");
                    set(2, "status", Some(name.to_string()));
                    format!(": {name} ({status:#x})")
                })
                .unwrap_or_default();
            match (at(0), at(1)) {
                (Some(0), Some(address)) => Some(format!("read from {address:#x}{status}")),
                (Some(1), Some(address)) => Some(format!("write to {address:#x}{status}")),
                (Some(8), Some(address)) => Some(format!("execute at {address:#x} (DEP){status}")),
                (Some(access), Some(address)) => Some(format!(
                    "unknown access {access:#x} at {address:#x}{status}"
                )),
                _ => None,
            }
        }
        CPP_EH_EXCEPTION => {
            let magic = at(0).map(|magic| match magic {
                0x1993_0520 => "EH_MAGIC_NUMBER1",
                0x1993_0521 => "EH_MAGIC_NUMBER2",
                0x1993_0522 => "EH_MAGIC_NUMBER3",
                0x0199_4000 => "EH_PURE_MAGIC_NUMBER1",
                _ => "not a C++ EH magic number",
            });
            set(0, "magic", magic.map(str::to_string));
            set(1, "exception object", None);
            set(2, "ThrowInfo", None);
            set(
                3,
                "image base",
                at(3).and_then(|base| module_meaning(modules, base)),
            );
            at(1).map(|object| format!("object at {object:#x}"))
        }
        CLR_EXCEPTION | CLR_EXCEPTION_V2 => {
            set(0, "HRESULT", None);
            // The CLR tags its exceptions with the runtime's own base in the
            // last of five parameters, so one runtime can tell its
            // exceptions from another's.
            if values.len() == 5 {
                set(
                    4,
                    "runtime base",
                    at(4).and_then(|base| module_meaning(modules, base)),
                );
            }
            at(0).map(|hresult| format!("HRESULT {hresult:#010x}"))
        }
        STATUS_STACK_BUFFER_OVERRUN => {
            let name = at(0).map(|value| {
                FAST_FAIL_CODES
                    .iter()
                    .find(|(code, _)| *code == value)
                    .map_or("unknown fail-fast code", |(_, name)| name)
            });
            set(0, "fail-fast code", name.map(str::to_string));
            name.map(|name| format!("__fastfail: {name}"))
        }
        STATUS_STOWED_EXCEPTION => {
            set(0, "stowed exceptions", None);
            set(1, "count", None);
            at(1).map(|count| format!("{count} stowed exception(s)"))
        }
        MS_VC_EXCEPTION => {
            set(0, "type", None);
            set(1, "thread name", None);
            set(2, "thread id", None);
            set(3, "flags", None);
            None
        }
        DELAY_LOAD_MODULE_NOT_FOUND | DELAY_LOAD_PROC_NOT_FOUND => {
            set(0, "DelayLoadInfo", None);
            None
        }
        DBG_PRINTEXCEPTION_C | DBG_PRINTEXCEPTION_WIDE_C => {
            set(0, "length", None);
            set(1, "string", None);
            None
        }
        _ => None,
    };
    (parameters, summary)
}

/// The C++ name a `TypeDescriptor` records, undecorated when it is a plain
/// class, struct, or fundamental type; decorated otherwise (templates,
/// pointers to classes), which a demangler can still read.
pub fn undecorate_type_descriptor(name: &str) -> String {
    let scoped = |body: &str| {
        let body = body.strip_suffix("@@")?;
        if body.is_empty() || body.contains(['?', '$']) {
            return None;
        }
        Some(body.rsplit('@').collect::<Vec<_>>().join("::"))
    };
    let decoded = if let Some(body) = name.strip_prefix(".?AV") {
        scoped(body)
    } else if let Some(body) = name.strip_prefix(".?AU") {
        scoped(body)
    } else {
        match name {
            ".D" => Some("char".into()),
            ".E" => Some("unsigned char".into()),
            ".F" => Some("short".into()),
            ".G" => Some("unsigned short".into()),
            ".H" => Some("int".into()),
            ".I" => Some("unsigned int".into()),
            ".J" => Some("long".into()),
            ".K" => Some("unsigned long".into()),
            ".M" => Some("float".into()),
            ".N" => Some("double".into()),
            "._J" => Some("__int64".into()),
            "._K" => Some("unsigned __int64".into()),
            "._N" => Some("bool".into()),
            "._W" => Some("wchar_t".into()),
            ".PEAD" => Some("char *".into()),
            ".PEBD" => Some("const char *".into()),
            ".PEA_W" => Some("wchar_t *".into()),
            ".PEB_W" => Some("const wchar_t *".into()),
            _ => None,
        }
    };
    decoded.unwrap_or_else(|| name.to_string())
}

/// The type a 64-bit C++ throw threw: its `ThrowInfo` (RVAs from
/// `image_base`) names a `CatchableTypeArray`, whose first entry is the
/// thrown type itself, and that names the `TypeDescriptor` holding the
/// decorated name. `read` fills a buffer from process memory or fails.
pub fn cpp_thrown_type(
    throw_info: u64,
    image_base: u64,
    read: impl Fn(u64, &mut [u8]) -> bool,
) -> Option<String> {
    const THROW_INFO_CATCHABLE_TYPES: u64 = 12;
    const CATCHABLE_TYPE_ARRAY_FIRST: u64 = 4;
    const CATCHABLE_TYPE_TYPE: u64 = 4;
    const TYPE_DESCRIPTOR_NAME: u64 = 16;
    const NAME_LIMIT: usize = 512;

    let rva = |address: u64| -> Option<u64> {
        let mut bytes = [0u8; 4];
        read(address, &mut bytes).then_some(())?;
        let rva = u32::from_le_bytes(bytes);
        (rva != 0).then(|| image_base.checked_add(u64::from(rva)))?
    };
    if throw_info == 0 || image_base == 0 {
        return None;
    }
    let types = rva(throw_info.checked_add(THROW_INFO_CATCHABLE_TYPES)?)?;
    let catchable = rva(types.checked_add(CATCHABLE_TYPE_ARRAY_FIRST)?)?;
    let descriptor = rva(catchable.checked_add(CATCHABLE_TYPE_TYPE)?)?;
    let name_at = descriptor.checked_add(TYPE_DESCRIPTOR_NAME)?;
    let mut name = Vec::new();
    let mut byte = [0u8; 1];
    while name.len() < NAME_LIMIT {
        read(name_at.checked_add(name.len() as u64)?, &mut byte).then_some(())?;
        if byte[0] == 0 {
            break;
        }
        name.push(byte[0]);
    }
    let name = String::from_utf8(name).ok()?;
    name.starts_with('.')
        .then(|| undecorate_type_descriptor(&name))
}

fn region_description(info: &UserDumpInfo, address: u64) -> Option<String> {
    let region = info.region(address)?;
    if memory_state_name(region.state) == "MEM_FREE" {
        return Some("free memory".into());
    }
    let parts: Vec<String> = [
        memory_type_name(region.kind).to_string(),
        memory_state_name(region.state).to_string(),
        page_protection_name(region.protect),
    ]
    .into_iter()
    .filter(|part| !part.is_empty())
    .collect();
    (!parts.is_empty()).then(|| parts.join(" "))
}

/// What holds code address `address` in the dump.
fn code_owner(info: &UserDumpInfo, modules: &[ModuleInfo], address: u64) -> CodeOwner {
    if let Some(module) = modules
        .iter()
        .find(|module| module.contains_address(VirtAddr(address)))
    {
        return CodeOwner::Module {
            name: module.name.clone(),
            system: is_user_system_module(&module.name),
        };
    }
    if info.dynamic_function(address).is_some()
        && let Some(table) = info
            .function_tables
            .iter()
            .find(|table| (table.minimum..table.maximum).contains(&address))
    {
        return CodeOwner::DynamicCode {
            table_start: table.minimum,
            table_end: table.maximum,
        };
    }
    CodeOwner::Unowned {
        region: region_description(info, address),
    }
}

/// The frame the failure is blamed on: from `start` outward, the first
/// frame `owner` does not place in a system module.
pub fn blamed_frame(
    trace: &StackTrace,
    start: usize,
    owner: impl Fn(u64) -> CodeOwner,
) -> Option<UserFrame> {
    frame_where(trace, start, owner, |owner| {
        !matches!(owner, CodeOwner::Module { system: true, .. })
    })
}

/// The module code that called into a blamed frame in no module: from
/// `blamed + 1` outward, the first frame a module holds.
pub fn module_caller(
    trace: &StackTrace,
    blamed: &UserFrame,
    owner: impl Fn(u64) -> CodeOwner,
) -> Option<UserFrame> {
    if matches!(blamed.owner, CodeOwner::Module { .. }) {
        return None;
    }
    frame_where(trace, blamed.index + 1, owner, |owner| {
        matches!(owner, CodeOwner::Module { .. })
    })
}

fn frame_where(
    trace: &StackTrace,
    start: usize,
    owner: impl Fn(u64) -> CodeOwner,
    wanted: impl Fn(&CodeOwner) -> bool,
) -> Option<UserFrame> {
    trace
        .frames
        .iter()
        .enumerate()
        .skip(start)
        .map(|(index, frame)| (index, frame, owner(frame.ip)))
        .find(|(_, _, owner)| wanted(owner))
        .map(|(index, frame, owner)| UserFrame {
            index,
            ip: frame.ip,
            symbol: frame.symbol.clone(),
            source: frame.source,
            owner,
        })
}

fn general_registers(arch: Arch, values: &HashMap<String, u64>) -> Vec<RegisterValue> {
    let names: Vec<String> = match arch {
        Arch::Amd64 => AMD64_REGISTERS.map(String::from).to_vec(),
        Arch::Arm64 => (0..=28)
            .map(|index| format!("x{index}"))
            .chain(ARM64_EXTRA_REGISTERS.map(String::from))
            .collect(),
    };
    names
        .into_iter()
        .filter_map(|name| {
            let value = *values.get(&name)?;
            Some(RegisterValue { name, value })
        })
        .collect()
}

fn process_summary(info: &UserDumpInfo) -> UserProcessSummary {
    UserProcessSummary {
        name: info.process_name().map(str::to_string),
        pid: info.process_id,
        arch: info.arch,
        major_version: info.system.major_version,
        minor_version: info.system.minor_version,
        build_number: info.system.build_number,
        build_string: info.build_string.clone(),
        dump_time: info.time_date_stamp,
        create_time: info.process_create_time,
        cpu_times: info.process_cpu_times,
        threads: info.threads.len(),
        modules: info.modules.len(),
        unloaded_modules: info.unloaded_modules.len(),
        handles: info.handles.as_ref().map(Vec::len),
    }
}

/// The triage report of a user-mode minidump; `None` for a kernel target.
pub fn build(session: &mut Session) -> Option<TriageReport> {
    let has_exception = session.target.user_dump_info()?.exception.is_some();
    let status = session.run_status();
    let mut warnings = Vec::new();
    // Without an exception the stack is the selected thread's, as `k`
    // walks it; with one it is walked below from the exception's context.
    let thread_trace = if has_exception {
        None
    } else {
        match session.backtrace(TRIAGE_BACKTRACE_LIMIT) {
            Ok(trace) => Some(trace),
            Err(error) => {
                warnings.push(format!("backtrace: {error}"));
                None
            }
        }
    };
    let session = &*session;
    let target = &session.target;
    let info = target.user_dump_info()?;
    let modules = target.user_modules().unwrap_or_default().to_vec();
    let unloaded_drivers = info
        .unloaded_modules
        .iter()
        .map(|module| UnloadedDriver {
            name: module.name.clone(),
            start_address: module.base,
            end_address: module.base.saturating_add(u64::from(module.size)),
        })
        .collect();

    let mut exception_registers = Vec::new();
    let (backtrace, stack_thread) = match &info.exception {
        Some(exception) => {
            let thread = UserStackThread {
                tid: exception.thread_id,
                id: info.backend_thread_id(exception.thread_id),
                name: info
                    .thread(exception.thread_id)
                    .and_then(|thread| thread.name.clone()),
                source: UserStackSource::ExceptionContext,
            };
            let trace = match session
                .target
                .user_exception_registers(&session.register_map)
            {
                Ok(registers) => {
                    exception_registers = general_registers(info.arch, &registers);
                    Some(
                        build_stacktrace_with_register_values(
                            target,
                            &session.register_map,
                            &registers,
                            TRIAGE_BACKTRACE_LIMIT,
                        )
                        .into_stacktrace(),
                    )
                }
                Err(error) => {
                    warnings.push(format!("exception stack: {error}"));
                    None
                }
            };
            (trace, Some(thread))
        }
        None => {
            let thread = target.user_thread().map(|thread| UserStackThread {
                tid: thread.tid,
                id: info.backend_thread_id(thread.tid),
                name: thread.name.clone(),
                source: UserStackSource::ThreadContext,
            });
            (thread_trace, thread)
        }
    };

    let exception = info
        .exception
        .as_ref()
        .map(|exception| exception_finding(session, info, exception, &modules, backtrace.as_ref()));
    let mut report = TriageReport {
        status,
        bugcheck: None,
        exception: info.exception.as_ref().map(|exception| DmpException {
            code: exception.code,
            flags: exception.flags,
            address: exception.address,
            parameters: exception.parameters.clone(),
        }),
        system_info: None,
        backtrace,
        modules,
        unloaded_drivers,
        crash_context: None,
        prcb: None,
        broken_driver: None,
        triage_overflowed: None,
        failure_signature: None,
        culprit: None,
        verifier: None,
        whea: None,
        blackboxes: Vec::new(),
        kmdf_log: None,
        power: None,
        user: Some(UserDumpTriage {
            process: process_summary(info),
            exception,
            stack_thread,
            exception_registers,
        }),
        warnings,
    };
    report.failure_signature = user_failure_signature(&report);
    report.culprit = user_culprit_attribution(&report);
    Some(report)
}

fn exception_finding(
    session: &Session,
    info: &UserDumpInfo,
    exception: &UserException,
    modules: &[ModuleInfo],
    backtrace: Option<&StackTrace>,
) -> UserExceptionFinding {
    let target = &session.target;
    let (kind, name) = user_exception_name(exception.code);
    let (parameters, mut summary) =
        decode_exception_parameters(exception.code, &exception.parameters, modules);
    if exception.code == CPP_EH_EXCEPTION
        && let [_, object, throw_info, image_base] = exception.parameters[..]
    {
        let memory = target.context_memory();
        let thrown = cpp_thrown_type(throw_info, image_base, |address, buf| {
            memory.read_bytes(VirtAddr(address), buf).is_ok()
        });
        if let Some(thrown) = thrown {
            summary = Some(format!("{thrown} object at {object:#x}"));
        }
    }
    let trace = resolve_thread_trace_context(target, target.current_dtb());
    let owner = |address| code_owner(info, modules, address);
    let faulting_frame = backtrace.and_then(|trace| {
        trace
            .frames
            .iter()
            .position(|frame| frame.ip == exception.address)
    });
    let blamed_frame = backtrace.and_then(|trace| {
        // A stack that never reaches the exception address is blamed from
        // its top: it is still the faulting thread's.
        blamed_frame(trace, faulting_frame.unwrap_or(0), owner)
    });
    let module_caller = backtrace
        .zip(blamed_frame.as_ref())
        .and_then(|(trace, blamed)| module_caller(trace, blamed, owner));
    UserExceptionFinding {
        code: exception.code,
        kind,
        name,
        flags: exception.flags,
        flag_names: exception_flag_names(exception.flags),
        record: exception.record,
        address: exception.address,
        symbol: format_symbol(target, &trace, exception.address),
        address_owner: owner(exception.address),
        parameters,
        summary,
        thread_id: exception.thread_id,
        thread: info.backend_thread_id(exception.thread_id),
        thread_name: info
            .thread(exception.thread_id)
            .and_then(|thread| thread.name.clone()),
        faulting_frame,
        blamed_frame,
        module_caller,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symbols::CodeFrame;
    use crate::unwind::StackFrame;

    fn modules() -> Vec<ModuleInfo> {
        vec![
            ModuleInfo::new("app.exe".into(), VirtAddr(0x1_4000_0000), 0x10_0000),
            ModuleInfo::new(
                "KERNELBASE.dll".into(),
                VirtAddr(0x7ff9_0000_0000),
                0x40_0000,
            ),
            ModuleInfo::new(
                "VCRUNTIME140.dll".into(),
                VirtAddr(0x7ff8_0000_0000),
                0x2_0000,
            ),
            ModuleInfo::new("clr.dll".into(), VirtAddr(0x7ff7_0000_0000), 0x100_0000),
        ]
    }

    fn frame(ip: u64, symbol: &str, source: FrameSource) -> StackFrame {
        StackFrame {
            sp: 0,
            ip,
            symbol: symbol.into(),
            source,
            source_location: None,
            machine_frame: None,
            code: CodeFrame::at(VirtAddr(ip)),
            inline: false,
        }
    }

    fn owner_in(modules: &[ModuleInfo], jit: u64) -> impl Fn(u64) -> CodeOwner + '_ {
        move |address| match modules
            .iter()
            .find(|module| module.contains_address(VirtAddr(address)))
        {
            Some(module) => CodeOwner::Module {
                name: module.name.clone(),
                system: is_user_system_module(&module.name),
            },
            None if address == jit => CodeOwner::DynamicCode {
                table_start: jit & !0xfff,
                table_end: (jit & !0xfff) + 0x1000,
            },
            None => CodeOwner::Unowned { region: None },
        }
    }

    #[test]
    fn access_violation_parameters_name_the_access_and_target() {
        let (parameters, summary) =
            decode_exception_parameters(STATUS_ACCESS_VIOLATION, &[1, 0x10], &[]);
        assert_eq!(parameters[0].label, Some("access"));
        assert_eq!(parameters[0].meaning.as_deref(), Some("write"));
        assert_eq!(parameters[1].label, Some("address"));
        assert_eq!(summary.as_deref(), Some("write to 0x10"));

        let (_, summary) =
            decode_exception_parameters(STATUS_ACCESS_VIOLATION, &[8, 0xdead_0000], &[]);
        assert_eq!(summary.as_deref(), Some("execute at 0xdead0000 (DEP)"));
        let (_, summary) = decode_exception_parameters(STATUS_ACCESS_VIOLATION, &[0, 0], &[]);
        assert_eq!(summary.as_deref(), Some("read from 0x0"));
        let (parameters, summary) =
            decode_exception_parameters(STATUS_ACCESS_VIOLATION, &[3, 0x20], &[]);
        assert_eq!(parameters[0].meaning.as_deref(), Some("unknown access"));
        assert_eq!(summary.as_deref(), Some("unknown access 0x3 at 0x20"));
        // A truncated record decodes what it has.
        let (parameters, summary) = decode_exception_parameters(STATUS_ACCESS_VIOLATION, &[1], &[]);
        assert_eq!(parameters.len(), 1);
        assert_eq!(summary, None);
    }

    #[test]
    fn in_page_error_names_the_underlying_status() {
        let (parameters, summary) =
            decode_exception_parameters(STATUS_IN_PAGE_ERROR, &[0, 0x7ff0_1000, 0xC000_009C], &[]);
        assert_eq!(parameters[2].label, Some("status"));
        assert_eq!(
            parameters[2].meaning.as_deref(),
            Some("STATUS_DEVICE_DATA_ERROR")
        );
        assert_eq!(
            summary.as_deref(),
            Some("read from 0x7ff01000: STATUS_DEVICE_DATA_ERROR (0xc000009c)")
        );
    }

    #[test]
    fn cpp_exception_parameters_are_labelled_and_name_the_throwing_image() {
        let modules = modules();
        let (parameters, summary) = decode_exception_parameters(
            CPP_EH_EXCEPTION,
            &[0x1993_0520, 0x5000, 0x1_4000_2000, 0x1_4000_0000],
            &modules,
        );
        let labels: Vec<_> = parameters.iter().map(|p| p.label).collect();
        assert_eq!(
            labels,
            [
                Some("magic"),
                Some("exception object"),
                Some("ThrowInfo"),
                Some("image base")
            ]
        );
        assert_eq!(parameters[0].meaning.as_deref(), Some("EH_MAGIC_NUMBER1"));
        assert_eq!(parameters[3].meaning.as_deref(), Some("app.exe"));
        assert_eq!(summary.as_deref(), Some("object at 0x5000"));
    }

    #[test]
    fn clr_runtime_tag_is_labelled_only_in_the_five_parameter_form() {
        let modules = modules();
        let (parameters, summary) = decode_exception_parameters(
            CLR_EXCEPTION,
            &[0x8013_1500, 0, 0, 0, 0x7ff7_0000_0000],
            &modules,
        );
        assert_eq!(parameters[4].label, Some("runtime base"));
        assert_eq!(parameters[4].meaning.as_deref(), Some("clr.dll"));
        assert_eq!(summary.as_deref(), Some("HRESULT 0x80131500"));
        let (parameters, _) = decode_exception_parameters(CLR_EXCEPTION, &[1, 2, 3], &modules);
        assert_eq!(parameters[2].label, None);
    }

    #[test]
    fn fail_fast_code_is_named() {
        let (parameters, summary) =
            decode_exception_parameters(STATUS_STACK_BUFFER_OVERRUN, &[2], &[]);
        assert_eq!(
            parameters[0].meaning.as_deref(),
            Some("FAST_FAIL_STACK_COOKIE_CHECK_FAILURE")
        );
        assert_eq!(
            summary.as_deref(),
            Some("__fastfail: FAST_FAIL_STACK_COOKIE_CHECK_FAILURE")
        );
        let (parameters, _) = decode_exception_parameters(STATUS_STACK_BUFFER_OVERRUN, &[16], &[]);
        assert_eq!(
            parameters[0].meaning.as_deref(),
            Some("unknown fail-fast code")
        );
    }

    #[test]
    fn exception_codes_are_named_by_kind() {
        assert_eq!(
            user_exception_name(0xE06D_7363),
            (UserExceptionKind::CppException, "C++ exception")
        );
        assert_eq!(
            user_exception_name(0xE043_4F4D).0,
            UserExceptionKind::ClrException
        );
        assert_eq!(
            user_exception_name(0xC000_0005),
            (UserExceptionKind::Ntstatus, "STATUS_ACCESS_VIOLATION")
        );
        // The customer bit marks a code the application chose; it has no
        // standard name.
        assert_eq!(
            user_exception_name(0xE0D7_E5E1).0,
            UserExceptionKind::ApplicationDefined
        );
        assert_eq!(
            user_exception_name(0xC0AB_CDEF).0,
            UserExceptionKind::Unknown
        );
    }

    #[test]
    fn exception_flags_are_named_and_unknown_bits_kept() {
        assert_eq!(
            exception_flag_names(0x81),
            ["EXCEPTION_NONCONTINUABLE", "EXCEPTION_SOFTWARE_ORIGINATE"]
        );
        assert_eq!(exception_flag_names(0x300), ["0x300"]);
        assert!(exception_flag_names(0).is_empty());
    }

    #[test]
    fn type_descriptor_names_undecorate_plain_types_only() {
        assert_eq!(
            undecorate_type_descriptor(".?AVruntime_error@std@@"),
            "std::runtime_error"
        );
        assert_eq!(undecorate_type_descriptor(".?AUFault@@"), "Fault");
        assert_eq!(undecorate_type_descriptor(".H"), "int");
        assert_eq!(undecorate_type_descriptor(".PEBD"), "const char *");
        // A template keeps its decoration rather than a wrong guess.
        assert_eq!(
            undecorate_type_descriptor(".?AV?$basic_string@DU?$char_traits@D@std@@@std@@"),
            ".?AV?$basic_string@DU?$char_traits@D@std@@@std@@"
        );
    }

    #[test]
    fn thrown_type_follows_the_throw_info_rvas() {
        const BASE: u64 = 0x1_4000_0000;
        let mut memory = HashMap::new();
        let mut put = |address: u64, bytes: &[u8]| {
            for (offset, byte) in bytes.iter().enumerate() {
                memory.insert(address + offset as u64, *byte);
            }
        };
        // ThrowInfo at +0x1000: pCatchableTypeArray (offset 12) -> +0x2000.
        put(BASE + 0x1000 + 12, &0x2000u32.to_le_bytes());
        // CatchableTypeArray: count, then the first CatchableType -> +0x3000.
        put(BASE + 0x2000, &2u32.to_le_bytes());
        put(BASE + 0x2004, &0x3000u32.to_le_bytes());
        // CatchableType: properties, then pType -> +0x4000.
        put(BASE + 0x3004, &0x4000u32.to_le_bytes());
        // TypeDescriptor: vftable, spare, then the name.
        put(BASE + 0x4010, b".?AVlogic_error@std@@\0");
        let read = |address: u64, buf: &mut [u8]| {
            buf.iter_mut().enumerate().all(|(offset, byte)| {
                memory
                    .get(&(address + offset as u64))
                    .map(|value| *byte = *value)
                    .is_some()
            })
        };
        assert_eq!(
            cpp_thrown_type(BASE + 0x1000, BASE, read).as_deref(),
            Some("std::logic_error")
        );
        // A ThrowInfo whose pages the dump lacks yields nothing.
        assert_eq!(cpp_thrown_type(BASE + 0x9000, BASE, read), None);
    }

    #[test]
    fn a_raise_in_a_system_module_is_blamed_on_its_caller() {
        let modules = modules();
        let trace = StackTrace {
            frames: vec![
                frame(
                    0x7ff9_0000_1000,
                    "kernelbase!RaiseException+0x8a",
                    FrameSource::Current,
                ),
                frame(
                    0x7ff8_0000_2000,
                    "vcruntime140!_CxxThrowException+0x90",
                    FrameSource::Unwind,
                ),
                frame(0x1_4000_3000, "app!Parse+0x40", FrameSource::Unwind),
            ],
            truncated: 0,
        };
        let blamed = blamed_frame(&trace, 0, owner_in(&modules, 0)).unwrap();
        assert_eq!(blamed.index, 2);
        assert_eq!(
            blamed.owner,
            CodeOwner::Module {
                name: "app.exe".into(),
                system: false
            }
        );
    }

    #[test]
    fn a_caller_in_no_module_is_reported_as_such() {
        let modules = modules();
        let trace = StackTrace {
            frames: vec![
                frame(
                    0x7ff9_0000_1000,
                    "kernelbase!RaiseException+0x8a",
                    FrameSource::Current,
                ),
                frame(0x7ff6_0000_0040, "0x7ff600000040", FrameSource::Unwind),
                frame(0x7ff6_0000_0040, "0x7ff600000040", FrameSource::Unwind),
                frame(
                    0x7ff9_0000_2000,
                    "kernelbase!Callback+0x10",
                    FrameSource::Unwind,
                ),
                frame(0x1_4000_3000, "app!Main+0x40", FrameSource::Unwind),
            ],
            truncated: 0,
        };
        let owner = owner_in(&modules, 0x7ff6_0000_0040);
        let blamed = blamed_frame(&trace, 0, &owner).unwrap();
        assert_eq!(blamed.index, 1);
        assert!(matches!(blamed.owner, CodeOwner::DynamicCode { .. }));
        // What called into the JIT code is the next frame a module holds,
        // system or not.
        let caller = module_caller(&trace, &blamed, &owner).unwrap();
        assert_eq!(caller.index, 3);
        // A blamed frame in a module has no caller to name.
        let app = blamed_frame(&trace, 4, &owner).unwrap();
        assert!(module_caller(&trace, &app, &owner).is_none());
        // Only system frames: nothing to blame.
        let trace = StackTrace {
            frames: vec![frame(
                0x7ff7_0000_0100,
                "clr!IL_Throw+0x10",
                FrameSource::Current,
            )],
            truncated: 0,
        };
        assert!(blamed_frame(&trace, 0, owner_in(&modules, 0)).is_none());
    }
}
