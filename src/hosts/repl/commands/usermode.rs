use crate::base::error::Result;
use crate::base::types::VirtAddr;
use crate::hosts::repl::args::{ArgCursor, ArgCx, ArgError};
use crate::hosts::repl::*;
use crate::hosts::ui;
use crate::nt::target::usermode::critsec::{CriticalSection, CriticalSections};
use crate::nt::target::usermode::runaway::{ThreadTime, ThreadTimes};
use crate::nt::target::usermode::{
    ImageByteDiff, ImageCheck, ImageMismatchRange, ImageSectionCheck, ImageSelfPatchCounts,
    ImageSelfPatchRange, LastError, LoaderListHead, LoaderLists, LoaderModules, Peb, Peb32,
    ProcessParameters, SelfPatchKind, Teb, Teb32,
};
use crate::nt::target::{DiagnosticValue, ListTermination};
use crate::session::Session;
use ntoseye_macros::{command, grammar};
use tabled::builder::Builder;

use std::fmt::Display;

use super::process::display_pointer;

/// `[address]`: one optional expression; more words print the help.
#[grammar(usage = "[{}]", complete = [Expression])]
fn optional_address(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<Option<VirtAddr>, ArgError> {
    if cursor.remaining() > 1 {
        return Err(ArgError::Missing);
    }
    cursor.word().map(|text| cx.eval(&text)).transpose()
}

/// Decode the process environment block and process parameters of the
/// current process.
///
/// If you do not give an address, the command uses EPROCESS.Peb of the
/// current process: the one that .process selected, else the owner of the
/// current thread. On a user-mode minidump it uses the PEB that the selected
/// thread's TEB names, and the layouts of the dump's ntdll. It decodes the
/// process parameters with their PDB layouts. To list the loader modules,
/// use !dlls.
#[command(
    names = ["!peb", "peb"],
    category = "user mode",
    kind = Query,
    target = Nt,
    python = [Process, UserProcess],
    python_name = "decode_peb",
)]
fn peb(
    session: &Session,
    #[arg(parse = optional_address, positional)] address: Option<VirtAddr>,
) -> Result<Peb> {
    session.target.inspect_peb(address)
}

impl Render for Peb {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_peb(self);
    }
}

/// Decode a thread environment block.
///
/// If you do not give an address, the command uses the teb pseudo-register
/// of the current thread. On a user-mode minidump it uses the TEB of the
/// selected thread (~<n>s), and the layouts of the dump's ntdll.
#[command(
    names = ["!teb", "teb"],
    category = "user mode",
    kind = Query,
    target = Nt,
    python = [Thread, UserThread],
    python_name = "decode_teb",
)]
fn teb(
    session: &Session,
    #[arg(parse = optional_address, positional)] address: Option<VirtAddr>,
) -> Result<Teb> {
    session.target.inspect_teb(address)
}

impl Render for Teb {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_teb(self);
    }
}

/// `[-c <address>]`.
#[grammar(usage = "[-c <address>]", complete = [None, Expression])]
fn dlls_filter(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<Option<VirtAddr>, ArgError> {
    let mut filter = None;
    while let Some(word) = cursor.word() {
        if word != "-c" {
            return Err(ArgError::Missing);
        }
        if filter.is_some() {
            return Err(ArgError::Message(
                "!dlls: -c may only be specified once".into(),
            ));
        }
        let text = cursor.word().ok_or(ArgError::Missing)?;
        filter = Some(cx.eval(&text)?);
    }
    Ok(filter)
}

/// List the modules in the loader lists of the current process.
///
/// The current process is the one that .process selected, else the owner of
/// the current thread; on a user-mode minidump, its one process, as far as
/// the dump captured the loader's lists (lm lists the dump's own module
/// list). With -c <address>, the command shows only the module that
/// contains that address. The module walk has a limit, and also stops if it
/// finds a cycle in a list.
#[command(
    names = ["!dlls", "dlls"],
    category = "user mode",
    kind = Query,
    target = Nt,
    python = [Process, UserProcess],
    python_name = "loader_modules",
)]
fn dlls(
    session: &Session,
    #[arg(parse = dlls_filter)] containing: Option<VirtAddr>,
) -> Result<LoaderModules> {
    session.target.loader_modules(containing)
}

impl Render for LoaderModules {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_loader_module_table(self);
    }
}

/// Show the last Win32 error value and the last NT status value of the
/// current thread.
#[command(
    names = ["!gle", "gle"],
    category = "user mode",
    kind = Query,
    target = Nt,
    python = [Thread, UserThread],
)]
fn last_error(session: &Session) -> Result<LastError> {
    session.target.last_error()
}

impl Render for LastError {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_last_error(self);
    }
}

/// Show the critical sections of the current process, or one critical section.
///
/// Without an address, the command lists the sections ntdll keeps on
/// RtlCriticalSectionList, each with whether a thread holds it, the owner's
/// thread ID, its recursion count, how many threads wait for it, and how
/// often threads have waited; -l lists only the held ones. A section
/// initialized without debug information (DebugInfo -1, as
/// ntdll!FastPebLock is) is not on that list: give its address. The current
/// process is the one that .process selected, else the owner of the current
/// thread; on a user-mode minidump, its one process. Needs ntdll's symbols.
#[command(
    names = ["!cs", "cs"],
    category = "user mode",
    kind = Query,
    target = Nt,
    forms = [critical_section, critical_sections],
)]
fn cs(
    session: &Session,
    #[arg(switch = "-l")] locked_only: bool,
    #[arg(name = "address")] address: Option<VirtAddr>,
) -> Result<CriticalSectionView> {
    match address {
        Some(address) => critical_section(session, address).map(CriticalSectionView::One),
        None => {
            critical_sections(session).map(|list| CriticalSectionView::List { list, locked_only })
        }
    }
}

/// Decode a critical section (`!cs address`).
#[command(form_of = cs, python = [Process, UserProcess])]
fn critical_section(session: &Session, address: VirtAddr) -> Result<CriticalSection> {
    session.target.critical_section(address)
}

/// List the critical sections of the process (`!cs`).
#[command(form_of = cs, python = [Process, UserProcess])]
fn critical_sections(session: &Session) -> Result<CriticalSections> {
    session.target.critical_sections()
}

/// What `!cs` read: one section, or the list, whole or only the held ones.
enum CriticalSectionView {
    One(CriticalSection),
    List {
        list: CriticalSections,
        locked_only: bool,
    },
}

impl Render for CriticalSectionView {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        match self {
            Self::One(section) => print_critical_section(section),
            Self::List { list, locked_only } => {
                let locked = list
                    .sections
                    .iter()
                    .filter(|section| section.locked() == Some(true))
                    .count();
                let count = list.sections.len();
                let walk = match &list.termination {
                    ListTermination::Head => String::new(),
                    ListTermination::Null => ", then a null link (the list is corrupt)".into(),
                    ListTermination::Cycle(address) => {
                        format!(", then a cycle at {:#x} (the list is corrupt)", address.0)
                    }
                    ListTermination::Bound => " (the walk stops there)".into(),
                    ListTermination::Corrupt(error) => format!(", then a read error: {error}"),
                };
                outln!(
                    "critical sections: list head {}, {count}{walk}, {locked} held",
                    ui::addr(list.list_head.0)
                );
                let shown: Vec<&CriticalSection> = list
                    .sections
                    .iter()
                    .filter(|section| !locked_only || section.locked() == Some(true))
                    .collect();
                if shown.is_empty() {
                    outln!("{}", ui::muted("no critical section is held"));
                    return;
                }
                let mut builder = Builder::default();
                builder.push_record([
                    "Address",
                    "State",
                    "Owner",
                    "Recursion",
                    "Waiters",
                    "Contention",
                    "Symbol",
                ]);
                for section in shown {
                    let (state, owner, recursion, waiters) = section_state(section);
                    builder.push_record([
                        ui::addr(section.address.0).to_string(),
                        state,
                        owner,
                        recursion,
                        waiters,
                        value_or_dash(&section.contention_count),
                        section.symbol.clone().unwrap_or_else(|| "-".into()),
                    ]);
                }
                print_padded_table(builder);
            }
        }
    }
}

/// A section's state, its owner's TID, its recursion count and its
/// waiters, each `-` while it is not held.
fn section_state(section: &CriticalSection) -> (String, String, String, String) {
    match section.locked() {
        Some(true) => (
            "locked".into(),
            match &section.owning_thread {
                DiagnosticValue::Available(tid) => format!("TID {tid:#x}"),
                DiagnosticValue::Unavailable(_) => "?".into(),
            },
            value_or_dash(&section.recursion_count),
            section
                .waiters()
                .map_or_else(|| "?".into(), |waiters| waiters.to_string()),
        ),
        Some(false) => ("free".into(), "-".into(), "-".into(), "-".into()),
        None => ("?".into(), "-".into(), "-".into(), "-".into()),
    }
}

fn value_or_dash<T: Display>(value: &DiagnosticValue<T>) -> String {
    match value {
        DiagnosticValue::Available(value) => value.to_string(),
        DiagnosticValue::Unavailable(_) => "-".into(),
    }
}

fn print_critical_section(section: &CriticalSection) {
    let field = |name: &str, value: String| outln!("  {name:<16} : {value}");
    outln!(
        "critical section {}{}",
        ui::addr(section.address.0),
        section
            .symbol
            .as_ref()
            .map(|symbol| format!(" ({})", ui::symbol(symbol)))
            .unwrap_or_default()
    );
    let (state, owner, recursion, waiters) = section_state(section);
    field("State", state);
    field("OwningThread", owner);
    field("RecursionCount", recursion);
    field("Waiters", waiters);
    field(
        "LockCount",
        match section.lock_count {
            DiagnosticValue::Available(count) => format!("{count:#x}"),
            DiagnosticValue::Unavailable(ref error) => format!("unavailable: {error}"),
        },
    );
    field("ContentionCount", value_or_dash(&section.contention_count));
    field(
        "DebugInfo",
        match section.debug_info {
            DiagnosticValue::Available(address) => ui::addr(address.0).to_string(),
            DiagnosticValue::Unavailable(ref error) => format!("unavailable: {error}"),
        },
    );
    field(
        "LockSemaphore",
        match section.lock_semaphore {
            DiagnosticValue::Available(address) => ui::addr(address.0).to_string(),
            DiagnosticValue::Unavailable(ref error) => format!("unavailable: {error}"),
        },
    );
    field(
        "SpinCount",
        match section.spin_count {
            DiagnosticValue::Available(count) => format!("{count:#x}"),
            DiagnosticValue::Unavailable(ref error) => format!("unavailable: {error}"),
        },
    );
}

/// Show how much processor time each thread of the current process has used.
///
/// The flags choose what to show, each as a list of the threads by that time,
/// most first: 1 the user-mode time (the default), 2 the kernel-mode time,
/// 4 the time since each thread started, so 7 shows all three. The current
/// process is the one that .process selected, else the owner of the current
/// thread; on a user-mode minidump, its one process, whose thread-info
/// stream records the times. A kernel target counts them in clock ticks, so
/// they are as precise as one tick (15.6 ms by default).
#[command(
    names = ["!runaway", "runaway"],
    category = "user mode",
    kind = Query,
    target = Nt,
    python = [Process, UserProcess],
    python_name = "thread_times",
)]
fn runaway(session: &Session, #[arg(default = 1, render)] flags: u64) -> Result<ThreadTimes> {
    session.target.thread_times()
}

impl Render<u64> for ThreadTimes {
    fn render(&self, _: &mut ReplState<'_>, flags: u64) {
        let flags = if flags & 7 == 0 { 1 } else { flags };
        let sections: [Section; 3] = [
            (1, "User Mode Time", |thread| thread.user_time),
            (2, "Kernel Mode Time", |thread| thread.kernel_time),
            (4, "Elapsed Time", |thread| thread.elapsed),
        ];
        if let (Some(process), Some(pid)) = (&self.process, self.pid) {
            outln!("{}", ui::muted(&format!("{process} (PID {pid})")));
        }
        for (bit, title, time) in sections {
            if flags & bit == 0 {
                continue;
            }
            let mut threads: Vec<&ThreadTime> = self.threads.iter().collect();
            threads.sort_by_key(|thread| std::cmp::Reverse(time(thread)));
            outln!(" {}", ui::label(title));
            let mut builder = Builder::default();
            builder.push_record(["Thread", "Time"]);
            for thread in threads {
                let label = match thread.index {
                    Some(index) => format!("{index}:{:x}", thread.tid),
                    None => format!("TID {}", thread.tid),
                };
                builder.push_record([
                    label,
                    time(thread).map_or_else(|| "-".to_string(), format_thread_time),
                ]);
            }
            print_padded_table(builder);
        }
    }
}

/// One list `!runaway` shows: its flag, its title, and the time it sorts by.
type Section = (u64, &'static str, fn(&ThreadTime) -> Option<u64>);

/// A time in 100 ns units as WinDbg's `!runaway` writes it:
/// `0 days 0:00:01.453`.
fn format_thread_time(time: u64) -> String {
    let millis = time / 10_000;
    let seconds = millis / 1000;
    format!(
        "{} days {}:{:02}:{:02}.{:03}",
        seconds / 86_400,
        seconds / 3600 % 24,
        seconds / 60 % 60,
        seconds % 60,
        millis % 1000
    )
}

/// `<module>`: the one word the switches leave; none, or more, print the
/// help.
#[grammar(usage = "<{}>", complete = [Symbol])]
fn chkimg_module(
    _: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<String, ArgError> {
    if cursor.remaining() != 1 {
        return Err(ArgError::Missing);
    }
    cursor
        .word()
        .map(|word| word.into_owned())
        .ok_or(ArgError::Missing)
}

/// Compare the executable sections of a module with the cached on-disk
/// image.
///
/// Compares the .text, PAGE*, and INIT executable sections after applying
/// the DIR64/HIGHLOW relocations, and skips discardable and paged-out
/// sections. The command counts known kernel self-patches separately:
/// import optimization, retpoline, KiPatchSelf retargets, and the addresses
/// of the kernel VA regions that the kernel moves at boot. With -nospec, the
/// command does not show this breakdown and reports the self-patches as
/// ordinary mismatches. -d prints byte diffs, up to a limit, and -v prints
/// the results for each section.
#[command(
    names = ["!chkimg", "chkimg"],
    category = "analysis",
    kind = Query,
    python = Module,
    python_name = "check_image",
)]
fn chkimg(
    session: &Session,
    #[arg(switch = "-d")] include_diffs: bool,
    #[arg(switch = "-v", render)] verbose: bool,
    #[arg(switch = "-nospec", render)] no_spec: bool,
    #[arg(receiver, parse = chkimg_module)] module: String,
) -> Result<ImageCheck> {
    session.check_image(&module, include_diffs)
}

impl Render<(bool, bool)> for ImageCheck {
    fn render(&self, _: &mut ReplState<'_>, (verbose, no_spec): (bool, bool)) {
        print_image_check(self, no_spec, verbose);
    }
}

/// A field's text, or why it could not be read.
type Cell = std::result::Result<String, String>;

/// `value` rendered, or the reason it is unavailable.
fn read<T>(value: &DiagnosticValue<T>, render: impl FnOnce(&T) -> String) -> Cell {
    match value {
        DiagnosticValue::Available(value) => Ok(render(value)),
        DiagnosticValue::Unavailable(error) => Err(error.clone()),
    }
}

/// A number as it reads.
fn number<T: Display>(value: &DiagnosticValue<T>) -> Cell {
    read(value, ToString::to_string)
}

/// Structure fields, one per line at `indent`, with the colons in one
/// column: `dt`'s layout, which `!teb` and `!peb` follow. A field that could
/// not be read shows `-`, and one muted note per reason after the block
/// says why.
fn print_fields(indent: usize, rows: &[(&str, Cell)]) {
    let width = rows.iter().map(|(name, _)| name.len()).max().unwrap_or(0);
    let mut unavailable: Vec<(&str, Vec<&str>)> = Vec::new();
    for (name, value) in rows {
        let text = match value {
            Ok(text) => text.as_str(),
            Err(reason) => {
                match unavailable.iter_mut().find(|(known, _)| *known == reason) {
                    Some((_, names)) => names.push(name),
                    None => unavailable.push((reason, vec![name])),
                }
                "-"
            }
        };
        outln!("{:indent$}{name:<width$} : {text}", "");
    }
    for (reason, names) in unavailable {
        outln!(
            "{:indent$}{}",
            "",
            ui::muted(&format!("{} unavailable: {reason}", names.join(", ")))
        );
    }
}

/// A pointer field: `-` for null.
fn pointer_cell(value: &DiagnosticValue<VirtAddr>) -> Cell {
    read(value, |address| display_pointer(Some(*address)))
}

/// A `UNICODE_STRING` field: `-` for an empty string.
fn text_cell(value: &DiagnosticValue<String>) -> Cell {
    read(value, |text| {
        if text.is_empty() {
            "-".to_string()
        } else {
            text.clone()
        }
    })
}

/// An NTSTATUS field: eight hex digits, as WinDbg shows status values.
fn status_cell(value: &DiagnosticValue<u32>) -> Cell {
    read(value, |status| format!("{status:#010x}"))
}

/// A `CLIENT_ID` half: an id, so `0x`-prefixed hex.
fn id_cell(value: &DiagnosticValue<VirtAddr>) -> Cell {
    read(value, |id| format!("{:#x}", id.0))
}

/// The decoded `_RTL_USER_PROCESS_PARAMETERS`, as a sub-block under the
/// PEB's fields; nothing when the pointer is null or unreadable, which the
/// `ProcessParameters` field already shows.
fn print_process_parameters(
    pointer: &DiagnosticValue<VirtAddr>,
    detail: &DiagnosticValue<ProcessParameters>,
) {
    let DiagnosticValue::Available(address) = pointer else {
        return;
    };
    if address.is_zero() {
        return;
    }
    outln!("  ProcessParameters {}", ui::addr(address.0));
    match detail {
        DiagnosticValue::Available(parameters) => print_fields(
            4,
            &[
                ("CommandLine", text_cell(&parameters.command_line)),
                ("ImagePathName", text_cell(&parameters.image_path_name)),
                ("CurrentDirectory", text_cell(&parameters.current_directory)),
                ("DllPath", text_cell(&parameters.dll_path)),
                ("WindowTitle", text_cell(&parameters.window_title)),
                ("Environment", pointer_cell(&parameters.environment)),
                (
                    "EnvironmentSize",
                    read(&parameters.environment_size, |size| format!("{size:#x}")),
                ),
                ("DesktopInfo", text_cell(&parameters.desktop_info)),
                ("ShellInfo", text_cell(&parameters.shell_info)),
                ("RuntimeData", text_cell(&parameters.runtime_data)),
            ],
        ),
        DiagnosticValue::Unavailable(error) => {
            outln!("    {}", ui::muted(&format!("layout unavailable: {error}")));
        }
    }
}

/// The three `_PEB_LDR_DATA` list heads, as `Flink . Blink` rows.
fn loader_list_rows(value: &DiagnosticValue<LoaderLists>) -> Vec<(&'static str, Cell)> {
    let head = |value: &DiagnosticValue<LoaderListHead>| -> Cell {
        match value {
            DiagnosticValue::Available(head) => Ok(format!(
                "{} . {}",
                pointer_cell(&head.flink)?,
                pointer_cell(&head.blink)?
            )),
            DiagnosticValue::Unavailable(error) => Err(error.clone()),
        }
    };
    let names = [
        "Ldr.InLoadOrderModuleList",
        "Ldr.InMemoryOrderModuleList",
        "Ldr.InInitializationOrderModuleList",
    ];
    match value {
        DiagnosticValue::Available(heads) => names
            .into_iter()
            .zip([
                head(&heads.in_load_order),
                head(&heads.in_memory_order),
                head(&heads.in_initialization_order),
            ])
            .collect(),
        DiagnosticValue::Unavailable(error) => names
            .into_iter()
            .map(|name| (name, Err(error.clone())))
            .collect(),
    }
}

fn print_peb32(detail: &Peb32) {
    outln!("PEB32 {}", ui::addr(detail.address.0));
    let mut rows = vec![
        ("ImageBaseAddress", pointer_cell(&detail.image_base_address)),
        ("Ldr", pointer_cell(&detail.ldr)),
    ];
    rows.extend(loader_list_rows(&detail.loader_lists));
    rows.extend([
        (
            "ProcessParameters",
            pointer_cell(&detail.process_parameters),
        ),
        ("ProcessHeap", pointer_cell(&detail.process_heap)),
        ("NumberOfHeaps", number(&detail.number_of_heaps)),
        ("ProcessHeaps", pointer_cell(&detail.process_heaps)),
        ("BeingDebugged", number(&detail.being_debugged)),
        ("OSMajorVersion", number(&detail.os_major_version)),
        ("OSMinorVersion", number(&detail.os_minor_version)),
        ("OSBuildNumber", number(&detail.os_build_number)),
        ("SessionId", number(&detail.session_id)),
        ("NumberOfProcessors", number(&detail.number_of_processors)),
    ]);
    print_fields(2, &rows);
    print_process_parameters(
        &detail.process_parameters,
        &detail.process_parameters_detail,
    );
}

fn print_peb(detail: &Peb) {
    outln!("PEB {}", ui::addr(detail.address.0));
    let mut rows = vec![
        ("ImageBaseAddress", pointer_cell(&detail.image_base_address)),
        ("Ldr", pointer_cell(&detail.ldr)),
    ];
    rows.extend(loader_list_rows(&detail.loader_lists));
    rows.extend([
        (
            "ProcessParameters",
            pointer_cell(&detail.process_parameters),
        ),
        ("ProcessHeap", pointer_cell(&detail.process_heap)),
        ("NumberOfHeaps", number(&detail.number_of_heaps)),
        ("ProcessHeaps", pointer_cell(&detail.process_heaps)),
        ("BeingDebugged", number(&detail.being_debugged)),
        ("OSMajorVersion", number(&detail.os_major_version)),
        ("OSMinorVersion", number(&detail.os_minor_version)),
        ("OSBuildNumber", number(&detail.os_build_number)),
        ("SessionId", number(&detail.session_id)),
        ("NumberOfProcessors", number(&detail.number_of_processors)),
        ("ApiSetMap", pointer_cell(&detail.api_set_map)),
    ]);
    print_fields(2, &rows);
    print_process_parameters(
        &detail.process_parameters,
        &detail.process_parameters_detail,
    );
    if let Some(peb32) = &detail.peb32 {
        outln!();
        print_peb32(peb32);
    }
}

fn print_teb32(detail: &Teb32) {
    outln!("TEB32 {}", ui::addr(detail.address.0));
    print_fields(
        2,
        &[
            ("StackBase", pointer_cell(&detail.stack_base)),
            ("StackLimit", pointer_cell(&detail.stack_limit)),
            ("TlsPointer", pointer_cell(&detail.tls_pointer)),
            (
                "ClientId.UniqueProcess",
                id_cell(&detail.client_id_unique_process),
            ),
            (
                "ClientId.UniqueThread",
                id_cell(&detail.client_id_unique_thread),
            ),
            ("PEB", pointer_cell(&detail.peb)),
            ("LastErrorValue", number(&detail.last_error_value)),
            ("LastStatusValue", status_cell(&detail.last_status_value)),
            (
                "CountOfOwnedCriticalSections",
                number(&detail.count_of_owned_critical_sections),
            ),
        ],
    );
}

fn print_teb(detail: &Teb) {
    outln!("TEB {}", ui::addr(detail.address.0));
    // WowTebOffset when the layout has it; older layouts name the WOW64
    // transition thunk in WOW32Reserved instead.
    let wow64 = match &detail.wow_teb_offset {
        DiagnosticValue::Available(offset) => ("WowTebOffset", Ok(format!("{offset:#x}"))),
        DiagnosticValue::Unavailable(_) => ("WOW32Reserved", pointer_cell(&detail.wow64_reserved)),
    };
    print_fields(
        2,
        &[
            ("StackBase", pointer_cell(&detail.stack_base)),
            ("StackLimit", pointer_cell(&detail.stack_limit)),
            ("TlsPointer", pointer_cell(&detail.tls_pointer)),
            (
                "ClientId.UniqueProcess",
                id_cell(&detail.client_id_unique_process),
            ),
            (
                "ClientId.UniqueThread",
                id_cell(&detail.client_id_unique_thread),
            ),
            ("PEB", pointer_cell(&detail.peb)),
            ("LastErrorValue", number(&detail.last_error_value)),
            ("LastStatusValue", status_cell(&detail.last_status_value)),
            (
                "CountOfOwnedCriticalSections",
                number(&detail.count_of_owned_critical_sections),
            ),
            wow64,
            (
                "ActivationContext",
                read(&detail.activation_context, |address| {
                    display_pointer(*address)
                }),
            ),
        ],
    );
    if let Some(teb32) = &detail.teb32 {
        outln!();
        print_teb32(teb32);
    }
}

fn termination_text(termination: &ListTermination) -> String {
    match termination {
        ListTermination::Head => "head".into(),
        ListTermination::Null => "null (corrupt)".into(),
        ListTermination::Cycle(address) => {
            format!("cycle at {} (corrupt)", ui::addr(address.0))
        }
        ListTermination::Bound => "bound (truncated)".into(),
        ListTermination::Corrupt(error) => format!("read error: {error}"),
    }
}

fn print_loader_module_table(detail: &LoaderModules) {
    let count = detail.modules.len();
    outln!(
        "{count} loader {}",
        if count == 1 { "module" } else { "modules" }
    );
    let mut builder = Builder::default();
    builder.push_record(["Base", "Size", "Entry", "Timestamp", "Name"]);
    for module in &detail.modules {
        builder.push_record([
            ui::addr(module.base_address.0),
            format!("{:#x}", module.size),
            module
                .entry_point
                .map(|address| ui::addr(address.0))
                .unwrap_or_else(|| "-".into()),
            module
                .time_date_stamp
                .map(|value| format!("{value:#010x}"))
                .unwrap_or_else(|| "-".into()),
            module.name.clone(),
        ]);
    }
    if !detail.modules.is_empty() {
        print_padded_table(builder);
    }
    if !matches!(detail.termination, ListTermination::Head) {
        outln!(
            "loader list terminated: {}",
            termination_text(&detail.termination)
        );
    }
    if let Some(termination) = &detail.wow64_termination
        && !matches!(termination, ListTermination::Head)
    {
        outln!(
            "32-bit loader list terminated: {}",
            termination_text(termination)
        );
    }
}

/// A value and, when it has one, its symbolic name.
fn named_value(
    value: &DiagnosticValue<u32>,
    name: &DiagnosticValue<Option<String>>,
    format_value: impl Fn(u32) -> String,
) -> Cell {
    read(value, |value| match name {
        DiagnosticValue::Available(Some(name)) => format!("{} ({name})", format_value(*value)),
        _ => format_value(*value),
    })
}

/// `!gle`'s two fields of one TEB.
fn print_last_error_fields(
    last_error: (&DiagnosticValue<u32>, &DiagnosticValue<Option<String>>),
    last_status: (&DiagnosticValue<u32>, &DiagnosticValue<Option<String>>),
) {
    print_fields(
        2,
        &[
            (
                "LastErrorValue",
                named_value(last_error.0, last_error.1, |value| value.to_string()),
            ),
            (
                "LastStatusValue",
                named_value(last_status.0, last_status.1, |value| {
                    format!("{value:#010x}")
                }),
            ),
        ],
    );
}

fn print_last_error(detail: &LastError) {
    outln!("TEB {}", ui::addr(detail.teb.0));
    print_last_error_fields(
        (&detail.last_error_value, &detail.last_error_name),
        (&detail.last_status_value, &detail.last_status_name),
    );
    if let Some(teb32) = &detail.teb32 {
        outln!("TEB32 {}", ui::addr(teb32.teb.0));
        print_last_error_fields(
            (&teb32.last_error_value, &teb32.last_error_name),
            (&teb32.last_status_value, &teb32.last_status_name),
        );
    }
}

fn print_self_patch_counts(counts: &ImageSelfPatchCounts) {
    if counts.total() == 0 {
        return;
    }
    outln!("  {} bytes in known kernel self-patches", counts.total());
    for kind in SelfPatchKind::ALL {
        let count = counts.get(kind);
        if count != 0 {
            outln!("    {count} bytes: {kind}");
        }
    }
}

fn print_section_result(section: &ImageSectionCheck, no_spec: bool, verbose: bool) {
    if section.skipped {
        outln!(
            "  {:<8} skipped ({})",
            section.name,
            section.skip_reason.as_deref().unwrap_or("paged out")
        );
    } else if let Some(error) = &section.unavailable {
        outln!("  {:<8} unavailable: {}", section.name, error);
    } else if verbose {
        if no_spec {
            outln!(
                "  {:<8} mismatches: {}",
                section.name,
                section.total_mismatches
            );
        } else if section.self_patches.total() != 0 {
            outln!(
                "  {:<8} mismatches: {} ({} known self-patch bytes)",
                section.name,
                section.genuine_mismatches,
                section.self_patches.total()
            );
        } else {
            outln!(
                "  {:<8} mismatches: {}",
                section.name,
                section.genuine_mismatches
            );
        }
    }
}

fn print_mismatch_ranges(ranges: &[ImageMismatchRange], overflow: bool) {
    if ranges.is_empty() {
        return;
    }
    let suffix = if overflow { ", first 64" } else { "" };
    outln!("mismatch ranges ({}{}):", ranges.len(), suffix);
    for range in ranges {
        outln!(
            "  RVA {:#x}-{:#x} ({} bytes)",
            range.start,
            range.end,
            range.end.saturating_sub(range.start)
        );
    }
}

fn print_self_patch_ranges(ranges: &[ImageSelfPatchRange], overflow: bool) {
    if ranges.is_empty() {
        return;
    }
    let suffix = if overflow { ", first 64" } else { "" };
    outln!("known self-patch ranges ({}{}):", ranges.len(), suffix);
    for range in ranges {
        let function = range
            .function
            .as_deref()
            .map(|name| format!(", inside {name}"))
            .unwrap_or_default();
        outln!(
            "  RVA {:#x}-{:#x} ({} bytes): {}{}",
            range.start,
            range.end,
            range.end.saturating_sub(range.start),
            range.kind,
            function
        );
    }
}

fn print_byte_diffs(diffs: &[ImageByteDiff], truncated: bool, no_spec: bool) {
    if diffs.is_empty() {
        return;
    }
    let suffix = if truncated { " (first 4096)" } else { "" };
    outln!("byte diffs{}:", suffix);
    for diff in diffs {
        if !no_spec && let Some(kind) = diff.kind {
            outln!(
                "  RVA {:#x}: expected {:02x}, actual {:02x} ({})",
                diff.rva,
                diff.expected,
                diff.actual,
                kind
            );
        } else {
            outln!(
                "  RVA {:#x}: expected {:02x}, actual {:02x}",
                diff.rva,
                diff.expected,
                diff.actual
            );
        }
    }
}

fn print_image_check(detail: &ImageCheck, no_spec: bool, verbose: bool) {
    if detail.sections.is_empty() {
        outln!("{}: no executable .text/PAGE*/INIT sections", detail.module);
        return;
    }
    for section in &detail.sections {
        if verbose || section.skipped || section.unavailable.is_some() {
            print_section_result(section, no_spec, verbose);
        }
    }
    let mismatched = if no_spec {
        detail.total_mismatched_bytes
    } else {
        detail.genuine_mismatched_bytes
    };
    outln!(
        "{}: {} genuine mismatched byte{}",
        detail.module,
        mismatched,
        if mismatched == 1 { "" } else { "s" }
    );
    if !no_spec {
        print_self_patch_counts(&detail.self_patches);
    }
    if no_spec {
        print_mismatch_ranges(
            &detail.all_mismatch_ranges,
            detail.all_mismatch_range_overflow,
        );
    } else {
        print_mismatch_ranges(&detail.mismatch_ranges, detail.mismatch_range_overflow);
    }
    if verbose && !no_spec {
        print_self_patch_ranges(&detail.self_patch_ranges, detail.self_patch_range_overflow);
    }
    print_byte_diffs(&detail.byte_diffs, detail.byte_diffs_truncated, no_spec);
}
