use crate::error::Result;
use crate::repl::args::{ArgCursor, ArgCx, ArgError};
use crate::repl::*;
use crate::session::Session;
use crate::target::usermode::{
    ImageByteDiff, ImageCheck, ImageMismatchRange, ImageSectionCheck, ImageSelfPatchCounts,
    ImageSelfPatchRange, LastError, LastError32, LoaderListHead, LoaderLists, LoaderModules, Peb,
    Peb32, ProcessParameters, SelfPatchKind, Teb, Teb32,
};
use crate::target::{DiagnosticValue, ListTermination};
use crate::types::VirtAddr;
use crate::ui;
use ntoseye_macros::command;
use tabled::builder::Builder;

use super::diagnostics::{diagnostic_addr, diagnostic_cell};

/// `[address]`: one optional expression; more words print the help.
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
    python = [Process, UserProcess],
    python_name = "decode_peb",
    usage = "!peb [address]",
    completion = [Expression]
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
    python = [Thread, UserThread],
    python_name = "decode_teb",
    usage = "!teb [address]",
    completion = [Expression]
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
    python = [Process, UserProcess],
    python_name = "loader_modules",
    usage = "!dlls [-c <address>]",
    completion = [None, Expression]
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
    python = [Thread, UserThread],
    usage = "!gle"
)]
fn last_error(session: &Session) -> Result<LastError> {
    session.target.last_error()
}

impl Render for LastError {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_last_error(self);
    }
}

/// `<module>`: the one word the switches leave; none, or more, print the
/// help.
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
    usage = "!chkimg [-d] [-v] [-nospec] <module>",
    completion = [None, None, None, Symbol]
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

fn print_process_parameters(parameters: &ProcessParameters) {
    outln!(
        "    CommandLine       : {}",
        diagnostic_cell(&parameters.command_line)
    );
    outln!(
        "    ImagePathName     : {}",
        diagnostic_cell(&parameters.image_path_name)
    );
    outln!(
        "    CurrentDirectory  : {}",
        diagnostic_cell(&parameters.current_directory)
    );
    outln!(
        "    DllPath           : {}",
        diagnostic_cell(&parameters.dll_path)
    );
    outln!(
        "    WindowTitle       : {}",
        diagnostic_cell(&parameters.window_title)
    );
    outln!(
        "    Environment       : {}",
        diagnostic_addr(&parameters.environment)
    );
    outln!(
        "    EnvironmentSize   : {}",
        diagnostic_cell(&parameters.environment_size)
    );
    outln!(
        "    DesktopInfo       : {}",
        diagnostic_cell(&parameters.desktop_info)
    );
    outln!(
        "    ShellInfo         : {}",
        diagnostic_cell(&parameters.shell_info)
    );
    outln!(
        "    RuntimeData       : {}",
        diagnostic_cell(&parameters.runtime_data)
    );
}

fn print_parameters_field(
    pointer: &DiagnosticValue<VirtAddr>,
    detail: &DiagnosticValue<ProcessParameters>,
) {
    match pointer {
        DiagnosticValue::Available(address) if address.is_zero() => {
            outln!("  Process parameters : <unavailable or null>");
        }
        DiagnosticValue::Available(address) => {
            outln!("  Process parameters {}", ui::addr(address.0));
            match detail {
                DiagnosticValue::Available(parameters) => print_process_parameters(parameters),
                DiagnosticValue::Unavailable(error) => {
                    outln!("    process-parameter layout: <unavailable: {error}>");
                }
            }
        }
        DiagnosticValue::Unavailable(error) => {
            outln!("  Process parameters : <unavailable: {error}>");
        }
    }
}

fn print_loader_list_head(label: &str, value: &DiagnosticValue<LoaderListHead>) {
    match value {
        DiagnosticValue::Available(head) => outln!(
            "  {label:22}: {} (Flink {}, Blink {})",
            ui::addr(head.address.0),
            diagnostic_addr(&head.flink),
            diagnostic_addr(&head.blink)
        ),
        DiagnosticValue::Unavailable(error) => {
            outln!("  {label:22}: <unavailable: {error}>");
        }
    }
}

fn print_loader_lists(value: &DiagnosticValue<LoaderLists>) {
    match value {
        DiagnosticValue::Available(heads) => {
            print_loader_list_head("InLoadOrderModuleList", &heads.in_load_order);
            print_loader_list_head("InMemoryOrderModuleList", &heads.in_memory_order);
            print_loader_list_head(
                "InInitializationOrderModuleList",
                &heads.in_initialization_order,
            );
        }
        DiagnosticValue::Unavailable(error) => {
            outln!("  Loader list heads    : <unavailable: {error}>");
        }
    }
}

fn print_peb32(detail: &Peb32) {
    outln!("PEB32 {}", ui::addr(detail.address.0));
    outln!(
        "  ImageBaseAddress : {}",
        diagnostic_addr(&detail.image_base_address)
    );
    outln!("  Ldr              : {}", diagnostic_addr(&detail.ldr));
    outln!(
        "  ProcessParameters : {}",
        diagnostic_addr(&detail.process_parameters)
    );
    outln!(
        "  ProcessHeap      : {}",
        diagnostic_addr(&detail.process_heap)
    );
    outln!(
        "  NumberOfHeaps    : {}",
        diagnostic_cell(&detail.number_of_heaps)
    );
    outln!(
        "  ProcessHeaps     : {}",
        diagnostic_addr(&detail.process_heaps)
    );
    outln!(
        "  BeingDebugged    : {}",
        diagnostic_cell(&detail.being_debugged)
    );
    for (label, value) in [
        ("OSMajorVersion", &detail.os_major_version),
        ("OSMinorVersion", &detail.os_minor_version),
        ("OSBuildNumber", &detail.os_build_number),
        ("SessionId", &detail.session_id),
        ("NumberOfProcessors", &detail.number_of_processors),
    ] {
        outln!("  {label:17}: {}", diagnostic_cell(value));
    }
    print_parameters_field(
        &detail.process_parameters,
        &detail.process_parameters_detail,
    );
    print_loader_lists(&detail.loader_lists);
}

fn print_peb(detail: &Peb) {
    outln!("PEB {}", ui::addr(detail.address.0));
    outln!(
        "  ImageBaseAddress : {}",
        diagnostic_addr(&detail.image_base_address)
    );
    outln!("  Ldr              : {}", diagnostic_addr(&detail.ldr));
    outln!(
        "  ProcessParameters : {}",
        diagnostic_addr(&detail.process_parameters)
    );
    outln!(
        "  ProcessHeap      : {}",
        diagnostic_addr(&detail.process_heap)
    );
    outln!(
        "  NumberOfHeaps    : {}",
        diagnostic_cell(&detail.number_of_heaps)
    );
    outln!(
        "  ProcessHeaps     : {}",
        diagnostic_addr(&detail.process_heaps)
    );
    outln!(
        "  BeingDebugged    : {}",
        diagnostic_cell(&detail.being_debugged)
    );
    for (label, value) in [
        ("OSMajorVersion", &detail.os_major_version),
        ("OSMinorVersion", &detail.os_minor_version),
        ("OSBuildNumber", &detail.os_build_number),
        ("SessionId", &detail.session_id),
        ("NumberOfProcessors", &detail.number_of_processors),
    ] {
        outln!("  {label:17}: {}", diagnostic_cell(value));
    }
    print_parameters_field(
        &detail.process_parameters,
        &detail.process_parameters_detail,
    );
    print_loader_lists(&detail.loader_lists);
    outln!(
        "  ApiSetMap          : {}",
        diagnostic_addr(&detail.api_set_map)
    );
    if let Some(peb32) = &detail.peb32 {
        print_peb32(peb32);
    }
}

fn display_activation(value: &DiagnosticValue<Option<VirtAddr>>) -> String {
    match value {
        DiagnosticValue::Available(Some(address)) => {
            format!("present ({})", ui::addr(address.0))
        }
        DiagnosticValue::Available(None) => "absent".into(),
        DiagnosticValue::Unavailable(error) => format!("<unavailable: {error}>"),
    }
}

fn print_teb32(detail: &Teb32) {
    outln!("TEB32 {}", ui::addr(detail.address.0));
    outln!(
        "  {:30}: {}",
        "StackBase",
        diagnostic_addr(&detail.stack_base)
    );
    outln!(
        "  {:30}: {}",
        "StackLimit",
        diagnostic_addr(&detail.stack_limit)
    );
    outln!(
        "  {:30}: {}",
        "TlsPointer",
        diagnostic_addr(&detail.tls_pointer)
    );
    outln!(
        "  {:30}: {}",
        "LastErrorValue",
        diagnostic_cell(&detail.last_error_value)
    );
    outln!(
        "  {:30}: {}",
        "LastStatusValue",
        diagnostic_cell(&detail.last_status_value)
    );
    outln!(
        "  {:30}: {}",
        "CountOfOwnedCriticalSections",
        diagnostic_cell(&detail.count_of_owned_critical_sections)
    );
    outln!("  {:30}: {}", "PEB", diagnostic_addr(&detail.peb));
    outln!(
        "  ClientId.UniqueProcess          : {}",
        diagnostic_addr(&detail.client_id_unique_process)
    );
    outln!(
        "  ClientId.UniqueThread           : {}",
        diagnostic_addr(&detail.client_id_unique_thread)
    );
}

fn print_teb(detail: &Teb) {
    outln!("TEB {}", ui::addr(detail.address.0));
    outln!(
        "  {:30}: {}",
        "StackBase",
        diagnostic_addr(&detail.stack_base)
    );
    outln!(
        "  {:30}: {}",
        "StackLimit",
        diagnostic_addr(&detail.stack_limit)
    );
    outln!(
        "  {:30}: {}",
        "TlsPointer",
        diagnostic_addr(&detail.tls_pointer)
    );
    outln!(
        "  {:30}: {}",
        "LastErrorValue",
        diagnostic_cell(&detail.last_error_value)
    );
    outln!(
        "  {:30}: {}",
        "LastStatusValue",
        diagnostic_cell(&detail.last_status_value)
    );
    outln!(
        "  {:30}: {}",
        "CountOfOwnedCriticalSections",
        diagnostic_cell(&detail.count_of_owned_critical_sections)
    );
    outln!("  {:30}: {}", "PEB", diagnostic_addr(&detail.peb));
    match &detail.wow_teb_offset {
        DiagnosticValue::Available(value) => {
            outln!("  {:30}: {value} ({value:#x})", "WOW64");
        }
        DiagnosticValue::Unavailable(_) => {
            outln!(
                "  {:30}: {}",
                "WOW64",
                diagnostic_addr(&detail.wow64_reserved)
            );
        }
    }
    outln!(
        "  ActivationContext             : {}",
        display_activation(&detail.activation_context)
    );
    outln!(
        "  ClientId.UniqueProcess          : {}",
        diagnostic_addr(&detail.client_id_unique_process)
    );
    outln!(
        "  ClientId.UniqueThread           : {}",
        diagnostic_addr(&detail.client_id_unique_thread)
    );
    if let Some(teb32) = &detail.teb32 {
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
    outln!("{} loader modules", detail.modules.len());
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
                .map(|value| format!("{value:#x}"))
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

fn display_named_value(
    value: &DiagnosticValue<u32>,
    name: &DiagnosticValue<Option<String>>,
    format_value: impl Fn(u32) -> String,
) -> String {
    match value {
        DiagnosticValue::Unavailable(error) => format!("<unavailable: {error}>"),
        DiagnosticValue::Available(value) => {
            let name = match name {
                DiagnosticValue::Available(Some(name)) => name.as_str(),
                DiagnosticValue::Available(None) => "unknown",
                DiagnosticValue::Unavailable(_) => "unknown",
            };
            format!("{} ({name})", format_value(*value))
        }
    }
}

fn print_last_error32(detail: &LastError32) {
    outln!(
        "TEB32 LastErrorValue = {}",
        display_named_value(&detail.last_error_value, &detail.last_error_name, |value| {
            value.to_string()
        })
    );
    outln!(
        "TEB32 LastStatusValue = {}",
        display_named_value(
            &detail.last_status_value,
            &detail.last_status_name,
            |value| format!("{value:#010x}")
        )
    );
}

fn print_last_error(detail: &LastError) {
    outln!(
        "LastErrorValue = {}",
        display_named_value(&detail.last_error_value, &detail.last_error_name, |value| {
            value.to_string()
        })
    );
    outln!(
        "LastStatusValue = {}",
        display_named_value(
            &detail.last_status_value,
            &detail.last_status_name,
            |value| format!("{value:#010x}")
        )
    );
    if let Some(teb32) = &detail.teb32 {
        print_last_error32(teb32);
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
            outln!("    {count} bytes: {}", kind.as_str());
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
            range.kind.as_str(),
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
                kind.as_str()
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
