use std::fmt::Display;

use crate::error::Result;
use crate::repl::*;
use crate::target::usermode::{
    ByteDiff, ImageCheckDetail, ImageSectionResult, LastError32Detail, LastErrorDetail,
    LoaderListHead, LoaderListHeads, LoaderModulesDetail, MismatchRange, Peb32Detail, PebDetail,
    ProcessParametersDetail, SelfPatchCounts, SelfPatchRange, Teb32Detail, TebDetail,
};
use crate::target::{DiagnosticValue, ListTermination};
use crate::types::VirtAddr;
use crate::ui;
use tabled::builder::Builder;

repl_command! {
    cmd_peb;
    names: ["!peb", "peb"],
    usage: "!peb [address]",
    summary: "Decode the attached process environment block and parameters.",
    details: "Without an address, uses the attached process's EPROCESS.Peb. Process parameters are decoded from their PDB layouts; use !dlls to list loader modules.",
    completion: Expression,
}

repl_command! {
    cmd_teb;
    names: ["!teb", "teb"],
    usage: "!teb [address]",
    summary: "Decode a thread environment block.",
    details: "Without an address, uses the current thread's teb pseudo-register.",
    completion: Expression,
}

repl_command! {
    cmd_dlls;
    names: ["!dlls", "dlls"],
    usage: "!dlls [-c <address>]",
    summary: "List modules from the attached process loader lists.",
    details: "The optional -c address limits the output to the module containing that address. Module traversal is bounded and cycle-safe.",
    completion: [None, Expression],
}

repl_command! {
    cmd_gle();
    names: ["!gle", "gle"],
    usage: "!gle",
    summary: "Display the current thread's last Win32 and NT status values.",
    completion: None,
}

repl_command! {
    cmd_chkimg;
    names: ["!chkimg", "chkimg"],
    usage: "!chkimg [-d] [-v] [-nospec] <module>",
    summary: "Compare executable module sections with the cached on-disk image.",
    details: "Compares .text, PAGE*, and INIT executable sections after applying DIR64/HIGHLOW relocations. Discardable or paged-out sections are skipped. Known kernel self-patches (import optimization, retpoline, KiPatchSelf retargets) are counted separately unless -nospec is given, which drops that breakdown and reports them as ordinary mismatches. -d prints bounded byte diffs; -v prints per-section results.",
    completion: [None, None, None, Symbol],
}

fn display_diagnostic<T: Display>(value: &DiagnosticValue<T>) -> String {
    match value {
        DiagnosticValue::Available(value) => value.to_string(),
        DiagnosticValue::Unavailable(error) => format!("<unavailable: {error}>"),
    }
}

fn display_pointer(value: &DiagnosticValue<VirtAddr>) -> String {
    match value {
        DiagnosticValue::Available(value) => ui::addr(value.0),
        DiagnosticValue::Unavailable(error) => format!("<unavailable: {error}>"),
    }
}

fn display_u8(value: &DiagnosticValue<u8>) -> String {
    display_diagnostic(value)
}

fn display_parameter_string(value: &DiagnosticValue<String>) -> String {
    display_diagnostic(value)
}

fn print_process_parameters(parameters: &ProcessParametersDetail) {
    outln!(
        "    CommandLine       : {}",
        display_parameter_string(&parameters.command_line)
    );
    outln!(
        "    ImagePathName     : {}",
        display_parameter_string(&parameters.image_path_name)
    );
    outln!(
        "    CurrentDirectory  : {}",
        display_parameter_string(&parameters.current_directory)
    );
    outln!(
        "    DllPath           : {}",
        display_parameter_string(&parameters.dll_path)
    );
    outln!(
        "    WindowTitle       : {}",
        display_parameter_string(&parameters.window_title)
    );
    outln!(
        "    Environment       : {}",
        display_pointer(&parameters.environment)
    );
    outln!(
        "    EnvironmentSize   : {}",
        display_diagnostic(&parameters.environment_size)
    );
    outln!(
        "    DesktopInfo       : {}",
        display_parameter_string(&parameters.desktop_info)
    );
    outln!(
        "    ShellInfo         : {}",
        display_parameter_string(&parameters.shell_info)
    );
    outln!(
        "    RuntimeData       : {}",
        display_parameter_string(&parameters.runtime_data)
    );
}

fn print_parameters_field(
    pointer: &DiagnosticValue<VirtAddr>,
    detail: &DiagnosticValue<ProcessParametersDetail>,
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
            display_pointer(&head.flink),
            display_pointer(&head.blink)
        ),
        DiagnosticValue::Unavailable(error) => {
            outln!("  {label:22}: <unavailable: {error}>");
        }
    }
}

fn print_loader_lists(value: &DiagnosticValue<LoaderListHeads>) {
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

fn print_peb32(detail: &Peb32Detail) {
    outln!("PEB32 {}", ui::addr(detail.address.0));
    outln!(
        "  ImageBaseAddress : {}",
        display_pointer(&detail.image_base_address)
    );
    outln!("  Ldr              : {}", display_pointer(&detail.ldr));
    outln!(
        "  ProcessParameters : {}",
        display_pointer(&detail.process_parameters)
    );
    outln!(
        "  ProcessHeap      : {}",
        display_pointer(&detail.process_heap)
    );
    outln!(
        "  NumberOfHeaps    : {}",
        display_diagnostic(&detail.number_of_heaps)
    );
    outln!(
        "  ProcessHeaps     : {}",
        display_pointer(&detail.process_heaps)
    );
    outln!(
        "  BeingDebugged    : {}",
        display_u8(&detail.being_debugged)
    );
    for (label, value) in [
        ("OSMajorVersion", &detail.os_major_version),
        ("OSMinorVersion", &detail.os_minor_version),
        ("OSBuildNumber", &detail.os_build_number),
        ("SessionId", &detail.session_id),
        ("NumberOfProcessors", &detail.number_of_processors),
    ] {
        outln!("  {label:17}: {}", display_diagnostic(value));
    }
    print_parameters_field(
        &detail.process_parameters,
        &detail.process_parameters_detail,
    );
    print_loader_lists(&detail.loader_lists);
}

fn print_peb(detail: &PebDetail) {
    outln!("PEB {}", ui::addr(detail.address.0));
    outln!(
        "  ImageBaseAddress : {}",
        display_pointer(&detail.image_base_address)
    );
    outln!("  Ldr              : {}", display_pointer(&detail.ldr));
    outln!(
        "  ProcessParameters : {}",
        display_pointer(&detail.process_parameters)
    );
    outln!(
        "  ProcessHeap      : {}",
        display_pointer(&detail.process_heap)
    );
    outln!(
        "  NumberOfHeaps    : {}",
        display_diagnostic(&detail.number_of_heaps)
    );
    outln!(
        "  ProcessHeaps     : {}",
        display_pointer(&detail.process_heaps)
    );
    outln!(
        "  BeingDebugged    : {}",
        display_u8(&detail.being_debugged)
    );
    for (label, value) in [
        ("OSMajorVersion", &detail.os_major_version),
        ("OSMinorVersion", &detail.os_minor_version),
        ("OSBuildNumber", &detail.os_build_number),
        ("SessionId", &detail.session_id),
        ("NumberOfProcessors", &detail.number_of_processors),
    ] {
        outln!("  {label:17}: {}", display_diagnostic(value));
    }
    print_parameters_field(
        &detail.process_parameters,
        &detail.process_parameters_detail,
    );
    print_loader_lists(&detail.loader_lists);
    outln!(
        "  ApiSetMap          : {}",
        display_pointer(&detail.api_set_map)
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

fn print_teb32(detail: &Teb32Detail) {
    outln!("TEB32 {}", ui::addr(detail.address.0));
    outln!(
        "  {:30}: {}",
        "StackBase",
        display_pointer(&detail.stack_base)
    );
    outln!(
        "  {:30}: {}",
        "StackLimit",
        display_pointer(&detail.stack_limit)
    );
    outln!(
        "  {:30}: {}",
        "TlsPointer",
        display_pointer(&detail.tls_pointer)
    );
    outln!(
        "  {:30}: {}",
        "LastErrorValue",
        display_diagnostic(&detail.last_error_value)
    );
    outln!(
        "  {:30}: {}",
        "LastStatusValue",
        display_diagnostic(&detail.last_status_value)
    );
    outln!(
        "  {:30}: {}",
        "CountOfOwnedCriticalSections",
        display_diagnostic(&detail.count_of_owned_critical_sections)
    );
    outln!("  {:30}: {}", "PEB", display_pointer(&detail.peb));
    outln!(
        "  ClientId.UniqueProcess          : {}",
        display_pointer(&detail.client_id_unique_process)
    );
    outln!(
        "  ClientId.UniqueThread           : {}",
        display_pointer(&detail.client_id_unique_thread)
    );
}

fn print_teb(detail: &TebDetail) {
    outln!("TEB {}", ui::addr(detail.address.0));
    outln!(
        "  {:30}: {}",
        "StackBase",
        display_pointer(&detail.stack_base)
    );
    outln!(
        "  {:30}: {}",
        "StackLimit",
        display_pointer(&detail.stack_limit)
    );
    outln!(
        "  {:30}: {}",
        "TlsPointer",
        display_pointer(&detail.tls_pointer)
    );
    outln!(
        "  {:30}: {}",
        "LastErrorValue",
        display_diagnostic(&detail.last_error_value)
    );
    outln!(
        "  {:30}: {}",
        "LastStatusValue",
        display_diagnostic(&detail.last_status_value)
    );
    outln!(
        "  {:30}: {}",
        "CountOfOwnedCriticalSections",
        display_diagnostic(&detail.count_of_owned_critical_sections)
    );
    outln!("  {:30}: {}", "PEB", display_pointer(&detail.peb));
    match &detail.wow_teb_offset {
        DiagnosticValue::Available(value) => {
            outln!("  {:30}: {value} ({value:#x})", "WOW64");
        }
        DiagnosticValue::Unavailable(_) => {
            outln!(
                "  {:30}: {}",
                "WOW64",
                display_pointer(&detail.wow64_reserved)
            );
        }
    }
    outln!(
        "  ActivationContext             : {}",
        display_activation(&detail.activation_context)
    );
    outln!(
        "  ClientId.UniqueProcess          : {}",
        display_pointer(&detail.client_id_unique_process)
    );
    outln!(
        "  ClientId.UniqueThread           : {}",
        display_pointer(&detail.client_id_unique_thread)
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

fn print_loader_module_table(detail: &LoaderModulesDetail) {
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

fn print_last_error32(detail: &LastError32Detail) {
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

fn print_last_error(detail: &LastErrorDetail) {
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

fn print_self_patch_counts(counts: &SelfPatchCounts) {
    if counts.total() == 0 {
        return;
    }
    outln!(
        "  {} bytes in known kernel self-patches (import optimization/retpoline)",
        counts.total()
    );
    if counts.import_optimization != 0 {
        outln!(
            "    {} bytes: import optimization",
            counts.import_optimization
        );
    }
    if counts.retpoline != 0 {
        outln!("    {} bytes: retpoline", counts.retpoline);
    }
    if counts.ki_patch_self != 0 {
        outln!("    {} bytes: KiPatchSelf/JMP thunk", counts.ki_patch_self);
    }
}

fn print_section_result(section: &ImageSectionResult, no_spec: bool, verbose: bool) {
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

fn print_mismatch_ranges(ranges: &[MismatchRange], overflow: bool) {
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

fn print_self_patch_ranges(ranges: &[SelfPatchRange], overflow: bool) {
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
            range.kind.name(),
            function
        );
    }
}

fn print_byte_diffs(diffs: &[ByteDiff], truncated: bool, no_spec: bool) {
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
                kind.name()
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

fn print_image_check(detail: &ImageCheckDetail, no_spec: bool, verbose: bool) {
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

impl ReplState<'_> {
    fn cmd_peb(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if invocation.argv.len() > 1 {
            outln!("{}\n", command_help("!peb"));
            return Ok(());
        }
        let address = match invocation.arg(0) {
            Some(text) => match self.eval_or_report(text) {
                Some(address) => Some(address),
                None => return Ok(()),
            },
            None => None,
        };
        match self.ctx.target.inspect_peb(address) {
            Ok(detail) => print_peb(&detail),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_teb(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if invocation.argv.len() > 1 {
            outln!("{}\n", command_help("!teb"));
            return Ok(());
        }
        let address = match invocation.arg(0) {
            Some(text) => match self.eval_or_report(text) {
                Some(address) => Some(address),
                None => return Ok(()),
            },
            None => None,
        };
        match self.ctx.target.inspect_teb(address) {
            Ok(detail) => print_teb(&detail),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_dlls(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let mut filter = None;
        let mut arguments = invocation.argv.iter();
        while let Some(argument) = arguments.next() {
            if argument.as_ref() != "-c" || filter.is_some() {
                if argument.as_ref() == "-c" && filter.is_some() {
                    error!("!dlls: -c may only be specified once");
                } else {
                    outln!("{}\n", command_help("!dlls"));
                }
                return Ok(());
            }
            let Some(text) = arguments.next() else {
                outln!("{}\n", command_help("!dlls"));
                return Ok(());
            };
            filter = match self.eval_or_report(text) {
                Some(address) => Some(address),
                None => return Ok(()),
            };
        }
        match self.ctx.target.loader_modules(filter) {
            Ok(detail) => print_loader_module_table(&detail),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_gle(&mut self) -> Result<()> {
        match self.ctx.target.last_error() {
            Ok(detail) => print_last_error(&detail),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_chkimg(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let mut show_diffs = false;
        let mut verbose = false;
        let mut no_spec = false;
        let mut module_name = None;
        for argument in &invocation.argv {
            match argument.as_ref() {
                "-d" => show_diffs = true,
                "-v" => verbose = true,
                "-nospec" => no_spec = true,
                value if module_name.is_none() => module_name = Some(value),
                _ => {
                    outln!("{}\n", command_help("!chkimg"));
                    return Ok(());
                }
            }
        }
        let Some(module_name) = module_name else {
            outln!("{}\n", command_help("!chkimg"));
            return Ok(());
        };
        match self.ctx.target.check_image(module_name, show_diffs) {
            Ok(detail) => print_image_check(&detail, no_spec, verbose),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }
}
