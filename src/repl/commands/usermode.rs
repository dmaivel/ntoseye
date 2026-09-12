use std::fs;

use crate::error::{Error, Result};
use crate::expr::Expr;
use crate::guest::{ModuleInfo, read_pe_header_page};
use crate::ntstatus::{ntstatus_name, win32_error_name};
use crate::repl::*;
use crate::target::Target;
use crate::types::{Arch, VirtAddr};
use crate::ui;
use iced_x86::{Code, Decoder, DecoderOptions};
use pelite::pe64::{Pe, PeView};
use tabled::builder::Builder;

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x0200_0000;
const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
const IMAGE_REL_BASED_HIGHLOW: u16 = 3;
const IMAGE_REL_BASED_DIR64: u16 = 10;
const MAX_REPORT_RANGES: usize = 64;
const MAX_BYTE_DIFFS: usize = 4096;
const SECTION_READ_CHUNK: usize = 0x1000;

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
    details: "Compares .text, PAGE*, and INIT executable sections after applying DIR64/HIGHLOW relocations. Discardable or paged-out sections are skipped. Known kernel self-patches are counted separately unless -nospec is given. -d prints bounded byte diffs; -v prints per-section results.",
    completion: [None, None, None, Symbol],
}

#[derive(Debug)]
struct CheckSection {
    name: String,
    rva: u32,
    expected: Vec<u8>,
    discardable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SelfPatchKind {
    ImportOptimization,
    Retpoline,
    KiPatchSelf,
}

impl SelfPatchKind {
    fn label(self) -> &'static str {
        match self {
            SelfPatchKind::ImportOptimization => "import optimization",
            SelfPatchKind::Retpoline => "retpoline",
            SelfPatchKind::KiPatchSelf => "KiPatchSelf/JMP thunk",
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct SelfPatchCounts {
    import_optimization: u64,
    retpoline: u64,
    ki_patch_self: u64,
}

impl SelfPatchCounts {
    fn add(&mut self, kind: SelfPatchKind, count: u64) {
        match kind {
            SelfPatchKind::ImportOptimization => self.import_optimization += count,
            SelfPatchKind::Retpoline => self.retpoline += count,
            SelfPatchKind::KiPatchSelf => self.ki_patch_self += count,
        }
    }

    fn total(self) -> u64 {
        self.import_optimization
            .saturating_add(self.retpoline)
            .saturating_add(self.ki_patch_self)
    }

    fn add_counts(&mut self, other: Self) {
        self.add(SelfPatchKind::ImportOptimization, other.import_optimization);
        self.add(SelfPatchKind::Retpoline, other.retpoline);
        self.add(SelfPatchKind::KiPatchSelf, other.ki_patch_self);
    }
}

#[derive(Debug)]
struct SelfPatchRange {
    start: u64,
    end: u64,
    kind: SelfPatchKind,
    function: Option<String>,
}

#[derive(Debug, Default)]
struct SectionCheckResult {
    genuine: u64,
    self_patches: SelfPatchCounts,
    skipped: bool,
    skip_reason: Option<&'static str>,
    unavailable: Option<String>,
    mismatch_ranges: Vec<MismatchRange>,
    mismatch_range_overflow: bool,
    self_patch_ranges: Vec<SelfPatchRange>,
    self_patch_range_overflow: bool,
    diffs: Vec<ByteDiff>,
}

#[derive(Debug)]
struct SelfPatchMatch {
    kind: SelfPatchKind,
    function: Option<String>,
}

#[derive(Debug, Clone, Copy)]
struct MismatchRange {
    start: u64,
    end: u64,
}

#[derive(Debug, Clone, Copy)]
struct ByteDiff {
    rva: u32,
    expected: u8,
    actual: u8,
    kind: Option<SelfPatchKind>,
}

fn attached_dtb(target: &Target) -> Result<u64> {
    target
        .current_process_info
        .as_ref()
        .map(|process| process.dtb)
        .ok_or_else(|| Error::DebugInfo("this command requires an attached user process".into()))
}

fn selected_thread_dtb(target: &Target, attached_dtb: u64) -> Result<u64> {
    let Some(thread) = target.windows_thread_selection.as_ref() else {
        return Ok(attached_dtb);
    };
    target.thread_process_dtb(thread).ok_or_else(|| {
        Error::DebugInfo(format!(
            "selected Windows thread's owning process DTB is unavailable; refusing to read its TEB through attached DTB {}",
            ui::addr(attached_dtb)
        ))
    })
}

fn resolve_peb(target: &Target, dtb: u64, explicit: Option<VirtAddr>) -> Result<VirtAddr> {
    if let Some(address) = explicit {
        return Ok(address);
    }
    let process = target
        .current_process_info
        .as_ref()
        .ok_or_else(|| Error::DebugInfo("no attached process".into()))?;
    let eprocess = target
        .guest()?
        .ntoskrnl
        .types_in(dtb)
        .struct_at("_EPROCESS", process.eprocess_va)?;
    let peb = eprocess.follow("Peb")?;
    if peb.addr().is_zero() {
        return Err(Error::MissingPEB);
    }
    Ok(peb.addr())
}

fn display_read<T: std::fmt::Display>(value: Result<T>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|error| format!("<unavailable: {error}>"))
}

fn display_ptr(value: Result<VirtAddr>) -> String {
    value
        .map(|value| ui::addr(value.0))
        .unwrap_or_else(|error| format!("<unavailable: {error}>"))
}

impl ReplState<'_> {
    fn cmd_peb(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if invocation.argv.len() > 1 {
            outln!("{}\n", command_help("!peb"));
            return Ok(());
        }
        let dtb = match attached_dtb(&self.ctx.target) {
            Ok(dtb) => dtb,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let explicit = match invocation.arg(0) {
            Some(text) => match Expr::eval_with_radix(text, &self.ctx.target, self.radix) {
                Ok(address) => Some(address),
                Err(error) => {
                    error!("{error}");
                    return Ok(());
                }
            },
            None => None,
        };
        let peb = match resolve_peb(&self.ctx.target, dtb, explicit) {
            Ok(address) => address,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let peb_ref = match self
            .ctx
            .target
            .guest()
            .and_then(|guest| guest.ntoskrnl.types_in(dtb).struct_at("_PEB", peb))
        {
            Ok(peb_ref) => peb_ref,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        outln!("PEB {}", ui::addr(peb.0));
        outln!(
            "  ImageBaseAddress : {}",
            display_ptr(peb_ref.read_field("ImageBaseAddress"))
        );
        outln!(
            "  Ldr              : {}",
            display_ptr(peb_ref.read_field("Ldr"))
        );
        outln!(
            "  ProcessParameters : {}",
            display_ptr(peb_ref.read_field("ProcessParameters"))
        );
        outln!(
            "  BeingDebugged    : {}",
            display_read(peb_ref.read_field::<u8>("BeingDebugged"))
        );
        for (label, value) in [
            (
                "OSMajorVersion",
                peb_ref.read_field::<u32>("OSMajorVersion").map(u64::from),
            ),
            (
                "OSMinorVersion",
                peb_ref.read_field::<u32>("OSMinorVersion").map(u64::from),
            ),
            (
                "OSBuildNumber",
                peb_ref.read_field::<u16>("OSBuildNumber").map(u64::from),
            ),
            (
                "SessionId",
                peb_ref.read_field::<u32>("SessionId").map(u64::from),
            ),
            (
                "NumberOfProcessors",
                peb_ref
                    .read_field::<u32>("NumberOfProcessors")
                    .map(u64::from),
            ),
        ] {
            outln!("  {label:17}: {}", display_read(value));
        }

        let params = peb_ref
            .read_field::<VirtAddr>("ProcessParameters")
            .ok()
            .filter(|address| !address.is_zero());
        match params {
            Some(params) => {
                outln!("  Process parameters {}", ui::addr(params.0));
                match self.ctx.target.guest().and_then(|guest| {
                    guest
                        .ntoskrnl
                        .types_in(dtb)
                        .struct_at("_RTL_USER_PROCESS_PARAMETERS", params)
                }) {
                    Ok(params_ref) => {
                        outln!(
                            "    CommandLine       : {}",
                            params_ref
                                .unicode_string("CommandLine")
                                .unwrap_or_else(|error| format!("<unavailable: {error}>"))
                        );
                        outln!(
                            "    ImagePathName     : {}",
                            params_ref
                                .unicode_string("ImagePathName")
                                .unwrap_or_else(|error| format!("<unavailable: {error}>"))
                        );
                        let current_directory = params_ref
                            .embedded("CurrentDirectory")
                            .and_then(|directory| directory.unicode_string("DosPath"))
                            .or_else(|_| params_ref.unicode_string("CurrentDirectory"));
                        outln!(
                            "    CurrentDirectory  : {}",
                            current_directory
                                .unwrap_or_else(|error| format!("<unavailable: {error}>"))
                        );
                        outln!(
                            "    EnvironmentSize   : {}",
                            display_read(params_ref.read_field::<u64>("EnvironmentSize"))
                        );
                    }
                    Err(error) => outln!("    process-parameter layout: <unavailable: {error}>"),
                }
            }
            None => outln!("  Process parameters : <unavailable or null>"),
        }

        match peb_ref.read_field::<VirtAddr>("Ldr") {
            Ok(ldr) if ldr.is_zero() => outln!("  Loader data        : null"),
            Ok(ldr) => outln!("  Loader data        : {}", ui::addr(ldr.0)),
            Err(error) => outln!("  Loader data        : <unavailable: {error}>"),
        }
        Ok(())
    }

    fn cmd_teb(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if invocation.argv.len() > 1 {
            outln!("{}\n", command_help("!teb"));
            return Ok(());
        }
        let attached_dtb = match attached_dtb(&self.ctx.target) {
            Ok(dtb) => dtb,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let dtb = match selected_thread_dtb(&self.ctx.target, attached_dtb) {
            Ok(dtb) => dtb,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let teb = match invocation.arg(0) {
            Some(text) => match Expr::eval_with_radix(text, &self.ctx.target, self.radix) {
                Ok(address) => address,
                Err(error) => {
                    error!("{error}");
                    return Ok(());
                }
            },
            None => match self.ctx.target.current_thread_pseudo_register("teb") {
                Some(address) if address != 0 => VirtAddr(address),
                _ => {
                    error!("current thread has no teb pseudo-register; select a user thread first");
                    return Ok(());
                }
            },
        };
        let teb_ref = match self
            .ctx
            .target
            .guest()
            .and_then(|guest| guest.ntoskrnl.types_in(dtb).struct_at("_TEB", teb))
        {
            Ok(teb_ref) => teb_ref,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        outln!("TEB {}", ui::addr(teb.0));
        outln!(
            "  {:30}: {}",
            "StackBase",
            display_ptr(teb_ref.read_field("StackBase"))
        );
        outln!(
            "  {:30}: {}",
            "StackLimit",
            display_ptr(teb_ref.read_field("StackLimit"))
        );
        let tls = teb_ref
            .read_field::<VirtAddr>("ThreadLocalStoragePointer")
            .or_else(|_| teb_ref.read_field("TlsPointer"));
        outln!("  {:30}: {}", "TlsPointer", display_ptr(tls));
        outln!(
            "  {:30}: {}",
            "LastErrorValue",
            display_read(teb_ref.read_field::<u32>("LastErrorValue"))
        );
        outln!(
            "  {:30}: {}",
            "LastStatusValue",
            display_read(teb_ref.read_field::<u32>("LastStatusValue"))
        );
        outln!(
            "  {:30}: {}",
            "CountOfOwnedCriticalSections",
            display_read(teb_ref.read_field::<u32>("CountOfOwnedCriticalSections"))
        );
        let peb = teb_ref
            .read_field::<VirtAddr>("ProcessEnvironmentBlock")
            .or_else(|_| teb_ref.read_field("Peb"));
        outln!("  {:30}: {}", "PEB", display_ptr(peb));
        match teb_ref.read_field::<i32>("WowTebOffset") {
            Ok(value) => outln!("  {:30}: {value} ({value:#x})", "WOW64"),
            Err(_) => {
                let value = teb_ref
                    .read_field::<VirtAddr>("Wow32Reserved")
                    .or_else(|_| teb_ref.read_field("Wow64Reserved"));
                outln!("  {:30}: {}", "WOW64", display_ptr(value));
            }
        }
        let activation = teb_ref
            .read_field::<VirtAddr>("ActivationContextStackPointer")
            .or_else(|_| teb_ref.read_field("ActivationContextStack"));
        outln!(
            "  ActivationContext             : {}",
            activation
                .map(|value| if value.is_zero() {
                    "absent".into()
                } else {
                    format!("present ({})", ui::addr(value.0))
                })
                .unwrap_or_else(|error| format!("<unavailable: {error}>"))
        );

        match teb_ref.embedded("ClientId") {
            Ok(client) => {
                outln!(
                    "  ClientId.UniqueProcess          : {}",
                    display_ptr(client.read_field("UniqueProcess"))
                );
                outln!(
                    "  ClientId.UniqueThread           : {}",
                    display_ptr(client.read_field("UniqueThread"))
                );
            }
            Err(error) => outln!("  ClientId                       : <unavailable: {error}>"),
        }
        Ok(())
    }

    fn cmd_dlls(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let mut filter = None;
        let mut arguments = invocation.argv.iter();
        while let Some(argument) = arguments.next() {
            if argument.as_ref() != "-c" {
                outln!("{}\n", command_help("!dlls"));
                return Ok(());
            }
            if filter.is_some() {
                error!("!dlls: -c may only be specified once");
                return Ok(());
            }
            let Some(text) = arguments.next() else {
                outln!("{}\n", command_help("!dlls"));
                return Ok(());
            };
            filter = match Expr::eval_with_radix(text, &self.ctx.target, self.radix) {
                Ok(address) => Some(address),
                Err(error) => {
                    error!("{error}");
                    return Ok(());
                }
            };
        }
        let Some(process) = self.ctx.target.current_process_info.as_ref() else {
            error!("this command requires an attached user process");
            return Ok(());
        };
        let modules = match self
            .ctx
            .target
            .guest()
            .and_then(|guest| guest.process_modules(process))
        {
            Ok(modules) => modules,
            Err(error) => {
                error!("failed to enumerate loader list: {error}");
                return Ok(());
            }
        };
        let modules: Vec<_> = modules
            .into_iter()
            .filter(|module| filter.is_none_or(|address| module.contains_address(address)))
            .collect();
        outln!("{} loader modules", modules.len());
        let mut builder = Builder::default();
        builder.push_record(["Base", "Size", "Entry", "Timestamp", "Name"]);
        for module in &modules {
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
        if !modules.is_empty() {
            print_padded_table(builder);
        }
        Ok(())
    }

    fn cmd_gle(&mut self) -> Result<()> {
        let attached_dtb = match attached_dtb(&self.ctx.target) {
            Ok(dtb) => dtb,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let dtb = match selected_thread_dtb(&self.ctx.target, attached_dtb) {
            Ok(dtb) => dtb,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let teb = match self.ctx.target.current_thread_pseudo_register("teb") {
            Some(address) if address != 0 => VirtAddr(address),
            _ => {
                error!("current thread has no teb pseudo-register");
                return Ok(());
            }
        };
        let teb_ref = match self
            .ctx
            .target
            .guest()
            .and_then(|guest| guest.ntoskrnl.types_in(dtb).struct_at("_TEB", teb))
        {
            Ok(teb_ref) => teb_ref,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let last_error = teb_ref.read_field::<u32>("LastErrorValue");
        let last_status = teb_ref.read_field::<u32>("LastStatusValue");
        match last_error {
            Ok(value) => outln!(
                "LastErrorValue = {value} ({})",
                win32_error_name(value).unwrap_or("unknown")
            ),
            Err(error) => outln!("LastErrorValue = <unavailable: {error}>"),
        }
        match last_status {
            Ok(value) => {
                outln!(
                    "LastStatusValue = {value:#010x} ({})",
                    ntstatus_name(value).unwrap_or("unknown")
                );
            }
            Err(error) => outln!("LastStatusValue = <unavailable: {error}>"),
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
        let mut modules = match self.ctx.target.modules() {
            Ok(modules) => modules,
            Err(error) => {
                error!("failed to enumerate modules: {error}");
                return Ok(());
            }
        };
        if find_module(&modules, module_name).is_none()
            && self.ctx.target.current_process_info.is_some()
            && let Ok(kernel_modules) = self.ctx.target.kernel_modules()
        {
            modules.extend(kernel_modules);
        }
        let module = match find_module(&modules, module_name) {
            Some(module) => module.clone(),
            None => {
                error!("module '{module_name}' was not found");
                return Ok(());
            }
        };
        let (timestamp, size) = match module_identity(&self.ctx.target, &module) {
            Ok(identity) => identity,
            Err(error) => {
                error!(
                    "cannot determine image identity for {}: {error}",
                    module.name
                );
                return Ok(());
            }
        };
        let cached_path = match self.ctx.target.symbols.ensure_module_image_on_disk(
            &module.name,
            timestamp,
            size,
        ) {
            Ok(path) => path,
            Err(error) => {
                error!(
                    "cached image for {} is unavailable: {error}; run `.reload {}` (the symbol pipeline downloads images on demand)",
                    module.name, module.short_name
                );
                return Ok(());
            }
        };
        let bytes = match fs::read(&cached_path) {
            Ok(bytes) => bytes,
            Err(error) => {
                error!(
                    "failed to read cached image {}: {error}",
                    cached_path.display()
                );
                return Ok(());
            }
        };
        let view = match PeView::from_bytes(&bytes) {
            Ok(view) => view,
            Err(error) => {
                error!(
                    "cached image {} is not a valid PE: {error}",
                    cached_path.display()
                );
                return Ok(());
            }
        };
        let mut sections = build_check_sections(&view, &bytes);
        if sections.is_empty() {
            outln!("{}: no executable .text/PAGE*/INIT sections", module.name);
            return Ok(());
        }
        apply_relocations(&view, &bytes, module.base_address.0, &mut sections);
        let allow_kernel_self_patches = is_kernel_self_patch_module(&module);
        let preferred_base = view.optional_header().ImageBase;
        let mut genuine_total = 0u64;
        let mut self_patch_total = SelfPatchCounts::default();
        let mut ranges = Vec::new();
        let mut range_overflow = false;
        let mut self_patch_ranges = Vec::new();
        let mut self_patch_range_overflow = false;
        let mut diffs = Vec::new();
        for section in &sections {
            let result = self.compare_section(
                module.base_address,
                section,
                preferred_base,
                &module,
                allow_kernel_self_patches,
                no_spec,
                show_diffs,
            );
            if verbose || result.skipped || result.unavailable.is_some() {
                print_section_result(&section.name, &result, verbose);
            }
            genuine_total = genuine_total.saturating_add(result.genuine);
            self_patch_total.add_counts(result.self_patches);
            for range in result.mismatch_ranges {
                push_mismatch_range(&mut ranges, &mut range_overflow, range.start, range.end);
            }
            range_overflow |= result.mismatch_range_overflow;
            for range in result.self_patch_ranges {
                push_self_patch_range(
                    &mut self_patch_ranges,
                    &mut self_patch_range_overflow,
                    range.start,
                    range.end,
                    range.kind,
                    range.function,
                );
            }
            self_patch_range_overflow |= result.self_patch_range_overflow;
            for diff in result.diffs {
                if diffs.len() < MAX_BYTE_DIFFS {
                    diffs.push(diff);
                }
            }
        }
        outln!(
            "{}: {genuine_total} genuine mismatched byte{}",
            module.name,
            if genuine_total == 1 { "" } else { "s" }
        );
        if !no_spec && self_patch_total.total() != 0 {
            outln!(
                "  {} bytes in known kernel self-patches (import optimization/retpoline)",
                self_patch_total.total()
            );
            if self_patch_total.import_optimization != 0 {
                outln!(
                    "    {} bytes: {}",
                    self_patch_total.import_optimization,
                    SelfPatchKind::ImportOptimization.label()
                );
            }
            if self_patch_total.retpoline != 0 {
                outln!(
                    "    {} bytes: {}",
                    self_patch_total.retpoline,
                    SelfPatchKind::Retpoline.label()
                );
            }
            if self_patch_total.ki_patch_self != 0 {
                outln!(
                    "    {} bytes: {}",
                    self_patch_total.ki_patch_self,
                    SelfPatchKind::KiPatchSelf.label()
                );
            }
        }
        if !ranges.is_empty() {
            let suffix = if range_overflow {
                format!(", first {MAX_REPORT_RANGES}")
            } else {
                String::new()
            };
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
        if verbose && !no_spec && !self_patch_ranges.is_empty() {
            let suffix = if self_patch_range_overflow {
                format!(", first {MAX_REPORT_RANGES}")
            } else {
                String::new()
            };
            outln!(
                "known self-patch ranges ({}{}):",
                self_patch_ranges.len(),
                suffix
            );
            for range in self_patch_ranges {
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
                    range.kind.label(),
                    function
                );
            }
        }
        if show_diffs && !diffs.is_empty() {
            let suffix = if diffs.len() >= MAX_BYTE_DIFFS {
                format!(" (first {MAX_BYTE_DIFFS})")
            } else {
                String::new()
            };
            outln!("byte diffs{}:", suffix);
            for diff in diffs {
                if let Some(kind) = diff.kind {
                    outln!(
                        "  RVA {:#x}: expected {:02x}, actual {:02x} ({})",
                        diff.rva,
                        diff.expected,
                        diff.actual,
                        kind.label()
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
        Ok(())
    }

    fn compare_section(
        &self,
        base: VirtAddr,
        section: &CheckSection,
        preferred_base: u64,
        module: &ModuleInfo,
        allow_kernel_self_patches: bool,
        no_spec: bool,
        show_diffs: bool,
    ) -> SectionCheckResult {
        if section.discardable {
            return SectionCheckResult {
                skipped: true,
                skip_reason: Some("discardable"),
                ..SectionCheckResult::default()
            };
        }

        let mut actual = vec![0u8; section.expected.len()];
        for offset in (0..section.expected.len()).step_by(SECTION_READ_CHUNK) {
            let take = (section.expected.len() - offset).min(SECTION_READ_CHUNK);
            let address = base + section.rva as u64 + offset as u64;
            if let Err(error) = self
                .ctx
                .read_masked(address, &mut actual[offset..offset + take])
            {
                if is_skippable_section_read_error(&error) {
                    return SectionCheckResult {
                        skipped: true,
                        skip_reason: Some("paged out"),
                        ..SectionCheckResult::default()
                    };
                }
                return SectionCheckResult {
                    unavailable: Some(error.to_string()),
                    ..SectionCheckResult::default()
                };
            }
        }

        let mut result = SectionCheckResult::default();
        let mut offset = 0usize;
        while offset < section.expected.len() {
            let instruction_len = match self.ctx.target.arch() {
                Arch::Amd64 => expected_instruction_len(
                    &section.expected[offset..],
                    base.0 + section.rva as u64 + offset as u64,
                ),
                Arch::Arm64 => 4.min(section.expected.len() - offset),
            };
            let end = (offset + instruction_len.max(1)).min(section.expected.len());
            let expected = &section.expected[offset..end];
            let actual = &actual[offset..end];
            if expected != actual {
                let patch = if allow_kernel_self_patches && !no_spec {
                    self.classify_self_patch(
                        base,
                        section,
                        offset,
                        preferred_base,
                        module,
                        expected,
                        actual,
                    )
                } else {
                    None
                };
                let mut run_start = None;
                for index in 0..expected.len() {
                    if expected[index] == actual[index] {
                        if let Some(start) = run_start.take() {
                            record_mismatch_run(
                                &mut result,
                                patch.as_ref(),
                                section.rva as u64 + offset as u64 + start as u64,
                                section.rva as u64 + offset as u64 + index as u64,
                            );
                        }
                        continue;
                    }
                    if run_start.is_none() {
                        run_start = Some(index);
                    }
                    if show_diffs && result.diffs.len() < MAX_BYTE_DIFFS {
                        result.diffs.push(ByteDiff {
                            rva: section.rva + (offset + index) as u32,
                            expected: expected[index],
                            actual: actual[index],
                            kind: patch.as_ref().map(|patch| patch.kind),
                        });
                    }
                }
                if let Some(start) = run_start {
                    record_mismatch_run(
                        &mut result,
                        patch.as_ref(),
                        section.rva as u64 + offset as u64 + start as u64,
                        section.rva as u64 + end as u64,
                    );
                }
            }
            offset = end;
        }
        result
    }

    fn classify_self_patch(
        &self,
        base: VirtAddr,
        section: &CheckSection,
        offset: usize,
        preferred_base: u64,
        module: &ModuleInfo,
        expected: &[u8],
        actual: &[u8],
    ) -> Option<SelfPatchMatch> {
        if expected.len() == 6
            && actual.len() == 6
            && (expected.starts_with(&[0xff, 0x15]) || expected.starts_with(&[0xff, 0x25]))
            && actual[0] == if expected[1] == 0x15 { 0xe8 } else { 0xe9 }
            && actual[5] == 0x90
        {
            return Some(SelfPatchMatch {
                kind: SelfPatchKind::ImportOptimization,
                function: self.self_patch_function_note(base, section.rva, offset),
            });
        }

        if expected.len() == 5
            && actual.len() == 5
            && expected[0] == actual[0]
            && matches!(expected[0], 0xe8 | 0xe9)
            && let (Some(expected_target), Some(actual_target)) = (
                rel32_target(
                    preferred_base
                        .wrapping_add(section.rva as u64)
                        .wrapping_add(offset as u64),
                    expected,
                ),
                rel32_target(
                    base.0
                        .wrapping_add(section.rva as u64)
                        .wrapping_add(offset as u64),
                    actual,
                ),
            )
        {
            let expected_target =
                rebase_module_target(expected_target, preferred_base, base.0, module.size);
            let expected_name = self.closest_symbol_name(expected_target);
            let actual_name = self.closest_symbol_name(actual_target);
            let kind = if is_import_optimization_target(actual_name.as_deref())
                || is_import_optimization_target(expected_name.as_deref())
            {
                Some(SelfPatchKind::ImportOptimization)
            } else if is_retpoline_target(actual_name.as_deref())
                || is_retpoline_target(expected_name.as_deref())
            {
                Some(SelfPatchKind::Retpoline)
            } else if is_patch_target(actual_name.as_deref())
                || is_patch_target(expected_name.as_deref())
            {
                Some(SelfPatchKind::KiPatchSelf)
            } else {
                None
            };
            if let Some(kind) = kind {
                return Some(SelfPatchMatch {
                    kind,
                    function: self.self_patch_function_note(base, section.rva, offset),
                });
            }
        }
        None
    }

    fn closest_symbol_name(&self, address: u64) -> Option<String> {
        self.ctx
            .target
            .nearest_symbol_current_context(VirtAddr(address))
            .map(|(_, name, _)| name)
    }

    fn self_patch_function_note(
        &self,
        base: VirtAddr,
        section_rva: u32,
        offset: usize,
    ) -> Option<String> {
        let address = base + section_rva as u64 + offset as u64;
        self.ctx
            .target
            .symbols
            .find_closest_symbol_for_address(self.ctx.target.kernel_dtb(), address)
            .and_then(|(module, name, offset)| {
                is_patch_function_name(&name).then(|| format!("{module}!{name}+{offset:#x}"))
            })
    }
}

fn record_mismatch_run(
    result: &mut SectionCheckResult,
    patch: Option<&SelfPatchMatch>,
    start: u64,
    end: u64,
) {
    let count = end.saturating_sub(start);
    if count == 0 {
        return;
    }
    if let Some(patch) = patch {
        result.self_patches.add(patch.kind, count);
        push_self_patch_range(
            &mut result.self_patch_ranges,
            &mut result.self_patch_range_overflow,
            start,
            end,
            patch.kind,
            patch.function.clone(),
        );
    } else {
        result.genuine = result.genuine.saturating_add(count);
        push_mismatch_range(
            &mut result.mismatch_ranges,
            &mut result.mismatch_range_overflow,
            start,
            end,
        );
    }
}

fn print_section_result(name: &str, result: &SectionCheckResult, verbose: bool) {
    if result.skipped {
        outln!(
            "  {name:<8} skipped ({})",
            result.skip_reason.unwrap_or("paged out")
        );
    } else if let Some(error) = &result.unavailable {
        outln!("  {name:<8} unavailable: {error}");
    } else if verbose {
        if result.self_patches.total() != 0 {
            outln!(
                "  {name:<8} mismatches: {} ({} known self-patch bytes)",
                result.genuine,
                result.self_patches.total()
            );
        } else {
            outln!("  {name:<8} mismatches: {}", result.genuine);
        }
    }
}

fn push_mismatch_range(ranges: &mut Vec<MismatchRange>, overflow: &mut bool, start: u64, end: u64) {
    if let Some(last) = ranges.last_mut()
        && last.end == start
    {
        last.end = end;
        return;
    }
    if ranges.len() < MAX_REPORT_RANGES {
        ranges.push(MismatchRange { start, end });
    } else {
        *overflow = true;
    }
}

fn push_self_patch_range(
    ranges: &mut Vec<SelfPatchRange>,
    overflow: &mut bool,
    start: u64,
    end: u64,
    kind: SelfPatchKind,
    function: Option<String>,
) {
    if let Some(last) = ranges.last_mut()
        && last.kind == kind
        && last.end == start
        && last.function == function
    {
        last.end = end;
        return;
    }
    if ranges.len() < MAX_REPORT_RANGES {
        ranges.push(SelfPatchRange {
            start,
            end,
            kind,
            function,
        });
    } else {
        *overflow = true;
    }
}

fn is_kernel_self_patch_module(module: &ModuleInfo) -> bool {
    module.short_name.eq_ignore_ascii_case("nt")
        || module.name.rsplit(['\\', '/']).next().is_some_and(|name| {
            name.eq_ignore_ascii_case("ntoskrnl.exe")
                || name.to_ascii_lowercase().starts_with("ntkrnl")
        })
}

fn is_skippable_section_read_error(error: &Error) -> bool {
    matches!(
        error,
        Error::BadVirtualAddress(_)
            | Error::PartialRead(_)
            | Error::AddressNotInDump(_)
            | Error::BadPhysicalAddress(_)
    )
}

fn expected_instruction_len(bytes: &[u8], address: u64) -> usize {
    let mut decoder = Decoder::with_ip(64, bytes, address, DecoderOptions::NONE);
    let instruction = decoder.decode();
    if instruction.code() == Code::INVALID || instruction.len() == 0 {
        1
    } else {
        instruction.len().min(bytes.len())
    }
}

fn rel32_target(address: u64, bytes: &[u8]) -> Option<u64> {
    (bytes.len() >= 5 && matches!(bytes[0], 0xe8 | 0xe9)).then(|| {
        let displacement = i32::from_le_bytes(bytes[1..5].try_into().unwrap());
        address
            .wrapping_add(5)
            .wrapping_add_signed(i64::from(displacement))
    })
}

fn rebase_module_target(address: u64, preferred_base: u64, actual_base: u64, size: u32) -> u64 {
    let Some(offset) = address.checked_sub(preferred_base) else {
        return address;
    };
    if offset < u64::from(size) {
        actual_base.wrapping_add(offset)
    } else {
        address
    }
}

fn symbol_leaf(name: &str) -> &str {
    name.rsplit_once('!').map(|(_, name)| name).unwrap_or(name)
}

fn is_import_optimization_target(name: Option<&str>) -> bool {
    let Some(name) = name else {
        return false;
    };
    let name = symbol_leaf(name).to_ascii_lowercase();
    name.contains("__memset_spec")
        || name.contains("__memcpy_spec")
        || name.contains("__memmove_spec")
        || name.contains("kecopypagentmfence")
}

fn is_retpoline_target(name: Option<&str>) -> bool {
    let Some(name) = name else {
        return false;
    };
    let name = symbol_leaf(name).to_ascii_lowercase();
    name.contains("__guard_dispatch_icall")
        || name.contains("__guard_retpoline_")
        || name.contains("guard_dispatch_icall")
        || name.contains("guard_retpoline")
        || name.contains("cfgdispatchusercalltarget")
}

fn is_patch_function_name(name: &str) -> bool {
    let name = symbol_leaf(name).to_ascii_lowercase();
    (name.starts_with("ki") && name.contains("patch")) || name.starts_with("expkernelpatch")
}

fn is_patch_target(name: Option<&str>) -> bool {
    let Some(name) = name else {
        return false;
    };
    let name = symbol_leaf(name);
    is_patch_function_name(name) || name.to_ascii_lowercase().contains("jmpthunk")
}

fn find_module<'a>(modules: &'a [ModuleInfo], query: &str) -> Option<&'a ModuleInfo> {
    let query = query.to_ascii_lowercase();
    modules.iter().find(|module| {
        module.short_name.eq_ignore_ascii_case(&query)
            || module.name.eq_ignore_ascii_case(&query)
            || module
                .name
                .rsplit(['\\', '/'])
                .next()
                .is_some_and(|name| name.eq_ignore_ascii_case(&query))
    })
}

fn module_identity(target: &Target, module: &ModuleInfo) -> Result<(u32, u32)> {
    if let Some(timestamp) = module.time_date_stamp
        && timestamp != 0
        && module.size != 0
    {
        return Ok((timestamp, module.size));
    }
    let memory = target.current_process()?.memory();
    let header = read_pe_header_page(module.base_address, &memory)?;
    let view = PeView::from_bytes(&header)?;
    Ok((
        module
            .time_date_stamp
            .unwrap_or(view.file_header().TimeDateStamp),
        if module.size == 0 {
            view.optional_header().SizeOfImage
        } else {
            module.size
        },
    ))
}

fn section_is_checked(name: &str, characteristics: u32) -> bool {
    if characteristics & IMAGE_SCN_MEM_EXECUTE == 0 {
        return false;
    }
    let upper = name.to_ascii_uppercase();
    let normalized = upper.trim_start_matches('.');
    normalized == "TEXT" || normalized.starts_with("PAGE") || normalized.starts_with("INIT")
}

fn build_check_sections(view: &PeView<'_>, image: &[u8]) -> Vec<CheckSection> {
    let image_size = view.optional_header().SizeOfImage;
    let mut sections = Vec::new();
    for section in view.section_headers() {
        let name = section
            .name()
            .ok()
            .map(|name| name.trim_matches('\0').to_string())
            .unwrap_or_else(|| "<unnamed>".into());
        if !section_is_checked(&name, section.Characteristics) {
            continue;
        }
        let size = section.VirtualSize.max(section.SizeOfRawData);
        let max_size = image_size.saturating_sub(section.VirtualAddress);
        let size = usize::try_from(size.min(max_size)).unwrap_or(0);
        if size == 0 {
            continue;
        }
        let mut expected = vec![0u8; size];
        let raw_start = section.PointerToRawData as usize;
        let raw_size = usize::try_from(section.SizeOfRawData)
            .unwrap_or(0)
            .min(size);
        if raw_start < image.len() {
            let available = (image.len() - raw_start).min(raw_size);
            expected[..available].copy_from_slice(&image[raw_start..raw_start + available]);
        }
        sections.push(CheckSection {
            name,
            rva: section.VirtualAddress,
            expected,
            discardable: section.Characteristics & IMAGE_SCN_MEM_DISCARDABLE != 0,
        });
    }
    sections
}

fn apply_relocations(
    view: &PeView<'_>,
    image: &[u8],
    actual_base: u64,
    sections: &mut [CheckSection],
) {
    let preferred_base = view.optional_header().ImageBase;
    let delta = actual_base.wrapping_sub(preferred_base) as i64;
    if delta == 0 {
        return;
    }
    let Some(directory) = view.data_directory().get(IMAGE_DIRECTORY_ENTRY_BASERELOC) else {
        return;
    };
    let rva_to_raw = |rva: u32| -> Option<usize> {
        if rva < view.optional_header().SizeOfHeaders {
            return Some(rva as usize);
        }
        view.section_headers().iter().find_map(|section| {
            let size = section.VirtualSize.max(section.SizeOfRawData);
            (rva >= section.VirtualAddress && rva < section.VirtualAddress.saturating_add(size))
                .then(|| {
                    (section.PointerToRawData as usize)
                        .checked_add((rva - section.VirtualAddress) as usize)
                })
                .flatten()
        })
    };
    let Some(mut cursor) = rva_to_raw(directory.VirtualAddress) else {
        return;
    };
    let end = cursor
        .checked_add(directory.Size as usize)
        .unwrap_or(image.len())
        .min(image.len());
    while cursor + 8 <= end {
        let page = u32::from_le_bytes(image[cursor..cursor + 4].try_into().unwrap());
        let block_size =
            u32::from_le_bytes(image[cursor + 4..cursor + 8].try_into().unwrap()) as usize;
        if block_size < 8 || block_size > end - cursor {
            break;
        }
        let count = (block_size - 8) / 2;
        for index in 0..count {
            let offset = cursor + 8 + index * 2;
            let entry = u16::from_le_bytes(image[offset..offset + 2].try_into().unwrap());
            let kind = entry >> 12;
            let rva = page.saturating_add(u32::from(entry & 0x0fff));
            let (width, apply) = match kind {
                IMAGE_REL_BASED_DIR64 => (8usize, true),
                IMAGE_REL_BASED_HIGHLOW => (4usize, true),
                _ => (0usize, false),
            };
            if !apply {
                continue;
            }
            for section in sections.iter_mut() {
                let Some(offset) = rva
                    .checked_sub(section.rva)
                    .and_then(|offset| usize::try_from(offset).ok())
                else {
                    continue;
                };
                if offset + width > section.expected.len() {
                    continue;
                }
                if width == 8 {
                    let value = u64::from_le_bytes(
                        section.expected[offset..offset + 8].try_into().unwrap(),
                    );
                    section.expected[offset..offset + 8]
                        .copy_from_slice(&value.wrapping_add_signed(delta).to_le_bytes());
                } else {
                    let value = u32::from_le_bytes(
                        section.expected[offset..offset + 4].try_into().unwrap(),
                    );
                    section.expected[offset..offset + 4]
                        .copy_from_slice(&value.wrapping_add(delta as u32).to_le_bytes());
                }
                break;
            }
        }
        cursor += block_size;
    }
}
