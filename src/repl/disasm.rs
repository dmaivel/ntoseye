use owo_colors::OwoColorize;

use crate::backend::MemoryOps;
use crate::gdb::{BreakpointManager, RegisterMap};
use crate::symbols::SourceLocation;
use crate::target::Target;
use crate::types::{Arch, VirtAddr};
use crate::ui;
use crate::unwind::{
    FrameSource, StackTrace, ThreadTraceContext, build_stacktrace, format_symbol,
    preferred_code_dtb,
};

pub fn print_section(title: &str) {
    println!("\n{}", ui::label(title));
}

/// Begin a stop block: a blank line. The single seam marking every
/// stop-output entry point, in case a heavier delimiter is ever wanted.
pub fn print_stop_separator() {
    println!();
}

/// Print the detail lines attached to an event banner: muted `├─` for middle
/// children, `╰─` for the last. `indent` is 1 space below a badge banner,
/// 4 spaces for a nested level; it is never derived from the badge width.
///
/// Children may contain `\n` (see [`wrap_prose`]): continuation lines get a
/// `│` gutter while the branch continues, bare spaces after the last child.
pub fn print_event_children(indent: &str, children: &[String]) {
    for (idx, child) in children.iter().enumerate() {
        let last = idx + 1 == children.len();
        let glyph = if last { "╰─" } else { "├─" };
        let mut lines = child.lines();
        if let Some(first) = lines.next() {
            println!("{indent}{} {}", ui::muted(glyph), first);
        }
        for continuation in lines {
            if last {
                println!("{indent}   {continuation}");
            } else {
                println!("{indent}{}  {continuation}", ui::muted("│"));
            }
        }
    }
}

/// Wrap plain prose for display starting at terminal column `col`, capped at
/// 100 columns of prose. Returns a single line when stdout is not a terminal
/// (piped output wants one line per field) or the terminal is too narrow.
/// Wrap before styling; width math over ANSI escapes miscounts.
pub fn wrap_prose(text: &str, col: usize) -> Vec<String> {
    let Some((terminal_size::Width(w), _)) = terminal_size::terminal_size() else {
        return vec![text.to_string()];
    };
    let width = (w as usize).saturating_sub(col).min(100);
    if width < 20 {
        return vec![text.to_string()];
    }
    textwrap::wrap(text, width)
        .into_iter()
        .map(|line| line.into_owned())
        .collect()
}

pub fn format_rflags(flags: u64) -> String {
    const FLAGS: &[(u64, &str)] = &[
        (0, "CF"),
        (2, "PF"),
        (4, "AF"),
        (6, "ZF"),
        (7, "SF"),
        (8, "TF"),
        (9, "IF"),
        (10, "DF"),
        (11, "OF"),
        (14, "NT"),
        (16, "RF"),
        (17, "VM"),
        (18, "AC"),
        (19, "VIF"),
        (20, "VIP"),
        (21, "ID"),
    ];

    let mut names = FLAGS
        .iter()
        .filter_map(|(bit, name)| ((flags & (1u64 << bit)) != 0).then_some(*name))
        .collect::<Vec<_>>();

    let iopl = (flags >> 12) & 0x3;
    if iopl != 0 {
        names.push(match iopl {
            1 => "IOPL1",
            2 => "IOPL2",
            _ => "IOPL3",
        });
    }

    if names.is_empty() {
        String::new()
    } else {
        format!(" [{}]", names.join(" "))
    }
}

/// AArch64 condition-flag summary aligned beneath the 16-hex-digit `cpsr`
/// value: each flag letter sits under the hex digit that contains its bit
/// (NZCV under the digit for bits 31-28, DAIF under the digits for bits 11-8
/// and 7-4). Multiple flags in one digit are joined in bit order, pushing any
/// later column right.
fn format_cpsr(flags: u64) -> String {
    const FLAGS: &[(u32, &str)] = &[
        (31, "N"),
        (30, "Z"),
        (29, "C"),
        (28, "V"),
        (9, "D"),
        (8, "A"),
        (7, "I"),
        (6, "F"),
    ];
    // Per hex-digit columns; digit 0 covers bits 63-60, digit 15 bits 3-0.
    let mut columns: [Vec<&str>; 16] = std::array::from_fn(|_| Vec::new());
    for (bit, name) in FLAGS {
        if flags & (1u64 << bit) != 0 {
            columns[15 - (bit / 4) as usize].push(name);
        }
    }
    let mut line = vec![' '; 16];
    for (idx, names) in columns.iter().enumerate() {
        if names.is_empty() {
            continue;
        }
        let text: String = names.concat();
        let len = text.len();
        if idx + len > line.len() {
            continue;
        }
        for i in (idx..line.len() - len).rev() {
            line[i + len] = line[i];
        }
        for (i, ch) in text.chars().enumerate() {
            line[idx + i] = ch;
        }
    }
    line.into_iter().collect()
}

/// Print the general-purpose register grid. `embedded` is true inside the
/// break/status dump (`registers` section header, 2-space indent); standalone
/// `registers` passes false so it reads flush-left with no header, matching
/// `disasm`. The row layout follows the register map's architecture.
pub fn print_registers(register_map: &RegisterMap, regs: &[u8], embedded: bool) {
    let read_reg_value = |name: &str| register_map.read_u64(name, regs);
    let styled_value = |name: &str| -> String {
        match read_reg_value(name) {
            Ok(value) => ui::addr(value),
            Err(_) => ui::muted(&format!("{:<16}", "N/A")),
        }
    };
    let cell = |name: &str| {
        format!(
            "{} {}",
            ui::muted(&format!("{name:<3}")),
            styled_value(name)
        )
    };

    let indent = if embedded { "  " } else { "" };
    if embedded {
        print_section("registers");
    }

    // ARM64 register map: x0-x30 grid plus fp/lr/sp/pc and cpsr flags.
    if read_reg_value("pc").is_ok() {
        for row in [
            ["x0", "x1", "x2", "x3"],
            ["x4", "x5", "x6", "x7"],
            ["x8", "x9", "x10", "x11"],
            ["x12", "x13", "x14", "x15"],
            ["x16", "x17", "x18", "x19"],
            ["x20", "x21", "x22", "x23"],
            ["x24", "x25", "x26", "x27"],
        ] {
            println!(
                "{indent}{}   {}   {}   {}",
                cell(row[0]),
                cell(row[1]),
                cell(row[2]),
                cell(row[3])
            );
        }
        println!(
            "{indent}{}   {}   {}   {}",
            cell("x28"),
            cell("fp"),
            cell("lr"),
            cell("sp")
        );
        let cpsr = read_reg_value("cpsr").unwrap_or(0);
        println!(
            "{indent}{}   {} {}",
            cell("pc"),
            ui::muted("cpsr"),
            styled_value("cpsr")
        );
        let flags = format_cpsr(cpsr);
        if !flags.is_empty() {
            // Align under the cpsr hex value: cell("pc") (4 + 16 chars) +
            // the "   cpsr " label, i.e. 28 columns.
            println!("{indent}                            {flags}");
        }
        return;
    }

    let rflags = read_reg_value("eflags").unwrap_or(0);
    for row in [
        ["rax", "rbx", "rcx"],
        ["rdx", "rsi", "rdi"],
        ["rsp", "rbp", "rip"],
        ["r8", "r9", "r10"],
        ["r11", "r12", "r13"],
    ] {
        println!(
            "{indent}{}   {}   {}",
            cell(row[0]),
            cell(row[1]),
            cell(row[2])
        );
    }
    println!(
        "{indent}{}   {}   {} {}{}",
        cell("r14"),
        cell("r15"),
        ui::muted("rfl"),
        styled_value("eflags"),
        format_rflags(rflags)
    );
}

// Decoding lives in core; the REPL owns the *rendering*
// (`format_disasm_line`/`render_rows` below).
pub use crate::disasm::{AsmToken, DisasmRow, decode_rows, decode_rows_arm64, disasm_formatter};

/// Width of the byte column for a listing: the longest hex string among the
/// rows about to be printed, so the asm column always aligns and never gets
/// pushed right by a long (up to 15-byte) instruction.
pub fn hex_column_width<'a>(hexes: impl Iterator<Item = &'a str>) -> usize {
    hexes.map(str::len).max().unwrap_or(0)
}

/// Render one disassembly line: yellow `>` cursor on the current
/// instruction, dim bytes, dim `;` comment with symbol. The single source of
/// truth for a disassembled instruction, shared by both call sites.
///
/// `hex_width` is the byte column width, computed per listing via
/// [`hex_column_width`] so the asm column stays aligned without overfilling.
pub fn format_disasm_line(
    ip: u64,
    hex: &str,
    tokens: &[AsmToken],
    comment: Option<&str>,
    marker: Option<bool>,
    hex_width: usize,
) -> String {
    // `marker` is None for a plain listing (no cursor column); Some(current) for
    // the break/status view, where the current instruction gets a yellow `>`
    let prefix = match marker {
        Some(true) => format!(" {} ", ">".yellow().bold()),
        Some(false) => "   ".to_string(),
        None => String::new(),
    };
    let bytes = format!("{hex:<hex_width$}").bright_black().to_string();
    let asm = ui::disasm_asm(tokens);
    let comment = comment
        .map(|sym| format!(" {} {}", ui::muted(";"), ui::symbol(sym)))
        .unwrap_or_default();
    format!("{}{}  {}  {}{}", prefix, ui::addr(ip), bytes, asm, comment)
}

/// Print decoded rows in the house style, sizing the byte column once across
/// all rows so the asm column aligns. `marker_for` gives each row its cursor
/// state: `None` for a plain listing (`disasm`), `Some(current)` for the
/// break/status view where the current instruction gets a `>`.
pub fn render_rows(rows: &[DisasmRow], marker_for: impl Fn(u64) -> Option<bool>) {
    let width = hex_column_width(rows.iter().map(|row| row.hex.as_str()));
    for row in rows {
        println!(
            "{}",
            format_disasm_line(
                row.ip,
                &row.hex,
                &row.tokens,
                row.comment.as_deref(),
                marker_for(row.ip),
                width,
            )
        );
    }
}

const DISASM_CONTEXT_BYTES: usize = 64;
const DISASM_CONTEXT_INSTRUCTIONS: usize = 7;

fn decode_disasm_context(
    bytes_at_rip: &[u8],
    rip: u64,
    arm64: bool,
    resolve: impl Fn(u64) -> String,
) -> Vec<DisasmRow> {
    if arm64 {
        return decode_rows_arm64(
            bytes_at_rip,
            rip,
            Some(DISASM_CONTEXT_INSTRUCTIONS),
            resolve,
        );
    }
    let mut formatter = disasm_formatter();
    decode_rows(
        bytes_at_rip,
        rip,
        Some(DISASM_CONTEXT_INSTRUCTIONS),
        &mut formatter,
        resolve,
    )
}

pub fn print_disasm_context(
    debugger: &Target,
    breakpoints: &BreakpointManager,
    trace: &ThreadTraceContext,
    rip: u64,
) {
    print_section("disasm");

    let active_memory = debugger.address_space(trace.active_dtb);
    let code_dtb = preferred_code_dtb(trace, rip);
    let code_memory = debugger.address_space(code_dtb);
    let mut bytes = [0u8; DISASM_CONTEXT_BYTES];

    if active_memory.read_bytes(VirtAddr(rip), &mut bytes).is_err()
        && (code_dtb == trace.active_dtb
            || code_memory.read_bytes(VirtAddr(rip), &mut bytes).is_err())
    {
        println!("{}", "  (could not read memory at RIP)".bright_black());
        return;
    }

    breakpoints.mask_breakpoint_bytes(VirtAddr(rip), &mut bytes, trace.active_dtb);

    let resolve = |target: u64| format_symbol(debugger, trace, target);
    let rows = decode_disasm_context(
        &bytes,
        rip,
        debugger.arch() == Arch::Arm64,
        resolve,
    );
    render_rows(&rows, |ip| Some(ip == rip));
}

/// Print the stack frames. `embedded` is true inside the break/status dump:
/// bold `stack` header, 2-space indent, and no child-SP column (the return
/// address is the token you act on). Standalone `k` passes false:
/// flush-left, full child-SP + retaddr columns.
pub fn print_stacktrace(
    debugger: &Target,
    register_map: &RegisterMap,
    regs: &[u8],
    build_limit: usize,
    display_limit: usize,
    embedded: bool,
) {
    let stacktrace = build_stacktrace(debugger, register_map, regs, build_limit);
    print_stacktrace_data(&stacktrace, display_limit, embedded);
}

pub fn print_stacktrace_verbose(
    debugger: &Target,
    register_map: &RegisterMap,
    regs: &[u8],
    build_limit: usize,
    display_limit: usize,
) {
    let stacktrace = build_stacktrace(debugger, register_map, regs, build_limit);
    print_stacktrace_data_with_provenance(&stacktrace, display_limit, false);
}

/// Render an already-collected stack trace in the same layout as [`print_stacktrace`].
pub fn print_stacktrace_data(stacktrace: &StackTrace, display_limit: usize, embedded: bool) {
    print_stacktrace_data_impl(stacktrace, display_limit, embedded, false);
}

pub fn print_stacktrace_data_with_provenance(
    stacktrace: &StackTrace,
    display_limit: usize,
    embedded: bool,
) {
    print_stacktrace_data_impl(stacktrace, display_limit, embedded, true);
}

fn format_source_location(location: &SourceLocation) -> String {
    let (label, path) = match location.local_path.as_ref() {
        Some(path) if location.local_exists => ("local", path.display().to_string()),
        Some(path) => ("mapped", path.display().to_string()),
        None => ("recorded", location.file.clone()),
    };
    match location.column {
        Some(column) => format!("[{label} {path}:{}:{column}]", location.line),
        None => format!("[{label} {path}:{}]", location.line),
    }
}

fn print_stacktrace_data_impl(
    stacktrace: &StackTrace,
    display_limit: usize,
    embedded: bool,
    show_provenance: bool,
) {
    let indent = if embedded { "  " } else { "" };
    if embedded {
        print_section("stack");
    }

    let shown = stacktrace.frames.len().min(display_limit);

    for (num, frame) in stacktrace.frames.iter().take(shown).enumerate() {
        let mut annotations = Vec::new();
        if !frame.symbol.starts_with("0x") {
            annotations.push(ui::symbol(&frame.symbol));
        }
        if show_provenance {
            annotations.push(
                format!("[{}]", frame.source.as_str())
                    .bright_black()
                    .to_string(),
            );
        } else if frame.source == FrameSource::Scan {
            annotations.push("[scan]".bright_black().to_string());
        }
        if let Some(location) = frame.source_location.as_ref() {
            annotations.push(format_source_location(location).bright_black().to_string());
        }
        let annotation = if annotations.is_empty() {
            String::new()
        } else {
            format!("  {}", annotations.join(" "))
        };
        if embedded {
            println!(
                "{indent}{} {}{}",
                ui::muted(&format!("#{num:<2}")),
                ui::addr(frame.ip),
                annotation
            );
        } else {
            println!(
                "{indent}{} {}  {}{}",
                ui::muted(&format!("#{num:<2}")),
                ui::addr(frame.sp),
                ui::addr(frame.ip),
                annotation
            );
        }
    }

    let hidden = stacktrace.frames.len().saturating_sub(display_limit) + stacktrace.truncated;
    if hidden > 0 {
        println!(
            "{indent}{}",
            format!("... {} more frames", hidden).bright_black()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stop_disassembly_starts_at_rip_and_only_looks_forward() {
        let rip = 0xffff_f807_c0e1_3ae0;
        let rows = decode_disasm_context(&[0x90; 8], rip, false, |_| String::new());
        let ips = rows.iter().map(|row| row.ip).collect::<Vec<_>>();

        assert_eq!(ips, (rip..rip + 7).collect::<Vec<_>>());
    }

    /// Flag letters sit under the hex digits containing their bits:
    /// 0x60000044 → Z,C (bits 30,29) under the '6' (cols 8-9), F (bit 6)
    /// under the '4' (col 14).
    #[test]
    fn cpsr_flags_align_under_hex_digits() {
        assert_eq!(format_cpsr(0x6000_0044), "        ZC    F ");
        // N, A, I, F → "N" under the '8', "AIF" under the trailing '4's.
        assert_eq!(format_cpsr(0x8000_01c4), "        N    AIF");
        assert_eq!(format_cpsr(0x0000_0000), "                ");
    }

    #[test]
    fn source_location_labels_recorded_and_local_paths() {        let recorded = SourceLocation {
            file: r"C:\build\driver.c".into(),
            line: 42,
            column: Some(7),
            local_path: None,
            local_exists: false,
        };
        assert_eq!(
            format_source_location(&recorded),
            r"[recorded C:\build\driver.c:42:7]"
        );

        let local = SourceLocation {
            local_path: Some("/checkout/driver.c".into()),
            local_exists: true,
            ..recorded
        };
        assert_eq!(
            format_source_location(&local),
            "[local /checkout/driver.c:42:7]"
        );
    }
}
