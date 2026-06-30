use owo_colors::OwoColorize;

use crate::backend::MemoryOps;
use crate::gdb::{BreakpointManager, RegisterMap};
use crate::memory::AddressSpace;
use crate::target::Target;
use crate::types::VirtAddr;
use crate::ui;
use crate::unwind::{
    FrameSource, ThreadTraceContext, build_stacktrace, format_symbol, preferred_code_dtb,
};

pub fn print_section(title: &str) {
    println!("\n{}", title.bold());
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

/// Print the general-purpose register grid. `embedded` is true inside the
/// break/status dump (bold `registers` header, 2-space indent); standalone
/// `registers` passes false so it reads flush-left with no header, matching
/// `disasm`.
pub fn print_registers(register_map: &RegisterMap, regs: &[u8], embedded: bool) {
    let read_reg_value = |name: &str| register_map.read_u64(name, regs);
    let read_reg = |name: &str| -> String {
        read_reg_value(name)
            .map(ui::addr)
            .unwrap_or_else(|_| "N/A".to_string())
    };
    let rflags = read_reg_value("eflags").unwrap_or(0);

    let indent = if embedded { "  " } else { "" };
    if embedded {
        print_section("registers");
    }
    println!(
        "{indent}rax {}   rbx {}   rcx {}",
        read_reg("rax"),
        read_reg("rbx"),
        read_reg("rcx")
    );
    println!(
        "{indent}rdx {}   rsi {}   rdi {}",
        read_reg("rdx"),
        read_reg("rsi"),
        read_reg("rdi")
    );
    println!(
        "{indent}rsp {}   rbp {}   rip {}",
        read_reg("rsp"),
        read_reg("rbp"),
        read_reg("rip")
    );
    println!(
        "{indent}r8  {}   r9  {}   r10 {}",
        read_reg("r8"),
        read_reg("r9"),
        read_reg("r10")
    );
    println!(
        "{indent}r11 {}   r12 {}   r13 {}",
        read_reg("r11"),
        read_reg("r12"),
        read_reg("r13")
    );
    println!(
        "{indent}r14 {}   r15 {}   rfl {}{}",
        read_reg("r14"),
        read_reg("r15"),
        read_reg("eflags"),
        format_rflags(rflags)
    );
}

// Decoding lives in core; the REPL owns the *rendering*
// (`format_disasm_line`/`render_rows` below).
pub use crate::disasm::{DisasmRow, decode_rows, disasm_formatter};

/// Width of the byte column for a listing: the longest hex string among the
/// rows about to be printed, so the asm column always aligns and never gets
/// pushed right by a long (up to 15-byte) instruction.
pub fn hex_column_width<'a>(hexes: impl Iterator<Item = &'a str>) -> usize {
    hexes.map(str::len).max().unwrap_or(0)
}

/// Render one disassembly line in the house style: yellow `>` for the current
/// instruction, bright_white+bold address, dark-gray space-joined bytes, NASM
/// asm, and a dimmed `; symbol` comment. The single source of truth for how a
/// disassembled instruction looks, shared by both disassembly call sites.
///
/// `hex_width` is the byte column width, computed per listing via
/// [`hex_column_width`] so the asm column stays aligned without overfilling.
pub fn format_disasm_line(
    ip: u64,
    hex: &str,
    asm: &str,
    comment: Option<&str>,
    marker: Option<bool>,
    hex_width: usize,
) -> String {
    // `marker` is None for a plain listing (no cursor column); Some(current) for
    // the break/status view, where the current instruction gets a yellow `>`
    let prefix = match marker {
        Some(true) => format!(" {} ", ">".yellow()),
        Some(false) => "   ".to_string(),
        None => String::new(),
    };
    let bytes = format!("{hex:<hex_width$}").bright_black().to_string();
    let comment = comment
        .map(|sym| format!(" ; {}", ui::symbol(sym)))
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
                &row.asm,
                row.comment.as_deref(),
                marker_for(row.ip),
                width,
            )
        );
    }
}

pub fn print_disasm_context(
    debugger: &Target,
    breakpoints: &BreakpointManager,
    trace: &ThreadTraceContext,
    rip: u64,
) {
    print_section("disasm");

    let pre_bytes: u64 = 64;
    let post_bytes: u64 = 64;
    let start_addr = rip.saturating_sub(pre_bytes);
    let total_len = (pre_bytes + post_bytes) as usize;
    let active_memory = AddressSpace::new(&debugger.phys, trace.active_dtb);
    let code_dtb = preferred_code_dtb(trace, rip);
    let code_memory = AddressSpace::new(&debugger.phys, code_dtb);

    let mut bytes = vec![0u8; total_len];
    if active_memory
        .read_bytes(VirtAddr(start_addr), &mut bytes)
        .is_err()
        && (code_dtb == trace.active_dtb
            || code_memory
                .read_bytes(VirtAddr(start_addr), &mut bytes)
                .is_err())
    {
        println!("{}", "  (could not read memory at RIP)".bright_black());
        return;
    }
    breakpoints.mask_breakpoint_bytes(VirtAddr(start_addr), &mut bytes, trace.active_dtb);

    let resolve = |target: u64| format_symbol(debugger, trace, target);
    let mut formatter = disasm_formatter();
    let instructions = decode_rows(&bytes, start_addr, None, &mut formatter, resolve);

    // find which instruction corresponds to RIP
    let rip_idx = instructions.iter().position(|row| row.ip == rip);

    if let Some(idx) = rip_idx {
        let context_before = 5;
        let context_after = 3;
        let start = idx.saturating_sub(context_before);
        let end = (idx + context_after + 1).min(instructions.len());
        render_rows(&instructions[start..end], |ip| Some(ip == rip));
    } else {
        let mut forward_buf = vec![0u8; post_bytes as usize];
        if active_memory
            .read_bytes(VirtAddr(rip), &mut forward_buf)
            .is_ok()
            || (code_dtb != trace.active_dtb
                && code_memory
                    .read_bytes(VirtAddr(rip), &mut forward_buf)
                    .is_ok())
        {
            breakpoints.mask_breakpoint_bytes(VirtAddr(rip), &mut forward_buf, trace.active_dtb);
            let rows = decode_rows(&forward_buf, rip, Some(11), &mut formatter, resolve);
            render_rows(&rows, |ip| Some(ip == rip));
        } else {
            println!("{}", "  (could not read memory at RIP)".bright_black());
        }
    }
}

/// Print the stack frames. `embedded` is true inside the break/status dump
/// (bold `stack` header, 2-space indent); standalone `k` passes false so it
/// reads flush-left with no header, matching `disasm`.
pub fn print_stacktrace(
    debugger: &Target,
    register_map: &RegisterMap,
    regs: &[u8],
    build_limit: usize,
    display_limit: usize,
    embedded: bool,
) {
    let indent = if embedded { "  " } else { "" };
    if embedded {
        print_section("stack");
    }

    let stacktrace = build_stacktrace(debugger, register_map, regs, build_limit);
    let shown = stacktrace.frames.len().min(display_limit);

    for (num, frame) in stacktrace.frames.iter().take(shown).enumerate() {
        let suffix = if frame.source == FrameSource::Scan {
            format!(" {}", "[scan]".bright_black())
        } else {
            String::new()
        };
        let symbol = if frame.symbol.starts_with("0x") {
            String::new()
        } else {
            format!("  {}{}", ui::symbol(&frame.symbol), suffix)
        };
        println!(
            "{indent}#{:<2} {}  {}{}",
            num,
            ui::addr(frame.sp),
            ui::addr(frame.ip),
            symbol
        );
    }

    let hidden = stacktrace.frames.len().saturating_sub(display_limit) + stacktrace.truncated;
    if hidden > 0 {
        println!(
            "{indent}{}",
            format!("... {} more frames", hidden).bright_black()
        );
    }
}
