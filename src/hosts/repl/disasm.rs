use std::collections::HashMap;

use owo_colors::OwoColorize;

use crate::arch::{Arch, RegisterMap};
use crate::base::error::Error;
use crate::base::memory::MemoryOps;
use crate::base::types::{CodeMachine, VirtAddr};
use crate::hosts::repl::listing::{self, Listing};
use crate::hosts::ui;
use crate::nt::bugchecks::looks_like_kernel_pointer;
use crate::nt::symbols::{LocalSourceState, SourceLocation};
use crate::nt::target::Target;
use crate::nt::unwind::{
    FrameSource, StackFrame, StackTrace, ThreadTraceContext, build_thread_stacktrace,
    format_symbol, preferred_code_dtb,
};
use crate::session::Session;

pub fn print_section(title: &str) {
    outln!("\n{}", ui::label(title));
}

/// Begin a stop block: a blank line.
pub fn print_stop_separator() {
    outln!();
}

/// Print the detail lines attached to an event banner: muted `├─` for middle
/// children, `└─` for the last. `indent` is 1 space below a badge banner,
/// 4 spaces for a nested level; it is never derived from the badge width.
///
/// Children may contain `\n` (see [`wrap_prose`]): continuation lines get a
/// `│` gutter while the branch continues, bare spaces after the last child.
pub fn print_event_children(indent: &str, children: &[String]) {
    for line in event_children_lines(indent, children) {
        outln!("{line}");
    }
}

/// The lines [`print_event_children`] prints, for a subtree that is itself
/// a child: join them with `\n` under its head line, and the parent's
/// gutter continues past them.
pub fn event_children_lines(indent: &str, children: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for (idx, child) in children.iter().enumerate() {
        let last = idx + 1 == children.len();
        let glyph = if last { "└─" } else { "├─" };
        let mut lines = child.lines();
        if let Some(first) = lines.next() {
            out.push(format!("{indent}{} {}", ui::muted(glyph), first));
        }
        for continuation in lines {
            if last {
                out.push(format!("{indent}   {continuation}"));
            } else {
                out.push(format!("{indent}{}  {continuation}", ui::muted("│")));
            }
        }
    }
    out
}

/// Tree child with a dim wrapped prose tail. `hang` is the child-relative
/// indent of continuation lines; `col` the absolute column where the prose
/// starts on screen, from which the wrap width is derived.
pub fn wrapped_dim_tail(prefix: String, hang: usize, prose: &str, col: usize) -> String {
    let lines = wrap_prose(prose, col);
    let mut out = format!("{prefix}{}", ui::muted(&lines[0]));
    for line in &lines[1..] {
        out.push_str(&format!("\n{}{}", " ".repeat(hang), ui::muted(line)));
    }
    out
}

/// Wrap plain prose for display starting at terminal column `col`, capped at
/// 100 columns of prose. Returns a single line when stdout is not a terminal
/// (piped output wants one line per field) or the terminal is too narrow.
/// A word longer than the width stays whole on its own line: a name split
/// in two reads as two names. Wrap before styling; width math over ANSI
/// escapes miscounts.
pub fn wrap_prose(text: &str, col: usize) -> Vec<String> {
    let Some((terminal_size::Width(w), _)) = terminal_size::terminal_size() else {
        return vec![text.to_string()];
    };
    let width = (w as usize).saturating_sub(col).min(100);
    if width < 20 {
        return vec![text.to_string()];
    }
    textwrap::wrap(text, textwrap::Options::new(width).break_words(false))
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

/// The general-purpose registers in `regs`, as a grid, under `heading` as
/// a section when given (indented, as the stop shows it), flush left
/// without (as `r` does). With `before`, the register file of the previous
/// stop on the same thread, the values that changed since stand out.
pub fn print_registers(
    register_map: &RegisterMap,
    arch: Arch,
    regs: &[u8],
    before: Option<&[u8]>,
    heading: Option<&str>,
) {
    print_register_grid(arch, heading, |name| {
        match register_map.read_u64(name, regs) {
            Ok(value) if changed(register_map, name, value, before) => RegisterCell::Changed(value),
            Ok(value) => RegisterCell::Value(value),
            Err(_) => RegisterCell::Unavailable,
        }
    });
}

/// Registers known by name, such as those a trap frame saved or the
/// unwinder recovered for a frame, as [`print_registers`] lays them out
/// under `heading`; one not known shows as `-`.
pub fn print_known_registers(values: &HashMap<String, u64>, arch: Arch, heading: &str) {
    print_register_grid(arch, Some(heading), |name| {
        values
            .get(name)
            .copied()
            .map_or(RegisterCell::Unsaved, RegisterCell::Value)
    });
}

/// A register's value as the grid shows it.
enum RegisterCell {
    Value(u64),
    /// Changed since the previous stop.
    Changed(u64),
    /// Not saved where the registers came from.
    Unsaved,
    /// Not in the register file.
    Unavailable,
}

/// `arch`'s register grid, each register as `read` gives it, the flags
/// named beside or under them.
fn print_register_grid(arch: Arch, heading: Option<&str>, read: impl Fn(&str) -> RegisterCell) {
    // A value's cell is as wide as an address, so the columns line up,
    // unless it `ends` its line.
    let styled_value = |name: &str, ends: bool| -> String {
        match read(name) {
            RegisterCell::Changed(value) => ui::changed(&ui::addr(value)),
            RegisterCell::Value(value) => ui::addr(value),
            RegisterCell::Unsaved | RegisterCell::Unavailable if ends => ui::muted("-"),
            RegisterCell::Unsaved | RegisterCell::Unavailable => ui::muted(&format!("{:<16}", "-")),
        }
    };
    let cell = |name: &str, ends: bool| {
        format!(
            "{} {}",
            ui::muted(&format!("{name:<3}")),
            styled_value(name, ends)
        )
    };

    let indent = if heading.is_some() { "  " } else { "" };
    if let Some(heading) = heading {
        print_section(heading);
    }

    let row_line = |row: &[&str], ends: bool| {
        row.iter()
            .enumerate()
            .map(|(index, name)| cell(name, ends && index + 1 == row.len()))
            .collect::<Vec<_>>()
            .join("   ")
    };
    let [names @ .., flags] = arch.general_registers() else {
        return;
    };
    let flags_value = match read(flags) {
        RegisterCell::Value(value) | RegisterCell::Changed(value) => value,
        RegisterCell::Unsaved | RegisterCell::Unavailable => 0,
    };
    match arch {
        // Rows of 3, the flags (as `rfl`, decoded) closing the last one.
        Arch::Amd64 => {
            let rows: Vec<&[&str]> = names.chunks(3).collect();
            let Some((last, rows)) = rows.split_last() else {
                return;
            };
            for row in rows {
                outln!("{indent}{}", row_line(row, true));
            }
            let decoded = format_rflags(flags_value);
            outln!(
                "{indent}{}   {} {}{decoded}",
                row_line(last, false),
                ui::muted("rfl"),
                styled_value(flags, decoded.is_empty())
            );
        }
        // Rows of 4 through sp, then pc and the flags, decoded below them.
        Arch::Arm64 => {
            let [grid @ .., pc] = names else {
                return;
            };
            for row in grid.chunks(4) {
                outln!("{indent}{}", row_line(row, true));
            }
            outln!(
                "{indent}{}   {} {}",
                cell(pc, false),
                ui::muted(flags),
                styled_value(flags, true)
            );
            let decoded = format_cpsr(flags_value);
            if !decoded.is_empty() {
                // Align under the cpsr hex value: cell("pc") (4 + 16 chars) +
                // the "   cpsr " label, i.e. 28 columns.
                outln!(
                    "{}",
                    format!("{indent}                            {decoded}").trim_end()
                );
            }
        }
    }
}

/// Whether register `name`, now `value`, held something else in `before`.
pub fn changed(register_map: &RegisterMap, name: &str, value: u64, before: Option<&[u8]>) -> bool {
    before
        .and_then(|before| register_map.read_u64(name, before).ok())
        .is_some_and(|was| was != value)
}

/// The general-purpose registers that changed since `before`, on one line
/// as `name=value` pairs: what a compact stop shows after a step.
pub fn print_changed_registers(
    register_map: &RegisterMap,
    arch: Arch,
    regs: &[u8],
    before: Option<&[u8]>,
) {
    let pairs: Vec<String> = arch
        .general_registers()
        .iter()
        .copied()
        .filter_map(|name| {
            let value = register_map.read_u64(name, regs).ok()?;
            changed(register_map, name, value, before)
                .then(|| format!("{name}={}", ui::addr(value)))
        })
        .collect();
    if pairs.is_empty() {
        outln!("{}", ui::muted("no register changed"));
    } else {
        outln!("{} {}", ui::muted("changed"), pairs.join("  "));
    }
}

// Decoding lives in core; the REPL owns the *rendering*
// (`format_disasm_line`/`render_rows` below).
pub use crate::base::disasm::{AsmToken, DisasmRow, decode_code, decode_preceding};

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
        outln!(
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

/// Why the instruction at `pc` could not be read, in the terms the user can
/// act on.
///
/// A page that is not resident is the normal outcome of an execute breakpoint
/// on code nothing has run yet: a code breakpoint fault outranks the code page
/// fault of the instruction fetch (Intel SDM, "Priority Among Concurrent
/// Events": code breakpoint fault is priority 7, faults from fetching the next
/// instruction priority 8), so the trap is delivered before the page is
/// faulted in. The bytes appear once the instruction is actually fetched, so a
/// single step reveals them.
pub fn non_resident_note(pc: u64, error: &Error) -> String {
    match error {
        Error::BadVirtualAddress(_) | Error::AddressNotInDump(_) | Error::PartialRead(0) => {
            format!(
                "  (the page holding {pc:#x} is not resident, so there is nothing to decode yet; \
                 an execute breakpoint traps before the fetch that pages it in, and `t` \
                 single-steps through the fetch)"
            )
        }
        error => format!("  (could not read memory at {pc:#x}: {error})"),
    }
}

fn decode_disasm_context(
    bytes_at_rip: &[u8],
    rip: u64,
    machine: CodeMachine,
    resolve: impl Fn(u64) -> String,
) -> Vec<DisasmRow> {
    decode_code(
        bytes_at_rip,
        rip,
        Some(DISASM_CONTEXT_INSTRUCTIONS),
        machine,
        resolve,
    )
}

/// Instructions a stop shows around the instruction pointer.
const STOP_INSTRUCTIONS: usize = 9;
/// Of them, how many come before it, where the function has them.
const STOP_LEAD: usize = 3;
/// Jumps a stop's code draws side by side in its gutter.
const STOP_LANES: usize = 4;

/// Reads a stopped thread's register by name.
pub type RegisterRead<'a> = &'a dyn Fn(&str) -> Option<u64>;

/// What a stop knows about the instruction it is at, for its listing: the
/// registers to tell whether its jump goes, and where a return there goes
/// back to. Neither when the code shown is not where the registers are (a
/// bugcheck's fault site, a saved VTL state).
#[derive(Default)]
pub struct NextStep<'a> {
    pub read: Option<RegisterRead<'a>>,
    pub returns_to: Option<&'a str>,
}

/// The code at a stop: the instructions around `rip` in its function (see
/// [`listing::code_window`]), with the jumps among them drawn and, from
/// `next`, whether the one at `rip` is taken and where a return goes.
pub fn print_disasm_context(
    session: &Session,
    trace: &ThreadTraceContext,
    rip: u64,
    next: NextStep<'_>,
) {
    print_disasm_lines(session, trace, rip, STOP_INSTRUCTIONS, STOP_LEAD, next);
}

/// [`print_disasm_context`] with `count` instructions, `lead` of them
/// before `rip`.
pub fn print_disasm_lines(
    session: &Session,
    trace: &ThreadTraceContext,
    rip: u64,
    count: usize,
    lead: usize,
    next: NextStep<'_>,
) {
    print_section("disasm");
    let window = match listing::code_window(session, trace, rip, count, lead) {
        Ok(window) => window,
        Err(note) => {
            outln!("{}", ui::muted(&note));
            return;
        }
    };
    let taken = next
        .read
        .and_then(|read| window.rows.get(window.current)?.jump_taken(read));
    let listing = Listing {
        rows: &window.rows,
        current: Some(window.current),
        taken,
        returns_to: next.returns_to,
        bytes: false,
        lanes: STOP_LANES,
        named: false,
    };
    for line in listing::listing_lines(session, trace, &listing) {
        outln!("{line}");
    }
}

/// The instructions a stop shows from `rip`, or the note saying why they
/// can't be read.
pub fn disasm_context_rows(
    session: &Session,
    trace: &ThreadTraceContext,
    rip: u64,
) -> std::result::Result<Vec<DisasmRow>, String> {
    let debugger = &session.target;

    let active_memory = debugger.address_space(trace.active_dtb);
    let code_dtb = preferred_code_dtb(trace, rip);
    let code_memory = debugger.address_space(code_dtb);
    let mut bytes = [0u8; DISASM_CONTEXT_BYTES];

    let read = match active_memory.read_bytes(VirtAddr(rip), &mut bytes) {
        Ok(()) => Ok(()),
        Err(active_error) if code_dtb == trace.active_dtb => Err(active_error),
        Err(_) => code_memory.read_bytes(VirtAddr(rip), &mut bytes),
    };
    if let Err(error) = read {
        return Err(non_resident_note(rip, &error));
    }

    session.mask_code(VirtAddr(rip), &mut bytes, trace.active_dtb);

    let resolve = |target: u64| format_symbol(debugger, trace, target);
    Ok(decode_disasm_context(
        &bytes,
        rip,
        debugger.code_machine(VirtAddr(rip)),
        resolve,
    ))
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
    let stacktrace = thread_stacktrace(debugger, register_map, regs, build_limit);
    print_stacktrace_data(debugger.arch(), &stacktrace, display_limit, embedded);
}

/// The stack of the selected thread from `regs`, walked `build_limit`
/// frames deep.
pub fn thread_stacktrace(
    debugger: &Target,
    register_map: &RegisterMap,
    regs: &[u8],
    build_limit: usize,
) -> StackTrace {
    build_thread_stacktrace(
        debugger,
        register_map,
        regs,
        debugger.windows_thread_selection.as_ref(),
        build_limit,
    )
    .into_stacktrace()
}

/// Render an already-collected stack trace in the same layout as [`print_stacktrace`].
pub fn print_stacktrace_data(
    arch: Arch,
    stacktrace: &StackTrace,
    display_limit: usize,
    embedded: bool,
) {
    print_stacktrace_data_with(
        arch,
        stacktrace,
        display_limit,
        embedded,
        StackColumns::default(),
    );
}

pub fn print_stacktrace_data_with_provenance(
    arch: Arch,
    stacktrace: &StackTrace,
    display_limit: usize,
    embedded: bool,
) {
    let columns = StackColumns {
        provenance: true,
        ..StackColumns::default()
    };
    print_stacktrace_data_with(arch, stacktrace, display_limit, embedded, columns);
}

/// The optional columns of the `k` family: `kv`'s provenance and `kf`'s
/// frame sizes.
#[derive(Clone, Copy, Debug, Default)]
pub struct StackColumns {
    pub provenance: bool,
    pub frame_size: bool,
}

/// `kf`'s memory column: how many stack bytes separate a frame from the
/// physical frame before it. Blank for the first physical frame, for an
/// inline frame (which has no stack of its own), and where the stack pointer
/// drops, which is a switch to another stack rather than a frame size.
pub fn frame_size_cell(previous_sp: Option<u64>, sp: u64) -> String {
    match previous_sp.and_then(|previous| sp.checked_sub(previous)) {
        Some(size) => format!("{size:>8x}"),
        None => format!("{:8}", ""),
    }
}

/// A frame's source line, `[local /checkout/driver.c:42:7]`: the local copy
/// when `.srcpath` maps one, else the path the PDB records. A local copy
/// that matches is a link that opens it.
pub fn format_source_location(location: &SourceLocation) -> String {
    let (label, path) = match &location.local {
        Some(local) => (
            match local.state {
                LocalSourceState::Found => "local",
                LocalSourceState::Missing => "mapped",
                LocalSourceState::Differs => "differs",
            },
            local.path.display().to_string(),
        ),
        None => ("recorded", location.file.clone()),
    };
    let text = match location.column {
        Some(column) => format!("[{label} {path}:{}:{column}]", location.line),
        None => format!("[{label} {path}:{}]", location.line),
    };
    match &location.local {
        Some(local) if local.state == LocalSourceState::Found => ui::file_link(&local.path, &text),
        _ => text,
    }
}

/// What a stack walk on `arch` crossed between a frame and its caller:
/// `user mode` where the kernel was entered from user code, `trap` where a
/// trap or interrupt stopped the caller within the same mode.
pub fn crossing(arch: Arch, callee: &StackFrame, caller: &StackFrame) -> Option<&'static str> {
    let kernel = |frame: &StackFrame| looks_like_kernel_pointer(arch, frame.ip);
    if kernel(callee) && !kernel(caller) {
        Some("user mode")
    } else if caller.machine_frame.is_some() {
        Some("trap")
    } else {
        None
    }
}

/// A muted `┄┄ label ┄┄┄` line between two frames, `indent` columns in.
pub fn crossing_line(label: &str, indent: usize) -> String {
    const LENGTH: usize = 40;
    let head = format!("┄┄ {label} ");
    let rest = LENGTH.saturating_sub(head.chars().count());
    ui::muted(&format!("{:indent$}{head}{}", "", "┄".repeat(rest)))
}

pub fn print_stacktrace_data_with(
    arch: Arch,
    stacktrace: &StackTrace,
    display_limit: usize,
    embedded: bool,
    columns: StackColumns,
) {
    let placement = if embedded {
        StackPlacement::Section
    } else {
        StackPlacement::Standalone
    };
    print_stack_frames(arch, stacktrace, 0, display_limit, placement, columns);
}

/// A stop's stack from frame `from`, the frames above it folded into one
/// line: at a bugcheck, the bugcheck's own frames above the frame that
/// faulted. Every frame keeps its number, as `.frame` takes it.
pub fn print_stop_stack(arch: Arch, stacktrace: &StackTrace, from: usize, display_limit: usize) {
    print_stack_frames(
        arch,
        stacktrace,
        from,
        display_limit,
        StackPlacement::Section,
        StackColumns::default(),
    );
}

/// A stack under the line of a report naming its thread, `indent` in, with
/// no heading of its own: one of several in `!analyze -hang` or the 0x9F
/// report.
pub fn print_indented_stack(
    arch: Arch,
    stacktrace: &StackTrace,
    display_limit: usize,
    indent: &str,
) {
    print_stack_frames(
        arch,
        stacktrace,
        0,
        display_limit,
        StackPlacement::Indented(indent),
        StackColumns::default(),
    );
}

/// Where a stack sits in the output.
enum StackPlacement<'a> {
    /// `k`'s own listing: flush left, with the child-SP column.
    Standalone,
    /// A section of a longer display, as the stop's: a `stack` heading,
    /// then the frames indented under it.
    Section,
    /// Under a report's line naming its thread, this far in, with no
    /// heading.
    Indented(&'a str),
}

fn print_stack_frames(
    arch: Arch,
    stacktrace: &StackTrace,
    from: usize,
    display_limit: usize,
    placement: StackPlacement<'_>,
    columns: StackColumns,
) {
    let indent = match placement {
        StackPlacement::Standalone => "",
        StackPlacement::Section => {
            print_section("stack");
            "  "
        }
        StackPlacement::Indented(indent) => indent,
    };
    // `k`'s own listing has the child-SP column; a stack inside another
    // display leaves it out: the return address is what to act on there.
    let with_sp = matches!(placement, StackPlacement::Standalone);
    if with_sp && !stacktrace.frames.is_empty() {
        print_stack_header(columns);
    }

    let from = from.min(stacktrace.frames.len());
    let end = stacktrace.frames.len().min(from + display_limit);
    if from > 0 {
        let folded = &stacktrace.frames[..from];
        let range = match from {
            1 => "00".to_string(),
            _ => format!("00\u{2013}{:02}", from - 1),
        };
        let name = |frame: &StackFrame| frame.symbol.clone();
        let ends = match folded {
            [only] => name(only),
            [first, .., last] => format!("{} \u{2026} {}", name(first), name(last)),
            [] => String::new(),
        };
        outln!("{indent}{}", ui::muted(&format!("{range}  {ends}")));
    }

    let mut previous_sp = None;
    for (num, frame) in stacktrace.frames.iter().enumerate().take(end).skip(from) {
        if num > 0
            && let Some(label) = crossing(arch, &stacktrace.frames[num - 1], frame)
        {
            outln!("{}", crossing_line(label, indent.len() + 4));
        }
        if columns.frame_size {
            let size = if frame.inline {
                frame_size_cell(None, frame.sp)
            } else {
                frame_size_cell(previous_sp.replace(frame.sp), frame.sp)
            };
            outln!(
                "{indent}{}{} {}",
                frame_number(num, with_sp),
                size,
                format_stack_frame(None, frame, with_sp, columns.provenance)
            );
        } else {
            outln!(
                "{indent}{}",
                format_stack_frame(Some(num), frame, with_sp, columns.provenance)
            );
        }
    }

    let hidden = stacktrace.frames.len().saturating_sub(end) + stacktrace.truncated;
    if hidden > 0 {
        outln!("{indent}{}", more_frames(hidden));
    }
}

/// The tag after the symbol of a call the compiler inlined, in the `k`
/// family and `.frame`.
pub fn inline_tag() -> String {
    "[inline]".bright_black().to_string()
}

/// The `k` layout's column header, as WinDbg prints one: the frame number,
/// `kf`'s frame size, the child SP, the frame's instruction address, and the
/// call site.
pub fn print_stack_header(columns: StackColumns) {
    let memory = if columns.frame_size {
        format!("{:>8} ", "Memory")
    } else {
        String::new()
    };
    outln!(
        " {:>2} {memory}{:<16}  {:<16}  Call Site",
        "#",
        "Child-SP",
        "IP"
    );
}

/// A frame's call site as the `k` layout shows it: its symbol, or its raw
/// address `0x…` when it has none, as WinDbg's Call Site does.
pub fn call_site(frame: &StackFrame) -> String {
    if frame.symbol.is_empty() {
        format!("{:#x}", frame.ip)
    } else if frame.symbol.starts_with("0x") {
        frame.symbol.clone()
    } else {
        ui::symbol(&frame.symbol)
    }
}

/// One frame line in `k`'s layout: the frame `number` when given, the child
/// SP when `with_sp`, the return address, then the symbol, whether it is an
/// inline frame, how the frame was recovered (always with
/// `show_provenance`, as `kv` shows it, else only a stack scan's guess), and
/// its source line.
pub fn format_stack_frame(
    number: Option<usize>,
    frame: &StackFrame,
    with_sp: bool,
    show_provenance: bool,
) -> String {
    let mut line = String::new();
    if let Some(number) = number {
        line.push_str(&frame_number(number, with_sp));
    }
    if with_sp {
        line.push_str(&ui::addr(frame.sp));
        line.push_str("  ");
    }
    line.push_str(&ui::addr(frame.ip));
    let mut annotations = vec![call_site(frame)];
    if frame.inline {
        annotations.push(inline_tag());
    }
    // A guess, by a stack scan or a prolog read, is marked always.
    if show_provenance || matches!(frame.source, FrameSource::Scan | FrameSource::Prolog) {
        annotations.push(
            format!("[{}]", frame.source.as_str())
                .bright_black()
                .to_string(),
        );
    }
    if let Some(location) = frame.source_location.as_ref() {
        annotations.push(format_source_location(location).bright_black().to_string());
    }
    // Two spaces between the call site and each tag, as `k` spaces them.
    line.push_str("  ");
    line.push_str(&annotations.join("  "));
    line
}

/// A frame's number as `k` writes it (`00`), with the space after it: in
/// `k`'s layout (`with_sp`) behind the column `k` marks the selected frame
/// in, else muted, as the stop's stack shows it.
fn frame_number(number: usize, with_sp: bool) -> String {
    if with_sp {
        format!(" {number:02} ")
    } else {
        format!("{}  ", ui::muted(&format!("{number:02}")))
    }
}

/// The note under a stack for the frames not shown or not walked.
pub fn more_frames(hidden: usize) -> String {
    let noun = if hidden == 1 { "frame" } else { "frames" };
    format!("... {hidden} more {noun}")
        .bright_black()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::output::strip_ansi;
    use crate::nt::symbols::LocalSource;

    #[test]
    fn cpsr_flags_align_under_hex_digits() {
        assert_eq!(format_cpsr(0x6000_0044), "        ZC    F ");
        assert_eq!(format_cpsr(0x8000_01c4), "        N    AIF");
        assert_eq!(format_cpsr(0x0000_0000), "                ");
    }

    #[test]
    fn source_location_labels_recorded_and_local_paths() {
        let recorded = SourceLocation {
            file: r"C:\build\driver.c".into(),
            line: 42,
            column: Some(7),
            local: None,
        };
        assert_eq!(
            format_source_location(&recorded),
            r"[recorded C:\build\driver.c:42:7]"
        );

        let local = SourceLocation {
            local: Some(LocalSource {
                path: "/checkout/driver.c".into(),
                state: LocalSourceState::Found,
            }),
            ..recorded
        };
        assert_eq!(
            strip_ansi(&format_source_location(&local)),
            "[local /checkout/driver.c:42:7]"
        );
    }
}
