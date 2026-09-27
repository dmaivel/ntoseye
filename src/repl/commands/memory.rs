use std::fs::File;
use std::io::{Read, Write};

use owo_colors::OwoColorize;

use crate::backend::MemoryOps;
use crate::error::{Error, Result, best_effort};
use crate::expr::Expr;
use crate::layout::utf16le_lossy;
use crate::memory::{PAGE_SIZE, for_each_page_chunk, read_page_chunks};
use crate::symbols::glob_matches;
use crate::target::{CODE_BITNESS_X86, MAX_SEARCH_MATCHES, SearchStop, StringDescriptor};
use crate::types::{CodeMachine, VirtAddr};
use crate::ui;
use crate::unwind::{
    ThreadTraceContext, format_symbol, resolve_thread_trace_context, try_format_symbol,
};

use crate::repl::*;

pub const MAX_DISPLAY_BYTES: usize = 1024 * 1024;
const MAX_DISASSEMBLY_INSTRUCTIONS: usize = 4096;
const FILETIME_UNIX_MIN_SECONDS: i64 = -62_135_596_800;
const FILETIME_UNIX_MAX_SECONDS: i64 = 253_402_300_799;
/// Characters `d*a`/`d*u` show of each string, as `da`/`du` do by default.
const POINTER_STRING_CHARS: usize = 256;

/// What the `d*p`, `d*a`, and `d*u` commands show after each pointer.
#[derive(Clone, Copy)]
enum Pointee {
    /// The pointer-sized value it points to (`d*p`).
    Value,
    /// The NUL-terminated string it points to, in 1-byte (`d*a`) or 2-byte
    /// (`d*u`) units.
    String { char_size: usize },
}

/// A little-endian doubleword or quadword.
fn le_value(bytes: &[u8]) -> Option<u64> {
    match bytes.len() {
        4 => Some(u64::from(u32::from_le_bytes(bytes.try_into().ok()?))),
        8 => Some(u64::from_le_bytes(bytes.try_into().ok()?)),
        _ => None,
    }
}

repl_command! {
    cmd_pagein;
    names: [".pagein"],
    usage: ".pagein [/p <pid|eprocess>] <address>",
    summary: "Make a paged-out address resident, using the guest's debugger worker.",
    details: "The guest does the work, so the target is resumed and comes back halted at nt!DbgBreakPointWithStatus rather than where it was. `/p` attaches the worker to a process first, which user-space addresses need.",
    completion: [None, Expression],
    run_state: Halted,
}

repl_command! {
    cmd_db;
    names: ["db"],
    usage: "db <address> [L<count>|length|end]",
    summary: "Display memory as bytes.",
    completion: Expression,
}

repl_command! {
    cmd_dw;
    names: ["dw"],
    usage: "dw <address> [L<count>|length|end]",
    summary: "Display memory as words (2 bytes).",
    completion: Expression,
}

repl_command! {
    cmd_dw_ascii;
    names: ["dW"],
    usage: "dW <address> [L<count>|length|end]",
    summary: "Display memory as words with an ASCII column.",
    completion: Expression,
}

repl_command! {
    cmd_dc;
    names: ["dc"],
    usage: "dc <address> [L<count>|length|end]",
    summary: "Display memory as doublewords with an ASCII column.",
    completion: Expression,
}

repl_command! {
    cmd_dd;
    names: ["dd"],
    usage: "dd <address> [L<count>|length|end]",
    summary: "Display memory as doublewords (4 bytes).",
    completion: Expression,
}

repl_command! {
    cmd_dq;
    names: ["dq"],
    usage: "dq <address> [L<count>|length|end]",
    summary: "Display memory as quadwords (8 bytes).",
    completion: Expression,
}

repl_command! {
    cmd_dp;
    names: ["dp"],
    usage: "dp <address> [L<count>|length|end]",
    summary: "Display memory as pointer-sized values.",
    completion: Expression,
}

repl_command! {
    cmd_dds;
    names: ["dds"],
    usage: "dds <address> [L<count>|length|end]",
    summary: "Display memory as doublewords, annotating values that resolve to symbols.",
    completion: Expression,
}

repl_command! {
    cmd_dqs;
    names: ["dqs", "dps"],
    usage: "dqs <address> [L<count>|length|end]",
    summary: "Display memory as quadwords, annotating values that resolve to symbols.",
    details: "raw stack triage: dqs @rsp scrapes return addresses when the unwinder can't",
    completion: Expression,
}

repl_command! {
    cmd_dyb;
    names: ["dyb"],
    usage: "dyb <address> [L<count>|length|end]",
    summary: "Display memory as binary values with their bytes.",
    completion: Expression,
}

repl_command! {
    cmd_dpp;
    names: ["dpp", "dqp"],
    usage: "dpp <address> [L<count>|length|end]",
    summary: "Display pointers, dereference them, and annotate symbols.",
    completion: Expression,
}

repl_command! {
    cmd_ddp;
    names: ["ddp"],
    usage: "ddp <address> [L<count>|length|end]",
    summary: "Display doublewords as pointers, each followed by the doubleword it points to.",
    completion: Expression,
}

repl_command! {
    cmd_dqa;
    names: ["dqa", "dpa"],
    usage: "dqa <address> [L<count>|length|end]",
    summary: "Display pointers, each followed by the ASCII string it points to.",
    completion: Expression,
}

repl_command! {
    cmd_dqu;
    names: ["dqu", "dpu"],
    usage: "dqu <address> [L<count>|length|end]",
    summary: "Display pointers, each followed by the UTF-16 string it points to.",
    completion: Expression,
}

repl_command! {
    cmd_dda;
    names: ["dda"],
    usage: "dda <address> [L<count>|length|end]",
    summary: "Display doublewords as pointers, each followed by the ASCII string it points to.",
    completion: Expression,
}

repl_command! {
    cmd_ddu;
    names: ["ddu"],
    usage: "ddu <address> [L<count>|length|end]",
    summary: "Display doublewords as pointers, each followed by the UTF-16 string it points to.",
    completion: Expression,
}

repl_command! {
    cmd_df;
    names: ["df"],
    usage: "df <address> [L<count>|length|end]",
    summary: "Display memory as single-precision (4-byte) floating-point numbers.",
    completion: Expression,
}

repl_command! {
    cmd_dd_double;
    names: ["dD"],
    usage: "dD <address> [L<count>|length|end]",
    summary: "Display memory as double-precision (8-byte) floating-point numbers.",
    completion: Expression,
}

repl_command! {
    cmd_da;
    names: ["da"],
    usage: "da <address> [max-chars]",
    summary: "Display a NUL-terminated ASCII string.",
    completion: Expression,
}

repl_command! {
    cmd_du;
    names: ["du"],
    usage: "du <address> [max-chars]",
    summary: "Display a NUL-terminated UTF-16 string (e.g. a UNICODE_STRING Buffer).",
    completion: Expression,
}

repl_command! {
    cmd_ds;
    names: ["ds"],
    usage: "ds <address>",
    summary: "Display an ANSI_STRING descriptor and its buffer.",
    completion: [Expression, None],
}

repl_command! {
    cmd_ds_unicode;
    names: ["dS"],
    usage: "dS <address>",
    summary: "Display a UNICODE_STRING descriptor and its buffer.",
    completion: [Expression, None],
}

repl_command! {
    cmd_disasm;
    names: ["u", "disasm"],
    usage: "u <address> [L<count>|length|end]",
    summary: "Disassemble memory at a symbol or address.",
    details: "`L<count>` counts instructions (default 8); with an end address, every instruction starting at or before it is shown.",
    completion: Expression,
}

repl_command! {
    cmd_uf;
    names: ["uf"],
    usage: "uf [address]",
    summary: "Disassemble the function containing an address.",
    completion: Expression,
}

repl_command! {
    cmd_ub;
    names: ["ub"],
    usage: "ub <address> [L<count>]",
    summary: "Disassemble instructions ending at an address.",
    completion: Expression,
}

repl_command! {
    cmd_disasm_search;
    names: ["#"],
    usage: "# [pattern] [address [L<count>]]",
    summary: "Search disassembly for the next instruction matching a pattern.",
    details: "The pattern matches anywhere in an instruction's address, bytes, or text (mnemonic, operands, and resolved symbol), case-insensitively, with `*` and `?` wildcards; quote it to include spaces (`# \"mov*cr3\" nt!KiSwapContext`). The first match is shown. Without an address the search continues after the last match (the first search starts at the instruction pointer), and without a pattern the last one is reused, so a bare `#` finds the next occurrence. `L<count>` bounds the instructions searched; otherwise the search runs until a match, an unreadable page, 1,048,576 instructions, or Ctrl+C.",
    completion: [None, Expression],
}

repl_command! {
    cmd_eb;
    names: ["eb"],
    usage: "eb <address> <value...>",
    summary: "Write one or more bytes to memory.",
    completion: Expression,
}

repl_command! {
    cmd_ew;
    names: ["ew"],
    usage: "ew <address> <value...>",
    summary: "Write one or more words (2 bytes) to memory.",
    completion: Expression,
}

repl_command! {
    cmd_ed;
    names: ["ed"],
    usage: "ed <address> <value...>",
    summary: "Write one or more doublewords (4 bytes) to memory.",
    completion: Expression,
}

repl_command! {
    cmd_eq;
    names: ["eq"],
    usage: "eq <address> <value...>",
    summary: "Write one or more quadwords (8 bytes) to memory.",
    completion: Expression,
}

repl_command! {
    cmd_ef;
    names: ["ef"],
    usage: "ef <address> <number...>",
    summary: "Write one or more single-precision (4-byte) floating-point numbers to memory.",
    details: "Numbers are decimal floating-point literals (`ef @rcx 1.5 -2 3e-4`), whatever the radix.",
    completion: Expression,
}

repl_command! {
    cmd_ed_double;
    names: ["eD"],
    usage: "eD <address> <number...>",
    summary: "Write one or more double-precision (8-byte) floating-point numbers to memory.",
    details: "Numbers are decimal floating-point literals (`eD @rcx 1.5 -2 3e-4`), whatever the radix.",
    completion: Expression,
}

repl_command! {
    cmd_ea;
    names: ["ea"],
    usage: "ea <address> \"text\"",
    summary: "Write an ANSI string to memory.",
    completion: Expression,
}

repl_command! {
    cmd_eu;
    names: ["eu"],
    usage: "eu <address> \"text\"",
    summary: "Write a UTF-16 string to memory.",
    completion: Expression,
}

repl_command! {
    cmd_eza;
    names: ["eza"],
    usage: "eza <address> \"text\"",
    summary: "Write a NUL-terminated ANSI string to memory.",
    completion: Expression,
}

repl_command! {
    cmd_ezu;
    names: ["ezu"],
    usage: "ezu <address> \"text\"",
    summary: "Write a NUL-terminated UTF-16 string to memory.",
    completion: Expression,
}

repl_command! {
    cmd_writemem;
    names: [".writemem"],
    usage: ".writemem <file> <address> <L<len>|end>",
    summary: "Write a virtual memory range to a file.",
    completion: [None, Expression, Expression],
}

repl_command! {
    cmd_readmem;
    names: [".readmem"],
    usage: ".readmem <file> <address> <L<len>|end>",
    summary: "Read a file into a virtual memory range.",
    completion: [None, Expression, Expression],
}

repl_command! {
    cmd_formats;
    names: [".formats"],
    usage: ".formats <expression>",
    summary: "Display an expression in common numeric formats.",
    completion: Expression,
    style: ExpressionTail,
}

repl_command! {
    cmd_f;
    names: ["f"],
    usage: "f <address> <L<count>|end> <pattern>",
    summary: "Fill memory with a repeated byte pattern.",
    details: "The pattern is bytes, as `s` takes them: `90`, `48 89 5c`, `48895c`, or `\\x48\\x89`, repeated to fill the range (`f @rsp L20 cc`).",
    completion: [Expression, Expression, None],
}

repl_command! {
    cmd_s;
    names: ["s"],
    usage: "s [-b|-w|-d|-q|-a|-u] <address> <L<count>|end> <pattern>",
    summary: "Search memory for bytes, values, or a string.",
    details: "-b (the default) searches for bytes: `4d 5a`, `4d5a`, or `\\x4d\\x5a`. -w, -d, and -q search for 2-, 4-, and 8-byte values (`s -d @rsp L100 0 1`). -a and -u search for an ASCII or UTF-16 string (`s -a nt L?1000000 \"This program\"`). `L<count>` counts elements of the searched type. Unreadable pages are skipped, at most 1 GiB is scanned, and the search stops after 4096 matches or at Ctrl+C.",
    completion: [None, Expression, Expression],
}

repl_command! {
    cmd_c;
    names: ["c"],
    usage: "c <address> <L<count>|end> <address2>",
    summary: "Compare two memory ranges byte by byte.",
    details: "Compares the range with as many bytes at <address2> and lists every byte that differs, as `<address> <byte> - <address2> <byte>` (`c nt L1000 poi(@$t0)`). Offsets unreadable in either range are skipped and counted, at most 1 GiB is compared, and the comparison stops after 4096 differences or at Ctrl+C.",
    completion: [Expression, Expression, Expression],
}

repl_command! {
    cmd_m;
    names: ["m"],
    usage: "m <address> <L<count>|end> <destination>",
    summary: "Copy a memory range to another address.",
    details: "The whole range is read before anything is written, so overlapping ranges copy as if through a buffer (`m @rsp L20 @rsp+8`). A breakpoint this session planted in the range is copied as the byte it displaced. At most 16 MiB is copied, and nothing is written when any byte of the range is unreadable.",
    completion: [Expression, Expression, Expression],
}

pub fn parse_write_values(
    state: &ReplState<'_>,
    invocation: &CommandInvocation<'_>,
) -> Result<Vec<u64>> {
    match invocation
        .argv
        .iter()
        .skip(1)
        .map(|value_arg| {
            Expr::eval_with_radix(value_arg, &state.ctx.target, state.radix).map(|value| value.0)
        })
        .collect::<Result<Vec<_>>>()
    {
        Ok(values) => Ok(values),
        Err(_) => {
            let expression = invocation.join_args(1);
            Expr::eval_with_radix(&expression, &state.ctx.target, state.radix)
                .map(|value| vec![value.0])
        }
    }
}

struct StringDescriptorFields {
    length: Option<u16>,
    maximum_length: Option<u16>,
    buffer: Option<VirtAddr>,
}

impl ReplState<'_> {
    /// Read guest memory in the current process context for *display*, masking
    /// out our own breakpoint int3 bytes so listings never show them.
    fn read_for_display(&self, addr: VirtAddr, buf: &mut [u8]) -> Result<()> {
        self.ctx.read_masked(addr, buf)
    }

    /// Read a range a page at a time so one missing page does not hide the
    /// readable rows before and after it.  The returned bitmap is byte based;
    /// display modes use it to mark an entire partially unreadable item.
    fn read_virtual_best_effort(&self, range: &AddressRange) -> Result<(Vec<u8>, Vec<bool>)> {
        read_page_chunks(range.start, range.len(), |address, buf| {
            self.read_for_display(address, buf)
        })
    }

    fn display_memory_command(
        &self,
        invocation: &CommandInvocation<'_>,
        default_count: u64,
        item_size: u64,
        mode: MemoryDisplayMode,
    ) -> Result<()> {
        let Some(range) = self.parse_display_range(invocation, default_count, item_size) else {
            return Ok(());
        };

        let (data, valid) = match self.read_virtual_best_effort(&range) {
            Ok(read) => read,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        display_memory_with_validity(range.start, &data, Some(&valid), &mode);

        Ok(())
    }

    /// The `<address> [L<count>|length|end]` range of a display command,
    /// bounded by [`MAX_DISPLAY_BYTES`]; `None` after saying why not.
    fn parse_display_range(
        &self,
        invocation: &CommandInvocation<'_>,
        default_count: u64,
        item_size: u64,
    ) -> Option<AddressRange> {
        let range = match AddressRange::parse(
            invocation,
            &self.ctx.target,
            self.radix,
            default_count,
            item_size,
        ) {
            Ok(range) => range,
            Err(error) => {
                error!("{error}");
                return None;
            }
        };
        if range.len() > MAX_DISPLAY_BYTES {
            error!("display range exceeds the maximum of {MAX_DISPLAY_BYTES:#x} bytes");
            return None;
        }
        Some(range)
    }

    fn write_scalar_command(
        &mut self,
        invocation: &CommandInvocation<'_>,
        command: &str,
        noun: &str,
        encode: impl Fn(u64) -> Vec<u8>,
        display_value: impl Fn(u64) -> String,
    ) -> Result<()> {
        if invocation.argv.len() < 2 {
            outln!("{}\n", command_help(command));
            return Ok(());
        }

        let Some(address) = self.eval_or_report(invocation.arg(0).unwrap()) else {
            return Ok(());
        };

        let values = match parse_write_values(self, invocation) {
            Ok(values) => values,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };
        let mut bytes = Vec::new();
        let formatted_values = values
            .iter()
            .map(|&value| {
                bytes.extend(encode(value));
                display_value(value)
            })
            .collect::<Vec<_>>();
        self.write_encoded(address, &bytes, &formatted_values, noun);
        Ok(())
    }

    /// `ef`/`eD`: write decimal floating-point literals as `size`-byte values.
    fn write_float_command(
        &mut self,
        invocation: &CommandInvocation<'_>,
        command: &str,
        size: usize,
    ) -> Result<()> {
        if invocation.argv.len() < 2 {
            outln!("{}\n", command_help(command));
            return Ok(());
        }
        let Some(address) = self.eval_or_report(invocation.arg(0).unwrap()) else {
            return Ok(());
        };
        let mut bytes = Vec::new();
        let mut formatted_values = Vec::new();
        for text in invocation.argv.iter().skip(1) {
            let Ok(value) = text.parse::<f64>() else {
                error!("invalid floating-point number '{text}'");
                return Ok(());
            };
            if size == 4 {
                let value = value as f32;
                bytes.extend(value.to_le_bytes());
                formatted_values.push(format_float(value));
            } else {
                bytes.extend(value.to_le_bytes());
                formatted_values.push(format_float(value));
            }
        }
        let noun = if size == 4 { "float" } else { "double" };
        self.write_encoded(address, &bytes, &formatted_values, noun);
        Ok(())
    }

    fn write_encoded(
        &self,
        address: VirtAddr,
        bytes: &[u8],
        formatted_values: &[String],
        noun: &str,
    ) {
        let mem = self.ctx.target.context_memory();
        if let Err(e) = mem.write_bytes(address, bytes) {
            error!("failed to write {}: {}", noun, e);
        } else {
            outln!(
                "{} {} -> {}\n",
                "wrote".green(),
                formatted_values.join(" "),
                ui::addr(address.0)
            );
        }
    }

    fn cmd_db(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.display_memory_command(&invocation, 128, 1, MemoryDisplayMode::bytes())
    }

    fn cmd_pagein(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let mut address_text = None;
        let mut process_text = None;
        let mut argv = invocation.argv.iter();
        while let Some(arg) = argv.next() {
            let arg = arg.as_ref();
            match arg {
                "/p" => {
                    let Some(selector) = argv.next() else {
                        error!("/p needs a PID or EPROCESS");
                        return Ok(());
                    };
                    process_text = Some(selector.as_ref());
                }
                _ if arg.starts_with('/') => {
                    error!("unknown .pagein switch '{arg}'; expected /p");
                    return Ok(());
                }
                _ if address_text.replace(arg).is_some() => {
                    error!(".pagein accepts one address");
                    return Ok(());
                }
                _ => {}
            }
        }
        let Some(address_text) = address_text else {
            error!("usage: .pagein [/p <pid|eprocess>] <address>");
            return Ok(());
        };
        let Some(address) = self.eval_or_report(address_text) else {
            return Ok(());
        };

        let process = match process_text {
            Some(selector) => {
                let processes = match self.ctx.target.matching_processes(None) {
                    Ok(processes) => processes,
                    Err(error) => {
                        error!("failed to enumerate processes: {error}");
                        return Ok(());
                    }
                };
                let Some(process) = self.process_for_selector(selector, &processes) else {
                    error!("no process matches '{selector}'");
                    return Ok(());
                };
                Some(process.eprocess_va.0)
            }
            None => None,
        };

        outln!("resuming the target so its debugger worker can run");
        self.clear_selected_frame();
        let report = match self.ctx.page_in(address, process) {
            Ok(report) => report,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        if !report.from_worker {
            error!(
                "the target stopped for another reason before the worker reported; \
                 {} may still be paged in",
                ui::addr(address.0)
            );
            return Ok(());
        }
        if report.resident {
            outln!("{} is resident", ui::addr(address.0));
        } else {
            // MmPrefetchVirtualMemory declines addresses that are not backed
            // at all, and the worker reports completion either way.
            error!(
                "{} is still unreadable; it may be unmapped rather than paged out",
                ui::addr(address.0)
            );
        }
        Ok(())
    }

    fn cmd_dw(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.display_memory_command(&invocation, 32, 2, MemoryDisplayMode::words())
    }

    fn cmd_dw_ascii(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.display_memory_command(&invocation, 32, 2, MemoryDisplayMode::words_ascii())
    }

    fn cmd_dc(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.display_memory_command(&invocation, 16, 4, MemoryDisplayMode::dwords_ascii())
    }

    fn cmd_dd(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.display_memory_command(&invocation, 16, 4, MemoryDisplayMode::dwords())
    }

    fn cmd_dq(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.display_memory_command(&invocation, 8, 8, MemoryDisplayMode::qwords())
    }

    fn cmd_dp(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        // ntoseye supports only 64-bit Windows targets, so pointer-sized
        // display is a qword on both supported architectures.
        self.display_memory_command(&invocation, 8, 8, MemoryDisplayMode::qwords())
    }

    fn visit_symbol_values(
        &self,
        invocation: &CommandInvocation<'_>,
        item_size: usize,
        default_count: u64,
        visit: impl FnMut(&Self, VirtAddr, &[u8], bool, &ThreadTraceContext),
    ) -> Result<()> {
        let Some(range) = self.parse_display_range(invocation, default_count, item_size as u64)
        else {
            return Ok(());
        };
        self.visit_symbol_range(&range, item_size, visit)
    }

    fn visit_symbol_range(
        &self,
        range: &AddressRange,
        item_size: usize,
        mut visit: impl FnMut(&Self, VirtAddr, &[u8], bool, &ThreadTraceContext),
    ) -> Result<()> {
        if range.len() > MAX_DISPLAY_BYTES {
            error!("display range exceeds the maximum of {MAX_DISPLAY_BYTES:#x} bytes");
            return Ok(());
        }
        let (data, valid) = match self.read_virtual_best_effort(range) {
            Ok(read) => read,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let dtb = self.ctx.target.current_dtb();
        let trace = resolve_thread_trace_context(&self.ctx.target, dtb);
        for (index, chunk) in data.chunks(item_size).enumerate() {
            let offset = index * item_size;
            let address = range.start + offset as u64;
            let readable = chunk.len() == item_size
                && valid
                    .get(offset..offset + item_size)
                    .is_some_and(|bytes| bytes.iter().all(|ok| *ok));
            visit(self, address, chunk, readable, &trace);
        }
        outln!();
        Ok(())
    }

    fn display_symbol_values(
        &self,
        invocation: &CommandInvocation<'_>,
        item_size: usize,
        default_count: u64,
    ) -> Result<()> {
        let Some(range) = self.parse_display_range(invocation, default_count, item_size as u64)
        else {
            return Ok(());
        };
        self.display_symbol_range(&range, item_size)
    }

    /// `dds`/`dqs` over `range`: each value, and the symbol it resolves to.
    pub fn display_symbol_range(&self, range: &AddressRange, item_size: usize) -> Result<()> {
        self.visit_symbol_range(
            range,
            item_size,
            |state, address, chunk, readable, trace| {
                if chunk.len() != item_size {
                    outln!("{}  <partial>", ui::addr(address.0));
                    return;
                }
                if !readable {
                    outln!("{}  <unreadable>", ui::addr(address.0));
                    return;
                }
                let Some(value) = le_value(chunk) else {
                    return;
                };
                let width = item_size * 2;
                match try_format_symbol(&state.ctx.target, trace, value) {
                    Some(symbol) => outln!(
                        "{}  {:0width$x}  {}",
                        ui::addr(address.0),
                        value,
                        ui::symbol(&symbol),
                        width = width
                    ),
                    None => {
                        outln!("{}  {:0width$x}", ui::addr(address.0), value, width = width)
                    }
                }
            },
        )
    }

    fn cmd_dds(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.display_symbol_values(&invocation, 4, 16)
    }

    fn cmd_dqs(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.display_symbol_values(&invocation, 8, 16)
    }

    fn cmd_dyb(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.display_memory_command(&invocation, 128, 1, MemoryDisplayMode::binary())
    }

    fn cmd_dpp(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.display_pointers(&invocation, 8, 8, Pointee::Value)
    }

    fn cmd_ddp(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.display_pointers(&invocation, 4, 16, Pointee::Value)
    }

    fn cmd_dqa(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.display_pointers(&invocation, 8, 8, Pointee::String { char_size: 1 })
    }

    fn cmd_dqu(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.display_pointers(&invocation, 8, 8, Pointee::String { char_size: 2 })
    }

    fn cmd_dda(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.display_pointers(&invocation, 4, 16, Pointee::String { char_size: 1 })
    }

    fn cmd_ddu(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.display_pointers(&invocation, 4, 16, Pointee::String { char_size: 2 })
    }

    fn cmd_df(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.display_memory_command(&invocation, 16, 4, MemoryDisplayMode::floats())
    }

    fn cmd_dd_double(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.display_memory_command(&invocation, 6, 8, MemoryDisplayMode::doubles())
    }

    /// The `d*p`, `d*a`, and `d*u` family: each `item_size`-byte value as a
    /// pointer, followed by what it points to.
    fn display_pointers(
        &self,
        invocation: &CommandInvocation<'_>,
        item_size: usize,
        default_count: u64,
        pointee: Pointee,
    ) -> Result<()> {
        let width = item_size * 2;
        self.visit_symbol_values(
            invocation,
            item_size,
            default_count,
            |state, address, chunk, readable, trace| {
                if chunk.len() != item_size {
                    outln!("{}  <partial>", ui::addr(address.0));
                    return;
                }
                if !readable {
                    outln!("{}  <unreadable>", ui::addr(address.0));
                    return;
                }
                let Some(pointer) = le_value(chunk) else {
                    return;
                };
                let mut line = format!("{}  {:0width$x}", ui::addr(address.0), pointer);
                match pointee {
                    Pointee::Value => {
                        if let Some(symbol) = try_format_symbol(&state.ctx.target, trace, pointer) {
                            line.push_str(&format!("  {}", ui::symbol(&symbol)));
                        }
                        if pointer == 0 {
                            line.push_str(&format!("  -> {:0width$x}", 0));
                        } else {
                            let mut pointed = vec![0u8; item_size];
                            match state
                                .read_for_display(VirtAddr(pointer), &mut pointed)
                                .ok()
                                .and_then(|()| le_value(&pointed))
                            {
                                Some(value) => {
                                    line.push_str(&format!("  -> {value:0width$x}"));
                                    if let Some(symbol) =
                                        try_format_symbol(&state.ctx.target, trace, value)
                                    {
                                        line.push_str(&format!("  {}", ui::symbol(&symbol)));
                                    }
                                }
                                None => line.push_str("  -> <unreadable>"),
                            }
                        }
                    }
                    // A null or unreadable pointer shows no string, as in WinDbg.
                    Pointee::String { char_size } if pointer != 0 => {
                        if let Ok(text) =
                            state.quoted_string(VirtAddr(pointer), POINTER_STRING_CHARS, char_size)
                        {
                            line.push_str("  ");
                            line.push_str(&text);
                        }
                    }
                    Pointee::String { .. } => {}
                }
                outln!("{}", line);
            },
        )
    }

    fn cmd_da(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.display_string_command(&invocation, "da", 1)
    }

    fn cmd_du(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.display_string_command(&invocation, "du", 2)
    }

    fn read_string_descriptor(
        &self,
        address: VirtAddr,
        unicode: bool,
    ) -> Result<StringDescriptorFields> {
        let target = &self.ctx.target;
        // `.effmach x86` reads a WOW64 process's 32-bit descriptors.
        let bits = target.data_bitness();
        let kind = if unicode {
            StringDescriptor::Unicode
        } else {
            StringDescriptor::Ansi
        };
        if let Ok(cursor) = target.string_descriptor(address, kind, bits) {
            let fields = StringDescriptorFields {
                length: best_effort(cursor.read_field::<u16>("Length"))?,
                maximum_length: best_effort(cursor.read_field::<u16>("MaximumLength"))?,
                buffer: best_effort(cursor.read_pointer("Buffer"))?,
            };
            if fields.length.is_some() || fields.maximum_length.is_some() || fields.buffer.is_some()
            {
                return Ok(fields);
            }
        }

        // These descriptors have a stable Windows layout at each width:
        // `Buffer` follows the two lengths at pointer alignment. Retaining it
        // keeps ds/dS useful in a dump whose PDB omits the tiny string type.
        let mem = target.context_memory();
        let buffer = if bits == CODE_BITNESS_X86 {
            best_effort(mem.read::<u32>(address + 4u64))?.map(VirtAddr::from)
        } else {
            best_effort(mem.read::<VirtAddr>(address + 8u64))?
        };
        Ok(StringDescriptorFields {
            length: best_effort(mem.read(address))?,
            maximum_length: best_effort(mem.read(address + 2u64))?,
            buffer,
        })
    }

    fn display_descriptor_string(
        &self,
        invocation: &CommandInvocation<'_>,
        command: &str,
        unicode: bool,
    ) -> Result<()> {
        let start_arg = require_arg!(invocation, 0, command);
        let Some(address) = self.eval_or_report(start_arg) else {
            return Ok(());
        };
        let StringDescriptorFields {
            length,
            maximum_length,
            buffer,
        } = match self.read_string_descriptor(address, unicode) {
            Ok(fields) => fields,
            Err(e) => {
                error!(
                    "failed to read {} at {}: {}",
                    command,
                    ui::addr(address.0),
                    e
                );
                return Ok(());
            }
        };
        let length_text = length
            .map(|value| value.to_string())
            .unwrap_or_else(|| "<unreadable>".to_string());
        let maximum_length_text = maximum_length
            .map(|value| value.to_string())
            .unwrap_or_else(|| "<unreadable>".to_string());
        let buffer_text = buffer
            .map(|value| ui::addr(value.0))
            .unwrap_or_else(|| "<unreadable>".to_string());
        let (Some(length), Some(buffer)) = (length, buffer) else {
            outln!(
                "{}  Length={} MaximumLength={} Buffer={}  <unreadable>\n",
                ui::addr(address.0),
                length_text,
                maximum_length_text,
                buffer_text
            );
            return Ok(());
        };
        let unit_size = if unicode { 2usize } else { 1usize };
        let byte_len = (length as usize / unit_size) * unit_size;
        if byte_len == 0 || buffer.is_zero() {
            outln!(
                "{}  Length={} MaximumLength={} Buffer={}  \"\"\n",
                ui::addr(address.0),
                length_text,
                maximum_length_text,
                buffer_text
            );
            return Ok(());
        }

        let range = AddressRange {
            start: buffer,
            end: buffer + byte_len as u64,
        };
        let (data, valid) = match self.read_virtual_best_effort(&range) {
            Ok(read) => read,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let text = if unicode {
            utf16le_lossy(&data)
        } else {
            String::from_utf8_lossy(&data).into_owned()
        };
        let suffix = if valid.iter().all(|ok| *ok) {
            String::new()
        } else {
            " <unreadable>".red().to_string()
        };
        outln!(
            "{}  Length={} MaximumLength={} Buffer={}  \"{}\"{}\n",
            ui::addr(address.0),
            length_text,
            maximum_length_text,
            buffer_text,
            text.escape_debug(),
            suffix
        );
        Ok(())
    }

    fn cmd_ds(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.display_descriptor_string(&invocation, "ds", false)
    }

    fn cmd_ds_unicode(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.display_descriptor_string(&invocation, "dS", true)
    }

    /// Shared `da`/`du` body: read a NUL-terminated string of `char_size`-wide
    /// units, chunking reads at page boundaries so a string ending near an
    /// unmapped page still displays up to the readable part.
    fn display_string_command(
        &mut self,
        invocation: &CommandInvocation<'_>,
        command: &str,
        char_size: usize,
    ) -> Result<()> {
        let Some(start_arg) = invocation.arg(0) else {
            outln!("{}\n", command_help(command));
            return Ok(());
        };
        let Some(start) = self.eval_or_report(start_arg) else {
            return Ok(());
        };
        let max_chars = match invocation.arg(1) {
            Some(arg) => match self.eval_or_report(arg) {
                Some(v) if v.0 > 0 => match checked_display_string_count(v.0, char_size) {
                    Ok(count) => count,
                    Err(error) => {
                        error!("{error}");
                        return Ok(());
                    }
                },
                Some(_) => {
                    error!("invalid max-chars: {}", arg);
                    return Ok(());
                }
                None => return Ok(()),
            },
            None => 256,
        };

        match self.quoted_string(start, max_chars, char_size) {
            Ok(text) => outln!("{}  {}\n", ui::addr(start.0), text),
            Err(error) => {
                error!("failed to read string at {:#x}: {}", start.0, error);
            }
        }

        Ok(())
    }

    /// The NUL-terminated string of `char_size`-wide units at `start`,
    /// quoted and escaped as `da`/`du` show it, marked when it is cut short
    /// by `max_chars` or an unreadable page.
    fn quoted_string(&self, start: VirtAddr, max_chars: usize, char_size: usize) -> Result<String> {
        let read = self.ctx.read_terminated(start, max_chars, char_size)?;
        let text: String = if char_size == 1 {
            read.bytes.iter().map(|&byte| char::from(byte)).collect()
        } else {
            utf16le_lossy(&read.bytes)
        };
        let suffix = if read.unreadable {
            " <unreadable>".red().to_string()
        } else if read.bytes.len() / char_size == max_chars {
            "...".bright_black().to_string()
        } else {
            String::new()
        };
        Ok(format!("\"{}\"{}", text.escape_debug(), suffix))
    }

    fn cmd_disasm(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        // WinDbg: `L<n>` counts instructions; an end address lists every
        // instruction starting at or before it.
        const DEFAULT_INSTRUCTIONS: u64 = 8;
        // The window is sized for the machine at the start expression's
        // address, which is only known once it is evaluated: size it for the
        // longest instruction set, and decode what the address holds.
        let max_instruction_bytes = CodeMachine::Amd64.max_instruction_bytes() as u64;
        let (start_addr, byte_len, instruction_limit, last_start) =
            match invocation.arg(1).and_then(windbg_count_expression) {
                Some(count_expr) => {
                    let start_arg = require_arg!(invocation, 0, "u");
                    let Some(start) = self.eval_or_report(start_arg) else {
                        return Ok(());
                    };
                    let count = match self.eval_or_report(count_expr) {
                        Some(c) if c.0 > 0 && c.0 <= MAX_DISASSEMBLY_INSTRUCTIONS as u64 => c.0,
                        Some(_) => {
                            error!(
                                "instruction count must be 1..{}",
                                MAX_DISASSEMBLY_INSTRUCTIONS
                            );
                            return Ok(());
                        }
                        None => return Ok(()),
                    };
                    (
                        start,
                        count * max_instruction_bytes,
                        Some(count as usize),
                        None,
                    )
                }
                None => match invocation.arg(1) {
                    Some(_) => {
                        let range = match AddressRange::parse(
                            &invocation,
                            &self.ctx.target,
                            self.radix,
                            DEFAULT_INSTRUCTIONS,
                            1,
                        ) {
                            Ok(r) => r,
                            Err(e) => {
                                error!("{}", e);
                                return Ok(());
                            }
                        };
                        // The last instruction may run past the end.
                        (
                            range.start,
                            range.len() as u64 + max_instruction_bytes - 1,
                            None,
                            Some(range.end.0),
                        )
                    }
                    None => {
                        let start_arg = require_arg!(invocation, 0, "u");
                        match self.eval_or_report(start_arg) {
                            Some(a) => (
                                a,
                                DEFAULT_INSTRUCTIONS * max_instruction_bytes,
                                Some(DEFAULT_INSTRUCTIONS as usize),
                                None,
                            ),
                            None => return Ok(()),
                        }
                    }
                },
            };

        // An instruction window may run past the end of the mapped image;
        // keep what is readable up to the first unreadable page.
        let mut bytes: Vec<u8> = vec![0u8; byte_len as usize];
        if self.read_for_display(start_addr, &mut bytes).is_err() {
            let page_end = start_addr
                .0
                .checked_add(PAGE_SIZE as u64 - start_addr.page_offset())
                .ok_or(Error::InvalidRange)?;
            let readable = page_end.saturating_sub(start_addr.0).min(byte_len) as usize;
            bytes.truncate(readable);
            if let Err(e) = self.read_for_display(start_addr, &mut bytes) {
                error!("{e}");
                return Ok(());
            }
        }

        let dtb = self.ctx.target.current_dtb();
        let trace = resolve_thread_trace_context(&self.ctx.target, dtb);
        let resolve = |target: u64| format_symbol(&self.ctx.target, &trace, target);
        let machine = self.ctx.target.code_machine(start_addr);
        let mut rows = decode_code(&bytes, start_addr.0, instruction_limit, machine, resolve);
        if let Some(end) = last_start {
            rows.retain(|row| row.ip < end);
        }
        render_rows(&rows, |_| None);
        outln!();

        Ok(())
    }

    fn cmd_ub(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let address_arg = require_arg!(invocation, 0, "ub");
        let Some(address) = self.eval_or_report(address_arg) else {
            return Ok(());
        };
        let count = match invocation.arg(1) {
            Some(arg) => {
                let count = windbg_count_expression(arg)
                    .map(|count| count.strip_prefix('?').unwrap_or(count))
                    .unwrap_or(arg);
                match self.eval_or_report(count) {
                    Some(count) if (1..=MAX_DISASSEMBLY_INSTRUCTIONS as u64).contains(&count.0) => {
                        count.0 as usize
                    }
                    Some(_) => {
                        error!(
                            "instruction count must be 1..{}: {}",
                            MAX_DISASSEMBLY_INSTRUCTIONS, arg
                        );
                        return Ok(());
                    }
                    None => return Ok(()),
                }
            }
            None => 8,
        };

        let rows = match self.ctx.disassemble_back(address, count) {
            Ok(rows) => rows,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        render_rows(&rows, |_| None);
        outln!();
        Ok(())
    }

    fn cmd_uf(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let expression = invocation.arg(0).unwrap_or("@rip");
        let Some(address) = self.eval_or_report(expression) else {
            return Ok(());
        };

        let (symbol, len, rows) = match self.ctx.disassemble_function(address) {
            Ok(disassembly) => disassembly,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        outln!("{}  {} bytes", ui::symbol(&symbol), len);
        render_rows(&rows, |_| None);
        outln!();

        Ok(())
    }

    fn cmd_disasm_search(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        /// Instructions searched when no count bounds the search.
        const MAX_SEARCH_INSTRUCTIONS: u64 = 1 << 20;
        /// Code decoded per read.
        const CHUNK: usize = PAGE_SIZE;
        let args: Vec<&str> = invocation.argv.iter().map(|arg| arg.as_ref()).collect();
        let count_arg = match args.get(2..).unwrap_or_default() {
            [] => None,
            [count] => match windbg_count_expression(count) {
                Some(count) => Some(count),
                None => {
                    outln!("{}\n", command_help("#"));
                    return Ok(());
                }
            },
            [l, count] if l.eq_ignore_ascii_case("l") => Some(*count),
            _ => {
                outln!("{}\n", command_help("#"));
                return Ok(());
            }
        };
        if let Some(pattern) = args.first() {
            self.disasm_search.pattern = Some((*pattern).to_string());
        }
        let Some(pattern) = self.disasm_search.pattern.clone() else {
            outln!("{}\n", command_help("#"));
            return Ok(());
        };
        let start = match args.get(1) {
            Some(address) => self.eval_or_report(address),
            None => self.disasm_search.next.or_else(|| {
                let ip = self.ctx.target.builtin_variable_value("ip");
                if ip.is_none() {
                    error!("no address to search from: give one, or halt the target");
                }
                ip.map(VirtAddr)
            }),
        };
        let Some(start) = start else {
            return Ok(());
        };
        let budget = match count_arg {
            Some(count) => match self.eval_or_report(count) {
                Some(count) if (1..=MAX_SEARCH_INSTRUCTIONS).contains(&count.0) => count.0,
                Some(_) => {
                    error!("instruction count must be 1..{MAX_SEARCH_INSTRUCTIONS:#x}");
                    return Ok(());
                }
                None => return Ok(()),
            },
            None => MAX_SEARCH_INSTRUCTIONS,
        };

        let wildcard = format!("*{pattern}*");
        let matches = |row: &DisasmRow| {
            let bytes: String = row.hex.split_whitespace().collect();
            let text = match &row.comment {
                Some(comment) => format!("{} {comment}", row.asm()),
                None => row.asm(),
            };
            [format!("{:016x}", row.ip), bytes, text]
                .iter()
                .any(|part| glob_matches(&wildcard, part, true))
        };
        let target = &self.ctx.target;
        let trace = resolve_thread_trace_context(target, target.current_dtb());
        let resolve = |address: u64| format_symbol(target, &trace, address);
        let machine = target.code_machine(start);
        let max_instruction_bytes = machine.max_instruction_bytes();
        let mut cursor = start.0;
        let mut searched = 0u64;
        let mut found = None;
        let mut stop = None;
        let mut buffer = vec![0u8; CHUNK + max_instruction_bytes];
        'search: while searched < budget {
            if target.interrupted() {
                stop = Some("interrupted".to_string());
                break;
            }
            let readable = self.ctx.read_masked_partial(VirtAddr(cursor), &mut buffer);
            let bytes = &buffer[..readable];
            // Instructions starting past the chunk are decoded again from the
            // next read, which has the bytes after them.
            let window_end = cursor.saturating_add(CHUNK.min(readable) as u64);
            let read_end = cursor.saturating_add(readable as u64);
            let mut next = cursor;
            for row in decode_code(bytes, cursor, None, machine, resolve) {
                let end = row
                    .ip
                    .saturating_add(row.hex.split_whitespace().count() as u64);
                if row.ip >= window_end || end > read_end {
                    break;
                }
                searched += 1;
                next = end;
                if matches(&row) {
                    found = Some(row);
                    break 'search;
                }
                if searched == budget {
                    break;
                }
            }
            if next == cursor {
                stop = Some(format!("{} is unreadable", ui::addr(read_end)));
                break;
            }
            cursor = next;
        }

        match found {
            Some(row) => {
                let len = row.hex.split_whitespace().count() as u64;
                self.disasm_search.next = Some(VirtAddr(row.ip.saturating_add(len)));
                render_rows(&[row], |_| None);
            }
            None => {
                self.disasm_search.next = Some(VirtAddr(cursor));
                outln!(
                    "{} for '{pattern}' in {searched:#x} instructions from {}{}",
                    "no match".bright_black(),
                    ui::addr(start.0),
                    stop.map(|stop| format!("; {stop}")).unwrap_or_default()
                );
            }
        }
        outln!();
        Ok(())
    }

    fn cmd_eb(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.write_scalar_command(
            &invocation,
            "eb",
            "byte",
            |value| vec![value as u8],
            |value| format!("{:02x}", value as u8),
        )
    }

    fn cmd_ew(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.write_scalar_command(
            &invocation,
            "ew",
            "word",
            |value| (value as u16).to_le_bytes().to_vec(),
            |value| format!("{:04x}", value as u16),
        )
    }

    fn cmd_ed(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.write_scalar_command(
            &invocation,
            "ed",
            "dword",
            |value| (value as u32).to_le_bytes().to_vec(),
            |value| format!("{:#x}", value as u32),
        )
    }

    fn cmd_eq(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.write_scalar_command(
            &invocation,
            "eq",
            "qword",
            |value| value.to_le_bytes().to_vec(),
            |value| format!("{:#x}", value),
        )
    }

    fn cmd_ef(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.write_float_command(&invocation, "ef", 4)
    }

    fn cmd_ed_double(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.write_float_command(&invocation, "eD", 8)
    }

    fn write_string_command(
        &mut self,
        invocation: &CommandInvocation<'_>,
        command: &str,
        unicode: bool,
        nul_terminated: bool,
    ) -> Result<()> {
        if invocation.argv.len() < 2 {
            outln!("{}\n", command_help(command));
            return Ok(());
        }
        let Some(address) = self.eval_or_report(invocation.arg(0).unwrap()) else {
            return Ok(());
        };
        let text = invocation.join_args(1);
        let mut bytes = if unicode {
            text.encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>()
        } else {
            text.into_bytes()
        };
        if nul_terminated {
            if unicode {
                bytes.extend_from_slice(&[0, 0]);
            } else {
                bytes.push(0);
            }
        }
        let mem = self.ctx.target.context_memory();
        match mem.write_bytes(address, &bytes) {
            Ok(()) => outln!(
                "{} {} bytes -> {}\n",
                "wrote".green(),
                bytes.len(),
                ui::addr(address.0)
            ),
            Err(e) => error!("failed to write {}: {}", command, e),
        }
        Ok(())
    }

    fn cmd_ea(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.write_string_command(&invocation, "ea", false, false)
    }

    fn cmd_eu(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.write_string_command(&invocation, "eu", true, false)
    }

    fn cmd_eza(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.write_string_command(&invocation, "eza", false, true)
    }

    fn cmd_ezu(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.write_string_command(&invocation, "ezu", true, true)
    }

    fn parse_range_at(
        &self,
        invocation: &CommandInvocation<'_>,
        address_index: usize,
        item_size: u64,
    ) -> Result<AddressRange> {
        let start_arg = invocation.arg(address_index).ok_or(Error::InvalidRange)?;
        let start = Expr::eval_with_radix(start_arg, &self.ctx.target, self.radix)?;
        let range_arg = invocation
            .arg(address_index + 1)
            .ok_or(Error::InvalidRange)?;
        eval_range(range_arg, &self.ctx.target, self.radix, start, item_size)
    }

    fn cmd_writemem(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let path = require_arg!(invocation, 0, ".writemem");
        let range = match self.parse_range_at(&invocation, 1, 1) {
            Ok(range) => range,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };
        let mut file = match File::create(path) {
            Ok(file) => file,
            Err(e) => {
                error!("failed to create '{}': {}", path, e);
                return Ok(());
            }
        };
        let mut unreadable = 0usize;
        let mut write_error = None;
        for_each_page_chunk(range.start, range.len(), |_, address, len| {
            if write_error.is_some() {
                return;
            }
            let mut bytes = vec![0u8; len];
            if self.read_for_display(address, &mut bytes).is_err() {
                bytes.fill(0);
                unreadable += len;
            }
            if let Err(e) = file.write_all(&bytes) {
                write_error = Some(e.to_string());
            }
        });
        if let Some(error) = write_error {
            error!("failed to write '{}': {}", path, error);
            return Ok(());
        }
        if unreadable == 0 {
            outln!("wrote {:#x} bytes to '{}'\n", range.len(), path);
        } else {
            outln!(
                "wrote {:#x} bytes to '{}' ({} unreadable bytes written as zero)\n",
                range.len(),
                path,
                unreadable
            );
        }
        Ok(())
    }

    fn cmd_readmem(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let path = require_arg!(invocation, 0, ".readmem");
        let range = match self.parse_range_at(&invocation, 1, 1) {
            Ok(range) => range,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };
        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(e) => {
                error!("failed to open '{}': {}", path, e);
                return Ok(());
            }
        };
        let memory = self.ctx.target.context_memory();
        let mut unwritten = 0usize;
        let mut read_error = None;
        for_each_page_chunk(range.start, range.len(), |offset, address, len| {
            if read_error.is_some() {
                return;
            }
            let mut bytes = vec![0u8; len];
            if let Err(e) = file.read_exact(&mut bytes) {
                read_error = Some((offset, e.to_string()));
                return;
            }
            if let Err(error) = memory.write_bytes(address, &bytes) {
                error!(
                    "failed to write memory at {}: {}",
                    ui::addr(address.0),
                    error
                );
                unwritten += len;
            }
        });
        if let Some((offset, error)) = read_error {
            error!(
                "failed to read '{}' at file offset {:#x}: {}",
                path, offset, error
            );
            return Ok(());
        }
        if unwritten == 0 {
            outln!(
                "read {:#x} bytes from '{}' into {}\n",
                range.len(),
                path,
                ui::addr(range.start.0)
            );
        } else {
            outln!(
                "read {:#x} bytes from '{}' ({} bytes not written)\n",
                range.len(),
                path,
                unwritten
            );
        }
        Ok(())
    }

    fn cmd_formats(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let expression = invocation.raw_tail.trim();
        if expression.is_empty() {
            outln!("{}\n", command_help(".formats"));
            return Ok(());
        }
        let Some(VirtAddr(value)) = self.eval_or_report(expression) else {
            return Ok(());
        };
        outln!("hexadecimal: 0x{value:016x}");
        outln!("decimal: {value} (signed {})", value as i64);
        outln!("octal: 0o{value:o}");
        outln!("binary: 0b{value:064b}");
        outln!("characters: \"{}\"", format_characters(value));
        outln!("float: {}", format_float(f32::from_bits(value as u32)));
        outln!("double: {}", format_float(f64::from_bits(value)));

        const FILETIME_UNIX_OFFSET_SECONDS: i64 = 11_644_473_600;
        const FILETIME_MAX_TICKS: u64 = 265_046_774_400_000_000;
        let filetime_seconds = value / 10_000_000;
        let filetime_unix_seconds =
            (filetime_seconds as i64).saturating_sub(FILETIME_UNIX_OFFSET_SECONDS);
        if value <= FILETIME_MAX_TICKS
            && (FILETIME_UNIX_MIN_SECONDS..=FILETIME_UNIX_MAX_SECONDS)
                .contains(&filetime_unix_seconds)
        {
            let nanos = ((value % 10_000_000) * 100) as u32;
            outln!(
                "time (FILETIME): {} UTC",
                format_unix_timestamp(filetime_unix_seconds, nanos)
            );
        } else {
            outln!("time (FILETIME): out of range");
        }
        let unix_seconds = value as i64;
        if (FILETIME_UNIX_MIN_SECONDS..=FILETIME_UNIX_MAX_SECONDS).contains(&unix_seconds) {
            outln!(
                "time (Unix seconds): {} UTC",
                format_unix_timestamp(unix_seconds, 0)
            );
        } else {
            outln!("time (Unix seconds): out of range");
        }
        outln!();
        Ok(())
    }

    fn cmd_f(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let args: Vec<&str> = invocation.argv.iter().map(|arg| arg.as_ref()).collect();
        let [address_arg, range_arg, pattern_args @ ..] = args.as_slice() else {
            outln!("{}\n", command_help("f"));
            return Ok(());
        };
        if pattern_args.is_empty() {
            outln!("{}\n", command_help("f"));
            return Ok(());
        }
        let Some(start) = self.eval_or_report(address_arg) else {
            return Ok(());
        };
        let range = match eval_range(range_arg, &self.ctx.target, self.radix, start, 1) {
            Ok(range) => range,
            Err(e) => {
                error!("invalid range '{}': {}", range_arg, e);
                return Ok(());
            }
        };
        let (address, length) = (range.start, range.len());
        let pattern = match SearchKind::Bytes.pattern(pattern_args, |value| {
            Expr::eval_with_radix(value, &self.ctx.target, self.radix).map(|value| value.0)
        }) {
            Ok(pattern) => pattern,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };

        let data = repeat_pattern(&pattern, length);
        let mem = self.ctx.target.context_memory();

        if let Err(e) = mem.write_bytes(address, &data) {
            error!("failed to fill memory: {}", e);
        } else {
            outln!(
                "{} {:#x} bytes at {} with {}\n",
                "filled".green(),
                length,
                ui::addr(address.0),
                format!("[{}]", hex::encode(&pattern)).green()
            );
        }

        Ok(())
    }

    /// The range `<address> <L<count>|end>` and the address after it, the
    /// shape `c` and `m` share; `None` after printing why not.
    fn range_and_address(
        &self,
        invocation: &CommandInvocation<'_>,
    ) -> Option<(AddressRange, VirtAddr)> {
        let [start_arg, range_arg, other_arg] = invocation.argv.as_slice() else {
            outln!("{}\n", command_help(invocation.name));
            return None;
        };
        let start = self.eval_or_report(start_arg)?;
        let range = match eval_range(range_arg, &self.ctx.target, self.radix, start, 1) {
            Ok(range) => range,
            Err(error) => {
                error!("invalid range '{range_arg}': {error}");
                return None;
            }
        };
        let other = self.eval_or_report(other_arg)?;
        Some((range, other))
    }

    fn cmd_c(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some((range, other)) = self.range_and_address(&invocation) else {
            return Ok(());
        };
        let result = match self.ctx.compare(range.start, other, range.len()) {
            Ok(result) => result,
            Err(error) => {
                error!("failed to compare memory: {error}");
                return Ok(());
            }
        };
        for &(offset, left, right) in &result.differences {
            outln!(
                "{}  {:02x} - {}  {:02x}",
                ui::addr(range.start.0.wrapping_add(offset as u64)),
                left,
                ui::addr(other.0.wrapping_add(offset as u64)),
                right
            );
        }
        match result.differences.len() {
            0 => outln!(
                "{} ({:#x} bytes compared)",
                "no differences".bright_black(),
                result.compared
            ),
            count => outln!(
                "\n{count} {} ({:#x} bytes compared)",
                if count == 1 {
                    "difference"
                } else {
                    "differences"
                },
                result.compared
            ),
        }
        if result.unreadable > 0 {
            outln!(
                "{}",
                format!("{:#x} unreadable bytes skipped", result.unreadable).bright_black()
            );
        }
        match result.stopped {
            Some(SearchStop::MatchLimit) => outln!(
                "{}",
                format!("stopped after {MAX_SEARCH_MATCHES} differences").bright_black()
            ),
            Some(SearchStop::Interrupted) => outln!("{}", "interrupted".bright_black()),
            None => {}
        }
        outln!();
        Ok(())
    }

    fn cmd_m(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        /// A copy is buffered whole, so it is bounded.
        const MAX_MOVE_BYTES: usize = 16 << 20;
        let Some((range, destination)) = self.range_and_address(&invocation) else {
            return Ok(());
        };
        if range.len() > MAX_MOVE_BYTES {
            error!(
                "cannot copy {:#x} bytes: at most {MAX_MOVE_BYTES:#x} are copied at once",
                range.len()
            );
            return Ok(());
        }
        let (data, valid) = match self.read_virtual_best_effort(&range) {
            Ok(read) => read,
            Err(error) => {
                error!("failed to read {}: {error}", ui::addr(range.start.0));
                return Ok(());
            }
        };
        if let Some(offset) = valid.iter().position(|valid| !valid) {
            error!(
                "nothing copied: {} is unreadable",
                ui::addr(range.start.0.wrapping_add(offset as u64))
            );
            return Ok(());
        }
        match self
            .ctx
            .target
            .context_memory()
            .write_bytes(destination, &data)
        {
            Ok(()) => outln!(
                "copied {:#x} bytes from {} to {}\n",
                data.len(),
                ui::addr(range.start.0),
                ui::addr(destination.0)
            ),
            Err(error) => error!("failed to write {}: {error}", ui::addr(destination.0)),
        }
        Ok(())
    }

    fn cmd_s(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let mut args: Vec<&str> = invocation.argv.iter().map(|arg| arg.as_ref()).collect();
        let kind = match args.first().and_then(|flag| SearchKind::from_flag(flag)) {
            Some(kind) => {
                args.remove(0);
                kind
            }
            None => SearchKind::Bytes,
        };
        let [start_arg, range_arg, pattern_args @ ..] = args.as_slice() else {
            outln!("{}\n", command_help("s"));
            return Ok(());
        };
        if pattern_args.is_empty() {
            outln!("{}\n", command_help("s"));
            return Ok(());
        }
        let Some(start_addr) = self.eval_or_report(start_arg) else {
            return Ok(());
        };
        let range = match eval_range(
            range_arg,
            &self.ctx.target,
            self.radix,
            start_addr,
            kind.element_size(),
        ) {
            Ok(range) => range,
            Err(error) => {
                error!("invalid range '{range_arg}': {error}");
                return Ok(());
            }
        };
        let (start_addr, length) = (range.start, range.len());
        let pattern = match kind.pattern(pattern_args, |value| {
            Expr::eval_with_radix(value, &self.ctx.target, self.radix).map(|value| value.0)
        }) {
            Ok(pattern) => pattern,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };

        let result = match self.ctx.search(start_addr, &pattern, length) {
            Ok(result) => result,
            Err(e) => {
                error!("failed to search memory: {}", e);
                return Ok(());
            }
        };
        let hits = result.matches;
        for &addr in &hits {
            let sym = self
                .ctx
                .target
                .closest_symbol_current_context(VirtAddr(addr))
                .unwrap_or_default();

            outln!("{}  {}", ui::addr(addr), ui::symbol(&sym));
        }

        if hits.is_empty() {
            outln!(
                "{} (searched {:#x} bytes at {})",
                "no matches found".bright_black(),
                length,
                ui::addr(start_addr.0)
            );
        } else {
            outln!(
                "\n{} {} (in $0..${})",
                hits.len(),
                if hits.len() == 1 { "match" } else { "matches" },
                hits.len() - 1
            );
        }
        if result.unreadable > 0 {
            outln!(
                "{}",
                format!("{:#x} unreadable bytes skipped", result.unreadable).bright_black()
            );
        }
        match result.stopped {
            Some(SearchStop::MatchLimit) => outln!(
                "{}",
                format!("stopped after {MAX_SEARCH_MATCHES} matches").bright_black()
            ),
            Some(SearchStop::Interrupted) => outln!("{}", "interrupted".bright_black()),
            None => {}
        }
        self.ctx.target.set_results(hits, self.line.clone());
        outln!();

        Ok(())
    }
}

fn checked_display_string_count(max_chars: u64, char_size: usize) -> Result<usize> {
    let max_chars_by_bytes = u64::try_from(MAX_DISPLAY_BYTES / char_size).unwrap_or(u64::MAX);
    if max_chars > max_chars_by_bytes {
        return Err(Error::InvalidArgument(format!(
            "display range exceeds the maximum of {MAX_DISPLAY_BYTES:#x} bytes"
        )));
    }
    usize::try_from(max_chars)
        .map_err(|_| Error::InvalidArgument("string length exceeds the platform limit".into()))
}

fn format_characters(value: u64) -> String {
    value
        .to_le_bytes()
        .into_iter()
        .map(|byte| {
            if byte.is_ascii_graphic() || byte == b' ' {
                byte as char
            } else {
                '.'
            }
        })
        .collect()
}

/// Format a proleptic-Gregorian UTC timestamp without pulling a date/time
/// dependency into the debugger. `seconds` is Unix time and `nanos` is the
/// fractional second component.
fn format_unix_timestamp(seconds: i64, nanos: u32) -> String {
    let days = seconds.div_euclid(86_400);
    let day_seconds = seconds.rem_euclid(86_400);
    let hour = day_seconds / 3_600;
    let minute = (day_seconds % 3_600) / 60;
    let second = day_seconds % 60;

    // Howard Hinnant's civil_from_days algorithm, shifted from 1970-01-01.
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = year + if month <= 2 { 1 } else { 0 };
    if nanos == 0 {
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}")
    } else {
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{nanos:09}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_display_counts_are_limited_by_requested_bytes() {
        assert_eq!(
            checked_display_string_count(MAX_DISPLAY_BYTES as u64, 1).unwrap(),
            MAX_DISPLAY_BYTES
        );
        assert!(matches!(
            checked_display_string_count(MAX_DISPLAY_BYTES as u64 + 1, 1),
            Err(Error::InvalidArgument(_))
        ));
        assert_eq!(
            checked_display_string_count((MAX_DISPLAY_BYTES / 2) as u64, 2).unwrap(),
            MAX_DISPLAY_BYTES / 2
        );
        assert!(matches!(
            checked_display_string_count((MAX_DISPLAY_BYTES / 2) as u64 + 1, 2),
            Err(Error::InvalidArgument(_))
        ));
    }
}
