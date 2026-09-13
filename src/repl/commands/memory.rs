use std::fmt::Display;
use std::fs::File;
use std::io::{Read, Write};

use iced_x86::{Code, Decoder, DecoderOptions};
use owo_colors::OwoColorize;

use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::expr::Expr;
use crate::memory::PAGE_SIZE;
use crate::types::{Arch, VirtAddr};
use crate::ui;
use crate::unwind::{
    ThreadTraceContext, format_symbol, function_range, resolve_thread_trace_context,
    try_format_symbol,
};

use crate::repl::*;

pub const MAX_DISPLAY_BYTES: usize = 1024 * 1024;
const MAX_DISASSEMBLY_INSTRUCTIONS: usize = 4096;
const FILETIME_UNIX_MIN_SECONDS: i64 = -62_135_596_800;
const FILETIME_UNIX_MAX_SECONDS: i64 = 253_402_300_799;

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
    names: ["dpp"],
    usage: "dpp <address> [L<count>|length|end]",
    summary: "Display pointers, dereference them, and annotate symbols.",
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
    usage: ".writemem <file> <address> [L<len>|end]",
    summary: "Write a virtual memory range to a file.",
    completion: [None, Expression, Expression],
}

repl_command! {
    cmd_readmem;
    names: [".readmem"],
    usage: ".readmem <file> <address> [L<len>|end]",
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
    usage: "f <address> <hex bytes> [L<count>|length|end]",
    summary: "Fill memory with a repeated byte pattern.",
    details: "hex bytes: 90, 4883792000740a, or \\x90\\x90",
    completion: [Expression, None, Expression],
}

repl_command! {
    cmd_s;
    names: ["s"],
    usage: "s <address> <hex bytes> [length]",
    summary: "Search memory for a byte pattern.",
    details: "hex bytes: 4883792000740a or \\x48\\x83\\x79\\x20\\x00\\x74\\x0a",
    completion: [Expression, None, Expression],
}

fn page_bounded_unit_read_len(
    address: VirtAddr,
    remaining_units: usize,
    unit_size: usize,
) -> usize {
    debug_assert!(remaining_units > 0);
    debug_assert!(unit_size > 0);

    let page_remaining = PAGE_SIZE - address.page_offset() as usize;
    let bounded = remaining_units
        .saturating_mul(unit_size)
        .min(page_remaining);
    let whole_units = bounded - bounded % unit_size;
    // A unit beginning at the final byte of a page must be read whole across
    // the boundary; otherwise every read ends on a unit boundary.
    if whole_units == 0 {
        unit_size
    } else {
        whole_units
    }
}

pub fn for_each_page_chunk(
    start: VirtAddr,
    length: usize,
    mut visit: impl FnMut(usize, VirtAddr, usize),
) {
    let mut offset = 0usize;
    while offset < length {
        let address = start + offset as u64;
        let chunk_len = page_bounded_unit_read_len(address, length - offset, 1);
        visit(offset, address, chunk_len);
        offset += chunk_len;
    }
}

pub fn read_page_chunks(
    start: VirtAddr,
    length: usize,
    mut read: impl FnMut(VirtAddr, &mut [u8]) -> Result<()>,
) -> (Vec<u8>, Vec<bool>) {
    let mut data = vec![0u8; length];
    let mut valid = vec![false; length];
    for_each_page_chunk(start, length, |offset, address, chunk_len| {
        if read(address, &mut data[offset..offset + chunk_len]).is_ok() {
            valid[offset..offset + chunk_len].fill(true);
        }
    });
    (data, valid)
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
    fn read_virtual_best_effort(&self, range: &AddressRange) -> (Vec<u8>, Vec<bool>) {
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
        let range = match AddressRange::parse(
            invocation,
            &self.ctx.target,
            self.radix,
            default_count,
            item_size,
        ) {
            Ok(r) => r,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };
        if range.len() > MAX_DISPLAY_BYTES {
            error!("display range exceeds the maximum of {MAX_DISPLAY_BYTES:#x} bytes");
            return Ok(());
        }

        let (data, valid) = self.read_virtual_best_effort(&range);
        display_memory_with_validity(range.start, &data, Some(&valid), &mode);

        Ok(())
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

        let address =
            match Expr::eval_with_radix(invocation.arg(0).unwrap(), &self.ctx.target, self.radix) {
                Ok(a) => a,
                Err(e) => {
                    error!("{}", e);
                    return Ok(());
                }
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

        let mem = self.ctx.target.current_process()?.memory();
        if let Err(e) = mem.write_bytes(address, &bytes) {
            error!("failed to write {}: {}", noun, e);
        } else {
            outln!(
                "{} {} -> {}\n",
                "wrote".green(),
                formatted_values.join(" "),
                ui::addr(address.0)
            );
        }

        Ok(())
    }

    fn cmd_db(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.display_memory_command(&invocation, 128, 1, MemoryDisplayMode::bytes())
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
        mut visit: impl FnMut(&Self, VirtAddr, &[u8], bool, &ThreadTraceContext),
    ) -> Result<()> {
        let range = match AddressRange::parse(
            invocation,
            &self.ctx.target,
            self.radix,
            default_count,
            item_size as u64,
        ) {
            Ok(r) => r,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };
        if range.len() > MAX_DISPLAY_BYTES {
            error!("display range exceeds the maximum of {MAX_DISPLAY_BYTES:#x} bytes");
            return Ok(());
        }
        let (data, valid) = self.read_virtual_best_effort(&range);
        let dtb = self.ctx.target.current_process()?.dtb();
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
                let value = match item_size {
                    4 => {
                        let Ok(bytes) = chunk.try_into() else {
                            return;
                        };
                        u32::from_le_bytes(bytes) as u64
                    }
                    8 => {
                        let Ok(bytes) = chunk.try_into() else {
                            return;
                        };
                        u64::from_le_bytes(bytes)
                    }
                    _ => return,
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
        self.visit_symbol_values(
            &invocation,
            8,
            8,
            |state, address, chunk, readable, trace| {
                if chunk.len() != 8 {
                    outln!("{}  <partial>", ui::addr(address.0));
                    return;
                }
                if !readable {
                    outln!("{}  <unreadable>", ui::addr(address.0));
                    return;
                }
                let Ok(pointer_bytes) = chunk.try_into() else {
                    return;
                };
                let pointer = u64::from_le_bytes(pointer_bytes);
                let pointer_symbol = try_format_symbol(&state.ctx.target, trace, pointer);
                let mut line = format!("{}  {:016x}", ui::addr(address.0), pointer);
                if let Some(symbol) = pointer_symbol {
                    line.push_str(&format!("  {}", ui::symbol(&symbol)));
                }
                if pointer == 0 {
                    line.push_str("  -> 0000000000000000");
                } else {
                    let mut pointed = [0u8; 8];
                    match state.read_for_display(VirtAddr(pointer), &mut pointed) {
                        Ok(()) => {
                            let value = u64::from_le_bytes(pointed);
                            line.push_str(&format!("  -> {:016x}", value));
                            if let Some(symbol) = try_format_symbol(&state.ctx.target, trace, value)
                            {
                                line.push_str(&format!("  {}", ui::symbol(&symbol)));
                            }
                        }
                        Err(_) => line.push_str("  -> <unreadable>"),
                    }
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
        let process = self.ctx.target.current_process()?;
        let type_names: &[&str] = if unicode {
            &["_UNICODE_STRING"]
        } else {
            // `_STRING` is the canonical Windows name; older PDBs sometimes
            // expose only its `_ANSI_STRING` spelling.
            &["_STRING", "_ANSI_STRING"]
        };
        for type_name in type_names {
            if let Ok(cursor) = process.types().struct_at(type_name, address) {
                let fields = StringDescriptorFields {
                    length: cursor.read_field::<u16>("Length").ok(),
                    maximum_length: cursor.read_field::<u16>("MaximumLength").ok(),
                    buffer: cursor.read_field::<VirtAddr>("Buffer").ok(),
                };
                if fields.length.is_some()
                    || fields.maximum_length.is_some()
                    || fields.buffer.is_some()
                {
                    return Ok(fields);
                }
            }
        }

        // These descriptors have a stable 64-bit Windows layout.  Retaining a
        // layout fallback keeps ds/dS useful in a dump whose PDB omits the
        // otherwise tiny string type.
        let mem = process.memory();
        Ok(StringDescriptorFields {
            length: mem.read(address).ok(),
            maximum_length: mem.read(address + 2u64).ok(),
            buffer: mem.read(address + 8u64).ok(),
        })
    }

    fn display_descriptor_string(
        &self,
        invocation: &CommandInvocation<'_>,
        command: &str,
        unicode: bool,
    ) -> Result<()> {
        let start_arg = require_arg!(invocation, 0, command);
        let address = match Expr::eval_with_radix(start_arg, &self.ctx.target, self.radix) {
            Ok(address) => address,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
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
        let (data, valid) = self.read_virtual_best_effort(&range);
        let text = if unicode {
            let units = data
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]));
            String::from_utf16_lossy(&units.collect::<Vec<_>>())
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
        let start = match Expr::eval_with_radix(start_arg, &self.ctx.target, self.radix) {
            Ok(a) => a,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };
        let max_chars = match invocation.arg(1) {
            Some(arg) => match Expr::eval_with_radix(arg, &self.ctx.target, self.radix) {
                Ok(v) if v.0 > 0 => v.0 as usize,
                Ok(_) => {
                    error!("invalid max-chars: {}", arg);
                    return Ok(());
                }
                Err(e) => {
                    error!("{}", e);
                    return Ok(());
                }
            },
            None => 256,
        };

        let mut units: Vec<u16> = Vec::new();
        let mut terminated = false;
        let mut failed_at = None;
        let mut addr = start;
        while units.len() < max_chars && !terminated {
            // End each ordinary read at both a page boundary and a whole-unit
            // boundary. If one UTF-16 unit itself straddles pages, read that
            // unit whole so neither byte is discarded.
            let want = page_bounded_unit_read_len(addr, max_chars - units.len(), char_size);
            let mut buf = vec![0u8; want];
            if let Err(e) = self.read_for_display(addr, &mut buf) {
                failed_at = Some((addr, e));
                break;
            }
            terminated = push_string_units(&buf, char_size, max_chars, &mut units);
            addr += want as u64;
        }

        if units.is_empty()
            && let Some((addr, e)) = failed_at
        {
            error!("failed to read string at {:#x}: {}", addr, e);
            return Ok(());
        }

        let text: String = if char_size == 1 {
            units.iter().map(|&u| u as u8 as char).collect()
        } else {
            String::from_utf16_lossy(&units)
        };
        let suffix = if failed_at.is_some() {
            " <unreadable>".red().to_string()
        } else if !terminated {
            "...".bright_black().to_string()
        } else {
            String::new()
        };
        outln!(
            "{}  \"{}\"{}\n",
            ui::addr(start.0),
            text.escape_debug(),
            suffix
        );

        Ok(())
    }

    fn cmd_disasm(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        // WinDbg: `L<n>` counts instructions, an end address bounds bytes.
        const DEFAULT_INSTRUCTIONS: u64 = 8;
        let max_instruction_bytes = match self.ctx.target.arch() {
            Arch::Amd64 => 15u64,
            Arch::Arm64 => 4u64,
        };
        let (start_addr, byte_len, instruction_limit) = match invocation
            .arg(1)
            .and_then(windbg_count_expression)
        {
            Some(count_expr) => {
                let start_arg = require_arg!(invocation, 0, "u");
                let start = match Expr::eval_with_radix(start_arg, &self.ctx.target, self.radix) {
                    Ok(a) => a,
                    Err(e) => {
                        error!("{}", e);
                        return Ok(());
                    }
                };
                let count = match Expr::eval_with_radix(count_expr, &self.ctx.target, self.radix) {
                    Ok(c) if c.0 > 0 && c.0 <= MAX_DISASSEMBLY_INSTRUCTIONS as u64 => c.0,
                    Ok(_) => {
                        error!(
                            "instruction count must be 1..{}",
                            MAX_DISASSEMBLY_INSTRUCTIONS
                        );
                        return Ok(());
                    }
                    Err(e) => {
                        error!("{}", e);
                        return Ok(());
                    }
                };
                (start, count * max_instruction_bytes, Some(count as usize))
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
                    (range.start, range.len() as u64, None)
                }
                None => {
                    let start_arg = require_arg!(invocation, 0, "u");
                    match Expr::eval_with_radix(start_arg, &self.ctx.target, self.radix) {
                        Ok(a) => (
                            a,
                            DEFAULT_INSTRUCTIONS * max_instruction_bytes,
                            Some(DEFAULT_INSTRUCTIONS as usize),
                        ),
                        Err(e) => {
                            error!("{}", e);
                            return Ok(());
                        }
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
                outln!("{e}\n");
                return Ok(());
            }
        }

        let dtb = self.ctx.target.current_process()?.dtb();
        let trace = resolve_thread_trace_context(&self.ctx.target, dtb);
        let resolve = |target: u64| format_symbol(&self.ctx.target, &trace, target);

        let rows = match self.ctx.target.arch() {
            Arch::Amd64 => {
                let mut formatter = disasm_formatter();
                decode_rows(
                    &bytes,
                    start_addr.0,
                    instruction_limit,
                    &mut formatter,
                    resolve,
                )
            }
            Arch::Arm64 => decode_rows_arm64(&bytes, start_addr.0, instruction_limit, resolve),
        };
        render_rows(&rows, |_| None);
        outln!();

        Ok(())
    }

    fn cmd_ub(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let address_arg = require_arg!(invocation, 0, "ub");
        let address = match Expr::eval_with_radix(address_arg, &self.ctx.target, self.radix) {
            Ok(address) => address,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };
        let count = match invocation.arg(1) {
            Some(arg) => match eval_range_length(arg, &self.ctx.target, self.radix, address, 1) {
                Ok(count) if count > 0 && count <= MAX_DISASSEMBLY_INSTRUCTIONS => count,
                Ok(_) => {
                    error!(
                        "instruction count must be 1..{}: {}",
                        MAX_DISASSEMBLY_INSTRUCTIONS, arg
                    );
                    return Ok(());
                }
                Err(e) => {
                    error!("invalid instruction count '{}': {}", arg, e);
                    return Ok(());
                }
            },
            None => 8,
        };

        let max_instruction_bytes = match self.ctx.target.arch() {
            Arch::Amd64 => 15usize,
            Arch::Arm64 => 4usize,
        };
        let max_bytes = count.saturating_mul(max_instruction_bytes);
        let initial_start = VirtAddr(address.0.saturating_sub(max_bytes as u64));
        let range = AddressRange {
            start: initial_start,
            end: address,
        };
        let (data, valid) = self.read_virtual_best_effort(&range);
        let mut suffix_len = valid.iter().rev().take_while(|valid| **valid).count();
        if self.ctx.target.arch() == Arch::Arm64 {
            suffix_len -= suffix_len % 4;
        }
        let suffix_offset = data.len().saturating_sub(suffix_len);
        let read_start = initial_start + suffix_offset as u64;
        let bytes = data[suffix_offset..].to_vec();
        if bytes.is_empty() {
            error!("could not read memory before {}", ui::addr(address.0));
            return Ok(());
        }

        let dtb = self.ctx.target.current_process()?.dtb();
        let trace = resolve_thread_trace_context(&self.ctx.target, dtb);
        let resolve = |target: u64| format_symbol(&self.ctx.target, &trace, target);
        let rows = match self.ctx.target.arch() {
            Arch::Amd64 => {
                let mut first_candidate = None;
                let mut candidate_offset = None;
                for offset in 0..bytes.len() {
                    let start = read_start.0 + offset as u64;
                    let mut decoder =
                        Decoder::with_ip(64, &bytes[offset..], start, DecoderOptions::NONE);
                    let mut valid = true;
                    while decoder.can_decode() {
                        let instruction = decoder.decode();
                        valid &= instruction.code() != Code::INVALID;
                        let end = decoder.ip();
                        if end >= address.0 {
                            if end == address.0 {
                                first_candidate.get_or_insert(offset);
                                if valid {
                                    candidate_offset = Some(offset);
                                }
                            }
                            break;
                        }
                    }
                    if candidate_offset.is_some() {
                        break;
                    }
                }
                let Some(offset) = candidate_offset.or(first_candidate) else {
                    error!(
                        "could not decode instructions ending at {}",
                        ui::addr(address.0)
                    );
                    return Ok(());
                };
                let start = read_start.0 + offset as u64;
                let mut decoder =
                    Decoder::with_ip(64, &bytes[offset..], start, DecoderOptions::NONE);
                let mut instruction_starts = Vec::new();
                while decoder.can_decode() {
                    instruction_starts.push(decoder.ip());
                    let _ = decoder.decode();
                    if decoder.ip() >= address.0 {
                        break;
                    }
                }
                let Some(&tail_start) =
                    instruction_starts.get(instruction_starts.len().saturating_sub(count))
                else {
                    error!(
                        "could not decode instructions ending at {}",
                        ui::addr(address.0)
                    );
                    return Ok(());
                };
                let tail_offset = usize::try_from(tail_start - read_start.0).unwrap_or(offset);
                let mut formatter = disasm_formatter();
                decode_rows(
                    &bytes[tail_offset..],
                    tail_start,
                    Some(count),
                    &mut formatter,
                    resolve,
                )
            }
            Arch::Arm64 => {
                let tail_len = count.saturating_mul(4) as usize;
                let tail_offset = bytes.len().saturating_sub(tail_len);
                decode_rows_arm64(
                    &bytes[tail_offset..],
                    read_start.0 + tail_offset as u64,
                    Some(count),
                    resolve,
                )
            }
        };

        if rows.is_empty() {
            error!(
                "could not decode instructions ending at {}",
                ui::addr(address.0)
            );
            return Ok(());
        }
        let ends_at_address = rows.last().is_some_and(|row| match self.ctx.target.arch() {
            Arch::Amd64 => {
                let Ok(offset) = usize::try_from(row.ip.saturating_sub(read_start.0)) else {
                    return false;
                };
                let Some(bytes) = bytes.get(offset..) else {
                    return false;
                };
                let mut decoder = Decoder::with_ip(64, bytes, row.ip, DecoderOptions::NONE);
                if !decoder.can_decode() {
                    return false;
                }
                let instruction = decoder.decode();
                instruction.code() != Code::INVALID && decoder.ip() == address.0
            }
            Arch::Arm64 => row.ip.saturating_add(4) == address.0,
        });
        if !ends_at_address {
            error!(
                "could not decode instructions ending at {}",
                ui::addr(address.0)
            );
            return Ok(());
        }
        render_rows(&rows, |_| None);
        outln!();
        Ok(())
    }

    fn cmd_uf(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let expression = invocation.arg(0).unwrap_or("@rip");
        let address = match Expr::eval_with_radix(expression, &self.ctx.target, self.radix) {
            Ok(address) => address,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };

        let dtb = self.ctx.target.current_process()?.dtb();
        let trace = resolve_thread_trace_context(&self.ctx.target, dtb);
        let Some((start, end)) = function_range(&self.ctx.target, &trace, address.0) else {
            error!("no runtime-function entry contains {}", ui::addr(address.0));
            return Ok(());
        };
        let Some(len) = end
            .checked_sub(start)
            .and_then(|len| usize::try_from(len).ok())
        else {
            error!("invalid function range {start:#x}..{end:#x}");
            return Ok(());
        };
        const MAX_FUNCTION_BYTES: usize = 1024 * 1024;
        if len == 0 || len > MAX_FUNCTION_BYTES {
            error!("refusing invalid function size {len:#x} bytes");
            return Ok(());
        }

        let symbol = format_symbol(&self.ctx.target, &trace, start);
        outln!("{}  {} bytes", ui::symbol(&symbol), len);
        let mut bytes = vec![0u8; len];
        if let Err(e) = self.read_for_display(VirtAddr(start), &mut bytes) {
            outln!("{e}\n");
            return Ok(());
        }
        let resolve = |target: u64| format_symbol(&self.ctx.target, &trace, target);
        let rows = match self.ctx.target.arch() {
            Arch::Amd64 => {
                let mut formatter = disasm_formatter();
                decode_rows(&bytes, start, None, &mut formatter, resolve)
            }
            Arch::Arm64 => decode_rows_arm64(&bytes, start, None, resolve),
        };
        render_rows(&rows, |_| None);
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
        let address =
            match Expr::eval_with_radix(invocation.arg(0).unwrap(), &self.ctx.target, self.radix) {
                Ok(address) => address,
                Err(e) => {
                    error!("{}", e);
                    return Ok(());
                }
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
        let mem = self.ctx.target.current_process()?.memory();
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
        let length = eval_range_length(range_arg, &self.ctx.target, self.radix, start, item_size)?;
        let end = start
            .0
            .checked_add(u64::try_from(length).map_err(|_| Error::InvalidRange)?)
            .map(VirtAddr)
            .ok_or(Error::InvalidRange)?;
        Ok(AddressRange { start, end })
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
        let memory = self.ctx.target.current_process()?.memory();
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
        let value = match Expr::eval_with_radix(expression, &self.ctx.target, self.radix) {
            Ok(value) => value.0,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
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
        if invocation.argv.len() < 2 {
            outln!("{}\n", command_help("f"));
            return Ok(());
        }

        let address =
            match Expr::eval_with_radix(invocation.arg(0).unwrap(), &self.ctx.target, self.radix) {
                Ok(a) => a,
                Err(e) => {
                    error!("{}", e);
                    return Ok(());
                }
            };

        let pattern_str = invocation.arg(1).unwrap();
        let pattern = match parse_byte_pattern(pattern_str) {
            Some(pattern) => pattern,
            None => {
                error!("invalid pattern: {}", pattern_str);
                return Ok(());
            }
        };

        let length = match invocation.arg(2) {
            Some(length_arg) => {
                match eval_range_length(length_arg, &self.ctx.target, self.radix, address, 1) {
                    Ok(length) => length,
                    Err(e) => {
                        error!("invalid length or end '{}': {}", length_arg, e);
                        return Ok(());
                    }
                }
            }
            None => pattern.len(),
        };

        let data = repeat_pattern(&pattern, length);
        let mem = self.ctx.target.current_process()?.memory();

        if let Err(e) = mem.write_bytes(address, &data) {
            error!("failed to fill memory: {}", e);
        } else {
            outln!(
                "{} {:#x} bytes at {} with {}\n",
                "filled".green(),
                length,
                ui::addr(address.0),
                format!("[{}]", pattern_str).green()
            );
        }

        Ok(())
    }

    fn cmd_s(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if invocation.argv.len() < 2 {
            outln!("{}\n", command_help("s"));
            return Ok(());
        }

        let pattern_str = invocation.arg(1).unwrap();

        let start_addr =
            match Expr::eval_with_radix(invocation.arg(0).unwrap(), &self.ctx.target, self.radix) {
                Ok(a) => a,
                Err(e) => {
                    error!("{}", e);
                    return Ok(());
                }
            };

        let pattern = match parse_byte_pattern(pattern_str) {
            Some(pattern) => pattern,
            None => {
                error!("invalid pattern: {}", pattern_str);
                return Ok(());
            }
        };

        let length = match invocation.arg(2) {
            Some(length_arg) => {
                match Expr::eval_with_radix(length_arg, &self.ctx.target, self.radix) {
                    Ok(value) => match usize::try_from(value.0) {
                        Ok(length) => length,
                        Err(_) => {
                            error!("invalid length: {}", length_arg);
                            return Ok(());
                        }
                    },
                    Err(e) => {
                        error!("{}", e);
                        return Ok(());
                    }
                }
            }
            None => 0x100,
        };

        let hits = match self.ctx.target.search(start_addr, &pattern, length) {
            Ok(hits) => hits,
            Err(e) => {
                error!("failed to read memory: {}", e);
                return Ok(());
            }
        };
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
        self.ctx.target.set_results(hits, self.line.clone());
        outln!();

        Ok(())
    }
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

fn format_float<T>(value: T) -> String
where
    T: Copy + Display + std::fmt::LowerExp + Into<f64>,
{
    let magnitude = value.into().abs();
    if (1e-4..1e15).contains(&magnitude) {
        value.to_string()
    } else {
        format!("{value:e}")
    }
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
    use super::page_bounded_unit_read_len;
    use crate::types::VirtAddr;

    #[test]
    fn utf16_page_chunks_never_drop_an_unaligned_unit_byte() {
        assert_eq!(page_bounded_unit_read_len(VirtAddr(0xffd), 8, 2), 2);
        assert_eq!(page_bounded_unit_read_len(VirtAddr(0xfff), 7, 2), 2);
    }

    #[test]
    fn string_page_chunks_respect_unit_budget() {
        assert_eq!(page_bounded_unit_read_len(VirtAddr(0x100), 3, 2), 6);
        assert_eq!(page_bounded_unit_read_len(VirtAddr(0x100), 3, 1), 3);
        assert_eq!(page_bounded_unit_read_len(VirtAddr(0xffe), 1, 2), 2);
    }
}
