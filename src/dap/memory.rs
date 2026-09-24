//! The memory and disassembly views: `readMemory`, `writeMemory`, and
//! `disassemble`.

use std::result;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde_json::{Value, json};

use crate::backend::MemoryOps;
use crate::disasm::{decode_preceding, max_instruction_bytes};
use crate::error::Error;
use crate::types::VirtAddr;

use super::{Handled, Server, arg_bool, arg_i64, arg_str, parse_address, source_value};

/// Largest single `readMemory` response, before the client's own chunking.
const MAX_READ_MEMORY: usize = 1024 * 1024;

/// Bound client-controlled disassembly buffers, matching console `u`.
pub(super) const MAX_DISASSEMBLE_INSTRUCTIONS: usize = 4096;

impl Server {
    pub(super) fn on_read_memory(&mut self, args: &Value) -> Handled {
        let reference = arg_str(args, "memoryReference")
            .ok_or_else(|| "missing memoryReference".to_string())?;
        let base = parse_address(&reference)?;
        let offset = arg_i64(args, "offset").unwrap_or(0);
        let address = base.wrapping_add_signed(offset);
        let count = arg_i64(args, "count").unwrap_or(0).max(0) as usize;
        let count = count.min(MAX_READ_MEMORY);
        if count == 0 {
            return Ok(Some(
                json!({"address": format!("{address:#x}"), "data": ""}),
            ));
        }

        let session = self.session()?;
        let mut buffer = vec![0u8; count];
        let read = session.read_masked_partial(VirtAddr(address), &mut buffer);
        buffer.truncate(read);
        let mut body = json!({
            "address": format!("{address:#x}"),
            "data": BASE64.encode(&buffer),
        });
        if read < count {
            body["unreadableBytes"] = json!((count - read) as i64);
        }
        Ok(Some(body))
    }

    pub(super) fn on_write_memory(&mut self, args: &Value) -> Handled {
        let reference = arg_str(args, "memoryReference")
            .ok_or_else(|| "missing memoryReference".to_string())?;
        let base = parse_address(&reference)?;
        let offset = arg_i64(args, "offset").unwrap_or(0);
        let address = base.wrapping_add_signed(offset);
        let data = arg_str(args, "data").ok_or_else(|| "missing data".to_string())?;
        let bytes = BASE64
            .decode(data.as_bytes())
            .map_err(|error| format!("invalid base64 payload: {error}"))?;
        if bytes.is_empty() {
            return Ok(Some(json!({"bytesWritten": 0})));
        }
        let allow_partial = arg_bool(args, "allowPartial").unwrap_or(false);
        let session = self.session()?;
        let written = session
            .target
            .context_memory()
            .write_bytes(VirtAddr(address), &bytes);
        let written = match written {
            Ok(()) => bytes.len(),
            // The write ran into an untranslatable page after committing a
            // prefix. The client decides whether that prefix stands.
            Err(Error::PartialWrite(committed)) if allow_partial => committed,
            Err(error) => return Err(error.to_string()),
        };
        Ok(Some(json!({"bytesWritten": written as i64})))
    }

    pub(super) fn on_disassemble(&mut self, args: &Value) -> Handled {
        let reference = arg_str(args, "memoryReference")
            .ok_or_else(|| "missing memoryReference".to_string())?;
        let base = parse_address(&reference)?;
        let offset = arg_i64(args, "offset").unwrap_or(0);
        let address = base.wrapping_add_signed(offset);
        let instruction_offset = arg_i64(args, "instructionOffset").unwrap_or(0);
        let count = (arg_i64(args, "instructionCount").unwrap_or(0).max(0) as usize)
            .min(MAX_DISASSEMBLE_INSTRUCTIONS);
        if count == 0 {
            return Ok(Some(json!({"instructions": []})));
        }

        // Row `i` is instruction `instructionOffset + i` from the reference.
        // A client records the reference's address positionally and derives
        // instruction-breakpoint offsets from it, so a hole is an invalid
        // row, never a shifted one.
        let mut rows: Vec<Option<DisassembledRow>> = Vec::with_capacity(count);
        // Negative offsets ask for the instructions *before* the reference, so
        // decode backwards into the gap first; a short decode leaves its hole
        // at the far end.
        let backwards = usize::try_from(instruction_offset.min(0).saturating_neg())
            .unwrap_or(0)
            .min(MAX_DISASSEMBLE_INSTRUCTIONS);
        if backwards > 0 {
            let preceding = self.disassemble_preceding(address, backwards)?;
            rows.resize_with(backwards.saturating_sub(preceding.len()), || None);
            rows.extend(preceding.into_iter().map(Some));
        }
        let forward_start = if instruction_offset > 0 {
            // Skip forward by decoding and dropping instructions.
            let skip = (instruction_offset as usize).min(MAX_DISASSEMBLE_INSTRUCTIONS);
            let session = self.session()?;
            match session.disassemble(VirtAddr(address), skip + 1) {
                Ok(decoded) => decoded.get(skip).map(|row| row.ip).unwrap_or(address),
                Err(_) => address,
            }
        } else {
            address
        };
        let remaining = count.saturating_sub(rows.len());
        if remaining > 0 {
            let session = self.session()?;
            match session.disassemble(VirtAddr(forward_start), remaining) {
                Ok(decoded) => rows.extend(decoded.into_iter().map(|row| {
                    Some(DisassembledRow {
                        address: row.ip,
                        bytes: Some(row.hex.clone()),
                        text: row.asm(),
                    })
                })),
                Err(error) => rows.push(Some(DisassembledRow {
                    address: forward_start,
                    bytes: None,
                    text: format!("<{error}>"),
                })),
            }
        }

        // The protocol requires exactly `instructionCount` entries.
        rows.resize_with(count, || None);
        let instructions = self.disassembly_values(rows);
        Ok(Some(json!({"instructions": instructions})))
    }

    fn disassemble_preceding(
        &mut self,
        address: u64,
        count: usize,
    ) -> result::Result<Vec<DisassembledRow>, String> {
        let session = self.session()?;
        let arch = session.target.arch();
        let bitness = session.target.code_bitness(VirtAddr(address));
        let window = count.saturating_mul(max_instruction_bytes(arch));
        let start = address.saturating_sub(window as u64);
        let mut bytes = vec![0u8; (address - start) as usize];
        if bytes.is_empty() || session.read_masked(VirtAddr(start), &mut bytes).is_err() {
            return Ok(Vec::new());
        }
        let rows = decode_preceding(arch, &bytes, start, address, count, bitness, |target| {
            format!("{target:#x}")
        });
        Ok(rows
            .unwrap_or_default()
            .into_iter()
            .map(|row| DisassembledRow {
                address: row.ip,
                bytes: Some(row.hex.clone()),
                text: row.asm(),
            })
            .collect())
    }

    /// A `None` row is the invalid-instruction value. Its address is `-1`,
    /// which no instruction has, so a client keying rows by address (VS Code
    /// sorts and merges on it) drops it rather than filing it under 0.
    fn disassembly_values(&mut self, rows: Vec<Option<DisassembledRow>>) -> Vec<Value> {
        let mut instructions = Vec::with_capacity(rows.len());
        for row in rows {
            let Some(row) = row else {
                instructions.push(json!({
                    "address": "-1",
                    "instruction": "(unreadable)",
                    "presentationHint": "invalid",
                }));
                continue;
            };
            let symbol = self.session.as_ref().and_then(|session| {
                session
                    .target
                    .closest_symbol_current_context(VirtAddr(row.address))
            });
            let location = self
                .session
                .as_ref()
                .and_then(|session| session.target.source_location(VirtAddr(row.address)));
            let mut value = json!({
                "address": format!("{:#x}", row.address),
                "instruction": row.text,
            });
            if let Some(bytes) = row.bytes {
                value["instructionBytes"] = json!(bytes);
            }
            if let Some(symbol) = symbol {
                value["symbol"] = json!(symbol);
            }
            if let Some(location) = &location {
                value["location"] = source_value(location);
                value["line"] = json!(self.to_client_line(location.line as i64));
            }
            instructions.push(value);
        }
        instructions
    }
}

/// A decoded instruction on its way to a `disassemble` response.
struct DisassembledRow {
    address: u64,
    bytes: Option<String>,
    text: String,
}
