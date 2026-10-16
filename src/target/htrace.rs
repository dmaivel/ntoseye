//! Handle traces (`!htrace`): the stacks the kernel records in a process
//! handle table's `DebugInfo` (`_HANDLE_TRACE_DEBUG_INFO`) when handle
//! tracing is on. `TraceDb` is a ring of `TableSize` entries; the kernel
//! bumps `CurrentStackIndex` and then fills slot `CurrentStackIndex %
//! TableSize`, so the newest trace is there and older ones precede it.

use crate::error::{Error, Result};
use crate::guest::ProcessInfo;
use crate::target::Target;
use crate::types::VirtAddr;
use ntoseye_macros::record;

/// Traces a ring is read for at most, whatever its `TableSize` says.
const MAX_TRACE_SLOTS: u64 = 0x10000;

/// `HANDLE_TRACE_DB_*`: what a trace recorded.
pub fn handle_trace_kind_name(kind: u32) -> &'static str {
    match kind {
        1 => "OPEN",
        2 => "CLOSE",
        3 => "BAD REFERENCE",
        _ => "UNKNOWN",
    }
}

/// A return address on the stack of a handle trace.
#[record]
pub struct HandleTraceFrame {
    pub address: VirtAddr,
    /// The symbol of the address in the traced process. None if no symbol
    /// resolves.
    pub symbol: Option<String>,
}

/// One `_HANDLE_TRACE_DB_ENTRY`.
#[record(impl)]
pub struct HandleTrace {
    #[record(hex)]
    pub handle: u64,
    /// 1 open, 2 close, 3 bad reference.
    pub kind: u32,
    pub process_id: u64,
    pub thread_id: u64,
    /// Newest frame first.
    pub stack: Vec<HandleTraceFrame>,
}

#[record]
impl HandleTrace {
    /// `OPEN`, `CLOSE`, `BAD REFERENCE`, or `UNKNOWN`.
    #[record(getter)]
    pub fn kind_name(&self) -> &'static str {
        handle_trace_kind_name(self.kind)
    }
}

/// The handle traces of a process (`!htrace`).
#[record]
pub struct HandleTraces {
    /// The traced process.
    pub process: ProcessInfo,
    pub object_table: VirtAddr,
    /// The `_HANDLE_TRACE_DEBUG_INFO`. None if handle tracing is off.
    pub debug_info: Option<VirtAddr>,
    /// The capacity of the ring.
    pub table_size: u64,
    /// The total number of recorded traces (`CurrentStackIndex`), of which
    /// the ring keeps the last `table_size`.
    pub recorded: u64,
    /// The number of ring slots that ntoseye read.
    pub parsed: u64,
    /// The number of ring slots that ntoseye could not read.
    pub unreadable: u64,
    /// The matching traces, newest first.
    pub traces: Vec<HandleTrace>,
}

impl Target {
    /// The handle traces of `process`, newest first: those of `handle` when
    /// given, at most `max_traces` of them.
    pub fn handle_traces(
        &self,
        process: &ProcessInfo,
        handle: Option<u64>,
        max_traces: Option<usize>,
    ) -> Result<HandleTraces> {
        let types = self.guest()?.ntoskrnl.types_in(process.dtb);
        let object_table = types
            .struct_at("_EPROCESS", process.eprocess)?
            .read_pointer("ObjectTable")?;
        if object_table.is_zero() {
            return Err(Error::DebugInfo(format!(
                "{} (PID {}) has no handle table",
                process.name, process.pid
            )));
        }
        let debug_info = types
            .struct_at("_HANDLE_TABLE", object_table)?
            .read_pointer("DebugInfo")?;
        let mut detail = HandleTraces {
            process: process.clone(),
            object_table,
            debug_info: (!debug_info.is_zero()).then_some(debug_info),
            table_size: 0,
            recorded: 0,
            parsed: 0,
            traces: Vec::new(),
            unreadable: 0,
        };
        if debug_info.is_zero() {
            return Ok(detail);
        }
        let info = types.struct_at("_HANDLE_TRACE_DEBUG_INFO", debug_info)?;
        detail.table_size = info.read_uint("TableSize")?;
        detail.recorded = info.read_uint("CurrentStackIndex")?;
        if detail.table_size == 0 {
            return Ok(detail);
        }
        let db = debug_info + info.layout().field_offset("TraceDb")?;
        let entry_layout = types.layout("_HANDLE_TRACE_DB_ENTRY")?;
        let entry_size = entry_layout.size as u64;
        let max_traces = max_traces.unwrap_or(usize::MAX);
        let symbols = &self.symbols;
        let slots = detail.recorded.min(detail.table_size).min(MAX_TRACE_SLOTS);
        for back in 0..slots {
            if detail.traces.len() >= max_traces || self.interrupted() {
                break;
            }
            let slot = (detail.recorded - back) % detail.table_size;
            detail.parsed += 1;
            let entry = types
                .struct_with_layout(entry_layout.clone(), db + slot * entry_size)
                .prefetch();
            let read = || -> Result<Option<HandleTrace>> {
                let traced = entry.read_uint("Handle")?;
                if handle.is_some_and(|handle| handle != traced) {
                    return Ok(None);
                }
                let client = entry.embedded("ClientId")?;
                let stack = entry.read_field_bytes("StackTrace", 8 * 64)?;
                Ok(Some(HandleTrace {
                    handle: traced,
                    kind: entry.read_field("Type")?,
                    process_id: client.read_uint("UniqueProcess")?,
                    thread_id: client.read_uint("UniqueThread")?,
                    stack: stack
                        .as_chunks::<8>()
                        .0
                        .iter()
                        .map(|bytes| VirtAddr(u64::from_le_bytes(*bytes)))
                        .take_while(|address| !address.is_zero())
                        .map(|address| {
                            let symbol =
                                symbols.format_closest_symbol_for_address(process.dtb, address);
                            HandleTraceFrame { address, symbol }
                        })
                        .collect(),
                }))
            };
            match read() {
                Ok(Some(trace)) => detail.traces.push(trace),
                Ok(None) => {}
                Err(_) => detail.unreadable += 1,
            }
        }
        Ok(detail)
    }
}
