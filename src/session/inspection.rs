//! Reading the halted guest: breakpoint-masked memory, disassembly,
//! backtraces, exception/context records, and debugger-worker page-in.

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use crate::backend::MemoryOps;
use crate::bytes;
use crate::disasm::{
    DisasmRow, decode_preceding, decode_rows, decode_rows_arm64, disasm_formatter,
    max_instruction_bytes,
};
use crate::error::{Error, Result};
use crate::kd::{context, context_arm64};
use crate::memory::{PAGE_SIZE, read_page_chunks};
use crate::session::{ContinueOutcome, ExceptionRecord, PageInReport, Session, TerminatedRead};
use crate::target::ThreadInfo;
use crate::types::{Arch, Dtb, VirtAddr};
use crate::unwind::{
    RecoveredStackTrace, StackTrace, ThreadStackTrace, build_parked_thread_recovered_stack,
    build_parked_thread_stack, build_stacktrace_with_context, format_symbol, function_range,
    resolve_thread_trace_context,
};

/// `DBG_STATUS_WORKER`, the status the kernel's debugger worker passes to
/// `DbgBreakPointWithStatus` when it has finished a [`Session::page_in`].
pub(super) const DBG_STATUS_WORKER: u64 = 7;

/// How long [`Session::page_in`] lets the target run before giving up on the
/// worker. The work is a DPC and a work item behind one resume; a second is
/// already generous, and the guest may be busy.
const PAGE_IN_TIMEOUT: Duration = Duration::from_secs(10);

impl Session {
    /// Read `buf` at `address` in the current inspection space, falling back
    /// to the kernel's: a record a trap or bugcheck saved lives in either.
    /// The error is the current space's.
    fn read_record_bytes(&self, address: VirtAddr, buf: &mut [u8]) -> Result<()> {
        let current = self.target.context_memory().read_bytes(address, buf);
        if current.is_err()
            && self
                .target
                .kernel_address_space()
                .read_bytes(address, buf)
                .is_ok()
        {
            return Ok(());
        }
        current
    }

    /// Decode an `EXCEPTION_RECORD64` at `address` (`.exr`).
    pub fn read_exception_record(&self, address: VirtAddr) -> Result<ExceptionRecord> {
        const SIZE: usize = 0x98;
        let mut record = [0u8; SIZE];
        self.read_record_bytes(address, &mut record)?;
        let read_u32 = |offset| bytes::read_u32(&record, offset);
        let read_u64 = |offset| bytes::read_u64(&record, offset);
        let count = (read_u32(24) as usize).min(15);
        let parameters = (0..count).map(|index| read_u64(32 + index * 8)).collect();
        Ok(ExceptionRecord {
            code: read_u32(0),
            flags: read_u32(4),
            nested: read_u64(8),
            address: read_u64(16),
            parameters,
        })
    }

    /// Decode the `CONTEXT` record at `address` into a register map, without
    /// changing the selected backend context (`.cxr`).
    pub fn read_context_record(&self, address: VirtAddr) -> Result<HashMap<String, u64>> {
        let (size, map) = match self.target.arch() {
            Arch::Amd64 => (context::CONTEXT_SIZE, context::build_register_map()),
            Arch::Arm64 => (
                context_arm64::CONTEXT_SIZE,
                context_arm64::build_register_map(),
            ),
        };
        let mut bytes = vec![0u8; size];
        self.read_record_bytes(address, &mut bytes)?;
        Ok(map.to_hashmap(&bytes))
    }

    /// The current `.exr -1` view, when the last event contains exception
    /// metadata or the attached dump carries a saved exception record.
    pub fn current_exception_record(&self) -> Option<ExceptionRecord> {
        if let Some(event) = &self.last_event {
            let stop = &event.stop;
            let code = stop
                .exception_code
                .or_else(|| stop.bugcheck.as_ref().map(|info| info.code))?;
            return Some(ExceptionRecord {
                code,
                flags: 0,
                nested: 0,
                address: stop.exception_address.or(stop.program_counter).unwrap_or(0),
                parameters: Vec::new(),
            });
        }
        let exception = self.target.phys.dmp_info()?.exception.as_ref()?;
        Some(ExceptionRecord {
            code: exception.code,
            flags: exception.flags,
            nested: 0,
            address: exception.address,
            parameters: exception.parameters.clone(),
        })
    }

    /// Read guest virtual memory in the inspection address space
    /// ([`Target::current_dtb`](crate::target::Target::current_dtb)) with our
    /// own breakpoint patch bytes masked back to the original code, so every
    /// host (REPL, MCP, SDK) sees the same bytes the guest would run.
    pub fn read_masked(&self, addr: VirtAddr, buf: &mut [u8]) -> Result<()> {
        self.read_masked_in(self.target.current_dtb(), addr, buf)
    }

    /// [`Self::read_masked`] in the address space `dtb` rather than the
    /// inspection one, for values that belong to a particular stack frame.
    pub fn read_masked_in(&self, dtb: Dtb, addr: VirtAddr, buf: &mut [u8]) -> Result<()> {
        self.target.address_space(dtb).read_bytes(addr, buf)?;
        self.breakpoints
            .mask_breakpoint_bytes(&self.target, addr, buf, dtb);
        self.mask_bugcheck_trap(addr, buf);
        Ok(())
    }

    /// Read up to `max_units` NUL-terminated 1- or 2-byte units. The returned
    /// bytes exclude the terminator; a later unreadable page is reported with
    /// the readable prefix, while a failure at the start remains an error.
    pub fn read_terminated(
        &mut self,
        addr: VirtAddr,
        max_units: usize,
        unit: usize,
    ) -> Result<TerminatedRead> {
        if !matches!(unit, 1 | 2) {
            return Err(Error::InvalidArgument(
                "string unit size must be 1 or 2 bytes".to_string(),
            ));
        }
        let max_bytes = max_units
            .checked_mul(unit)
            .ok_or_else(|| Error::InvalidArgument("string length overflows".to_string()))?;
        let mut bytes = Vec::with_capacity(max_bytes.min(PAGE_SIZE));
        let mut unreadable = false;
        while bytes.len() < max_bytes {
            let offset = u64::try_from(bytes.len())
                .map_err(|_| Error::InvalidArgument("string address overflows".to_string()))?;
            let current = addr
                .0
                .checked_add(offset)
                .ok_or_else(|| Error::InvalidArgument("string address overflows".to_string()))?;
            let page_remaining = PAGE_SIZE - VirtAddr(current).page_offset() as usize;
            let chunk_len = page_remaining.min(max_bytes - bytes.len());
            let mut page = [0u8; PAGE_SIZE];
            if let Err(error) = self.read_masked(VirtAddr(current), &mut page[..chunk_len]) {
                if matches!(&error, Error::TargetRunning(_)) {
                    return Err(error);
                }
                if bytes.is_empty() {
                    return Err(error);
                }
                unreadable = true;
                break;
            }

            let first_new_unit = bytes.len() / unit;
            bytes.extend_from_slice(&page[..chunk_len]);
            let complete_units = bytes.len() / unit;
            if let Some(index) = (first_new_unit..complete_units).find(|&index| {
                let start = index * unit;
                bytes[start..start + unit].iter().all(|byte| *byte == 0)
            }) {
                bytes.truncate(index * unit);
                return Ok(TerminatedRead {
                    bytes,
                    unreadable: false,
                });
            }
        }
        bytes.truncate(bytes.len() - bytes.len() % unit);
        Ok(TerminatedRead { bytes, unreadable })
    }

    /// Read as much of `buf` as the guest will give with [`Self::read_masked`],
    /// one page-sized chunk at a time, returning how many leading bytes are
    /// valid. Chunks are relative to `addr`, so an unmapped page truncates the
    /// read at the request's own granularity rather than at a page boundary.
    pub fn read_masked_partial(&self, addr: VirtAddr, buf: &mut [u8]) -> usize {
        if self.read_masked(addr, buf).is_ok() {
            return buf.len();
        }
        const CHUNK: usize = 0x1000;
        let mut read = 0;
        while read < buf.len() {
            let end = (read + CHUNK).min(buf.len());
            let chunk_address = VirtAddr(addr.0.wrapping_add(read as u64));
            if self
                .read_masked(chunk_address, &mut buf[read..end])
                .is_err()
            {
                break;
            }
            read = end;
        }
        read
    }

    /// Disassemble `count` instructions starting at `addr` in the current
    /// address space. Our own breakpoint `int3` bytes are masked back to the
    /// original opcode, and branch / rip-relative targets get symbol comments.
    pub fn disassemble(&self, addr: VirtAddr, count: usize) -> Result<Vec<DisasmRow>> {
        let dtb = self.target.current_dtb();

        // x86-64 instructions are at most 15 bytes; ARM64 is fixed 4 bytes.
        // Over-read so `count` decode.
        let overread = match self.target.arch() {
            Arch::Amd64 => count * 16,
            Arch::Arm64 => count * 4,
        };
        let mut buf = vec![0u8; overread];
        self.read_masked(addr, &mut buf)?;

        let symbols = &self.target.symbols;
        let resolve = |target: u64| {
            symbols
                .format_closest_symbol_for_address(dtb, VirtAddr(target))
                .unwrap_or_default()
        };
        let bitness = self.target.code_bitness(addr);
        match self.target.arch() {
            Arch::Amd64 => {
                let mut formatter = disasm_formatter();
                Ok(decode_rows(
                    &buf,
                    addr.0,
                    Some(count),
                    bitness,
                    &mut formatter,
                    resolve,
                ))
            }
            Arch::Arm64 => Ok(decode_rows_arm64(&buf, addr.0, Some(count), resolve)),
        }
    }

    /// Disassemble the runtime function containing `addr`. Returns its start
    /// symbol, byte length, and decoded rows.
    pub fn disassemble_function(&self, addr: VirtAddr) -> Result<(String, usize, Vec<DisasmRow>)> {
        let dtb = self.target.current_dtb();
        let trace = resolve_thread_trace_context(&self.target, dtb);
        let Some((start, end)) = function_range(&self.target, &trace, addr.0) else {
            return Err(Error::DebugInfo(format!(
                "no runtime-function entry contains {:#x}",
                addr.0
            )));
        };
        let len = end
            .checked_sub(start)
            .and_then(|length| usize::try_from(length).ok())
            .ok_or_else(|| {
                Error::DebugInfo(format!("invalid function range {start:#x}..{end:#x}"))
            })?;
        const MAX_FUNCTION_BYTES: usize = 1024 * 1024;
        if len == 0 || len > MAX_FUNCTION_BYTES {
            return Err(Error::DebugInfo(format!(
                "refusing invalid function size {len:#x} bytes"
            )));
        }

        let mut bytes = vec![0u8; len];
        self.read_masked(VirtAddr(start), &mut bytes)?;
        let resolve = |target| format_symbol(&self.target, &trace, target);
        let bitness = self.target.code_bitness(VirtAddr(start));
        let rows = match self.target.arch() {
            Arch::Amd64 => {
                let mut formatter = disasm_formatter();
                decode_rows(&bytes, start, None, bitness, &mut formatter, resolve)
            }
            Arch::Arm64 => decode_rows_arm64(&bytes, start, None, resolve),
        };
        Ok((format_symbol(&self.target, &trace, start), len, rows))
    }

    /// Disassemble the instructions ending at `addr`. Missing pages before
    /// the readable suffix are skipped.
    pub fn disassemble_back(&self, addr: VirtAddr, count: usize) -> Result<Vec<DisasmRow>> {
        if count == 0 {
            return Err(Error::InvalidArgument(
                "instruction count must be greater than zero".to_string(),
            ));
        }
        let arch = self.target.arch();
        let max_bytes = count.saturating_mul(max_instruction_bytes(arch));
        let start = VirtAddr(addr.0.saturating_sub(max_bytes as u64));
        let length = usize::try_from(addr.0 - start.0).unwrap_or(max_bytes);
        let (data, valid) =
            read_page_chunks(start, length, |address, buf| self.read_masked(address, buf))?;
        let readable_suffix_start = valid
            .iter()
            .rposition(|readable| !readable)
            .map_or(0, |last_unreadable| last_unreadable + 1);
        let mut suffix_len = length - readable_suffix_start;
        if arch == Arch::Arm64 {
            suffix_len -= suffix_len % 4;
        }
        let suffix_offset = length.saturating_sub(suffix_len);
        let read_start = start.0 + suffix_offset as u64;
        let bytes = &data[suffix_offset..];
        if bytes.is_empty() {
            return Err(Error::DebugInfo(format!(
                "could not read memory before {:#x}",
                addr.0
            )));
        }

        let dtb = self.target.current_dtb();
        let trace = resolve_thread_trace_context(&self.target, dtb);
        let bitness = self.target.code_bitness(addr);
        decode_preceding(arch, bytes, read_start, addr.0, count, bitness, |target| {
            format_symbol(&self.target, &trace, target)
        })
        .ok_or_else(|| {
            Error::DebugInfo(format!(
                "could not decode instructions ending at {:#x}",
                addr.0
            ))
        })
    }

    /// The current backend context's call stack with the sparse registers
    /// recovered for every frame, plus the seed register file the walk started
    /// from. A parked Windows thread is walked from its saved context without
    /// touching the backend vCPU.
    pub fn recovered_backtrace(
        &mut self,
        limit: usize,
    ) -> Result<(RecoveredStackTrace, HashMap<String, u64>)> {
        if let Some(thread) = self.parked_windows_thread() {
            let recovered = build_parked_thread_recovered_stack(&self.target, thread, limit)?;
            // The walk's own first frame is the only register context a parked
            // thread has; there is no live file to seed from.
            let seed = recovered
                .stacktrace
                .frames
                .first()
                .map(|frame| frame.registers.clone())
                .unwrap_or_default();
            return Ok((recovered.stacktrace, seed));
        }

        let registers = self.read_registers()?;
        let seed = self.register_map.to_hashmap(&registers);
        let recovered =
            build_stacktrace_with_context(&self.target, &self.register_map, &registers, limit);
        Ok((recovered, seed))
    }

    /// Walk the currently selected backend context's call stack, returning up to
    /// `limit` frames. A parked Windows thread uses stack-only recovery without
    /// touching the backend vCPU.
    pub fn backtrace(&mut self, limit: usize) -> Result<StackTrace> {
        let (recovered, _) = self.recovered_backtrace(limit)?;
        Ok(StackTrace {
            frames: recovered
                .frames
                .into_iter()
                .map(|frame| frame.frame)
                .collect(),
            truncated: recovered.truncated,
        })
    }

    /// Unwind a specified non-running Windows thread in its owning process
    /// address space without selecting it or mutating the backend vCPU.
    pub fn backtrace_thread(&self, thread: &ThreadInfo, limit: usize) -> Result<ThreadStackTrace> {
        build_parked_thread_stack(&self.target, thread, limit)
    }

    /// Ask the guest's own debugger worker to fault a page in, and wait for it
    /// to report back.
    ///
    /// The kernel exposes this as three globals plus a flag. `KdExitDebugger`
    /// runs on our own resume and calls `ExQueueDebuggerWorker`, which
    /// compare-exchanges `ExpDebuggerWork` from 1 to 2 and queues a DPC; the
    /// resulting work item runs `ExpDebuggerWorker`, which attaches to
    /// `ExpDebuggerProcessAttach`, calls `MmPrefetchVirtualMemory` on
    /// `ExpDebuggerPageIn`, and breaks in with `DbgBreakPointWithStatus(7)`
    /// (`DBG_STATUS_WORKER`).
    ///
    /// Two consequences the caller cannot be shielded from: the target has to
    /// **run** for the worker thread to be scheduled, and it comes back halted
    /// at the worker rather than wherever it was. The worker zeroes all three
    /// globals before doing any of the work, so an abandoned request leaves
    /// nothing armed.
    pub fn page_in(&mut self, address: VirtAddr, process: Option<u64>) -> Result<PageInReport> {
        let worker_break = self.page_in_globals(address, process)?;
        // The worker signals completion at the same address KD break-ins land
        // on, which the transport would otherwise dismiss as its own noise.
        self.backend.surface_next_break_at(Some(worker_break.0));
        self.resume()?;
        let cancel = AtomicBool::new(false);
        let outcome = self.wait_for_stop_bounded(Some(PAGE_IN_TIMEOUT), &cancel);
        self.backend.surface_next_break_at(None);
        match outcome? {
            ContinueOutcome::Running => Err(Error::DebugInfo(format!(
                "the debugger worker did not report within {}s; the target is still running",
                PAGE_IN_TIMEOUT.as_secs()
            ))),
            _ => Ok(self.page_in_result(address, worker_break)),
        }
    }

    /// Arm the worker request. Every global is kernel data, so a mediated
    /// virtual write reaches it under any process context.
    fn page_in_globals(&mut self, address: VirtAddr, process: Option<u64>) -> Result<VirtAddr> {
        let dtb = self.target.kernel_dtb();
        let symbol = |name: &str| -> Result<VirtAddr> {
            self.target
                .symbols
                .find_symbol_with_module(dtb, name)?
                .map(|(address, _)| address)
                .ok_or_else(|| {
                    Error::DebugInfo(format!(
                        "{name} is not in the kernel's symbols; .pagein needs ntoskrnl symbols"
                    ))
                })
        };
        let attach_global = symbol("nt!ExpDebuggerProcessAttach")?;
        let page_in_global = symbol("nt!ExpDebuggerPageIn")?;
        let work_global = symbol("nt!ExpDebuggerWork")?;
        let worker_break = symbol("nt!DbgBreakPointWithStatus")?;

        let memory = self.target.kernel_address_space();
        memory.write_bytes(attach_global, &process.unwrap_or(0).to_le_bytes())?;
        memory.write_bytes(page_in_global, &address.0.to_le_bytes())?;
        // Exactly 1: `ExQueueDebuggerWorker` compare-exchanges 1 to 2, so any
        // other non-zero value is ignored and the worker never runs.
        memory.write_bytes(work_global, &1u32.to_le_bytes())?;
        Ok(worker_break)
    }

    /// Classify the stop the wait produced and probe the requested page.
    pub(super) fn page_in_result(
        &mut self,
        address: VirtAddr,
        worker_break: VirtAddr,
    ) -> PageInReport {
        let registers = self.backend.read_registers().ok();
        let pc = registers
            .as_ref()
            .and_then(|regs| self.register_map.read_u64("rip", regs).ok());
        let first_argument = match self.target.arch() {
            Arch::Amd64 => "rcx",
            Arch::Arm64 => "x0",
        };
        let status = registers
            .as_ref()
            .and_then(|regs| self.register_map.read_u64(first_argument, regs).ok());
        // `DbgBreakPointWithStatus` takes its status in the first argument
        // register, so a worker break is distinguishable from any other
        // hard-coded break at the same address.
        let from_worker = pc == Some(worker_break.0) && status == Some(DBG_STATUS_WORKER);
        let mut probe = [0u8; 1];
        let resident = self
            .target
            .address_space(self.target.current_dtb())
            .read_bytes(address, &mut probe)
            .is_ok();
        PageInReport {
            from_worker,
            resident,
        }
    }
}
