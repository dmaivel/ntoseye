//! Reading the halted guest: breakpoint-masked memory, disassembly,
//! backtraces, exception/context records, version metadata, and
//! debugger-worker page-in.

use std::collections::HashMap;
use std::time::Duration;

use crate::backend::dbg_backend::{ContinueDisposition, processor_index_from_backend_thread_id};
use crate::base::bytes;
use crate::base::disasm::{
    DisasmRow, FunctionDisassembly, decode_code, decode_preceding, function_extent,
    instruction_containing,
};
use crate::base::error::{Error, Result};
use crate::base::memory::{
    self, MemoryOps, PAGE_SIZE, ScanFault, TerminatedRead, read_page_chunks,
};
use crate::base::types::{CodeMachine, Dtb, VirtAddr};
use crate::nt::bugchecks::{
    BugcheckAnalysis, analyze_bugcheck, bugcheck_from_dump_info, current_bugcheck,
};
use crate::nt::guest::hypervisor::{HvPartition, HvVirtualProcessor, processor_guest_vp};
use crate::nt::target::meta::TargetVersion;
use crate::nt::target::usermode::ImageCheck;
use crate::nt::target::{CompareResult, SearchResult, SelectedFrame, ThreadInfo, exit_registers};
use crate::nt::unwind::{
    FunctionEntry, RecoveredStackTrace, StackTrace, ThreadStackSource, ThreadStackTrace,
    ThreadTraceContext, build_parked_thread_recovered_stack, build_parked_thread_stack,
    build_stacktrace_with_register_values, build_thread_stacktrace, format_symbol, function_entry,
    function_range, guest_vp_running, halted_in_windows_hypervisor, resolve_thread_trace_context,
    saved_vtls,
};
use crate::session::context::windows_thread_on_backend_thread;
use crate::session::{
    Cancel, ExceptionRecord, InstructionBoundary, Motion, PageInReport, RunOutcome, Session,
    VpRegisters,
};

/// `DBG_STATUS_WORKER`, the status the kernel's debugger worker passes to
/// `DbgBreakPointWithStatus` when it has finished a [`Session::page_in`].
pub(super) const DBG_STATUS_WORKER: u64 = 7;

/// How long [`Session::page_in`] lets the target run before giving up on the
/// worker. The work is a DPC and a work item behind one resume; a second is
/// already generous, and the guest may be busy.
const PAGE_IN_TIMEOUT: Duration = Duration::from_secs(10);

/// The farthest before an address the code around it may start for
/// [`Session::instruction_boundary`] to decode up to the address.
const MAX_BOUNDARY_SCAN: u64 = 1 << 20;

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
            record_address: Some(address.0),
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
        let arch = self.target.arch();
        let mut bytes = vec![0u8; arch.context_size()];
        self.read_record_bytes(address, &mut bytes)?;
        Ok(arch.register_map().to_hashmap(&bytes))
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
                record_address: None,
                code,
                flags: 0,
                nested: 0,
                address: stop.exception_address.or(stop.program_counter).unwrap_or(0),
                parameters: Vec::new(),
            });
        }
        if let Some(exception) = self.target.user_exception() {
            return Some(ExceptionRecord {
                record_address: None,
                code: exception.code,
                flags: exception.flags,
                nested: exception.record,
                address: exception.address,
                parameters: exception.parameters.clone(),
            });
        }
        let exception = self.target.phys.dmp_info()?.exception.as_ref()?;
        Some(ExceptionRecord {
            record_address: None,
            code: exception.code,
            flags: exception.flags,
            nested: 0,
            address: exception.address,
            parameters: exception.parameters.clone(),
        })
    }

    /// `.ecxr` on a user-mode minidump: switch to the thread the exception
    /// was raised on and select the exception's CONTEXT, which the dump
    /// stores beside the record. Returns the selection and the thread's id.
    pub fn select_user_exception_context(&mut self) -> Result<(SelectedFrame, String)> {
        let info = self
            .target
            .user_dump_info()
            .ok_or_else(|| Error::DebugInfo("this target is not a user-mode minidump".into()))?;
        let exception = info
            .exception
            .as_ref()
            .ok_or_else(|| Error::DebugInfo("the minidump records no exception".into()))?;
        let thread = info.backend_thread_id(exception.thread_id);
        let registers = self.target.user_exception_registers()?;
        if self.current_thread != thread {
            self.set_current_thread(&thread)?;
        }
        let selected = SelectedFrame::from_registers(self.target.arch(), 0, registers);
        self.select_frame(selected.clone());
        Ok((selected, thread))
    }

    /// Search the inspection address space for `pattern`
    /// ([`Target::search`](crate::nt::target::Target::search)) as
    /// [`Target::read_masked`](crate::nt::target::Target::read_masked) reads
    /// it, so a breakpoint this session planted neither hides the original
    /// bytes nor matches as an `int3`.
    pub fn search(&self, start: VirtAddr, pattern: &[u8], length: usize) -> Result<SearchResult> {
        self.target.search(start, pattern, length, |address, buf| {
            self.target.read_masked(address, buf)
        })
    }

    /// Compare two ranges of the inspection address space
    /// ([`Target::compare`](crate::nt::target::Target::compare)) as
    /// [`Target::read_masked`](crate::nt::target::Target::read_masked) reads
    /// them, so a breakpoint this session planted is compared as the byte it
    /// displaced.
    pub fn compare(
        &self,
        first: VirtAddr,
        second: VirtAddr,
        length: usize,
    ) -> Result<CompareResult> {
        self.target.compare(first, second, length, |address, buf| {
            self.target.read_masked(address, buf)
        })
    }

    /// Compare `module`'s executable sections against its cached image
    /// (`!chkimg`), with this session's own breakpoints (and the bugcheck
    /// trap) masked back to the code they replaced. The code is what the
    /// target holds, never the image file a dump's hole would be read from
    /// for display, which would compare the file with itself.
    pub fn check_image(&self, module: &str, include_diffs: bool) -> Result<ImageCheck> {
        let dtb = self.target.process_dtb();
        self.target
            .check_image(module, include_diffs, &|address, buf| {
                self.target.read_masked_held(dtb, address, buf)
            })
    }

    /// Read up to `max_units` NUL-terminated 1- or 2-byte units. The returned
    /// bytes exclude the terminator; a later unreadable page is reported with
    /// the readable prefix, while a failure at the start, a running target
    /// and a string past the top of the address space remain errors.
    pub fn read_terminated(
        &self,
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
        memory::read_terminated(addr, max_bytes, unit, |at, buf| {
            // A wrapped address is a string past the top of the address space.
            if at < addr {
                return Err(ScanFault::Fatal(Error::InvalidArgument(
                    "string address overflows".to_string(),
                )));
            }
            self.target
                .read_masked(at, buf)
                .map_err(|error| match error {
                    Error::TargetRunning(_) => ScanFault::Fatal(error),
                    error => ScanFault::Unreadable(error),
                })
        })
    }

    /// Read as much of `buf` as the guest will give with
    /// [`Target::read_masked`](crate::nt::target::Target::read_masked), one
    /// page at a time, returning how many leading bytes are valid: the read
    /// stops at the first unreadable page.
    pub fn read_masked_partial(&self, addr: VirtAddr, buf: &mut [u8]) -> usize {
        if self.target.read_masked(addr, buf).is_ok() {
            return buf.len();
        }
        let mut read = 0;
        while read < buf.len() {
            let chunk_address = VirtAddr(addr.0.wrapping_add(read as u64));
            let end = (read + PAGE_SIZE - chunk_address.page_offset() as usize).min(buf.len());
            if self
                .target
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
    /// Near unreadable memory it decodes the instructions that end before
    /// it, fewer than `count`; it fails only when `addr` itself is unreadable.
    pub fn disassemble(&self, addr: VirtAddr, count: usize) -> Result<Vec<DisasmRow>> {
        let dtb = self.target.current_dtb();

        let machine = self.target.code_machine(addr);
        // Over-read so `count` instructions decode even at their longest.
        let mut buf = vec![0u8; count * machine.max_instruction_bytes()];
        let readable = self.read_masked_partial(addr, &mut buf);
        if readable == 0 && !buf.is_empty() {
            // Nothing reads: report why the first byte does not.
            self.target.read_masked(addr, &mut buf[..1])?;
        }
        let bytes = &buf[..readable];
        let read_end = addr.0.saturating_add(readable as u64);

        let symbols = &self.target.symbols;
        let resolve = |target: u64| {
            symbols
                .format_closest_symbol_for_address(dtb, VirtAddr(target))
                .unwrap_or_default()
        };
        // An instruction cut off by the unreadable byte would decode from
        // bytes that are not the target's, so the rows stop before it.
        let mut rows = decode_code(bytes, addr.0, Some(count), machine, resolve);
        if let Some(cut) = rows.iter().position(|row| {
            row.ip
                .saturating_add(row.hex.split_whitespace().count() as u64)
                > read_end
        }) {
            rows.truncate(cut);
        }
        Ok(rows)
    }

    /// Whether an instruction starts at `ip` in the address space `dtb`. A
    /// software breakpoint needs one: its `int3` replaces an instruction's
    /// first byte, and written inside an instruction it changes what the
    /// processor decodes there. A symbol at `ip` confirms a start; otherwise
    /// the code is decoded forward from where the code around `ip` starts,
    /// its function's unwind entry or else its symbol, and must land on `ip`.
    pub fn instruction_boundary(&self, dtb: Dtb, ip: VirtAddr) -> InstructionBoundary {
        let target = &self.target;
        let machine = target.code_machine(ip);
        if machine == CodeMachine::Arm64 {
            let instruction = VirtAddr(ip.0 & !3);
            return if instruction == ip {
                InstructionBoundary::Start
            } else {
                InstructionBoundary::Inside {
                    instruction,
                    from: instruction,
                }
            };
        }
        let symbol = target.symbols.find_closest_symbol_for_address(dtb, ip);
        if symbol.as_ref().is_some_and(|(_, _, offset)| *offset == 0) {
            return InstructionBoundary::Start;
        }
        let trace = resolve_thread_trace_context(target, dtb);
        let Some(from) = function_range(target, &trace, ip.0)
            .map(|(start, _)| start)
            .or_else(|| symbol.map(|(_, _, offset)| ip.0 - u64::from(offset)))
            .filter(|start| {
                ip.0.checked_sub(*start)
                    .is_some_and(|distance| distance <= MAX_BOUNDARY_SCAN)
            })
        else {
            return InstructionBoundary::NoAnchor;
        };
        if from == ip.0 {
            return InstructionBoundary::Start;
        }
        // Every instruction that starts before `ip` ends in this window, so
        // none is cut short.
        let mut bytes = vec![0u8; (ip.0 - from) as usize + machine.max_instruction_bytes()];
        let unreadable = InstructionBoundary::Unreadable {
            from: VirtAddr(from),
        };
        if self
            .target
            .read_masked_in(dtb, VirtAddr(from), &mut bytes)
            .is_err()
        {
            return unreadable;
        }
        match instruction_containing(machine, &bytes, from, ip.0) {
            Some(start) if start == ip.0 => InstructionBoundary::Start,
            Some(start) => InstructionBoundary::Inside {
                instruction: VirtAddr(start),
                from: VirtAddr(from),
            },
            None => unreadable,
        }
    }

    /// Check that an instruction starts at `address` in the address space
    /// `dtb` before a software breakpoint goes there (see
    /// [`Self::instruction_boundary`]). `Err` refuses an address inside an
    /// instruction, where the breakpoint would corrupt it. Where nothing
    /// confirms an instruction start, the breakpoint is set, as other
    /// debuggers set any address they are given, and the warning returned
    /// says so. Shared by `bp`, `bu` and `g <address>`.
    pub fn check_instruction_start(&self, dtb: Dtb, address: VirtAddr) -> Result<Option<String>> {
        let symbols = &self.target.symbols;
        let name = |address: VirtAddr| {
            symbols
                .format_closest_symbol_for_address(dtb, address)
                .unwrap_or_else(|| format!("{:#x}", address.0))
        };
        let unconfirmed = match self.instruction_boundary(dtb, address) {
            InstructionBoundary::Start => return Ok(None),
            InstructionBoundary::Inside { instruction, from } => {
                let decoding = if from == instruction {
                    String::new()
                } else {
                    format!(", decoding from {}", name(from))
                };
                return Err(Error::Breakpoint(format!(
                    "{} is inside the instruction at {}{decoding}; a breakpoint there would \
                     corrupt that instruction",
                    name(address),
                    name(instruction)
                )));
            }
            InstructionBoundary::NoAnchor => {
                format!(
                    "nothing near {} says where instructions start",
                    name(address)
                )
            }
            InstructionBoundary::Unreadable { from } => format!(
                "the code from {} to {} cannot be read",
                name(from),
                name(address)
            ),
        };
        Ok(Some(format!(
            "{unconfirmed}, so ntoseye could not confirm that an instruction starts there"
        )))
    }

    /// Disassemble the function containing `addr`: the one its runtime
    /// function entry describes, or else a leaf, which has none (see
    /// [`Self::leaf_function_range`]).
    pub fn disassemble_function(&self, addr: VirtAddr) -> Result<FunctionDisassembly> {
        let dtb = self.target.current_dtb();
        let trace = resolve_thread_trace_context(&self.target, dtb);
        let (start, end) = match function_range(&self.target, &trace, addr.0) {
            Some(range) => range,
            None => self.leaf_function_range(dtb, addr)?,
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
        self.target.read_masked(VirtAddr(start), &mut bytes)?;
        let resolve = |target| format_symbol(&self.target, &trace, target);
        let machine = self.target.code_machine(VirtAddr(start));
        let rows = decode_code(&bytes, start, None, machine, resolve);
        Ok(FunctionDisassembly {
            symbol: format_symbol(&self.target, &trace, start),
            length: len,
            rows,
        })
    }

    /// Where the function containing `addr` begins and ends, in the code
    /// `trace` runs: its runtime function entry, or else the leaf its symbol
    /// starts (see [`Self::leaf_function_range`]).
    pub fn function_bounds(
        &self,
        trace: &ThreadTraceContext,
        addr: VirtAddr,
    ) -> Option<(u64, u64)> {
        function_range(&self.target, trace, addr.0)
            .or_else(|| self.leaf_function_range(trace.active_dtb, addr).ok())
            .filter(|(start, end)| (*start..*end).contains(&addr.0))
    }

    /// The function containing `addr` that no runtime function entry
    /// describes, a leaf: from its symbol, as far as its control flow
    /// reaches before the next symbol.
    fn leaf_function_range(&self, dtb: Dtb, addr: VirtAddr) -> Result<(u64, u64)> {
        const MAX_LEAF_BYTES: u64 = 64 * 1024;
        let (start, limit) = self.target.symbols.symbol_span(dtb, addr).ok_or_else(|| {
            Error::DebugInfo(format!(
                "no runtime-function entry or symbol contains {:#x}",
                addr.0
            ))
        })?;
        let span = (limit.0 - start.0).min(MAX_LEAF_BYTES) as usize;
        let (code, valid) = read_page_chunks(start, span, |address, buf| {
            self.target.read_masked(address, buf)
        })?;
        let readable = valid.iter().position(|valid| !valid).unwrap_or(span);
        let machine = self.target.code_machine(start);
        let length = function_extent(&code[..readable], start.0, machine).ok_or_else(|| {
            Error::DebugInfo(format!(
                "no runtime-function entry contains {:#x}, and no code decodes at its symbol {:#x}",
                addr.0, start.0
            ))
        })?;
        let end = start.0 + length as u64;
        if addr.0 >= end {
            return Err(Error::DebugInfo(format!(
                "no runtime-function entry contains {:#x}, and the code of its symbol at {:#x} ends at {end:#x}",
                addr.0, start.0
            )));
        }
        Ok((start.0, end))
    }

    /// The bugcheck the target is in: the one its stop reported (a target
    /// that reports the crash itself, like KD, or a stop trapped at
    /// `nt!KeBugCheckEx`, before the call that fills `nt!KiBugCheckData`
    /// has run), else `nt!KiBugCheckData`'s, else a dump header's.
    pub fn bugcheck(&self) -> Option<BugcheckAnalysis> {
        self.last_event
            .as_ref()
            .and_then(|event| event.stop.bugcheck.as_ref())
            .map(|info| analyze_bugcheck(&self.target, info))
            .or_else(|| current_bugcheck(&self.target))
            .or_else(|| bugcheck_from_dump_info(&self.target))
    }

    /// Add backend identity and a backend vCPU count fallback to the target
    /// metadata. The target-only method remains useful for passive memory and
    /// dump consumers that have no execution backend.
    pub fn target_version(&mut self) -> Result<TargetVersion> {
        let mut detail = self.target.target_version()?;
        if detail.processors.is_none() {
            detail.processors = self
                .backend
                .thread_list()
                .ok()
                .map(|threads| threads.len() as u16);
        }
        detail.backend = Some(self.backend.name().to_string());
        Ok(detail)
    }

    /// The function-table entry and unwind data for the function containing
    /// `addr` in the current address space (`.fnent`).
    pub fn function_entry(&self, addr: VirtAddr) -> Result<FunctionEntry> {
        let trace = resolve_thread_trace_context(&self.target, self.target.current_dtb());
        function_entry(&self.target, &trace, addr.0)
    }

    /// Disassemble the instructions ending at `addr`. Missing pages before
    /// the readable suffix are skipped.
    pub fn disassemble_back(&self, addr: VirtAddr, count: usize) -> Result<Vec<DisasmRow>> {
        if count == 0 {
            return Err(Error::InvalidArgument(
                "instruction count must be greater than zero".to_string(),
            ));
        }
        let machine = self.target.code_machine(addr);
        let max_bytes = count.saturating_mul(machine.max_instruction_bytes());
        let start = VirtAddr(addr.0.saturating_sub(max_bytes as u64));
        let length = usize::try_from(addr.0 - start.0).unwrap_or(max_bytes);
        let (data, valid) = read_page_chunks(start, length, |address, buf| {
            self.target.read_masked(address, buf)
        })?;
        let readable_suffix_start = valid
            .iter()
            .rposition(|readable| !readable)
            .map_or(0, |last_unreadable| last_unreadable + 1);
        let mut suffix_len = length - readable_suffix_start;
        if machine == CodeMachine::Arm64 {
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
        decode_preceding(machine, bytes, read_start, addr.0, count, |target| {
            format_symbol(&self.target, &trace, target)
        })
        .ok_or_else(|| {
            Error::DebugInfo(format!(
                "could not decode instructions ending at {:#x}",
                addr.0
            ))
        })
    }

    /// The current inspection context's call stack with the sparse registers
    /// recovered for every frame, the seed register file the walk started
    /// from, and whether that seed is the vCPU's live register file. A
    /// selected context (`.cxr`, `.trap`, a thread's saved VTL0 state) seeds
    /// the walk in place of the vCPU or a parked thread; otherwise a parked
    /// Windows thread is walked from its saved context without touching the
    /// backend vCPU, and failing both, the vCPU's registers are read.
    pub fn recovered_backtrace(
        &mut self,
        limit: usize,
    ) -> Result<(RecoveredStackTrace, HashMap<String, u64>, bool)> {
        if let Some(selected) = self
            .target
            .selected_frame
            .as_ref()
            .filter(|selected| selected.thread.is_none())
        {
            let seed = if selected.seed_registers.is_empty() {
                &selected.registers
            } else {
                &selected.seed_registers
            };
            let seed = seed.clone();
            let trace = build_stacktrace_with_register_values(
                &self.target,
                &self.register_map,
                &seed,
                limit,
            );
            return Ok((trace, seed, selected.seed_live));
        }
        if let Some(thread) = self.parked_thread_now()? {
            let recovered = build_parked_thread_recovered_stack(&self.target, &thread, limit)?;
            // The walk's own first frame is the only register context a parked
            // thread has; there is no live file to seed from.
            let seed = recovered
                .stacktrace
                .frames
                .first()
                .map(|frame| frame.registers.clone())
                .unwrap_or_default();
            return Ok((recovered.stacktrace, seed, false));
        }
        let registers = self.read_registers()?;
        let seed = self.target.register_values(&self.register_map, &registers);
        let trace = build_thread_stacktrace(
            &self.target,
            &self.register_map,
            &registers,
            self.target.windows_thread_selection.as_ref(),
            limit,
        );
        Ok((trace, seed, true))
    }

    /// The selected parked thread as it is now. A halted target's cannot
    /// have changed since `.thread` read it. A running one's is read again,
    /// since reads are live and the thread may since have run, waited
    /// somewhere else, or exited; the selection keeps what was read.
    fn parked_thread_now(&mut self) -> Result<Option<ThreadInfo>> {
        let Some(thread) = self.parked_windows_thread().cloned() else {
            return Ok(None);
        };
        if !self.backend.is_running() {
            return Ok(Some(thread));
        }
        let now = self
            .target
            .thread_info_from_ethread(thread.ethread)
            .map_err(|error| {
                Error::DebugInfo(format!(
                    "the selected thread {:#x} can no longer be read: {error}",
                    thread.ethread.0
                ))
            })?;
        self.target.windows_thread_selection = Some(now.clone());
        Ok(Some(now))
    }

    /// [`Self::recovered_backtrace`]'s frames alone, up to `limit`.
    pub fn backtrace(&mut self, limit: usize) -> Result<StackTrace> {
        let (recovered, _, _) = self.recovered_backtrace(limit)?;
        Ok(recovered.into_stacktrace())
    }

    /// Unwind a Windows thread without selecting it or moving the backend's
    /// current vCPU. `running_on` is the vCPU running it, if any: the walk
    /// starts from that vCPU's registers, or, when it is halted in the Windows
    /// hypervisor, from the VTL0 state the hypervisor saved. A thread not
    /// running is walked from what it saved on its kernel stack; one running
    /// whose vCPU's registers cannot be read (the target runs) has no stack.
    pub fn backtrace_thread(
        &mut self,
        thread: &ThreadInfo,
        running_on: Option<&str>,
        limit: usize,
    ) -> Result<ThreadStackTrace> {
        if let Some(vcpu) = running_on
            && let Some(trace) = self.running_thread_stack(vcpu, thread, limit)?
        {
            return Ok(trace);
        }
        build_parked_thread_stack(&self.target, thread, limit)
    }

    /// `vcpu`'s register file, read without making it the current vCPU;
    /// `None` while the target runs or when the backend cannot read it.
    pub fn read_vcpu_registers(&mut self, vcpu: &str) -> Result<Option<Vec<u8>>> {
        if self.backend.is_running() {
            return Ok(None);
        }
        let registers = self
            .backend
            .set_current_thread(vcpu)
            .and_then(|()| self.backend.read_registers());
        self.backend.set_current_thread(&self.current_thread)?;
        Ok(registers.ok())
    }

    /// [`Self::recovered_backtrace`] for `vcpu` without selecting it: the
    /// current vCPU's stack is the inspection context's (a parked thread,
    /// `.cxr`, `.trap`), any other vCPU's starts from its default context, its
    /// own registers or, halted in the Windows hypervisor, where NT left off.
    /// A host showing every vCPU's stack (a DAP client) walks them this way,
    /// so looking at one does not move the context the console selected.
    pub fn recovered_vcpu_backtrace(
        &mut self,
        vcpu: &str,
        limit: usize,
    ) -> Result<(RecoveredStackTrace, HashMap<String, u64>, bool)> {
        if vcpu == self.current_thread {
            return self.recovered_backtrace(limit);
        }
        let registers = self
            .read_vcpu_registers(vcpu)?
            .ok_or_else(|| Error::DebugInfo(format!("{vcpu}'s registers are unavailable")))?;
        let live = self.register_map.to_hashmap(&registers);
        if let Some(saved) = self.target.saved_vtl0_registers(vcpu, &live) {
            let trace = build_stacktrace_with_register_values(
                &self.target,
                &self.register_map,
                &saved,
                limit,
            );
            return Ok((trace, saved, false));
        }
        let thread = windows_thread_on_backend_thread(&self.target, vcpu);
        let trace = build_thread_stacktrace(
            &self.target,
            &self.register_map,
            &registers,
            thread.as_ref(),
            limit,
        );
        Ok((trace, live, true))
    }

    /// The Windows hypervisor's own stack on `vcpu`, walked from its live
    /// registers, with them, when it is halted in the hypervisor: what a
    /// host shows above where NT or VTL1 left off, which is where its
    /// [`Self::recovered_vcpu_backtrace`] starts there. `None` elsewhere, or
    /// when its registers cannot be read.
    pub fn hypervisor_vcpu_backtrace(
        &mut self,
        vcpu: &str,
        limit: usize,
    ) -> Result<Option<(RecoveredStackTrace, HashMap<String, u64>)>> {
        let Some(registers) = self.read_vcpu_registers(vcpu)? else {
            return Ok(None);
        };
        let live = self.register_map.to_hashmap(&registers);
        let arch = self.target.arch();
        let (Some(&cr3), Some(&rip)) =
            (live.get(arch.dtb_register()), live.get(arch.pc_register()))
        else {
            return Ok(None);
        };
        if !halted_in_windows_hypervisor(&self.target, cr3, rip) {
            return Ok(None);
        }
        let trace =
            build_stacktrace_with_register_values(&self.target, &self.register_map, &live, limit);
        Ok(Some((trace, live)))
    }

    /// `vcpu`'s stack walked from its own registers, whatever the inspection
    /// context selected: halted in the Windows hypervisor, the hypervisor's
    /// frames (what `.cxr` then `k` shows), else the code it runs. With
    /// `vtl`, the walk starts where that VTL left off, as the hypervisor
    /// saved it (what `.vtlcxr <vtl>` then `k` shows): NT's stack for 0, the
    /// secure kernel's for 1, whose symbols it loads first.
    pub fn vcpu_backtrace(
        &mut self,
        vcpu: &str,
        vtl: Option<u8>,
        limit: usize,
    ) -> Result<RecoveredStackTrace> {
        let registers = self
            .read_vcpu_registers(vcpu)?
            .ok_or_else(|| Error::DebugInfo(format!("{vcpu}'s registers are unavailable")))?;
        let live = self.register_map.to_hashmap(&registers);
        let arch = self.target.arch();
        let in_hypervisor = match (live.get(arch.dtb_register()), live.get(arch.pc_register())) {
            (Some(&cr3), Some(&rip)) => {
                halted_in_windows_hypervisor(&self.target, cr3, rip).then_some((cr3, rip))
            }
            _ => None,
        };
        let Some(vtl) = vtl else {
            return Ok(match in_hypervisor {
                Some(_) => build_stacktrace_with_register_values(
                    &self.target,
                    &self.register_map,
                    &live,
                    limit,
                ),
                None => build_thread_stacktrace(
                    &self.target,
                    &self.register_map,
                    &registers,
                    windows_thread_on_backend_thread(&self.target, vcpu).as_ref(),
                    limit,
                ),
            });
        };
        let Some((cr3, rip)) = in_hypervisor else {
            return Err(Error::DebugInfo(format!(
                "{vcpu} is not halted in the Windows hypervisor, so no VTL state is saved"
            )));
        };
        let saved = saved_vtls(
            &self.target,
            cr3,
            rip,
            processor_index_from_backend_thread_id(vcpu),
        )?;
        let chosen = saved
            .iter()
            .find(|saved| saved.context.vtl == vtl)
            .ok_or_else(|| {
                Error::DebugInfo(format!(
                    "no saved VTL{vtl} state belongs to {vcpu}'s virtual processor"
                ))
            })?;
        if vtl == 1 {
            self.target.load_secure_kernel_symbols()?;
        }
        Ok(build_stacktrace_with_register_values(
            &self.target,
            &self.register_map,
            &chosen.context.registers(),
            limit,
        ))
    }

    /// The stack of the thread `vcpu` runs, from that vCPU's context; `None`
    /// when its registers cannot be read (the target runs).
    fn running_thread_stack(
        &mut self,
        vcpu: &str,
        thread: &ThreadInfo,
        limit: usize,
    ) -> Result<Option<ThreadStackTrace>> {
        let Some(registers) = self.read_vcpu_registers(vcpu)? else {
            return Ok(None);
        };
        let values = self.register_map.to_hashmap(&registers);
        if values
            .get(self.target.arch().dtb_register())
            .is_some_and(|dtb| self.target.recognize_secure_root(*dtb))
        {
            return Err(Error::DebugInfo(format!(
                "{vcpu} is running VTL1; NT's thread there is suspended in a VTL call"
            )));
        }
        let (source, recovered) = match self.target.saved_vtl0_registers(vcpu, &values) {
            Some(saved) => (
                ThreadStackSource::SavedVtl0,
                build_stacktrace_with_register_values(
                    &self.target,
                    &self.register_map,
                    &saved,
                    limit,
                ),
            ),
            None => (
                ThreadStackSource::Live,
                build_thread_stacktrace(
                    &self.target,
                    &self.register_map,
                    &registers,
                    Some(thread),
                    limit,
                ),
            ),
        };
        Ok(Some(ThreadStackTrace {
            source,
            stacktrace: recovered.into_stacktrace(),
        }))
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
        let resume = Motion::Continue {
            disposition: ContinueDisposition::Handled,
        };
        let outcome = self.run(resume, &Cancel::within(PAGE_IN_TIMEOUT));
        self.backend.surface_next_break_at(None);
        match outcome? {
            RunOutcome::Running => Err(Error::DebugInfo(format!(
                "the debugger worker did not report within {}s; the target is still running",
                PAGE_IN_TIMEOUT.as_secs()
            ))),
            RunOutcome::Stopped(_) => Ok(self.page_in_result(address, worker_break)),
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
        let pc = registers.as_ref().and_then(|regs| {
            self.register_map
                .read_u64(self.target.arch().pc_register(), regs)
                .ok()
        });
        let status = registers.as_ref().and_then(|regs| {
            self.argument_on_entry(0, |name| self.register_map.read_u64(name, regs).ok())
        });
        // `DbgBreakPointWithStatus` takes its status as its first argument,
        // so a worker break is distinguishable from any other hard-coded
        // break at the same address.
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

impl Session {
    /// The registers of VTL `vtl` (by default the current one) of VP `vp` of
    /// partition `partition` of the Windows hypervisor: those of a vCPU that
    /// runs the VP now, those of the exit a vCPU in the hypervisor handles
    /// for it, or else those it saved at its last exit, which it resumes
    /// with. The general-purpose registers are shared by a VP's VTLs and
    /// belong to the current one's state; another VTL's state is its eVMCS
    /// alone. The target must be halted.
    pub fn vp_registers(
        &mut self,
        partition: u64,
        vp: u32,
        vtl: Option<u8>,
    ) -> Result<VpRegisters> {
        let partitions = self.target.hypervisor_partitions()?;
        let owner = partitions
            .iter()
            .find(|candidate| candidate.id == partition)
            .ok_or_else(|| {
                Error::InvalidArgument(format!("the hypervisor has no partition {partition:#x}"))
            })?;
        let selected = owner
            .virtual_processors
            .iter()
            .find(|candidate| candidate.index == vp)
            .ok_or_else(|| {
                Error::InvalidArgument(format!("partition {partition:#x} has no VP {vp}"))
            })?;
        let level = vtl.unwrap_or(selected.vtl);
        let state = selected
            .vtls
            .iter()
            .find(|candidate| candidate.level == level)
            .ok_or_else(|| {
                Error::InvalidArgument(format!(
                    "VP {vp} of partition {partition:#x} has no VTL{level}"
                ))
            })?
            .state;
        let saved = |general: Option<&HashMap<&'static str, u64>>| match &state {
            Some(state) => exit_registers(state, general),
            None => general
                .into_iter()
                .flatten()
                .map(|(name, value)| (name.to_string(), *value))
                .collect(),
        };
        if level != selected.vtl {
            return Ok(VpRegisters {
                registers: saved(None),
                source: format!("the state VTL{level} left off in"),
                missing: Some(format!(
                    "the general-purpose registers are shared by the VP's VTLs, and are VTL{}'s, the one it runs in",
                    selected.vtl
                )),
                vcpu: None,
            });
        }
        let root = owner.parent.is_none();
        if let Some(found) = self.vp_on_vcpu(&partitions, partition, root, selected)? {
            return Ok(found);
        }
        let (general, missing) = match self.target.saved_vp_registers(&partitions, selected) {
            Ok(general) => (Some(general), None),
            Err(error) => (None, Some(error.to_string())),
        };
        Ok(VpRegisters {
            registers: saved(general.as_ref()),
            source: if state.is_some() {
                "its last exit".to_string()
            } else {
                "its register block; it has no eVMCS state, so it has not run".to_string()
            },
            missing,
            vcpu: None,
        })
    }

    /// The registers of `vp` (the VP of partition `partition`, the root one
    /// when `root`, of `partitions`) on a vCPU, when the processor it is the
    /// current VP of runs it now, or handles its exit in the hypervisor. A
    /// root partition's VP is pinned to the processor with its number.
    fn vp_on_vcpu(
        &mut self,
        partitions: &[HvPartition],
        partition: u64,
        root: bool,
        vp: &HvVirtualProcessor,
    ) -> Result<Option<VpRegisters>> {
        let mut numbers: Vec<u16> = vp
            .processors
            .iter()
            .filter_map(|processor| u16::try_from(processor.number?).ok())
            .collect();
        if root && let Ok(number) = u16::try_from(vp.index) {
            numbers.push(number);
        }
        for thread in self.backend.thread_list()? {
            let Some(number) = processor_index_from_backend_thread_id(&thread)
                .filter(|number| numbers.contains(number))
            else {
                continue;
            };
            let registers = self
                .backend
                .set_current_thread(&thread)
                .and_then(|()| self.backend.read_registers());
            self.backend.set_current_thread(&self.current_thread)?;
            let registers = registers?;
            let (Ok(rip), Ok(cr3)) = (
                self.register_map
                    .read_u64(self.target.arch().pc_register(), &registers),
                self.register_map
                    .read_u64(self.target.arch().dtb_register(), &registers),
            ) else {
                continue;
            };
            if halted_in_windows_hypervisor(&self.target, cr3, rip) {
                let Some(caller) =
                    self.target
                        .hypercall_caller(cr3, rip, number)
                        .filter(|caller| {
                            caller.partition == partition
                                && caller.vp == vp.index
                                && caller.vtl == vp.vtl
                        })
                else {
                    continue;
                };
                let missing = (!caller.registers.contains_key("rax")).then(|| {
                    format!("{thread} handles its exit, and its saved registers are not known")
                });
                return Ok(Some(VpRegisters {
                    registers: caller.registers,
                    source: format!("the exit {thread} handles for it in the hypervisor"),
                    missing,
                    vcpu: None,
                }));
            }
            // A vCPU outside the hypervisor runs the guest VP its processor
            // block names when its code is that guest's, else the root's.
            let runs = match guest_vp_running(&self.target, cr3, rip, Some(number))
                .and(processor_guest_vp(partitions, number))
            {
                Some((id, running)) => !root && id == partition && running.index == vp.index,
                None => root,
            };
            if runs {
                return Ok(Some(VpRegisters {
                    registers: self.register_map.to_hashmap(&registers),
                    source: format!("{thread}, which runs it"),
                    missing: None,
                    vcpu: Some(thread),
                }));
            }
        }
        Ok(None)
    }
}
