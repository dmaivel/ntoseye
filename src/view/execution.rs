//! Debugger execution-state [`View`] builders: run status,
//! vCPUs, breakpoints, exception policies, stacks, call traces, and
//! disassembly.

use super::process::{ProcessIdentity, ThreadSummary, process, thread_summary};
use super::shape::{Hex, Omit, shapes, unions};
use super::symbols::source_location;
use crate::types::VirtAddr;
use crate::breakpoints::Breakpoint;
use crate::disasm::DisasmRow;
use crate::exception_policy::{self, ExceptionPolicyFinalAction, exception_alias};
use crate::session::{self, CallTraceEnd, VcpuInfo};
use crate::unwind::{
    self, Arm64CodeDetail, Arm64UnwindDetail, FunctionEntryDetail, HandlerDetail, UnwindDetail,
};

shapes! {
    /// A vCPU (backend execution context) and the guest code it runs.
    VcpuStatus {
        /// The backend thread/vCPU id (`p1.1`).
        id: String,
        /// None when the register context was unreadable.
        rip: Option<Hex>,
        /// The address space the vCPU executes in: `kernel`, a process name,
        /// or `unknown`; empty when it could not be determined.
        context: String,
        /// The nearest symbol to `rip`, when one resolved.
        symbol: Option<String>,
        /// For a vCPU halted in the Windows hypervisor, where each VTL left
        /// off (`VTL0 nt!HalProcessorIdle+0xf`).
        saved_vtl: Vec<String>,
        /// Why the register context was unavailable, when it was.
        error: Option<String>,
    }

    /// A code breakpoint or data watchpoint (`bl`).
    BreakpointStatus {
        id: u32,
        /// None while a symbolic or source breakpoint is deferred.
        address: Option<VirtAddr>,
        enabled: bool,
        /// Whether the breakpoint resolved to an address; tells a deferred
        /// breakpoint from a disabled one.
        resolved: bool,
        /// Whether a symbolic or source specification awaits resolution.
        deferred: bool,
        /// The symbolic or source specification (`bu`/`bm`), kept across
        /// re-resolution.
        specification: Option<String>,
        /// The display name of the current resolution.
        symbol: Option<String>,
        /// `global`, or the process it is limited to (`name (pid)`).
        scope: String,
        /// The thread that may surface a hit (`/t`: `tid N` or `ethread
        /// 0x...`), if restricted.
        thread: Option<String>,
        /// The processor that may surface a hit (`/c`), if restricted.
        processor: Option<u16>,
        /// The condition expression a hit must satisfy.
        condition: Option<String>,
        /// The requested hit number; 0 and 1 both break on the first hit.
        pass_count: u64,
        hit_count: u64,
        /// Hits left before the breakpoint breaks.
        remaining_pass_count: u64,
        /// Whether the breakpoint is removed after its first break.
        one_shot: bool,
        /// Commands run when it breaks.
        action: Option<String>,
        temporary: bool,
        /// `write` or `read_write` for a data watchpoint, None for a code
        /// breakpoint.
        watch_access: Option<&'static str>,
        /// The watched width in bytes, None for a code breakpoint.
        watch_length: Option<u8>,
    }

    /// Whether the target runs and where it stopped.
    RunStatus {
        running: bool,
        /// The backend thread/vCPU selected.
        current_thread: String,
        /// The instruction pointer when halted, None while running.
        rip: Option<Hex>,
        /// The nearest symbol to `rip` when halted; code outside NT is named
        /// for what it is (`hvix64+0x3a6bde`).
        symbol: Option<String>,
        /// For a vCPU halted in the Windows hypervisor, where each VTL left
        /// off (`VTL0 nt!HalProcessorIdle+0xf`).
        saved_vtl: Vec<String>,
        /// The process chosen with `.process` whose memory `dt`, `dq`, ...
        /// read; it survives resumes.
        attached_process: Option<ProcessIdentity>,
        /// The process whose page tables the stopped vCPU has loaded.
        stopped_process: Option<ProcessIdentity>,
        /// The Windows thread the stopped vCPU runs; its owner can differ
        /// from `stopped_process` (`KeStackAttachProcess`).
        stopped_thread: Option<ThreadSummary>,
        /// False after a reboot until the kernel's loaded-module list exists:
        /// process and module enumeration is not yet meaningful.
        coherent: bool,
        /// The rediscovered `nt` base; it changes across a reboot.
        kernel_base: Hex,
    }

    /// One frame of a walked stack.
    StackFrame {
        /// The frame's position in the walked stack, present in a selection
        /// of a stack's frames.
        index: Omit<usize>,
        /// The instruction pointer.
        ip: Hex,
        /// The stack pointer.
        sp: Hex,
        /// The symbol at `ip`; empty when none resolved.
        symbol: String,
        /// How the frame was recovered: `current`, `seed`, `unwind`, or `scan`.
        source: &'static str,
        /// The source line at `ip`, when line information resolves it.
        source_location: Option<super::symbols::SourceLocation>,
    }

    /// One decoded instruction.
    DisassembledInstruction {
        ip: Hex,
        /// The instruction's bytes, in hex.
        hex: String,
        /// The instruction text.
        asm: String,
        /// The resolved branch or rip-relative target, when there is one.
        comment: Option<String>,
    }

    /// The function-table entry covering an address and each chained parent's
    /// (`.fnent`).
    FunctionEntry {
        /// The module containing the function.
        module: String,
        image_base: Hex,
        /// The entry covering the address, then each parent its chained unwind
        /// info names, in order.
        entries: Vec<RuntimeFunction>,
        /// Why the chain ends before its last parent, when it does.
        incomplete: Option<String>,
    }

    /// One function-table entry and its unwind data. Addresses are absolute;
    /// `*_rva` fields are the raw image-relative values.
    RuntimeFunction {
        begin: Hex,
        end: Hex,
        begin_rva: Hex<u32>,
        end_rva: Hex<u32>,
        /// The unwind info's address; None for ARM64 packed unwind data.
        unwind_info: Option<Hex>,
        /// The entry's raw unwind word: the unwind info's RVA, or ARM64's
        /// packed unwind data.
        unwind_data: Hex<u32>,
        /// The symbol at `begin`.
        symbol: String,
        /// The decoded unwind data, None when it is unreadable.
        unwind: Option<Unwind>,
    }

    /// AMD64 `UNWIND_INFO`.
    Amd64UnwindInfo {
        /// `amd64`.
        form: &'static str,
        version: u8,
        /// `UNW_FLAG_*` bits.
        flags: u8,
        /// Bytes of the prolog.
        prolog_size: u8,
        /// Unwind-code slots.
        code_count: u8,
        /// The frame pointer register, when the function establishes one.
        frame_register: Option<&'static str>,
        /// The frame pointer's offset from the stack pointer, in bytes.
        frame_offset: u32,
        /// Bytes of the structure: header, codes, and the handler RVA or the
        /// chained entry, without the handler's own data.
        size: usize,
        codes: Vec<Amd64UnwindCode>,
        /// The exception or termination handler, for `UNW_FLAG_EHANDLER` or
        /// `UNW_FLAG_UHANDLER`.
        handler: Option<UnwindHandler>,
    }

    /// One AMD64 unwind code.
    Amd64UnwindCode {
        /// Index of the code's first slot.
        slot: usize,
        /// Offset in the prolog of the end of the instruction it undoes.
        code_offset: u8,
        /// The `UWOP_*` operation.
        op: u8,
        /// The operation's info nibble.
        op_info: u8,
        /// The operation and its operands, e.g. `UWOP_SAVE_NONVOL rbx at +0x30`.
        description: String,
    }

    /// An unwind info's exception or termination handler.
    UnwindHandler {
        address: Hex,
        symbol: String,
        /// Where the handler's language-specific data starts.
        data: Hex,
    }

    /// ARM64 unwind data packed into the `.pdata` entry (flag 1 or 2): a
    /// canonical prolog, listed as the codes it stands for.
    Arm64PackedUnwind {
        /// `packed`.
        form: &'static str,
        /// 1, or 2 for a function fragment without a prolog.
        flag: u32,
        /// The `RegF` field: saved non-volatile floating-point registers.
        reg_f: u32,
        /// The `RegI` field: saved non-volatile integer registers.
        reg_i: u32,
        /// Whether the prolog homes the argument registers.
        homes_arguments: bool,
        /// The `CR` field: whether and how the frame chain and link register
        /// are saved.
        cr: u32,
        /// The frame's size, in bytes.
        frame_size: u32,
        codes: Vec<Arm64UnwindCode>,
    }

    /// An ARM64 `.xdata` unwind record.
    Arm64XdataUnwind {
        /// `xdata`.
        form: &'static str,
        version: u32,
        /// The `X` bit: exception data (a handler) follows.
        exception_data: bool,
        /// The `E` bit: a single epilog described in the header.
        epilog_in_header: bool,
        epilog_count: u32,
        /// 32-bit words of unwind codes.
        code_words: u32,
        epilog_scopes: Vec<Arm64EpilogScope>,
        /// Bytes of the record, the handler's RVA included.
        size: usize,
        codes: Vec<Arm64UnwindCode>,
        handler: Option<UnwindHandler>,
    }

    /// One ARM64 unwind code.
    Arm64UnwindCode {
        /// Its first byte's index in the code bytes.
        index: usize,
        bytes: Vec<Hex<u8>>,
        /// Its name and the prolog instruction it stands for.
        description: String,
    }

    /// One ARM64 epilog scope.
    Arm64EpilogScope {
        /// The epilog's start, in bytes from the function's.
        start_offset: Hex<u32>,
        /// The index of the epilog's first unwind code.
        first_code: u32,
    }

    /// A `wt` call trace: why it stopped, the instructions it stepped, and
    /// the call tree.
    CallTrace {
        /// `returned`, `limit`, `interrupted`, `breakpoint`, `diverted`, or
        /// `failed`; anything but `returned` leaves a partial tree.
        end: &'static str,
        /// What failed, for `failed`.
        error: Option<String>,
        /// Instructions single-stepped.
        instructions: usize,
        root: CallTraceFrame,
    }

    /// One call-tree node of a `wt` trace.
    CallTraceFrame {
        /// The called function.
        name: String,
        /// Instructions stepped in the function itself.
        instructions: usize,
        /// The calls it made.
        children: Vec<CallTraceFrame>,
    }

    /// One exception stop policy (`sx`).
    ExceptionPolicy {
        /// The exception code.
        code: Hex<u32>,
        /// The code's WinDbg alias (`av`, `bp`, ...), when it has one.
        alias: Option<&'static str>,
        /// `break`, `second_chance`, `notify`, or `ignore`.
        mode: &'static str,
        /// An explicit final action: `break`, or continue as `handled` or
        /// `not_handled`; None for the mode's default.
        disposition: Option<&'static str>,
        /// Commands run when the exception arrives.
        command: Option<String>,
    }

    /// An evaluated debugger expression (`?`).
    ExpressionValue {
        expression: String,
        value: VirtAddr,
    }

    /// One register of the current context (`r`).
    RegisterValue {
        name: String,
        /// An int, or for a vector register a `0x`-prefixed 32-digit hex
        /// string.
        value: RegisterContent,
    }
}

unions! {
    /// An entry's decoded unwind data, by form.
    Unwind {
        Amd64(Amd64UnwindInfo),
        Packed(Arm64PackedUnwind),
        Xdata(Arm64XdataUnwind),
    }
}

unions! {
    /// A register's value: an address-width value, or a vector register too
    /// wide for an int's hex rendering.
    RegisterContent {
        Scalar(Hex),
        /// A 128-bit value, as `0x` and 32 hex digits.
        Wide(String),
    }
}

pub fn vcpu(v: &VcpuInfo) -> VcpuStatus {
    VcpuStatus {
        id: v.id.clone(),
        rip: v.rip,
        context: v.context.clone(),
        symbol: v.symbol.clone(),
        saved_vtl: v.saved_vtl.clone(),
        error: v.error.clone(),
    }
}

/// One code-breakpoint/data-watchpoint row.
pub fn breakpoint(bp: &Breakpoint) -> BreakpointStatus {
    BreakpointStatus {
        id: bp.id,
        address: bp.resolved_address(),
        enabled: bp.enabled,
        resolved: bp.resolved,
        deferred: bp.deferred(),
        specification: bp.specification().map(str::to_string),
        symbol: bp.symbol.clone(),
        scope: bp.scope.label(),
        thread: bp.thread.as_ref().map(|thread| thread.label()),
        processor: bp.processor,
        condition: bp.condition.clone(),
        pass_count: bp.pass_count,
        hit_count: bp.hit_count,
        remaining_pass_count: bp.remaining_pass_count,
        one_shot: bp.one_shot,
        action: bp.action.clone(),
        temporary: bp.temporary,
        watch_access: bp.watch_access_name(),
        watch_length: bp.watch_length(),
    }
}

pub fn run_status(status: &session::RunStatus) -> RunStatus {
    RunStatus {
        running: status.running,
        current_thread: status.current_thread.clone(),
        rip: status.rip,
        symbol: status.symbol.clone(),
        saved_vtl: status.saved_vtl.clone(),
        attached_process: status.attached_process.as_ref().map(process),
        stopped_process: status.stopped_process.as_ref().map(process),
        stopped_thread: status
            .stopped_thread
            .as_ref()
            .map(|thread| thread_summary(thread, None)),
        coherent: status.coherent,
        kernel_base: status.kernel_base,
    }
}

pub fn stack_frame(frame: &unwind::StackFrame) -> StackFrame {
    StackFrame {
        index: None,
        ip: frame.ip,
        sp: frame.sp,
        symbol: frame.symbol.clone(),
        source: frame.source.as_str(),
        source_location: frame.source_location.as_ref().map(source_location),
    }
}

/// [`stack_frame`] with its position in the walked stack, for a selection of
/// a stack's frames.
pub fn numbered_stack_frame(index: usize, frame: &unwind::StackFrame) -> StackFrame {
    StackFrame {
        index: Some(index),
        ..stack_frame(frame)
    }
}

/// One decoded instruction.
pub fn disasm_row(row: &DisasmRow) -> DisassembledInstruction {
    DisassembledInstruction {
        ip: row.ip,
        hex: row.hex.clone(),
        asm: row.asm(),
        comment: row.comment.clone(),
    }
}

fn arm64_codes(codes: &[Arm64CodeDetail]) -> Vec<Arm64UnwindCode> {
    codes
        .iter()
        .map(|code| Arm64UnwindCode {
            index: code.index,
            bytes: code.bytes.clone(),
            description: code.description.clone(),
        })
        .collect()
}

/// `.fnent`: the function-table entry covering an address and its unwind
/// info, then each chained parent's.
pub fn function_entry(detail: &FunctionEntryDetail) -> FunctionEntry {
    let base = detail.image_base;
    let va = |rva: u32| base.wrapping_add(u64::from(rva));
    let handler = |handler: &Option<HandlerDetail>| {
        handler.as_ref().map(|handler| UnwindHandler {
            address: va(handler.rva),
            symbol: handler.symbol.clone(),
            data: va(handler.data_rva),
        })
    };
    let entries = detail
        .entries
        .iter()
        .map(|entry| {
            let unwind = entry.unwind.as_ref().map(|unwind| match unwind {
                UnwindDetail::Amd64(info) => Unwind::Amd64(Amd64UnwindInfo {
                    form: "amd64",
                    version: info.version,
                    flags: info.flags,
                    prolog_size: info.prolog_size,
                    code_count: info.code_count,
                    frame_register: info.frame_register,
                    frame_offset: info.frame_offset,
                    size: info.size,
                    codes: info
                        .codes
                        .iter()
                        .map(|code| Amd64UnwindCode {
                            slot: code.slot,
                            code_offset: code.code_offset,
                            op: code.op,
                            op_info: code.op_info,
                            description: code.description.clone(),
                        })
                        .collect(),
                    handler: handler(&info.handler),
                }),
                UnwindDetail::Arm64(Arm64UnwindDetail::Packed {
                    flag,
                    reg_f,
                    reg_i,
                    homes_arguments,
                    cr,
                    frame_size,
                    codes,
                }) => Unwind::Packed(Arm64PackedUnwind {
                    form: "packed",
                    flag: *flag,
                    reg_f: *reg_f,
                    reg_i: *reg_i,
                    homes_arguments: *homes_arguments,
                    cr: *cr,
                    frame_size: *frame_size,
                    codes: arm64_codes(codes),
                }),
                UnwindDetail::Arm64(Arm64UnwindDetail::Xdata {
                    version,
                    exception_data,
                    epilog_in_header,
                    epilog_count,
                    code_words,
                    scopes,
                    codes,
                    handler: xdata_handler,
                    size,
                }) => Unwind::Xdata(Arm64XdataUnwind {
                    form: "xdata",
                    version: *version,
                    exception_data: *exception_data,
                    epilog_in_header: *epilog_in_header,
                    epilog_count: *epilog_count,
                    code_words: *code_words,
                    epilog_scopes: scopes
                        .iter()
                        .map(|&(start, first_code)| Arm64EpilogScope {
                            start_offset: start,
                            first_code,
                        })
                        .collect(),
                    size: *size,
                    codes: arm64_codes(codes),
                    handler: handler(xdata_handler),
                }),
            });
            let packed = matches!(unwind, Some(Unwind::Packed(_)));
            RuntimeFunction {
                begin: va(entry.begin),
                end: va(entry.end),
                begin_rva: entry.begin,
                end_rva: entry.end,
                unwind_info: (!packed).then(|| va(entry.unwind_data)),
                unwind_data: entry.unwind_data,
                symbol: entry.symbol.clone(),
                unwind,
            }
        })
        .collect();
    FunctionEntry {
        module: detail.module.clone(),
        image_base: base,
        entries,
        incomplete: detail.incomplete.clone(),
    }
}

/// A `wt` call trace.
pub fn call_trace(trace: &session::CallTrace) -> CallTrace {
    let (end, error) = match &trace.end {
        CallTraceEnd::Returned => ("returned", None),
        CallTraceEnd::Limit => ("limit", None),
        CallTraceEnd::Interrupted => ("interrupted", None),
        CallTraceEnd::Breakpoint => ("breakpoint", None),
        CallTraceEnd::Diverted => ("diverted", None),
        CallTraceEnd::Failed(error) => ("failed", Some(error.clone())),
    };
    CallTrace {
        end,
        error,
        instructions: trace.instructions,
        root: call_trace_frame(&trace.root),
    }
}

fn call_trace_frame(frame: &session::CallTraceFrame) -> CallTraceFrame {
    CallTraceFrame {
        name: frame.name.clone(),
        instructions: frame.instructions,
        children: frame.children.iter().map(call_trace_frame).collect(),
    }
}

/// One exception stop policy (`sx`).
pub fn exception_policy(code: u32, policy: &exception_policy::ExceptionPolicy) -> ExceptionPolicy {
    let disposition = match policy.final_action {
        Some(ExceptionPolicyFinalAction::Continue(disposition)) => Some(disposition.name()),
        Some(ExceptionPolicyFinalAction::Break) => Some("break"),
        None => None,
    };
    ExceptionPolicy {
        code,
        alias: exception_alias(code),
        mode: policy.mode.name(),
        disposition,
        command: policy.command.clone(),
    }
}
