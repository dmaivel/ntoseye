//! Debugger execution-state [`View`] builders: run status,
//! vCPUs, breakpoints, exception policies, stacks, call traces, and
//! disassembly.

use super::process::{ProcessIdentity, ThreadSummary, process, thread_summary};
use super::shape::{Hex, shapes, unions};
use super::symbols::source_location;
use crate::types::VirtAddr;
use crate::breakpoints::Breakpoint;
use crate::disasm::{DisasmOperand, DisasmRow, disasm_formatter};
use crate::exception_policy::{self, ExceptionPolicyFinalAction, exception_alias};
use crate::session::{self, CallTraceEnd, VcpuInfo};
use crate::unwind::{
    self, Arm64CodeDetail, Arm64UnwindDetail, FunctionEntryDetail, HandlerDetail, UnwindDetail,
};

shapes! {
    /// A vCPU (backend execution context) and the guest code that it runs.
    VcpuStatus {
        /// The backend thread/vCPU ID (`p1.1`).
        id: String,
        /// None if ntoseye cannot read the register context.
        rip: Option<Hex>,
        /// The address space in which the vCPU runs: `kernel`, a process name,
        /// or `unknown`. Empty if ntoseye cannot find the address space.
        context: String,
        /// The nearest symbol to `rip`, if one resolves.
        symbol: Option<String>,
        /// For a vCPU halted in the Windows hypervisor, the VTL states that the
        /// hypervisor saved for the vCPU's virtual processor, VTL0 first.
        saved_vtl: Vec<SavedVtlState>,
        /// The reason that the register context is not available. None if it is
        /// available.
        error: Option<String>,
    }

    /// One VTL of a virtual processor, as the Windows hypervisor last saved it
    /// in the VTL's Enlightened VMCS. A VMCS holds no general-purpose register
    /// other than `rsp`.
    SavedVtlState {
        /// 0 or 1.
        vtl: u8,
        /// Whether the VP assist page names this state's eVMCS as current. The
        /// current VTL is the one that entered the hypervisor or that the
        /// hypervisor is about to enter.
        current: bool,
        rip: VirtAddr,
        /// The symbol at `rip` in the VTL's address space, if one resolves.
        symbol: Option<String>,
        rsp: VirtAddr,
        rflags: Hex,
        cr0: Hex,
        /// The page-table root of the VTL.
        cr3: Hex,
        cr4: Hex,
        dr7: Hex,
        cs: Hex<u16>,
        ss: Hex<u16>,
        ds: Hex<u16>,
        es: Hex<u16>,
        fs: Hex<u16>,
        gs: Hex<u16>,
        fs_base: VirtAddr,
        gs_base: VirtAddr,
        /// The VM-exit reason of the last exit from the VTL. Bits 15:0 hold the
        /// basic reason, and bit 31 is set for a failed VM entry.
        exit_reason: Hex<u32>,
        /// The name of the exit reason (`HLT`, `VMCALL`, ...), if it is a
        /// common reason.
        exit_reason_name: Option<&'static str>,
        /// The physical address of the eVMCS page that ntoseye read the state
        /// from.
        evmcs: Hex,
    }

    /// A code breakpoint or data watchpoint (`bl`).
    BreakpointStatus {
        id: u32,
        /// None while a symbolic or source breakpoint is deferred.
        address: Option<VirtAddr>,
        enabled: bool,
        /// Whether the breakpoint resolved to an address. Use it to tell a
        /// deferred breakpoint from a disabled one.
        resolved: bool,
        /// Whether a symbolic or source specification waits for resolution.
        deferred: bool,
        /// The symbolic or source specification (`bu`/`bm`), which ntoseye
        /// keeps when it resolves the breakpoint again.
        specification: Option<String>,
        /// The display name of the current resolution.
        symbol: Option<String>,
        /// `global`, or the process that the breakpoint is limited to
        /// (`name (pid)`).
        scope: String,
        /// The only thread that can report a hit (`/t`: `tid N` or
        /// `ethread 0x...`). None if there is no thread restriction.
        thread: Option<String>,
        /// The only processor that can report a hit (`/c`). None if there is no
        /// processor restriction.
        processor: Option<u16>,
        /// The condition expression that a hit must satisfy.
        condition: Option<String>,
        /// The requested hit number. Both 0 and 1 break on the first hit.
        pass_count: u64,
        hit_count: u64,
        /// The number of hits that remain before the breakpoint breaks.
        remaining_pass_count: u64,
        /// Whether ntoseye removes the breakpoint after its first break.
        one_shot: bool,
        /// The commands that run when the breakpoint breaks.
        action: Option<String>,
        temporary: bool,
        /// `write` or `read_write` for a data watchpoint. None for a code
        /// breakpoint.
        watch_access: Option<&'static str>,
        /// The watched width in bytes. None for a code breakpoint.
        watch_length: Option<u8>,
    }

    /// Whether the target runs, and where it stopped.
    RunStatus {
        running: bool,
        /// The selected backend thread/vCPU.
        current_thread: String,
        /// The instruction pointer when halted. None while the target runs.
        rip: Option<Hex>,
        /// The nearest symbol to `rip` when halted. For code outside NT, the
        /// name identifies that code (`hvix64+0x3a6bde`).
        symbol: Option<String>,
        /// For a vCPU halted in the Windows hypervisor, the VTL states that the
        /// hypervisor saved for the vCPU's virtual processor, VTL0 first.
        saved_vtl: Vec<SavedVtlState>,
        /// The process that you selected with `.process`. `dt`, `dq`, and
        /// similar commands read its memory, and the selection stays after the
        /// target resumes.
        attached_process: Option<ProcessIdentity>,
        /// The process whose page tables the stopped vCPU has loaded.
        stopped_process: Option<ProcessIdentity>,
        /// The Windows thread that the stopped vCPU runs. Its owner can be
        /// different from `stopped_process` (`KeStackAttachProcess`).
        stopped_thread: Option<ThreadSummary>,
        /// False after a reboot until the kernel's loaded-module list exists,
        /// and process and module enumeration is not valid until then.
        coherent: bool,
        /// The `nt` base that ntoseye found again. It changes across a reboot.
        kernel_base: Hex,
    }

    /// One frame of a stack walk.
    StackFrame {
        /// The position of the frame in the stack walk. The innermost frame is 0.
        index: usize,
        /// The instruction pointer.
        ip: Hex,
        /// The stack pointer.
        sp: Hex,
        /// The symbol at `ip`. Empty if no symbol resolves.
        symbol: String,
        /// True for a call that the compiler inlined into the physical frame
        /// after it, so the call has no stack frame of its own. `symbol` is the
        /// inlined function, and `ip` and `sp` are those of the physical frame.
        inline: bool,
        /// How ntoseye recovered the frame: `current`, `seed`, `unwind`, or `scan`.
        source: &'static str,
        /// The source line of the frame, if line information resolves it. For
        /// an inline frame this is the line in the inlined function, and for a
        /// caller it is the line of the call.
        source_location: Option<super::symbols::SourceLocation>,
    }

    /// One decoded instruction.
    DisassembledInstruction {
        ip: Hex,
        /// The bytes of the instruction, in hex.
        hex: String,
        /// The instruction text.
        asm: String,
        /// The resolved branch or rip-relative target, if there is one.
        comment: Option<String>,
        /// The instruction length in bytes.
        length: usize,
        /// The lowercase mnemonic, without prefixes (`mov`, `ldr`). `.inst`
        /// for an ARM64 word that encodes no instruction.
        mnemonic: String,
        /// The explicit operands, in instruction order.
        operands: Vec<Operand>,
    }

    /// One explicit operand of a decoded instruction. Fields that do not apply
    /// to its `kind` are None.
    Operand {
        /// `register`, `memory`, `immediate`, `branch` (a branch or PC-relative
        /// label target), or `other`.
        kind: &'static str,
        /// The operand as `asm` shows it.
        text: String,
        /// A register operand's register as written, lowercase (`r8d`, `w3`).
        register: Option<String>,
        /// The architectural register that `register` is part of (`r8` for
        /// `r8d`, `x3` for `w3`; vector registers stay as written).
        full_register: Option<String>,
        /// A memory operand's base register, full and lowercase (`rip` when
        /// RIP-relative).
        base: Option<String>,
        /// A memory operand's index register, full and lowercase.
        index: Option<String>,
        /// The scale of `index`.
        scale: Option<u32>,
        /// A memory operand's signed displacement: relative to the next
        /// instruction when RIP-relative, and the writeback offset of an ARM64
        /// post-indexed operand.
        displacement: Option<i64>,
        /// A memory operand's access size in bytes, when known (x86 only).
        size: Option<u32>,
        /// A memory operand's x86 segment override (`gs`).
        segment: Option<String>,
        /// An immediate operand's value (negative when the instruction
        /// sign-extends it), or a branch operand's target address.
        immediate: Option<i128>,
    }

    /// The function-table entry that covers an address, and the entry of each
    /// chained parent (`.fnent`).
    FunctionEntry {
        /// The module that contains the function.
        module: String,
        image_base: Hex,
        /// The entry that covers the address, then each parent that its chained
        /// unwind info names, in order.
        entries: Vec<RuntimeFunction>,
        /// The reason that the chain ends before its last parent. None if the
        /// chain is complete.
        incomplete: Option<String>,
    }

    /// One function-table entry and its unwind data. Addresses are absolute,
    /// and the `*_rva` fields hold the raw image-relative values.
    RuntimeFunction {
        begin: Hex,
        end: Hex,
        begin_rva: Hex<u32>,
        end_rva: Hex<u32>,
        /// The address of the unwind info. None for ARM64 packed unwind data.
        unwind_info: Option<Hex>,
        /// The raw unwind word of the entry: the RVA of the unwind info, or
        /// the packed unwind data on ARM64.
        unwind_data: Hex<u32>,
        /// The symbol at `begin`.
        symbol: String,
        /// The decoded unwind data. None if ntoseye cannot read it.
        unwind: Option<Unwind>,
    }

    /// AMD64 `UNWIND_INFO`.
    Amd64UnwindInfo {
        /// `amd64`.
        form: &'static str,
        version: u8,
        /// `UNW_FLAG_*` bits.
        flags: u8,
        /// The size of the prolog, in bytes.
        prolog_size: u8,
        /// The number of unwind-code slots.
        code_count: u8,
        /// The frame pointer register, if the function sets one up.
        frame_register: Option<&'static str>,
        /// The frame pointer's offset from the stack pointer, in bytes.
        frame_offset: u32,
        /// The size of the structure in bytes, covering the header, the codes,
        /// and the handler RVA or the chained entry, but not the handler's
        /// data.
        size: usize,
        codes: Vec<Amd64UnwindCode>,
        /// The exception or termination handler, for `UNW_FLAG_EHANDLER` or
        /// `UNW_FLAG_UHANDLER`.
        handler: Option<UnwindHandler>,
    }

    /// One AMD64 unwind code.
    Amd64UnwindCode {
        /// The index of the first slot of the code.
        slot: usize,
        /// The prolog offset of the end of the instruction that the code
        /// undoes.
        code_offset: u8,
        /// The `UWOP_*` operation.
        op: u8,
        /// The info nibble of the operation.
        op_info: u8,
        /// The operation and its operands, for example
        /// `UWOP_SAVE_NONVOL rbx at +0x30`.
        description: String,
    }

    /// The exception or termination handler of an unwind info.
    UnwindHandler {
        address: Hex,
        symbol: String,
        /// The start address of the language-specific data of the handler.
        data: Hex,
    }

    /// ARM64 unwind data that is packed into the `.pdata` entry (flag 1 or 2).
    /// It describes a canonical prolog, and ntoseye lists it as the codes that
    /// it represents.
    Arm64PackedUnwind {
        /// `packed`.
        form: &'static str,
        /// 1, or 2 for a function fragment without a prolog.
        flag: u32,
        /// The `RegF` field: the saved non-volatile floating-point registers.
        reg_f: u32,
        /// The `RegI` field: the saved non-volatile integer registers.
        reg_i: u32,
        /// Whether the prolog stores the argument registers in their home
        /// locations.
        homes_arguments: bool,
        /// The `CR` field: whether and how the prolog saves the frame chain
        /// and the link register.
        cr: u32,
        /// The size of the frame, in bytes.
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
        /// The `E` bit: the header describes a single epilog.
        epilog_in_header: bool,
        epilog_count: u32,
        /// The number of 32-bit words of unwind codes.
        code_words: u32,
        epilog_scopes: Vec<Arm64EpilogScope>,
        /// The size of the record in bytes, including the RVA of the handler.
        size: usize,
        codes: Vec<Arm64UnwindCode>,
        handler: Option<UnwindHandler>,
    }

    /// One ARM64 unwind code.
    Arm64UnwindCode {
        /// The index of its first byte in the code bytes.
        index: usize,
        bytes: Vec<Hex<u8>>,
        /// Its name and the prolog instruction that it represents.
        description: String,
    }

    /// One ARM64 epilog scope.
    Arm64EpilogScope {
        /// The start of the epilog, in bytes from the start of the function.
        start_offset: Hex<u32>,
        /// The index of the first unwind code of the epilog.
        first_code: u32,
    }

    /// A `wt` call trace: why it stopped, the instructions that it stepped,
    /// and the call tree.
    CallTrace {
        /// `returned`, `limit`, `interrupted`, `breakpoint`, `diverted`, or
        /// `failed`. `diverted` means that an interrupt diverted a step and the
        /// traced thread is not known. Any value other than `returned` means
        /// that the tree is partial.
        end: &'static str,
        /// A description of the failure, for `failed`.
        error: Option<String>,
        /// The number of single-stepped instructions.
        instructions: usize,
        root: CallTraceFrame,
    }

    /// One call-tree node of a `wt` trace.
    CallTraceFrame {
        /// The called function.
        name: String,
        /// The number of instructions stepped in the function itself.
        instructions: usize,
        /// The calls that the function made.
        children: Vec<CallTraceFrame>,
    }

    /// One exception stop policy (`sx`).
    ExceptionPolicy {
        /// The exception code.
        code: Hex<u32>,
        /// The WinDbg alias of the code (`av`, `bp`, ...), if it has one.
        alias: Option<&'static str>,
        /// `break`, `second_chance`, `notify`, or `ignore`.
        mode: &'static str,
        /// An explicit final action: `break`, or continue as `handled` or
        /// `not_handled`. None for the default action of the mode.
        disposition: Option<&'static str>,
        /// The commands that run when the exception occurs.
        command: Option<String>,
    }

    /// One module load or unload filter (`sx* ld[:<module>]` or
    /// `sx* ud[:<module>]`).
    ModuleEventPolicy {
        /// `ld` for a load filter, `ud` for an unload filter.
        event: &'static str,
        /// The image-name glob that the filter matches, with or without
        /// extension. None for all modules (bare `ld` or `ud`).
        module: Option<String>,
        /// `break` stops at the event, and `notify` reports it.
        /// `second_chance` and `ignore` let the load or unload continue with
        /// no output.
        mode: &'static str,
        /// The commands that run at a `break` stop.
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
        /// An int, or a `0x`-prefixed 32-digit hex string for a vector
        /// register.
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
        saved_vtl: v.saved_vtl.iter().map(saved_vtl_state).collect(),
        error: v.error.clone(),
    }
}

/// A VTL state the Windows hypervisor saved.
pub fn saved_vtl_state(saved: &unwind::SavedVtl) -> SavedVtlState {
    let state = &saved.context.state;
    SavedVtlState {
        vtl: saved.context.vtl,
        current: state.current,
        rip: VirtAddr(state.rip),
        symbol: saved.symbol.clone(),
        rsp: VirtAddr(state.rsp),
        rflags: state.rflags,
        cr0: state.cr0,
        cr3: state.cr3,
        cr4: state.cr4,
        dr7: state.dr7,
        cs: state.cs,
        ss: state.ss,
        ds: state.ds,
        es: state.es,
        fs: state.fs,
        gs: state.gs,
        fs_base: VirtAddr(state.fs_base),
        gs_base: VirtAddr(state.gs_base),
        exit_reason: state.exit_reason,
        exit_reason_name: state.exit_reason_name(),
        evmcs: state.address,
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
        saved_vtl: status.saved_vtl.iter().map(saved_vtl_state).collect(),
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

/// Frame `index` of a walked stack.
pub fn stack_frame(index: usize, frame: &unwind::StackFrame) -> StackFrame {
    StackFrame {
        index,
        ip: frame.ip,
        sp: frame.sp,
        symbol: frame.symbol.clone(),
        inline: frame.inline,
        source: frame.source.as_str(),
        source_location: frame.source_location.as_ref().map(source_location),
    }
}

/// A walked stack's frames, innermost first.
pub fn stack_frames(frames: &[unwind::StackFrame]) -> Vec<StackFrame> {
    frames.iter().enumerate().map(|(index, frame)| stack_frame(index, frame)).collect()
}

/// Decoded instructions.
pub fn disasm_rows(rows: &[DisasmRow]) -> Vec<DisassembledInstruction> {
    let mut formatter = disasm_formatter();
    rows.iter()
        .map(|row| DisassembledInstruction {
            ip: row.ip,
            hex: row.hex.clone(),
            asm: row.asm(),
            comment: row.comment.clone(),
            length: row.length,
            mnemonic: row.mnemonic(&mut formatter),
            operands: row
                .operands(&mut formatter)
                .into_iter()
                .map(operand)
                .collect(),
        })
        .collect()
}

/// One operand of a decoded instruction.
fn operand(operand: DisasmOperand) -> Operand {
    Operand {
        kind: operand.kind.as_str(),
        text: operand.text,
        register: operand.register,
        full_register: operand.full_register,
        base: operand.base,
        index: operand.index,
        scale: operand.scale,
        displacement: operand.displacement,
        size: operand.size,
        segment: operand.segment,
        immediate: operand.immediate,
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

/// One module load or unload filter (`sx`).
pub fn module_event_policy(policy: &exception_policy::ModuleEventPolicy) -> ModuleEventPolicy {
    ModuleEventPolicy {
        event: policy.event.filter_name(),
        module: policy.module.clone(),
        mode: policy.mode.name(),
        command: policy.command.clone(),
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
