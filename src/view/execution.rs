//! Debugger execution-state [`View`] builders: run status,
//! vCPUs, breakpoints, exception policies, stacks, call traces, and
//! disassembly.

use crate::types::Keyed;
use ntoseye_macros::record;

use super::hypervisor::{DecodedHypercall, ServedVp, decoded_hypercall, exit_registers, served_vp};
use crate::breakpoints::{self, Breakpoint};
use crate::exception_policy::{self, ExceptionPolicyFinalAction, exception_alias};
use crate::guest::ProcessInfo;
use crate::guest::exit_reason_name;
use crate::guest::hypercalls::tlfs_hypercall;
use crate::guest::vm_exits;
use crate::session::{self, CallTraceEnd, VcpuInfo};
use crate::target::ThreadInfo;
use crate::types::VirtAddr;
use crate::unwind::{
    self, Arm64CodeDetail, Arm64UnwindDetail, FunctionEntryDetail, HandlerDetail, UnwindDetail,
};

/// A vCPU (backend execution context) and the guest code that it runs.
#[record]
pub struct VcpuStatus {
    /// The backend thread/vCPU ID (`p1.1`).
    pub id: String,
    /// None if ntoseye cannot read the register context.
    #[record(hex)]
    pub rip: Option<u64>,
    /// What the vCPU runs: `kernel`, a process name, `hypervisor`, `VTL1`,
    /// a guest partition's VP (`partition 0x3 VP 1`), or `unknown`; `no
    /// context` for a dump CPU whose context the dump lacks. Empty if
    /// ntoseye cannot read the register context.
    pub context: String,
    /// The nearest symbol to `rip`, if one resolves.
    pub symbol: Option<String>,
    /// For a vCPU halted in the Windows hypervisor, the VTL states that the
    /// hypervisor saved for the vCPU's virtual processor, VTL0 first.
    pub saved_vtl: Vec<SavedVtlState>,
    /// For a vCPU halted in the Windows hypervisor, the guest partition's
    /// virtual processor whose exit it handles or that it is about to
    /// enter, when it is not one of the root partition's.
    pub serving: Option<ServedVp>,
    /// The reason that the register context is not available. None if it is
    /// available.
    pub error: Option<String>,
}

/// One VTL of a virtual processor, as the Windows hypervisor last saved it
/// in the VTL's Enlightened VMCS. A VMCS holds no general-purpose register
/// other than `rsp`; `general_registers` has the others when they are known.
#[record]
pub struct SavedVtlState {
    /// 0 or 1.
    pub vtl: u8,
    /// Whether the VP assist page names this state's eVMCS as current. The
    /// current VTL is the one that entered the hypervisor or that the
    /// hypervisor is about to enter.
    pub current: bool,
    pub rip: VirtAddr,
    /// The symbol at `rip` in the VTL's address space, if one resolves.
    pub symbol: Option<String>,
    pub rsp: VirtAddr,
    #[record(hex)]
    pub rflags: u64,
    #[record(hex)]
    pub cr0: u64,
    /// The page-table root of the VTL.
    #[record(hex)]
    pub cr3: u64,
    #[record(hex)]
    pub cr4: u64,
    #[record(hex)]
    pub dr7: u64,
    #[record(hex)]
    pub cs: u16,
    #[record(hex)]
    pub ss: u16,
    #[record(hex)]
    pub ds: u16,
    #[record(hex)]
    pub es: u16,
    #[record(hex)]
    pub fs: u16,
    #[record(hex)]
    pub gs: u16,
    pub fs_base: VirtAddr,
    pub gs_base: VirtAddr,
    /// The VM-exit reason of the last exit from the VTL. Bits 15:0 hold the
    /// basic reason, and bit 31 is set for a failed VM entry.
    #[record(hex)]
    pub exit_reason: u32,
    /// The name of the exit reason (`HLT`, `VMCALL`, ...), if it is a
    /// common reason.
    pub exit_reason_name: Option<&'static str>,
    /// Reason-specific detail of the last exit, such as the access that
    /// caused an EPT violation (Intel SDM, exit qualification).
    #[record(hex)]
    pub exit_qualification: u64,
    /// The vector and type of the event behind an exception or interrupt
    /// exit (Intel SDM, VM-exit interruption information).
    #[record(hex)]
    pub exit_interruption_info: u32,
    /// The length of the instruction that caused the exit, for exits that
    /// an instruction caused.
    pub exit_instruction_length: u32,
    /// The hypervisor's VM-exit entry point.
    pub host_rip: VirtAddr,
    /// The stack the hypervisor's VM-exit entry point runs on.
    pub host_rsp: VirtAddr,
    /// The vCPU is stopped on `host_rip`, and not by a breakpoint there.
    /// KVM writes the eVMCS when it enters the hypervisor, and a stop from
    /// outside can fall between a VM exit and that entry, so this state
    /// may still describe the exit before the one in progress. The
    /// guest's general-purpose registers are then still in the vCPU's own
    /// registers. A breakpoint on `host_rip` fires after the write.
    /// Only the current state, the exiting VTL's, can be behind; when no
    /// state of the VP is current, every state is marked.
    pub may_be_stale: bool,
    /// The guest's general-purpose registers other than `rsp` at the last
    /// exit (`rax` to `r15`), read where the hypervisor's VM-exit entry
    /// code saved them. Experimental: where that is, is read off the
    /// entry code. None when they are not known: for a VTL that is not
    /// the current one, while the vCPU is on `host_rip` (unless it stopped
    /// there on a breakpoint, when they are the vCPU's own) or still saving
    /// them, or when the entry code does not save them in one block.
    #[record(hex)]
    pub general_registers: Option<Keyed<u64>>,
    /// The physical address of the eVMCS page that ntoseye read the state
    /// from.
    #[record(hex)]
    pub evmcs: u64,
    /// The hypercall of a VMCALL exit whose general-purpose registers are
    /// known, with its input decoded.
    pub hypercall: Option<DecodedHypercall>,
}

/// A code breakpoint or data watchpoint (`bl`).
#[record]
pub struct BreakpointStatus {
    pub id: u32,
    /// None while a symbolic or source breakpoint is deferred.
    pub address: Option<VirtAddr>,
    pub enabled: bool,
    /// Whether the breakpoint resolved to an address. Use it to tell a
    /// deferred breakpoint from a disabled one.
    pub resolved: bool,
    /// Whether a symbolic or source specification waits for resolution.
    pub deferred: bool,
    /// The symbolic or source specification (`bu`/`bm`), which ntoseye
    /// keeps when it resolves the breakpoint again.
    pub specification: Option<String>,
    /// The display name of the current resolution.
    pub symbol: Option<String>,
    /// `global`, or the process that the breakpoint is limited to
    /// (`name (pid)`).
    pub scope: String,
    /// The only thread that can report a hit (`/t`: `tid N` or
    /// `ethread 0x...`). None if there is no thread restriction.
    pub thread: Option<String>,
    /// The only processor that can report a hit (`/c`). None if there is no
    /// processor restriction.
    pub processor: Option<u16>,
    /// The hypercall a hit must be handling, and from which caller, for a
    /// hypercall breakpoint (`!hvbp`). None for any other breakpoint.
    pub hypercall: Option<HypercallFilter>,
    /// The VM exit a hit must be handling, and from which caller, for a
    /// VM-exit breakpoint (`!hvexit`). None for any other breakpoint.
    pub vm_exit: Option<ExitFilter>,
    /// The guest partition of the Windows hypervisor whose VPs a hit
    /// must be on, for a breakpoint set in its view (`.partition`). None
    /// for the target's own breakpoints.
    pub partition: Option<PartitionFilter>,
    /// The condition expression that a hit must satisfy.
    pub condition: Option<String>,
    /// The requested hit number. Both 0 and 1 break on the first hit.
    pub pass_count: u64,
    pub hit_count: u64,
    /// The number of hits that remain before the breakpoint breaks.
    pub remaining_pass_count: u64,
    /// Whether ntoseye removes the breakpoint after its first break.
    pub one_shot: bool,
    /// The commands that run when the breakpoint breaks.
    pub action: Option<String>,
    pub temporary: bool,
    /// `write` or `read_write` for a data watchpoint. None for a code
    /// breakpoint.
    pub watch_access: Option<&'static str>,
    /// The watched width in bytes. None for a code breakpoint.
    pub watch_length: Option<u8>,
}

/// What a hypercall breakpoint (`!hvbp`) stops on: one call code, from
/// any caller or from one partition or VP of the Windows hypervisor.
#[record]
pub struct HypercallFilter {
    /// The call code: the low 16 bits of the caller's RCX.
    #[record(hex)]
    pub code: u16,
    /// The TLFS name, or None for a code that the TLFS does not list.
    pub name: Option<&'static str>,
    /// The caller's partition ID. None for any caller.
    pub partition: Option<u64>,
    /// The caller's VP index in `partition`. None for any VP.
    pub vp: Option<u32>,
}

/// What a VM-exit breakpoint (`!hvexit`) stops on: one basic exit
/// reason, from any VP or from one partition or VP of the Windows
/// hypervisor.
#[record]
pub struct ExitFilter {
    /// The basic exit reason (Intel SDM Appendix C).
    pub reason: u16,
    /// Its name, or None for a reason ntoseye does not name.
    pub name: Option<&'static str>,
    /// The caller's partition ID. None for any caller.
    pub partition: Option<u64>,
    /// The caller's VP index in `partition`. None for any VP.
    pub vp: Option<u32>,
}

/// The guest partition a breakpoint set in its view (`.partition`)
/// stops in: a hit by any other VP than the partition's resumes.
#[record]
pub struct PartitionFilter {
    /// The partition ID.
    pub partition: u64,
    /// The VP index a hit must be on (`/c` in the view). None for any of
    /// the partition's VPs.
    pub vp: Option<u32>,
}

/// Whether the target runs, and where it stopped.
#[record]
pub struct RunStatus {
    pub running: bool,
    /// The selected backend thread/vCPU.
    pub current_thread: String,
    /// The instruction pointer when halted. None while the target runs.
    #[record(hex)]
    pub rip: Option<u64>,
    /// The nearest symbol to `rip` when halted. For code outside NT, the
    /// name identifies that code (`hv+0x3a6bde`).
    pub symbol: Option<String>,
    /// For a vCPU halted in the Windows hypervisor, the VTL states that the
    /// hypervisor saved for the vCPU's virtual processor, VTL0 first.
    pub saved_vtl: Vec<SavedVtlState>,
    /// For a vCPU halted in the Windows hypervisor, the guest partition's
    /// virtual processor it serves, as `VcpuStatus.serving`.
    pub serving: Option<ServedVp>,
    /// The guest partition's virtual processor that the halted vCPU runs
    /// (`partition 0x5 VP 2`), whose registers and code the vCPU then
    /// shows, or None.
    pub running_vp: Option<String>,
    /// The process that you selected with `.process`. `dt`, `dq`, and
    /// similar commands read its memory, and the selection stays after the
    /// target resumes.
    pub attached_process: Option<ProcessInfo>,
    /// The process whose page tables the stopped vCPU has loaded.
    pub stopped_process: Option<ProcessInfo>,
    /// The Windows thread that the stopped vCPU runs. Its owner can be
    /// different from `stopped_process` (`KeStackAttachProcess`).
    pub stopped_thread: Option<ThreadInfo>,
    /// False after a reboot until the kernel's loaded-module list exists,
    /// and process and module enumeration is not valid until then.
    pub coherent: bool,
    /// The `nt` base that ntoseye found again. It changes across a reboot.
    #[record(hex)]
    pub kernel_base: u64,
    /// The hypervisor partition whose Windows guest is inspected in place
    /// of the target (`.partition`), or None while the target is. Every
    /// other field is then that guest's.
    #[record(hex)]
    pub partition: Option<u64>,
}

/// One frame of a stack walk.
#[record]
pub struct StackFrame {
    /// The position of the frame in the stack walk. The innermost frame is 0.
    pub index: usize,
    /// The instruction pointer.
    #[record(hex)]
    pub ip: u64,
    /// The stack pointer.
    #[record(hex)]
    pub sp: u64,
    /// The symbol at `ip`. Empty if no symbol resolves.
    pub symbol: String,
    /// True for a call that the compiler inlined into the physical frame
    /// after it, so the call has no stack frame of its own. `symbol` is the
    /// inlined function, and `ip` and `sp` are those of the physical frame.
    pub inline: bool,
    /// How ntoseye recovered the frame: `current`, `seed`, `unwind`,
    /// `prolog` (read off its function's prolog, for the Windows
    /// hypervisor's code without its file), or `scan`.
    pub source: &'static str,
    /// The source line of the frame, if line information resolves it. For
    /// an inline frame this is the line in the inlined function, and for a
    /// caller it is the line of the call.
    pub source_location: Option<crate::symbols::SourceLocation>,
}

/// The function-table entry that covers an address, and the entry of each
/// chained parent (`.fnent`).
#[record]
pub struct FunctionEntry {
    /// The module that contains the function.
    pub module: String,
    #[record(hex)]
    pub image_base: u64,
    /// The entry that covers the address, then each parent that its chained
    /// unwind info names, in order.
    pub entries: Vec<RuntimeFunction>,
    /// The reason that the chain ends before its last parent. None if the
    /// chain is complete.
    pub incomplete: Option<String>,
}

/// One function-table entry and its unwind data. Addresses are absolute,
/// and the `*_rva` fields hold the raw image-relative values.
#[record]
pub struct RuntimeFunction {
    #[record(hex)]
    pub begin: u64,
    #[record(hex)]
    pub end: u64,
    #[record(hex)]
    pub begin_rva: u32,
    #[record(hex)]
    pub end_rva: u32,
    /// The address of the unwind info. None for ARM64 packed unwind data.
    #[record(hex)]
    pub unwind_info: Option<u64>,
    /// The raw unwind word of the entry: the RVA of the unwind info, or
    /// the packed unwind data on ARM64.
    #[record(hex)]
    pub unwind_data: u32,
    /// The symbol at `begin`.
    pub symbol: String,
    /// The decoded unwind data. None if ntoseye cannot read it.
    pub unwind: Option<Unwind>,
}

/// AMD64 `UNWIND_INFO`.
#[record]
pub struct Amd64UnwindInfo {
    /// `amd64`.
    pub form: &'static str,
    pub version: u8,
    /// `UNW_FLAG_*` bits.
    pub flags: u8,
    /// The size of the prolog, in bytes.
    pub prolog_size: u8,
    /// The number of unwind-code slots.
    pub code_count: u8,
    /// The frame pointer register, if the function sets one up.
    pub frame_register: Option<&'static str>,
    /// The frame pointer's offset from the stack pointer, in bytes.
    pub frame_offset: u32,
    /// The size of the structure in bytes, covering the header, the codes,
    /// and the handler RVA or the chained entry, but not the handler's
    /// data.
    pub size: usize,
    pub codes: Vec<Amd64UnwindCode>,
    /// The exception or termination handler, for `UNW_FLAG_EHANDLER` or
    /// `UNW_FLAG_UHANDLER`.
    pub handler: Option<UnwindHandler>,
}

/// One AMD64 unwind code.
#[record]
pub struct Amd64UnwindCode {
    /// The index of the first slot of the code.
    pub slot: usize,
    /// The prolog offset of the end of the instruction that the code
    /// undoes.
    pub code_offset: u8,
    /// The `UWOP_*` operation.
    pub op: u8,
    /// The info nibble of the operation.
    pub op_info: u8,
    /// The operation and its operands, for example
    /// `UWOP_SAVE_NONVOL rbx at +0x30`.
    pub description: String,
}

/// The exception or termination handler of an unwind info.
#[record]
pub struct UnwindHandler {
    #[record(hex)]
    pub address: u64,
    pub symbol: String,
    /// The start address of the language-specific data of the handler.
    #[record(hex)]
    pub data: u64,
}

/// ARM64 unwind data that is packed into the `.pdata` entry (flag 1 or 2).
/// It describes a canonical prolog, and ntoseye lists it as the codes that
/// it represents.
#[record]
pub struct Arm64PackedUnwind {
    /// `packed`.
    pub form: &'static str,
    /// 1, or 2 for a function fragment without a prolog.
    pub flag: u32,
    /// The `RegF` field: the saved non-volatile floating-point registers.
    pub reg_f: u32,
    /// The `RegI` field: the saved non-volatile integer registers.
    pub reg_i: u32,
    /// Whether the prolog stores the argument registers in their home
    /// locations.
    pub homes_arguments: bool,
    /// The `CR` field: whether and how the prolog saves the frame chain
    /// and the link register.
    pub cr: u32,
    /// The size of the frame, in bytes.
    pub frame_size: u32,
    pub codes: Vec<Arm64UnwindCode>,
}

/// An ARM64 `.xdata` unwind record.
#[record]
pub struct Arm64XdataUnwind {
    /// `xdata`.
    pub form: &'static str,
    pub version: u32,
    /// The `X` bit: exception data (a handler) follows.
    pub exception_data: bool,
    /// The `E` bit: the header describes a single epilog.
    pub epilog_in_header: bool,
    pub epilog_count: u32,
    /// The number of 32-bit words of unwind codes.
    pub code_words: u32,
    pub epilog_scopes: Vec<Arm64EpilogScope>,
    /// The size of the record in bytes, including the RVA of the handler.
    pub size: usize,
    pub codes: Vec<Arm64UnwindCode>,
    pub handler: Option<UnwindHandler>,
}

/// One ARM64 unwind code.
#[record]
pub struct Arm64UnwindCode {
    /// The index of its first byte in the code bytes.
    pub index: usize,
    #[record(hex)]
    pub bytes: Vec<u8>,
    /// Its name and the prolog instruction that it represents.
    pub description: String,
}

/// One ARM64 epilog scope.
#[record]
pub struct Arm64EpilogScope {
    /// The start of the epilog, in bytes from the start of the function.
    #[record(hex)]
    pub start_offset: u32,
    /// The index of the first unwind code of the epilog.
    pub first_code: u32,
}

/// A `wt` call trace: why it stopped, the instructions that it stepped,
/// and the call tree.
#[record]
pub struct CallTrace {
    /// `returned`, `limit`, `interrupted`, `breakpoint`, `diverted`, or
    /// `failed`. `interrupted` means Ctrl+C or the `timeout` ended it.
    /// `diverted` means that an interrupt diverted a step and the traced
    /// thread is not known. Any value other than `returned` means that
    /// the tree is partial.
    pub end: &'static str,
    /// A description of the failure, for `failed`.
    pub error: Option<String>,
    /// The number of single-stepped instructions.
    pub instructions: usize,
    pub root: CallTraceFrame,
}

/// One call-tree node of a `wt` trace.
#[record]
pub struct CallTraceFrame {
    /// The called function.
    pub name: String,
    /// The number of instructions stepped in the function itself.
    pub instructions: usize,
    /// The calls that the function made.
    pub children: Vec<CallTraceFrame>,
}

/// One exception stop policy (`sx`).
#[record]
pub struct ExceptionPolicy {
    /// The exception code.
    #[record(hex)]
    pub code: u32,
    /// The WinDbg alias of the code (`av`, `bp`, ...), if it has one.
    pub alias: Option<&'static str>,
    /// `break`, `second_chance`, `notify`, or `ignore`.
    pub mode: &'static str,
    /// An explicit final action: `break`, or continue as `handled` or
    /// `not_handled`. None for the default action of the mode.
    pub disposition: Option<&'static str>,
    /// The commands that run when the exception occurs.
    pub command: Option<String>,
}

/// One module load or unload filter (`sx* ld[:<module>]` or
/// `sx* ud[:<module>]`).
#[record]
pub struct ModuleEventPolicy {
    /// `ld` for a load filter, `ud` for an unload filter.
    pub event: &'static str,
    /// The image-name glob that the filter matches, with or without
    /// extension. None for all modules (bare `ld` or `ud`).
    pub module: Option<String>,
    /// `break` stops at the event, and `notify` reports it.
    /// `second_chance` and `ignore` let the load or unload continue with
    /// no output.
    pub mode: &'static str,
    /// The commands that run at a `break` stop.
    pub command: Option<String>,
}

/// An evaluated debugger expression (`?`).
#[record]
pub struct ExpressionValue {
    pub expression: String,
    pub value: VirtAddr,
}

/// An entry's decoded unwind data, by form.
#[record]
pub enum Unwind {
    Amd64(Amd64UnwindInfo),
    Packed(Arm64PackedUnwind),
    Xdata(Arm64XdataUnwind),
}

pub fn vcpu(v: &VcpuInfo) -> VcpuStatus {
    VcpuStatus {
        id: v.id.clone(),
        rip: v.rip,
        context: v.context.clone(),
        symbol: v.symbol.clone(),
        saved_vtl: v.saved_vtl.iter().map(saved_vtl_state).collect(),
        serving: v.serving.as_ref().map(served_vp),
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
        exit_qualification: state.exit_qualification,
        exit_interruption_info: state.exit_interruption_info,
        exit_instruction_length: state.exit_instruction_length,
        host_rip: VirtAddr(state.host_rip),
        host_rsp: VirtAddr(state.host_rsp),
        may_be_stale: saved.context.may_be_stale,
        general_registers: saved
            .context
            .general_registers
            .as_ref()
            .ok()
            .map(exit_registers),
        evmcs: state.address,
        hypercall: saved.context.hypercall.call().map(decoded_hypercall),
    }
}

/// What a hypercall breakpoint stops on.
pub fn hypercall_filter(filter: &breakpoints::HypercallFilter) -> HypercallFilter {
    HypercallFilter {
        code: filter.code,
        name: tlfs_hypercall(filter.code).map(|(name, _)| name),
        partition: filter.partition,
        vp: filter.vp,
    }
}

/// What a VM-exit breakpoint stops on.
pub fn exit_filter(filter: &vm_exits::ExitFilter) -> ExitFilter {
    ExitFilter {
        reason: filter.reason,
        name: exit_reason_name(u32::from(filter.reason)),
        partition: filter.partition,
        vp: filter.vp,
    }
}

/// Which guest partition a breakpoint set in its view stops in.
pub fn partition_filter(filter: &breakpoints::PartitionFilter) -> PartitionFilter {
    PartitionFilter {
        partition: filter.partition,
        vp: filter.vp,
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
        hypercall: bp.hypercall.as_ref().map(hypercall_filter),
        vm_exit: bp.vm_exit.as_ref().map(exit_filter),
        partition: bp.partition.as_ref().map(partition_filter),
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
        serving: status.serving.as_ref().map(served_vp),
        running_vp: status.running_vp.clone(),
        attached_process: status.attached_process.clone(),
        stopped_process: status.stopped_process.clone(),
        stopped_thread: status.stopped_thread.clone(),
        coherent: status.coherent,
        kernel_base: status.kernel_base,
        partition: status.partition,
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
        source_location: frame.source_location.clone(),
    }
}

/// A walked stack's frames, innermost first.
pub fn stack_frames(frames: &[unwind::StackFrame]) -> Vec<StackFrame> {
    frames
        .iter()
        .enumerate()
        .map(|(index, frame)| stack_frame(index, frame))
        .collect()
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
