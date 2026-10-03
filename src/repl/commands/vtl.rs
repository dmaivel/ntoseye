use tabled::builder::Builder;

use super::memory::MAX_DISASSEMBLY_INSTRUCTIONS;
use super::memory::MAX_DISPLAY_BYTES;
use crate::dbg_backend::processor_index_from_backend_thread_id;
use crate::error::{Error, Result};
use crate::guest::{
    EvmcsState, HvPartition, HvProcessor, HvVirtualProcessor,
    ept::{self, Access, EptTranslation},
    evmcs_fields::{self, IoIntercepts, MsrIntercepts},
    hypercall_input::{DecodedHypercall, HypercallField},
    hypercalls::{HypercallCaller, HypercallInput, tlfs_hypercall},
    privilege_names,
};
use crate::repl::memory_view::{MemoryDisplayMode, display_memory_with_validity, eval_range};
use crate::repl::*;
use crate::target::{CodeExtent, VP_STATE_REGISTERS};
use crate::types::VirtAddr;
use crate::ui;
use crate::unwind::{halted_in_windows_hypervisor, try_format_symbol_at};
use std::collections::{HashMap, HashSet};

repl_command! {
    cmd_vtl;
    names: [".vtl"],
    usage: ".vtl [0|1 [pid]]",
    summary: "Select NT (VTL0) or secure-kernel (VTL1) memory inspection, or show which one is active.",
    details: "VTL1 requires AMD64 direct host memory. `.vtl 1` changes the scope of reads and symbols, but does not change the VTL of the CPU. With no argument, `.vtl` shows the current scope. `.vtl 0` goes back to the NT kernel. After `.vtl 1`, it returns to the view the stop selected, which at a stop in the Windows hypervisor is where NT left off; otherwise, at a stop in VTL1 or in the Windows hypervisor, it selects the address space of the vCPU, where you use `.vtlcxr` or `.thread` to select NT. `.vtl 1` selects the system address space of the secure kernel, and `.vtl 1 <pid>` selects the address space of a trustlet by its NT PID, which is always decimal. The VTL1 scope is a read-only memory view. Registers, stepping, software breakpoints, writes, and NT-specific extensions need .vtl 0. To stop in VTL1, set a hardware execute breakpoint there (`ba e1 securekernel!<function>`, GDB backends), and then resume with a plain `g`, which first goes back to the live context. A vCPU stopped in VTL1 shows its real registers, stack, and memory. With no argument, `.vtl` also shows whether reads follow such a live stop or the manual view.",
}

repl_command! {
    cmd_trustlets();
    names: ["!trustlets"],
    usage: "!trustlets",
    summary: "List the validated VTL1 processes with their NT identities and address-space roots.",
    details: "Reads SkpsProcessList through the page tables of the secure kernel. Each row shows the secure-kernel process object, the NT PID and image name, the trustlet ID, and the address-space root. If the internal layout is not supported, the command gives an error and does not guess offsets. The command does not change the scope.",
}

repl_command! {
    cmd_hvpartitions();
    names: ["!hvpartitions"],
    usage: "!hvpartitions",
    summary: "Show the partitions of the Windows hypervisor as a tree, with their virtual processors.",
    details: "Walks the hypervisor's partition objects from its processor blocks, which come from the eVMCS pages (the VM's hv-evmcs enlightenment) or from a vCPU stopped in the hypervisor. Each child partition is below its parent, with its partition ID and object, and below each partition are its privilege mask (HV_PARTITION_PRIVILEGE_MASK) with the TLFS names, then each VP: the processor whose current VP it is, the VTL it runs or last ran in (the other enabled VTLs after it), the guest RIP where that VTL left off, named from symbols for the root partition's VPs, and why it last left for the hypervisor. !hvvps shows each VTL of a partition's VPs in full. hvix64 has no public symbols, so the offsets are read off the hypervisor's own code and each object is validated before it is shown; if the layout is not recognized, the command gives an error and does not guess offsets. Intel hosts only.",
}

repl_command! {
    cmd_hvvps;
    names: ["!hvvps"],
    usage: "!hvvps [partition-id]",
    summary: "List the virtual processors of a Windows hypervisor partition (the root by default).",
    details: "Each row is one VTL enabled on a VP, and * marks the VTL the VP runs or last ran in. CPU is the processor whose current VP it is (the one that runs it, or ran it last), by number, or by processor block on builds before 10.0.19041, which keep no number there. The row shows the hypervisor's context object for the VTL and, when found, the physical address of the VTL's eVMCS with the EPT pointer (the root of the VTL's second-level address translation), the guest RIP where the VTL left off, and why it last left for the hypervisor. The eVMCS columns need the VM's hv-evmcs enlightenment. The partition ID uses the current radix. See !hvpartitions for where the objects come from.",
}

repl_command! {
    cmd_hvept;
    names: ["!hvept"],
    usage: "!hvept [-v] <address> [partition-id [vp-index]]",
    summary: "Translate a guest physical address through each VTL's EPT (second-level address translation) of a Windows hypervisor VP.",
    details: "Walks the extended page tables that each enabled VTL's eVMCS names, by default for the VP the current vCPU's processor runs (with -v the root partition's), or the root partition's VP 0. The address is guest physical, or with -v virtual in the current address space (the .process or VTL1 scope), which the command translates through the guest's page tables first; that space is the root partition's, so -v takes only a root partition VP. Each row shows the VTL, its EPT pointer, the host physical address, the access that every level of the walk allows (r, w, and x, where x is supervisor-mode execute when the VTL uses mode-based execute control), user-mode execute under that control, the page size, and the memory type, or the level where the walk found no entry. This is how memory integrity (HVCI) and the secure kernel set page permissions that NT cannot change. The address and IDs use the current radix. Needs the VM's hv-evmcs enlightenment. See !hvpartitions for where the objects come from.",
}

repl_command! {
    cmd_hveptdiff;
    names: ["!hveptdiff"],
    usage: "!hveptdiff [partition-id [vp-index]]",
    summary: "List the guest physical ranges that VTL0's and VTL1's EPTs of a Windows hypervisor VP map differently.",
    details: "Walks the whole EPT of VTL0 and of VTL1 of a VP, by default the one the current vCPU's processor runs (a guest partition's first), else the root partition's VP 0, and lists each range of guest physical memory that the two map with different access, or that only one of them maps, with the access in each (r, w, x, and u for user-mode execute under mode-based execute control). Adjacent ranges that differ the same way are merged. These are the pages that the secure kernel and memory integrity (HVCI) protect from NT. The IDs use the current radix. Needs VBS and the VM's hv-evmcs enlightenment.",
}

repl_command! {
    cmd_hvcalls;
    names: ["!hvcalls"],
    usage: "!hvcalls [-a]",
    summary: "List the hypercalls the Windows hypervisor implements, from its hypercall table.",
    details: "Reads the hypervisor's hypercall table and shows, for each call code, the name the Hyper-V TLFS gives it (when the TLFS documents it), whether it is a simple or a rep call (var marks a variable-size input header), the sizes of its fixed input and output and of each rep element, and its handler in the hv image. Codes that share the handler of the reserved code 0 are not implemented; -a lists them too. Needs the VM's hv-evmcs enlightenment or a vCPU stopped in the hypervisor.",
}

repl_command! {
    cmd_hvcall();
    names: ["!hvcall"],
    usage: "!hvcall",
    summary: "Decode the hypercall that the current vCPU's processor handles in the Windows hypervisor.",
    details: "For a vCPU halted in the Windows hypervisor, for example on a breakpoint on a hypercall handler (ba e1 hv!HvCallFlushVirtualAddressList), shows the hypercall of the VMCALL exit that its processor handles: the caller (a VTL of the root partition, or the guest partition's VP that the processor serves), the call code with its TLFS name, the flags (fast, variable header size, nested), a rep call's start and count, the GPAs of the input and output, and each field of the input as the Hyper-V TLFS lays it out, with names for special values, processor sets, flags, and the common register names, then each element of a rep call's input list. A slow call's input is read at its GPA through the EPT of the calling VTL. A fast call's input is RDX and R8, then, for an XMM fast call, XMM0 to XMM5 as the hypervisor's VM-exit entry code saved them; when they are not known, it says what is missing. A call whose layout ntoseye does not know shows its input as raw qwords. The command needs the general-purpose registers of the exit, which ntoseye reads where the hypervisor's VM-exit entry code saved them, so it explains why when the vCPU is still on the entry or the last exit was not a VMCALL. Needs the VM's hv-evmcs enlightenment.",
    run_state: Halted,
}

repl_command! {
    cmd_hvvmcs;
    names: ["!hvvmcs"],
    usage: "!hvvmcs [-msr|-io] [partition-id [vp-index [vtl]]]",
    summary: "Show the eVMCS of a VTL of a Windows hypervisor VP, or the MSRs and I/O ports it intercepts.",
    details: "Reads the Enlightened VMCS of a VTL, by default the VP the current vCPU's processor runs (a guest partition's first, else the root partition's) and the VTL it runs in, and shows each field with its offset and value. With -msr, it shows the MSRs whose reads and writes the VTL's MSR bitmap intercepts, with the architectural MSRs each range holds, and then the architectural MSRs the VTL reads and writes without an exit; MSRs outside the bitmap's 0x0-0x1fff and 0xc0000000-0xc0001fff always exit. With -io the I/O ports its I/O bitmaps intercept, or that every access is intercepted when the VM-execution controls do not use the bitmaps. The layout is the Hyper-V TLFS's, so this does not depend on the hypervisor build. The IDs use the current radix. Needs the VM's hv-evmcs enlightenment.",
}

repl_command! {
    cmd_hvd;
    names: ["!hvd"],
    usage: "!hvd [-p] [-b|-d|-q] [<partition-id> <vp-index>] <address> [range]",
    summary: "Display the memory of a Windows hypervisor partition's guest (a Hyper-V VM, WSL2, Windows Sandbox).",
    details: "Reads the guest's memory through the EPT of the VTL its VP runs in, as its eVMCS names them: guest virtual memory through the VP's page tables (its CR3), or with -p guest physical memory. Without a partition and VP it reads the guest VP that the current vCPU's processor runs, as ~ and a stop in the hypervisor name it. -b shows bytes (the default), -d dwords, and -q qwords. The range is L<count>, an end address, or a byte length, as for db. Unreadable pages show as ??. The memory is read-only, and ntoseye has no symbols for the guest. The numbers use the current radix. Needs the VM's hv-evmcs enlightenment.",
}

repl_command! {
    cmd_hvu;
    names: ["!hvu"],
    usage: "!hvu [-p] [<partition-id> <vp-index>] <address> [range]",
    summary: "Disassemble the memory of a Windows hypervisor partition's guest (a Hyper-V VM, WSL2, Windows Sandbox).",
    details: "Reads the guest's memory as !hvd does: guest virtual memory through the page tables (CR3) and EPT of the VTL its VP runs in, or with -p guest physical memory through the EPT. Without a partition and VP it reads the guest VP that the current vCPU's processor runs. The code decodes in the mode the VTL left off in, by its eVMCS: 64-bit in IA-32e mode with a 64-bit code segment, else 32-bit; real mode and 16-bit code give an error. The range is as for u: L<count> instructions (8 by default), or an end address or byte length, listing every instruction that starts before the range ends. The listing stops at the first unreadable page and says where. ntoseye has no symbols for the guest, so branch targets and RIP-relative operands show as addresses. The numbers use the current radix. Needs the VM's hv-evmcs enlightenment.",
}

/// How two VTLs' access to a range differs: VTL0's, then VTL1's.
type DifferenceKind = (Option<Access>, Option<Access>);

repl_command! {
    cmd_hvr;
    names: ["!hvr"],
    usage: "!hvr [partition-id vp-index [vtl]]",
    summary: "Show the registers of a VTL of a Windows hypervisor VP, whether or not a processor runs it.",
    details: "By default the VP the current vCPU's processor runs (a guest partition's first, else the root partition's) and the VTL it runs in. For a VP that a vCPU runs now, they are that vCPU's; for one whose exit a vCPU in the hypervisor handles, those of that exit; otherwise those the VP saved at its last exit, read from its register block through the descriptor of its register region, which no processor maps while the VP does not run. The VP resumes with them but for what the hypervisor writes as the exit's result, such as a hypercall's status in RAX. RIP, RSP, flags, control and segment registers come from the VTL's eVMCS. The general-purpose registers are shared by a VP's VTLs and belong to the one it runs in; another VTL shows its eVMCS state only. The IDs use the current radix. Needs the VM's hv-evmcs enlightenment; builds before 10.0.17763 keep the saved registers on the processor's stack, so a VP no processor runs has none there.",
    run_state: Halted,
}

repl_command! {
    cmd_partition;
    names: [".partition"],
    usage: ".partition [partition-id]",
    summary: "Inspect the Windows guest that a Windows hypervisor partition runs (a Windows Sandbox, a Hyper-V VM) in place of the target, or show which is inspected.",
    details: "With a partition ID, the session inspects that partition's guest instead of the target: its memory is read through the partition's EPT, its NT kernel is found from the page-table root of a VP in kernel mode, and its symbols are loaded, so lm, !process, dt, db, u, k and the other inspection commands read the guest. Its VPs are the threads (p<partition>.<VP index + 1>, so ~Ns selects VP N), with their VTL0 registers, as !hvr <partition> <vp> 0 shows them: a VP that runs in VTL1 has VTL0's RIP, RSP, flags, control and segment registers there, without its general-purpose registers. The view is read-only and the target stays halted: g, steps, breakpoints and writes are refused until you leave it. The root partition's ID (0x1) returns to the target. Without an ID, it shows which partition is inspected. The ID uses the current radix. Needs the VM's hv-evmcs enlightenment and a 64-bit Windows guest.",
    run_state: Halted,
}

/// `registers` three to a row in [`VP_STATE_REGISTERS`] order, as `r` lays
/// them out, leaving out the ones not known.
fn print_vp_registers(registers: &HashMap<String, u64>) {
    for row in VP_STATE_REGISTERS.chunks(3) {
        let cells: Vec<String> = row
            .iter()
            .filter_map(|name| {
                let value = registers.get(*name)?;
                Some(format!(
                    "{} {}",
                    ui::muted(&format!("{name:<7}")),
                    ui::addr(*value)
                ))
            })
            .collect();
        if !cells.is_empty() {
            outln!("  {}", cells.join("   "));
        }
    }
}

/// `access` as `rwx`, or `none` for no mapping.
fn access_text(access: Option<Access>) -> String {
    access.map_or_else(|| "none".to_string(), |access| access.to_string())
}

/// `bytes` in the largest of K, M, and G it reaches, with one decimal when
/// it is not a whole number of them.
fn size_text(bytes: u64) -> String {
    let (unit, name) = match bytes {
        b if b >= 1 << 30 => (1u64 << 30, 'G'),
        b if b >= 1 << 20 => (1 << 20, 'M'),
        _ => (1 << 10, 'K'),
    };
    if bytes.is_multiple_of(unit) {
        format!("{}{name}", bytes / unit)
    } else {
        format!("{:.1}{name}", bytes as f64 / unit as f64)
    }
}

/// The processors whose current VP a VP is, by number, or by processor
/// block where the build keeps no number.
fn processors_text(processors: &[HvProcessor]) -> String {
    processors
        .iter()
        .map(|processor| match processor.number {
            Some(number) => number.to_string(),
            None => format!("{:x}", processor.block),
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// A VP that a command's partition ID and VP index select.
struct SelectedVp {
    partition: u64,
    /// The partition is the root partition.
    root: bool,
    vp: HvVirtualProcessor,
}

/// The VP a hypervisor command shows by default, as indexes into
/// `partitions` and its VPs: the one processor `number` (the current
/// vCPU's) runs or last ran, a guest partition's first unless `root_only`,
/// then the root partition's VP on that processor (its VPs are pinned to
/// the processors with their numbers), then the root's VP 0.
fn default_vp(
    partitions: &[HvPartition],
    number: Option<u16>,
    root_only: bool,
) -> Option<(usize, usize)> {
    let number = number.map(u32::from);
    let runs = |vp: &HvVirtualProcessor| {
        number.is_some_and(|number| {
            vp.processors
                .iter()
                .any(|processor| processor.number == Some(number))
        })
    };
    if !root_only {
        let guest = partitions
            .iter()
            .enumerate()
            .skip(1)
            .find_map(|(at, partition)| {
                let vp = partition.virtual_processors.iter().position(runs)?;
                Some((at, vp))
            });
        if guest.is_some() {
            return guest;
        }
    }
    let root = partitions.first()?;
    let vp = root
        .virtual_processors
        .iter()
        .position(runs)
        .or_else(|| {
            root.virtual_processors
                .iter()
                .position(|vp| number.is_some_and(|number| vp.index == number))
        })
        .unwrap_or(0);
    (vp < root.virtual_processors.len()).then_some((0, vp))
}

/// The name of an EPT memory type (Intel SDM 29.3.7).
fn memory_type_name(memory_type: u8) -> &'static str {
    match memory_type {
        0 => "UC",
        1 => "WC",
        4 => "WT",
        5 => "WP",
        6 => "WB",
        _ => "?",
    }
}

/// What `!hvcall` shows for `caller`, the VP whose exit a processor
/// handles: the lines of its decoded hypercall, or why it has none.
fn hypercall_report(caller: &HypercallCaller) -> std::result::Result<Vec<String>, String> {
    let label = caller.label();
    match &caller.input {
        HypercallInput::Known(call) => Ok(hypercall_lines(&label, call)),
        HypercallInput::NotHypercall => Err(format!(
            "{label} last left for the hypervisor on an exit other than a VMCALL: it made no hypercall"
        )),
        HypercallInput::Unknown(reason) => {
            Err(format!("the hypercall of {label} is unknown: {reason}"))
        }
    }
}

/// The tree `!hvcall` prints for `caller`'s hypercall `call`: the call on
/// the head line, then its input value and flags, its GPAs, each field of
/// its input, and its rep list, the elements before the rep start marked
/// done.
fn hypercall_lines(caller: &str, call: &DecodedHypercall) -> Vec<String> {
    let control = &call.control;
    let mut flags = Vec::new();
    if control.fast {
        flags.push("fast".to_string());
    }
    if control.variable_header_qwords != 0 {
        flags.push(format!(
            "variable header {} qwords",
            control.variable_header_qwords
        ));
    }
    if control.nested {
        flags.push("nested".to_string());
    }
    let mut children = vec![format!(
        "{} {:#018x}{}",
        ui::muted("input value"),
        call.input_value,
        if flags.is_empty() {
            String::new()
        } else {
            format!("  {}", flags.join(", "))
        }
    )];
    match (call.input_gpa, call.output_gpa) {
        (Some(input), Some(output)) => children.push(format!(
            "{} {input:#x}  {} {output:#x}",
            ui::muted("input GPA"),
            ui::muted("output GPA")
        )),
        _ if control.fast => children.push(ui::muted("input in RDX and R8")),
        _ => {}
    }
    if !call.decoded {
        children.push(ui::muted(
            "ntoseye does not know this call's input layout: its first qwords, raw",
        ));
    }
    children.extend(field_lines(&call.fields));
    if !call.elements.is_empty() {
        let done = call
            .elements
            .iter()
            .filter(|element| element.index < control.rep_start)
            .count();
        let count = call.elements.len();
        let mut head = format!(
            "{} {count} element{}",
            ui::muted("rep list"),
            if count == 1 { "" } else { "s" }
        );
        if done != 0 {
            head.push_str(&format!(", {done} done"));
        }
        let elements: Vec<String> = call
            .elements
            .iter()
            .map(|element| {
                let mark = if element.index < control.rep_start {
                    ui::muted("  done")
                } else {
                    String::new()
                };
                let lines = field_lines(&element.fields);
                match lines.as_slice() {
                    [line] => format!("[{}] {line}{mark}", element.index),
                    _ => std::iter::once(format!("[{}]{mark}", element.index))
                        .chain(event_children_lines("", &lines))
                        .collect::<Vec<_>>()
                        .join("\n"),
                }
            })
            .collect();
        children.push(
            std::iter::once(head)
                .chain(event_children_lines("", &elements))
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }
    if let Some(reason) = &call.unavailable {
        children.push(ui::muted(reason));
    }
    std::iter::once(format!("{}  {}", ui::label(caller), call.summary()))
        .chain(event_children_lines("", &children))
        .collect()
}

/// One line per field, `name  value  meaning`, the values aligned and each
/// shown at its size.
fn field_lines(fields: &[HypercallField]) -> Vec<String> {
    let width = fields
        .iter()
        .map(|field| field.name.len())
        .max()
        .unwrap_or(0);
    fields
        .iter()
        .map(|field| {
            let digits = usize::from(field.size) * 2 + 2;
            let meaning = field
                .meaning
                .as_deref()
                .map(|meaning| format!("  {}", ui::muted(meaning)))
                .unwrap_or_default();
            format!(
                "{:<width$}  {:#0digits$x}{meaning}",
                field.name, field.value
            )
        })
        .collect()
}

/// Commands that only read memory through the current root or are
/// debugger-local, so they mean the same in any VTL1 address space. No VTL0
/// register file or mediated write may be interpreted as belonging to the
/// secure kernel. Aliases pass this same gate.
fn secure_inspection_command(spec: &CommandSpec) -> bool {
    matches!(
        spec.names[0],
        ".vtl"
            | "!trustlets"
            | "!hvpartitions"
            | "!hvvps"
            | "!hvept"
            | "!hveptdiff"
            | "!hvcalls"
            | "!hvvmcs"
            | "!hvr"
            | "!hvd"
            | "!hvu"
            | ".process"
            | "attach"
            | "detach"
            | ".context"
            | "db"
            | "dw"
            | "dW"
            | "dc"
            | "dd"
            | "dq"
            | "dp"
            | "dds"
            | "dqs"
            | "dyb"
            | "dpp"
            | "da"
            | "du"
            | "ds"
            | "dS"
            | "u"
            | "uf"
            | "ub"
            | "dt"
            | "dl"
            | "!list"
            | "x"
            | "ln"
            // An explicit root and a page walk; no NT state.
            | "!vtop"
            | "?"
            | "set"
            | "vars"
            | "unset"
            | "lm"
            | "lmv"
            | ".reload"
            | "ld"
            | ".fetchimage"
            | ".sympath"
            | ".sympath+"
            | ".symfix"
            | ".srcpath"
            | ".srcpath+"
            | "n"
            | ".effmach"
            | ".echo"
            | ".printf"
            // Each command it runs passes this gate itself.
            | ".foreach"
            // Walks `lm`'s list, the secure kernel's in VTL1.
            | "!for_each_module"
            // Script control flow; each command it runs passes this gate.
            | ".if"
            | ".elsif"
            | ".else"
            | ".while"
            | ".for"
            | ".do"
            | ".break"
            | ".continue"
            | ".block"
            | "j"
            | "$<"
            | "$$"
            | ".sleep"
            | ".cls"
            | ".logopen"
            | ".logappend"
            | ".logclose"
            | ".hh"
            | "!error"
            | "q"
            | "capabilities"
    )
}

/// Breakpoint bookkeeping and the one resume a VTL1 stop can be reached and
/// left with. The core accepts only GDB hardware execute breakpoints in a
/// VTL1 space; software sites (`bp`, `g <address>`, stepping) would patch or
/// trap code VTL0 cannot see. `g` is refused with an address by its handler.
fn secure_hardware_workflow_command(spec: &CommandSpec) -> bool {
    matches!(
        spec.names[0],
        "ba" | "bl" | ".bpcmds" | "bc" | "bd" | "be" | "bpc" | "bs" | "br" | "bpp" | "g" | "gc"
    )
}

/// vCPU state that is genuinely VTL1's when the backend is stopped there:
/// the live register file (read-only: `r` refuses assignment), its stack,
/// frames, and the processor list, and `.vtlcxr`, which selects a saved
/// VTL state the hypervisor wrote and writes nothing, so a selected VTL1
/// state has a way back to VTL0's. NT structures (KPCR, threads,
/// processes) and `.cxr` (a context record read from memory) stay refused
/// because the secure kernel's state is not laid out as NT's.
fn live_secure_vcpu_command(spec: &CommandSpec) -> bool {
    matches!(
        spec.names[0],
        "r" | "kn"
            | ".frame"
            | ".vtlcxr"
            | "!for_each_frame"
            | "dv"
            | "~"
            | "vcpu"
            | "rdmsr"
            | "break"
            | "status"
            | ".lastevent"
    )
}

/// Whether the explicit `.vtl 1` scope admits `spec`. The scope is a memory
/// view, not a claim that the backend is stopped in VTL1, so it has no
/// register file: only reads, the hardware breakpoint workflow, and a plain
/// `g` (which leaves the scope before resuming) run in it.
pub fn secure_scope_admits(spec: &CommandSpec) -> bool {
    secure_inspection_command(spec) || secure_hardware_workflow_command(spec)
}

/// Whether a live stop whose read root is a VTL1 root admits `spec`: what
/// the explicit scope admits plus the real vCPU state.
pub fn live_secure_admits(spec: &CommandSpec) -> bool {
    secure_scope_admits(spec) || live_secure_vcpu_command(spec) || secure_step_command(spec)
}

/// Run control a live VTL1 stop can take without writing secure-kernel code:
/// steps run the vCPU alone to debug-register sites on an instruction's
/// successors, and run-to targets (`p` over a call, `gu`, `g <address>`)
/// in secure-kernel code take a debug-register site too. A software site
/// anywhere in VTL1 is still refused by the breakpoint core.
fn secure_step_command(spec: &CommandSpec) -> bool {
    matches!(spec.names[0], "t" | "p" | "gu" | "pa" | "ta" | "wt")
}

impl ReplState<'_> {
    /// Why the current VTL1 address space refuses `spec`, if it does. Decided
    /// on the resolved command, after alias expansion, so an alias cannot
    /// reach a write or an NT extension from VTL1.
    pub fn secure_denial(&self, spec: &CommandSpec) -> Option<String> {
        let target = &self.ctx.target;
        let name = spec.names[0];
        if target.in_secure_scope() {
            return (!secure_scope_admits(spec)).then(|| {
                format!(
                    "'{name}' is unavailable in the .vtl 1 memory view (reads, `ba e1`, and plain g \
                     only); use .vtl 0 first"
                )
            });
        }
        if target.in_secure_address_space() && !live_secure_admits(spec) {
            if target
                .selected_frame
                .as_ref()
                .is_some_and(|frame| !frame.is_live())
            {
                return Some(format!(
                    "'{name}' is unavailable while a VTL1 context is selected, which is \
                     read-only; .vtlcxr goes back to VTL0's"
                ));
            }
            return Some(format!(
                "'{name}' is unavailable while the vCPU is stopped in VTL1: it needs NT state, \
                 or writes VTL1 memory, registers, or code"
            ));
        }
        None
    }

    /// Leave the explicit VTL1 scope before a VTL0 selection (`.vtl 0`,
    /// `.process`, `attach`, `detach`, `.context`) or a resume. The live
    /// register file and the root it implies come back, which is a VTL1 root
    /// again when the vCPU is stopped there.
    pub(super) fn leave_vtl1(&mut self) {
        if self.ctx.target.in_secure_scope() {
            self.ctx.target.leave_secure_scope();
            self.ctx.restore_live_register_cache();
            self.caches.refresh_symbol_context(&self.ctx.target);
        }
    }

    fn cmd_vtl(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if let Err(error) = self.select_vtl(invocation) {
            error!("{error}");
        }
        Ok(())
    }

    fn select_vtl(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let mut live_hint = false;
        match (invocation.arg(0), invocation.arg(1), invocation.argv.len()) {
            (None, _, _) => {}
            (Some("0"), None, 1) => {
                // A live VTL1 stop has no explicit scope to leave; its root
                // follows the vCPU. Say how to read NT instead.
                live_hint = !self.ctx.target.in_secure_scope();
                let viewed = !live_hint;
                self.leave_vtl1();
                // Back where the stop left inspection: at a stop in the
                // hypervisor that is the saved VTL0 state, not the
                // hypervisor's registers, which map no NT memory.
                if viewed {
                    self.ctx.reset_to_stop_context();
                    self.caches.refresh_symbol_context(&self.ctx.target);
                }
            }
            (Some("1"), pid, count) if count <= 2 => {
                let pid = pid
                    .map(|text| {
                        text.parse::<u64>().map_err(|_| {
                            Error::InvalidArgument("trustlet PID must be decimal".to_string())
                        })
                    })
                    .transpose()?;
                let report = self.ctx.target.select_secure_scope(pid)?;
                print_module_symbol_report(&report);
                self.ctx.clear_selected_frame();
                self.caches.refresh_symbol_context(&self.ctx.target);
            }
            _ => {
                return Err(Error::InvalidArgument(
                    "usage: .vtl [0|1 [pid]]".to_string(),
                ));
            }
        }
        let target = &self.ctx.target;
        if target.in_secure_scope() {
            let secure = target.secure_kernel()?;
            outln!(
                "VTL1 memory view (.vtl 1, no registers): DTB {}, securekernel {} (system DTB {})\n",
                ui::addr(target.current_dtb()),
                ui::addr(secure.image.base_address.0),
                ui::addr(secure.image.dtb())
            );
        } else if target.in_secure_address_space() {
            let secure = target.secure_kernel()?;
            outln!(
                "VTL1 live stop on vCPU {}: DTB {}, securekernel {} (system DTB {}); registers and stack are VTL1 state",
                self.ctx.current_thread,
                ui::addr(target.current_dtb()),
                ui::addr(secure.image.base_address.0),
                ui::addr(secure.image.dtb())
            );
            if live_hint {
                outln!(
                    "{}",
                    ui::muted(
                        "the vCPU is stopped in VTL1; .process or attach reads an NT address space"
                    )
                );
            }
            outln!();
        } else if let Some(rip) = target.register_value("rip")
            && halted_in_windows_hypervisor(target, target.current_dtb(), rip)
        {
            // Not VTL0: the vCPU halted in the Windows hypervisor, whose root
            // maps no NT memory.
            outln!(
                "hypervisor stop on vCPU {}: DTB {} is the Windows hypervisor's and maps no NT memory",
                self.ctx.current_thread,
                ui::addr(target.current_dtb())
            );
            outln!(
                "{}\n",
                ui::muted(".vtlcxr selects where VTL0 left off; .thread <tid> a Windows thread")
            );
        } else {
            outln!("VTL0 inspection: DTB {}\n", ui::addr(target.current_dtb()));
        }
        Ok(())
    }

    fn cmd_hvpartitions(&mut self) -> Result<()> {
        let partitions = match self.ctx.target.hypervisor_partitions() {
            Ok(partitions) => partitions,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        // Each partition under its parent, once: the root, then any whose
        // parent the walk did not find (or whose parents loop).
        let mut seen = HashSet::new();
        for partition in &partitions {
            let orphan = partition
                .parent
                .is_none_or(|parent| !partitions.iter().any(|p| p.id == parent));
            if orphan && !seen.contains(&partition.id) {
                outln!(
                    "{}",
                    self.partition_tree(partition, &partitions, 0, &mut seen)
                );
            }
        }
        for partition in &partitions {
            if !seen.contains(&partition.id) {
                outln!(
                    "{}",
                    self.partition_tree(partition, &partitions, 0, &mut seen)
                );
            }
        }
        outln!();
        Ok(())
    }

    /// `partition` with its privileges, its VPs, and its child partitions
    /// nested below it, as lines for a tree `depth` levels down. A partition
    /// in `seen` is not shown again.
    fn partition_tree(
        &self,
        partition: &HvPartition,
        partitions: &[HvPartition],
        depth: usize,
        seen: &mut HashSet<u64>,
    ) -> String {
        seen.insert(partition.id);
        let mut head = format!("{} {:#x}", ui::label("partition"), partition.id);
        if partition.parent.is_none() {
            head.push_str("  root");
        }
        head.push_str(&format!("  {}", ui::muted(&ui::addr(partition.address))));
        let (names, unnamed) = privilege_names(partition.privileges);
        let mut privileges = names.join(" ");
        if unnamed != 0 {
            privileges.push_str(&format!(" (+{unnamed:#x})"));
        }
        // The names hang under the first: "privileges " (11), the mask
        // (16), and a separator (2), after the tree's indent and gutter.
        let mut children = vec![wrapped_dim_tail(
            format!(
                "{} {:016x}  ",
                ui::muted("privileges"),
                partition.privileges
            ),
            29,
            &privileges,
            3 * (depth + 1) + 29,
        )];
        let root = partition.parent.is_none();
        children.extend(
            partition
                .virtual_processors
                .iter()
                .map(|vp| self.vp_line(vp, root, 3 * (depth + 1))),
        );
        for child in partitions {
            if child.parent == Some(partition.id) && !seen.contains(&child.id) {
                children.push(self.partition_tree(child, partitions, depth + 1, seen));
            }
        }
        std::iter::once(head)
            .chain(event_children_lines("", &children))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// One VP in a partition tree: its processor, the VTL it runs (the
    /// other enabled ones after it), and where that VTL left off and why.
    /// The root partition's are named from NT's and the secure kernel's
    /// symbols. A line too long for the terminal from column `col` puts the
    /// last exit on a line of its own, under where the VTL left off.
    fn vp_line(&self, vp: &HvVirtualProcessor, root: bool, col: usize) -> String {
        let mut head = format!("VP {}", vp.index);
        let cpu = processors_text(&vp.processors);
        if !cpu.is_empty() {
            head.push_str(&format!("  CPU {cpu}"));
        }
        head.push_str(&format!("  VTL{}", vp.vtl));
        let others: Vec<String> = vp
            .vtls
            .iter()
            .filter(|vtl| vtl.level != vp.vtl)
            .map(|vtl| format!("VTL{}", vtl.level))
            .collect();
        let others = if others.is_empty() {
            String::new()
        } else {
            format!(" (+{})", others.join(" "))
        };
        let state = vp
            .vtls
            .iter()
            .find(|vtl| vtl.level == vp.vtl)
            .and_then(|vtl| vtl.state);
        let styled_head = format!("{head}{}", ui::muted(&others));
        let Some(state) = state else {
            return styled_head;
        };
        let symbol = root
            .then(|| try_format_symbol_at(&self.ctx.target, state.cr3, state.rip))
            .flatten();
        let (at, styled_at) = match symbol {
            Some(symbol) => (symbol.clone(), ui::symbol(&symbol)),
            None => (format!("{:016x}", state.rip), ui::addr(state.rip)),
        };
        let line = format!("{styled_head}  {styled_at}");
        let Some(exit) = state.exit_reason_name() else {
            return line;
        };
        let exit = format!("last exit {exit}");
        // Measured plain: styling's escapes would count toward the width.
        let plain = format!("{head}{others}  {at}  {exit}");
        if wrap_prose(&plain, col).len() > 1 {
            let hang = head.len() + others.len() + 2;
            format!("{line}\n{}{}", " ".repeat(hang), ui::muted(&exit))
        } else {
            format!("{line}  {}", ui::muted(&exit))
        }
    }

    fn cmd_hvvps(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if invocation.argv.len() > 1 {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        }
        let id = match invocation.arg(0) {
            Some(text) => match self.eval_or_report(text) {
                Some(value) => Some(value.0),
                None => return Ok(()),
            },
            None => None,
        };
        let partitions = match self.ctx.target.hypervisor_partitions() {
            Ok(partitions) => partitions,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let partition = match id {
            Some(id) => partitions.into_iter().find(|p| p.id == id),
            None => partitions.into_iter().next(),
        };
        let Some(partition) = partition else {
            error!("no partition with ID {:#x}", id.unwrap_or_default());
            return Ok(());
        };
        let mut table = Builder::default();
        table.push_record([
            "VP",
            "Address",
            "CPU",
            "VTL",
            "Context",
            "eVMCS",
            "EPT pointer",
            "Guest RIP",
            "Last exit",
        ]);
        for vp in &partition.virtual_processors {
            for (row, vtl) in vp.vtls.iter().enumerate() {
                let current = if vtl.level == vp.vtl { "*" } else { "" };
                let state = vtl.state.as_ref();
                table.push_record([
                    if row == 0 {
                        vp.index.to_string()
                    } else {
                        String::new()
                    },
                    if row == 0 {
                        ui::addr(vp.address)
                    } else {
                        String::new()
                    },
                    if row == 0 {
                        processors_text(&vp.processors)
                    } else {
                        String::new()
                    },
                    format!("{}{current}", vtl.level),
                    ui::addr(vtl.context),
                    vtl.vmcs
                        .map_or_else(String::new, |page| format!("{page:x}")),
                    state.map_or_else(String::new, |state| format!("{:x}", state.ept_pointer)),
                    state.map_or_else(String::new, |state| ui::addr(state.rip)),
                    state
                        .and_then(|state| state.exit_reason_name())
                        .unwrap_or_default()
                        .to_string(),
                ]);
            }
        }
        print_padded_table(table);
        // A partition with no VPs yet links nothing either way.
        let mut vtls = partition
            .virtual_processors
            .iter()
            .flat_map(|vp| &vp.vtls)
            .peekable();
        let unlinked = vtls.peek().is_some() && vtls.all(|vtl| vtl.vmcs.is_none());
        if unlinked && self.ctx.target.evmcs_found() == Some(true) {
            outln!(
                "{}\n",
                ui::muted(
                    "eVMCS pages were found, but not where this hypervisor build's VTL contexts keep theirs"
                )
            );
        }
        Ok(())
    }

    fn cmd_hvept(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let virtual_address = matches!(invocation.arg(0), Some("-v" | "/v"));
        let arguments = &invocation.argv[usize::from(virtual_address)..];
        if arguments.is_empty() || arguments.len() > 3 {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        }
        let Some(values) = self.eval_all(arguments) else {
            return Ok(());
        };
        let Some(SelectedVp {
            partition: id,
            root,
            vp,
        }) = self.hypervisor_vp(
            values.get(1).copied(),
            values.get(2).copied(),
            virtual_address,
        )
        else {
            return Ok(());
        };
        // -v translates through NT's page tables, which are the root
        // partition's; a guest's addresses mean nothing there.
        if virtual_address && !root {
            error!(
                "-v translates through the root partition's address space; read a guest partition's virtual memory with !hvd"
            );
            return Ok(());
        }
        outln!(
            "{}",
            ui::muted(&format!("VP {} of partition {id:#x}", vp.index))
        );
        let gpa = if virtual_address {
            match self.ctx.target.virt_to_phys(None, VirtAddr(values[0])) {
                Ok(Some(gpa)) => {
                    outln!(
                        "{} {} {} {:x}",
                        ui::muted("virtual"),
                        ui::addr(values[0]),
                        ui::muted("-> guest physical"),
                        gpa
                    );
                    gpa
                }
                Ok(None) => {
                    error!(
                        "{} is not mapped in the current address space",
                        ui::addr(values[0])
                    );
                    return Ok(());
                }
                Err(error) => {
                    error!("{error}");
                    return Ok(());
                }
            }
        } else {
            values[0]
        };
        let mut table = Builder::default();
        table.push_record([
            "VTL",
            "EPT pointer",
            "Host physical",
            "Access",
            "User exec",
            "Page",
            "Type",
        ]);
        for vtl in &vp.vtls {
            let Some(state) = &vtl.state else {
                table.push_record([vtl.level.to_string(), "no eVMCS state".to_string()]);
                continue;
            };
            let mut row = vec![vtl.level.to_string(), format!("{:x}", state.ept_pointer)];
            match self.ctx.target.translate_guest_physical(state, gpa) {
                Some(EptTranslation::Mapped(mapping)) => {
                    let bit = |allowed: bool, letter: char| if allowed { letter } else { '-' };
                    row.extend([
                        format!("{:x}", mapping.host_physical),
                        [
                            bit(mapping.read, 'r'),
                            bit(mapping.write, 'w'),
                            bit(mapping.execute, 'x'),
                        ]
                        .iter()
                        .collect(),
                        mapping
                            .user_execute
                            .map_or_else(String::new, |allowed| bit(allowed, 'x').to_string()),
                        match mapping.page_size {
                            0x1000 => "4K".to_string(),
                            0x20_0000 => "2M".to_string(),
                            _ => "1G".to_string(),
                        },
                        memory_type_name(mapping.memory_type).to_string(),
                    ]);
                }
                Some(EptTranslation::NotPresent { level }) => {
                    row.push(format!("not mapped (no level-{level} entry)"));
                }
                None => row.push("unreadable EPT".to_string()),
            }
            table.push_record(row);
        }
        print_padded_table(table);
        Ok(())
    }

    fn cmd_hveptdiff(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if invocation.argv.len() > 2 {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        }
        let Some(values) = self.eval_all(&invocation.argv) else {
            return Ok(());
        };
        let Some(SelectedVp {
            partition: id, vp, ..
        }) = self.hypervisor_vp(values.first().copied(), values.get(1).copied(), false)
        else {
            return Ok(());
        };
        outln!(
            "{}",
            ui::muted(&format!("VP {} of partition {id:#x}", vp.index))
        );
        let states: Vec<_> = [0, 1]
            .iter()
            .map(|level| {
                vp.vtls
                    .iter()
                    .find(|vtl| vtl.level == *level)
                    .and_then(|vtl| vtl.state)
            })
            .collect();
        let (Some(vtl0), Some(vtl1)) = (states[0], states[1]) else {
            error!(
                "VP {} of partition {id:#x} has no eVMCS state for both VTL0 and VTL1",
                vp.index
            );
            return Ok(());
        };
        let mut mappings = Vec::new();
        for (level, state) in [(0, &vtl0), (1, &vtl1)] {
            let Some(leaves) = self.ctx.target.guest_physical_mappings(state) else {
                error!("VTL{level}'s EPT is unreadable or not a 4-level walk");
                return Ok(());
            };
            let bytes: u64 = leaves.iter().map(|leaf| leaf.size).sum();
            outln!(
                "{} EPT {:x}: {} mappings, {}",
                ui::muted(&format!("VTL{level}")),
                state.ept_pointer,
                leaves.len(),
                size_text(bytes)
            );
            mappings.push(leaves);
        }
        let differences = ept::differences(&mappings[0], &mappings[1]);
        // How the VTLs differ, largest first, before the ranges themselves.
        let mut kinds: Vec<(DifferenceKind, usize, u64)> = Vec::new();
        for difference in &differences {
            let kind = (difference.first, difference.second);
            match kinds.iter_mut().find(|(seen, _, _)| *seen == kind) {
                Some((_, ranges, bytes)) => {
                    *ranges += 1;
                    *bytes += difference.end - difference.start;
                }
                None => kinds.push((kind, 1, difference.end - difference.start)),
            }
        }
        kinds.sort_by_key(|&(_, _, bytes)| std::cmp::Reverse(bytes));
        let mut summary = Builder::default();
        summary.push_record(["VTL0", "VTL1", "Ranges", "Size"]);
        for ((first, second), ranges, bytes) in &kinds {
            summary.push_record([
                access_text(*first),
                access_text(*second),
                ranges.to_string(),
                size_text(*bytes),
            ]);
        }
        outln!();
        print_padded_table(summary);
        let mut table = Builder::default();
        table.push_record(["Start", "End", "Size", "VTL0", "VTL1"]);
        for difference in &differences {
            table.push_record([
                format!("{:x}", difference.start),
                format!("{:x}", difference.end - 1),
                size_text(difference.end - difference.start),
                access_text(difference.first),
                access_text(difference.second),
            ]);
        }
        let total: u64 = differences.iter().map(|d| d.end - d.start).sum();
        print_padded_table(table);
        outln!(
            "{} ranges differ, {} in all\n",
            differences.len(),
            size_text(total)
        );
        Ok(())
    }

    fn cmd_hvcalls(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let all = match invocation.argv.as_slice() {
            [] => false,
            [flag] if matches!(flag.as_ref(), "-a" | "/a") => true,
            _ => {
                outln!("{}\n", command_help(invocation.name));
                return Ok(());
            }
        };
        let (base, table) = match self.ctx.target.hypercalls() {
            Ok(found) => found,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let unassigned = table[0].handler;
        let mut table_out = Builder::default();
        table_out.push_record([
            "Code", "Name", "Kind", "Input", "Rep in", "Output", "Rep out", "Handler",
        ]);
        let mut implemented = 0;
        for (code, entry) in table.iter().enumerate() {
            let assigned = entry.handler != unassigned || code == 0;
            implemented += usize::from(entry.handler != unassigned);
            if !assigned && !all {
                continue;
            }
            let name = tlfs_hypercall(code as u16).map_or("", |(name, _)| name);
            let mut kind = if entry.rep() { "rep" } else { "simple" }.to_string();
            if entry.variable_header() {
                kind.push_str("+var");
            }
            let size = |bytes: u16| {
                if bytes == 0 {
                    String::new()
                } else {
                    format!("{bytes:#x}")
                }
            };
            table_out.push_record([
                format!("{code:#06x}"),
                name.to_string(),
                kind,
                size(entry.input),
                size(entry.input_element),
                size(entry.output),
                size(entry.output_element),
                format!("hv+{:#x}", entry.handler - base),
            ]);
        }
        print_padded_table(table_out);
        outln!(
            "{implemented} of {} codes implemented; code 0's handler serves the rest\n",
            table.len()
        );
        Ok(())
    }

    fn cmd_hvcall(&mut self) -> Result<()> {
        if let Err(error) = self
            .ctx
            .backend
            .set_current_thread(&self.ctx.current_thread)
        {
            error!("failed to select execution context: {error}");
            return Ok(());
        }
        let regs = match self.ctx.read_registers() {
            Ok(regs) => regs,
            Err(error) => {
                error!("failed to read registers: {error}");
                return Ok(());
            }
        };
        let target = &self.ctx.target;
        let map = &self.ctx.register_map;
        let (Ok(cr3), Ok(rip)) = (
            map.read_u64(target.arch().dtb_register(), &regs),
            map.read_u64("rip", &regs),
        ) else {
            error!("the vCPU's CR3 and RIP are unavailable");
            return Ok(());
        };
        if !halted_in_windows_hypervisor(target, cr3, rip) {
            error!(
                "{} is not halted in the Windows hypervisor; !hvcall decodes the hypercall a VP made at a stop there, such as on a hypercall handler (ba e1 hv!HvCallFlushVirtualAddressList)",
                ui::thread_id(&self.ctx.current_thread)
            );
            return Ok(());
        }
        let processor = processor_index_from_backend_thread_id(&self.ctx.current_thread);
        let Some(caller) = processor.and_then(|number| target.hypercall_caller(cr3, rip, number))
        else {
            if target.evmcs_found() == Some(false) {
                error!(
                    "no Enlightened VMCS in guest RAM: the VM must expose hv-evmcs (libvirt <evmcs state=\"on\"/>) for the Windows hypervisor to use one"
                );
            } else {
                error!(
                    "the caller is unknown: the hypervisor's partitions cannot be walked, or the processor serves no guest partition's VP and no saved state of its root partition VP is current"
                );
            }
            return Ok(());
        };
        match hypercall_report(&caller) {
            Ok(lines) => {
                for line in lines {
                    outln!("{line}");
                }
                outln!();
            }
            Err(reason) => error!("{reason}"),
        }
        Ok(())
    }

    fn cmd_hvvmcs(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let view = match invocation.arg(0) {
            Some("-msr" | "/msr") => "msr",
            Some("-io" | "/io") => "io",
            _ => "fields",
        };
        let arguments = &invocation.argv[usize::from(view != "fields")..];
        if arguments.len() > 3 {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        }
        let Some(values) = self.eval_all(arguments) else {
            return Ok(());
        };
        let Some(SelectedVp {
            partition: id, vp, ..
        }) = self.hypervisor_vp(values.first().copied(), values.get(1).copied(), false)
        else {
            return Ok(());
        };
        let level = values.get(2).map_or(vp.vtl, |&level| level as u8);
        let Some(page) = vp
            .vtls
            .iter()
            .find(|vtl| vtl.level == level)
            .and_then(|vtl| vtl.vmcs)
        else {
            error!(
                "VP {} of partition {id:#x} has no eVMCS for VTL{level}",
                vp.index
            );
            return Ok(());
        };
        let mut vmcs = vec![0u8; 0x400];
        if let Err(error) = self.ctx.target.read_physical(page, &mut vmcs) {
            error!("{error}");
            return Ok(());
        }
        outln!(
            "{} {page:x}\n",
            ui::muted(&format!(
                "VP {} of partition {id:#x}, VTL{level}: eVMCS",
                vp.index
            ))
        );
        match view {
            "msr" => self.print_msr_intercepts(&vmcs),
            "io" => self.print_io_intercepts(&vmcs),
            _ => {
                let mut table = Builder::default();
                table.push_record(["Field", "Offset", "Value"]);
                for (name, offset, size, value) in evmcs_fields::field_values(&vmcs) {
                    table.push_record([
                        name.to_string(),
                        format!("{offset:#05x}"),
                        format!("{value:0width$x}", width = usize::from(size) * 2),
                    ]);
                }
                print_padded_table(table);
            }
        }
        Ok(())
    }

    /// The MSRs the eVMCS `vmcs` intercepts: through its MSR bitmap when the
    /// primary controls use one (bit 28), else every MSR.
    fn print_msr_intercepts(&mut self, vmcs: &[u8]) {
        let target = &self.ctx.target;
        let (address, read, write) = match evmcs_fields::msr_intercepts(vmcs, |address, page| {
            target.read_physical(address, page)
        }) {
            Ok(MsrIntercepts::Every) => {
                outln!("every RDMSR and WRMSR exits: the controls use no MSR bitmap\n");
                return;
            }
            Ok(MsrIntercepts::Bitmap {
                bitmap,
                read,
                write,
            }) => (bitmap, read, write),
            Err(error) => {
                error!("{error}");
                return;
            }
        };
        let mut table = Builder::default();
        table.push_record(["Access", "First MSR", "Last MSR", "Names"]);
        for (access, ranges) in [("read", &read), ("write", &write)] {
            for &(first, last) in ranges {
                let names = evmcs_fields::msr_names(first, last);
                let shown = names.iter().take(4).copied().collect::<Vec<_>>().join(" ");
                table.push_record([
                    access.to_string(),
                    format!("{first:#x}"),
                    format!("{last:#x}"),
                    if names.len() > 4 {
                        format!("{shown} (+{})", names.len() - 4)
                    } else {
                        shown
                    },
                ]);
            }
        }
        outln!("{} {address:x}", ui::muted("MSR bitmap"));
        print_padded_table(table);
        for (access, ranges) in [("read", &read), ("write", &write)] {
            let names = evmcs_fields::msr_names_outside(ranges);
            let names = if names.is_empty() {
                "none of the MSRs ntoseye names".to_string()
            } else {
                names.join(" ")
            };
            // Both labels padded to the longer, "write without an exit: "
            // (23), and the names wrapped to hang under the first.
            let lines = wrap_prose(&names, 23);
            outln!(
                "{}{}",
                ui::muted(&format!("{:<23}", format!("{access} without an exit:"))),
                lines[0]
            );
            for line in &lines[1..] {
                outln!("{}{line}", " ".repeat(23));
            }
        }
        for line in wrap_prose(
            "MSRs outside 0x0-0x1fff and 0xc0000000-0xc0001fff, such as the Hyper-V synthetic ones \
             at 0x40000000, always exit",
            0,
        ) {
            outln!("{}", ui::muted(&line));
        }
        outln!();
    }

    /// The I/O ports the eVMCS `vmcs` intercepts: through its I/O bitmaps A
    /// (ports 0-0x7fff) and B when the primary controls use them (bit 25),
    /// else every port or none (unconditional I/O exiting, bit 24).
    fn print_io_intercepts(&mut self, vmcs: &[u8]) {
        let target = &self.ctx.target;
        let ports = match evmcs_fields::io_intercepts(vmcs, |address, page| {
            target.read_physical(address, page)
        }) {
            Ok(IoIntercepts::None) => {
                outln!("no I/O instruction exits: the controls use no I/O bitmaps\n");
                return;
            }
            Ok(IoIntercepts::Every) => {
                outln!("every I/O instruction exits: the controls use no I/O bitmaps\n");
                return;
            }
            Ok(IoIntercepts::Bitmaps { ports }) => ports,
            Err(error) => {
                error!("{error}");
                return;
            }
        };
        let mut table = Builder::default();
        table.push_record(["First port", "Last port"]);
        for (first, last) in ports {
            table.push_record([format!("{first:#x}"), format!("{last:#x}")]);
        }
        print_padded_table(table);
    }

    fn cmd_hvd(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let mut physical = false;
        let (mut mode, mut item) = (MemoryDisplayMode::bytes(), 1);
        let mut arguments = invocation.argv.as_slice();
        while let Some(flag) = arguments.first().filter(|text| text.starts_with('-')) {
            match flag.as_ref() {
                "-p" => physical = true,
                "-b" => (mode, item) = (MemoryDisplayMode::bytes(), 1),
                "-d" => (mode, item) = (MemoryDisplayMode::dwords(), 4),
                "-q" => (mode, item) = (MemoryDisplayMode::qwords(), 8),
                _ => break,
            }
            arguments = &arguments[1..];
        }
        // `<partition-id> <vp-index> <address> [range]`, or `<address>
        // [range]` for the guest VP the current vCPU's processor runs.
        if !(1..=4).contains(&arguments.len()) {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        }
        let (selector, arguments) = arguments.split_at(if arguments.len() >= 3 { 2 } else { 0 });
        let Some(selector) = self.eval_all(selector) else {
            return Ok(());
        };
        let Some(address) = self.eval_or_report(&arguments[0]) else {
            return Ok(());
        };
        let start = VirtAddr(address.0);
        let range = match arguments.get(1) {
            Some(text) => eval_range(text, &self.ctx.target, self.radix, start, item),
            None => eval_range("L80", &self.ctx.target, NumberRadix::Hexadecimal, start, 1),
        };
        let range = match range {
            Ok(range) if range.len() <= MAX_DISPLAY_BYTES => range,
            Ok(_) => {
                error!("display range exceeds the maximum of {MAX_DISPLAY_BYTES:#x} bytes");
                return Ok(());
            }
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let Some(state) = self.guest_memory_state("!hvd", &selector, physical) else {
            return Ok(());
        };
        // Page by page, so an unmapped page does not hide the rest.
        let mut data = vec![0u8; range.len()];
        let mut valid = vec![false; range.len()];
        let mut offset = 0;
        while offset < data.len() {
            let address = range.start.0 + offset as u64;
            let chunk = ((0x1000 - (address & 0xfff)) as usize).min(data.len() - offset);
            let target = &mut data[offset..offset + chunk];
            if self
                .ctx
                .target
                .read_guest_partition(&state, !physical, address, target)
                .is_ok()
            {
                valid[offset..offset + chunk].fill(true);
            }
            offset += chunk;
        }
        display_memory_with_validity(range.start, &data, Some(&valid), &mode);
        Ok(())
    }

    fn cmd_hvu(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        const DEFAULT_INSTRUCTIONS: usize = 8;
        let mut arguments = invocation.argv.as_slice();
        let physical = arguments.first().is_some_and(|flag| flag == "-p");
        if physical {
            arguments = &arguments[1..];
        }
        // As for !hvd: `<partition-id> <vp-index> <address> [range]`, or
        // `<address> [range]` for the guest VP the current vCPU's processor
        // runs.
        if !(1..=4).contains(&arguments.len()) {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        }
        let (selector, arguments) = arguments.split_at(if arguments.len() >= 3 { 2 } else { 0 });
        let Some(selector) = self.eval_all(selector) else {
            return Ok(());
        };
        let Some(address) = self.eval_or_report(&arguments[0]) else {
            return Ok(());
        };
        // As for u: `L<count>` counts instructions; an end address or a
        // length lists every instruction that starts before the range ends.
        let extent = match arguments.get(1) {
            None => CodeExtent::Count(DEFAULT_INSTRUCTIONS),
            Some(text) => match windbg_count_expression(text) {
                Some(count) => match self.eval_or_report(count) {
                    Some(count) if (1..=MAX_DISASSEMBLY_INSTRUCTIONS as u64).contains(&count.0) => {
                        CodeExtent::Count(count.0 as usize)
                    }
                    Some(_) => {
                        error!("instruction count must be 1..{MAX_DISASSEMBLY_INSTRUCTIONS}");
                        return Ok(());
                    }
                    None => return Ok(()),
                },
                None => match eval_range(text, &self.ctx.target, self.radix, address, 1) {
                    Ok(range) if range.len() <= MAX_DISPLAY_BYTES => {
                        CodeExtent::Before(range.end.0)
                    }
                    Ok(_) => {
                        error!("range exceeds the maximum of {MAX_DISPLAY_BYTES:#x} bytes");
                        return Ok(());
                    }
                    Err(error) => {
                        error!("{error}");
                        return Ok(());
                    }
                },
            },
        };
        let Some(state) = self.guest_memory_state("!hvu", &selector, physical) else {
            return Ok(());
        };
        let code = match self
            .ctx
            .target
            .disassemble_guest_partition(&state, !physical, address.0, extent)
        {
            Ok(code) => code,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        render_rows(&code.rows, |_| None);
        if let Some(at) = code.unreadable {
            let space = if physical { "physical" } else { "virtual" };
            error!("guest {space} memory at {at:#x} is unreadable");
        }
        outln!();
        Ok(())
    }

    /// The saved state of the VTL that a guest partition's VP runs in, for
    /// `command` to read its memory: the VP `selector` names (a partition ID
    /// and a VP index), else the guest VP the current vCPU's processor runs.
    /// `None` after reporting why there is none, or why its virtual memory
    /// cannot be read when `physical` is false.
    fn guest_memory_state(
        &mut self,
        command: &str,
        selector: &[u64],
        physical: bool,
    ) -> Option<EvmcsState> {
        let SelectedVp {
            partition: id,
            root,
            vp,
        } = self.hypervisor_vp(selector.first().copied(), selector.get(1).copied(), false)?;
        if root && selector.is_empty() {
            error!(
                "{command} reads a guest partition's memory, and the current vCPU's processor runs none; name one: {command} <partition-id> <vp-index> <address>"
            );
            return None;
        }
        let Some(state) = vp
            .vtls
            .iter()
            .find(|vtl| vtl.level == vp.vtl)
            .and_then(|vtl| vtl.state)
        else {
            error!(
                "VP {} of partition {id:#x} has no eVMCS state: it has not started, or it runs without paging",
                vp.index
            );
            return None;
        };
        // Each page's read would fail the same way; say why once.
        if !physical && !state.four_level_paging() {
            error!(
                "VP {} of partition {id:#x} is not in 4-level long-mode paging; read its guest physical memory with -p",
                vp.index
            );
            return None;
        }
        Some(state)
    }

    /// Each of `arguments` evaluated, or `None` after reporting the first
    /// that does not evaluate.
    fn eval_all(&mut self, arguments: &[std::borrow::Cow<'_, str>]) -> Option<Vec<u64>> {
        arguments
            .iter()
            .map(|text| self.eval_or_report(text).map(|value| value.0))
            .collect()
    }

    /// VP `index` (0 by default) of partition `id`, with its partition's ID,
    /// or `None` after reporting why there is none. Without either, the VP
    /// the current vCPU's processor runs (see [`default_vp`]); `root_only`
    /// keeps that to the root partition's.
    fn hypervisor_vp(
        &mut self,
        id: Option<u64>,
        index: Option<u64>,
        root_only: bool,
    ) -> Option<SelectedVp> {
        let partitions = match self.ctx.target.hypervisor_partitions() {
            Ok(partitions) => partitions,
            Err(error) => {
                error!("{error}");
                return None;
            }
        };
        if id.is_none() && index.is_none() {
            let number = processor_index_from_backend_thread_id(&self.ctx.current_thread);
            let (partition, vp) = default_vp(&partitions, number, root_only)?;
            let partition = &partitions[partition];
            return Some(SelectedVp {
                partition: partition.id,
                root: partition.parent.is_none(),
                vp: partition.virtual_processors[vp].clone(),
            });
        }
        let partition = match id {
            Some(id) => partitions.into_iter().find(|p| p.id == id),
            None => partitions.into_iter().next(),
        };
        let Some(partition) = partition else {
            error!("no partition with ID {:#x}", id.unwrap_or_default());
            return None;
        };
        let index = index.unwrap_or(0);
        let Some(vp) = partition
            .virtual_processors
            .into_iter()
            .find(|vp| u64::from(vp.index) == index)
        else {
            error!("partition {:#x} has no VP {index}", partition.id);
            return None;
        };
        Some(SelectedVp {
            partition: partition.id,
            root: partition.parent.is_none(),
            vp,
        })
    }

    fn cmd_partition(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if invocation.argv.len() > 1 {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        }
        if invocation.argv.is_empty() {
            match self.ctx.partition() {
                Some(partition) => outln!(
                    "inspecting partition {partition:#x}; .partition with the root partition's ID returns to the target\n"
                ),
                None => outln!("inspecting the target (the root partition)\n"),
            }
            return Ok(());
        }
        let Some(arguments) = self.eval_all(&invocation.argv) else {
            return Ok(());
        };
        let result = self.ctx.enter_partition(arguments[0]);
        self.caches.clear_threads();
        self.caches.refresh_symbol_context(&self.ctx.target);
        match result {
            Ok(()) => match self.ctx.partition() {
                Some(partition) => {
                    let kernel = self
                        .ctx
                        .target
                        .kernel_base()
                        .map_or_else(|| "?".to_string(), |base| format!("{:#x}", base.0));
                    let vps = self.ctx.backend.thread_list().unwrap_or_default();
                    outln!(
                        "inspecting partition {partition:#x}: nt at {kernel}, VPs {}\n",
                        vps.join(" ")
                    );
                }
                None => outln!("inspecting the target (the root partition)\n"),
            },
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_hvr(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if !matches!(invocation.argv.len(), 0 | 2 | 3) {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        }
        let Some(arguments) = self.eval_all(&invocation.argv) else {
            return Ok(());
        };
        let Some(SelectedVp { partition, vp, .. }) =
            self.hypervisor_vp(arguments.first().copied(), arguments.get(1).copied(), false)
        else {
            return Ok(());
        };
        let vtl = match arguments.get(2).map(|vtl| u8::try_from(*vtl)) {
            None => None,
            Some(Ok(vtl)) => Some(vtl),
            Some(Err(_)) => {
                error!("VTL {:#x} is out of range", arguments[2]);
                return Ok(());
            }
        };
        match self.ctx.vp_registers(partition, vp.index, vtl) {
            Ok(found) => {
                outln!(
                    "partition {partition:#x} VP {} VTL{}  {}",
                    vp.index,
                    vtl.unwrap_or(vp.vtl),
                    ui::muted(&format!("from {}", found.source))
                );
                if let Some(missing) = &found.missing {
                    outln!(
                        "{}",
                        ui::muted(&format!("no general-purpose registers: {missing}"))
                    );
                }
                print_vp_registers(&found.registers);
                outln!();
            }
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_trustlets(&mut self) -> Result<()> {
        let processes = match self.ctx.target.trustlets() {
            Ok(processes) => processes,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let mut table = Builder::default();
        table.push_record(["SK process", "NT PID", "Image", "Trustlet ID", "DTB"]);
        for process in processes {
            table.push_record([
                ui::addr(process.process.0),
                process.pid.to_string(),
                process.name,
                process.trustlet_id.to_string(),
                ui::addr(process.dtb),
            ]);
        }
        print_padded_table(table);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest::hypercall_input::decode_hypercall;
    use crate::output::capture;
    use crate::session::tests::{MockBackend, session_with_mock};

    fn spec(name: &str) -> &'static CommandSpec {
        command_registry()
            .get(name)
            .unwrap_or_else(|| panic!("'{name}' is not registered"))
    }

    /// `caller`'s hypercall as `!hvcall` prints it, line by line.
    fn hvcall_output(caller: HypercallCaller) -> Vec<String> {
        let (result, text) = capture(|| {
            for line in hypercall_report(&caller)? {
                outln!("{line}");
            }
            Ok::<(), String>(())
        });
        result.unwrap();
        text.lines().map(str::to_string).collect()
    }

    /// Root partition VP 2's hypercall `value`, whose input page holds
    /// `parts`, each `(offset, qword)`.
    fn root_caller(value: u64, parts: &[(usize, u64)]) -> HypercallCaller {
        let mut page = vec![0u8; 0x1000];
        for &(offset, qword) in parts {
            page[offset..offset + 8].copy_from_slice(&qword.to_le_bytes());
        }
        let call = decode_hypercall(value, 0x5000, 0x6000, Err(String::new()), |_, buf| {
            buf.copy_from_slice(&page[..buf.len()]);
            Ok(())
        });
        HypercallCaller {
            partition: 1,
            root: true,
            vp: 2,
            vtl: 0,
            input: HypercallInput::Known(Box::new(call)),
            registers: Default::default(),
            state: None,
        }
    }

    /// The call heads the tree; its GPAs and fields follow, values aligned at
    /// their sizes, and its rep list last, the elements before the rep start
    /// marked done.
    #[test]
    fn hvcall_shows_the_fields_and_marks_the_reps_already_done() {
        let caller = root_caller(
            0x0001_0002_0000_0003,
            &[
                (0, 0x1ad000),
                (16, 0x3),
                (24, 0x1000),
                (32, 0x7ff6_0000_0001),
            ],
        );
        assert_eq!(
            hvcall_output(caller),
            [
                "root partition VP 2 VTL0  hypercall 0x0003 HvCallFlushVirtualAddressList rep 1/2",
                "├─ input value 0x0001000200000003",
                "├─ input GPA 0x5000  output GPA 0x6000",
                "├─ AddressSpace   0x00000000001ad000",
                "├─ Flags          0x0000000000000000",
                "├─ ProcessorMask  0x0000000000000003  VPs 0-1",
                "└─ rep list 2 elements, 1 done",
                "   ├─ [0] GvaRange  0x0000000000001000  0x1000, 1 page  done",
                "   └─ [1] GvaRange  0x00007ff600000001  0x7ff600000000, 2 pages",
            ]
        );
    }

    /// An element of several fields is a subtree of its own.
    #[test]
    fn hvcall_nests_an_element_of_several_fields() {
        let caller = root_caller(
            0x0000_0001_0000_0051,
            &[(0, u64::MAX), (16, 0x0004_0002), (32, 0x1ad000)],
        );
        let tail: Vec<String> = hvcall_output(caller)
            .into_iter()
            .skip_while(|line| !line.contains("rep list"))
            .collect();
        assert_eq!(
            tail,
            [
                "└─ rep list 1 element",
                "   └─ [0]",
                "      ├─ RegisterName        0x00040002  HvX64RegisterCr3",
                "      ├─ RegisterValue.Low   0x00000000001ad000",
                "      └─ RegisterValue.High  0x0000000000000000",
            ]
        );
    }

    /// Without a decoded call `!hvcall` says why rather than print a tree.
    #[test]
    fn hvcall_explains_an_exit_with_no_known_call() {
        let caller = |input| HypercallCaller {
            partition: 4,
            root: false,
            vp: 1,
            vtl: 0,
            input,
            registers: Default::default(),
            state: None,
        };
        let error = hypercall_report(&caller(HypercallInput::NotHypercall)).unwrap_err();
        assert!(error.starts_with("partition 0x4 VP 1 VTL0") && error.contains("no hypercall"));
        let reason = "the vCPU is saving them";
        let error =
            hypercall_report(&caller(HypercallInput::Unknown(reason.to_string()))).unwrap_err();
        assert!(error.ends_with(reason));
    }

    /// A vCPU outside the hypervisor has no hypercall to decode.
    #[test]
    fn hvcall_refuses_a_vcpu_outside_the_hypervisor() {
        let mut session = session_with_mock(MockBackend::default().one_vcpu());
        let mut state = ReplState::for_oneshot(&mut session);
        let (result, text) = capture(|| state.dispatch_line("!hvcall"));
        result.unwrap();
        assert!(
            text.contains("is not halted in the Windows hypervisor"),
            "{text}"
        );
    }

    /// A hypervisor command without a VP shows the one the current vCPU's
    /// processor runs: a guest partition's first, unless it takes only the
    /// root's; then the root's VP on that processor, found by number when
    /// the processor runs a guest's; then the root's VP 0.
    #[test]
    fn the_default_vp_is_the_one_the_current_processor_runs() {
        let vp = |index, processor: Option<u32>| HvVirtualProcessor {
            index,
            address: 0,
            vtl: 0,
            vtls: Vec::new(),
            processors: processor
                .map(|number| HvProcessor {
                    block: 0,
                    number: Some(number),
                })
                .into_iter()
                .collect(),
        };
        let partition = |id, parent, virtual_processors| HvPartition {
            address: 0,
            id,
            parent,
            privileges: 0,
            virtual_processors,
        };
        let partitions = [
            partition(1, None, vec![vp(0, Some(0)), vp(1, None), vp(2, Some(2))]),
            partition(7, Some(1), vec![vp(0, None), vp(1, Some(1))]),
        ];
        assert_eq!(default_vp(&partitions, Some(1), false), Some((1, 1)));
        assert_eq!(default_vp(&partitions, Some(1), true), Some((0, 1)));
        assert_eq!(default_vp(&partitions, Some(2), false), Some((0, 2)));
        assert_eq!(default_vp(&partitions, None, false), Some((0, 0)));
    }

    #[test]
    fn memory_view_admits_the_hardware_breakpoint_workflow_without_registers_or_writes() {
        for name in [
            "ba", "bl", "bc", "bd", "be", "g", "continue", "db", "u", "x", "!vtop", ".vtl",
        ] {
            assert!(secure_scope_admits(spec(name)), "'{name}' refused");
        }
        for name in [
            "bp", "bu", "bm", "gh", "gn", "t", "p", "gu", "pa", "wt", "r", "k", ".frame", "~",
            "vcpu", "eb", "ed", "f", ".readmem", "!eb", "wrmsr", "!process", "!thread", "!pcr",
        ] {
            assert!(!secure_scope_admits(spec(name)), "'{name}' admitted");
        }
    }

    #[test]
    fn live_vtl1_stop_admits_vcpu_state_and_steps_but_not_nt_extensions_or_writes() {
        for name in [
            "r", "k", "kb", ".frame", "~", "vcpu", "break", "status", "ba", "bl", "g", "db", "u",
            ".vtl", "t", "p", "gu", "pa", "ta", "wt", ".vtlcxr",
        ] {
            assert!(live_secure_admits(spec(name)), "'{name}' refused");
        }
        for name in [
            "bp", "bu", "bm", "gh", "gn", "eb", "eq", "f", ".readmem", "!eb", "wrmsr", "!process",
            "!thread", ".thread", "!pcr", "!prcb", "!irql", "!idt", ".cxr", ".trap", "!peb",
            "!pte",
        ] {
            assert!(!live_secure_admits(spec(name)), "'{name}' admitted");
        }
    }

    /// Only run control whose temporary sites become debug-register sites
    /// in VTL1 may leave a VTL1 stop, so a new run command stays refused
    /// until someone decides it is VTL1-safe.
    #[test]
    fn only_g_and_hardware_steps_move_the_target_from_a_vtl1_address_space() {
        for spec in COMMANDS.iter() {
            if spec.run != RunEffect::None && live_secure_admits(spec) {
                assert!(
                    matches!(spec.names[0], "g" | "t" | "p" | "gu" | "pa" | "ta" | "wt"),
                    "'{}' admitted",
                    spec.names[0]
                );
            }
        }
    }

    /// A stop whose root is a VTL1 root: a run-to that would need a software
    /// site in VTL1, and writes, leave the target exactly as stopped; plain
    /// `g` still resumes it.
    #[test]
    fn vtl1_stop_refuses_patching_run_to_and_writes_but_resumes_on_plain_g() {
        let mut session = session_with_mock(MockBackend::default());
        let root = session.target.current_dtb();
        session.target.symbols.set_secure_roots(root, []);
        let mut state = ReplState::for_oneshot(&mut session);
        state.stop_wait = Some(StopWaitBudget::new(
            std::time::Duration::from_millis(150),
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        ));
        assert!(state.ctx.target.in_secure_address_space());
        assert!(!state.ctx.target.in_secure_scope());

        let (result, _) = capture(|| state.dispatch_line("g 1000"));
        result.unwrap();
        assert!(!state.ctx.backend.is_running(), "g <address> resumed");

        let (result, _) = capture(|| state.dispatch_line("eb 1000 cc"));
        assert_eq!(result.unwrap(), Flow::Denied);
        let (result, _) = capture(|| state.dispatch_line("bp 1000"));
        assert_eq!(result.unwrap(), Flow::Denied);
        assert!(!state.ctx.backend.is_running(), "bp resumed");

        let (result, _) = capture(|| state.dispatch_line("g"));
        result.unwrap();
        assert!(state.ctx.backend.is_running(), "plain g did not resume");
    }
}
