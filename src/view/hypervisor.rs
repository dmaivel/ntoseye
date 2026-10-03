//! hypervisor: [`View`](super::View) builders for the Windows hypervisor's
//! processors, EPTs, and hypercall table, the guest VP a processor serves,
//! and the hypercall a VP made.

use std::collections::HashMap;

use super::shape::{Hex, Keyed, shapes};
use crate::guest::{EXIT_GPRS, HvProcessor};
use crate::guest::ept::{Difference, EptMapping as EptInfo};
use crate::guest::evmcs_fields::{self, IoIntercepts as IoInfo, MsrIntercepts as MsrInfo};
use crate::guest::hv_layout::HypercallEntry;
use crate::guest::hypercall_input::{self, DecodedHypercall as Decoded};
use crate::guest::hypercalls::tlfs_hypercall;
use crate::session;
use crate::target::{ServedVp as Served, VP_STATE_REGISTERS};
use crate::types::VirtAddr;

shapes! {
    /// A logical processor whose current VP a VP is: the one that runs it, or
    /// ran it last.
    HypervisorProcessor {
        /// The processor number, or None on builds before 10.0.19041.
        number: Option<u32>,
        /// The processor block (the processor's GS base in the hypervisor).
        block: VirtAddr,
    }

    /// The registers of one VTL of a Windows hypervisor VP (`!hvr`).
    VpRegisters {
        /// RIP, RSP, flags, control and segment registers, and the
        /// general-purpose ones when they are known.
        registers: Keyed<Hex>,
        /// Where they are from: a vCPU that runs the VP now, the exit a vCPU
        /// in the hypervisor handles for it, or its last exit.
        source: String,
        /// Why the general-purpose registers are missing, when they are.
        missing: Option<String>,
    }

    /// Where a guest physical address goes through one VTL's EPT, and the
    /// access that every level of the walk allows.
    EptMapping {
        host_physical: Hex,
        /// The size of the mapping page: 4 KiB, 2 MiB, or 1 GiB.
        page_size: Hex,
        read: bool,
        write: bool,
        /// Execute access: supervisor-mode only when `user_execute` is not
        /// None.
        execute: bool,
        /// User-mode execute access when the VTL uses mode-based execute
        /// control, else None.
        user_execute: Option<bool>,
        /// The EPT memory type (0 UC, 1 WC, 4 WT, 5 WP, 6 WB).
        memory_type: u8,
        /// The entry of each level of the walk, from the PML4 down.
        entries: Vec<Hex>,
    }

    /// A guest physical range that VTL0's and VTL1's EPTs map differently.
    EptDifference {
        start: Hex,
        /// The end of the range (exclusive).
        end: Hex,
        /// VTL0's access as `r-x`-style text, with `u` for user-mode execute
        /// under mode-based execute control, or None where VTL0 maps nothing.
        vtl0: Option<String>,
        /// VTL1's access, as `vtl0` gives VTL0's.
        vtl1: Option<String>,
    }

    /// A range of MSRs whose accesses exit, with the architectural MSRs (or
    /// blocks, such as `x2APIC`) that ntoseye names in it.
    MsrRange {
        first: Hex<u32>,
        last: Hex<u32>,
        names: Vec<&'static str>,
    }

    /// Which RDMSRs and WRMSRs of a VTL exit (`!hvvmcs -msr`). MSRs outside
    /// the bitmap's 0x0-0x1fff and 0xc0000000-0xc0001fff always exit.
    MsrIntercepts {
        /// Whether every RDMSR and WRMSR exits: the controls use no MSR
        /// bitmap, and the lists are empty.
        every: bool,
        /// The MSR bitmap's physical address, or None without one.
        bitmap: Option<Hex>,
        /// The MSR ranges whose reads exit.
        read: Vec<MsrRange>,
        /// The MSR ranges whose writes exit.
        write: Vec<MsrRange>,
        /// The MSRs ntoseye names that the VTL reads without an exit.
        read_without_exit: Vec<&'static str>,
        /// The MSRs ntoseye names that the VTL writes without an exit.
        write_without_exit: Vec<&'static str>,
    }

    /// A range of I/O ports whose accesses exit.
    PortRange {
        first: Hex<u32>,
        last: Hex<u32>,
    }

    /// Which I/O instructions of a VTL exit (`!hvvmcs -io`).
    IoIntercepts {
        /// Whether every I/O instruction exits: the controls use no I/O
        /// bitmaps but unconditional I/O exiting.
        every: bool,
        /// The port ranges whose accesses exit, through I/O bitmaps A and B.
        /// Empty with `every`, and when no I/O instruction exits.
        ports: Vec<PortRange>,
    }

    /// One call code of the hypervisor's hypercall table.
    Hypercall {
        code: Hex<u16>,
        /// The TLFS name, or None for a code that the TLFS does not list.
        name: Option<&'static str>,
        /// Whether the call has its own handler, not the reserved code 0's.
        implemented: bool,
        /// Whether the call is a rep hypercall.
        rep: bool,
        /// Whether the call takes a variable-size header.
        variable_header: bool,
        input_size: u16,
        input_element_size: u16,
        output_size: u16,
        output_element_size: u16,
        handler: VirtAddr,
    }

    /// One field of a hypercall's input, as the Hyper-V TLFS lays it out.
    HypercallField {
        /// The TLFS parameter name, with its member for a structure
        /// (`ProcessorSet.ValidBanksMask`) and its index for an array
        /// (`Message[2]`); `Input[n]` for the raw qwords of a call whose
        /// layout ntoseye does not know.
        name: String,
        /// The offset in the input, from its first byte.
        offset: u16,
        /// The size in bytes, at most 8.
        size: u8,
        value: Hex,
        /// What the value means, where it has a name or stands for a set
        /// (`HV_PARTITION_ID_SELF`, `VPs 0-3`, a register's TLFS name).
        meaning: Option<String>,
    }

    /// One element of a rep hypercall's input list.
    HypercallElement {
        index: u16,
        fields: Vec<HypercallField>,
    }

    /// The hypercall of a VMCALL exit, with its input decoded as the Hyper-V
    /// TLFS lays it out (`!hvcall`).
    DecodedHypercall {
        /// The hypercall input value (RCX).
        input_value: Hex,
        code: Hex<u16>,
        /// The TLFS name, or None for a code that the TLFS does not list.
        name: Option<&'static str>,
        /// Whether the input is in registers (RDX, R8, and XMM0 to XMM5)
        /// rather than in memory.
        fast: bool,
        /// The size of the variable input header, in qwords.
        variable_header_size: u16,
        /// Whether the call is for the L0 hypervisor of a nested environment.
        nested: bool,
        rep_count: u16,
        /// The first rep element still to process; those before it are done.
        rep_start: u16,
        /// The guest physical address of the input (RDX), for a call whose
        /// input is in memory.
        input_gpa: Option<Hex>,
        /// The guest physical address of the output (R8), for a call whose
        /// input is in memory.
        output_gpa: Option<Hex>,
        /// Whether ntoseye knows the layout of the call's input. When it does
        /// not, `fields` holds the input as raw qwords: RDX and R8 for a fast
        /// call, else the first 8 qwords of the input.
        decoded: bool,
        fields: Vec<HypercallField>,
        /// A rep call's input list, each element up to the rep count.
        elements: Vec<HypercallElement>,
        /// Why some of the input is missing: an unreadable input page, input
        /// in XMM registers, or input past the end of its page.
        unavailable: Option<String>,
        /// The call on one line, as the stop header shows it.
        summary: String,
    }

    /// The guest partition's virtual processor that a processor in the
    /// Windows hypervisor runs or last ran: the VP whose exit it handles, or
    /// which it is about to enter.
    ServedVp {
        partition_id: Hex,
        vp_index: u32,
        /// The VTL the VP runs in.
        vtl: u8,
        /// Where the VTL left off, when the partition walk read its state.
        rip: Option<VirtAddr>,
        /// Whether the processor's VP assist page names this VTL's eVMCS: the
        /// processor handles this VP's exit, or is about to enter it.
        current: bool,
        /// The VM-exit reason of the VTL's last exit.
        exit_reason: Option<Hex<u32>>,
        /// The name of the exit reason (`HLT`, `VMCALL`, ...), if it is a
        /// common reason.
        exit_reason_name: Option<&'static str>,
        /// The guest's general-purpose registers other than `rsp` at the last
        /// exit, as `SavedVtlState.general_registers`. None when they are not
        /// known.
        general_registers: Option<Keyed<Hex>>,
        /// The hypercall of a VMCALL exit whose registers are known.
        hypercall: Option<DecodedHypercall>,
    }
}

pub fn hypervisor_processor(processor: &HvProcessor) -> HypervisorProcessor {
    HypervisorProcessor {
        number: processor.number,
        block: VirtAddr(processor.block),
    }
}

pub fn ept_mapping(mapping: &EptInfo) -> EptMapping {
    EptMapping {
        host_physical: mapping.host_physical,
        page_size: mapping.page_size,
        read: mapping.read,
        write: mapping.write,
        execute: mapping.execute,
        user_execute: mapping.user_execute,
        memory_type: mapping.memory_type,
        entries: mapping.entries.clone(),
    }
}

pub fn ept_difference(difference: &Difference) -> EptDifference {
    let text = |access: Option<crate::guest::ept::Access>| access.map(|access| access.to_string());
    EptDifference {
        start: difference.start,
        end: difference.end,
        vtl0: text(difference.first),
        vtl1: text(difference.second),
    }
}

fn msr_range(&(first, last): &(u32, u32)) -> MsrRange {
    MsrRange {
        first,
        last,
        names: evmcs_fields::msr_names(first, last),
    }
}

pub fn msr_intercepts(intercepts: &MsrInfo) -> MsrIntercepts {
    match intercepts {
        MsrInfo::Every => MsrIntercepts {
            every: true,
            bitmap: None,
            read: Vec::new(),
            write: Vec::new(),
            read_without_exit: Vec::new(),
            write_without_exit: Vec::new(),
        },
        MsrInfo::Bitmap {
            bitmap,
            read,
            write,
        } => MsrIntercepts {
            every: false,
            bitmap: Some(*bitmap),
            read: read.iter().map(msr_range).collect(),
            write: write.iter().map(msr_range).collect(),
            read_without_exit: evmcs_fields::msr_names_outside(read),
            write_without_exit: evmcs_fields::msr_names_outside(write),
        },
    }
}

pub fn io_intercepts(intercepts: &IoInfo) -> IoIntercepts {
    let ports = match intercepts {
        IoInfo::Bitmaps { ports } => ports
            .iter()
            .map(|&(first, last)| PortRange { first, last })
            .collect(),
        IoInfo::None | IoInfo::Every => Vec::new(),
    };
    IoIntercepts {
        every: matches!(intercepts, IoInfo::Every),
        ports,
    }
}

/// The table's entry for `code`. `unassigned` is the handler of the reserved
/// code 0, which unimplemented codes share.
pub fn hypercall(code: u16, entry: &HypercallEntry, unassigned: Option<u64>) -> Hypercall {
    Hypercall {
        code,
        name: tlfs_hypercall(code).map(|(name, _)| name),
        implemented: Some(entry.handler) != unassigned,
        rep: entry.rep(),
        variable_header: entry.variable_header(),
        input_size: entry.input,
        input_element_size: entry.input_element,
        output_size: entry.output,
        output_element_size: entry.output_element,
        handler: VirtAddr(entry.handler),
    }
}

fn hypercall_field(field: &hypercall_input::HypercallField) -> HypercallField {
    HypercallField {
        name: field.name.clone(),
        offset: field.offset,
        size: field.size,
        value: field.value,
        meaning: field.meaning.clone(),
    }
}

pub fn decoded_hypercall(call: &Decoded) -> DecodedHypercall {
    DecodedHypercall {
        input_value: call.input_value,
        code: call.control.code,
        name: call.name,
        fast: call.control.fast,
        variable_header_size: call.control.variable_header_qwords,
        nested: call.control.nested,
        rep_count: call.control.rep_count,
        rep_start: call.control.rep_start,
        input_gpa: call.input_gpa,
        output_gpa: call.output_gpa,
        decoded: call.decoded,
        fields: call.fields.iter().map(hypercall_field).collect(),
        elements: call
            .elements
            .iter()
            .map(|element| HypercallElement {
                index: element.index,
                fields: element.fields.iter().map(hypercall_field).collect(),
            })
            .collect(),
        unavailable: call.unavailable.clone(),
        summary: call.summary(),
    }
}

/// A VP's registers, in [`VP_STATE_REGISTERS`] order.
pub fn vp_registers(found: &session::VpRegisters) -> VpRegisters {
    VpRegisters {
        registers: VP_STATE_REGISTERS
            .iter()
            .filter_map(|name| Some((*name, *found.registers.get(*name)?)))
            .collect(),
        source: found.source.clone(),
        missing: found.missing.clone(),
    }
}

/// An exit's general-purpose registers, in [`EXIT_GPRS`] order.
pub fn exit_registers(registers: &HashMap<&'static str, u64>) -> Vec<(&'static str, u64)> {
    EXIT_GPRS
        .iter()
        .filter_map(|name| Some((*name, *registers.get(name)?)))
        .collect()
}

pub fn served_vp(served: &Served) -> ServedVp {
    let state = served.state.as_ref();
    ServedVp {
        partition_id: served.partition,
        vp_index: served.vp,
        vtl: served.vtl,
        rip: state.map(|state| VirtAddr(state.rip)),
        current: state.is_some_and(|state| state.current),
        exit_reason: state.map(|state| state.exit_reason),
        exit_reason_name: state.and_then(|state| state.exit_reason_name()),
        general_registers: served.general_registers.as_ref().ok().map(exit_registers),
        hypercall: served.hypercall.call().map(decoded_hypercall),
    }
}
