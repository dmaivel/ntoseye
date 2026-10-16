//! hypervisor: [`View`](super::View) builders for the Windows hypervisor's
//! processors, EPTs, and hypercall table, the guest VP a processor serves,
//! and the hypercall a VP made.

use super::record::Keyed;
use ntoseye_macros::record;

use std::collections::HashMap;

use crate::guest::EXIT_GPRS;
use crate::guest::evmcs_fields::{self, IoIntercepts as IoInfo, MsrIntercepts as MsrInfo};
use crate::guest::hv_layout::HypercallEntry;
use crate::guest::hypercall_input::{self, DecodedHypercall as Decoded};
use crate::guest::hypercalls::tlfs_hypercall;
use crate::session;
use crate::target::{ServedVp as Served, VP_STATE_REGISTERS};
use crate::types::VirtAddr;

/// The registers of one VTL of a Windows hypervisor VP (`!hvr`).
#[record]
pub struct VpRegisters {
    /// RIP, RSP, flags, control and segment registers, and the
    /// general-purpose ones when they are known.
    #[record(hex)]
    pub registers: Keyed<u64>,
    /// Where they are from: a vCPU that runs the VP now, the exit a vCPU
    /// in the hypervisor handles for it, or its last exit.
    pub source: String,
    /// Why the general-purpose registers are missing, when they are.
    pub missing: Option<String>,
}

/// A range of MSRs whose accesses exit, with the architectural MSRs (or
/// blocks, such as `x2APIC`) that ntoseye names in it.
#[record]
pub struct MsrRange {
    #[record(hex)]
    pub first: u32,
    #[record(hex)]
    pub last: u32,
    pub names: Vec<&'static str>,
}

/// Which RDMSRs and WRMSRs of a VTL exit (`!hvvmcs -msr`). MSRs outside
/// the bitmap's 0x0-0x1fff and 0xc0000000-0xc0001fff always exit.
#[record]
pub struct MsrIntercepts {
    /// Whether every RDMSR and WRMSR exits: the controls use no MSR
    /// bitmap, and the lists are empty.
    pub every: bool,
    /// The MSR bitmap's physical address, or None without one.
    #[record(hex)]
    pub bitmap: Option<u64>,
    /// The MSR ranges whose reads exit.
    pub read: Vec<MsrRange>,
    /// The MSR ranges whose writes exit.
    pub write: Vec<MsrRange>,
    /// The MSRs ntoseye names that the VTL reads without an exit.
    pub read_without_exit: Vec<&'static str>,
    /// The MSRs ntoseye names that the VTL writes without an exit.
    pub write_without_exit: Vec<&'static str>,
}

/// A range of I/O ports whose accesses exit.
#[record]
pub struct PortRange {
    #[record(hex)]
    pub first: u32,
    #[record(hex)]
    pub last: u32,
}

/// Which I/O instructions of a VTL exit (`!hvvmcs -io`).
#[record]
pub struct IoIntercepts {
    /// Whether every I/O instruction exits: the controls use no I/O
    /// bitmaps but unconditional I/O exiting.
    pub every: bool,
    /// The port ranges whose accesses exit, through I/O bitmaps A and B.
    /// Empty with `every`, and when no I/O instruction exits.
    pub ports: Vec<PortRange>,
}

/// One call code of the hypervisor's hypercall table.
#[record]
pub struct Hypercall {
    #[record(hex)]
    pub code: u16,
    /// The TLFS name, or None for a code that the TLFS does not list.
    pub name: Option<&'static str>,
    /// Whether the call has its own handler, not the reserved code 0's.
    pub implemented: bool,
    /// Whether the call is a rep hypercall.
    pub rep: bool,
    /// Whether the call takes a variable-size header.
    pub variable_header: bool,
    pub input_size: u16,
    pub input_element_size: u16,
    pub output_size: u16,
    pub output_element_size: u16,
    pub handler: VirtAddr,
}

/// One field of a hypercall's input, as the Hyper-V TLFS lays it out.
#[record]
pub struct HypercallField {
    /// The TLFS parameter name, with its member for a structure
    /// (`ProcessorSet.ValidBanksMask`) and its index for an array
    /// (`Message[2]`); `Input[n]` for the raw qwords of a call whose
    /// layout ntoseye does not know.
    pub name: String,
    /// The offset in the input, from its first byte.
    pub offset: u16,
    /// The size in bytes, at most 8.
    pub size: u8,
    #[record(hex)]
    pub value: u64,
    /// What the value means, where it has a name or stands for a set
    /// (`HV_PARTITION_ID_SELF`, `VPs 0-3`, a register's TLFS name).
    pub meaning: Option<String>,
}

/// One element of a rep hypercall's input list.
#[record]
pub struct HypercallElement {
    pub index: u16,
    pub fields: Vec<HypercallField>,
}

/// The hypercall of a VMCALL exit, with its input decoded as the Hyper-V
/// TLFS lays it out (`!hvcall`).
#[record]
pub struct DecodedHypercall {
    /// The hypercall input value (RCX).
    #[record(hex)]
    pub input_value: u64,
    #[record(hex)]
    pub code: u16,
    /// The TLFS name, or None for a code that the TLFS does not list.
    pub name: Option<&'static str>,
    /// Whether the input is in registers (RDX, R8, and XMM0 to XMM5)
    /// rather than in memory.
    pub fast: bool,
    /// The size of the variable input header, in qwords.
    pub variable_header_size: u16,
    /// Whether the call is for the L0 hypervisor of a nested environment.
    pub nested: bool,
    pub rep_count: u16,
    /// The first rep element still to process; those before it are done.
    pub rep_start: u16,
    /// The guest physical address of the input (RDX), for a call whose
    /// input is in memory.
    #[record(hex)]
    pub input_gpa: Option<u64>,
    /// The guest physical address of the output (R8), for a call whose
    /// input is in memory.
    #[record(hex)]
    pub output_gpa: Option<u64>,
    /// Whether ntoseye knows the layout of the call's input. When it does
    /// not, `fields` holds the input as raw qwords: RDX and R8 for a fast
    /// call, else the first 8 qwords of the input.
    pub decoded: bool,
    pub fields: Vec<HypercallField>,
    /// A rep call's input list, each element up to the rep count.
    pub elements: Vec<HypercallElement>,
    /// Why some of the input is missing: an unreadable input page, input
    /// in XMM registers, or input past the end of its page.
    pub unavailable: Option<String>,
    /// The call on one line, as the stop header shows it.
    pub summary: String,
}

/// The guest partition's virtual processor that a processor in the
/// Windows hypervisor runs or last ran: the VP whose exit it handles, or
/// which it is about to enter.
#[record]
pub struct ServedVp {
    #[record(hex)]
    pub partition_id: u64,
    pub vp_index: u32,
    /// The VTL the VP runs in.
    pub vtl: u8,
    /// Where the VTL left off, when the partition walk read its state.
    pub rip: Option<VirtAddr>,
    /// Whether the processor's VP assist page names this VTL's eVMCS: the
    /// processor handles this VP's exit, or is about to enter it.
    pub current: bool,
    /// The VM-exit reason of the VTL's last exit.
    #[record(hex)]
    pub exit_reason: Option<u32>,
    /// The name of the exit reason (`HLT`, `VMCALL`, ...), if it is a
    /// common reason.
    pub exit_reason_name: Option<&'static str>,
    /// The guest's general-purpose registers other than `rsp` at the last
    /// exit, as `SavedVtlState.general_registers`. None when they are not
    /// known.
    #[record(hex)]
    pub general_registers: Option<Keyed<u64>>,
    /// The hypercall of a VMCALL exit whose registers are known.
    pub hypercall: Option<DecodedHypercall>,
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
pub fn exit_registers(registers: &HashMap<&'static str, u64>) -> Keyed<u64> {
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
