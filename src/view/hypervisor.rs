//! hypervisor: the [`View`](super::View) of the Windows hypervisor's
//! hypercall table.

use ntoseye_macros::record;

use crate::guest::hv_layout::HypercallEntry;
use crate::guest::hypercalls::tlfs_hypercall;
use crate::types::VirtAddr;

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
