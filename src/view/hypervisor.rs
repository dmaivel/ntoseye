//! hypervisor: [`View`](super::View) builders for the Windows hypervisor's
//! processors, EPTs, and hypercall table.

use super::shape::{Hex, shapes};
use crate::guest::HvProcessor;
use crate::guest::ept::{Difference, EptMapping as EptInfo};
use crate::guest::hv_layout::HypercallEntry;
use crate::guest::hypercalls::tlfs_hypercall;
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
