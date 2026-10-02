//! The Windows hypervisor's partitions and virtual processors
//! (`dbg.hypervisor_partitions()`), as the REPL's `!hvpartitions` and
//! `!hvvps` list them. Each call walks and validates them again.

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};

use super::handle::Owner;
use super::memory::check_disassembly_count;
use super::record::PlainDict;
use super::{MAX_READ_LEN, err, raise, view_dict};
use crate::guest::ept::{EptTranslation, differences};
use crate::guest::hypercalls::HypercallCaller as Caller;
use crate::guest::{HvPartition, HvVirtualProcessor, HvVtl, evmcs_fields, privilege_names};
use crate::target::CodeExtent;
use crate::view::execution::{DisassembledInstruction, disasm_rows};
use crate::view::hypervisor::{
    DecodedHypercall, EptDifference, EptMapping, HypervisorProcessor, decoded_hypercall,
    ept_difference, ept_mapping, hypervisor_processor,
};
use crate::view::shape::{Hex, Keyed, Typed};

/// A partition of the Windows hypervisor, as it was when listed.
#[pyclass(module = "ntoseye", frozen)]
pub struct HypervisorPartition {
    owner: Owner,
    info: HvPartition,
}

impl HypervisorPartition {
    pub fn new(owner: Owner, info: HvPartition) -> Self {
        Self { owner, info }
    }
}

#[pymethods]
impl HypervisorPartition {
    /// The address of the hypervisor's partition object.
    #[getter]
    fn address(&self, py: Python<'_>) -> PyResult<u64> {
        self.owner.check(py)?;
        Ok(self.info.address)
    }

    /// The partition ID (the root partition's is 1).
    #[getter]
    fn id(&self, py: Python<'_>) -> PyResult<u64> {
        self.owner.check(py)?;
        Ok(self.info.id)
    }

    /// The parent partition's ID, or `None` for the root partition.
    #[getter]
    fn parent_id(&self, py: Python<'_>) -> PyResult<Option<u64>> {
        self.owner.check(py)?;
        Ok(self.info.parent)
    }

    /// The partition's privileges, as the TLFS `HV_PARTITION_PRIVILEGE_MASK`.
    #[getter]
    fn privileges(&self, py: Python<'_>) -> PyResult<u64> {
        self.owner.check(py)?;
        Ok(self.info.privileges)
    }

    /// The TLFS names of the privileges in `privileges`
    /// (`["AccessVpRunTimeReg", ..., "CreatePartitions", ...]`). Set bits
    /// that the TLFS lists as reserved have no name and are left out.
    #[getter]
    fn privilege_names(&self, py: Python<'_>) -> PyResult<Vec<&'static str>> {
        self.owner.check(py)?;
        Ok(privilege_names(self.info.privileges).0)
    }

    /// The partition's virtual processors, by index.
    #[getter]
    fn virtual_processors(&self, py: Python<'_>) -> PyResult<Vec<VirtualProcessor>> {
        self.owner.check(py)?;
        Ok(self
            .info
            .virtual_processors
            .iter()
            .map(|info| VirtualProcessor {
                owner: self.owner.clone_ref(py),
                info: info.clone(),
            })
            .collect())
    }

    /// Return the partition as a plain `dict` (`address`, `id`, `parent_id`,
    /// `privileges`, `privilege_names`, and `virtual_processors`, a list of their dicts).
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<PlainDict<'py>> {
        self.owner.check(py)?;
        let dict = PyDict::new(py);
        dict.set_item("address", self.info.address)?;
        dict.set_item("id", self.info.id)?;
        dict.set_item("parent_id", self.info.parent)?;
        dict.set_item("privileges", self.info.privileges)?;
        dict.set_item("privilege_names", privilege_names(self.info.privileges).0)?;
        let vps = self
            .info
            .virtual_processors
            .iter()
            .map(|vp| vp_dict(py, vp))
            .collect::<PyResult<Vec<_>>>()?;
        dict.set_item("virtual_processors", vps)?;
        Ok(PlainDict(dict))
    }

    fn __repr__(&self) -> String {
        format!(
            "HypervisorPartition(id={:#x}, address={:#x}, virtual_processors={})",
            self.info.id,
            self.info.address,
            self.info.virtual_processors.len()
        )
    }
}

/// A virtual processor of a Windows hypervisor partition.
#[pyclass(module = "ntoseye", frozen)]
pub struct VirtualProcessor {
    owner: Owner,
    info: HvVirtualProcessor,
}

fn vtl_map<'py>(py: Python<'py>, vp: &HvVirtualProcessor) -> PyResult<Bound<'py, PyDict>> {
    let map = PyDict::new(py);
    for vtl in &vp.vtls {
        map.set_item(vtl.level, vtl_dict(py, vtl)?)?;
    }
    Ok(map)
}

fn vtl_dict<'py>(py: Python<'py>, vtl: &HvVtl) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("level", vtl.level)?;
    dict.set_item("context", vtl.context)?;
    dict.set_item("vmcs", vtl.vmcs)?;
    dict.set_item("ept_pointer", vtl.state.map(|state| state.ept_pointer))?;
    dict.set_item("rip", vtl.state.map(|state| state.rip))?;
    dict.set_item("exit_reason", vtl.state.map(|state| state.exit_reason))?;
    Ok(dict)
}

fn vp_dict<'py>(py: Python<'py>, vp: &HvVirtualProcessor) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("index", vp.index)?;
    dict.set_item("address", vp.address)?;
    let processors = vp
        .processors
        .iter()
        .map(|processor| view_dict(py, hypervisor_processor(processor)))
        .collect::<PyResult<Vec<_>>>()?;
    dict.set_item("processors", processors)?;
    dict.set_item("vtl", vp.vtl)?;
    dict.set_item("vtls", vtl_map(py, vp)?)?;
    Ok(dict)
}

#[pymethods]
impl VirtualProcessor {
    /// The VP index in its partition.
    #[getter]
    fn index(&self, py: Python<'_>) -> PyResult<u32> {
        self.owner.check(py)?;
        Ok(self.info.index)
    }

    /// The address of the hypervisor's VP object.
    #[getter]
    fn address(&self, py: Python<'_>) -> PyResult<u64> {
        self.owner.check(py)?;
        Ok(self.info.address)
    }

    /// The processors whose current VP this is (the one that runs it, or ran
    /// it last).
    #[getter]
    fn processors<'py>(&self, py: Python<'py>) -> PyResult<Typed<'py, Vec<HypervisorProcessor>>> {
        self.owner.check(py)?;
        Typed::new(
            py,
            self.info
                .processors
                .iter()
                .map(hypervisor_processor)
                .collect(),
        )
    }

    /// The VTL that the VP runs, or last ran, in.
    #[getter]
    fn vtl(&self, py: Python<'_>) -> PyResult<u8> {
        self.owner.check(py)?;
        Ok(self.info.vtl)
    }

    /// Each VTL enabled on the VP, keyed by VTL (`{0: ..., 1: ...}` under
    /// VBS).
    #[getter]
    fn vtls(&self, py: Python<'_>) -> PyResult<std::collections::BTreeMap<u8, HypervisorVtl>> {
        self.owner.check(py)?;
        Ok(self
            .info
            .vtls
            .iter()
            .map(|vtl| {
                (
                    vtl.level,
                    HypervisorVtl {
                        owner: self.owner.clone_ref(py),
                        info: vtl.clone(),
                    },
                )
            })
            .collect())
    }

    /// The guest physical ranges that VTL0's and VTL1's EPTs map differently,
    /// in order, as `!hveptdiff` lists them. Raises `NtoseyeError` unless both
    /// VTLs have eVMCS state and readable EPTs.
    fn ept_differences<'py>(&self, py: Python<'py>) -> PyResult<Typed<'py, Vec<EptDifference>>> {
        let state = |level: u8| {
            self.info
                .vtls
                .iter()
                .find(|vtl| vtl.level == level)
                .and_then(|vtl| vtl.state)
        };
        let (Some(vtl0), Some(vtl1)) = (state(0), state(1)) else {
            return Err(raise("this VP has no eVMCS state for both VTL0 and VTL1"));
        };
        let mappings = self.owner.with(py, |session| {
            Ok((
                session.target.guest_physical_mappings(&vtl0),
                session.target.guest_physical_mappings(&vtl1),
            ))
        })?;
        let (Some(first), Some(second)) = mappings else {
            return Err(raise("an EPT is unreadable or not a 4-level walk"));
        };
        Typed::new(
            py,
            differences(&first, &second)
                .iter()
                .map(ept_difference)
                .collect(),
        )
    }

    /// Return the VP as a plain `dict` (`index`, `address`, `processors`,
    /// `vtl`, and `vtls`, a dict from each VTL to its dict).
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<PlainDict<'py>> {
        self.owner.check(py)?;
        Ok(PlainDict(vp_dict(py, &self.info)?))
    }

    fn __repr__(&self) -> String {
        format!(
            "VirtualProcessor(index={}, address={:#x}, vtl={})",
            self.info.index, self.info.address, self.info.vtl
        )
    }
}

/// One VTL of a virtual processor: the hypervisor's context for it and, when
/// found, its eVMCS and the guest state saved there.
#[pyclass(module = "ntoseye", frozen)]
pub struct HypervisorVtl {
    owner: Owner,
    info: HvVtl,
}

#[pymethods]
impl HypervisorVtl {
    /// The VTL (0 for NT, 1 for the secure kernel).
    #[getter]
    fn level(&self, py: Python<'_>) -> PyResult<u8> {
        self.owner.check(py)?;
        Ok(self.info.level)
    }

    /// The address of the hypervisor's context object for this VTL.
    #[getter]
    fn context(&self, py: Python<'_>) -> PyResult<u64> {
        self.owner.check(py)?;
        Ok(self.info.context)
    }

    /// The physical address of the VTL's eVMCS, or `None` when ntoseye did
    /// not find where the context keeps it (no `hv-evmcs`).
    #[getter]
    fn vmcs(&self, py: Python<'_>) -> PyResult<Option<u64>> {
        self.owner.check(py)?;
        Ok(self.info.vmcs)
    }

    /// The VTL's EPT pointer, the root of its second-level address
    /// translation, or `None` without the eVMCS.
    #[getter]
    fn ept_pointer(&self, py: Python<'_>) -> PyResult<Option<u64>> {
        self.owner.check(py)?;
        Ok(self.info.state.map(|state| state.ept_pointer))
    }

    /// The guest RIP where the VTL left off, or `None` without the eVMCS.
    #[getter]
    fn rip(&self, py: Python<'_>) -> PyResult<Option<u64>> {
        self.owner.check(py)?;
        Ok(self.info.state.map(|state| state.rip))
    }

    /// The basic reason (Intel SDM Appendix C) the VTL last left for the
    /// hypervisor, or `None` without the eVMCS.
    #[getter]
    fn exit_reason(&self, py: Python<'_>) -> PyResult<Option<u32>> {
        self.owner.check(py)?;
        Ok(self.info.state.map(|state| state.exit_reason))
    }

    /// Return the VTL as a plain `dict` (`level`, `context`, `vmcs`,
    /// `ept_pointer`, `rip`, `exit_reason`).
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<PlainDict<'py>> {
        self.owner.check(py)?;
        Ok(PlainDict(vtl_dict(py, &self.info)?))
    }

    /// Read `size` bytes of the memory of this VTL's guest, as `!hvd` does:
    /// guest virtual memory through the VTL's page tables (its saved CR3),
    /// or with `physical=True` guest physical memory, both through the VTL's
    /// EPT. Raises `NtoseyeError` without the VTL's eVMCS state or when a
    /// page is not mapped, and for a virtual address unless the guest is in
    /// 4-level long-mode paging. The memory is read-only.
    #[pyo3(signature = (address, size, physical = false))]
    fn read<'py>(
        &self,
        py: Python<'py>,
        address: u64,
        size: usize,
        physical: bool,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let Some(state) = self.info.state else {
            return Err(raise("this VTL has no eVMCS state"));
        };
        if size > MAX_READ_LEN {
            return Err(raise(format!("read length {size} exceeds {MAX_READ_LEN}")));
        }
        let mut buf = vec![0u8; size];
        self.owner.with(py, |session| {
            session
                .target
                .read_guest_partition(&state, !physical, address, &mut buf)
                .map_err(err)
        })?;
        Ok(PyBytes::new(py, &buf))
    }

    /// Translate a guest virtual address of this VTL's guest through its page
    /// tables and its EPT: `(guest_physical, host_physical)`, or `None` when
    /// the page tables do not map it. Raises `NtoseyeError` unless the guest
    /// is in 4-level long-mode paging.
    fn translate_virtual(&self, py: Python<'_>, address: u64) -> PyResult<Option<(u64, u64)>> {
        let Some(state) = self.info.state else {
            return Err(raise("this VTL has no eVMCS state"));
        };
        self.owner.with(py, |session| {
            session
                .target
                .translate_guest_partition(&state, address)
                .map_err(err)
        })
    }

    /// Disassemble `count` instructions of this VTL's guest at `address`, as
    /// `!hvu` does: read as `read` reads it (guest virtual, or with
    /// `physical=True` guest physical), and decoded in the mode the VTL left
    /// off in, 64-bit in IA-32e mode with a 64-bit code segment, else
    /// 32-bit. Branch and RIP-relative comments are addresses: there are no
    /// symbols for a guest. The listing stops at the first unreadable page,
    /// so it can hold fewer than `count` instructions. Raises `NtoseyeError`
    /// when the first instruction is unreadable, without the VTL's eVMCS
    /// state, for real-mode or 16-bit code, and for a virtual address
    /// unless the guest is in 4-level long-mode paging.
    #[pyo3(signature = (address, count, physical = false))]
    fn disassemble<'py>(
        &self,
        py: Python<'py>,
        address: u64,
        count: usize,
        physical: bool,
    ) -> PyResult<Typed<'py, Vec<DisassembledInstruction>>> {
        let Some(state) = self.info.state else {
            return Err(raise("this VTL has no eVMCS state"));
        };
        check_disassembly_count(count)?;
        let code = self.owner.with(py, |session| {
            session
                .target
                .disassemble_guest_partition(&state, !physical, address, CodeExtent::Count(count))
                .map_err(err)
        })?;
        if let (true, Some(at)) = (code.rows.is_empty(), code.unreadable) {
            return Err(raise(format!("guest memory at {at:#x} is unreadable")));
        }
        Typed::new(py, disasm_rows(&code.rows))
    }

    /// Every field of this VTL's eVMCS, read now, named as the TLFS names it
    /// (`guest_rip`, `msr_bitmap`, ...), as `!hvvmcs` shows them:
    /// `fields.guest_rip` or `fields["guest_rip"]`. Raises `NtoseyeError`
    /// without the VTL's eVMCS.
    fn vmcs_fields<'py>(&self, py: Python<'py>) -> PyResult<Typed<'py, Keyed<Hex>>> {
        let Some(page) = self.info.vmcs else {
            return Err(raise("this VTL has no eVMCS"));
        };
        let mut vmcs = vec![0u8; 0x400];
        self.owner.with(py, |session| {
            session.target.read_physical(page, &mut vmcs).map_err(err)
        })?;
        Typed::new(
            py,
            evmcs_fields::field_values(&vmcs)
                .into_iter()
                .map(|(name, _, _, value)| (name, value))
                .collect(),
        )
    }

    /// Translate a guest physical address through this VTL's EPT, as
    /// `!hvept` does. Returns `None` when no entry maps it, and raises
    /// `NtoseyeError` without the VTL's eVMCS state or when a table is
    /// unreadable.
    fn translate<'py>(
        &self,
        py: Python<'py>,
        gpa: u64,
    ) -> PyResult<Option<Typed<'py, EptMapping>>> {
        let Some(state) = self.info.state else {
            return Err(raise("this VTL has no eVMCS state"));
        };
        let translation = self.owner.with(py, |session| {
            Ok(session.target.translate_guest_physical(&state, gpa))
        })?;
        match translation {
            Some(EptTranslation::Mapped(info)) => Typed::new(py, ept_mapping(&info)).map(Some),
            Some(EptTranslation::NotPresent { .. }) => Ok(None),
            None => Err(raise("the EPT is unreadable or not a 4-level walk")),
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "HypervisorVtl(level={}, context={:#x}, vmcs={})",
            self.info.level,
            self.info.context,
            self.info
                .vmcs
                .map_or_else(|| "None".to_string(), |page| format!("{page:#x}"))
        )
    }
}

/// The virtual processor whose hypercall a processor halted in the Windows
/// hypervisor handles (`cpu.hypercall_caller()`), found as `!hvcall` and a
/// hypercall breakpoint's filter find it: the call as the caller made it,
/// and the caller's memory, which a hypercall breakpoint's condition reads.
#[pyclass(module = "ntoseye", frozen)]
pub struct HypercallCaller {
    owner: Owner,
    info: Caller,
}

impl HypercallCaller {
    pub fn new(owner: Owner, info: Caller) -> Self {
        Self { owner, info }
    }
}

#[pymethods]
impl HypercallCaller {
    /// The caller's partition ID (the root partition's is 1).
    #[getter]
    fn partition_id(&self, py: Python<'_>) -> PyResult<u64> {
        self.owner.check(py)?;
        Ok(self.info.partition)
    }

    /// Whether the caller is a VP of the root partition (Windows itself)
    /// rather than of a guest partition.
    #[getter]
    fn root(&self, py: Python<'_>) -> PyResult<bool> {
        self.owner.check(py)?;
        Ok(self.info.root)
    }

    /// The caller's VP index in its partition.
    #[getter]
    fn vp_index(&self, py: Python<'_>) -> PyResult<u32> {
        self.owner.check(py)?;
        Ok(self.info.vp)
    }

    /// The VTL that made the call.
    #[getter]
    fn vtl(&self, py: Python<'_>) -> PyResult<u8> {
        self.owner.check(py)?;
        Ok(self.info.vtl)
    }

    /// The caller's registers at its VMCALL by name (`rcx`, `rdx`, `r8`,
    /// `rip`, `cr3`, ...), as a hypercall breakpoint's condition sees them:
    /// RIP, RSP, flags, control and segment registers from the calling
    /// VTL's eVMCS, and the general-purpose registers when ntoseye
    /// recovered them. Empty when the state ntoseye found is an older
    /// exit's.
    #[getter]
    fn registers(&self, py: Python<'_>) -> PyResult<std::collections::HashMap<String, u64>> {
        self.owner.check(py)?;
        Ok(self.info.registers.clone())
    }

    /// The call with its input decoded, as `!hvcall` shows it, or `None`
    /// when the caller's registers are not known.
    #[getter]
    fn hypercall<'py>(&self, py: Python<'py>) -> PyResult<Typed<'py, Option<DecodedHypercall>>> {
        self.owner.check(py)?;
        Typed::new(py, self.info.input.call().map(decoded_hypercall))
    }

    /// Read `size` bytes of the caller's memory, as a hypercall
    /// breakpoint's condition reads it: guest virtual memory through the
    /// calling VTL's page tables (its CR3), or with `physical=True` guest
    /// physical memory (a slow call's input, at the GPA in `rdx`), both
    /// through its EPT. The memory is read now, so read it while the target
    /// is halted at the call. Raises `NtoseyeError` when the caller's state
    /// at the call is not known, when a page is not mapped, and for a
    /// virtual address unless the caller is in 4-level long-mode paging.
    /// The memory is read-only.
    #[pyo3(signature = (address, size, physical = false))]
    fn read<'py>(
        &self,
        py: Python<'py>,
        address: u64,
        size: usize,
        physical: bool,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let Some(state) = self.info.state else {
            return Err(raise(
                "the caller's saved state is an older exit's, so its memory is not known",
            ));
        };
        if size > MAX_READ_LEN {
            return Err(raise(format!("read length {size} exceeds {MAX_READ_LEN}")));
        }
        let mut buf = vec![0u8; size];
        self.owner.with(py, |session| {
            session
                .target
                .read_guest_partition(&state, !physical, address, &mut buf)
                .map_err(err)
        })?;
        Ok(PyBytes::new(py, &buf))
    }

    /// Return the caller as a plain `dict` (`partition_id`, `root`,
    /// `vp_index`, `vtl`, `registers`, and `hypercall`, the call's dict or
    /// `None`).
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<PlainDict<'py>> {
        self.owner.check(py)?;
        let dict = PyDict::new(py);
        dict.set_item("partition_id", self.info.partition)?;
        dict.set_item("root", self.info.root)?;
        dict.set_item("vp_index", self.info.vp)?;
        dict.set_item("vtl", self.info.vtl)?;
        dict.set_item("registers", self.info.registers.clone())?;
        let hypercall = match self.info.input.call() {
            Some(call) => Some(view_dict(py, decoded_hypercall(call))?),
            None => None,
        };
        dict.set_item("hypercall", hypercall)?;
        Ok(PlainDict(dict))
    }

    fn __repr__(&self) -> String {
        format!("HypercallCaller({})", self.info.label())
    }
}
