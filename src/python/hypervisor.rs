//! The Windows hypervisor's partitions and virtual processors
//! (`dbg.hypervisor_partitions()`), as the REPL's `!hvpartitions` and
//! `!hvvps` list them. Each call walks and validates them again.

use pyo3::prelude::*;
use pyo3::types::PyDict;

use super::handle::Owner;
use super::raise;
use super::record::PlainDict;
use crate::guest::ept::{Access, EptMapping as EptInfo, EptTranslation, differences};
use crate::guest::{HvPartition, HvVirtualProcessor, HvVtl, privilege_names};

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
    /// as `!hveptdiff` lists them: dicts with `start`, `end` (exclusive), and
    /// `vtl0` and `vtl1`, each access as `"r-x"`-style text (with `u` for
    /// user-mode execute under mode-based execute control) or `None` where
    /// that VTL maps nothing. Raises `NtoseyeError` unless both VTLs have eVMCS
    /// state and readable EPTs.
    fn ept_differences<'py>(&self, py: Python<'py>) -> PyResult<Vec<PlainDict<'py>>> {
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
        let text = |access: Option<Access>| access.map(|access| access.to_string());
        differences(&first, &second)
            .into_iter()
            .map(|difference| {
                let dict = PyDict::new(py);
                dict.set_item("start", difference.start)?;
                dict.set_item("end", difference.end)?;
                dict.set_item("vtl0", text(difference.first))?;
                dict.set_item("vtl1", text(difference.second))?;
                Ok(PlainDict(dict))
            })
            .collect()
    }

    /// Return the VP as a plain `dict` (`index`, `address`, `vtl`, and `vtls`,
    /// a dict from each VTL to its dict).
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

    /// Translate a guest physical address through this VTL's EPT, as
    /// `!hvept` does. Returns `None` when no entry maps it, and raises
    /// `NtoseyeError` without the VTL's eVMCS state or when a table is
    /// unreadable.
    fn translate(&self, py: Python<'_>, gpa: u64) -> PyResult<Option<EptMapping>> {
        let Some(state) = self.info.state else {
            return Err(raise("this VTL has no eVMCS state"));
        };
        let translation = self.owner.with(py, |session| {
            Ok(session.target.translate_guest_physical(&state, gpa))
        })?;
        match translation {
            Some(EptTranslation::Mapped(info)) => Ok(Some(EptMapping {
                owner: self.owner.clone_ref(py),
                info,
            })),
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

/// Where a guest physical address goes through one VTL's EPT, and the access
/// that every level of the walk allows.
#[pyclass(module = "ntoseye", frozen)]
pub struct EptMapping {
    owner: Owner,
    info: EptInfo,
}

#[pymethods]
impl EptMapping {
    /// The host physical address.
    #[getter]
    fn host_physical(&self, py: Python<'_>) -> PyResult<u64> {
        self.owner.check(py)?;
        Ok(self.info.host_physical)
    }

    /// The size of the mapping page: 4 KiB, 2 MiB, or 1 GiB.
    #[getter]
    fn page_size(&self, py: Python<'_>) -> PyResult<u64> {
        self.owner.check(py)?;
        Ok(self.info.page_size)
    }

    #[getter]
    fn read(&self, py: Python<'_>) -> PyResult<bool> {
        self.owner.check(py)?;
        Ok(self.info.read)
    }

    #[getter]
    fn write(&self, py: Python<'_>) -> PyResult<bool> {
        self.owner.check(py)?;
        Ok(self.info.write)
    }

    /// Execute access: supervisor-mode only when `user_execute` is not
    /// `None`.
    #[getter]
    fn execute(&self, py: Python<'_>) -> PyResult<bool> {
        self.owner.check(py)?;
        Ok(self.info.execute)
    }

    /// User-mode execute access when the VTL uses mode-based execute
    /// control, else `None`.
    #[getter]
    fn user_execute(&self, py: Python<'_>) -> PyResult<Option<bool>> {
        self.owner.check(py)?;
        Ok(self.info.user_execute)
    }

    /// The EPT memory type (0 UC, 1 WC, 4 WT, 5 WP, 6 WB).
    #[getter]
    fn memory_type(&self, py: Python<'_>) -> PyResult<u8> {
        self.owner.check(py)?;
        Ok(self.info.memory_type)
    }

    /// The entry of each level of the walk, from the PML4 down.
    #[getter]
    fn entries(&self, py: Python<'_>) -> PyResult<Vec<u64>> {
        self.owner.check(py)?;
        Ok(self.info.entries.clone())
    }

    fn __repr__(&self) -> String {
        let bit = |allowed: bool, letter: char| if allowed { letter } else { '-' };
        format!(
            "EptMapping(host_physical={:#x}, access='{}{}{}', page_size={:#x})",
            self.info.host_physical,
            bit(self.info.read, 'r'),
            bit(self.info.write, 'w'),
            bit(self.info.execute, 'x'),
            self.info.page_size
        )
    }
}
