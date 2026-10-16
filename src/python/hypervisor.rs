//! The Windows hypervisor's partitions and virtual processors
//! (`dbg.hypervisor_partitions()`), as the REPL's `!hvpartitions` and
//! `!hvvps` list them. Each call walks and validates them again.

use std::collections::{BTreeMap, HashMap};

use ntoseye_macros::handle;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use super::handle::{Owner, require_halted};
use super::memory::check_disassembly_count;
use super::record::{Hex, Typed};
use super::{MAX_READ_LEN, err, raise};
use crate::disasm::DisasmRow;
use crate::guest::ept::{EptDifference, EptMapping, EptTranslation, differences};
use crate::guest::evmcs_fields::{IoIntercepts, MsrIntercepts};
use crate::guest::hypercalls::HypercallCallerInfo;
use crate::guest::{HvPartition, HvVirtualProcessor, HvVtl, evmcs_fields};
use crate::session::VpRegisters;
use crate::target::CodeExtent;
use crate::types::Keyed;

/// A partition of the Windows hypervisor, as it was when listed.
#[handle(record = HvPartition, key = id, impl)]
pub struct HypervisorPartition {
    owner: Owner,
    info: HvPartition,
}

impl HypervisorPartition {
    pub fn new(owner: Owner, info: HvPartition) -> Self {
        Self { owner, info }
    }
}

#[handle]
impl HypervisorPartition {
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
                partition: self.info.id,
                info: info.clone(),
            })
            .collect())
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
#[handle(record = HvVirtualProcessor, key = address, impl)]
pub struct VirtualProcessor {
    owner: Owner,
    /// The ID of the partition it belongs to.
    partition: u64,
    info: HvVirtualProcessor,
}

#[handle]
impl VirtualProcessor {
    /// Each VTL enabled on the VP, keyed by VTL (`{0: ..., 1: ...}` under
    /// VBS).
    #[getter]
    fn vtls(&self, py: Python<'_>) -> PyResult<BTreeMap<u8, HypervisorVtl>> {
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
        Typed::new(py, differences(&first, &second))
    }

    /// The registers of VTL `vtl` of this VP, by default the VTL it runs
    /// in, as `!hvr` shows them, whether or not a processor runs it: those
    /// of a vCPU that runs it now, those of the exit a vCPU in the
    /// hypervisor handles for it, or those it saved at its last exit, which
    /// it resumes with but for the exit's result, such as a hypercall's
    /// status in RAX (`source` says which). The general-purpose registers
    /// are shared by a VP's VTLs and belong to the one it runs in; another
    /// VTL's are its eVMCS state alone, and `missing` says why. Reads the
    /// target now, so it must be halted. This feature is experimental.
    #[pyo3(signature = (*, vtl=None))]
    fn registers<'py>(
        &self,
        py: Python<'py>,
        vtl: Option<u8>,
    ) -> PyResult<Typed<'py, VpRegisters>> {
        let found = self.owner.with(py, |session| {
            require_halted(session, "VirtualProcessor.registers")?;
            session
                .vp_registers(self.partition, self.info.index, vtl)
                .map_err(err)
        })?;
        Typed::new(py, found)
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
#[handle(record = HvVtl, key = context, impl)]
pub struct HypervisorVtl {
    owner: Owner,
    info: HvVtl,
}

impl HypervisorVtl {
    /// This VTL's eVMCS, read now.
    fn read_vmcs(&self, py: Python<'_>) -> PyResult<Vec<u8>> {
        let Some(page) = self.info.vmcs else {
            return Err(raise("this VTL has no eVMCS"));
        };
        let mut vmcs = vec![0u8; 0x400];
        self.owner.with(py, |session| {
            session.target.read_physical(page, &mut vmcs).map_err(err)
        })?;
        Ok(vmcs)
    }
}

#[handle]
impl HypervisorVtl {
    /// Read `size` bytes of the memory of this VTL's guest, as `!hvd` does:
    /// guest virtual memory through the VTL's page tables (its saved CR3),
    /// or with `physical=True` guest physical memory, both through the VTL's
    /// EPT. Raises `NtoseyeError` without the VTL's eVMCS state or when a
    /// page is not mapped, and for a virtual address unless the guest is in
    /// 4-level long-mode paging. The memory is read-only.
    #[pyo3(signature = (address, size, *, physical = false))]
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
    #[pyo3(signature = (address, count, *, physical = false))]
    fn disassemble<'py>(
        &self,
        py: Python<'py>,
        address: u64,
        count: usize,
        physical: bool,
    ) -> PyResult<Typed<'py, Vec<DisasmRow>>> {
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
        Typed::new(py, code.rows)
    }

    /// Every field of this VTL's eVMCS, read now, named as the TLFS names it
    /// (`guest_rip`, `msr_bitmap`, ...), as `!hvvmcs` shows them:
    /// `fields["guest_rip"]`. Raises `NtoseyeError` without the VTL's eVMCS.
    fn vmcs_fields<'py>(&self, py: Python<'py>) -> PyResult<Typed<'py, Keyed<u64>, Hex>> {
        let vmcs = self.read_vmcs(py)?;
        Typed::new(
            py,
            Keyed(
                evmcs_fields::field_values(&vmcs)
                    .into_iter()
                    .map(|(name, _, _, value)| (name, value))
                    .collect(),
            ),
        )
    }

    /// Which RDMSRs and WRMSRs of this VTL exit, as `!hvvmcs -msr` shows
    /// them: through its MSR bitmap when its controls use one, else every one
    /// (`every`). Each intercepted range names the architectural MSRs in it,
    /// and `read_without_exit` and `write_without_exit` list those the VTL
    /// accesses without an exit. MSRs outside the bitmap's 0x0-0x1fff and
    /// 0xc0000000-0xc0001fff always exit. Raises `NtoseyeError` without the
    /// VTL's eVMCS, or when the bitmap is unreadable.
    fn msr_intercepts<'py>(&self, py: Python<'py>) -> PyResult<Typed<'py, MsrIntercepts>> {
        let vmcs = self.read_vmcs(py)?;
        let intercepts = self.owner.with(py, |session| {
            evmcs_fields::msr_intercepts(&vmcs, |address, page| {
                session.target.read_physical(address, page)
            })
            .map_err(err)
        })?;
        Typed::new(py, intercepts)
    }

    /// Which I/O instructions of this VTL exit, as `!hvvmcs -io` shows them:
    /// the port ranges its I/O bitmaps intercept, or, when its controls use
    /// none, every port (`every`) or none. Raises `NtoseyeError` without the
    /// VTL's eVMCS, or when a bitmap is unreadable.
    fn io_intercepts<'py>(&self, py: Python<'py>) -> PyResult<Typed<'py, IoIntercepts>> {
        let vmcs = self.read_vmcs(py)?;
        let intercepts = self.owner.with(py, |session| {
            evmcs_fields::io_intercepts(&vmcs, |address, page| {
                session.target.read_physical(address, page)
            })
            .map_err(err)
        })?;
        Typed::new(py, intercepts)
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
            Some(EptTranslation::Mapped(info)) => Typed::new(py, info).map(Some),
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
#[handle(
    record = HypercallCallerInfo,
    key = vp,
    identity = HypercallCaller::identity,
    impl
)]
pub struct HypercallCaller {
    owner: Owner,
    info: HypercallCallerInfo,
}

impl HypercallCaller {
    pub fn new(owner: Owner, info: HypercallCallerInfo) -> Self {
        Self { owner, info }
    }

    /// The VP and VTL that made the call.
    fn identity(&self) -> (u64, u32, u8) {
        (self.info.partition, self.info.vp, self.info.vtl)
    }
}

#[handle]
impl HypercallCaller {
    /// The caller's registers at its VMCALL by name (`rcx`, `rdx`, `r8`,
    /// `rip`, `cr3`, ...), as a hypercall breakpoint's condition sees them:
    /// RIP, RSP, flags, control and segment registers from the calling
    /// VTL's eVMCS, and the general-purpose registers when ntoseye
    /// recovered them. Empty when the state ntoseye found is an older
    /// exit's.
    #[getter]
    fn registers(&self, py: Python<'_>) -> PyResult<HashMap<String, u64>> {
        self.owner.check(py)?;
        Ok(self.info.registers.clone())
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
    #[pyo3(signature = (address, size, *, physical = false))]
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

    fn __repr__(&self) -> String {
        format!("HypercallCaller({})", self.info.label())
    }
}
