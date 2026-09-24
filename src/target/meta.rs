//! Metadata inspectors shared by the REPL, Python SDK, and MCP.

use std::collections::HashSet;

use crate::backend::MemoryOps;
use crate::cpu_state::processor_count;
use crate::error::{Error, Result};
use crate::guest::{Guest, ModuleInfo};
use crate::kuser_shared::KuserSharedData;
use crate::layout::{StructRef, Types};
use crate::ntstatus::{ntstatus_name, win32_error_name};
use crate::session::Session;
use crate::symbols::ModuleSymbolStatus;
use crate::target::{DiagnosticValue, ListCursor, ListTermination, Target};
use crate::triage_report::time::filetime_to_iso;
use crate::types::VirtAddr;

const VERIFIER_LEVEL_FLAGS: &[(u64, &str)] = &[
    (0x0000_0001, "Special pool"),
    (0x0000_0002, "Force IRQL checking"),
    (0x0000_0004, "Low resources simulation"),
    (0x0000_0008, "Pool tracking"),
    (0x0000_0010, "I/O verification"),
    (0x0000_0020, "Deadlock detection"),
    (0x0000_0040, "Enhanced I/O verification"),
    (0x0000_0080, "DMA verification"),
    (0x0000_0100, "Security checks"),
    (0x0000_0200, "Force pending I/O requests"),
    (0x0000_0400, "IRP logging"),
    (0x0000_0800, "Miscellaneous checks"),
    (0x0000_2000, "Invariant MDL checking for stack"),
    (0x0000_4000, "Invariant MDL checking for driver"),
    (0x0000_8000, "Power framework delay fuzzing"),
    (0x0001_0000, "Port/miniport interface checking"),
    (0x0002_0000, "DDI compliance checking"),
    (0x0004_0000, "Systematic low resources simulation"),
    (0x0008_0000, "DDI compliance checking (additional)"),
    (0x0020_0000, "NDIS/WIFI verification"),
    (0x0080_0000, "Kernel synchronization delay fuzzing"),
    (0x0100_0000, "VM switch verification"),
    (0x0200_0000, "Code integrity checks"),
];

/// Decode Driver Verifier's bitmask in ascending bit order, retaining unknown
/// bits as `bit N` labels rather than silently dropping them.
pub fn decode_verifier_level_flags(level: u64) -> Vec<String> {
    (0..u64::BITS)
        .filter_map(|bit| {
            let mask = 1u64 << bit;
            (level & mask != 0).then(|| {
                VERIFIER_LEVEL_FLAGS
                    .iter()
                    .find(|(flag, _)| *flag == mask)
                    .map_or_else(|| format!("bit {bit}"), |(_, name)| (*name).to_string())
            })
        })
        .collect()
}

#[derive(Debug, Clone)]
pub struct VerifierStatistics {
    pub raise_irqls: DiagnosticValue<u64>,
    pub acquire_spin_locks: DiagnosticValue<u64>,
    pub synchronize_executions: DiagnosticValue<u64>,
    pub trims: DiagnosticValue<u64>,
    pub allocations_attempted: DiagnosticValue<u64>,
    pub allocations_succeeded: DiagnosticValue<u64>,
    pub allocations_succeeded_special_pool: DiagnosticValue<u64>,
    pub allocations_with_no_tag: DiagnosticValue<u64>,
    pub allocations_failed: DiagnosticValue<u64>,
    pub current_paged_pool_allocations: DiagnosticValue<u64>,
    pub paged_bytes: DiagnosticValue<u64>,
    pub peak_paged_pool_allocations: DiagnosticValue<u64>,
    pub peak_paged_bytes: DiagnosticValue<u64>,
    pub current_nonpaged_pool_allocations: DiagnosticValue<u64>,
    pub nonpaged_bytes: DiagnosticValue<u64>,
    pub peak_nonpaged_pool_allocations: DiagnosticValue<u64>,
    pub peak_nonpaged_bytes: DiagnosticValue<u64>,
    pub loads: DiagnosticValue<u64>,
    pub unloads: DiagnosticValue<u64>,
}

#[derive(Debug, Clone)]
pub struct VerifierSuspectDriver {
    pub address: VirtAddr,
    pub full_name: String,
    pub base_name: String,
    pub loads: u64,
    pub unloads: u64,
}

#[derive(Debug, Clone)]
pub struct VerifierDriverSummary {
    pub entry: VirtAddr,
    pub state: String,
    pub nonpaged_bytes: u64,
    pub paged_bytes: u64,
    pub module_name: String,
}

#[derive(Debug, Clone)]
pub struct VerifierDetail {
    pub level: DiagnosticValue<u64>,
    pub option_flags: DiagnosticValue<u64>,
    pub verify_mode: DiagnosticValue<u64>,
    pub level_options: DiagnosticValue<Vec<String>>,
    pub statistics: VerifierStatistics,
    pub drivers: DiagnosticValue<Vec<VerifierDriverSummary>>,
    /// True when an AVL table advertised fewer elements than its reachable
    /// tree, so the bounded walk stopped before visiting every link.
    pub drivers_truncated: bool,
    pub configured_but_unloaded: DiagnosticValue<Vec<VerifierSuspectDriver>>,
    /// Termination state of the bounded suspect-list walk.
    pub suspect_list_termination: ListTermination,
}

#[derive(Debug, Clone)]
pub struct VerifierDriverDetail {
    pub module_name: String,
    pub image_base: VirtAddr,
    pub image_size: u64,
    pub driver_object: VirtAddr,
    pub se_signing_level: u64,
    pub raise_irqls: u64,
    pub acquire_spin_locks: u64,
    pub synchronize_executions: u64,
    pub allocations_with_no_tag: u64,
    pub allocations_failed: u64,
    pub allocations_failed_deliberately: u64,
    pub current_paged_pool_allocations: u64,
    pub paged_bytes: u64,
    pub peak_paged_pool_allocations: u64,
    pub peak_paged_bytes: u64,
    pub current_nonpaged_pool_allocations: u64,
    pub nonpaged_bytes: u64,
    pub peak_nonpaged_pool_allocations: u64,
    pub peak_nonpaged_bytes: u64,
    pub locked_bytes: u64,
    pub peak_locked_bytes: u64,
    pub mapped_locked_bytes: u64,
    pub peak_mapped_locked_bytes: u64,
    pub mapped_io_space_bytes: u64,
    pub peak_mapped_io_space_bytes: u64,
    pub pages_for_mdl_bytes: u64,
    pub peak_pages_for_mdl_bytes: u64,
    pub contiguous_memory_bytes: u64,
    pub peak_contiguous_memory_bytes: u64,
    pub suspect: Option<VerifierSuspectDriver>,
}

#[derive(Clone)]
struct VerifierStateRead {
    level: DiagnosticValue<u64>,
    option_flags: DiagnosticValue<u64>,
    verify_mode: DiagnosticValue<u64>,
    statistics: VerifierStatistics,
}

#[derive(Clone)]
struct VerifiedData {
    suspect_entry: VirtAddr,
    se_signing_level: u64,
    raise_irqls: u64,
    acquire_spin_locks: u64,
    synchronize_executions: u64,
    allocations_with_no_tag: u64,
    allocations_failed: u64,
    allocations_failed_deliberately: u64,
    current_paged_pool_allocations: u64,
    current_nonpaged_pool_allocations: u64,
    peak_paged_pool_allocations: u64,
    peak_nonpaged_pool_allocations: u64,
    paged_bytes: u64,
    nonpaged_bytes: u64,
    peak_paged_bytes: u64,
    peak_nonpaged_bytes: u64,
    locked_bytes: u64,
    peak_locked_bytes: u64,
    mapped_locked_bytes: u64,
    peak_mapped_locked_bytes: u64,
    mapped_io_space_bytes: u64,
    peak_mapped_io_space_bytes: u64,
    pages_for_mdl_bytes: u64,
    peak_pages_for_mdl_bytes: u64,
    contiguous_memory_bytes: u64,
    peak_contiguous_memory_bytes: u64,
}

#[derive(Clone)]
struct SuspectDriver {
    address: VirtAddr,
    full_name: String,
    base_name: String,
    loads: u64,
    unloads: u64,
}

#[derive(Clone)]
struct VerifiedDriver {
    entry: VirtAddr,
    image_base: VirtAddr,
    image_size: u64,
    driver_object: VirtAddr,
    data: VerifiedData,
    suspect: Option<SuspectDriver>,
    module_name: String,
}

fn unavailable<T>(error: impl ToString) -> DiagnosticValue<T> {
    DiagnosticValue::Unavailable(error.to_string())
}

fn read_verifier_state(guest: &Guest) -> VerifierStateRead {
    let types = guest.ntoskrnl.types();
    let verifier = guest
        .ntoskrnl
        .symbol("MmVerifierData")
        .and_then(|symbol| types.struct_at("_MM_DRIVER_VERIFIER_DATA", symbol.address()));
    let read = |name: &str| match verifier.as_ref() {
        Ok(verifier) => DiagnosticValue::from_result(verifier.read_uint(name)),
        Err(error) => unavailable(error),
    };
    let option_flags = match guest.ntoskrnl.symbol("VfOptionFlags") {
        Ok(symbol) => DiagnosticValue::from_result(symbol.read::<u32>().map(u64::from)),
        Err(error) => unavailable(error),
    };
    VerifierStateRead {
        level: read("Level"),
        option_flags,
        verify_mode: read("VerifyMode"),
        statistics: VerifierStatistics {
            raise_irqls: read("RaiseIrqls"),
            acquire_spin_locks: read("AcquireSpinLocks"),
            synchronize_executions: read("SynchronizeExecutions"),
            trims: read("Trims"),
            allocations_attempted: read("AllocationsAttempted"),
            allocations_succeeded: read("AllocationsSucceeded"),
            allocations_succeeded_special_pool: read("AllocationsSucceededSpecialPool"),
            allocations_with_no_tag: read("AllocationsWithNoTag"),
            allocations_failed: read("AllocationsFailed"),
            current_paged_pool_allocations: read("CurrentPagedPoolAllocations"),
            paged_bytes: read("PagedBytes"),
            peak_paged_pool_allocations: read("PeakPagedPoolAllocations"),
            peak_paged_bytes: read("PeakPagedBytes"),
            current_nonpaged_pool_allocations: read("CurrentNonPagedPoolAllocations"),
            nonpaged_bytes: read("NonPagedBytes"),
            peak_nonpaged_pool_allocations: read("PeakNonPagedPoolAllocations"),
            peak_nonpaged_bytes: read("PeakNonPagedBytes"),
            loads: read("Loads"),
            unloads: read("Unloads"),
        },
    }
}

fn read_verified_data(types: Types<'_>, address: VirtAddr) -> Result<VerifiedData> {
    let data = types.struct_at("_VF_TARGET_VERIFIED_DRIVER_DATA", address)?;
    let read = |name: &str| data.read_uint(name);
    Ok(VerifiedData {
        suspect_entry: data.read_pointer("SuspectDriverEntry")?,
        se_signing_level: read("SeSigningLevel")?,
        raise_irqls: read("RaiseIrqls")?,
        acquire_spin_locks: read("AcquireSpinLocks")?,
        synchronize_executions: read("SynchronizeExecutions")?,
        allocations_with_no_tag: read("AllocationsWithNoTag")?,
        allocations_failed: read("AllocationsFailed")?,
        allocations_failed_deliberately: read("AllocationsFailedDeliberately")?,
        current_paged_pool_allocations: read("CurrentPagedPoolAllocations")?,
        current_nonpaged_pool_allocations: read("CurrentNonPagedPoolAllocations")?,
        peak_paged_pool_allocations: read("PeakPagedPoolAllocations")?,
        peak_nonpaged_pool_allocations: read("PeakNonPagedPoolAllocations")?,
        paged_bytes: read("PagedBytes")?,
        nonpaged_bytes: read("NonPagedBytes")?,
        peak_paged_bytes: read("PeakPagedBytes")?,
        peak_nonpaged_bytes: read("PeakNonPagedBytes")?,
        locked_bytes: read("LockedBytes")?,
        peak_locked_bytes: read("PeakLockedBytes")?,
        mapped_locked_bytes: read("MappedLockedBytes")?,
        peak_mapped_locked_bytes: read("PeakMappedLockedBytes")?,
        mapped_io_space_bytes: read("MappedIoSpaceBytes")?,
        peak_mapped_io_space_bytes: read("PeakMappedIoSpaceBytes")?,
        pages_for_mdl_bytes: read("PagesForMdlBytes")?,
        peak_pages_for_mdl_bytes: read("PeakPagesForMdlBytes")?,
        contiguous_memory_bytes: read("ContiguousMemoryBytes")?,
        peak_contiguous_memory_bytes: read("PeakContiguousMemoryBytes")?,
    })
}

fn read_suspect_driver(record: &StructRef<'_>) -> Result<SuspectDriver> {
    let full_name = record.unicode_string("FullName")?;
    let mut base_name = record.unicode_string("BaseName")?;
    if base_name.is_empty() {
        base_name = full_name
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or_default()
            .to_string();
    }
    Ok(SuspectDriver {
        address: record.addr(),
        full_name,
        base_name,
        loads: record.read_uint("Loads")?,
        unloads: record.read_uint("Unloads")?,
    })
}

fn read_suspect_list(guest: &Guest) -> Result<(Vec<SuspectDriver>, ListTermination)> {
    let types = guest.ntoskrnl.types();
    let head = guest.ntoskrnl.symbol("VfSuspectDriversList")?.address();
    let record_layout = types.layout("_VF_SUSPECT_DRIVER_ENTRY")?;
    let link_offset = record_layout.field_offset("Links")?;
    let first = types
        .struct_at("_LIST_ENTRY", head)?
        .read_pointer("Flink")?;
    let mut cursor = ListCursor::new(head, 1000);
    cursor.advance(Ok(first));
    let mut suspects = Vec::new();
    while let Some(link) = cursor.take_current() {
        let record = types
            .struct_at("_VF_SUSPECT_DRIVER_ENTRY", link - link_offset)?
            .prefetch();
        let next = record
            .embedded("Links")
            .and_then(|links| links.read_pointer("Flink"));
        suspects.push(read_suspect_driver(&record)?);
        cursor.advance(next.map_err(|error| error.to_string()));
    }
    let termination = cursor.finish();
    Ok((suspects, termination))
}

fn read_verified_driver(
    types: Types<'_>,
    links: VirtAddr,
    links_size: u64,
) -> Result<Option<VerifiedDriver>> {
    let entry = links + links_size;
    let driver = types.struct_at("_VF_TARGET_DRIVER", entry)?;
    let verified_data = driver.read_pointer("VerifiedData")?;
    if verified_data.is_zero() {
        return Ok(None);
    }
    let tree_node = driver.embedded("TreeNode")?;
    let image_base = tree_node.read_pointer("p")?;
    let image_size = tree_node.read_uint("RangeSize")?;
    let driver_object = driver.read_pointer("DriverObject")?;
    let data = read_verified_data(types, verified_data)?;
    let suspect = if data.suspect_entry.is_zero() {
        None
    } else {
        types
            .struct_at("_VF_SUSPECT_DRIVER_ENTRY", data.suspect_entry)
            .ok()
            .and_then(|record| read_suspect_driver(&record).ok())
    };
    Ok(Some(VerifiedDriver {
        entry,
        image_base,
        image_size,
        driver_object,
        data,
        suspect,
        module_name: String::new(),
    }))
}

fn walk_avl_table(
    types: Types<'_>,
    table_address: VirtAddr,
    links_size: u64,
) -> Result<(Vec<VerifiedDriver>, bool)> {
    let table = types.struct_at("_VF_AVL_TABLE", table_address)?;
    let rtl_table = table.embedded("RtlTable")?;
    let element_count = usize::try_from(rtl_table.read_uint("NumberGenericTableElements")?)
        .map_err(|_| Error::DebugInfo("invalid verifier AVL element count".into()))?;
    let root = rtl_table
        .embedded("BalancedRoot")?
        .read_pointer("RightChild")?;
    let mut stack = vec![(root, false)];
    let mut seen = HashSet::new();
    let mut drivers = Vec::new();
    let mut truncated = false;

    while let Some((links, expanded)) = stack.pop() {
        if links.is_zero() {
            continue;
        }
        if expanded {
            if let Some(driver) = read_verified_driver(types, links, links_size)? {
                drivers.push(driver);
            }
            continue;
        }
        if seen.len() >= element_count {
            truncated = true;
            continue;
        }
        if !seen.insert(links.0) {
            continue;
        }
        let node = types.struct_at("_RTL_BALANCED_LINKS", links)?;
        let left = node.read_pointer("LeftChild")?;
        let right = node.read_pointer("RightChild")?;
        stack.push((right, false));
        stack.push((links, true));
        stack.push((left, false));
    }
    Ok((drivers, truncated))
}

fn walk_verified_drivers(guest: &Guest) -> Result<(Vec<VerifiedDriver>, bool)> {
    let types = guest.ntoskrnl.types();
    let tree = types.struct_at(
        "_VF_AVL_TREE",
        guest.ntoskrnl.symbol("ViTargetDriversAvl")?.address(),
    )?;
    let tables = tree.read_pointer("Tables")?;
    let tables_count = usize::try_from(tree.read_uint("TablesNo")?)
        .map_err(|_| Error::DebugInfo("invalid verifier AVL table count".into()))?;
    if tables_count != 0 && tables.is_zero() {
        return Err(Error::DebugInfo("verifier AVL Tables is null".into()));
    }
    let table_layout = types.layout("_VF_AVL_TABLE")?;
    let links_size = types.layout("_RTL_BALANCED_LINKS")?.size as u64;
    if table_layout.size == 0 || links_size == 0 {
        return Err(Error::DebugInfo("invalid verifier AVL type size".into()));
    }

    let mut drivers = Vec::new();
    let mut truncated = false;
    for index in 0..tables_count {
        let address = tables + (index as u64).wrapping_mul(table_layout.size as u64);
        let (table_drivers, table_truncated) = walk_avl_table(types, address, links_size)?;
        drivers.extend(table_drivers);
        truncated |= table_truncated;
    }
    Ok((drivers, truncated))
}

fn module_key(name: &str) -> String {
    let name = name
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(name)
        .to_ascii_lowercase();
    name.strip_suffix(".sys").unwrap_or(&name).to_string()
}

fn set_module_names(drivers: &mut [VerifiedDriver], modules: &[ModuleInfo]) {
    for driver in drivers {
        driver.module_name = modules
            .iter()
            .find(|module| module.contains_address(driver.image_base))
            .map(|module| module.name.clone())
            .or_else(|| {
                driver
                    .suspect
                    .as_ref()
                    .filter(|suspect| !suspect.base_name.is_empty())
                    .map(|suspect| suspect.base_name.clone())
            })
            .unwrap_or_else(|| format!("{:#x}", driver.image_base.0));
    }
}

fn suspect_detail(suspect: &SuspectDriver) -> VerifierSuspectDriver {
    VerifierSuspectDriver {
        address: suspect.address,
        full_name: suspect.full_name.clone(),
        base_name: suspect.base_name.clone(),
        loads: suspect.loads,
        unloads: suspect.unloads,
    }
}

fn loaded_suspect(suspect: &SuspectDriver, drivers: &[VerifiedDriver]) -> bool {
    let key = module_key(&suspect.base_name);
    drivers.iter().any(|driver| {
        driver
            .suspect
            .as_ref()
            .is_some_and(|loaded| module_key(&loaded.base_name) == key)
    })
}

fn driver_summary(driver: &VerifiedDriver) -> VerifierDriverSummary {
    VerifierDriverSummary {
        entry: driver.entry,
        state: "Loaded".to_string(),
        nonpaged_bytes: driver.data.nonpaged_bytes,
        paged_bytes: driver.data.paged_bytes,
        module_name: driver.module_name.clone(),
    }
}

fn driver_detail(driver: &VerifiedDriver) -> VerifierDriverDetail {
    VerifierDriverDetail {
        module_name: driver.module_name.clone(),
        image_base: driver.image_base,
        image_size: driver.image_size,
        driver_object: driver.driver_object,
        se_signing_level: driver.data.se_signing_level,
        raise_irqls: driver.data.raise_irqls,
        acquire_spin_locks: driver.data.acquire_spin_locks,
        synchronize_executions: driver.data.synchronize_executions,
        allocations_with_no_tag: driver.data.allocations_with_no_tag,
        allocations_failed: driver.data.allocations_failed,
        allocations_failed_deliberately: driver.data.allocations_failed_deliberately,
        current_paged_pool_allocations: driver.data.current_paged_pool_allocations,
        paged_bytes: driver.data.paged_bytes,
        peak_paged_pool_allocations: driver.data.peak_paged_pool_allocations,
        peak_paged_bytes: driver.data.peak_paged_bytes,
        current_nonpaged_pool_allocations: driver.data.current_nonpaged_pool_allocations,
        nonpaged_bytes: driver.data.nonpaged_bytes,
        peak_nonpaged_pool_allocations: driver.data.peak_nonpaged_pool_allocations,
        peak_nonpaged_bytes: driver.data.peak_nonpaged_bytes,
        locked_bytes: driver.data.locked_bytes,
        peak_locked_bytes: driver.data.peak_locked_bytes,
        mapped_locked_bytes: driver.data.mapped_locked_bytes,
        peak_mapped_locked_bytes: driver.data.peak_mapped_locked_bytes,
        mapped_io_space_bytes: driver.data.mapped_io_space_bytes,
        peak_mapped_io_space_bytes: driver.data.peak_mapped_io_space_bytes,
        pages_for_mdl_bytes: driver.data.pages_for_mdl_bytes,
        peak_pages_for_mdl_bytes: driver.data.peak_pages_for_mdl_bytes,
        contiguous_memory_bytes: driver.data.contiguous_memory_bytes,
        peak_contiguous_memory_bytes: driver.data.peak_contiguous_memory_bytes,
        suspect: driver.suspect.as_ref().map(suspect_detail),
    }
}

impl Target {
    /// Decode Driver Verifier's global level, option flags, independent
    /// counters, loaded AVL entries, and configured-but-unloaded suspect
    /// entries. `level`, `option_flags`, `verify_mode`, and `level_options`
    /// describe the global configuration; each statistics field carries its
    /// own read/layout error, while `drivers` and
    /// `configured_but_unloaded` carry an AVL/list-walk error when that whole
    /// collection is unavailable. Every [`DiagnosticValue`] retains the exact
    /// field, layout, or bounded-walk error for only the value that was
    /// unavailable.
    pub fn verifier_status(&self) -> Result<VerifierDetail> {
        let guest = self.guest()?;
        let state = read_verifier_state(guest);
        let level_options = match &state.level {
            DiagnosticValue::Available(level) => {
                DiagnosticValue::Available(decode_verifier_level_flags(*level))
            }
            DiagnosticValue::Unavailable(error) => DiagnosticValue::Unavailable(error.clone()),
        };

        let modules = self.kernel_modules().unwrap_or_default();
        let (drivers, loaded_drivers, drivers_truncated) = match walk_verified_drivers(guest) {
            Ok((mut drivers, truncated)) => {
                set_module_names(&mut drivers, &modules);
                (
                    DiagnosticValue::Available(drivers.iter().map(driver_summary).collect()),
                    Some(drivers),
                    truncated,
                )
            }
            Err(error) => (unavailable(error), None, false),
        };
        let (configured_but_unloaded, suspect_list_termination) = match read_suspect_list(guest) {
            Ok((suspects, termination)) => {
                let loaded = loaded_drivers.as_deref().unwrap_or(&[]);
                (
                    DiagnosticValue::Available(
                        suspects
                            .iter()
                            .filter(|suspect| !loaded_suspect(suspect, loaded))
                            .map(suspect_detail)
                            .collect(),
                    ),
                    termination,
                )
            }
            Err(error) => {
                let error = error.to_string();
                (unavailable(error.clone()), ListTermination::Corrupt(error))
            }
        };

        Ok(VerifierDetail {
            level: state.level,
            option_flags: state.option_flags,
            verify_mode: state.verify_mode,
            level_options,
            statistics: state.statistics,
            drivers,
            drivers_truncated,
            configured_but_unloaded,
            suspect_list_termination,
        })
    }

    /// Decode the verified-driver AVL entry matching `module`, including image
    /// range, signing level, verifier counters, and suspect-driver load counts.
    /// A missing module or an unreadable required field is returned as an error;
    /// optional suspect load counts are absent when no suspect entry is linked.
    pub fn verifier_driver(&self, module: &str) -> Result<VerifierDriverDetail> {
        let guest = self.guest()?;
        let (mut drivers, _) = walk_verified_drivers(guest)?;
        let modules = self.kernel_modules().unwrap_or_default();
        set_module_names(&mut drivers, &modules);
        let driver = drivers
            .iter()
            .find(|driver| module_key(&driver.module_name) == module_key(module))
            .or_else(|| {
                drivers.iter().find(|driver| {
                    driver
                        .suspect
                        .as_ref()
                        .is_some_and(|suspect| module_key(&suspect.base_name) == module_key(module))
                })
            })
            .ok_or_else(|| Error::DebugInfo(format!("unknown verifier module: {module}")))?;
        Ok(driver_detail(driver))
    }
}

#[derive(Debug, Clone)]
pub struct TargetKernelDetail {
    pub name: String,
    pub short_name: String,
    pub base: VirtAddr,
    pub size: Option<u64>,
    pub file_version: Option<String>,
    pub product_version: Option<String>,
    pub pdb_guid: Option<String>,
    pub pdb_age: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct TargetDumpMetadata {
    pub is_triage: bool,
    pub directory_table_base: VirtAddr,
    pub bugcheck_code: u32,
    pub bugcheck_parameters: Vec<u64>,
    pub number_processors: u32,
    pub major_version: u32,
    pub minor_version: u32,
    pub product_type: u32,
    pub machine_image_type: u32,
    pub service_pack_build: u32,
    pub system_time: Option<u64>,
    pub uptime_seconds: Option<u64>,
    pub exception_code: Option<u32>,
    pub triage_overflowed: bool,
    pub kernel_base: Option<VirtAddr>,
}

#[derive(Debug, Clone)]
pub struct TargetVersionDetail {
    pub major_version: Option<u64>,
    pub minor_version: Option<u64>,
    pub build_number: Option<u64>,
    pub build_lab: Option<String>,
    pub architecture: String,
    pub processors: Option<u16>,
    pub product: String,
    pub kernel: Option<TargetKernelDetail>,
    pub symbol_status: Option<String>,
    pub debugger_version: String,
    pub symbol_path: String,
    pub system_time: Option<u64>,
    pub system_time_iso: Option<String>,
    pub uptime_seconds: Option<u64>,
    pub uptime: Option<String>,
    pub backend: Option<String>,
    pub dump: Option<TargetDumpMetadata>,
}

#[derive(Debug, Clone)]
pub struct TargetTimeDetail {
    pub system_time: Option<u64>,
    pub system_time_iso: Option<String>,
    pub uptime_seconds: Option<u64>,
    pub uptime: Option<String>,
}

fn dump_system_time(target: &Target) -> Option<u64> {
    target
        .phys
        .dmp_info()
        .and_then(|info| info.system_info.as_ref())
        .map(|info| info.system_time)
        .filter(|time| *time > 0)
        .map(|time| time as u64)
}

fn dump_uptime_seconds(target: &Target) -> Option<u64> {
    target
        .phys
        .dmp_info()
        .and_then(|info| info.system_info.as_ref())
        .map(|info| info.system_up_time)
        .filter(|time| *time > 0)
        .map(|time| time as u64)
}

fn system_time(target: &Target, kuser: &KuserSharedData<'_>) -> Option<u64> {
    dump_system_time(target).or_else(|| kuser.system_time().filter(|time| *time > 0))
}

fn uptime_seconds(target: &Target, kuser: &KuserSharedData<'_>) -> Option<u64> {
    dump_uptime_seconds(target).or_else(|| {
        kuser
            .interrupt_time()
            .filter(|ticks| *ticks > 0)
            .map(|ticks| ticks / 10_000_000)
    })
}

fn target_time(target: &Target, kuser: &KuserSharedData<'_>) -> TargetTimeDetail {
    let system_time = system_time(target, kuser);
    let uptime_seconds = uptime_seconds(target, kuser);
    TargetTimeDetail {
        system_time,
        system_time_iso: system_time.and_then(filetime_to_iso),
        uptime_seconds,
        uptime: uptime_seconds.map(format_uptime),
    }
}

fn format_uptime(seconds: u64) -> String {
    let days = seconds / 86_400;
    let hours = (seconds / 3_600) % 24;
    let minutes = (seconds / 60) % 60;
    let seconds = seconds % 60;
    format!("{days}d {hours:02}:{minutes:02}:{seconds:02}")
}

fn shared_build_lab(target: &Target) -> Option<String> {
    let guest = target.guest().ok()?;
    let address = guest.ntoskrnl.symbol("NtBuildLab").ok()?.address();
    let mut bytes = [0u8; 128];
    guest
        .ntoskrnl
        .memory()
        .read_bytes(address, &mut bytes)
        .ok()?;
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    let text = String::from_utf8_lossy(&bytes[..end]).trim().to_string();
    (!text.is_empty()).then_some(text)
}

fn symbol_build_number(target: &Target) -> Option<u64> {
    let guest = target.guest().ok()?;
    guest
        .ntoskrnl
        .symbol("NtBuildNumber")
        .and_then(|symbol| symbol.read::<u16>())
        .ok()
        .map(u64::from)
}

fn product_label(product: Option<u64>) -> String {
    match product {
        Some(1) => "Workstation".to_string(),
        Some(2) => "DomainController".to_string(),
        Some(3) => "Server".to_string(),
        _ => "unknown".to_string(),
    }
}

fn dump_metadata(target: &Target, kernel_base: Option<VirtAddr>) -> Option<TargetDumpMetadata> {
    target.phys.dmp_info().map(|info| {
        let system_info = info.system_info.as_ref();
        TargetDumpMetadata {
            is_triage: info.is_triage,
            directory_table_base: VirtAddr(info.directory_table_base),
            bugcheck_code: info.bug_check_code,
            bugcheck_parameters: info.bug_check_parameters.to_vec(),
            number_processors: info.number_processors,
            major_version: system_info.map_or(0, |value| value.major_version),
            minor_version: system_info.map_or(0, |value| value.minor_version),
            product_type: system_info.map_or(0, |value| value.product_type),
            machine_image_type: system_info.map_or(0, |value| value.machine_image_type),
            service_pack_build: system_info.map_or(0, |value| value.service_pack_build),
            system_time: system_info
                .map(|value| value.system_time)
                .filter(|value| *value > 0)
                .map(|value| value as u64),
            uptime_seconds: system_info
                .map(|value| value.system_up_time)
                .filter(|value| *value > 0)
                .map(|value| value as u64),
            exception_code: info.exception.as_ref().map(|exception| exception.code),
            triage_overflowed: info.triage_overflowed,
            kernel_base: info
                .kern_base
                .filter(|value| *value != 0)
                .map(VirtAddr)
                .or(kernel_base),
        }
    })
}

impl Target {
    /// Decode target/kernel build strings, architecture, target-known
    /// processor count, kernel image and symbol status, debugger version, time
    /// metadata, and dump-header metadata when this target came from a dump.
    pub fn target_version(&self) -> Result<TargetVersionDetail> {
        let dump_info = self
            .phys
            .dmp_info()
            .and_then(|info| info.system_info.as_ref());
        let kuser = KuserSharedData::new(self);
        let major = dump_info
            .map(|info| info.major_version as u64)
            .filter(|value| *value != 0)
            .or_else(|| kuser.nt_major_version());
        let minor = dump_info
            .map(|info| info.minor_version as u64)
            .filter(|value| *value != 0)
            .or_else(|| kuser.nt_minor_version());
        let build = symbol_build_number(self)
            .or_else(|| kuser.nt_build_number())
            .map(|value| value & 0xffff);
        let product = dump_info
            .map(|info| info.product_type as u64)
            .filter(|value| *value != 0)
            .or_else(|| kuser.nt_product_type());
        let time = target_time(self, &kuser);

        let modules = self
            .kernel_modules_with_versions()
            .or_else(|_| self.kernel_modules())
            .unwrap_or_default();
        let kernel_module = self
            .kernel_base()
            .and_then(|base| modules.iter().find(|module| module.base_address == base))
            .cloned()
            .or_else(|| {
                modules
                    .iter()
                    .find(|module| module.short_name == "nt")
                    .cloned()
            });
        let base = kernel_module
            .as_ref()
            .map(|module| module.base_address)
            .or_else(|| self.kernel_base());
        let identity =
            base.and_then(|base| self.symbols.module_pdb_identity(self.kernel_dtb(), base));
        let symbol_status = base.map(|base| {
            self.symbols
                .module_symbol_status(self.kernel_dtb(), base)
                .map(|status| status.label().to_string())
                .unwrap_or_else(|| {
                    if identity.is_some() {
                        ModuleSymbolStatus::Loaded.label().to_string()
                    } else {
                        "unknown".to_string()
                    }
                })
        });
        let kernel = base.map(|base| TargetKernelDetail {
            name: kernel_module
                .as_ref()
                .map(|module| module.name.clone())
                .unwrap_or_else(|| "ntoskrnl.exe".to_string()),
            short_name: kernel_module
                .as_ref()
                .map(|module| module.short_name.clone())
                .unwrap_or_else(|| "nt".to_string()),
            base,
            size: kernel_module.as_ref().map(|module| u64::from(module.size)),
            file_version: kernel_module
                .as_ref()
                .and_then(|module| module.file_version.clone()),
            product_version: kernel_module
                .as_ref()
                .and_then(|module| module.product_version.clone()),
            pdb_guid: identity.map(|identity| format!("{:032X}", identity.guid)),
            pdb_age: identity.map(|identity| identity.age),
        });
        let processors = processor_count(self).ok().or_else(|| {
            self.phys
                .dmp_info()
                .map(|info| info.number_processors as u16)
        });
        let dump = dump_metadata(self, base);
        Ok(TargetVersionDetail {
            major_version: major,
            minor_version: minor,
            build_number: build,
            build_lab: shared_build_lab(self),
            architecture: self.arch().label().to_string(),
            processors,
            product: product_label(product),
            kernel,
            symbol_status,
            debugger_version: env!("CARGO_PKG_VERSION").to_string(),
            symbol_path: self
                .symbols
                .symbol_sources()
                .into_iter()
                .map(|source| source.to_string())
                .collect::<Vec<_>>()
                .join("; "),
            system_time: time.system_time,
            system_time_iso: time.system_time_iso,
            uptime_seconds: time.uptime_seconds,
            uptime: time.uptime,
            backend: None,
            dump,
        })
    }

    /// Decode target system time as raw FILETIME and ISO-8601 UTC, plus uptime
    /// in seconds and WinDbg-style day/hour/minute/second form. Missing KUSER
    /// data and missing dump metadata are represented by `None` fields.
    pub fn target_time(&self) -> Result<TargetTimeDetail> {
        Ok(target_time(self, &KuserSharedData::new(self)))
    }
}

impl Session {
    /// Add backend identity and a backend vCPU count fallback to the target
    /// metadata. The target-only method remains useful for passive memory and
    /// dump consumers that have no execution backend.
    pub fn target_version(&mut self) -> Result<TargetVersionDetail> {
        let mut detail = self.target.target_version()?;
        if detail.processors.is_none() {
            detail.processors = self
                .backend
                .thread_list()
                .ok()
                .map(|threads| threads.len() as u16);
        }
        detail.backend = Some(self.backend.name().to_string());
        Ok(detail)
    }
}

#[derive(Debug, Clone)]
pub struct ErrorCodeDetail {
    pub code: u64,
    pub kind: String,
    pub name: String,
    pub description: String,
    pub severity: Option<String>,
    pub facility: Option<u32>,
    pub customer: Option<bool>,
    pub win32_code: Option<u32>,
    pub win32_name: Option<String>,
}

fn decode_error_code_inner(code: u64, force_ntstatus: bool) -> ErrorCodeDetail {
    let Some(raw) = u32::try_from(code).ok() else {
        return ErrorCodeDetail {
            code,
            kind: "unknown".to_string(),
            name: "UNKNOWN".to_string(),
            description: "error code exceeds 32 bits".to_string(),
            severity: None,
            facility: None,
            customer: None,
            win32_code: None,
            win32_name: None,
        };
    };

    let is_ntstatus = force_ntstatus || raw >= 0xc000_0000;
    if is_ntstatus {
        let severity = match raw >> 30 {
            0 => "success",
            1 => "informational",
            2 => "warning",
            _ => "error",
        };
        let facility = (raw >> 16) & 0x0fff;
        let customer = raw & 0x2000_0000 != 0;
        return ErrorCodeDetail {
            code,
            kind: "NTSTATUS".to_string(),
            name: ntstatus_name(raw).unwrap_or("STATUS_UNKNOWN").to_string(),
            description: format!(
                "severity: {severity}; facility: {facility:#x}; customer: {}",
                if customer { "yes" } else { "no" }
            ),
            severity: Some(severity.to_string()),
            facility: Some(facility),
            customer: Some(customer),
            win32_code: None,
            win32_name: None,
        };
    }

    if raw & 0x8000_0000 != 0 {
        let facility = (raw >> 16) & 0x1fff;
        let win32_code = (facility == 7).then_some(raw & 0xffff);
        let win32_name = win32_code.and_then(win32_error_name).map(str::to_string);
        let customer = raw & 0x2000_0000 != 0;
        return ErrorCodeDetail {
            code,
            kind: "HRESULT".to_string(),
            name: win32_name
                .as_deref()
                .unwrap_or("HRESULT_UNKNOWN")
                .to_string(),
            description: format!(
                "severity: error; facility: {facility:#x}; customer: {}",
                if customer { "yes" } else { "no" }
            ),
            severity: Some("error".to_string()),
            facility: Some(facility),
            customer: Some(customer),
            win32_code,
            win32_name,
        };
    }

    ErrorCodeDetail {
        code,
        kind: "Win32".to_string(),
        name: win32_error_name(raw).unwrap_or("ERROR_UNKNOWN").to_string(),
        description: format!("Win32 error {raw} ({raw:#x})"),
        severity: None,
        facility: None,
        customer: None,
        win32_code: Some(raw),
        win32_name: win32_error_name(raw).map(str::to_string),
    }
}

/// Decode a 32-bit NTSTATUS, Win32, or HRESULT value from a plain integer.
/// Unknown values retain their classification and the structured bit-field
/// description used by the REPL's `!error` output.
pub fn decode_error_code(code: u64) -> ErrorCodeDetail {
    decode_error_code_inner(code, false)
}

/// Decode the `!ntstatus` alias without exposing a REPL-specific flag in the
/// SDK/MCP operation's public signature.
pub fn decode_error_code_as_ntstatus(code: u64) -> ErrorCodeDetail {
    decode_error_code_inner(code, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_level_flags_decode_in_bit_order() {
        assert_eq!(
            decode_verifier_level_flags(0x209bb),
            vec![
                "Special pool".to_string(),
                "Force IRQL checking".to_string(),
                "Pool tracking".to_string(),
                "I/O verification".to_string(),
                "Deadlock detection".to_string(),
                "DMA verification".to_string(),
                "Security checks".to_string(),
                "Miscellaneous checks".to_string(),
                "DDI compliance checking".to_string(),
            ]
        );
        assert_eq!(
            decode_verifier_level_flags((1 << 0) | (1 << 20)),
            vec!["Special pool".to_string(), "bit 20".to_string()]
        );
        assert!(decode_verifier_level_flags(0).is_empty());
    }

    #[test]
    fn error_code_decoding_keeps_win32_hresult_and_ntstatus_metadata() {
        let win32 = decode_error_code(5);
        assert_eq!(win32.kind, "Win32");
        assert_eq!(win32.name, "ERROR_ACCESS_DENIED");
        assert_eq!(win32.win32_code, Some(5));

        let hresult = decode_error_code(0x8007_0005);
        assert_eq!(hresult.kind, "HRESULT");
        assert_eq!(hresult.name, "ERROR_ACCESS_DENIED");
        assert_eq!(hresult.facility, Some(7));
        assert_eq!(hresult.win32_code, Some(5));

        let ntstatus = decode_error_code(0xc000_0005);
        assert_eq!(ntstatus.kind, "NTSTATUS");
        assert_eq!(ntstatus.name, "STATUS_ACCESS_VIOLATION");
        assert_eq!(ntstatus.severity.as_deref(), Some("error"));
    }
}
