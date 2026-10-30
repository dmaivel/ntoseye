//! Metadata inspectors shared by the REPL, Python SDK, and MCP.

use std::collections::HashSet;

use ntoseye_macros::record;

use crate::base::bytes::before_nul;
use crate::base::error::{Error, Result};
use crate::base::memory::MemoryOps;
use crate::base::ntstatus::{ntstatus_name, win32_error_name};
use crate::base::time::{filetime_to_iso, unix_time_to_iso};
use crate::base::types::VirtAddr;
use crate::nt::cpu_state::processor_count;
use crate::nt::dmp::tagged::known_tag;
use crate::nt::guest::{Guest, ModuleInfo};
use crate::nt::kuser_shared::KuserSharedData;
use crate::nt::layout::{StructRef, Types};
use crate::nt::symbols::ModuleSymbolStatus;
use crate::nt::target::{DiagnosticValue, ListCursor, ListTermination, Target};
use crate::nt::userdump::UserDumpInfo;

/// Bounds on the verifier AVL walk, whose counts come from guest memory.
const MAX_VERIFIER_TABLES: usize = 256;
const MAX_VERIFIER_TABLE_ELEMENTS: usize = 1 << 16;

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

/// A driver that Driver Verifier verifies, from the `!verifier` list.
#[record]
pub struct VerifierDriverSummary {
    /// The verifier entry of the driver.
    pub entry: VirtAddr,
    /// The state of the entry (`Loaded`).
    pub state: String,
    /// The nonpaged pool that the driver holds, in bytes.
    pub nonpaged_bytes: u64,
    /// The paged pool that the driver holds, in bytes.
    pub paged_bytes: u64,
    /// The module name of the driver.
    #[record(rename = "module")]
    pub module_name: String,
}

/// A driver that is configured for verification, from the verifier
/// suspect list.
#[record]
pub struct VerifierSuspectDriver {
    /// The suspect-list entry.
    pub address: VirtAddr,
    pub full_name: String,
    pub base_name: String,
    /// The number of times that the driver loaded.
    pub loads: u64,
    /// The number of times that the driver unloaded.
    pub unloads: u64,
}

/// The aggregate counters of Driver Verifier. ntoseye reads each counter
/// separately, and each read can fail.
#[record]
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

/// The Driver Verifier configuration, statistics, and drivers
/// (`!verifier`). The drivers are the verified drivers and the configured
/// suspect drivers that are not loaded.
#[record]
pub struct Verifier {
    /// The verification level (`MmVerifierData.Level`).
    #[record(hex)]
    pub level: DiagnosticValue<u64>,
    /// The option flags (`VerifierOptionFlags`).
    #[record(hex)]
    pub option_flags: DiagnosticValue<u64>,
    pub verify_mode: DiagnosticValue<u64>,
    /// The names of the checks that `level` enables.
    pub level_options: DiagnosticValue<Vec<String>>,
    pub statistics: VerifierStatistics,
    /// The verified drivers.
    pub drivers: DiagnosticValue<Vec<VerifierDriverSummary>>,
    /// Whether the driver table gives a smaller entry count than the
    /// number of linked entries, which means that the walk stopped before
    /// it reached all drivers.
    pub drivers_truncated: bool,
    /// The suspect drivers that are configured for verification but are
    /// not loaded.
    pub configured_but_unloaded: DiagnosticValue<Vec<VerifierSuspectDriver>>,
    /// How the suspect-list walk ended.
    pub suspect_list_termination: ListTermination,
}

/// The image, signing level, and counters of one verified driver
/// (`!verifier <module>`).
#[record]
pub struct VerifierDriver {
    #[record(rename = "module")]
    pub module_name: String,
    pub image_base: VirtAddr,
    /// The image size in bytes.
    pub image_size: u64,
    /// The `_DRIVER_OBJECT` of the driver.
    pub driver_object: VirtAddr,
    /// The signing level of the image (`SE_SIGNING_LEVEL`).
    #[record(hex)]
    pub se_signing_level: u64,
    pub raise_irqls: u64,
    pub acquire_spin_locks: u64,
    pub synchronize_executions: u64,
    pub allocations_with_no_tag: u64,
    pub allocations_failed: u64,
    /// The number of allocations that the verifier failed on purpose
    /// (fault injection).
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
    /// The suspect-list entry of the driver, with its load history.
    /// `None` if the driver has no entry; unavailable if its entry does not
    /// read.
    pub suspect: Option<DiagnosticValue<VerifierSuspectDriver>>,
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
    /// `None` if the driver has no suspect-list entry.
    suspect: Option<DiagnosticValue<SuspectDriver>>,
    module_name: String,
}

impl VerifiedDriver {
    /// The suspect-list entry, when the driver has one and it reads.
    fn readable_suspect(&self) -> Option<&SuspectDriver> {
        self.suspect.as_ref()?.as_result().ok()
    }
}

fn read_verifier_state(guest: &Guest) -> VerifierStateRead {
    let types = guest.ntoskrnl.types();
    let verifier = guest
        .ntoskrnl
        .symbol("MmVerifierData")
        .and_then(|symbol| types.struct_at("_MM_DRIVER_VERIFIER_DATA", symbol.address()));
    let read = |name: &str| match verifier.as_ref() {
        Ok(verifier) => DiagnosticValue::from_result(verifier.read_uint(name)),
        Err(error) => DiagnosticValue::unavailable(error.to_string()),
    };
    let option_flags = DiagnosticValue::from_result(
        guest
            .ntoskrnl
            .symbol("VfOptionFlags")
            .and_then(|symbol| symbol.read::<u32>().map(u64::from)),
    );
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
        Some(DiagnosticValue::from_result(
            types
                .struct_at("_VF_SUSPECT_DRIVER_ENTRY", data.suspect_entry)
                .and_then(|record| read_suspect_driver(&record)),
        ))
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
        .map_err(|_| Error::DebugInfo("invalid verifier AVL element count".into()))?
        .min(MAX_VERIFIER_TABLE_ELEMENTS);
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
    let mut truncated = tables_count > MAX_VERIFIER_TABLES;
    for index in 0..tables_count.min(MAX_VERIFIER_TABLES) {
        let address = (index as u64)
            .checked_mul(table_layout.size as u64)
            .and_then(|offset| tables.0.checked_add(offset))
            .map(VirtAddr)
            .ok_or_else(|| Error::DebugInfo("verifier AVL table address overflows".into()))?;
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
                    .readable_suspect()
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
        // A loaded driver whose own suspect entry is unreadable still has the
        // module name, which is enough to tell it is loaded.
        module_key(&driver.module_name) == key
            || driver
                .readable_suspect()
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

fn driver_detail(driver: &VerifiedDriver) -> VerifierDriver {
    VerifierDriver {
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
        suspect: driver
            .suspect
            .as_ref()
            .map(|suspect| suspect.map(suspect_detail)),
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
    pub fn verifier_status(&self) -> Result<Verifier> {
        let guest = self.guest()?;
        let state = read_verifier_state(guest);
        let level_options = match &state.level {
            DiagnosticValue::Available(level) => {
                DiagnosticValue::Available(decode_verifier_level_flags(*level))
            }
            DiagnosticValue::Unavailable(error) => DiagnosticValue::unavailable(error.clone()),
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
            Err(error) => (DiagnosticValue::unavailable(error.to_string()), None, false),
        };
        let (configured_but_unloaded, suspect_list_termination) = match read_suspect_list(guest) {
            Ok((suspects, termination)) => match loaded_drivers.as_deref() {
                // Without the full loaded set, every unmatched suspect would
                // be misreported as not loaded.
                Some(_) if drivers_truncated => (
                    DiagnosticValue::unavailable(
                        "the verified driver walk was truncated".to_string(),
                    ),
                    termination,
                ),
                None => (
                    DiagnosticValue::unavailable("the verified driver walk failed".to_string()),
                    termination,
                ),
                Some(loaded) => (
                    DiagnosticValue::Available(
                        suspects
                            .iter()
                            .filter(|suspect| !loaded_suspect(suspect, loaded))
                            .map(suspect_detail)
                            .collect(),
                    ),
                    termination,
                ),
            },
            Err(error) => {
                let error = error.to_string();
                (
                    DiagnosticValue::unavailable(error.clone()),
                    ListTermination::Corrupt(error),
                )
            }
        };

        Ok(Verifier {
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
    pub fn verifier_driver(&self, module: &str) -> Result<VerifierDriver> {
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
                        .readable_suspect()
                        .is_some_and(|suspect| module_key(&suspect.base_name) == module_key(module))
                })
            })
            .ok_or_else(|| Error::DebugInfo(format!("unknown verifier module: {module}")))?;
        Ok(driver_detail(driver))
    }
}

/// The identity of the kernel image.
#[record]
pub struct TargetKernel {
    /// The file name of the image.
    pub name: String,
    /// The module name (`nt`).
    pub short_name: String,
    pub base: VirtAddr,
    /// The image size in bytes.
    pub size: Option<u64>,
    pub file_version: Option<String>,
    pub product_version: Option<String>,
    /// The file name of the loaded PDB (`ntkrnlmp.pdb`).
    pub pdb_name: Option<String>,
    /// The GUID of the PDB, which identifies the symbols.
    pub pdb_guid: Option<String>,
    /// The age of the PDB.
    pub pdb_age: Option<u32>,
}

/// The data that a crash dump header records.
#[record]
pub struct TargetDump {
    /// Whether the dump is a triage (minidump-style) dump.
    pub is_triage: bool,
    /// The kernel page-table root that the dump records.
    pub directory_table_base: VirtAddr,
    #[record(hex)]
    pub bugcheck_code: u32,
    pub bugcheck_parameters: Vec<u64>,
    pub number_processors: u32,
    pub major_version: u32,
    pub minor_version: u32,
    pub product_type: u32,
    /// The machine type (`IMAGE_FILE_MACHINE_*`).
    pub machine_image_type: u32,
    pub service_pack_build: u32,
    /// The time when the dump was taken (FILETIME).
    #[record(hex)]
    pub system_time: Option<u64>,
    /// The system uptime in seconds.
    pub uptime_seconds: Option<u64>,
    /// The exception code that the dump records.
    #[record(hex)]
    pub exception_code: Option<u32>,
    /// Whether the triage data of the dump overflowed.
    pub triage_overflowed: bool,
    pub kernel_base: Option<VirtAddr>,
    /// The blocks that bugcheck callbacks added to the dump (`.enumtag`);
    /// `Inspect.read_tagged` reads one.
    pub tagged_blocks: Vec<TaggedBlock>,
}

/// A tagged data block of a crash dump.
#[record]
pub struct TaggedBlock {
    /// The GUID tag, `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`.
    pub tag: String,
    /// The data's size in bytes.
    pub size: u64,
    /// For a tag Windows writes, the global that holds it, such as
    /// `nt!PopBlackBoxPnpGuid`.
    pub owner: Option<&'static str>,
    /// For a tag Windows writes, what the block holds.
    pub holds: Option<&'static str>,
}

/// The version data of the target (`vertarget`), with the build,
/// architecture, kernel, symbols, debugger version, time, and dump
/// metadata.
#[record]
pub struct TargetVersion {
    pub major_version: Option<u64>,
    pub minor_version: Option<u64>,
    pub build_number: Option<u64>,
    /// The build lab string.
    pub build_lab: Option<String>,
    pub architecture: String,
    /// The number of processors in the target.
    pub processors: Option<u16>,
    /// The product name.
    pub product: String,
    /// The kernel image. `None` if ntoseye did not find it.
    pub kernel: Option<TargetKernel>,
    /// The symbol status label of the kernel. `None` if ntoseye did not
    /// find the kernel.
    pub symbol_status: Option<String>,
    pub debugger_version: String,
    pub symbol_path: String,
    pub time: TargetTime,
    /// The backend attached to the target.
    pub backend: Option<String>,
    /// The crash dump header. `None` for a live target.
    pub dump: Option<TargetDump>,
    /// What a user-mode minidump records of its process and how it was
    /// written. `None` for a kernel target.
    pub user_dump: Option<TargetUserDump>,
}

/// A user-mode minidump's process and header.
#[record]
pub struct TargetUserDump {
    pub process_name: Option<String>,
    pub process_id: Option<u32>,
    /// `ProcessorLevel`: on AMD64, the processor family.
    pub processor_level: u16,
    /// `ProcessorRevision`: on AMD64, the model (high byte) and stepping
    /// (low byte).
    #[record(hex)]
    pub processor_revision: u16,
    pub service_pack: Option<String>,
    /// The `MINIDUMP_TYPE` flags the dump was written with.
    #[record(hex)]
    pub flags: u64,
    /// `flags` as `MINIDUMP_TYPE` names (`MiniDumpWithFullMemory`, ...).
    pub flag_names: Vec<String>,
    pub threads: usize,
    pub modules: usize,
    /// The code of the exception the dump was written for.
    #[record(hex)]
    pub exception_code: Option<u32>,
}

/// The UTC time and uptime of the target (`.time`). A user-mode minidump
/// records neither: its `user_dump` says when it was written instead.
#[record]
pub struct TargetTime {
    /// The UTC time of the target (FILETIME).
    #[record(hex)]
    pub system_time: Option<u64>,
    /// `system_time` as ISO 8601.
    pub system_time_iso: Option<String>,
    /// `KUSER_SHARED_DATA.InterruptTime`: the time since boot, in 100 ns
    /// units. The `due_time` of clock timers uses this clock.
    #[record(hex)]
    pub interrupt_time: Option<u64>,
    /// Seconds since boot.
    pub uptime_seconds: Option<u64>,
    /// The uptime as formatted text.
    pub uptime: Option<String>,
    /// When a user-mode minidump was written, and its process's times.
    /// `None` for a kernel target.
    pub user_dump: Option<UserDumpTime>,
}

/// When a user-mode minidump was written (its header), and how long its
/// process had run (`MiscInfoStream`), where it records them.
#[record]
pub struct UserDumpTime {
    /// When the dump was written, in seconds since 1970 (UTC).
    pub written: u32,
    /// `written` as ISO 8601 UTC.
    pub written_iso: Option<String>,
    /// `written` in the system's time zone.
    pub written_local: Option<String>,
    /// The name of that zone's period in effect.
    pub time_zone: Option<String>,
    /// When the process started, in seconds since 1970 (UTC).
    pub process_created: Option<u32>,
    /// `process_created` as ISO 8601 UTC.
    pub process_created_iso: Option<String>,
    /// From the process's start to the dump, in seconds.
    pub process_uptime_seconds: Option<u64>,
    /// `process_uptime_seconds` as formatted text.
    pub process_uptime: Option<String>,
    /// User-mode time the process had run, in seconds.
    pub user_time_seconds: Option<u32>,
    /// Kernel-mode time the process had run, in seconds.
    pub kernel_time_seconds: Option<u32>,
}

/// `MINIDUMP_TYPE` flags, by bit.
const MINIDUMP_TYPES: [(u64, &str); 25] = [
    (0x1, "MiniDumpWithDataSegs"),
    (0x2, "MiniDumpWithFullMemory"),
    (0x4, "MiniDumpWithHandleData"),
    (0x8, "MiniDumpFilterMemory"),
    (0x10, "MiniDumpScanMemory"),
    (0x20, "MiniDumpWithUnloadedModules"),
    (0x40, "MiniDumpWithIndirectlyReferencedMemory"),
    (0x80, "MiniDumpFilterModulePaths"),
    (0x100, "MiniDumpWithProcessThreadData"),
    (0x200, "MiniDumpWithPrivateReadWriteMemory"),
    (0x400, "MiniDumpWithoutOptionalData"),
    (0x800, "MiniDumpWithFullMemoryInfo"),
    (0x1000, "MiniDumpWithThreadInfo"),
    (0x2000, "MiniDumpWithCodeSegs"),
    (0x4000, "MiniDumpWithoutAuxiliaryState"),
    (0x8000, "MiniDumpWithFullAuxiliaryState"),
    (0x1_0000, "MiniDumpWithPrivateWriteCopyMemory"),
    (0x2_0000, "MiniDumpIgnoreInaccessibleMemory"),
    (0x4_0000, "MiniDumpWithTokenInformation"),
    (0x8_0000, "MiniDumpWithModuleHeaders"),
    (0x10_0000, "MiniDumpFilterTriage"),
    (0x20_0000, "MiniDumpWithAvxXStateContext"),
    (0x40_0000, "MiniDumpWithIptTrace"),
    (0x80_0000, "MiniDumpScanInaccessiblePartialPages"),
    (0x100_0000, "MiniDumpFilterWriteCombinedMemory"),
];

/// The `MINIDUMP_TYPE` names of `flags` in bit order (`MiniDumpNormal` for
/// none), with any bit Windows does not define kept as its value.
pub fn minidump_type_names(flags: u64) -> Vec<String> {
    if flags == 0 {
        return vec!["MiniDumpNormal".to_string()];
    }
    let mut names: Vec<String> = MINIDUMP_TYPES
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, name)| (*name).to_string())
        .collect();
    let known = MINIDUMP_TYPES.iter().fold(0, |mask, (bit, _)| mask | bit);
    if flags & !known != 0 {
        names.push(format!("{:#x}", flags & !known));
    }
    names
}

/// Seconds since 1970 (UTC) as ISO-8601 local time in a zone `bias` minutes
/// behind UTC (`TIME_ZONE_INFORMATION`'s sign: UTC = local + bias).
pub fn unix_to_local_iso(seconds: u64, bias: i32) -> Option<String> {
    let local = seconds.checked_add_signed(-i64::from(bias) * 60)?;
    let utc = unix_time_to_iso(local)?;
    let offset = -i64::from(bias);
    let sign = if offset < 0 { '-' } else { '+' };
    let offset = offset.unsigned_abs();
    Some(format!(
        "{}{sign}{:02}:{:02}",
        utc.strip_suffix('Z')?,
        offset / 60,
        offset % 60
    ))
}

fn user_dump_time(info: &UserDumpInfo) -> UserDumpTime {
    let written = info.time_date_stamp;
    let process_uptime_seconds = info
        .process_create_time
        .and_then(|created| written.checked_sub(created))
        .map(u64::from);
    UserDumpTime {
        written,
        written_iso: unix_time_to_iso(u64::from(written)),
        written_local: info
            .time_zone
            .as_ref()
            .and_then(|zone| unix_to_local_iso(u64::from(written), zone.bias)),
        time_zone: info.time_zone.as_ref().map(|zone| zone.name.clone()),
        process_created: info.process_create_time,
        process_created_iso: info
            .process_create_time
            .and_then(|created| unix_time_to_iso(u64::from(created))),
        process_uptime_seconds,
        process_uptime: process_uptime_seconds.map(format_uptime),
        user_time_seconds: info.process_cpu_times.map(|(user, _)| user),
        kernel_time_seconds: info.process_cpu_times.map(|(_, kernel)| kernel),
    }
}

fn user_dump_detail(info: &UserDumpInfo) -> TargetUserDump {
    TargetUserDump {
        process_name: info.process_name().map(str::to_string),
        process_id: info.process_id,
        processor_level: info.system.processor_level,
        processor_revision: info.system.processor_revision,
        service_pack: info
            .system
            .service_pack
            .clone()
            .filter(|text| !text.is_empty()),
        flags: info.flags,
        flag_names: minidump_type_names(info.flags),
        threads: info.threads.len(),
        modules: info.modules.len(),
        exception_code: info.exception.as_ref().map(|exception| exception.code),
    }
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

/// Seconds since boot: the dump header's, else the interrupt time's.
fn uptime_seconds(target: &Target, interrupt_time: Option<u64>) -> Option<u64> {
    dump_uptime_seconds(target).or_else(|| {
        interrupt_time
            .filter(|ticks| *ticks > 0)
            .map(|ticks| ticks / 10_000_000)
    })
}

fn target_time(target: &Target, kuser: &KuserSharedData<'_>) -> TargetTime {
    if let Some(info) = target.user_dump_info() {
        return TargetTime {
            system_time: None,
            system_time_iso: None,
            interrupt_time: None,
            uptime_seconds: None,
            uptime: None,
            user_dump: Some(user_dump_time(info)),
        };
    }
    let system_time = system_time(target, kuser);
    let interrupt_time = kuser.interrupt_time();
    let uptime_seconds = uptime_seconds(target, interrupt_time);
    TargetTime {
        system_time,
        system_time_iso: system_time.and_then(filetime_to_iso),
        interrupt_time,
        uptime_seconds,
        uptime: uptime_seconds.map(format_uptime),
        user_dump: None,
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
    let text = String::from_utf8_lossy(before_nul(&bytes))
        .trim()
        .to_string();
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

fn dump_metadata(target: &Target, kernel_base: Option<VirtAddr>) -> Option<TargetDump> {
    target.phys.dmp_info().map(|info| {
        let system_info = info.system_info.as_ref();
        TargetDump {
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
            tagged_blocks: info
                .tagged_blocks
                .iter()
                .map(|block| {
                    let known = known_tag(&block.tag);
                    TaggedBlock {
                        tag: block.tag_text(),
                        size: block.data.len() as u64,
                        owner: known.map(|known| known.owner),
                        holds: known.map(|known| known.holds),
                    }
                })
                .collect(),
        }
    })
}

impl Target {
    /// Decode target/kernel build strings, architecture, target-known
    /// processor count, kernel image and symbol status, debugger version, time
    /// metadata, and dump-header metadata when this target came from a dump.
    pub fn target_version(&self) -> Result<TargetVersion> {
        let dump_info = self
            .phys
            .dmp_info()
            .and_then(|info| info.system_info.as_ref());
        let kuser = KuserSharedData::new(self);
        // A user dump records its system in SystemInfoStream; it has no
        // kernel or KUSER_SHARED_DATA to ask.
        let user_system = self.user_dump_info().map(|info| &info.system);
        // A kernel dump header's MajorVersion is 0xF (free) or 0xC (checked)
        // and its MinorVersion the build number, not the Windows version:
        // the kernel's KUSER_SHARED_DATA has that. Early in boot (a KD attach
        // at the first break) the kernel has not filled it in yet, and a
        // major version of 0 is no version: both numbers are unknown then.
        let major = user_system
            .map(|system| u64::from(system.major_version))
            .filter(|value| *value != 0)
            .or_else(|| kuser.nt_major_version().filter(|value| *value != 0));
        let minor = match user_system {
            Some(system) => Some(u64::from(system.minor_version)),
            None => major.and_then(|_| kuser.nt_minor_version()),
        };
        let build = user_system
            .map(|system| u64::from(system.build_number))
            .or_else(|| symbol_build_number(self))
            .or_else(|| kuser.nt_build_number())
            .map(|value| value & 0xffff);
        let product = user_system
            .map(|system| u64::from(system.product_type))
            .or_else(|| dump_info.map(|info| info.product_type as u64))
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
        let kernel = base.map(|base| TargetKernel {
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
            pdb_name: self
                .symbols
                .module_pdb_path(self.kernel_dtb(), base)
                .and_then(|path| Some(path.file_name()?.to_string_lossy().into_owned())),
            pdb_guid: identity.map(|identity| format!("{:032X}", identity.guid)),
            pdb_age: identity.map(|identity| identity.age),
        });
        let processors = match user_system {
            Some(system) => Some(u16::from(system.number_of_processors)),
            None => processor_count(self).ok().or_else(|| {
                self.phys
                    .dmp_info()
                    .map(|info| info.number_processors as u16)
            }),
        };
        let dump = dump_metadata(self, base);
        let user_info = self.user_dump_info();
        // A user dump's MiscInfo build string is the system's build lab.
        let build_lab = match user_info {
            Some(info) => info.build_string.clone().filter(|text| !text.is_empty()),
            None => shared_build_lab(self),
        };
        Ok(TargetVersion {
            major_version: major,
            minor_version: minor,
            build_number: build,
            build_lab,
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
            time,
            backend: None,
            dump,
            user_dump: user_info.map(user_dump_detail),
        })
    }

    /// Decode target system time as raw FILETIME and ISO-8601 UTC, plus uptime
    /// in seconds and WinDbg-style day/hour/minute/second form. Missing KUSER
    /// data and missing dump metadata are represented by `None` fields.
    pub fn target_time(&self) -> Result<TargetTime> {
        Ok(target_time(self, &KuserSharedData::new(self)))
    }
}

/// The family of a decoded error code: `ntstatus`, `hresult`, `win32`, or
/// `unknown` (a code wider than 32 bits).
#[record]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCodeKind {
    #[record(label = "NTSTATUS")]
    Ntstatus,
    #[record(label = "HRESULT")]
    Hresult,
    #[record(label = "Win32")]
    Win32,
    Unknown,
}

/// The severity of an NTSTATUS or HRESULT code: `success`,
/// `informational`, `warning`, or `error`.
#[record]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorSeverity {
    Success,
    Informational,
    Warning,
    Error,
}

/// A decoded NTSTATUS, Win32, or HRESULT code (`!error`).
#[record]
pub struct ErrorCode {
    #[record(hex)]
    pub code: u64,
    pub kind: ErrorCodeKind,
    /// The symbolic name of the code; empty when no name is known.
    pub name: String,
    pub description: String,
    /// `success`, `informational`, `warning`, or `error`. `None` for a
    /// Win32 code.
    pub severity: Option<ErrorSeverity>,
    /// The facility that the code encodes.
    pub facility: Option<u32>,
    /// Whether the code is customer-defined (its C bit).
    pub customer: Option<bool>,
    /// The Win32 error: the code itself, or the Win32 error that a
    /// `HRESULT_FROM_WIN32` code wraps.
    #[record(hex)]
    pub win32_code: Option<u32>,
    /// The name of that Win32 error.
    pub win32_name: Option<String>,
}

fn decode_error_code_inner(code: u64, force_ntstatus: bool) -> ErrorCode {
    let Some(raw) = u32::try_from(code).ok() else {
        return ErrorCode {
            code,
            kind: ErrorCodeKind::Unknown,
            name: String::new(),
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
            0 => ErrorSeverity::Success,
            1 => ErrorSeverity::Informational,
            2 => ErrorSeverity::Warning,
            _ => ErrorSeverity::Error,
        };
        let facility = (raw >> 16) & 0x0fff;
        let customer = raw & 0x2000_0000 != 0;
        return ErrorCode {
            code,
            kind: ErrorCodeKind::Ntstatus,
            name: ntstatus_name(raw).unwrap_or_default().to_string(),
            description: format!(
                "severity: {severity}; facility: {facility:#x}; customer: {}",
                if customer { "yes" } else { "no" }
            ),
            severity: Some(severity),
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
        return ErrorCode {
            code,
            kind: ErrorCodeKind::Hresult,
            name: win32_name.clone().unwrap_or_default(),
            description: format!(
                "severity: error; facility: {facility:#x}; customer: {}",
                if customer { "yes" } else { "no" }
            ),
            severity: Some(ErrorSeverity::Error),
            facility: Some(facility),
            customer: Some(customer),
            win32_code,
            win32_name,
        };
    }

    // Win32 error codes are 16 bits wide; a larger value with neither the
    // NTSTATUS nor the HRESULT severity bits set is none of the three.
    if raw > 0xffff {
        return ErrorCode {
            code,
            kind: ErrorCodeKind::Unknown,
            name: String::new(),
            description: "not an NTSTATUS, HRESULT, or Win32 error code".to_string(),
            severity: None,
            facility: None,
            customer: None,
            win32_code: None,
            win32_name: None,
        };
    }

    ErrorCode {
        code,
        kind: ErrorCodeKind::Win32,
        name: win32_error_name(raw).unwrap_or_default().to_string(),
        description: format!("Win32 error {raw:#x}"),
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
pub fn decode_error_code(code: u64) -> ErrorCode {
    decode_error_code_inner(code, false)
}

/// Decode the `!ntstatus` alias without exposing a REPL-specific flag in the
/// SDK/MCP operation's public signature.
pub fn decode_error_code_as_ntstatus(code: u64) -> ErrorCode {
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
        assert_eq!(win32.kind, ErrorCodeKind::Win32);
        assert_eq!(win32.name, "ERROR_ACCESS_DENIED");
        assert_eq!(win32.win32_code, Some(5));

        let hresult = decode_error_code(0x8007_0005);
        assert_eq!(hresult.kind, ErrorCodeKind::Hresult);
        assert_eq!(hresult.name, "ERROR_ACCESS_DENIED");
        assert_eq!(hresult.facility, Some(7));
        assert_eq!(hresult.win32_code, Some(5));

        let ntstatus = decode_error_code(0xc000_0005);
        assert_eq!(ntstatus.kind, ErrorCodeKind::Ntstatus);
        assert_eq!(ntstatus.name, "STATUS_ACCESS_VIOLATION");
        assert_eq!(ntstatus.severity, Some(ErrorSeverity::Error));
    }

    #[test]
    fn minidump_types_decode_in_bit_order_with_normal_for_none() {
        assert_eq!(minidump_type_names(0), ["MiniDumpNormal"]);
        assert_eq!(
            minidump_type_names(0x1826),
            [
                "MiniDumpWithFullMemory",
                "MiniDumpWithHandleData",
                "MiniDumpWithUnloadedModules",
                "MiniDumpWithFullMemoryInfo",
                "MiniDumpWithThreadInfo",
            ]
        );
        assert_eq!(
            minidump_type_names(0x2_0000_0004),
            ["MiniDumpWithHandleData", "0x200000000"]
        );
    }

    #[test]
    fn local_time_applies_the_bias_and_writes_its_offset() {
        // 2026-10-11T06:17:41Z.
        let written = 1_791_699_461;
        assert_eq!(
            unix_to_local_iso(written, -120).as_deref(),
            Some("2026-10-11T08:17:41+02:00")
        );
        assert_eq!(
            unix_to_local_iso(written, 330).as_deref(),
            Some("2026-10-11T00:47:41-05:30")
        );
        // West of UTC, across midnight.
        assert_eq!(
            unix_to_local_iso(written, 420).as_deref(),
            Some("2026-10-10T23:17:41-07:00")
        );
        assert_eq!(
            unix_to_local_iso(written, 0).as_deref(),
            Some("2026-10-11T06:17:41+00:00")
        );
    }
}
