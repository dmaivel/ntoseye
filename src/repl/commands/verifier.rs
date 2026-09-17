use std::collections::HashSet;

use crate::error::{Error, Result};
use crate::guest::{Guest, ModuleInfo, StructRef, Types};
use crate::repl::*;
use crate::types::VirtAddr;
use crate::ui;

repl_command! {
    cmd_verifier;
    names: ["!verifier", "verifier"],
    usage: "!verifier [module]",
    summary: "Display Driver Verifier status, statistics, and verified drivers.",
    details: "Without a module, display the verifier level, aggregate counters, and the configured driver list. With a module, display its verified-driver counters and image details.",
}

const VERIFIER_LEVEL_FLAGS: &[(u32, &str)] = &[
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

fn decode_level_flags(level: u32) -> Vec<String> {
    (0..u32::BITS)
        .filter_map(|bit| {
            let mask = 1u32 << bit;
            (level & mask != 0).then(|| {
                VERIFIER_LEVEL_FLAGS
                    .iter()
                    .find(|(flag, _)| *flag == mask)
                    .map_or_else(|| format!("bit {bit}"), |(_, name)| (*name).to_string())
            })
        })
        .collect()
}

#[derive(Clone)]
struct VerifierState {
    level: u64,
    option_flags: u64,
    verify_mode: u64,
    raise_irqls: u64,
    acquire_spin_locks: u64,
    synchronize_executions: u64,
    trims: u64,
    allocations_attempted: u64,
    allocations_succeeded: u64,
    allocations_succeeded_special_pool: u64,
    allocations_with_no_tag: u64,
    allocations_failed: u64,
    current_paged_pool_allocations: u64,
    paged_bytes: u64,
    peak_paged_pool_allocations: u64,
    peak_paged_bytes: u64,
    current_nonpaged_pool_allocations: u64,
    nonpaged_bytes: u64,
    peak_nonpaged_pool_allocations: u64,
    peak_nonpaged_bytes: u64,
    loads: u64,
    unloads: u64,
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

fn read_verifier_state(guest: &Guest) -> Result<VerifierState> {
    let types = guest.ntoskrnl.types();
    let verifier = types.struct_at(
        "_MM_DRIVER_VERIFIER_DATA",
        guest.ntoskrnl.symbol("MmVerifierData")?.address(),
    )?;
    let read = |name: &str| verifier.read_uint(name);
    Ok(VerifierState {
        level: read("Level")?,
        option_flags: u64::from(guest.ntoskrnl.symbol("VfOptionFlags")?.read::<u32>()?),
        verify_mode: read("VerifyMode")?,
        raise_irqls: read("RaiseIrqls")?,
        acquire_spin_locks: read("AcquireSpinLocks")?,
        synchronize_executions: read("SynchronizeExecutions")?,
        trims: read("Trims")?,
        allocations_attempted: read("AllocationsAttempted")?,
        allocations_succeeded: read("AllocationsSucceeded")?,
        allocations_succeeded_special_pool: read("AllocationsSucceededSpecialPool")?,
        allocations_with_no_tag: read("AllocationsWithNoTag")?,
        allocations_failed: read("AllocationsFailed")?,
        current_paged_pool_allocations: read("CurrentPagedPoolAllocations")?,
        paged_bytes: read("PagedBytes")?,
        peak_paged_pool_allocations: read("PeakPagedPoolAllocations")?,
        peak_paged_bytes: read("PeakPagedBytes")?,
        current_nonpaged_pool_allocations: read("CurrentNonPagedPoolAllocations")?,
        nonpaged_bytes: read("NonPagedBytes")?,
        peak_nonpaged_pool_allocations: read("PeakNonPagedPoolAllocations")?,
        peak_nonpaged_bytes: read("PeakNonPagedBytes")?,
        loads: read("Loads")?,
        unloads: read("Unloads")?,
    })
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

fn read_suspect_list(guest: &Guest) -> Result<Vec<SuspectDriver>> {
    let types = guest.ntoskrnl.types();
    let head = guest.ntoskrnl.symbol("VfSuspectDriversList")?.address();
    types
        .list_at(head, "_VF_SUSPECT_DRIVER_ENTRY", "Links")?
        .map(|record| record.and_then(|record| read_suspect_driver(&record)))
        .collect()
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
) -> Result<Vec<VerifiedDriver>> {
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
        if seen.len() >= element_count || !seen.insert(links.0) {
            continue;
        }
        let node = types.struct_at("_RTL_BALANCED_LINKS", links)?;
        let left = node.read_pointer("LeftChild")?;
        let right = node.read_pointer("RightChild")?;
        stack.push((right, false));
        stack.push((links, true));
        stack.push((left, false));
    }
    Ok(drivers)
}

fn walk_verified_drivers(guest: &Guest) -> Result<Vec<VerifiedDriver>> {
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
    for index in 0..tables_count {
        let address = tables + (index as u64).wrapping_mul(table_layout.size as u64);
        drivers.extend(walk_avl_table(types, address, links_size)?);
    }
    Ok(drivers)
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
            .unwrap_or_else(|| ui::addr(driver.image_base.0));
    }
}

fn print_hex_stat(label: &str, value: u64) {
    outln!("  {label:<40}{value:#x}");
}

fn print_value(label: &str, value: &str) {
    outln!("  {label:<40}{value}");
}

fn print_pool_stat(label: &str, allocations: u64, bytes: u64) {
    outln!("  {label:<40}{allocations:#x} for {bytes:#x} bytes");
}

fn print_level(state: &VerifierState) {
    outln!("Verify Level {:x}  enabled options are:", state.level);
    if state.level == 0 {
        outln!("Driver Verifier is not enabled");
        return;
    }
    for option in decode_level_flags(state.level as u32) {
        outln!("        {option}");
    }
    outln!(
        "  option flags {:#x}  verify mode {}",
        state.option_flags,
        state.verify_mode
    );
}

fn print_summary(state: &VerifierState) {
    outln!();
    outln!("Summary of All Verifier Statistics");
    print_hex_stat("RaiseIrqls", state.raise_irqls);
    print_hex_stat("AcquireSpinLocks", state.acquire_spin_locks);
    print_hex_stat("Synch Executions", state.synchronize_executions);
    print_hex_stat("Trims", state.trims);
    print_hex_stat("Pool Allocations Attempted", state.allocations_attempted);
    print_hex_stat("Pool Allocations Succeeded", state.allocations_succeeded);
    print_hex_stat(
        "Pool Allocations Succeeded SpecialPool",
        state.allocations_succeeded_special_pool,
    );
    print_hex_stat(
        "Pool Allocations With NO TAG",
        state.allocations_with_no_tag,
    );
    print_hex_stat("Pool Allocations Failed", state.allocations_failed);
    print_pool_stat(
        "Current paged pool allocations",
        state.current_paged_pool_allocations,
        state.paged_bytes,
    );
    print_pool_stat(
        "Peak paged pool allocations",
        state.peak_paged_pool_allocations,
        state.peak_paged_bytes,
    );
    print_pool_stat(
        "Current nonpaged pool allocations",
        state.current_nonpaged_pool_allocations,
        state.nonpaged_bytes,
    );
    print_pool_stat(
        "Peak nonpaged pool allocations",
        state.peak_nonpaged_pool_allocations,
        state.peak_nonpaged_bytes,
    );
    outln!("  Loads {:#x}  Unloads {:#x}", state.loads, state.unloads);
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

fn print_driver_list(drivers: &[VerifiedDriver], suspects: &[SuspectDriver]) {
    outln!();
    outln!("Driver Verification List");
    outln!("  Entry             State       NonPagedPool  PagedPool  Module");
    for driver in drivers {
        outln!(
            "  {:<18}{:<12}{:<14}{:<11}{}",
            ui::addr(driver.entry.0),
            "Loaded",
            format!("{:#x}", driver.data.nonpaged_bytes),
            format!("{:#x}", driver.data.paged_bytes),
            driver.module_name
        );
    }
    for suspect in suspects
        .iter()
        .filter(|suspect| !loaded_suspect(suspect, drivers))
    {
        let module = if suspect.base_name.is_empty() {
            suspect.full_name.as_str()
        } else {
            suspect.base_name.as_str()
        };
        outln!(
            "  {:<18}{:<12}{:<14}{:<11}{}",
            ui::addr(suspect.address.0),
            "Not loaded",
            "0x0",
            "0x0",
            module
        );
    }
}

fn print_driver_details(driver: &VerifiedDriver) {
    outln!("Verifier driver {}", driver.module_name);
    print_value("Image base", &ui::addr(driver.image_base.0));
    print_hex_stat("Image size", driver.image_size);
    print_value("DriverObject", &ui::addr(driver.driver_object.0));
    print_hex_stat("SeSigningLevel", driver.data.se_signing_level);
    print_hex_stat("RaiseIrqls", driver.data.raise_irqls);
    print_hex_stat("AcquireSpinLocks", driver.data.acquire_spin_locks);
    print_hex_stat("Synch Executions", driver.data.synchronize_executions);
    print_hex_stat(
        "Pool Allocations With NO TAG",
        driver.data.allocations_with_no_tag,
    );
    print_hex_stat("Pool Allocations Failed", driver.data.allocations_failed);
    print_hex_stat(
        "Pool Allocations Failed Deliberately",
        driver.data.allocations_failed_deliberately,
    );
    print_pool_stat(
        "Current paged pool allocations",
        driver.data.current_paged_pool_allocations,
        driver.data.paged_bytes,
    );
    print_pool_stat(
        "Peak paged pool allocations",
        driver.data.peak_paged_pool_allocations,
        driver.data.peak_paged_bytes,
    );
    print_pool_stat(
        "Current nonpaged pool allocations",
        driver.data.current_nonpaged_pool_allocations,
        driver.data.nonpaged_bytes,
    );
    print_pool_stat(
        "Peak nonpaged pool allocations",
        driver.data.peak_nonpaged_pool_allocations,
        driver.data.peak_nonpaged_bytes,
    );
    print_hex_stat("Locked bytes", driver.data.locked_bytes);
    print_hex_stat("Peak locked bytes", driver.data.peak_locked_bytes);
    print_hex_stat("Mapped locked bytes", driver.data.mapped_locked_bytes);
    print_hex_stat(
        "Peak mapped locked bytes",
        driver.data.peak_mapped_locked_bytes,
    );
    print_hex_stat("Mapped I/O space bytes", driver.data.mapped_io_space_bytes);
    print_hex_stat(
        "Peak mapped I/O space bytes",
        driver.data.peak_mapped_io_space_bytes,
    );
    print_hex_stat("Pages for MDL bytes", driver.data.pages_for_mdl_bytes);
    print_hex_stat(
        "Peak pages for MDL bytes",
        driver.data.peak_pages_for_mdl_bytes,
    );
    print_hex_stat(
        "Contiguous memory bytes",
        driver.data.contiguous_memory_bytes,
    );
    print_hex_stat(
        "Peak contiguous memory bytes",
        driver.data.peak_contiguous_memory_bytes,
    );
    if let Some(suspect) = &driver.suspect {
        print_value("SuspectDriver FullName", &suspect.full_name);
        print_hex_stat("SuspectDriver Loads", suspect.loads);
        print_hex_stat("SuspectDriver Unloads", suspect.unloads);
    } else {
        print_value("SuspectDriver FullName", "-");
        print_value("SuspectDriver Loads", "-");
        print_value("SuspectDriver Unloads", "-");
    }
}

impl ReplState<'_> {
    fn cmd_verifier(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if invocation.argv.len() > 1 {
            outln!("{}\n", command_help("!verifier"));
            return Ok(());
        }
        let guest = match self.ctx.target.guest() {
            Ok(guest) => guest,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let module = invocation.arg(0).map(str::to_owned);
        if let Some(module) = module {
            let mut drivers = match walk_verified_drivers(guest) {
                Ok(drivers) => drivers,
                Err(error) => {
                    error!("driver verification AVL walk failed: {error}");
                    return Ok(());
                }
            };
            let modules = self.ctx.target.kernel_modules().unwrap_or_default();
            set_module_names(&mut drivers, &modules);
            if let Some(driver) = drivers
                .iter()
                .find(|driver| module_key(&driver.module_name) == module_key(&module))
                .or_else(|| {
                    drivers.iter().find(|driver| {
                        driver.suspect.as_ref().is_some_and(|suspect| {
                            module_key(&suspect.base_name) == module_key(&module)
                        })
                    })
                })
            {
                print_driver_details(driver);
            } else {
                error!("unknown verifier module: {module}");
            }
            return Ok(());
        }

        let state = match read_verifier_state(guest) {
            Ok(state) => state,
            Err(error) => {
                error!("verifier data unavailable: {error}");
                return Ok(());
            }
        };
        print_level(&state);
        if state.level == 0 {
            return Ok(());
        }

        let modules = self.ctx.target.kernel_modules().unwrap_or_default();
        let (mut drivers, avl_error) = match walk_verified_drivers(guest) {
            Ok(drivers) => (drivers, None),
            Err(error) => (Vec::new(), Some(error)),
        };
        set_module_names(&mut drivers, &modules);
        let (suspects, suspect_error) = match read_suspect_list(guest) {
            Ok(suspects) => (suspects, None),
            Err(error) => (Vec::new(), Some(error)),
        };
        print_summary(&state);
        if let Some(error) = avl_error {
            error!("driver verification AVL walk failed: {error}");
        }
        if let Some(error) = suspect_error {
            error!("verifier suspect-driver list unavailable: {error}");
        }
        print_driver_list(&drivers, &suspects);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_flags_decode_in_bit_order() {
        assert_eq!(
            decode_level_flags(0x209bb),
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
            decode_level_flags((1 << 0) | (1 << 20)),
            vec!["Special pool".to_string(), "bit 20".to_string()]
        );
        assert!(decode_level_flags(0).is_empty());
    }
}
