//! The `!vm` system and per-process memory summaries: global memory-manager
//! counters, symbol-discovered `MiState` pool fields, and `_EPROCESS.Vm` usage.

use std::sync::Arc;

use super::{
    ProcessMemoryUsage, SystemMemorySummary, VmCounter, VmDetail, VmPoolDetail, VmPteDetail,
    VmUnit, find_mi_state_fields,
};
use crate::backend::debugger_data::{
    DebuggerDataBlock, MetadataSource, MetadataValue, read_counter_from_getter,
};
use crate::base::error::{Error, Result};
use crate::base::memory::{MemoryOps, PAGE_SIZE};
use crate::base::types::VirtAddr;
use crate::nt::guest::ProcessInfo;
use crate::nt::layout::{ParsedType, TypeInfo};
use crate::nt::target::pool::read_kernel_global_u64;
use crate::nt::target::{DiagnosticMetric, DiagnosticValue, Target};

const DEFAULT_MEMORY_PROCESS_LIMIT: usize = 64;
const MAX_MI_STATE_FIELDS: usize = 16;

fn available_metric(value: u64) -> DiagnosticMetric<u64> {
    DiagnosticMetric {
        value: DiagnosticValue::Available(value),
        source: Some(MetadataSource::KernelSymbol),
    }
}

fn unavailable_metric(error: impl std::fmt::Display) -> DiagnosticMetric<u64> {
    DiagnosticMetric {
        value: DiagnosticValue::unavailable(error.to_string()),
        source: None,
    }
}

fn global_metric(target: &Target, symbol: &str) -> DiagnosticMetric<u64> {
    match read_kernel_global_u64(target, symbol) {
        Ok(value) => available_metric(value),
        Err(error) => unavailable_metric(error),
    }
}

fn counter(name: &str, value: u64, unit: Option<VmUnit>) -> VmCounter {
    VmCounter {
        name: name.to_string(),
        value: available_metric(value),
        unit,
    }
}

/// Counters called `names` that could not be read, for `error`.
fn unavailable_counters(names: &[&str], error: impl std::fmt::Display) -> Vec<VmCounter> {
    names
        .iter()
        .map(|name| VmCounter {
            name: name.to_string(),
            value: unavailable_metric(&error),
            unit: None,
        })
        .collect()
}

fn mi_state_pool_field_unit(name: &str) -> VmUnit {
    let leaf = name
        .to_ascii_lowercase()
        .rsplit('.')
        .next()
        .unwrap_or_default()
        .to_string();
    if leaf == "maximumnonpagedpoolthreshold"
        || (leaf.contains("allocated")
            && (leaf.contains("nonpagedpool") || leaf.contains("pagedpool")))
    {
        VmUnit::Pages
    } else {
        VmUnit::Bytes
    }
}

fn curated_mi_state_pool_field(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let leaf = lower.rsplit('.').next().unwrap_or(&lower);
    (leaf == "allocatednonpagedpool")
        || (leaf == "allocatedpagedpool")
        || (leaf == "allocatedsecurenonpagedpool")
        || (leaf == "maximumnonpagedpoolthreshold")
        || (leaf.starts_with("total") && leaf.contains("poolquota"))
        || ((leaf.contains("nonpagedpool") || leaf.contains("pagedpool")) && leaf.contains("bytes"))
}

fn vm_processes(target: &Target, include: bool) -> Result<(Vec<ProcessMemoryUsage>, usize, bool)> {
    if !include {
        return Ok((Vec::new(), 0, false));
    }
    let all_processes = target.matching_processes(None)?;
    let process_count = all_processes.len();
    let process_limit = DEFAULT_MEMORY_PROCESS_LIMIT;
    let layouts = target.process_vm_layouts();
    let processes = all_processes
        .into_iter()
        .take(process_limit)
        .map(|process| match &layouts {
            Ok((eprocess_layout, vm_layout)) => {
                target.process_memory_usage(eprocess_layout, vm_layout, process)
            }
            Err(error) => ProcessMemoryUsage::from_counters(process, |_| {
                DiagnosticValue::unavailable(error.to_string())
            }),
        })
        .collect();
    Ok((processes, process_count, process_count > process_limit))
}

impl Target {
    /// Decode system memory, pool, PTE, page-file, and bounded per-process
    /// counters. Global `DiagnosticMetric` values report the kernel-symbol (or
    /// debugger-data fallback) read failure in their value/source; process fields
    /// report missing VM layouts or individual field-read failures independently.
    pub fn inspect_vm(&self, include_processes: bool) -> Result<VmDetail> {
        let debugger_data = self.debugger_data();
        let (processes, process_count, truncated) = vm_processes(self, include_processes)?;
        let system = SystemMemorySummary {
            physical_pages: self.global_memory_counter(
                "MmNumberOfPhysicalPages",
                self.debugger_data_counter(
                    debugger_data.and_then(DebuggerDataBlock::mm_number_of_physical_pages_address),
                ),
                Some("MmGetNumberOfPhysicalPages"),
            ),
            available_pages: self.global_memory_counter(
                "MmAvailablePages",
                self.debugger_data_counter(
                    debugger_data.and_then(DebuggerDataBlock::mm_available_pages_address),
                ),
                Some("MmGetAvailablePages"),
            ),
            committed_pages: self.global_memory_counter(
                "MmTotalCommittedPages",
                self.debugger_data_counter(
                    debugger_data.and_then(DebuggerDataBlock::mm_total_committed_pages_address),
                ),
                Some("MmGetTotalCommittedPages"),
            ),
            commit_limit_pages: self.global_memory_counter(
                "MmTotalCommitLimit",
                self.debugger_data_counter(
                    debugger_data.and_then(DebuggerDataBlock::mm_total_commit_limit_address),
                ),
                Some("MmGetTotalCommitLimit"),
            ),
            paged_pool_pages: self.paged_pool_pages(),
            nonpaged_pool_bytes: self.nonpaged_pool_bytes(),
            processes,
            process_count,
            truncated,
        };
        let pool_fields: Vec<VmCounter> = find_mi_state_fields(self, &["pool"])
            .into_iter()
            .filter(|(name, _)| curated_mi_state_pool_field(name))
            .take(MAX_MI_STATE_FIELDS)
            .map(|(name, value)| VmCounter {
                unit: Some(mi_state_pool_field_unit(&name)),
                name,
                value: available_metric(value),
            })
            .collect();
        // Windows 10 keeps the maximum in MiState instead, in pages.
        let nonpaged_pool_maximum = match global_metric(self, "MmMaximumNonPagedPoolInBytes") {
            metric @ DiagnosticMetric {
                value: DiagnosticValue::Available(_),
                ..
            } => metric,
            missing => pool_fields
                .iter()
                .filter(|field| field.name.ends_with("MaximumNonPagedPoolThreshold"))
                .find_map(|field| match field.value.value {
                    DiagnosticValue::Available(pages) => pages.checked_mul(PAGE_SIZE as u64),
                    DiagnosticValue::Unavailable(_) => None,
                })
                .map_or(missing, available_metric),
        };
        let pool = VmPoolDetail {
            nonpaged_pool_bytes: self.nonpaged_pool_bytes(),
            nonpaged_pool_maximum,
            paged_pool_pages: self.paged_pool_pages(),
            fields: pool_fields,
        };
        // Windows 10 allocates system PTEs from bitmaps, as `!sysptes` reads
        // them, and keeps no counters.
        let counters = match self.counted_system_ptes() {
            Some(counters) => counters,
            None => match self.system_ptes(false) {
                Ok(ptes) if ptes.uncounted.is_empty() => vec![
                    counter("total system PTEs", ptes.total, None),
                    counter("free system PTEs", ptes.free, None),
                ],
                // A sum without an allocator would pass for all of them.
                Ok(ptes) => {
                    let why = format!(
                        "the kernel's counters for {} contradict {} bitmap (see !sysptes)",
                        ptes.uncounted.join(", "),
                        if ptes.uncounted.len() == 1 {
                            "its"
                        } else {
                            "their"
                        }
                    );
                    unavailable_counters(&["total system PTEs", "free system PTEs"], why)
                }
                Err(error) => {
                    unavailable_counters(&["total system PTEs", "free system PTEs"], error)
                }
            },
        };
        let pte = VmPteDetail { counters };
        let page_files = self
            .paging_files()
            .unwrap_or_else(|error| unavailable_counters(&["number of paging files"], error));
        Ok(VmDetail {
            system,
            pool,
            pte,
            page_files,
            include_processes,
        })
    }

    /// The system PTE counts of the builds that keep them, `None` on one
    /// that keeps neither: Vista through 8.1 count in `MiSystemPteInfo`,
    /// Windows Server 2003 in `MmTotalSystemPtes` and in
    /// `MmTotalFreeSystemPtes`, a ULONG for each MMSYSTEM_PTE_POOL_TYPE of
    /// which `SystemPteSpace` is the system PTEs'.
    fn counted_system_ptes(&self) -> Option<Vec<VmCounter>> {
        let kernel = &self.guest().ok()?.ntoskrnl;
        let names = ["total system PTEs", "free system PTEs"];
        if let Ok(info) = kernel.symbol("MiSystemPteInfo") {
            let read = || -> Result<Vec<VmCounter>> {
                let info = kernel
                    .types()
                    .struct_at("_MI_SYSTEM_PTE_TYPE", info.address())?;
                Ok(vec![
                    counter(names[0], info.read_uint("TotalSystemPtes")?, None),
                    counter(names[1], info.read_uint("TotalFreeSystemPtes")?, None),
                ])
            };
            return Some(read().unwrap_or_else(|error| unavailable_counters(&names, error)));
        }
        let total = kernel.symbol("MmTotalSystemPtes").ok()?;
        let free = kernel.symbol("MmTotalFreeSystemPtes").ok()?;
        let read = || -> Result<Vec<VmCounter>> {
            let index = self
                .symbols
                .find_enum_across_modules(self.kernel_dtb(), "_MMSYSTEM_PTE_POOL_TYPE")
                .and_then(|values| {
                    values
                        .into_iter()
                        .find(|(name, _)| name == "SystemPteSpace")
                })
                .and_then(|(_, value)| u64::try_from(value).ok())
                .ok_or_else(|| {
                    Error::DebugInfo("no SystemPteSpace in _MMSYSTEM_PTE_POOL_TYPE".into())
                })?;
            let memory = self.kernel_address_space();
            let free = memory.read::<u32>(free.address() + index * 4)?;
            Ok(vec![
                counter(names[0], total.read::<u32>()?.into(), None),
                counter(names[1], free.into(), None),
            ])
        };
        Some(read().unwrap_or_else(|error| unavailable_counters(&names, error)))
    }

    /// The paging files: how many, and each one's size, limits, use, free
    /// space and peak use, in pages. Their use is what Windows reports as
    /// a file's current usage. Before Windows 10 the kernel keeps them in
    /// `MmPagingFile`, `MmNumberOfPagingFiles` of them; from Windows 10 in
    /// the system partition, `MiSystemPartition.Vp`.
    fn paging_files(&self) -> Result<Vec<VmCounter>> {
        let kernel = &self.guest()?.ntoskrnl;
        let types = kernel.types();
        let (count, slots, capacity) = match kernel.symbol("MmPagingFile") {
            Ok(slots) => {
                let count = kernel.symbol("MmNumberOfPagingFiles")?.read::<u32>()?;
                // The array has a slot for each number `PageFileNumber`
                // can hold.
                let number = types.layout("_MMPAGING_FILE")?;
                let ParsedType::Bitfield { len, .. } = number.field("PageFileNumber")?.type_data
                else {
                    return Err(Error::FieldTypeMismatch(
                        "PageFileNumber".to_string(),
                        "bitfield".to_string(),
                    ));
                };
                (u64::from(count), slots.address(), 1u64 << len)
            }
            Err(_) => {
                let partition = types.struct_at(
                    "_MI_PARTITION",
                    kernel.symbol("MiSystemPartition")?.address(),
                )?;
                let visible = partition.embedded("Vp")?;
                let count = visible.read_uint("NumberOfPagingFiles")?;
                let slots_field = visible.layout().field("PagingFile")?;
                let ParsedType::Array(_, capacity) = slots_field.type_data else {
                    return Err(Error::FieldTypeMismatch(
                        "PagingFile".to_string(),
                        "array".to_string(),
                    ));
                };
                (
                    count,
                    visible.addr() + slots_field.offset as u64,
                    u64::from(capacity),
                )
            }
        };
        let mut counters = vec![counter("number of paging files", count, None)];
        let memory = self.kernel_address_space();
        for index in 0..count.min(capacity) {
            let pointer = memory.read_pointer(slots + 8 * index)?;
            if pointer.is_zero() {
                continue;
            }
            let file = types.struct_at("_MMPAGING_FILE", pointer)?;
            let name = match file.unicode_string("PageFileName") {
                Ok(name) if !name.is_empty() => name,
                _ if file
                    .read_bits("VirtualStorePagefile")
                    .is_ok_and(|bit| bit != 0) =>
                {
                    "virtual store".to_string()
                }
                _ => format!("paging file {index}"),
            };
            let size = file.read_uint("Size")?;
            let free = file.read_uint("FreeSpace")?;
            for (label, pages) in [
                ("size", size),
                ("minimum", file.read_uint("MinimumSize")?),
                ("maximum", file.read_uint("MaximumSize")?),
                ("in use", size.saturating_sub(free)),
                ("free", free),
                ("peak use", file.read_uint("PeakUsage")?),
            ] {
                counters.push(counter(
                    &format!("{name} {label}"),
                    pages,
                    Some(VmUnit::Pages),
                ));
            }
        }
        Ok(counters)
    }

    /// `_EPROCESS` and the struct or union layout of its embedded `Vm`.
    fn process_vm_layouts(&self) -> Result<(Arc<TypeInfo>, Arc<TypeInfo>)> {
        let types = self.guest()?.ntoskrnl.types();
        let eprocess_layout = types.layout("_EPROCESS")?;
        let vm_layout = match &eprocess_layout.field("Vm")?.type_data {
            ParsedType::Struct(name) | ParsedType::Union(name) => types.layout(name)?,
            _ => {
                return Err(Error::FieldTypeMismatch(
                    "Vm".to_string(),
                    "embedded struct".to_string(),
                ));
            }
        };
        Ok((eprocess_layout, vm_layout))
    }

    fn process_memory_usage(
        &self,
        eprocess_layout: &Arc<TypeInfo>,
        vm_layout: &Arc<TypeInfo>,
        process: ProcessInfo,
    ) -> ProcessMemoryUsage {
        let eprocess = process.eprocess;
        ProcessMemoryUsage::from_counters(process, |field| {
            self.process_memory_counter(eprocess_layout, vm_layout, eprocess, field)
        })
    }

    fn process_memory_counter(
        &self,
        eprocess_layout: &Arc<TypeInfo>,
        vm_layout: &Arc<TypeInfo>,
        eprocess: VirtAddr,
        field: &str,
    ) -> DiagnosticValue<u64> {
        // `_MMSUPPORT` counts the working set in pages; the record holds bytes.
        let in_pages = matches!(field, "WorkingSetSize" | "PeakWorkingSetSize");
        let bytes = |value: u64| -> Result<u64> {
            if !in_pages {
                return Ok(value);
            }
            value.checked_mul(PAGE_SIZE as u64).ok_or_else(|| {
                Error::DebugInfo(format!("_MMSUPPORT.{field} overflows a byte count"))
            })
        };
        DiagnosticValue::from_result((|| -> Result<u64> {
            let vm = eprocess + eprocess_layout.field_offset("Vm")?;
            let types = self.guest()?.ntoskrnl.types();
            // At each field's own width: Windows 7's working-set counts are
            // ULONGs, 8.1's ULONGLONGs.
            let read = |layout: &Arc<TypeInfo>, base: VirtAddr, name: &str| {
                types
                    .struct_with_layout(Arc::clone(layout), base)
                    .read_uint(name)
            };

            if let Ok(value) = read(vm_layout, vm, field) {
                return bytes(value);
            }
            if let Ok(value) = read(eprocess_layout, eprocess, field) {
                return Ok(value);
            }

            for container in ["Instance", "Shared"] {
                let Some(container_field) = vm_layout.fields.get(container) else {
                    continue;
                };
                let (ParsedType::Struct(layout_name) | ParsedType::Union(layout_name)) =
                    &container_field.type_data
                else {
                    continue;
                };
                let Ok(layout) = types.layout(layout_name) else {
                    continue;
                };
                if let Ok(value) = read(&layout, vm + u64::from(container_field.offset), field) {
                    return bytes(value);
                }
            }

            let page_field = match field {
                "PagefileUsage" => Some("CommitCharge"),
                "PeakPagefileUsage" => Some("CommitChargePeak"),
                "PrivateUsage" => Some("NumberOfPrivatePages"),
                _ => None,
            };
            if let Some(page_field) = page_field {
                let pages = read(eprocess_layout, eprocess, page_field)?;
                return pages.checked_mul(PAGE_SIZE as u64).ok_or_else(|| {
                    Error::DebugInfo(format!("_EPROCESS.{page_field} overflows a byte count"))
                });
            }

            Err(Error::FieldNotFound(field.to_string()))
        })())
    }

    /// Paged pool in use, in pages: `MmPagedPoolInfo.AllocatedPagedPool`
    /// (Windows 7 and 8.1, whose `MmSizeOfPagedPoolInPages` is the pool's
    /// maximum), or `MiState.Vs.PagedPoolInfo.AllocatedPagedPool`.
    fn paged_pool_pages(&self) -> DiagnosticMetric<u64> {
        let global = (|| -> Result<u64> {
            let kernel = &self.guest()?.ntoskrnl;
            kernel
                .types()
                .struct_at(
                    "_MM_PAGED_POOL_INFO",
                    kernel.symbol("MmPagedPoolInfo")?.address(),
                )?
                .read_uint("AllocatedPagedPool")
        })();
        self.pool_in_use(global, &["Vs", "PagedPoolInfo", "AllocatedPagedPool"], 1)
    }

    /// Nonpaged pool in use, in bytes: `MmAllocatedNonPagedPool` pages
    /// (Windows 7 and 8.1, whose `MmSizeOfNonPagedPoolInBytes` is the
    /// initial size), or `MiState.Pools.AllocatedNonPagedPool` pages.
    fn nonpaged_pool_bytes(&self) -> DiagnosticMetric<u64> {
        let global = read_kernel_global_u64(self, "MmAllocatedNonPagedPool").and_then(|pages| {
            pages
                .checked_mul(PAGE_SIZE as u64)
                .ok_or_else(|| Error::DebugInfo("MmAllocatedNonPagedPool overflows".into()))
        });
        self.pool_in_use(
            global,
            &["Pools", "AllocatedNonPagedPool"],
            PAGE_SIZE as u64,
        )
    }

    /// `global`, the older kernels' count, else the `MiState` field at
    /// `path` times `scale`. Newer kernels keep pool usage only in `MiState`.
    /// KDBG's pool sizes are the configured ranges, not usage, so they are
    /// not used.
    fn pool_in_use(&self, global: Result<u64>, path: &[&str], scale: u64) -> DiagnosticMetric<u64> {
        let global = match global {
            Ok(value) => return available_metric(value),
            Err(error) => error,
        };
        let field = (|| -> Result<u64> {
            let guest = self.guest()?;
            let (leaf, parents) = path
                .split_last()
                .ok_or_else(|| Error::DebugInfo("empty MiState field path".into()))?;
            let types = guest.ntoskrnl.types();
            // `Vs` where the kernel keeps it (see `visible_state`).
            let (mut cursor, parents) = match parents.split_first() {
                Some((&"Vs", rest)) => (
                    types.struct_at("_MI_VISIBLE_STATE", self.visible_state()?)?,
                    rest,
                ),
                _ => (
                    types.struct_at(
                        "_MI_SYSTEM_INFORMATION",
                        guest.ntoskrnl.symbol("MiState")?.address(),
                    )?,
                    parents,
                ),
            };
            for parent in parents {
                cursor = cursor.embedded(parent)?;
            }
            cursor
                .read_uint(leaf)?
                .checked_mul(scale)
                .ok_or_else(|| Error::DebugInfo(format!("MiState.{} overflows", path.join("."))))
        })();
        match field {
            Ok(value) => available_metric(value),
            Err(error) => DiagnosticMetric::unavailable(vec![
                global.to_string(),
                format!("MiState.{}: {error}", path.join(".")),
            ]),
        }
    }

    fn debugger_data_counter(
        &self,
        address: Option<MetadataValue<VirtAddr>>,
    ) -> Option<Result<MetadataValue<u64>>> {
        address.map(|address| {
            // Page counts (`PFN_NUMBER`), as wide as a pointer.
            self.kernel_address_space()
                .read_pointer(address.value)
                .map(|value| MetadataValue {
                    value: value.0,
                    source: address.source,
                })
        })
    }

    fn global_memory_counter(
        &self,
        symbol_name: &str,
        debugger_data_value: Option<Result<MetadataValue<u64>>>,
        getter_name: Option<&str>,
    ) -> DiagnosticMetric<u64> {
        let mut errors = Vec::new();
        match self
            .guest()
            .and_then(|guest| guest.ntoskrnl.symbol(symbol_name))
            .and_then(|symbol| symbol.read())
        {
            Ok(value) => {
                return DiagnosticMetric::available(MetadataValue {
                    value,
                    source: MetadataSource::KernelSymbol,
                });
            }
            Err(error) => errors.push(error.to_string()),
        }

        if let Some(value) = debugger_data_value {
            match value {
                Ok(value) if value.value != 0 => return DiagnosticMetric::available(value),
                Ok(_) => {}
                Err(error) => errors.push(error.to_string()),
            }
        }

        if let Some(getter_name) = getter_name {
            match (|| -> Result<MetadataValue<u64>> {
                let guest = self.guest()?;
                let getter = guest.ntoskrnl.symbol(getter_name)?.address();
                let system_partition = guest.ntoskrnl.symbol("MiSystemPartition")?.address();
                read_counter_from_getter(
                    &self.kernel_address_space(),
                    self.arch(),
                    getter,
                    system_partition,
                )
            })() {
                Ok(value) => return DiagnosticMetric::available(value),
                Err(error) => errors.push(error.to_string()),
            }
        }

        DiagnosticMetric::unavailable(errors)
    }

    /// Build a bounded memory-use summary from exported memory-manager counters
    /// and per-process `_EPROCESS.Vm` fields.  It never scans physical memory or
    /// walks every VAD.
    pub fn memory_use_summary(&self, process_limit: usize) -> Result<SystemMemorySummary> {
        let process_limit = process_limit.clamp(1, 256);
        let all_processes = self.matching_processes(None)?;
        let process_count = all_processes.len();
        let (eprocess_layout, vm_layout) = self.process_vm_layouts()?;
        let processes = all_processes
            .into_iter()
            .take(process_limit)
            .map(|process| self.process_memory_usage(&eprocess_layout, &vm_layout, process))
            .collect();
        let debugger_data = self.debugger_data();
        Ok(SystemMemorySummary {
            physical_pages: self.global_memory_counter(
                "MmNumberOfPhysicalPages",
                self.debugger_data_counter(
                    debugger_data.and_then(DebuggerDataBlock::mm_number_of_physical_pages_address),
                ),
                Some("MmGetNumberOfPhysicalPages"),
            ),
            available_pages: self.global_memory_counter(
                "MmAvailablePages",
                self.debugger_data_counter(
                    debugger_data.and_then(DebuggerDataBlock::mm_available_pages_address),
                ),
                Some("MmGetAvailablePages"),
            ),
            committed_pages: self.global_memory_counter(
                "MmTotalCommittedPages",
                self.debugger_data_counter(
                    debugger_data.and_then(DebuggerDataBlock::mm_total_committed_pages_address),
                ),
                Some("MmGetTotalCommittedPages"),
            ),
            commit_limit_pages: self.global_memory_counter(
                "MmTotalCommitLimit",
                self.debugger_data_counter(
                    debugger_data.and_then(DebuggerDataBlock::mm_total_commit_limit_address),
                ),
                Some("MmGetTotalCommitLimit"),
            ),
            paged_pool_pages: self.paged_pool_pages(),
            nonpaged_pool_bytes: self.nonpaged_pool_bytes(),
            processes,
            process_count,
            truncated: process_count > process_limit,
        })
    }
}
