//! The `!vm` system and per-process memory summaries: global memory-manager
//! counters, symbol-discovered `MiState` pool fields, and `_EPROCESS.Vm` usage.

use std::sync::Arc;

use super::{
    ProcessMemoryUsage, SystemMemorySummary, VmCounter, VmDetail, VmPageFileDetail, VmPoolDetail,
    VmPteDetail, diagnostic_unavailable, find_mi_state_fields,
};
use crate::backend::MemoryOps;
use crate::debugger_data::{
    DebuggerDataBlock, MetadataSource, MetadataValue, read_counter_from_getter,
};
use crate::error::{Error, Result};
use crate::guest::ProcessInfo;
use crate::layout::{ParsedType, TypeInfo};
use crate::memory::PAGE_SIZE;
use crate::target::pool::read_kernel_global_u64;
use crate::target::{DiagnosticMetric, DiagnosticValue, Target};
use crate::types::VirtAddr;

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
        value: DiagnosticValue::Unavailable(error.to_string()),
        source: None,
    }
}

fn global_metric(target: &Target, symbol: &str) -> DiagnosticMetric<u64> {
    match read_kernel_global_u64(target, symbol) {
        Ok(value) => available_metric(value),
        Err(error) => unavailable_metric(error),
    }
}

fn named_counter(target: &Target, name: &str, unit: &'static str) -> VmCounter {
    VmCounter {
        name: name.to_string(),
        value: global_metric(target, name),
        unit,
    }
}

fn mi_state_pool_field_unit(name: &str) -> &'static str {
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
        "pages"
    } else {
        "bytes"
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
            Err(error) => {
                ProcessMemoryUsage::from_counters(process, |_| diagnostic_unavailable(error))
            }
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
            paged_pool_pages: self.global_memory_counter("MmSizeOfPagedPoolInPages", None, None),
            nonpaged_pool_bytes: self.global_memory_counter(
                "MmSizeOfNonPagedPoolInBytes",
                None,
                None,
            ),
            processes,
            process_count,
            truncated,
        };
        let pool_fields = find_mi_state_fields(self, &["pool"])
            .into_iter()
            .filter(|(name, _)| curated_mi_state_pool_field(name))
            .take(MAX_MI_STATE_FIELDS)
            .map(|(name, value)| VmCounter {
                unit: mi_state_pool_field_unit(&name),
                name,
                value: available_metric(value),
            })
            .collect();
        let pool = VmPoolDetail {
            nonpaged_pool_bytes: global_metric(self, "MmSizeOfNonPagedPoolInBytes"),
            nonpaged_pool_maximum: global_metric(self, "MmMaximumNonPagedPoolInBytes"),
            paged_pool_pages: global_metric(self, "MmSizeOfPagedPoolInPages"),
            fields: pool_fields,
        };
        let pte = VmPteDetail {
            counters: [
                ("MmTotalSystemPtes", "total system PTEs"),
                ("MmTotalFreeSystemPtes", "free system PTEs"),
                ("MmTotalNonPagedPoolPtes", "nonpaged pool PTEs"),
                ("MmAvailableSystemPtes", "available system PTEs"),
            ]
            .into_iter()
            .map(|(symbol, name)| {
                let mut counter = named_counter(self, symbol, "");
                counter.name = name.to_string();
                counter
            })
            .collect(),
        };
        let page_files = VmPageFileDetail {
            counters: [
                ("MmNumberOfPagingFiles", "number of paging files", ""),
                (
                    "MmTotalPagesForPagingFile",
                    "pages for paging file",
                    "pages",
                ),
                ("MmFreePages", "free paging pages", "pages"),
            ]
            .into_iter()
            .map(|(symbol, name, unit)| {
                let mut counter = named_counter(self, symbol, unit);
                counter.name = name.to_string();
                counter
            })
            .collect(),
        };
        Ok(VmDetail {
            system,
            pool,
            pte,
            page_files,
            include_processes,
        })
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
        eprocess_layout: &TypeInfo,
        vm_layout: &TypeInfo,
        process: ProcessInfo,
    ) -> ProcessMemoryUsage {
        let eprocess = process.eprocess_va;
        ProcessMemoryUsage::from_counters(process, |field| {
            self.process_memory_counter(eprocess_layout, vm_layout, eprocess, field)
        })
    }

    fn process_memory_counter(
        &self,
        eprocess_layout: &TypeInfo,
        vm_layout: &TypeInfo,
        eprocess: VirtAddr,
        field: &str,
    ) -> DiagnosticValue<u64> {
        DiagnosticValue::from_result((|| -> Result<u64> {
            let vm = eprocess + eprocess_layout.field_offset("Vm")?;

            if let Ok(value) = self.read_layout_field(vm_layout, vm, field) {
                return Ok(value);
            }
            if let Ok(value) = self.read_layout_field(eprocess_layout, eprocess, field) {
                return Ok(value);
            }

            let types = self.guest()?.ntoskrnl.types();
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
                if let Ok(value) =
                    self.read_layout_field(&layout, vm + u64::from(container_field.offset), field)
                {
                    return Ok(value);
                }
            }

            let page_field = match field {
                "PagefileUsage" => Some("CommitCharge"),
                "PeakPagefileUsage" => Some("CommitChargePeak"),
                "PrivateUsage" => Some("NumberOfPrivatePages"),
                _ => None,
            };
            if let Some(page_field) = page_field {
                let pages: u64 = self.read_layout_field(eprocess_layout, eprocess, page_field)?;
                return pages.checked_mul(PAGE_SIZE as u64).ok_or_else(|| {
                    Error::DebugInfo(format!("_EPROCESS.{page_field} overflows a byte count"))
                });
            }

            Err(Error::FieldNotFound(field.to_string()))
        })())
    }

    fn debugger_data_counter(
        &self,
        address: Option<MetadataValue<VirtAddr>>,
    ) -> Option<Result<MetadataValue<u64>>> {
        address.map(|address| {
            self.context_memory()
                .read::<u64>(address.value)
                .map(|value| MetadataValue {
                    value,
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
                read_counter_from_getter(&self.context_memory(), getter, system_partition)
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
            // KDBG exposes the configured paged-pool virtual range, not current
            // usage, so it is intentionally not substituted here.
            paged_pool_pages: self.global_memory_counter("MmSizeOfPagedPoolInPages", None, None),
            // KDBG exposes the configured maximum nonpaged-pool size, not the
            // current usage requested here, so it is intentionally not substituted.
            nonpaged_pool_bytes: self.global_memory_counter(
                "MmSizeOfNonPagedPoolInBytes",
                None,
                None,
            ),
            processes,
            process_count,
            truncated: process_count > process_limit,
        })
    }
}
