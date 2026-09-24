//! sched: structured inspector data (shared by the REPL, Python SDK, and MCP).

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::backend::MemoryOps;
use crate::cpu_state::{MAX_PROCESSORS, kpcr_for_processor, kprcb_for_processor, processor_count};
use crate::dbg_backend::processor_index_from_backend_thread_id;
use crate::error::{Error, Result};
use crate::guest::ProcessInfo;
use crate::kuser_shared::KuserSharedData;
use crate::layout::{ParsedType, TypeInfo};
use crate::session::Session;
use crate::target::{DiagnosticValue, ListTermination, Target, ThreadInfo, bounded_list_walk};
use crate::types::VirtAddr;
use crate::unwind::{StackFrame, ThreadTraceContext, format_symbol, resolve_thread_trace_context};

const MAX_LIST_ENTRIES: usize = 4096;
const MAX_RUNNING_STACK_FRAMES: usize = 8;
const MAX_STACK_FRAMES_LEVEL_1: usize = 32;
const MAX_STACK_FRAMES_LEVEL_2: usize = 64;
const READY_PRIORITY_COUNT: usize = 32;
const DPC_QUEUE_COUNT: usize = 2;
const TIMER_BUCKET_COUNT: usize = 256;
const APC_THREAD_DISPLAY_LIMIT: usize = 16_384;

#[derive(Debug, Clone)]
pub struct ThreadSummary {
    pub ethread: VirtAddr,
    pub kthread: VirtAddr,
    pub tid: DiagnosticValue<Option<u64>>,
    pub pid: DiagnosticValue<Option<u64>>,
    pub process_name: DiagnosticValue<Option<String>>,
    pub state: DiagnosticValue<Option<u8>>,
    pub wait_reason: DiagnosticValue<Option<u8>>,
    pub priority: DiagnosticValue<Option<u8>>,
}

#[derive(Debug, Clone)]
pub struct StackFrameDetail {
    pub sp: VirtAddr,
    pub ip: VirtAddr,
    pub symbol: String,
}

#[derive(Debug, Clone)]
pub struct RunningProcessor {
    pub index: u16,
    pub kpcr: DiagnosticValue<VirtAddr>,
    pub prcb: DiagnosticValue<VirtAddr>,
    pub current_thread: DiagnosticValue<Option<ThreadSummary>>,
    pub next_thread: DiagnosticValue<Option<ThreadSummary>>,
    pub idle_thread: DiagnosticValue<Option<ThreadSummary>>,
    /// Present only when `include_stacks` was requested. The vector is bounded
    /// to the short running-thread stack limit.
    pub short_stack: Option<DiagnosticValue<Vec<StackFrameDetail>>>,
}

#[derive(Debug, Clone)]
pub struct RunningDetail {
    pub processors: Vec<RunningProcessor>,
}

#[derive(Debug, Clone)]
pub struct ReadyQueueEntry {
    pub kthread: VirtAddr,
    pub thread: DiagnosticValue<Option<ThreadSummary>>,
}

#[derive(Debug, Clone)]
pub struct ReadyQueue {
    pub processor: u16,
    pub priority: u8,
    pub entries: Vec<ReadyQueueEntry>,
    pub termination: ListTermination,
}

#[derive(Debug, Clone)]
pub struct SchedulerError {
    pub processor: Option<u16>,
    pub queue: Option<u16>,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct ReadyQueuesDetail {
    pub queues: Vec<ReadyQueue>,
    pub total: usize,
    pub truncated: bool,
    pub errors: Vec<SchedulerError>,
}

#[derive(Debug, Clone)]
pub struct DpcDetail {
    pub address: VirtAddr,
    pub deferred_routine: DiagnosticValue<Option<VirtAddr>>,
    pub deferred_routine_symbol: DiagnosticValue<Option<String>>,
    pub context: DiagnosticValue<Option<VirtAddr>>,
    pub importance: DiagnosticValue<Option<u8>>,
}

#[derive(Debug, Clone)]
pub struct DpcQueue {
    pub processor: u16,
    pub queue: u8,
    pub entries: Vec<DpcDetail>,
    pub termination: ListTermination,
}

#[derive(Debug, Clone)]
pub struct DpcQueuesDetail {
    pub queues: Vec<DpcQueue>,
    pub total: usize,
    pub truncated: bool,
    pub errors: Vec<SchedulerError>,
}

#[derive(Debug, Clone)]
pub struct TimerDetail {
    pub address: VirtAddr,
    pub due_time: DiagnosticValue<u64>,
    pub period: DiagnosticValue<u32>,
    pub dpc_encoded: DiagnosticValue<Option<VirtAddr>>,
    pub dpc: DiagnosticValue<Option<VirtAddr>>,
    pub dpc_routine: DiagnosticValue<Option<VirtAddr>>,
    pub dpc_routine_symbol: DiagnosticValue<Option<String>>,
    pub interrupt_time: DiagnosticValue<Option<u64>>,
}

#[derive(Debug, Clone)]
pub struct TimerListEntry {
    pub processor: u16,
    pub bucket: u16,
    pub timer: TimerDetail,
}

#[derive(Debug, Clone)]
pub struct TimerBucketTermination {
    pub processor: u16,
    pub bucket: u16,
    pub termination: ListTermination,
}

#[derive(Debug, Clone)]
pub struct TimerListDetail {
    pub interrupt_time: DiagnosticValue<Option<u64>>,
    pub interrupt_time_source: Option<String>,
    pub entries: Vec<TimerListEntry>,
    pub terminations: Vec<TimerBucketTermination>,
    pub total: usize,
    pub truncated: bool,
    pub errors: Vec<SchedulerError>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApcSelector {
    /// Select the Windows thread currently selected by the session.
    CurrentThread,
    /// Select a thread by ETHREAD, KTHREAD, or TID value.
    Thread(VirtAddr),
    /// Select all threads owned by a PID or EPROCESS value.
    Process(u64),
    /// Resolve a numeric target as a thread first, then a PID/EPROCESS.
    Number(u64),
    /// Enumerate every thread in the bounded process/thread walk.
    All,
}

fn names_thread(thread: &ThreadInfo, value: u64) -> bool {
    thread.ethread.0 == value || thread.kthread.0 == value || thread.tid == Some(value)
}

fn names_process(thread: &ThreadInfo, value: u64) -> bool {
    thread.pid == Some(value) || thread.eprocess.is_some_and(|address| address.0 == value)
}

/// The threads `selector` names out of one thread walk, with a `Number`
/// resolved to the thread it names or, failing that, the process.
fn select_threads(
    selector: ApcSelector,
    threads: Vec<ThreadInfo>,
) -> (ApcSelector, Vec<ThreadInfo>) {
    let selector = match selector {
        ApcSelector::Number(value) if threads.iter().any(|thread| names_thread(thread, value)) => {
            ApcSelector::Thread(VirtAddr(value))
        }
        ApcSelector::Number(value) => ApcSelector::Process(value),
        selector => selector,
    };
    let selected = threads
        .into_iter()
        .filter(|thread| match selector {
            ApcSelector::Thread(value) => names_thread(thread, value.0),
            ApcSelector::Process(value) => names_process(thread, value),
            _ => true,
        })
        .collect();
    (selector, selected)
}

#[derive(Debug, Clone)]
pub struct ApcDetail {
    pub address: VirtAddr,
    pub kernel_routine: DiagnosticValue<Option<VirtAddr>>,
    pub kernel_routine_symbol: DiagnosticValue<Option<String>>,
    pub normal_routine: DiagnosticValue<Option<VirtAddr>>,
    pub normal_routine_symbol: DiagnosticValue<Option<String>>,
}

#[derive(Debug, Clone)]
pub struct ApcThread {
    pub thread: ThreadSummary,
    pub kernel: Vec<ApcDetail>,
    pub user: Vec<ApcDetail>,
    pub kernel_termination: ListTermination,
    pub user_termination: ListTermination,
    pub state_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ApcListDetail {
    pub selector: ApcSelector,
    pub threads: Vec<ApcThread>,
    pub total: usize,
    pub truncated: bool,
    pub layout_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct StackThreadDetail {
    pub thread: ThreadSummary,
    pub active_vcpu: Option<String>,
    pub top_symbol: DiagnosticValue<Option<String>>,
    pub frames: Vec<StackFrameDetail>,
    pub truncated: usize,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct StacksDetail {
    pub level: u8,
    pub filter: Option<String>,
    pub scanned_threads: usize,
    pub displayed_threads: usize,
    pub interrupted: bool,
    pub threads: Vec<StackThreadDetail>,
}

fn available<T>(value: T) -> DiagnosticValue<T> {
    DiagnosticValue::Available(value)
}

fn unavailable<T>(error: impl Into<String>) -> DiagnosticValue<T> {
    DiagnosticValue::Unavailable(error.into())
}

fn optional<T>(value: Option<T>) -> DiagnosticValue<Option<T>> {
    available(value)
}

fn thread_summary(thread: &ThreadInfo) -> ThreadSummary {
    ThreadSummary {
        ethread: thread.ethread,
        kthread: thread.kthread,
        tid: optional(thread.tid),
        pid: optional(thread.pid),
        process_name: optional(thread.process_name.clone()),
        state: optional(thread.state),
        wait_reason: optional(thread.wait_reason),
        priority: optional(thread.priority),
    }
}

fn thread_is_idle(thread: &ThreadSummary) -> bool {
    matches!(thread.pid, DiagnosticValue::Available(Some(0)))
        || matches!(
            &thread.process_name,
            DiagnosticValue::Available(Some(name)) if name.eq_ignore_ascii_case("idle")
        )
}

fn layout_for(target: &Target, name: &str) -> Result<Arc<TypeInfo>> {
    target.guest()?.ntoskrnl.types().layout(name)
}

fn aggregate_type_name(type_data: &ParsedType) -> Option<&str> {
    match type_data {
        ParsedType::Struct(name) | ParsedType::Union(name) => Some(name.as_str()),
        ParsedType::Pointer(inner) | ParsedType::Array(inner, _) => aggregate_type_name(inner),
        _ => None,
    }
}

fn array_element_type_name(type_data: &ParsedType) -> Option<&str> {
    let ParsedType::Array(inner, _) = type_data else {
        return None;
    };
    aggregate_type_name(inner)
}

fn array_count(type_data: &ParsedType, default: usize) -> usize {
    let mut current = type_data;
    let mut count = 1usize;
    let mut found_array = false;
    while let ParsedType::Array(inner, dimension) = current {
        found_array = true;
        let Ok(dimension) = usize::try_from(*dimension) else {
            return default;
        };
        let Some(product) = count.checked_mul(dimension) else {
            return default;
        };
        count = product;
        current = inner;
    }
    if found_array { count } else { default }
}

fn array_stride(target: &Target, type_data: &ParsedType, field_size: u64, default: usize) -> u64 {
    if let Some(element_name) = array_element_type_name(type_data)
        && let Ok(element) = layout_for(target, element_name)
        && element.size != 0
    {
        return element.size as u64;
    }

    if matches!(type_data, ParsedType::Array(_, _)) && field_size != 0 {
        let count = array_count(type_data, 0);
        if count != 0 {
            return field_size / count as u64;
        }
    }

    if field_size != 0 && !matches!(type_data, ParsedType::Array(_, _)) {
        return field_size;
    }

    default as u64
}

fn link_offset(target: &Target, record_type: &str, candidates: &[&str]) -> Option<u64> {
    let layout = layout_for(target, record_type).ok()?;
    candidates
        .iter()
        .find_map(|candidate| layout.field_offset(candidate).ok())
}

fn read_list_next(target: &Target, address: VirtAddr) -> Result<VirtAddr> {
    target
        .guest()?
        .ntoskrnl
        .types()
        .struct_at("_LIST_ENTRY", address)?
        .read_field("Flink")
}

fn walk_list_nodes(
    target: &Target,
    head: VirtAddr,
    limit: usize,
) -> (Vec<VirtAddr>, ListTermination) {
    bounded_list_walk(head, limit.min(MAX_LIST_ENTRIES), |address| {
        read_list_next(target, address)
    })
}

fn processor_indices(target: &Target) -> Result<Vec<u16>> {
    let count = usize::from(processor_count(target)?).clamp(1, usize::from(MAX_PROCESSORS));
    Ok((0..count).map(|index| index as u16).collect())
}

fn selected_processor_indices(target: &Target, processor: Option<u16>) -> Result<Vec<u16>> {
    let count = processor_count(target)?;
    match processor {
        Some(index) if index >= count => Err(Error::DebugInfo(format!(
            "processor index {index} out of range (target has {count} processor(s))"
        ))),
        Some(index) => Ok(vec![index]),
        None => processor_indices(target),
    }
}

fn read_kthread_pointer(target: &Target, prcb: VirtAddr, field: &str) -> Result<VirtAddr> {
    target
        .guest()?
        .ntoskrnl
        .types()
        .struct_at("_KPRCB", prcb)?
        .read_field(field)
}

fn decode_running_thread(
    target: &Target,
    pointer: Result<VirtAddr>,
    ethread_tcb_offset: u64,
) -> DiagnosticValue<Option<ThreadSummary>> {
    let pointer = match pointer {
        Ok(pointer) => pointer,
        Err(error) => return unavailable(error.to_string()),
    };
    if pointer.is_zero() {
        return available(None);
    }
    match target.thread_info_from_ethread(pointer - ethread_tcb_offset) {
        Ok(thread) => available(Some(thread_summary(&thread))),
        Err(error) => unavailable(error.to_string()),
    }
}

fn frame_details(frames: impl IntoIterator<Item = StackFrame>) -> Vec<StackFrameDetail> {
    frames
        .into_iter()
        .map(|frame| StackFrameDetail {
            sp: VirtAddr(frame.sp),
            ip: VirtAddr(frame.ip),
            symbol: frame.symbol,
        })
        .collect()
}

impl Target {
    /// Decode every processor's KPRCB current/next/idle thread pointers.  A
    /// processor is omitted when its current thread is the idle thread unless
    /// `include_idle` is true; each pointer and thread metadata field remains
    /// independently available or unavailable in the returned diagnostics.
    fn running_data(&self, include_idle: bool) -> Result<RunningDetail> {
        let processors = processor_indices(self)?;
        let tcb_offset = layout_for(self, "_ETHREAD")
            .ok()
            .and_then(|layout| layout.field_offset("Tcb").ok())
            .unwrap_or(0);
        let mut rows = Vec::with_capacity(processors.len());
        for index in processors {
            let kpcr = kpcr_for_processor(self, index)
                .map(available)
                .unwrap_or_else(|error| unavailable(error.to_string()));
            let prcb_address = match kprcb_for_processor(self, index) {
                Ok(prcb) => prcb,
                Err(error) => {
                    rows.push(RunningProcessor {
                        index,
                        kpcr,
                        prcb: unavailable(error.to_string()),
                        current_thread: unavailable(error.to_string()),
                        next_thread: unavailable(error.to_string()),
                        idle_thread: unavailable(error.to_string()),
                        short_stack: None,
                    });
                    continue;
                }
            };
            let prcb = available(prcb_address);
            let current = decode_running_thread(
                self,
                read_kthread_pointer(self, prcb_address, "CurrentThread"),
                tcb_offset,
            );
            if !include_idle
                && matches!(&current, DiagnosticValue::Available(Some(thread)) if thread_is_idle(thread))
            {
                continue;
            }
            let next = decode_running_thread(
                self,
                read_kthread_pointer(self, prcb_address, "NextThread"),
                tcb_offset,
            );
            let idle = decode_running_thread(
                self,
                read_kthread_pointer(self, prcb_address, "IdleThread"),
                tcb_offset,
            );
            rows.push(RunningProcessor {
                index,
                kpcr,
                prcb,
                current_thread: current,
                next_thread: next,
                idle_thread: idle,
                short_stack: None,
            });
        }
        Ok(RunningDetail { processors: rows })
    }

    /// Decode bounded dispatcher ready queues for all processors or one
    /// `processor`.  Queue/list termination is retained; a queue's `thread`
    /// diagnostic is unavailable when its link layout or thread metadata read
    /// fails, while `kthread` and other queues remain usable.
    pub fn inspect_ready_queues(&self, processor: Option<u16>) -> Result<ReadyQueuesDetail> {
        let processors = selected_processor_indices(self, processor)?;
        let prcb_layout = layout_for(self, "_KPRCB")?;
        let ready_name = if prcb_layout.fields.contains_key("DispatcherReadyListHead") {
            "DispatcherReadyListHead"
        } else if prcb_layout.fields.contains_key("ReadyListHead") {
            "ReadyListHead"
        } else {
            return Err(Error::FieldNotFound(
                "_KPRCB.DispatcherReadyListHead".to_string(),
            ));
        };
        let ready_field = prcb_layout.field(ready_name)?;
        let stride = array_stride(self, &ready_field.type_data, ready_field.size, 16).max(1);
        let count = array_count(&ready_field.type_data, READY_PRIORITY_COUNT)
            .clamp(1, READY_PRIORITY_COUNT);
        let thread_link_offset = link_offset(
            self,
            "_KTHREAD",
            &["WaitListEntry", "ReadyListEntry", "QueueListEntry"],
        );
        let ethread_tcb_offset = layout_for(self, "_ETHREAD")
            .ok()
            .and_then(|layout| layout.field_offset("Tcb").ok())
            .unwrap_or(0);
        let mut queues = Vec::new();
        let mut errors = Vec::new();
        let mut total = 0usize;
        for processor in processors {
            let prcb = match kprcb_for_processor(self, processor) {
                Ok(prcb) => prcb,
                Err(error) => {
                    errors.push(SchedulerError {
                        processor: Some(processor),
                        queue: None,
                        message: error.to_string(),
                    });
                    continue;
                }
            };
            for priority in 0..count {
                if total >= MAX_LIST_ENTRIES {
                    break;
                }
                let head = prcb + u64::from(ready_field.offset) + priority as u64 * stride;
                let remaining = MAX_LIST_ENTRIES - total;
                let (nodes, termination) = walk_list_nodes(self, head, remaining);
                let mut entries = Vec::with_capacity(nodes.len());
                for node in nodes {
                    let kthread = thread_link_offset
                        .map(|offset| node - offset)
                        .unwrap_or(node);
                    let thread = match thread_link_offset {
                        Some(_) => {
                            match self.thread_info_from_ethread(kthread - ethread_tcb_offset) {
                                Ok(thread) => available(Some(thread_summary(&thread))),
                                Err(error) => unavailable(error.to_string()),
                            }
                        }
                        None => unavailable("_KTHREAD link field not present"),
                    };
                    entries.push(ReadyQueueEntry { kthread, thread });
                    total += 1;
                    if total >= MAX_LIST_ENTRIES {
                        break;
                    }
                }
                queues.push(ReadyQueue {
                    processor,
                    priority: priority as u8,
                    entries,
                    termination,
                });
            }
        }
        Ok(ReadyQueuesDetail {
            queues,
            total,
            truncated: total >= MAX_LIST_ENTRIES,
            errors,
        })
    }

    fn kernel_global_u64(&self, name: &str) -> Result<u64> {
        let address = self.guest()?.ntoskrnl.symbol(name)?.address();
        self.guest()?.ntoskrnl.memory().read(address)
    }

    fn pointer_field(
        &self,
        type_name: &str,
        base: VirtAddr,
        field: Option<&str>,
    ) -> DiagnosticValue<Option<VirtAddr>> {
        let Some(field) = field else {
            return unavailable("field not present");
        };
        match self
            .guest()
            .and_then(|guest| guest.ntoskrnl.types().struct_at(type_name, base))
            .and_then(|cursor| cursor.read_field::<VirtAddr>(field))
        {
            Ok(value) if value.is_zero() => available(None),
            Ok(value) => available(Some(value)),
            Err(error) => unavailable(error.to_string()),
        }
    }

    fn pointer_symbol(
        &self,
        pointer: &DiagnosticValue<Option<VirtAddr>>,
        trace: &ThreadTraceContext,
    ) -> DiagnosticValue<Option<String>> {
        match pointer {
            DiagnosticValue::Unavailable(error) => unavailable(error.clone()),
            DiagnosticValue::Available(None) => available(None),
            DiagnosticValue::Available(Some(address)) => {
                available(Some(format_symbol(self, trace, address.0)))
            }
        }
    }

    /// Decode bounded DPC queues from each processor's `_KPRCB.DpcData`.
    /// Routine, context, importance, and list termination each retain their
    /// own unavailable diagnostic: a missing/unreadable `_KDPC` field affects
    /// only that field, and a bad list link affects only that queue.
    pub fn inspect_dpc_queues(&self) -> Result<DpcQueuesDetail> {
        let processors = processor_indices(self)?;
        let prcb_layout = layout_for(self, "_KPRCB")?;
        let dpc_data = prcb_layout
            .fields
            .get("DpcData")
            .ok_or_else(|| Error::FieldNotFound("_KPRCB.DpcData".to_string()))?;
        let data_count = array_count(&dpc_data.type_data, DPC_QUEUE_COUNT).min(DPC_QUEUE_COUNT);
        let data_stride = array_stride(self, &dpc_data.type_data, dpc_data.size, 0x40).max(1);
        let data_type_name = array_element_type_name(&dpc_data.type_data)
            .or_else(|| aggregate_type_name(&dpc_data.type_data))
            .ok_or_else(|| {
                Error::DebugInfo("_KPRCB.DpcData element type unavailable".to_string())
            })?;
        let data_layout = layout_for(self, data_type_name)?;
        let dpc_list = data_layout
            .fields
            .get("DpcList")
            .ok_or_else(|| Error::FieldNotFound(format!("{data_type_name}.DpcList")))?;
        let dpc_link_offset = link_offset(self, "_KDPC", &["DpcListEntry", "ListEntry", "SLink"]);
        let dpc_layout = layout_for(self, "_KDPC").ok();
        let routine_field = dpc_layout.as_ref().and_then(|layout| {
            if layout.fields.contains_key("DeferredRoutine") {
                Some("DeferredRoutine")
            } else if layout.fields.contains_key("DpcRoutine") {
                Some("DpcRoutine")
            } else {
                None
            }
        });
        let context_field = dpc_layout.as_ref().and_then(|layout| {
            if layout.fields.contains_key("DeferredContext") {
                Some("DeferredContext")
            } else if layout.fields.contains_key("Context") {
                Some("Context")
            } else {
                None
            }
        });
        let importance_field = dpc_layout.as_ref().and_then(|layout| {
            layout
                .fields
                .contains_key("Importance")
                .then_some("Importance")
        });
        let trace = resolve_thread_trace_context(self, self.kernel_dtb());
        let mut queues = Vec::new();
        let mut errors = Vec::new();
        let mut total = 0usize;
        for processor in processors {
            let prcb = match kprcb_for_processor(self, processor) {
                Ok(prcb) => prcb,
                Err(error) => {
                    errors.push(SchedulerError {
                        processor: Some(processor),
                        queue: None,
                        message: error.to_string(),
                    });
                    continue;
                }
            };
            for queue in 0..data_count {
                if total >= MAX_LIST_ENTRIES {
                    break;
                }
                let data = prcb + u64::from(dpc_data.offset) + queue as u64 * data_stride;
                let head = data + u64::from(dpc_list.offset);
                let remaining = MAX_LIST_ENTRIES - total;
                let (nodes, termination) = walk_list_nodes(self, head, remaining);
                let mut entries = Vec::with_capacity(nodes.len());
                for node in nodes {
                    let dpc = dpc_link_offset.map(|offset| node - offset).unwrap_or(node);
                    let routine = self.pointer_field("_KDPC", dpc, routine_field);
                    let context = self.pointer_field("_KDPC", dpc, context_field);
                    let importance = importance_field
                        .map(|field| {
                            self.guest()
                                .and_then(|guest| guest.ntoskrnl.types().struct_at("_KDPC", dpc))
                                .and_then(|cursor| cursor.read_field::<u8>(field))
                                .map(Some)
                                .map_err(|error| error.to_string())
                                .map_or_else(
                                    DiagnosticValue::Unavailable,
                                    DiagnosticValue::Available,
                                )
                        })
                        .unwrap_or_else(|| unavailable("field not present"));
                    let (routine, context, importance) = if dpc_link_offset.is_some() {
                        (routine, context, importance)
                    } else {
                        (
                            unavailable("_KDPC link field not present"),
                            unavailable("_KDPC link field not present"),
                            unavailable("_KDPC link field not present"),
                        )
                    };
                    entries.push(DpcDetail {
                        address: dpc,
                        deferred_routine_symbol: self.pointer_symbol(&routine, &trace),
                        deferred_routine: routine,
                        context,
                        importance,
                    });
                    total += 1;
                    if total >= MAX_LIST_ENTRIES {
                        break;
                    }
                }
                queues.push(DpcQueue {
                    processor,
                    queue: queue as u8,
                    entries,
                    termination,
                });
            }
        }
        Ok(DpcQueuesDetail {
            queues,
            total,
            truncated: total >= MAX_LIST_ENTRIES,
            errors,
        })
    }

    fn timer_dpc_keys(&self) -> Option<(u64, u64)> {
        Some((
            self.kernel_global_u64("KiWaitNever").ok()?,
            self.kernel_global_u64("KiWaitAlways").ok()?,
        ))
    }

    fn decode_timer_dpc(
        &self,
        encoded: u64,
        timer: VirtAddr,
        keys: Option<(u64, u64)>,
    ) -> Option<VirtAddr> {
        let (wait_never, wait_always) = keys?;
        let rotated = (encoded ^ wait_never).rotate_left((wait_never & 0xff) as u32);
        Some(VirtAddr((rotated ^ timer.0).swap_bytes() ^ wait_always))
    }

    fn interrupt_time(&self) -> (DiagnosticValue<Option<u64>>, Option<String>) {
        match KuserSharedData::new(self).interrupt_time() {
            Some(value) => (
                available(Some(value)),
                Some("KUSER_SHARED_DATA.InterruptTime".to_string()),
            ),
            None => (
                unavailable("KUSER_SHARED_DATA.InterruptTime unavailable"),
                None,
            ),
        }
    }

    fn decode_timer_with_context(
        &self,
        timer: VirtAddr,
        timer_layout: &TypeInfo,
        interrupt_time: DiagnosticValue<Option<u64>>,
        keys: Option<(u64, u64)>,
        trace: &ThreadTraceContext,
    ) -> TimerDetail {
        let cursor = self
            .guest()
            .and_then(|guest| guest.ntoskrnl.types().struct_at("_KTIMER", timer));
        let due_time = if !timer_layout.fields.contains_key("DueTime") {
            unavailable("DueTime field not present")
        } else {
            match cursor.as_ref() {
                Ok(cursor) => cursor
                    .read_field::<u64>("DueTime")
                    .map_err(|error| error.to_string())
                    .map_or_else(DiagnosticValue::Unavailable, DiagnosticValue::Available),
                Err(error) => unavailable(error.to_string()),
            }
        };
        let period = if !timer_layout.fields.contains_key("Period") {
            unavailable("Period field not present")
        } else {
            match cursor.as_ref() {
                Ok(cursor) => cursor
                    .read_field::<u32>("Period")
                    .map_err(|error| error.to_string())
                    .map_or_else(DiagnosticValue::Unavailable, DiagnosticValue::Available),
                Err(error) => unavailable(error.to_string()),
            }
        };
        let dpc_encoded = if !timer_layout.fields.contains_key("Dpc") {
            unavailable("Dpc field not present")
        } else {
            match cursor.as_ref() {
                Ok(cursor) => cursor
                    .read_field::<VirtAddr>("Dpc")
                    .map(|address| (!address.is_zero()).then_some(address))
                    .map_err(|error| error.to_string())
                    .map_or_else(DiagnosticValue::Unavailable, DiagnosticValue::Available),
                Err(error) => unavailable(error.to_string()),
            }
        };
        let dpc = match &dpc_encoded {
            DiagnosticValue::Unavailable(error) => unavailable(error.clone()),
            DiagnosticValue::Available(None) => available(None),
            DiagnosticValue::Available(Some(encoded)) => {
                match self.decode_timer_dpc(encoded.0, timer, keys) {
                    Some(address) if address.is_zero() => available(None),
                    Some(address) => available(Some(address)),
                    None => unavailable("timer DPC encoding keys unavailable"),
                }
            }
        };
        let dpc_routine = match &dpc {
            DiagnosticValue::Unavailable(error) => unavailable(error.clone()),
            DiagnosticValue::Available(None) => available(None),
            DiagnosticValue::Available(Some(address)) => {
                let layout = match layout_for(self, "_KDPC") {
                    Ok(layout) => layout,
                    Err(error) => {
                        return TimerDetail {
                            address: timer,
                            due_time,
                            period,
                            dpc_encoded,
                            dpc,
                            dpc_routine: unavailable(error.to_string()),
                            dpc_routine_symbol: unavailable(error.to_string()),
                            interrupt_time,
                        };
                    }
                };
                let field = if layout.fields.contains_key("DeferredRoutine") {
                    Some("DeferredRoutine")
                } else if layout.fields.contains_key("DpcRoutine") {
                    Some("DpcRoutine")
                } else {
                    None
                };
                self.pointer_field("_KDPC", *address, field)
            }
        };
        let dpc_routine_symbol = self.pointer_symbol(&dpc_routine, trace);
        TimerDetail {
            address: timer,
            due_time,
            period,
            dpc_encoded,
            dpc,
            dpc_routine,
            dpc_routine_symbol,
            interrupt_time,
        }
    }

    /// Decode one `_KTIMER` and its encoded DPC at `timer`.  `due_time`,
    /// `period`, encoded/decoded DPC pointers, DPC routine, and interrupt time
    /// are independent diagnostics; a missing field or encoding key marks only
    /// the affected value unavailable.
    pub fn inspect_timer(&self, timer: VirtAddr) -> Result<TimerDetail> {
        let timer_layout = layout_for(self, "_KTIMER")?;
        let (interrupt_time, _) = self.interrupt_time();
        let keys = self.timer_dpc_keys();
        let trace = resolve_thread_trace_context(self, self.kernel_dtb());
        Ok(self.decode_timer_with_context(timer, &timer_layout, interrupt_time, keys, &trace))
    }

    /// Walk every processor's timer table and decode each bounded timer.  The
    /// list form keeps bucket/processor provenance and list termination while
    /// sharing the exact single-timer decoder; processor/table/list failures
    /// are retained in `errors` and per-timer diagnostics.
    pub fn timer_list(&self) -> Result<TimerListDetail> {
        let timer_layout = layout_for(self, "_KTIMER")?;
        let (interrupt_time, interrupt_time_source) = self.interrupt_time();
        let keys = self.timer_dpc_keys();
        let trace = resolve_thread_trace_context(self, self.kernel_dtb());
        let prcb_layout = layout_for(self, "_KPRCB")?;
        let timer_table_field = prcb_layout
            .fields
            .get("TimerTable")
            .ok_or_else(|| Error::FieldNotFound("_KPRCB.TimerTable".to_string()))?;
        let table_type = aggregate_type_name(&timer_table_field.type_data)
            .ok_or_else(|| Error::DebugInfo("_KPRCB.TimerTable type unavailable".to_string()))?;
        let table_layout = layout_for(self, table_type)?;
        let entries = table_layout
            .fields
            .get("TimerEntries")
            .ok_or_else(|| Error::FieldNotFound("_KTIMER_TABLE.TimerEntries".to_string()))?;
        let resolved_entry_count = array_count(&entries.type_data, TIMER_BUCKET_COUNT);
        let entry_type_name = array_element_type_name(&entries.type_data)
            .or_else(|| aggregate_type_name(&entries.type_data))
            .ok_or_else(|| Error::DebugInfo("_KTIMER_TABLE entry type unavailable".to_string()))?;
        let entry_layout = layout_for(self, entry_type_name)?;
        let entry_stride = entry_layout.size as u64;
        if entry_stride == 0 {
            return Err(Error::DebugInfo(format!(
                "_KTIMER_TABLE.TimerEntries leaf type {entry_type_name} has no size"
            )));
        }
        if entries.size != 0
            && u64::try_from(resolved_entry_count)
                .ok()
                .and_then(|count| count.checked_mul(entry_stride))
                != Some(entries.size)
        {
            return Err(Error::DebugInfo(format!(
                "_KTIMER_TABLE.TimerEntries dimensions/size mismatch ({} entries * {:#x} != field size {:#x})",
                resolved_entry_count, entry_stride, entries.size
            )));
        }
        let entry_count = resolved_entry_count.min(MAX_LIST_ENTRIES);
        let entry_name = if entry_layout.fields.contains_key("Entry") {
            "Entry"
        } else if entry_layout.fields.contains_key("TimerListEntry") {
            "TimerListEntry"
        } else {
            return Err(Error::FieldNotFound(format!("{entry_type_name}.Entry")));
        };
        let entry = entry_layout
            .fields
            .get(entry_name)
            .ok_or_else(|| Error::FieldNotFound(format!("{entry_type_name}.{entry_name}")))?;
        let timer_link_offset = link_offset(
            self,
            "_KTIMER",
            &["TimerListEntry", "TimerList", "ListEntry"],
        );
        let processors = processor_indices(self)?;
        let mut list_entries = Vec::new();
        let mut terminations = Vec::new();
        let mut errors = Vec::new();
        let mut total = 0usize;
        for processor in processors {
            let prcb = match kprcb_for_processor(self, processor) {
                Ok(prcb) => prcb,
                Err(error) => {
                    errors.push(SchedulerError {
                        processor: Some(processor),
                        queue: None,
                        message: error.to_string(),
                    });
                    continue;
                }
            };
            let table = if matches!(timer_table_field.type_data, ParsedType::Pointer(_)) {
                match self
                    .guest()
                    .and_then(|guest| guest.ntoskrnl.types().struct_at("_KPRCB", prcb))
                    .and_then(|cursor| cursor.read_field::<VirtAddr>("TimerTable"))
                {
                    Ok(address) if !address.is_zero() => address,
                    Ok(_) => {
                        errors.push(SchedulerError {
                            processor: Some(processor),
                            queue: None,
                            message: "TimerTable is null".to_string(),
                        });
                        continue;
                    }
                    Err(error) => {
                        errors.push(SchedulerError {
                            processor: Some(processor),
                            queue: None,
                            message: error.to_string(),
                        });
                        continue;
                    }
                }
            } else {
                prcb + u64::from(timer_table_field.offset)
            };
            for bucket in 0..entry_count {
                if total >= MAX_LIST_ENTRIES {
                    break;
                }
                let head = table
                    + u64::from(entries.offset)
                    + bucket as u64 * entry_stride
                    + u64::from(entry.offset);
                let remaining = MAX_LIST_ENTRIES - total;
                let (nodes, termination) = walk_list_nodes(self, head, remaining);
                terminations.push(TimerBucketTermination {
                    processor,
                    bucket: bucket as u16,
                    termination: termination.clone(),
                });
                for node in nodes {
                    let timer = timer_link_offset
                        .map(|offset| node - offset)
                        .unwrap_or(node);
                    let detail = if timer_link_offset.is_some() {
                        self.decode_timer_with_context(
                            timer,
                            &timer_layout,
                            interrupt_time.clone(),
                            keys,
                            &trace,
                        )
                    } else {
                        TimerDetail {
                            address: timer,
                            due_time: unavailable("_KTIMER link field not present"),
                            period: unavailable("_KTIMER link field not present"),
                            dpc_encoded: unavailable("_KTIMER link field not present"),
                            dpc: unavailable("_KTIMER link field not present"),
                            dpc_routine: unavailable("_KTIMER link field not present"),
                            dpc_routine_symbol: unavailable("_KTIMER link field not present"),
                            interrupt_time: interrupt_time.clone(),
                        }
                    };
                    list_entries.push(TimerListEntry {
                        processor,
                        bucket: bucket as u16,
                        timer: detail,
                    });
                    total += 1;
                    if total >= MAX_LIST_ENTRIES {
                        break;
                    }
                }
            }
        }
        Ok(TimerListDetail {
            interrupt_time,
            interrupt_time_source,
            entries: list_entries,
            terminations,
            total,
            truncated: total >= MAX_LIST_ENTRIES,
            errors,
        })
    }

    fn apc_layout(&self) -> Result<ApcLayout> {
        let kthread = layout_for(self, "_KTHREAD")?;
        let state = kthread.field("ApcState")?;
        let state_name = aggregate_type_name(&state.type_data)
            .ok_or_else(|| Error::DebugInfo("ApcState type unavailable".to_string()))?;
        let state_layout = layout_for(self, state_name)?;
        let heads = state_layout.field("ApcListHead")?;
        let apc_layout = layout_for(self, "_KAPC").ok();
        let link_offset = link_offset(self, "_KAPC", &["ApcListEntry", "ListEntry"]);
        let head_stride = array_stride(self, &heads.type_data, heads.size, 16).max(1);
        Ok(ApcLayout {
            state_offset: u64::from(state.offset),
            state_is_pointer: matches!(state.type_data, ParsedType::Pointer(_)),
            heads_offset: u64::from(heads.offset),
            head_stride,
            link_offset,
            kernel_routine: apc_layout.as_ref().and_then(|layout| {
                layout
                    .fields
                    .contains_key("KernelRoutine")
                    .then_some("KernelRoutine")
            }),
            normal_routine: apc_layout.as_ref().and_then(|layout| {
                layout
                    .fields
                    .contains_key("NormalRoutine")
                    .then_some("NormalRoutine")
            }),
        })
    }
}

struct ApcLayout {
    state_offset: u64,
    state_is_pointer: bool,
    heads_offset: u64,
    head_stride: u64,
    link_offset: Option<u64>,
    kernel_routine: Option<&'static str>,
    normal_routine: Option<&'static str>,
}

impl Session {
    /// Decode running processor metadata and, when requested, append a bounded
    /// short stack for each current thread using the session's stack walker.
    /// KPRC/KPCR, current/next/idle pointers, thread metadata, and stack reads
    /// are independent diagnostics, so one processor's missing field does not
    /// discard its other rows.
    pub fn inspect_running(
        &self,
        include_idle: bool,
        include_stacks: bool,
    ) -> Result<RunningDetail> {
        let mut detail = self.target.running_data(include_idle)?;
        if include_stacks {
            for processor in &mut detail.processors {
                let stack = match &processor.current_thread {
                    DiagnosticValue::Available(Some(thread)) => {
                        match self.target.thread_info_from_ethread(thread.ethread) {
                            Ok(thread_info) => match self
                                .backtrace_thread(&thread_info, MAX_RUNNING_STACK_FRAMES)
                            {
                                Ok(trace) => available(frame_details(trace.stacktrace.frames)),
                                Err(error) => unavailable(error.to_string()),
                            },
                            Err(error) => unavailable(error.to_string()),
                        }
                    }
                    DiagnosticValue::Available(None) => unavailable("current thread is null"),
                    DiagnosticValue::Unavailable(error) => unavailable(error.clone()),
                };
                processor.short_stack = Some(stack);
            }
        }
        Ok(detail)
    }

    fn select_apc_threads(&self, selector: ApcSelector) -> Result<(ApcSelector, Vec<ThreadInfo>)> {
        match selector {
            ApcSelector::CurrentThread => {
                let thread = if let Some(thread) = self.target.windows_thread_selection.as_ref() {
                    thread.clone()
                } else {
                    let processor = processor_index_from_backend_thread_id(&self.current_thread)
                        .ok_or_else(|| {
                            Error::DebugInfo("current Windows thread is unavailable".to_string())
                        })?;
                    self.target
                        .current_windows_thread_for_processor(processor)?
                };
                Ok((selector, vec![thread]))
            }
            selector => Ok(select_threads(selector, self.target.enumerate_threads()?)),
        }
    }

    fn decode_apc(
        &self,
        apc: VirtAddr,
        layout: &ApcLayout,
        trace: &ThreadTraceContext,
    ) -> ApcDetail {
        let kernel = self
            .target
            .pointer_field("_KAPC", apc, layout.kernel_routine);
        let normal = self
            .target
            .pointer_field("_KAPC", apc, layout.normal_routine);
        ApcDetail {
            address: apc,
            kernel_routine_symbol: self.target.pointer_symbol(&kernel, trace),
            kernel_routine: kernel,
            normal_routine_symbol: self.target.pointer_symbol(&normal, trace),
            normal_routine: normal,
        }
    }

    /// Decode kernel and user APC queues for the selected/current thread, one
    /// thread, one PID/EPROCESS, or all threads.  APC list walks are bounded and
    /// preserve their per-list termination; layout failure is retained in
    /// `layout_error` while thread metadata still remains usable.
    pub fn inspect_apcs(&self, selector: ApcSelector) -> Result<ApcListDetail> {
        let (selector, threads) = self.select_apc_threads(selector)?;
        let layout = self.target.apc_layout();
        let layout_error = layout.as_ref().err().map(ToString::to_string);
        let trace = resolve_thread_trace_context(&self.target, self.target.kernel_dtb());
        let selected_count = threads.len();
        let mut detail_threads = Vec::new();
        let mut total = 0usize;
        let mut truncated = false;
        for thread in threads.into_iter().take(APC_THREAD_DISPLAY_LIMIT) {
            let summary = thread_summary(&thread);
            let (mut kernel_entries, mut user_entries) = (Vec::new(), Vec::new());
            let (mut kernel_termination, mut user_termination) =
                (ListTermination::Head, ListTermination::Head);
            let mut state_error = None;
            if let Ok(layout) = &layout {
                let state_base = if layout.state_is_pointer {
                    match self
                        .target
                        .guest()
                        .and_then(|guest| {
                            guest.ntoskrnl.types().struct_at("_KTHREAD", thread.kthread)
                        })
                        .and_then(|cursor| cursor.read_field::<VirtAddr>("ApcState"))
                    {
                        Ok(address) if !address.is_zero() => Some(address),
                        Ok(_) => {
                            state_error = Some("ApcState is null".to_string());
                            None
                        }
                        Err(error) => {
                            state_error = Some(error.to_string());
                            None
                        }
                    }
                } else {
                    Some(thread.kthread + layout.state_offset)
                };
                if let Some(state_base) = state_base {
                    for (index, entries, termination) in [
                        (0usize, &mut kernel_entries, &mut kernel_termination),
                        (1usize, &mut user_entries, &mut user_termination),
                    ] {
                        if total >= MAX_LIST_ENTRIES {
                            truncated = true;
                            break;
                        }
                        let head =
                            state_base + layout.heads_offset + index as u64 * layout.head_stride;
                        let remaining = MAX_LIST_ENTRIES - total;
                        let (nodes, stop) = walk_list_nodes(&self.target, head, remaining);
                        *termination = stop;
                        for node in nodes {
                            let apc = layout
                                .link_offset
                                .map(|offset| node - offset)
                                .unwrap_or(node);
                            entries.push(self.decode_apc(apc, layout, &trace));
                            total += 1;
                            if total >= MAX_LIST_ENTRIES {
                                truncated = true;
                                break;
                            }
                        }
                    }
                }
            }
            detail_threads.push(ApcThread {
                thread: summary,
                kernel: kernel_entries,
                user: user_entries,
                kernel_termination,
                user_termination,
                state_error,
            });
            if truncated {
                break;
            }
        }
        if selected_count > APC_THREAD_DISPLAY_LIMIT {
            truncated = true;
        }
        Ok(ApcListDetail {
            selector,
            threads: detail_threads,
            total,
            truncated,
            layout_error,
        })
    }

    /// Enumerate every Windows thread (including active vCPU threads absent
    /// from the process walk), resolve its bounded stack, and apply the optional
    /// case-insensitive process/symbol filter before returning structured rows.
    /// Each top symbol/stack read is independently diagnostic; unreadable
    /// thread metadata remains visible with its unavailable field.
    pub fn inspect_stacks(&mut self, level: u8, filter: Option<&str>) -> Result<StacksDetail> {
        let level = level.min(2);
        let filter = filter.map(|value| value.to_ascii_lowercase());
        let (threads, active_vcpus) = self.windows_threads()?;
        let scanned_threads = threads.len();
        let frame_limit = match level {
            1 => MAX_STACK_FRAMES_LEVEL_1,
            2 => MAX_STACK_FRAMES_LEVEL_2,
            _ => 1,
        };
        let mut interrupted = false;
        let mut details = Vec::new();
        for thread in threads {
            if interrupted || self.target.interrupt.swap(false, Ordering::SeqCst) {
                interrupted = true;
                break;
            }
            let stack = self.backtrace_thread(&thread, frame_limit);
            let (frames, truncated, error, top_symbol) = match stack {
                Ok(trace) => {
                    let frames = frame_details(trace.stacktrace.frames);
                    let top = frames.first().map(|frame| frame.symbol.clone());
                    (frames, trace.stacktrace.truncated, None, available(top))
                }
                Err(error) => {
                    let message = error.to_string();
                    (Vec::new(), 0, Some(message.clone()), unavailable(message))
                }
            };
            let process = thread
                .process_name
                .as_deref()
                .unwrap_or("<unknown>")
                .to_ascii_lowercase();
            let symbol_match = filter.as_deref().is_none_or(|needle| {
                top_symbol_contains(&top_symbol, needle)
                    || frames
                        .iter()
                        .any(|frame| frame.symbol.to_ascii_lowercase().contains(needle))
            });
            let process_match = filter
                .as_deref()
                .is_none_or(|needle| process.contains(needle));
            if !symbol_match && !process_match {
                continue;
            }
            details.push(StackThreadDetail {
                thread: thread_summary(&thread),
                active_vcpu: active_vcpus.get(&thread.ethread.0).cloned(),
                top_symbol,
                frames,
                truncated,
                error,
            });
        }
        Ok(StacksDetail {
            level,
            filter,
            scanned_threads,
            displayed_threads: details.len(),
            interrupted,
            threads: details,
        })
    }
}

fn top_symbol_contains(value: &DiagnosticValue<Option<String>>, needle: &str) -> bool {
    matches!(
        value,
        DiagnosticValue::Available(Some(symbol)) if symbol.to_ascii_lowercase().contains(needle)
    )
}

impl Target {
    pub fn enumerate_threads_for_process_info(
        &self,
        process: &ProcessInfo,
    ) -> Result<Vec<ThreadInfo>> {
        let guest = self.guest()?;
        let memory = guest.ntoskrnl.memory();
        let eprocess = guest
            .ntoskrnl
            .types_in(process.dtb)
            .struct_at("_EPROCESS", process.eprocess_va)?;
        let eprocess_layout = guest.ntoskrnl.types().layout("_EPROCESS")?;
        let thread_list_head_offset = eprocess_layout.field_offset("ThreadListHead")?;
        let ethread_layout = guest.ntoskrnl.types().layout("_ETHREAD")?;
        let thread_list_entry_offset = ethread_layout.field_offset("ThreadListEntry")?;
        let head = eprocess.addr() + thread_list_head_offset;

        let mut threads = Vec::new();
        let mut visited = HashSet::new();
        let mut current: VirtAddr = memory.read(head)?;

        for _ in 0..16384 {
            if current.is_zero() || current == head || !visited.insert(current.0) {
                break;
            }

            let ethread = current - thread_list_entry_offset;
            threads.push(self.thread_info_from_ethread_with_hint(ethread, Some(process))?);
            current = memory.read(current)?;
        }

        Ok(threads)
    }

    pub fn enumerate_threads(&self) -> Result<Vec<ThreadInfo>> {
        const MAX_ENUMERATED_THREADS: usize = 65_536;
        let processes = self.guest()?.enumerate_processes()?;
        let mut threads = Vec::new();

        for process in &processes {
            if threads.len() >= MAX_ENUMERATED_THREADS {
                break;
            }
            let Ok(process_threads) = self.enumerate_threads_for_process_info(process) else {
                continue;
            };
            threads.extend(
                process_threads
                    .into_iter()
                    .take(MAX_ENUMERATED_THREADS.saturating_sub(threads.len())),
            );
        }

        Ok(threads)
    }

    pub fn thread_info_from_ethread(&self, ethread: VirtAddr) -> Result<ThreadInfo> {
        self.thread_info_from_ethread_with_hint(ethread, None)
    }

    fn thread_info_from_ethread_with_hint(
        &self,
        ethread: VirtAddr,
        process_hint: Option<&ProcessInfo>,
    ) -> Result<ThreadInfo> {
        let guest = self.guest()?;
        let memory = guest.ntoskrnl.memory();
        let types = guest.ntoskrnl.types();
        let ethread_layout = types.layout("_ETHREAD")?;
        let kthread_layout = types.layout("_KTHREAD")?;
        let tcb_offset = ethread_layout.field_offset("Tcb").unwrap_or(0);
        let kthread = ethread + tcb_offset;

        let cid_base = ethread_layout
            .field_offset("Cid")
            .ok()
            .map(|offset| ethread + offset);
        let client_id_layout = types.layout("_CLIENT_ID").ok();
        let tid = cid_base.and_then(|base| {
            client_id_layout
                .as_ref()
                .and_then(|layout| layout.field_offset("UniqueThread").ok())
                .and_then(|offset| memory.read::<u64>(base + offset).ok())
        });
        let pid = cid_base.and_then(|base| {
            client_id_layout
                .as_ref()
                .and_then(|layout| layout.field_offset("UniqueProcess").ok())
                .and_then(|offset| memory.read::<u64>(base + offset).ok())
        });

        let read_ethread_ptr = |field: &str| -> Option<VirtAddr> {
            ethread_layout
                .field_offset(field)
                .ok()
                .and_then(|offset| memory.read::<VirtAddr>(ethread + offset).ok())
                .filter(|addr| !addr.is_zero())
        };
        let read_kthread_ptr = |field: &str| -> Option<VirtAddr> {
            kthread_layout
                .field_offset(field)
                .ok()
                .and_then(|offset| memory.read::<VirtAddr>(kthread + offset).ok())
                .filter(|addr| !addr.is_zero())
        };
        let read_kthread_u8 = |field: &str| -> Option<u8> {
            kthread_layout
                .field_offset(field)
                .ok()
                .and_then(|offset| memory.read::<u8>(kthread + offset).ok())
        };

        // KTHREAD.Process (KPROCESS* == EPROCESS base) first; ThreadsProcess
        // (older builds) and ProcessFastRef (EX_FAST_REF, refcount in low 4
        // bits) are build-specific fallbacks.
        let eprocess = read_kthread_ptr("Process")
            .or_else(|| read_ethread_ptr("ThreadsProcess"))
            .or_else(|| {
                ethread_layout
                    .field_offset("ProcessFastRef")
                    .ok()
                    .and_then(|offset| memory.read::<u64>(ethread + offset).ok())
                    .map(|raw| VirtAddr(raw & !0xf))
                    .filter(|addr| !addr.is_zero())
            });

        // Only a thread with neither a hint nor a readable process pointer
        // pays for a process-list walk.
        let owner: Option<ProcessInfo> = match (process_hint, eprocess) {
            (Some(_), _) | (None, Some(_)) => None,
            (None, None) => guest.enumerate_processes().ok().and_then(|processes| {
                processes
                    .into_iter()
                    .find(|process| pid.is_some_and(|pid| process.pid == pid))
            }),
        };
        let owner = process_hint.or(owner.as_ref());

        let process_name = owner
            .map(|process| process.name.clone())
            .or_else(|| eprocess.and_then(|eprocess| guest.process_name_at(eprocess)))
            // PID 0 is the System Idle Process, which isn't on PsActiveProcessHead
            // and so never matches above; label its per-CPU idle threads like WinDbg
            .or_else(|| (pid == Some(0)).then(|| "Idle".to_string()));

        Ok(ThreadInfo {
            ethread,
            kthread,
            tid,
            pid: pid.or_else(|| owner.map(|process| process.pid)),
            process_name,
            eprocess: eprocess.or_else(|| owner.map(|process| process.eprocess_va)),
            state: read_kthread_u8("State"),
            wait_reason: read_kthread_u8("WaitReason"),
            priority: read_kthread_u8("Priority"),
            base_priority: read_kthread_u8("BasePriority"),
            wait_irql: read_kthread_u8("WaitIrql"),
            // A one-bit field inside `MiscFlags`: the whole byte is never zero.
            kernel_stack_resident: self
                .extract_layout_bits(&kthread_layout, kthread, "KernelStackResident")
                .ok()
                .map(|value| value != 0),
            start_address: read_ethread_ptr("StartAddress"),
            win32_start_address: read_ethread_ptr("Win32StartAddress"),
            teb: read_kthread_ptr("Teb").or_else(|| read_ethread_ptr("Teb")),
            kernel_stack: read_kthread_ptr("KernelStack"),
            stack_base: read_kthread_ptr("StackBase"),
            stack_limit: read_kthread_ptr("StackLimit"),
            trap_frame: read_kthread_ptr("TrapFrame"),
            pending_irps: self.thread_pending_irps(&memory, &ethread_layout, ethread),
        })
    }

    fn thread_pending_irps(
        &self,
        memory: &impl MemoryOps<VirtAddr>,
        ethread_layout: &TypeInfo,
        ethread: VirtAddr,
    ) -> Option<Vec<VirtAddr>> {
        let irp_list_offset = ethread_layout.field_offset("IrpList").ok()?;
        let irp_layout = self.guest.as_ref()?.ntoskrnl.types().layout("_IRP").ok()?;
        let thread_list_entry_offset = irp_layout.field_offset("ThreadListEntry").ok()?;
        let head = ethread + irp_list_offset;
        let mut current: VirtAddr = memory.read(head).ok()?;
        let mut irps = Vec::new();
        let mut visited = HashSet::new();

        for _ in 0..256 {
            if current.is_zero() || current == head || !visited.insert(current.0) {
                break;
            }
            irps.push(current - thread_list_entry_offset);
            current = match memory.read(current) {
                Ok(next) => next,
                Err(_) => break,
            };
        }

        Some(irps)
    }

    pub fn current_windows_thread_for_processor(&self, processor: u16) -> Result<ThreadInfo> {
        let prcb = kprcb_for_processor(self, processor)?;
        let guest = self.guest()?;
        let memory = guest.ntoskrnl.memory();
        let prcb_current_thread_offset = guest
            .ntoskrnl
            .types()
            .layout("_KPRCB")?
            .field_offset("CurrentThread")?;
        let ethread_tcb_offset = guest
            .ntoskrnl
            .types()
            .layout("_ETHREAD")?
            .field_offset("Tcb")
            .unwrap_or(0);
        let kthread: VirtAddr = memory.read(prcb + prcb_current_thread_offset)?;
        if kthread.is_zero() {
            return Err(Error::DebugInfo(format!(
                "KPRCB.CurrentThread for processor {} is null",
                processor
            )));
        }

        self.thread_info_from_ethread(kthread - ethread_tcb_offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::session_over_memory;

    #[test]
    fn idle_detection_uses_pid_zero_or_idle_name() {
        let mut summary = ThreadSummary {
            ethread: VirtAddr(1),
            kthread: VirtAddr(2),
            tid: optional(Some(3)),
            pid: optional(Some(42)),
            process_name: optional(Some("Idle".to_string())),
            state: optional(None),
            wait_reason: optional(None),
            priority: optional(None),
        };
        assert!(thread_is_idle(&summary));
        summary.process_name = optional(Some("System".to_string()));
        summary.pid = optional(Some(0));
        assert!(thread_is_idle(&summary));
        summary.pid = optional(Some(4));
        assert!(!thread_is_idle(&summary));
    }

    #[test]
    fn current_windows_thread_rejects_out_of_range_processor() {
        let session = session_over_memory(0x1000, &[0u8; 0x80]);
        let error = session
            .target
            .current_windows_thread_for_processor(MAX_PROCESSORS)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains(&format!("processor index {MAX_PROCESSORS}"))
        );
    }

    fn selector_test_thread(ethread: u64, tid: u64, pid: u64) -> ThreadInfo {
        ThreadInfo {
            ethread: VirtAddr(ethread),
            kthread: VirtAddr(ethread + 0x100),
            tid: Some(tid),
            pid: Some(pid),
            process_name: None,
            eprocess: Some(VirtAddr(pid + 0x1000)),
            state: None,
            wait_reason: None,
            priority: None,
            base_priority: None,
            wait_irql: None,
            kernel_stack_resident: None,
            start_address: None,
            win32_start_address: None,
            teb: None,
            kernel_stack: None,
            stack_base: None,
            stack_limit: None,
            trap_frame: None,
            pending_irps: None,
        }
    }

    #[test]
    fn numeric_apc_selection_prefers_a_thread_over_a_process() {
        let thread = selector_test_thread(1, 7, 50);
        let process = selector_test_thread(2, 8, 7);
        let ethreads = |selected: Vec<ThreadInfo>| {
            selected
                .iter()
                .map(|thread| thread.ethread)
                .collect::<Vec<_>>()
        };

        let (selector, selected) = select_threads(
            ApcSelector::Number(7),
            vec![thread.clone(), process.clone()],
        );
        assert_eq!(selector, ApcSelector::Thread(VirtAddr(7)));
        assert_eq!(ethreads(selected), [VirtAddr(1)]);

        let (selector, selected) = select_threads(ApcSelector::Number(50), vec![thread, process]);
        assert_eq!(selector, ApcSelector::Process(50));
        assert_eq!(ethreads(selected), [VirtAddr(1)]);
    }
}
