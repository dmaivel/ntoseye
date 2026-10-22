//! Executive worker queues (`!exqueue`). Windows 10 and later keep one
//! `_EX_WORK_QUEUE` per partition, NUMA node, and queue index: an
//! `_EPARTITION`'s `ExPartition` is an `_EX_PARTITION` whose `WorkQueues`
//! is an array (one per node, `KeNumberNodes` long) of arrays (one per
//! `_EXQUEUEINDEX`, `ExPoolMax` long) of queue pointers. Each queue is a
//! `_KPRIQUEUE`: 32 priority lists of `_WORK_QUEUE_ITEM`s, the threads
//! serving it linked through `_KTHREAD.QueueListEntry`.

use crate::base::error::{Error, Result};
use crate::base::memory::MemoryOps;
use crate::base::types::VirtAddr;
use crate::nt::layout::Types;
use crate::nt::target::sched::walk_list_records;
use crate::nt::target::{DiagnosticValue, ListTermination, Target, ThreadInfo};
use crate::nt::unwind::StackFrame;
use ntoseye_macros::record;

/// `WORK_QUEUE_TYPE` names from wdm.h, in value order; `nt!ExpBuiltinPriorities`
/// holds the queue priority of each.
pub const WORK_QUEUE_TYPES: [&str; 7] = [
    "CriticalWorkQueue",
    "DelayedWorkQueue",
    "HyperCriticalWorkQueue",
    "NormalWorkQueue",
    "BackgroundWorkQueue",
    "RealTimeWorkQueue",
    "SuperCriticalWorkQueue",
];
const PRIORITY_COUNT: usize = 32;
const MAX_PARTITIONS: usize = 64;
const MAX_NODES: u64 = 64;
const MAX_QUEUE_INDEXES: u64 = 64;
const MAX_ITEMS_PER_PRIORITY: usize = 1024;
const MAX_THREADS_PER_QUEUE: usize = 4096;

/// An `_IO_WORKITEM` that `IoQueueWorkItem` queued. Its work item runs
/// `nt!IopProcessWorkItem`, which calls `routine`.
#[record]
pub struct IoWorkItem {
    /// The `_IO_WORKITEM` that holds the queued `_WORK_QUEUE_ITEM`.
    pub address: VirtAddr,
    pub routine: VirtAddr,
    /// `routine` as a symbol, when one resolves.
    pub routine_symbol: Option<String>,
    /// The device or driver object that the item was allocated for.
    pub io_object: VirtAddr,
    pub context: VirtAddr,
}

/// A pending `_WORK_QUEUE_ITEM`.
#[record]
pub struct WorkItem {
    pub address: VirtAddr,
    /// `WorkerRoutine`.
    pub routine: VirtAddr,
    /// `routine` as a symbol, when one resolves.
    pub routine_symbol: Option<String>,
    pub parameter: VirtAddr,
    /// The I/O work item that owns this item, if `IoQueueWorkItem` queued
    /// it.
    #[record(rename = "io_work_item")]
    pub io: Option<IoWorkItem>,
}

/// One of the 32 priority lists of a work queue.
#[record]
pub struct WorkQueuePriority {
    pub priority: u8,
    /// The `WORK_QUEUE_TYPE`s that `ExQueueWorkItem` maps to this priority.
    pub queue_types: Vec<&'static str>,
    /// `CurrentCount[priority]`, the number of threads that run an item of
    /// this priority.
    pub current_count: i32,
    /// The pending work items (key `items`).
    #[record(rename = "items")]
    pub work_items: Vec<WorkItem>,
    /// How the list walk ended.
    pub termination: ListTermination,
}

/// A thread that serves a work queue.
#[record]
pub struct WorkerThread {
    pub kthread: VirtAddr,
    pub thread: DiagnosticValue<ThreadInfo>,
    /// The stack of the thread; `None` if stacks were not requested or the
    /// thread did not decode.
    pub stack: Option<DiagnosticValue<Vec<StackFrame>>>,
}

/// An `_EX_WORK_QUEUE`.
#[record]
pub struct WorkQueue {
    pub address: VirtAddr,
    /// The `_EPARTITION` it belongs to.
    pub partition: VirtAddr,
    /// The NUMA node.
    pub node: u16,
    pub queue_index: u32,
    /// The name of `queue_index`, if it is a known index.
    pub queue_index_name: Option<String>,
    pub items_processed: u32,
    pub items_processed_last_pass: u32,
    pub thread_count: i32,
    pub min_threads: u64,
    pub max_threads: i32,
    /// `_KPRIQUEUE.MaximumCount`, the maximum number of threads that can run
    /// items at the same time.
    pub concurrency: u32,
    /// The number of items on all 32 priority lists, including items that
    /// are not listed.
    pub pending: u64,
    /// The priority lists that hold items or have running threads, limited
    /// to the requested priorities.
    pub priorities: Vec<WorkQueuePriority>,
    pub threads: Vec<WorkerThread>,
    /// How the worker-thread list walk ended.
    pub threads_termination: ListTermination,
}

/// All executive worker queues (`!exqueue`).
#[record]
pub struct WorkQueues {
    /// The `!exqueue` flags.
    #[record(hex)]
    pub flags: u64,
    /// The priorities that flags 0x10, 0x20, and 0x40 selected. `None` means
    /// all priorities.
    pub priority_filter: Option<Vec<u8>>,
    pub queues: Vec<WorkQueue>,
    /// The partitions or queues that ntoseye could not decode.
    pub errors: Vec<String>,
}

/// The `WORK_QUEUE_TYPE`s whose priorities `!exqueue` lists, as its flags
/// (0x10 critical, 0x20 delayed, 0x40 hypercritical).
#[derive(Debug, Clone, Copy)]
pub struct WorkQueueTypes(pub u64);

impl Target {
    /// The priority each `WORK_QUEUE_TYPE` maps to, read from
    /// `nt!ExpBuiltinPriorities`; empty when the symbol is absent.
    fn builtin_work_queue_priorities(&self) -> Vec<(&'static str, u8)> {
        let Ok(guest) = self.guest() else {
            return Vec::new();
        };
        let Ok(table) = guest.ntoskrnl.symbol("ExpBuiltinPriorities") else {
            return Vec::new();
        };
        let mut raw = [0u8; WORK_QUEUE_TYPES.len() * 4];
        if guest
            .ntoskrnl
            .memory()
            .read_bytes(table.address(), &mut raw)
            .is_err()
        {
            return Vec::new();
        }
        WORK_QUEUE_TYPES
            .iter()
            .zip(raw.as_chunks::<4>().0)
            .map(|(name, bytes)| (*name, u32::from_le_bytes(*bytes) as u8))
            .collect()
    }

    /// The `_EPARTITION`s on `PspActivePartitionListHead`, or the system
    /// partition alone when the list is absent.
    fn executive_partitions(&self) -> Result<Vec<VirtAddr>> {
        let ntos = &self.guest()?.ntoskrnl;
        let links = ntos
            .types()
            .layout("_EPARTITION")?
            .field_offset("ActivePartitionLinks");
        if let (Ok(head), Ok(links)) = (ntos.symbol("PspActivePartitionListHead"), links) {
            let (partitions, _) = walk_list_records(self, head.address(), links, MAX_PARTITIONS);
            if !partitions.is_empty() {
                return Ok(partitions);
            }
        }
        Ok(vec![ntos.symbol("PspSystemPartition")?.read_pointer()?])
    }

    /// Decode every executive worker queue: counters, the pending work items
    /// (routine symbolized; an `_IO_WORKITEM` also by its I/O routine), and
    /// the threads serving it. Flags 0x10, 0x20, and 0x40 restrict the
    /// listed items to the critical, delayed, and hypercritical priorities.
    pub fn executive_work_queues(&self, flags: u64) -> Result<WorkQueues> {
        let guest = self.guest()?;
        let ntos = &guest.ntoskrnl;
        let types = ntos.types();
        let memory = ntos.memory();
        let pointer_size = memory.arch().pointer_size();
        let unsupported = |why: String| {
            Error::DebugInfo(format!(
                "no partitioned executive work queues on this build ({why}); !exqueue reads the \
                 _EX_PARTITION queues of Windows 10 and later"
            ))
        };
        types
            .layout("_EX_WORK_QUEUE")
            .map_err(|error| unsupported(error.to_string()))?;
        types
            .layout("_EX_PARTITION")
            .map_err(|error| unsupported(error.to_string()))?;
        let entry_size = types.layout("_LIST_ENTRY")?.size as u64;
        let priqueue = types.layout("_KPRIQUEUE")?;
        let entry_lists = priqueue.field_offset("EntryListHead")?;
        let thread_list = priqueue.field_offset("ThreadListHead")?;
        let item_link = types.layout("_WORK_QUEUE_ITEM")?.field_offset("List")?;
        let io_item = types.layout("_IO_WORKITEM")?.field_offset("WorkItem")?;
        let queue_link = types.layout("_KTHREAD")?.field_offset("QueueListEntry")?;
        let tcb = types.layout("_ETHREAD")?.field_offset("Tcb")?;
        let node_count = u64::from(ntos.symbol("KeNumberNodes")?.read::<u16>()?).min(MAX_NODES);
        let index_names = self
            .symbols
            .find_enum_across_modules(ntos.dtb(), "_EXQUEUEINDEX")
            .unwrap_or_default();
        let index_count = index_names
            .iter()
            .find(|(name, _)| name == "ExPoolMax")
            .map(|(_, value)| *value as u64)
            .ok_or_else(|| unsupported("_EXQUEUEINDEX has no ExPoolMax".to_string()))?
            .min(MAX_QUEUE_INDEXES);
        let io_work_item = ntos
            .symbol("IopProcessWorkItem")
            .ok()
            .map(|symbol| symbol.address());
        let builtin = self.builtin_work_queue_priorities();
        let priority_filter = {
            let selected: Vec<u8> = [(0x10, 0), (0x20, 1), (0x40, 2)]
                .iter()
                .filter(|(bit, _)| flags & bit != 0)
                .filter_map(|(_, index)| builtin.get(*index).map(|(_, priority)| *priority))
                .collect();
            (flags & 0x70 != 0).then_some(selected)
        };
        if flags & 0x70 != 0 && builtin.is_empty() {
            return Err(Error::DebugInfo(
                "flags 0x10/0x20/0x40 name queue types by priority, but nt!ExpBuiltinPriorities \
                 is unreadable"
                    .into(),
            ));
        }
        let symbol = |address: VirtAddr| self.format_code_address(ntos.dtb(), address);

        let mut detail = WorkQueues {
            flags,
            priority_filter: priority_filter.clone(),
            queues: Vec::new(),
            errors: Vec::new(),
        };
        for partition in self.executive_partitions()? {
            let ex_partition = match types
                .struct_at("_EPARTITION", partition)
                .and_then(|epartition| epartition.read_pointer("ExPartition"))
            {
                Ok(address) if !address.is_zero() => address,
                Ok(_) => continue,
                Err(error) => {
                    detail
                        .errors
                        .push(format!("partition {:#x}: {error}", partition.0));
                    continue;
                }
            };
            let work_queues: VirtAddr = match types
                .struct_at("_EX_PARTITION", ex_partition)
                .and_then(|ex| ex.read_pointer("WorkQueues"))
            {
                Ok(address) => address,
                Err(error) => {
                    detail
                        .errors
                        .push(format!("_EX_PARTITION {:#x}: {error}", ex_partition.0));
                    continue;
                }
            };
            for node in 0..node_count {
                let Ok(per_node) = memory.read_pointer(work_queues + node * pointer_size) else {
                    detail.errors.push(format!(
                        "_EX_PARTITION {:#x}: node {node}'s queue array is unreadable",
                        ex_partition.0
                    ));
                    continue;
                };
                if per_node.is_zero() {
                    continue;
                }
                for index in 0..index_count {
                    let Ok(queue) = memory.read_pointer(per_node + index * pointer_size) else {
                        continue;
                    };
                    // ExpTryQueueWorkItem takes a slot with bit 0 set as no queue.
                    if queue.is_zero() || queue.0 & 1 != 0 {
                        continue;
                    }
                    let work_queue = types.struct_at("_EX_WORK_QUEUE", queue)?.prefetch();
                    match work_queue.read_pointer("Partition") {
                        Ok(owner) if owner == ex_partition => {}
                        Ok(owner) => {
                            detail.errors.push(format!(
                                "{:#x} (node {node}, index {index}) is not a work queue of \
                                 _EX_PARTITION {:#x}: its Partition is {:#x}",
                                queue.0, ex_partition.0, owner.0
                            ));
                            continue;
                        }
                        Err(error) => {
                            detail.errors.push(format!("queue {:#x}: {error}", queue.0));
                            continue;
                        }
                    }
                    let pri = work_queue.embedded("WorkPriQueue")?;
                    let mut counts = [0i32; PRIORITY_COUNT];
                    if let Ok(bytes) = pri.read_field_bytes("CurrentCount", PRIORITY_COUNT * 4) {
                        for (slot, chunk) in counts.iter_mut().zip(bytes.as_chunks::<4>().0) {
                            *slot = i32::from_le_bytes(*chunk);
                        }
                    }
                    let mut pending = 0u64;
                    let mut priorities = Vec::new();
                    for (priority, &current_count) in counts.iter().enumerate() {
                        let head = pri.addr() + entry_lists + priority as u64 * entry_size;
                        let (work_items, termination) =
                            walk_list_records(self, head, item_link, MAX_ITEMS_PER_PRIORITY);
                        pending += work_items.len() as u64;
                        let shown = priority_filter
                            .as_ref()
                            .is_none_or(|selected| selected.contains(&(priority as u8)));
                        if !shown || (work_items.is_empty() && current_count == 0) {
                            continue;
                        }
                        let shown_items = work_items
                            .into_iter()
                            .map(|item| work_item(types, item, io_item, io_work_item, &symbol))
                            .collect();
                        priorities.push(WorkQueuePriority {
                            priority: priority as u8,
                            queue_types: builtin
                                .iter()
                                .filter(|(_, p)| usize::from(*p) == priority)
                                .map(|(name, _)| *name)
                                .collect(),
                            current_count,
                            work_items: shown_items,
                            termination,
                        });
                    }
                    let (kthreads, threads_termination) = walk_list_records(
                        self,
                        pri.addr() + thread_list,
                        queue_link,
                        MAX_THREADS_PER_QUEUE,
                    );
                    let threads = kthreads
                        .into_iter()
                        .map(|kthread| WorkerThread {
                            kthread,
                            thread: DiagnosticValue::from_result(
                                self.thread_info_from_ethread(kthread - tcb),
                            ),
                            stack: None,
                        })
                        .collect();
                    let queue_index: u32 = work_queue.read_field("QueueIndex")?;
                    detail.queues.push(WorkQueue {
                        address: queue,
                        partition,
                        node: node as u16,
                        queue_index,
                        queue_index_name: index_names
                            .iter()
                            .find(|(_, value)| *value == i64::from(queue_index))
                            .map(|(name, _)| name.clone()),
                        items_processed: work_queue.read_field("WorkItemsProcessed")?,
                        items_processed_last_pass: work_queue
                            .read_field("WorkItemsProcessedLastPass")?,
                        thread_count: work_queue.read_field("ThreadCount")?,
                        min_threads: work_queue.read_bits("MinThreads")?,
                        max_threads: work_queue.read_field("MaxThreads")?,
                        concurrency: pri.read_field("MaximumCount")?,
                        pending,
                        priorities,
                        threads,
                        threads_termination,
                    });
                }
            }
        }
        if detail.queues.is_empty() && !detail.errors.is_empty() {
            return Err(Error::DebugInfo(detail.errors.join("; ")));
        }
        Ok(detail)
    }
}

/// The `_WORK_QUEUE_ITEM` at `address`; an `_IO_WORKITEM` (its `WorkItem`
/// at `io_item`) when the routine is `nt!IopProcessWorkItem`.
fn work_item(
    types: Types<'_>,
    address: VirtAddr,
    io_item: u64,
    io_work_item: Option<VirtAddr>,
    symbol: &impl Fn(VirtAddr) -> Option<String>,
) -> WorkItem {
    let item = types.struct_at("_WORK_QUEUE_ITEM", address).ok();
    let read = |name: &str| {
        item.as_ref()
            .and_then(|item| item.read_pointer(name).ok())
            .unwrap_or(VirtAddr(0))
    };
    let routine = read("WorkerRoutine");
    let io = (io_work_item == Some(routine))
        .then(|| types.struct_at("_IO_WORKITEM", address - io_item).ok())
        .flatten()
        .and_then(|io| {
            let routine = io.read_pointer("Routine").ok()?;
            Some(IoWorkItem {
                address: io.addr(),
                routine,
                routine_symbol: symbol(routine),
                io_object: io.read_pointer("IoObject").ok()?,
                context: io.read_pointer("Context").ok()?,
            })
        });
    WorkItem {
        address,
        routine,
        routine_symbol: symbol(routine),
        parameter: read("Parameter"),
        io,
    }
}
