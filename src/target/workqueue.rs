//! Executive worker queues (`!exqueue`). Windows 10 and later keep one
//! `_EX_WORK_QUEUE` per partition, NUMA node, and queue index: an
//! `_EPARTITION`'s `ExPartition` is an `_EX_PARTITION` whose `WorkQueues`
//! is an array (one per node, `KeNumberNodes` long) of arrays (one per
//! `_EXQUEUEINDEX`, `ExPoolMax` long) of queue pointers. Each queue is a
//! `_KPRIQUEUE`: 32 priority lists of `_WORK_QUEUE_ITEM`s, the threads
//! serving it linked through `_KTHREAD.QueueListEntry`.

use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::layout::Types;
use crate::target::sched::walk_list_nodes;
use crate::target::{DiagnosticValue, ListTermination, Target, ThreadInfo};
use crate::types::VirtAddr;
use crate::unwind::StackFrame;

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

/// An `_IO_WORKITEM` queued through `IoQueueWorkItem`: its `WorkItem`'s
/// routine is `nt!IopProcessWorkItem`, which calls `Routine`.
#[derive(Debug, Clone)]
pub struct IoWorkItemDetail {
    /// The `_IO_WORKITEM` holding the queued `_WORK_QUEUE_ITEM`.
    pub address: VirtAddr,
    pub routine: VirtAddr,
    pub routine_symbol: Option<String>,
    pub io_object: VirtAddr,
    pub context: VirtAddr,
}

/// One pending `_WORK_QUEUE_ITEM`.
#[derive(Debug, Clone)]
pub struct WorkItemDetail {
    pub address: VirtAddr,
    pub routine: VirtAddr,
    pub routine_symbol: Option<String>,
    pub parameter: VirtAddr,
    pub io: Option<IoWorkItemDetail>,
}

/// One of a queue's 32 priority lists.
#[derive(Debug, Clone)]
pub struct WorkQueuePriority {
    pub priority: u8,
    /// The `WORK_QUEUE_TYPE`s `ExQueueWorkItem` maps to this priority.
    pub queue_types: Vec<&'static str>,
    /// `CurrentCount[priority]`: threads running an item of this priority.
    pub current_count: i32,
    pub items: Vec<WorkItemDetail>,
    pub termination: ListTermination,
}

/// A thread serving a queue.
#[derive(Debug, Clone)]
pub struct WorkerThread {
    pub kthread: VirtAddr,
    pub thread: DiagnosticValue<ThreadInfo>,
    /// Filled when stacks were requested for a thread that decoded.
    pub stack: Option<DiagnosticValue<Vec<StackFrame>>>,
}

/// One `_EX_WORK_QUEUE`.
#[derive(Debug, Clone)]
pub struct WorkQueueDetail {
    pub address: VirtAddr,
    /// The `_EPARTITION` it belongs to.
    pub partition: VirtAddr,
    pub node: u16,
    pub queue_index: u32,
    pub queue_index_name: Option<String>,
    pub items_processed: u32,
    pub items_processed_last_pass: u32,
    pub thread_count: i32,
    pub min_threads: u64,
    pub max_threads: i32,
    /// `_KPRIQUEUE.MaximumCount`: how many threads may run items at once.
    pub concurrency: u32,
    /// Items on all 32 lists, shown or not.
    pub pending: u64,
    /// The lists holding items or running threads, restricted to the
    /// requested priorities.
    pub priorities: Vec<WorkQueuePriority>,
    pub threads: Vec<WorkerThread>,
    pub threads_termination: ListTermination,
}

/// Every executive worker queue (`!exqueue`).
#[derive(Debug, Clone)]
pub struct ExQueueDetail {
    pub flags: u64,
    /// The priorities flags 0x10/0x20/0x40 selected; `None` shows all.
    pub priority_filter: Option<Vec<u8>>,
    pub queues: Vec<WorkQueueDetail>,
    /// Partitions or queues that could not be decoded.
    pub errors: Vec<String>,
}

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
            let (nodes, _) = walk_list_nodes(self, head.address(), MAX_PARTITIONS);
            if !nodes.is_empty() {
                return Ok(nodes.into_iter().map(|node| node - links).collect());
            }
        }
        Ok(vec![ntos.symbol("PspSystemPartition")?.read()?])
    }

    /// Decode every executive worker queue: counters, the pending work items
    /// (routine symbolized; an `_IO_WORKITEM` also by its I/O routine), and
    /// the threads serving it. Flags 0x10, 0x20, and 0x40 restrict the
    /// listed items to the critical, delayed, and hypercritical priorities.
    pub fn executive_work_queues(&self, flags: u64) -> Result<ExQueueDetail> {
        let guest = self.guest()?;
        let ntos = &guest.ntoskrnl;
        let types = ntos.types();
        let memory = ntos.memory();
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
        let symbol = |address: VirtAddr| {
            self.symbols
                .format_closest_symbol_for_address(ntos.dtb(), address)
        };

        let mut detail = ExQueueDetail {
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
                let Ok(per_node) = memory.read::<VirtAddr>(work_queues + node * 8) else {
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
                    let Ok(queue) = memory.read::<VirtAddr>(per_node + index * 8) else {
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
                        let (nodes, termination) =
                            walk_list_nodes(self, head, MAX_ITEMS_PER_PRIORITY);
                        pending += nodes.len() as u64;
                        let shown = priority_filter
                            .as_ref()
                            .is_none_or(|selected| selected.contains(&(priority as u8)));
                        if !shown || (nodes.is_empty() && current_count == 0) {
                            continue;
                        }
                        let items = nodes
                            .into_iter()
                            .map(|link| {
                                work_item(types, link - item_link, io_item, io_work_item, &symbol)
                            })
                            .collect();
                        priorities.push(WorkQueuePriority {
                            priority: priority as u8,
                            queue_types: builtin
                                .iter()
                                .filter(|(_, p)| usize::from(*p) == priority)
                                .map(|(name, _)| *name)
                                .collect(),
                            current_count,
                            items,
                            termination,
                        });
                    }
                    let (links, threads_termination) =
                        walk_list_nodes(self, pri.addr() + thread_list, MAX_THREADS_PER_QUEUE);
                    let threads = links
                        .into_iter()
                        .map(|link| {
                            let kthread = link - queue_link;
                            WorkerThread {
                                kthread,
                                thread: DiagnosticValue::from_result(
                                    self.thread_info_from_ethread(kthread - tcb),
                                ),
                                stack: None,
                            }
                        })
                        .collect();
                    let queue_index: u32 = work_queue.read_field("QueueIndex")?;
                    detail.queues.push(WorkQueueDetail {
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
) -> WorkItemDetail {
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
            Some(IoWorkItemDetail {
                address: io.addr(),
                routine,
                routine_symbol: symbol(routine),
                io_object: io.read_pointer("IoObject").ok()?,
                context: io.read_pointer("Context").ok()?,
            })
        });
    WorkItemDetail {
        address,
        routine,
        routine_symbol: symbol(routine),
        parameter: read("Parameter"),
        io,
    }
}
