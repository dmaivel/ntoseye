//! Hang diagnosis from the processor blocks: the numbered queued spinlocks
//! (`!qlocks`) and each processor's interprocessor-interrupt state (`!ipi`).

use std::collections::HashMap;
use std::sync::Arc;

use crate::backend::MemoryOps;
use crate::cpu_state::{MAX_PROCESSORS, kprcb_for_processor, processor_count};
use crate::error::{Error, Result};
use crate::layout::{ParsedType, TypeInfo, le_uint};
use crate::target::{DiagnosticValue, Target};
use crate::types::VirtAddr;

/// `_KSPIN_LOCK_QUEUE.Lock` low bits: the processor waits for the lock, or
/// owns it (`LOCK_QUEUE_WAIT`, `LOCK_QUEUE_OWNER`).
const LOCK_QUEUE_WAIT: u64 = 1;
const LOCK_QUEUE_OWNER: u64 = 2;
/// More numbered queued locks than any build declares (17 on Windows 11).
const MAX_QUEUED_LOCKS: usize = 64;
/// `KSPIN_LOCK_QUEUE_NUMBER` as the WDK's wdm.h declares it for 17 locks
/// (Windows 8 and later), for public PDBs that omit the enum.
const WDK_QUEUED_LOCKS: [&str; 17] = [
    "LockQueueUnusedSpare0",
    "LockQueueUnusedSpare1",
    "LockQueueUnusedSpare2",
    "LockQueueUnusedSpare3",
    "LockQueueVacbLock",
    "LockQueueMasterLock",
    "LockQueueNonPagedPoolLock",
    "LockQueueIoCancelLock",
    "LockQueueUnusedSpare8",
    "LockQueueIoVpbLock",
    "LockQueueIoDatabaseLock",
    "LockQueueIoCompletionLock",
    "LockQueueNtfsStructLock",
    "LockQueueAfdWorkQueueLock",
    "LockQueueBcbLock",
    "LockQueueUnusedSpare15",
    "LockQueueUnusedSpare16",
];

/// One processor's position in one queued lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueuedLockState {
    Owner,
    /// 1-based place in the wait queue behind the owner.
    Waiting(u32),
    /// The entry's bits and the queue links disagree; the reason says how.
    Corrupt(String),
}

/// One processor's entry in a queued lock that it owns or waits for.
#[derive(Debug, Clone)]
pub struct QueuedLockHolder {
    pub processor: u16,
    pub state: QueuedLockState,
}

/// One numbered queued spinlock and the processors owning or waiting for it.
#[derive(Debug, Clone)]
pub struct QueuedLock {
    pub number: u32,
    /// The `_KSPIN_LOCK_QUEUE_NUMBER` name without its `LockQueue` prefix and
    /// `Lock` suffix (`IoCancel`), from the PDB or else the WDK's list when
    /// the array has its 17 entries; `LockQueue[n]` otherwise.
    pub name: String,
    /// The spinlock itself, from the first processor entry that names it.
    pub lock: Option<VirtAddr>,
    pub holders: Vec<QueuedLockHolder>,
}

#[derive(Debug, Clone)]
pub struct ProcessorError {
    pub processor: u16,
    pub message: String,
}

/// Every numbered queued spinlock across the processors (`!qlocks`).
#[derive(Debug, Clone)]
pub struct QueuedLocksDetail {
    /// Processors whose `_KPRCB.LockQueue` was read.
    pub processors: Vec<u16>,
    pub locks: Vec<QueuedLock>,
    pub errors: Vec<ProcessorError>,
}

/// One request a sender posted in a processor's IPI mailbox list.
#[derive(Debug, Clone)]
pub struct IpiRequest {
    /// The `_REQUEST_MAILBOX` (the sender's slot in the receiver's
    /// `RequestMailbox` array).
    pub mailbox: VirtAddr,
    /// The sending processor, from the slot's index; `None` when the mailbox
    /// lies outside the receiver's array.
    pub sender: Option<u16>,
    pub request_summary: DiagnosticValue<u64>,
    pub worker_routine: DiagnosticValue<VirtAddr>,
    pub worker_symbol: Option<String>,
    /// `RequestPacket.CurrentPacket`: the worker's three parameters.
    pub parameters: DiagnosticValue<Vec<u64>>,
}

/// A `_KPRCB` IPI field this build declares, with its value.
#[derive(Debug, Clone)]
pub struct IpiField {
    pub name: &'static str,
    pub value: DiagnosticValue<u64>,
}

/// One processor's IPI state (`!ipi`).
#[derive(Debug, Clone)]
pub struct IpiProcessor {
    pub processor: u16,
    pub kprcb: VirtAddr,
    /// The IPI fields of [`IPI_FIELDS`] this build's `_KPRCB` has.
    pub fields: Vec<IpiField>,
    /// Requests queued to this processor and not yet taken, in list order;
    /// unavailable on builds without per-sender mailboxes or when the list
    /// cannot be read.
    pub pending: DiagnosticValue<Vec<IpiRequest>>,
    /// Whether the pending walk stopped at its bound or a repeated mailbox.
    pub pending_truncated: bool,
    /// Processors whose pending list holds a request from this one.
    pub awaiting: Vec<u16>,
}

#[derive(Debug, Clone)]
pub struct IpiDetail {
    pub processors: Vec<IpiProcessor>,
    pub errors: Vec<ProcessorError>,
}

/// `_KPRCB` fields `!ipi` reports when the build has them: the freeze state,
/// the sender's outstanding-packet count and barrier, the self-IPI summary,
/// the trap frame of the IPI being serviced, and the older builds' fields.
pub const IPI_FIELDS: &[&str] = &[
    "IpiFrozen",
    "TargetCount",
    "PacketBarrier",
    "SelfIpiRequestSummary",
    "IpiFrame",
    "RequestSummary",
    "SignalDone",
    "TargetSet",
];

/// `_KPRCB.IpiFrozen`'s state (its low nibble), as `KeFreezeExecution`,
/// `KiSendFreeze`, `KiFreezeTargetExecution`, and `KiSendThawExecution` set it.
pub fn ipi_frozen_name(value: u64) -> &'static str {
    match value & 0xf {
        0 => "Running",
        2 => "Frozen",
        3 => "Thaw",
        4 => "Freeze owner",
        5 => "Freeze requested",
        _ => "Unknown",
    }
}

/// A mailbox request's type (the low nibble of `RequestSummary`), as
/// Windows 11's `KiIpiProcessRequests` dispatches it; `None` for a type it
/// ignores.
pub fn ipi_request_type_name(summary: u64) -> Option<&'static str> {
    Some(match summary & 0xf {
        1 => "flush current TB",
        2 => "flush TB range",
        3 => "flush entire TB",
        4 => "flush TB list",
        5 => "packet",
        6 => "flush cache",
        _ => return None,
    })
}

/// A `_KSPIN_LOCK_QUEUE_NUMBER` name as `!qlocks` shows it.
fn queued_lock_name(variant: &str) -> String {
    let name = variant.strip_prefix("LockQueue").unwrap_or(variant);
    let name = name
        .strip_suffix("Lock")
        .filter(|name| !name.is_empty())
        .unwrap_or(name);
    name.to_string()
}

/// Each processor's raw `(Next, Lock)` entry for one lock number.
struct LockEntry {
    processor: u16,
    address: u64,
    next: u64,
    lock: u64,
}

/// Owner and wait order of one lock from every processor's entry: follow
/// `Next` from the owner's entry, numbering the processors it reaches. An
/// entry that claims to wait but is not reached, a second owner, or a
/// processor reached twice is corrupt.
fn order_lock_queue(entries: &[LockEntry]) -> Vec<QueuedLockHolder> {
    let by_address: HashMap<u64, u16> = entries
        .iter()
        .map(|entry| (entry.address, entry.processor))
        .collect();
    let mut states: HashMap<u16, QueuedLockState> = HashMap::new();
    let owners: Vec<&LockEntry> = entries
        .iter()
        .filter(|entry| entry.lock & LOCK_QUEUE_OWNER != 0)
        .collect();
    for (index, owner) in owners.iter().enumerate() {
        if index > 0 {
            states.insert(
                owner.processor,
                QueuedLockState::Corrupt(format!(
                    "also claims ownership (processor {} owns it)",
                    owners[0].processor
                )),
            );
        }
    }
    if let Some(owner) = owners.first() {
        states.insert(owner.processor, QueuedLockState::Owner);
        let mut next = owner.next;
        let mut order = 0u32;
        // Every processor at most once: a cycle or a stray link ends it.
        for _ in 0..entries.len() {
            if next == 0 {
                break;
            }
            let Some(&processor) = by_address.get(&next) else {
                break;
            };
            if states.contains_key(&processor) {
                break;
            }
            order += 1;
            states.insert(processor, QueuedLockState::Waiting(order));
            next = entries
                .iter()
                .find(|entry| entry.processor == processor)
                .map_or(0, |entry| entry.next);
        }
    }
    for entry in entries {
        if entry.lock & LOCK_QUEUE_WAIT != 0 && !states.contains_key(&entry.processor) {
            let reason = if owners.is_empty() {
                "waits, but no processor owns the lock"
            } else {
                "waits, but is not queued behind the owner"
            };
            states.insert(entry.processor, QueuedLockState::Corrupt(reason.into()));
        }
    }
    let mut holders: Vec<QueuedLockHolder> = states
        .into_iter()
        .map(|(processor, state)| QueuedLockHolder { processor, state })
        .collect();
    holders.sort_by_key(|holder| holder.processor);
    holders
}

fn array_len(type_data: &ParsedType) -> Option<usize> {
    match type_data {
        ParsedType::Array(_, count) => usize::try_from(*count).ok(),
        _ => None,
    }
}

fn processors(target: &Target) -> Result<Vec<u16>> {
    let count = processor_count(target)?.clamp(1, MAX_PROCESSORS);
    Ok((0..count).collect())
}

impl Target {
    fn nt_layout(&self, name: &str) -> Result<Arc<TypeInfo>> {
        self.guest()?.ntoskrnl.types().layout(name)
    }

    /// Owner and waiters of every numbered queued spinlock, from each
    /// processor's `_KPRCB.LockQueue` entries. An unreadable processor block
    /// is reported and skipped.
    pub fn queued_locks(&self) -> Result<QueuedLocksDetail> {
        let guest = self.guest()?;
        let prcb = self.nt_layout("_KPRCB")?;
        let field = prcb.field("LockQueue")?;
        let entry_layout = self.nt_layout("_KSPIN_LOCK_QUEUE")?;
        let stride = entry_layout.size as u64;
        let next_offset = entry_layout.field_offset("Next")? as usize;
        let lock_offset = entry_layout.field_offset("Lock")? as usize;
        let pointer = usize::from(entry_layout.pointer_size);
        if stride == 0
            || next_offset + pointer > stride as usize
            || lock_offset + pointer > stride as usize
        {
            return Err(Error::DebugInfo(
                "_KSPIN_LOCK_QUEUE layout is inconsistent".into(),
            ));
        }
        let count = array_len(&field.type_data)
            .unwrap_or((field.size / stride) as usize)
            .min(MAX_QUEUED_LOCKS);
        let mut names: Vec<(String, i64)> = guest
            .ntoskrnl
            .guid
            .and_then(|guid| self.symbols.enum_variants(guid, "_KSPIN_LOCK_QUEUE_NUMBER"))
            .unwrap_or_default();
        if names.is_empty() && count == WDK_QUEUED_LOCKS.len() {
            names = WDK_QUEUED_LOCKS
                .iter()
                .zip(0..)
                .map(|(name, value)| (name.to_string(), value))
                .collect();
        }

        let memory = guest.ntoskrnl.memory();
        let mut per_lock: Vec<Vec<LockEntry>> = (0..count).map(|_| Vec::new()).collect();
        let mut detail = QueuedLocksDetail {
            processors: Vec::new(),
            locks: Vec::new(),
            errors: Vec::new(),
        };
        for processor in processors(self)? {
            let base = match kprcb_for_processor(self, processor) {
                Ok(kprcb) => kprcb + u64::from(field.offset),
                Err(error) => {
                    detail.errors.push(ProcessorError {
                        processor,
                        message: error.to_string(),
                    });
                    continue;
                }
            };
            let mut bytes = vec![0u8; count * stride as usize];
            if let Err(error) = memory.read_bytes(base, &mut bytes) {
                detail.errors.push(ProcessorError {
                    processor,
                    message: format!("LockQueue at {:#x}: {error}", base.0),
                });
                continue;
            }
            detail.processors.push(processor);
            for (number, entry) in bytes.chunks_exact(stride as usize).enumerate() {
                per_lock[number].push(LockEntry {
                    processor,
                    address: base.0 + number as u64 * stride,
                    next: le_uint(&entry[next_offset..next_offset + pointer]),
                    lock: le_uint(&entry[lock_offset..lock_offset + pointer]),
                });
            }
        }
        for (number, entries) in per_lock.iter().enumerate() {
            let name = names
                .iter()
                .find(|(_, value)| *value == number as i64)
                .map_or_else(
                    || format!("LockQueue[{number}]"),
                    |(name, _)| queued_lock_name(name),
                );
            detail.locks.push(QueuedLock {
                number: number as u32,
                name,
                lock: entries
                    .iter()
                    .map(|entry| entry.lock & !(LOCK_QUEUE_WAIT | LOCK_QUEUE_OWNER))
                    .find(|lock| *lock != 0)
                    .map(VirtAddr),
                holders: order_lock_queue(entries),
            });
        }
        Ok(detail)
    }

    /// IPI state of `processor`, or of every processor: the `_KPRCB` fields
    /// of [`IPI_FIELDS`] the build has, and the requests queued in the
    /// processor's mailbox list (`_KPRCB.Mailbox`, a list of the senders'
    /// slots in its `RequestMailbox` array) on builds that have one.
    pub fn ipi_state(&self, processor: Option<u16>) -> Result<IpiDetail> {
        let prcb = self.nt_layout("_KPRCB")?;
        let all = processors(self)?;
        let selected = match processor {
            Some(index) if !all.contains(&index) => {
                return Err(Error::InvalidArgument(format!(
                    "processor {index} does not exist; the target reports {}",
                    all.len()
                )));
            }
            Some(index) => vec![index],
            None => all.clone(),
        };
        let mailboxes = self.mailbox_layout(&prcb);
        let mut detail = IpiDetail {
            processors: Vec::new(),
            errors: Vec::new(),
        };
        // Senders are matched to receivers across every processor, so an
        // `!ipi 1` still names the processors 1 is waiting for.
        let mut pending_by_receiver: HashMap<u16, (DiagnosticValue<Vec<IpiRequest>>, bool)> =
            HashMap::new();
        let mut kprcbs = HashMap::new();
        for &index in &all {
            let kprcb = match kprcb_for_processor(self, index) {
                Ok(kprcb) => kprcb,
                Err(error) => {
                    if selected.contains(&index) {
                        detail.errors.push(ProcessorError {
                            processor: index,
                            message: error.to_string(),
                        });
                    }
                    continue;
                }
            };
            kprcbs.insert(index, kprcb);
            let pending = match &mailboxes {
                Ok(layout) => self.pending_ipi_requests(layout, kprcb, all.len()),
                Err(error) => (DiagnosticValue::Unavailable(error.clone()), false),
            };
            pending_by_receiver.insert(index, pending);
        }
        let types = self.guest()?.ntoskrnl.types();
        for index in selected {
            let Some(&kprcb) = kprcbs.get(&index) else {
                continue;
            };
            let cursor = types.struct_with_layout(Arc::clone(&prcb), kprcb);
            let fields = IPI_FIELDS
                .iter()
                .filter(|name| prcb.fields.contains_key(**name))
                .map(|name| IpiField {
                    name,
                    value: DiagnosticValue::from_result(cursor.read_uint(name)),
                })
                .collect();
            let mut awaiting: Vec<u16> = pending_by_receiver
                .iter()
                .filter(|(receiver, (pending, _))| {
                    **receiver != index
                        && matches!(pending, DiagnosticValue::Available(requests)
                            if requests.iter().any(|request| request.sender == Some(index)))
                })
                .map(|(receiver, _)| *receiver)
                .collect();
            awaiting.sort_unstable();
            let (pending, pending_truncated) = pending_by_receiver.remove(&index).unwrap_or((
                DiagnosticValue::Unavailable("processor block unreadable".into()),
                false,
            ));
            detail.processors.push(IpiProcessor {
                processor: index,
                kprcb,
                fields,
                pending,
                pending_truncated,
                awaiting,
            });
        }
        Ok(detail)
    }

    fn mailbox_layout(&self, prcb: &TypeInfo) -> std::result::Result<MailboxLayout, String> {
        let layout = || -> Result<MailboxLayout> {
            let mailbox = prcb.field_offset("Mailbox")?;
            let array = prcb.field_offset("RequestMailbox")?;
            let entry = self.nt_layout("_REQUEST_MAILBOX")?;
            Ok(MailboxLayout {
                mailbox,
                array,
                entry_size: entry.size as u64,
                entry,
            })
        };
        layout().map_err(|error| format!("no per-sender IPI mailboxes on this build ({error})"))
    }

    /// Walk the receiver `kprcb`'s mailbox list, at most `processors`
    /// entries (one per sender); a repeated mailbox ends it.
    fn pending_ipi_requests(
        &self,
        layout: &MailboxLayout,
        kprcb: VirtAddr,
        processors: usize,
    ) -> (DiagnosticValue<Vec<IpiRequest>>, bool) {
        let guest = match self.guest() {
            Ok(guest) => guest,
            Err(error) => return (DiagnosticValue::Unavailable(error.to_string()), false),
        };
        let types = guest.ntoskrnl.types();
        let mut next: VirtAddr = match guest.ntoskrnl.memory().read(kprcb + layout.mailbox) {
            Ok(head) => head,
            Err(error) => return (DiagnosticValue::Unavailable(error.to_string()), false),
        };
        let array = kprcb.0 + layout.array;
        let mut requests: Vec<IpiRequest> = Vec::new();
        let mut truncated = false;
        while !next.is_zero() {
            if requests.len() >= processors || requests.iter().any(|seen| seen.mailbox == next) {
                truncated = true;
                break;
            }
            let mailbox = types
                .struct_with_layout(Arc::clone(&layout.entry), next)
                .prefetch();
            let sender = next
                .0
                .checked_sub(array)
                .filter(|offset| layout.entry_size != 0 && offset % layout.entry_size == 0)
                .map(|offset| offset / layout.entry_size)
                .filter(|index| *index < processors as u64)
                .map(|index| index as u16);
            let packet = mailbox.embedded("RequestPacket").map(|packet| {
                let worker = packet.read_pointer("WorkerRoutine");
                let parameters = packet.read_field_bytes("CurrentPacket", 64).map(|bytes| {
                    bytes
                        .as_chunks::<8>()
                        .0
                        .iter()
                        .map(|word| u64::from_le_bytes(*word))
                        .collect::<Vec<_>>()
                });
                (worker, parameters)
            });
            let (worker_routine, parameters) = match packet {
                Ok((worker, parameters)) => (
                    DiagnosticValue::from_result(worker),
                    DiagnosticValue::from_result(parameters),
                ),
                Err(error) => (
                    DiagnosticValue::Unavailable(error.to_string()),
                    DiagnosticValue::Unavailable(error.to_string()),
                ),
            };
            let worker_symbol = match &worker_routine {
                DiagnosticValue::Available(address) if !address.is_zero() => {
                    self.closest_symbol_current_context(*address)
                }
                _ => None,
            };
            requests.push(IpiRequest {
                mailbox: next,
                sender,
                request_summary: DiagnosticValue::from_result(mailbox.read_uint("RequestSummary")),
                worker_routine,
                worker_symbol,
                parameters,
            });
            match mailbox.read_pointer("Next") {
                Ok(link) => next = link,
                Err(_) => {
                    truncated = true;
                    break;
                }
            }
        }
        (DiagnosticValue::Available(requests), truncated)
    }
}

struct MailboxLayout {
    /// `_KPRCB.Mailbox`: the head of the pending list.
    mailbox: u64,
    /// `_KPRCB.RequestMailbox`: one `_REQUEST_MAILBOX` per sender.
    array: u64,
    entry_size: u64,
    entry: Arc<TypeInfo>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(processor: u16, next: u64, lock: u64) -> LockEntry {
        LockEntry {
            processor,
            address: 0x1000 * (u64::from(processor) + 1),
            next,
            lock,
        }
    }

    fn states(holders: &[QueuedLockHolder]) -> Vec<(u16, QueuedLockState)> {
        holders
            .iter()
            .map(|holder| (holder.processor, holder.state.clone()))
            .collect()
    }

    #[test]
    fn wait_order_follows_next_links_from_the_owner() {
        // Processor 2 owns; 0 queued behind it, then 3; 1 is idle.
        let entries = [
            entry(0, 0x4000, 0x8000 | LOCK_QUEUE_WAIT),
            entry(1, 0, 0),
            entry(2, 0x1000, 0x8000 | LOCK_QUEUE_OWNER),
            entry(3, 0, 0x8000 | LOCK_QUEUE_WAIT),
        ];
        assert_eq!(
            states(&order_lock_queue(&entries)),
            vec![
                (0, QueuedLockState::Waiting(1)),
                (2, QueuedLockState::Owner),
                (3, QueuedLockState::Waiting(2)),
            ]
        );
    }

    #[test]
    fn unreached_waiters_and_link_cycles_are_corrupt() {
        // 0 owns and links to 1, which links back to 0; 2 waits unlinked.
        let entries = [
            entry(0, 0x2000, LOCK_QUEUE_OWNER),
            entry(1, 0x1000, LOCK_QUEUE_WAIT),
            entry(2, 0, LOCK_QUEUE_WAIT),
        ];
        let holders = states(&order_lock_queue(&entries));
        assert_eq!(holders[0], (0, QueuedLockState::Owner));
        assert_eq!(holders[1], (1, QueuedLockState::Waiting(1)));
        assert!(matches!(holders[2], (2, QueuedLockState::Corrupt(_))));

        let ownerless = [entry(0, 0, LOCK_QUEUE_WAIT)];
        assert!(matches!(
            states(&order_lock_queue(&ownerless))[0],
            (0, QueuedLockState::Corrupt(_))
        ));
    }

    #[test]
    fn lock_names_drop_the_enum_prefix_and_suffix() {
        assert_eq!(queued_lock_name("LockQueueIoCancelLock"), "IoCancel");
        assert_eq!(queued_lock_name("LockQueueUnusedSpare0"), "UnusedSpare0");
        assert_eq!(queued_lock_name("LockQueueMaximumLock"), "Maximum");
    }
}
