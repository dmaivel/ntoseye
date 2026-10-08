//! Virtio devices, their queues, and a queue's buffers (`!virtio`,
//! `!vring`) as SDK records.

use super::shape::{Hex, shapes};
use crate::target::Target;
use crate::target::virtio::{
    DescChain, MAX_LISTED_CHAINS, PackedChain, QueueProgress, QueueRole, Signal,
    VRING_DESC_F_INDIRECT, VRING_DESC_F_WRITE, VirtQueue, VirtioFunction, packed_verdict,
    queue_count, queue_role, queue_verdict, split_signals, virtio_type_name,
};
use crate::target::virtio_request::request_kind;
use crate::types::VirtAddr;

shapes! {
    /// A virtio PCI function (`!virtio`).
    VirtioDevice {
        /// `bb:dd.f`.
        location: String,
        /// The virtio device type: 1 net, 2 block, 3 console, 8 SCSI, ...
        virtio_id: u16,
        /// The specification's name of the type, such as `net` or `block`.
        kind: &'static str,
        device_id: Hex<u16>,
        /// Whether the device also offers the legacy interface.
        transitional: bool,
        /// The service that drives it.
        service: Option<String>,
        pdo: VirtAddr,
        /// What its virtio-win driver shows of it, with the driver's private
        /// PDB. None when `driver_missing` says why not.
        driver: Option<VirtioDriverState>,
        driver_missing: Option<String>,
    }

    /// A device as its virtio-win driver sees it.
    VirtioDriverState {
        /// The driver module whose PDB types its structures.
        module: String,
        /// The `virtio_device`.
        device: VirtAddr,
        packed: bool,
        /// Whether the device and driver negotiated the event index feature.
        event_idx: bool,
        msix: bool,
        queues: Vec<Virtqueue>,
    }

    /// One virtqueue and where its traffic stands.
    Virtqueue {
        index: u32,
        /// Its name where the virtio specification fixes it, such as `rx 0`
        /// or `request 2`.
        name: Option<String>,
        /// `device_fills` for a queue whose buffers wait until the device has
        /// something (receive, events), `requests` for one whose buffers
        /// carry requests.
        role: Option<&'static str>,
        /// The `virtqueue_split` or `virtqueue_packed`.
        address: VirtAddr,
        size: u32,
        packed: bool,
        /// The avail index the driver published (split), or the position it
        /// fills next (packed).
        avail: Option<u16>,
        /// The used index up to which the device returned buffers (split).
        used: Option<u16>,
        /// Where the driver takes buffers back next.
        taken_back: Option<u16>,
        /// The descriptors the driver has not given out.
        free: Option<u32>,
        /// Buffers the driver added but has not published (split).
        unpublished: Option<u16>,
        /// Buffers added since the driver last notified the device (split).
        unkicked: Option<u32>,
        /// Buffers the device holds.
        with_device: Option<u32>,
        /// Buffers the device returned that the driver has not taken back.
        returned: Option<u32>,
        /// What these mean together, as `!virtio` says it.
        state: String,
        /// When the driver wants interrupts.
        interrupts: Option<VirtioSignal>,
        /// When the device wants notifications.
        notifications: Option<VirtioSignal>,
        /// Whether an interrupt was due for the returned buffers (split).
        interrupt_due: bool,
        /// Counters that only grow, to compare two looks with.
        progress: Option<VirtioProgress>,
        /// The descriptor table.
        desc: Option<VirtAddr>,
        /// The avail ring (split) or the driver's event suppression structure
        /// (packed).
        driver_area: Option<VirtAddr>,
        /// The used ring (split) or the device's event suppression structure
        /// (packed).
        device_area: Option<VirtAddr>,
        /// Why the queue could not be read.
        error: Option<String>,
    }

    /// When one side of a queue wants to be signalled.
    VirtioSignal {
        /// `on` (after every buffer), `off`, `after` (the event index), or
        /// `at` (a packed ring position).
        kind: &'static str,
        /// The index for `after`, the position for `at`.
        value: Option<u16>,
        /// The lap for `at`.
        lap: Option<bool>,
    }

    /// A queue's counters at one look, which only grow modulo `modulus`;
    /// the difference between two looks is what moved.
    VirtioProgress {
        /// Buffers the driver handed the device.
        published: u32,
        /// Buffers the device returned (split rings).
        completed: Option<u32>,
        /// Buffers the driver took back.
        taken_back: u32,
        modulus: u32,
    }

    /// A virtqueue's ring and the buffers outstanding in it (`!vring`).
    VirtioRing {
        queue: Virtqueue,
        /// What its buffers hold, for decoding: `blk`, `scsi`, `net`, ...
        request_kind: Option<&'static str>,
        /// Buffers the device holds, at most 64.
        with_device: Vec<VirtioBuffer>,
        /// Buffers the device returned that the driver has not taken back
        /// (split rings), at most 64.
        returned: Vec<VirtioBuffer>,
        /// Why reading a packed ring stopped early.
        broken: Option<String>,
    }

    /// One buffer: its descriptors and the request it carries.
    VirtioBuffer {
        /// The avail entry (split, with the device), the used element
        /// (returned), or the ring position (packed).
        position: u16,
        /// The head descriptor's index (split) or the buffer ID (packed).
        head: u16,
        /// The bytes the device wrote, for a returned buffer.
        written: Option<u32>,
        descriptors: Vec<VirtioDescriptor>,
        /// The request and, once the device returned it, its answer, decoded
        /// from the virtio specification's layouts.
        request: Option<String>,
        /// Why walking the chain stopped early.
        broken: Option<String>,
    }

    /// One descriptor of a buffer.
    VirtioDescriptor {
        /// Its index in the table (split) or its ring position (packed).
        index: u16,
        /// The buffer's guest-physical address.
        address: Hex,
        length: u32,
        flags: Hex<u16>,
        device_writes: bool,
        /// For an indirect table: how many descriptors it holds and the
        /// bytes the driver gives the device and the device may write.
        indirect_descriptors: Option<u64>,
        out_bytes: Option<u64>,
        in_bytes: Option<u64>,
    }
}

fn signal(signal: Signal) -> VirtioSignal {
    let (kind, value, lap) = match signal {
        Signal::On => ("on", None, None),
        Signal::Off => ("off", None, None),
        Signal::After(index) => ("after", Some(index), None),
        Signal::At { position, lap } => ("at", Some(position), Some(lap)),
    };
    VirtioSignal { kind, value, lap }
}

fn role_name(role: QueueRole) -> &'static str {
    match role {
        QueueRole::DeviceFills => "device_fills",
        QueueRole::Requests => "requests",
    }
}

/// `queue` of a device of type `virtio_id` that set up `queues` queues.
pub fn virtqueue(queue: &VirtQueue, virtio_id: Option<u16>, queues: u32) -> Virtqueue {
    let name = virtio_id.and_then(|id| queue_role(id, queue.index, queues));
    let progress = QueueProgress::of(queue).map(|progress| VirtioProgress {
        published: progress.published,
        completed: progress.completed,
        taken_back: progress.taken_back,
        modulus: progress.modulus,
    });
    let mut view = Virtqueue {
        index: queue.index,
        name: name.as_ref().map(|(name, _)| name.clone()),
        role: name.map(|(_, role)| role_name(role)),
        address: queue.address,
        size: queue.size,
        packed: queue.packed.is_some(),
        avail: None,
        used: None,
        taken_back: None,
        free: None,
        unpublished: None,
        unkicked: None,
        with_device: None,
        returned: None,
        state: String::new(),
        interrupts: None,
        notifications: None,
        interrupt_due: false,
        progress,
        desc: None,
        driver_area: None,
        device_area: None,
        error: queue.error.clone(),
    };
    if let Some(ring) = &queue.ring {
        let driver = queue.driver.as_ref();
        let signals = split_signals(ring, driver, queue.event_idx);
        view.avail = Some(ring.avail_idx);
        view.used = Some(ring.used_idx);
        view.taken_back = driver.map(|driver| driver.last_used);
        view.free = driver.map(|driver| driver.free);
        view.unpublished = driver.map(|driver| driver.avail_idx.wrapping_sub(ring.avail_idx));
        view.unkicked = driver.map(|driver| driver.unkicked);
        view.with_device = Some(u32::from(ring.with_device()));
        view.returned = driver.map(|driver| u32::from(ring.used_idx.wrapping_sub(driver.last_used)));
        view.state = queue_verdict(ring, driver);
        view.interrupts = Some(signal(signals.interrupts));
        view.notifications = Some(signal(signals.notifications));
        view.interrupt_due = signals.interrupt_due;
        view.desc = Some(ring.desc);
        view.driver_area = Some(ring.avail);
        view.device_area = Some(ring.used);
    } else if let Some(state) = &queue.packed {
        view.avail = Some(state.next_avail);
        view.taken_back = Some(state.last_used);
        view.free = Some(state.free);
        view.interrupts = Some(signal(state.interrupts));
        view.notifications = Some(signal(state.notifications));
        view.desc = Some(state.desc);
        view.driver_area = Some(state.driver_event);
        view.device_area = Some(state.device_event);
        if let Some(ring) = &queue.packed_ring {
            view.with_device = Some(ring.with_device);
            view.returned = Some(ring.returned);
            view.state = packed_verdict(ring);
        }
    } else if let Some(error) = &queue.error {
        view.state = error.clone();
    }
    view
}

/// The virtio PCI functions, with their queues where the drivers' PDBs
/// type them.
pub fn virtio_devices(functions: &[VirtioFunction]) -> Vec<VirtioDevice> {
    functions
        .iter()
        .map(|function| VirtioDevice {
            location: format!(
                "{:02x}:{:02x}.{}",
                function.bus, function.device, function.function
            ),
            virtio_id: function.virtio_id,
            kind: virtio_type_name(function.virtio_id),
            device_id: function.device_id,
            transitional: function.transitional,
            service: function.service.clone(),
            pdo: function.pdo,
            driver: function.driver.as_ref().map(|driver| {
                let queues = queue_count(&driver.queues);
                VirtioDriverState {
                    module: driver.module.clone(),
                    device: driver.device,
                    packed: driver.packed,
                    event_idx: driver.event_idx,
                    msix: driver.msix,
                    queues: driver
                        .queues
                        .iter()
                        .map(|queue| virtqueue(queue, Some(function.virtio_id), queues))
                        .collect(),
                }
            }),
            driver_missing: function.driver_missing.clone(),
        })
        .collect()
}

/// One descriptor, with what its indirect table holds.
fn descriptor(target: &Target, index: u16, addr: u64, len: u32, flags: u16, packed: bool) -> VirtioDescriptor {
    let table = (flags & VRING_DESC_F_INDIRECT != 0)
        .then(|| target.read_indirect_table(addr, len, packed).ok())
        .flatten();
    VirtioDescriptor {
        index,
        address: addr,
        length: len,
        flags,
        device_writes: flags & VRING_DESC_F_WRITE != 0,
        indirect_descriptors: table.map(|table| table.descriptors as u64),
        out_bytes: table.map(|table| table.out_bytes),
        in_bytes: table.map(|table| table.in_bytes),
    }
}

/// The ring of `queue`, whose device `device` is (type, transitional, queue
/// count) when known, with its outstanding buffers and their requests.
pub fn virtio_ring(target: &Target, queue: &VirtQueue, device: Option<(u16, bool, u32)>) -> VirtioRing {
    let kind = device.and_then(|(id, transitional, queues)| request_kind(id, queue.index, queues, transitional));
    let split_buffer = |chain: &DescChain, position: u16, written: Option<u32>| VirtioBuffer {
        position,
        head: chain.head,
        written,
        descriptors: chain
            .descriptors
            .iter()
            .map(|(index, desc)| descriptor(target, *index, desc.addr, desc.len, desc.flags, false))
            .collect(),
        request: kind.and_then(|kind| {
            target.describe_request(
                kind,
                chain.descriptors.iter().map(|(_, desc)| (desc.addr, desc.len, desc.flags)),
                false,
                written.is_some(),
                written,
            )
        }),
        broken: chain.broken.clone(),
    };
    let packed_buffer = |chain: &PackedChain| VirtioBuffer {
        position: chain.position,
        head: chain.descriptors.first().map_or(0, |(_, desc)| desc.id),
        written: None,
        descriptors: chain
            .descriptors
            .iter()
            .map(|(position, desc)| descriptor(target, *position, desc.addr, desc.len, desc.flags, true))
            .collect(),
        request: kind.and_then(|kind| {
            target.describe_request(
                kind,
                chain.descriptors.iter().map(|(_, desc)| (desc.addr, desc.len, desc.flags)),
                true,
                false,
                None,
            )
        }),
        broken: None,
    };
    let (with_device, returned, broken) = match (&queue.ring, &queue.packed_ring) {
        (Some(ring), _) => (
            target
                .split_ring_outstanding(ring, MAX_LISTED_CHAINS)
                .iter()
                .map(|chain| split_buffer(chain, chain.avail_index, None))
                .collect(),
            queue
                .driver
                .map(|driver| {
                    target
                        .split_ring_returned(ring, driver.last_used, MAX_LISTED_CHAINS)
                        .iter()
                        .map(|buffer| split_buffer(&buffer.chain, buffer.used_index, Some(buffer.written)))
                        .collect()
                })
                .unwrap_or_default(),
            None,
        ),
        (None, Some(ring)) => (
            ring.chains.iter().map(packed_buffer).collect(),
            Vec::new(),
            ring.broken.clone(),
        ),
        (None, None) => (Vec::new(), Vec::new(), None),
    };
    VirtioRing {
        queue: virtqueue(queue, device.map(|(id, _, _)| id), device.map_or(0, |(_, _, queues)| queues)),
        request_kind: kind.map(|kind| kind.name()),
        with_device,
        returned,
        broken,
    }
}
