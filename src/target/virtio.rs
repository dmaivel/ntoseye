//! Virtio devices (`!virtio`, `!vring`): the virtio PCI functions pci.sys
//! lists, the driver that runs each, and the state of its virtqueues. The
//! queues come from the driver's own structures, those of the VirtIO
//! library that every virtio-win driver links (`virtio_device`,
//! `virtqueue_split`), found through its KMDF device context and typed by
//! its PDB, and from the rings themselves in guest memory, whose layout
//! the virtio specification fixes.

use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::target::Target;
use crate::target::pci::{PciTreeBus, PciTreeDevice};
use crate::types::VirtAddr;

/// The PCI vendor ID of virtio devices (Red Hat / Qumranet).
pub const VIRTIO_VENDOR: u16 = 0x1af4;
/// A descriptor continues in `next`.
pub const VRING_DESC_F_NEXT: u16 = 1;
/// The device writes the buffer.
pub const VRING_DESC_F_WRITE: u16 = 2;
/// The buffer is a table of descriptors.
pub const VRING_DESC_F_INDIRECT: u16 = 4;
/// Set by the driver in `avail.flags`: no interrupt for used buffers.
pub const VRING_AVAIL_F_NO_INTERRUPT: u16 = 1;
/// Set by the device in `used.flags`: no notification for new buffers.
pub const VRING_USED_F_NO_NOTIFY: u16 = 1;
/// In a packed ring descriptor: the driver made it available in the lap
/// this bit names.
pub const VRING_PACKED_DESC_F_AVAIL: u16 = 1 << 7;
/// In a packed ring descriptor: the device used it in the lap this bit
/// names, together with `AVAIL`.
pub const VRING_PACKED_DESC_F_USED: u16 = 1 << 15;
/// A size beyond the 32768 entries the specification allows.
const MAX_QUEUE_SIZE: u32 = 32768;
/// The most queues read from one device, past any real device's.
const MAX_QUEUES: u64 = 1024;
/// The most outstanding buffers listed from one queue.
pub const MAX_LISTED_CHAINS: usize = 64;
/// How much of a driver's context is searched for its `virtio_device` when
/// the framework does not record the context's size (NDIS).
const UNSIZED_CONTEXT_SCAN: u64 = 64 << 10;
/// The most of a context that is searched when its size is known.
const MAX_CONTEXT_SCAN: u64 = 1 << 20;

/// The virtio device ID of PCI device `device_id`, and whether it is a
/// transitional device (one that also offers the legacy interface).
pub fn virtio_device_id(device_id: u16) -> Option<(u16, bool)> {
    match device_id {
        0x1040..=0x107f => Some((device_id - 0x1040, false)),
        0x1000 => Some((1, true)),
        0x1001 => Some((2, true)),
        0x1002 => Some((5, true)),
        0x1003 => Some((3, true)),
        0x1004 => Some((8, true)),
        0x1005 => Some((4, true)),
        0x1009 => Some((9, true)),
        _ => None,
    }
}

/// The specification's name of virtio device ID `id`.
pub fn virtio_type_name(id: u16) -> &'static str {
    match id {
        1 => "net",
        2 => "block",
        3 => "console",
        4 => "entropy",
        5 => "balloon",
        8 => "scsi",
        9 => "9p",
        16 => "gpu",
        18 => "input",
        19 => "vsock",
        20 => "crypto",
        24 => "pmem",
        26 => "fs",
        27 => "pmem",
        29 => "mem",
        34 => "sound",
        _ => "unknown",
    }
}

/// A virtio PCI function and what its driver shows of it.
#[derive(Debug, Clone)]
pub struct VirtioFunction {
    pub bus: u32,
    pub device: u8,
    pub function: u8,
    pub device_id: u16,
    pub virtio_id: u16,
    pub transitional: bool,
    pub pdo: VirtAddr,
    /// The service that drives it, from its device node.
    pub service: Option<String>,
    pub driver: Option<VirtioDriver>,
    /// Why there is no driver state.
    pub driver_missing: Option<String>,
}

/// A device as its virtio-win driver sees it: its `virtio_device` and the
/// queues it set up.
#[derive(Debug, Clone)]
pub struct VirtioDriver {
    /// The driver module whose PDB types its structures.
    pub module: String,
    /// The `virtio_device`.
    pub device: VirtAddr,
    pub packed: bool,
    pub queues: Vec<VirtQueue>,
}

/// One queue: the driver's bookkeeping and, for a split ring, the ring.
#[derive(Debug, Clone)]
pub struct VirtQueue {
    /// Its index in the device's queue table.
    pub index: u32,
    /// The `virtqueue_split` or `virtqueue_packed`.
    pub address: VirtAddr,
    pub size: u32,
    pub driver: Option<DriverQueueState>,
    pub ring: Option<SplitRing>,
    /// The driver's bookkeeping of a packed queue.
    pub packed: Option<PackedQueueState>,
    /// A packed queue's ring, read against the driver's bookkeeping.
    pub packed_ring: Option<PackedRing>,
    /// Why the queue or its ring could not be read.
    pub error: Option<String>,
}

/// What the driver keeps of a packed queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackedQueueState {
    /// `num_free`: free descriptors.
    pub free: u32,
    /// `last_used_idx`: the position where the driver takes used buffers
    /// back next, in the lap `used_wrap` names.
    pub last_used: u16,
    pub used_wrap: bool,
    /// `next_avail_idx`: the position the driver fills next, in the lap
    /// `avail_wrap` names.
    pub next_avail: u16,
    pub avail_wrap: bool,
    /// The descriptor ring.
    pub desc: VirtAddr,
    /// The driver's per-buffer state (`desc_state`), by buffer ID.
    pub desc_state: VirtAddr,
    /// The driver's and the device's event suppression structures.
    pub driver_event: VirtAddr,
    pub device_event: VirtAddr,
}

/// One packed ring descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackedDesc {
    pub addr: u64,
    pub len: u32,
    pub id: u16,
    pub flags: u16,
}

impl PackedDesc {
    /// The driver made it available and the device has not used it: its
    /// AVAIL and USED bits differ.
    pub fn available(&self) -> bool {
        (self.flags & VRING_PACKED_DESC_F_AVAIL != 0)
            != (self.flags & VRING_PACKED_DESC_F_USED != 0)
    }

    /// The device used it in the lap `wrap` names: both bits equal it.
    pub fn used_in(&self, wrap: bool) -> bool {
        (self.flags & VRING_PACKED_DESC_F_AVAIL != 0) == wrap
            && (self.flags & VRING_PACKED_DESC_F_USED != 0) == wrap
    }
}

/// One buffer the device holds in a packed ring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackedChain {
    /// The ring position of its first descriptor.
    pub position: u16,
    pub descriptors: Vec<(u16, PackedDesc)>,
}

/// A packed ring as guest memory holds it, read from the driver's last
/// used position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackedRing {
    /// Buffers the device used that the driver has not taken back.
    pub returned: u32,
    /// How many buffers the device holds.
    pub with_device: u32,
    /// The first of them, each with its descriptors.
    pub chains: Vec<PackedChain>,
    /// Why the walk stopped before the driver's count of descriptors in
    /// flight.
    pub broken: Option<String>,
}

/// Read a packed ring of `size` descriptors as the driver will: from its
/// last used position, the used elements the device wrote, each covering
/// the descriptors `chain_len` of its buffer ID says, then the buffers
/// still available to the device, up to the descriptors the driver has in
/// flight (`size - free`). At most `limit` of those buffers are kept.
pub fn read_packed_ring(
    size: u32,
    state: &PackedQueueState,
    limit: usize,
    desc: impl Fn(u16) -> Option<PackedDesc>,
    chain_len: impl Fn(u16) -> Option<u16>,
) -> PackedRing {
    let mut ring = PackedRing {
        returned: 0,
        with_device: 0,
        chains: Vec::new(),
        broken: None,
    };
    if size == 0 || size > MAX_QUEUE_SIZE {
        ring.broken = Some(format!("a ring of {size} entries is not a virtqueue"));
        return ring;
    }
    let mut remaining = size.saturating_sub(state.free);
    let mut position = u32::from(state.last_used) % size;
    let mut wrap = state.used_wrap;
    let advance = |position: &mut u32, wrap: &mut bool, by: u32| {
        *position += by;
        while *position >= size {
            *position -= size;
            *wrap = !*wrap;
        }
    };
    while remaining > 0 {
        let Some(used) = desc(position as u16) else {
            ring.broken = Some(format!("descriptor {position} could not be read"));
            return ring;
        };
        if !used.used_in(wrap) {
            break;
        }
        let length = chain_len(used.id).map_or(0, u32::from);
        if length == 0 || length > remaining {
            ring.broken = Some(format!(
                "used buffer {} at {position} has a chain of {length} descriptors",
                used.id
            ));
            return ring;
        }
        ring.returned += 1;
        remaining -= length;
        advance(&mut position, &mut wrap, length);
    }
    while remaining > 0 {
        let first = position as u16;
        let mut descriptors = Vec::new();
        loop {
            let Some(entry) = desc(position as u16) else {
                ring.broken = Some(format!("descriptor {position} could not be read"));
                return ring;
            };
            if !entry.available() {
                ring.broken = Some(format!(
                    "descriptor {position} is not available, with {remaining} still in flight"
                ));
                return ring;
            }
            descriptors.push((position as u16, entry));
            remaining -= 1;
            advance(&mut position, &mut wrap, 1);
            if entry.flags & VRING_DESC_F_NEXT == 0 || remaining == 0 {
                break;
            }
        }
        ring.with_device += 1;
        if ring.chains.len() < limit {
            ring.chains.push(PackedChain {
                position: first,
                descriptors,
            });
        }
    }
    ring
}

/// [`queue_verdict`] for a packed ring.
pub fn packed_verdict(ring: &PackedRing) -> String {
    let mut parts = Vec::new();
    if ring.with_device != 0 {
        parts.push(format!("{} with the device", ring.with_device));
    }
    if ring.returned != 0 {
        parts.push(format!("{} returned, not yet taken back", ring.returned));
    }
    if parts.is_empty() {
        "idle".into()
    } else {
        parts.join(", ")
    }
}

/// What the driver keeps of a split queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriverQueueState {
    /// `master_vring_avail.idx`: the avail index the driver wrote, which
    /// the ring's own shows once published.
    pub avail_idx: u16,
    /// `last_used`: the used index up to which the driver took buffers back.
    pub last_used: u16,
    /// `num_unused`: free descriptors.
    pub free: u32,
    /// `num_added_since_kick`: buffers added since the device was notified.
    pub unkicked: u32,
}

/// A split ring as guest memory holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SplitRing {
    pub size: u32,
    pub desc: VirtAddr,
    pub avail: VirtAddr,
    pub used: VirtAddr,
    pub avail_flags: u16,
    pub avail_idx: u16,
    pub used_flags: u16,
    pub used_idx: u16,
}

impl SplitRing {
    /// Buffers the driver made available that the device has not returned.
    pub fn with_device(&self) -> u16 {
        self.avail_idx.wrapping_sub(self.used_idx)
    }
}

/// One descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VringDesc {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

/// The descriptors of one buffer, from its head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescChain {
    /// Its position in the avail ring.
    pub avail_index: u16,
    pub head: u16,
    pub descriptors: Vec<(u16, VringDesc)>,
    /// Why the walk stopped before a descriptor without `NEXT`.
    pub broken: Option<String>,
}

/// What an indirect descriptor's table holds: its descriptors, and the
/// bytes the driver gives the device and the device may write back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndirectTable {
    pub descriptors: usize,
    pub out_bytes: u64,
    pub in_bytes: u64,
}

/// Sum the indirect table `table`. A packed ring's entries keep their
/// flags at +14, after the buffer ID; a split ring's at +12, before the
/// next index.
pub fn indirect_table(table: &[u8], packed: bool) -> IndirectTable {
    let flags_at = if packed { 14 } else { 12 };
    let mut summary = IndirectTable {
        descriptors: 0,
        out_bytes: 0,
        in_bytes: 0,
    };
    for entry in table.as_chunks::<16>().0 {
        let len = u64::from(u32::from_le_bytes([
            entry[8], entry[9], entry[10], entry[11],
        ]));
        let flags = u16::from_le_bytes([entry[flags_at], entry[flags_at + 1]]);
        summary.descriptors += 1;
        if flags & VRING_DESC_F_WRITE != 0 {
            summary.in_bytes += len;
        } else {
            summary.out_bytes += len;
        }
    }
    summary
}

/// A buffer the device returned in a split ring that the driver has not
/// taken back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReturnedBuffer {
    /// Its position in the used ring.
    pub used_index: u16,
    /// The bytes the device wrote into it.
    pub written: u32,
    /// Its descriptors, from the head the used element names.
    pub chain: DescChain,
}

/// What the device and driver have done with a split queue, in words: the
/// buffers the device holds, the ones it returned that the driver has not
/// taken back, and the ones the driver added without notifying the device.
pub fn queue_verdict(ring: &SplitRing, driver: Option<&DriverQueueState>) -> String {
    let mut parts = Vec::new();
    let with_device = ring.with_device();
    if with_device != 0 {
        parts.push(format!("{with_device} with the device"));
    }
    if let Some(driver) = driver {
        let unreturned = ring.used_idx.wrapping_sub(driver.last_used);
        if unreturned != 0 {
            parts.push(format!("{unreturned} returned, not yet taken back"));
        }
        let unpublished = driver.avail_idx.wrapping_sub(ring.avail_idx);
        if unpublished != 0 {
            parts.push(format!("{unpublished} added, not yet published"));
        }
        if driver.unkicked != 0 {
            parts.push(format!("{} not kicked", driver.unkicked));
        }
    }
    if parts.is_empty() {
        "idle".into()
    } else {
        parts.join(", ")
    }
}

/// The heads of the buffers the device holds: avail entries `used_idx`
/// up to `avail_idx`, read through `avail_entry`. At most `limit`.
pub fn outstanding_heads(
    ring: &SplitRing,
    limit: usize,
    avail_entry: impl Fn(u16) -> Option<u16>,
) -> Vec<(u16, Option<u16>)> {
    let count = usize::from(ring.with_device()).min(limit);
    (0..count)
        .map(|offset| {
            let index = ring.used_idx.wrapping_add(offset as u16);
            (index, avail_entry(index))
        })
        .collect()
}

/// Walk the chain from `head` through `desc`, at most `size` descriptors
/// long, as the device would.
pub fn walk_chain(
    avail_index: u16,
    head: u16,
    size: u32,
    desc: impl Fn(u16) -> Option<VringDesc>,
) -> DescChain {
    let mut chain = DescChain {
        avail_index,
        head,
        descriptors: Vec::new(),
        broken: None,
    };
    let mut index = head;
    for _ in 0..size {
        if u32::from(index) >= size {
            chain.broken = Some(format!("descriptor {index} is past the ring's {size}"));
            return chain;
        }
        let Some(entry) = desc(index) else {
            chain.broken = Some(format!("descriptor {index} could not be read"));
            return chain;
        };
        chain.descriptors.push((index, entry));
        if entry.flags & VRING_DESC_F_NEXT == 0 {
            return chain;
        }
        index = entry.next;
    }
    chain.broken = Some(format!(
        "the chain is longer than the ring's {size} descriptors"
    ));
    chain
}

/// Where the fields that identify a `virtio_device` sit, from the driver's
/// PDB.
#[derive(Debug, Clone, Copy)]
pub struct DeviceFields {
    pub size: usize,
    pub max_queues: usize,
    pub info: usize,
}

/// Whether `value` is a canonical kernel address.
fn kernel_address(value: u64) -> bool {
    value >= 0xffff_8000_0000_0000
}

/// Whether the bytes at the start of `header` could be a `virtio_device`:
/// a queue count a device has and a kernel address for its queue table.
fn plausible_device(header: &[u8], fields: DeviceFields) -> bool {
    let read = |at: usize, len: usize| header.get(at..at + len);
    let (Some(queues), Some(info)) = (read(fields.max_queues, 4), read(fields.info, 8)) else {
        return false;
    };
    let queues = u32::from_le_bytes(queues.try_into().unwrap_or_default());
    let info = u64::from_le_bytes(info.try_into().unwrap_or_default());
    (1..=MAX_QUEUES).contains(&u64::from(queues)) && kernel_address(info)
}

/// The driver's `virtio_device` in its context, `bytes` read at `base`:
/// one embedded in it or one a pointer in it names, whichever comes first,
/// confirmed by `is_device`. Taking them in order of offset finds the
/// driver's own before anything past the end of its allocation, so a
/// context of unknown size can be read past its end.
pub fn locate_device(
    bytes: &[u8],
    base: u64,
    fields: DeviceFields,
    mut is_device: impl FnMut(u64) -> bool,
) -> Option<u64> {
    for offset in (0..bytes.len().saturating_sub(7)).step_by(8) {
        let here = &bytes[offset..];
        if here.len() >= fields.size && plausible_device(here, fields) {
            let address = base + offset as u64;
            if is_device(address) {
                return Some(address);
            }
        }
        let pointer = u64::from_le_bytes(here[..8].try_into().unwrap_or_default());
        if kernel_address(pointer) && is_device(pointer) {
            return Some(pointer);
        }
    }
    None
}

/// A driver's per-device state that holds its `virtio_device`: a KMDF
/// device context, a StorPort miniport's device extension, or an NDIS
/// miniport's adapter context.
struct DriverContext {
    address: VirtAddr,
    size: Option<u64>,
    what: String,
}

impl Target {
    /// The virtio PCI functions pci.sys lists, with the service that runs
    /// each and, when its PDB has the virtio-win types, its queues.
    pub fn virtio_functions(&self) -> Result<Vec<VirtioFunction>> {
        let tree = self.pci_tree()?;
        let mut functions = Vec::new();
        fn collect<'a>(bus: &'a PciTreeBus, out: &mut Vec<&'a PciTreeDevice>) {
            out.extend(&bus.devices);
            for child in &bus.child_buses {
                collect(child, out);
            }
        }
        let mut devices = Vec::new();
        for segment in &tree.segments {
            for bus in &segment.root_buses {
                collect(bus, &mut devices);
            }
        }
        for device in devices {
            if device.vendor_id != VIRTIO_VENDOR {
                continue;
            }
            let Some((virtio_id, transitional)) = virtio_device_id(device.device_id) else {
                continue;
            };
            let mut function = VirtioFunction {
                bus: device.bus,
                device: device.device,
                function: device.function,
                device_id: device.device_id,
                virtio_id,
                transitional,
                pdo: device.device_object,
                service: None,
                driver: None,
                driver_missing: None,
            };
            match self.virtio_driver_of(device.device_object) {
                Ok((service, driver)) => {
                    function.service = Some(service);
                    function.driver = Some(driver);
                }
                Err((service, why)) => {
                    function.service = service;
                    function.driver_missing = Some(why);
                }
            }
            functions.push(function);
        }
        Ok(functions)
    }

    /// The service on `pdo`'s device node and its virtio-win state: the
    /// `virtio_device` in the driver's per-device state, its KMDF device
    /// context, StorPort device extension, or NDIS adapter context.
    fn virtio_driver_of(
        &self,
        pdo: VirtAddr,
    ) -> std::result::Result<(String, VirtioDriver), (Option<String>, String)> {
        let stack = self
            .inspect_device_stack(pdo)
            .map_err(|error| (None, format!("its device stack: {error}")))?;
        let service = stack
            .pdo_devnode
            .as_ref()
            .map(|node| node.service_name.clone())
            .filter(|name| !name.is_empty())
            .ok_or_else(|| (None, "no service drives it".to_string()))?;
        let fail = |why: String| (Some(service.clone()), why);
        let fdo_entry = stack
            .entries
            .iter()
            .find(|entry| {
                entry
                    .driver_name
                    .rsplit('\\')
                    .next()
                    .is_some_and(|name| name.eq_ignore_ascii_case(&service))
            })
            .ok_or_else(|| {
                fail(format!(
                    "no device object of \\Driver\\{service} is on its stack"
                ))
            })?;
        let fdo = fdo_entry.device_object;
        let types = self
            .guest()
            .map_err(|error| fail(error.to_string()))?
            .ntoskrnl
            .types();
        // The service names the driver object (`\Driver\VirtioSerial`), not
        // the image (`vioser.sys`); the image is where the driver starts.
        let module = types
            .struct_at("_DRIVER_OBJECT", fdo_entry.driver_object)
            .and_then(|driver| driver.read_pointer("DriverStart"))
            .ok()
            .and_then(|start| self.module_containing(start))
            .map(|module| module.short_name)
            .ok_or_else(|| {
                fail(format!(
                    "the image of \\Driver\\{service} is not a loaded module"
                ))
            })?;
        if types.layout(format!("{module}!virtio_device")).is_err() {
            return Err(fail(format!(
                "{module}'s symbols have no virtio_device type; the driver's private PDB has \
                 it (.sympath+ <build directory>)"
            )));
        }
        let contexts = self.driver_contexts(&service, fdo, pdo);
        if contexts.is_empty() {
            return Err(fail(format!(
                "{module} keeps no device state ntoseye can find: it is not a KMDF, StorPort \
                 or NDIS driver of this device"
            )));
        }
        for context in &contexts {
            if let Some(device) = self.device_in_context(&module, context) {
                let driver = self
                    .virtio_device(&module, device)
                    .map_err(|error| fail(error.to_string()))?;
                return Ok((service, driver));
            }
        }
        let searched: Vec<&str> = contexts
            .iter()
            .map(|context| context.what.as_str())
            .collect();
        Err(fail(format!("no virtio_device in {}", searched.join(", "))))
    }

    /// The per-device state `service` keeps for the device whose FDO is
    /// `fdo` and PDO `pdo`, from whichever framework drives it.
    fn driver_contexts(&self, service: &str, fdo: VirtAddr, pdo: VirtAddr) -> Vec<DriverContext> {
        let mut contexts = Vec::new();
        if let Ok(info) = self.wdf_driver_info(service)
            && let Some(handle) = info
                .devices
                .iter()
                .find(|device| device.device_object == fdo)
                .and_then(|device| device.handle)
            && let Ok(object) = self.wdf_handle(handle)
        {
            contexts.extend(object.contexts.iter().map(|context| DriverContext {
                address: context.context,
                size: context.size,
                what: format!(
                    "the {} context of WDFDEVICE {handle:#x}",
                    context.name.as_deref().unwrap_or("unnamed")
                ),
            }));
        }
        if let Ok(ports) = self.storport_drivers() {
            let adapters = ports.drivers.iter().flat_map(|driver| &driver.adapters);
            for adapter in adapters.filter_map(|entry| entry.adapter.as_ref().ok()) {
                if adapter.fdo == fdo && !adapter.hw_device_extension.is_zero() {
                    contexts.push(DriverContext {
                        address: adapter.hw_device_extension,
                        size: adapter.hw_device_extension_size,
                        what: format!(
                            "the device extension of StorPort adapter {:#x}",
                            adapter.extension.0
                        ),
                    });
                }
            }
        }
        if let Ok(list) = self.ndis_miniports() {
            let addresses = list.miniports.iter().map(|entry| match entry {
                Ok(miniport) => miniport.address,
                Err(unreadable) => unreadable.address,
            });
            for address in addresses {
                let Ok(miniport) = self.ndis_miniport(address) else {
                    continue;
                };
                if (miniport.device_object == fdo || miniport.pdo == pdo)
                    && !miniport.adapter_context.is_zero()
                {
                    contexts.push(DriverContext {
                        address: miniport.adapter_context,
                        size: None,
                        what: format!("the adapter context of NDIS miniport {:#x}", address.0),
                    });
                }
            }
        }
        contexts
    }

    /// The `virtio_device` in `context`, typed by `module`'s PDB.
    fn device_in_context(&self, module: &str, context: &DriverContext) -> Option<VirtAddr> {
        let types = self.guest().ok()?.ntoskrnl.types();
        let device = types.layout(format!("{module}!virtio_device")).ok()?;
        let fields = DeviceFields {
            size: device.size as usize,
            max_queues: device.field_offset("maxQueues").ok()? as usize,
            info: device.field_offset("info").ok()? as usize,
        };
        let len = context
            .size
            .map_or(UNSIZED_CONTEXT_SCAN, |size| size.min(MAX_CONTEXT_SCAN));
        let bytes = self.read_readable(context.address, len as usize);
        locate_device(&bytes, context.address.0, fields, |address| {
            self.is_virtio_device(module, VirtAddr(address), context.address)
        })
        .map(VirtAddr)
    }

    /// Up to `len` bytes from `address`, stopping at the first page that
    /// cannot be read.
    fn read_readable(&self, address: VirtAddr, len: usize) -> Vec<u8> {
        let memory = self.kernel_address_space();
        let mut bytes = Vec::with_capacity(len);
        while bytes.len() < len {
            let at = address + bytes.len() as u64;
            let page_left = 0x1000 - (at.0 & 0xfff) as usize;
            let mut chunk = vec![0u8; page_left.min(len - bytes.len())];
            if memory.read_bytes(at, &mut chunk).is_err() {
                break;
            }
            bytes.extend_from_slice(&chunk);
        }
        bytes
    }

    /// Whether `address` holds a `virtio_device` of `module`'s driver: its
    /// queues point back at it (`virtqueue.vdev`), or, before it has
    /// queues, its `DeviceContext` names it or the driver's context.
    fn is_virtio_device(&self, module: &str, address: VirtAddr, context: VirtAddr) -> bool {
        let check = || -> Result<bool> {
            let types = self.guest()?.ntoskrnl.types();
            let device = types.struct_at(&format!("{module}!virtio_device"), address)?;
            let count = device.read_uint("maxQueues")?;
            let info = device.read_pointer("info")?;
            if !(1..=MAX_QUEUES).contains(&count) || !kernel_address(info.0) {
                return Ok(false);
            }
            let entry = types.layout(format!("{module}!virtio_queue_info"))?;
            let vq_offset = entry.field_offset("vq")?;
            let vdev_offset = types
                .layout(format!("{module}!virtqueue"))?
                .field_offset("vdev")?;
            let memory = self.kernel_address_space();
            let mut queues = 0;
            for index in 0..count {
                let vq = memory.read::<u64>(info + (index * entry.size as u64 + vq_offset))?;
                if vq == 0 {
                    continue;
                }
                if !kernel_address(vq)
                    || memory.read::<u64>(VirtAddr(vq) + vdev_offset)? != address.0
                {
                    return Ok(false);
                }
                queues += 1;
            }
            if queues > 0 {
                return Ok(true);
            }
            let owner = device.read_pointer("DeviceContext")?;
            Ok(owner == address || owner == context)
        };
        check().unwrap_or(false)
    }

    /// The `virtio_device` at `address`, typed by `module`'s PDB, and its
    /// queues.
    pub fn virtio_device(&self, module: &str, address: VirtAddr) -> Result<VirtioDriver> {
        let types = self.guest()?.ntoskrnl.types();
        let device = types.struct_at(&format!("{module}!virtio_device"), address)?;
        let packed = device.read_uint("packed_ring")? != 0;
        let count = device.read_uint("maxQueues")?;
        if count > MAX_QUEUES {
            return Err(Error::DebugInfo(format!(
                "virtio_device {:#x} says it has {count} queues; it is not a virtio_device",
                address.0
            )));
        }
        let info = device.read_pointer("info")?;
        let info_layout = types.layout(format!("{module}!virtio_queue_info"))?;
        let mut queues = Vec::new();
        for index in 0..count {
            let entry = types
                .struct_with_layout(info_layout.clone(), info + index * info_layout.size as u64);
            let vq = entry.read_pointer("vq")?;
            if vq.is_zero() {
                continue;
            }
            queues.push(self.virtqueue(module, vq, packed, index as u32));
        }
        Ok(VirtioDriver {
            module: module.to_string(),
            device: address,
            packed,
            queues,
        })
    }

    /// The queue at `address` (a `virtqueue_split`, or a `virtqueue_packed`
    /// when `packed`), typed by `module`'s PDB, and for a split queue its
    /// ring.
    pub fn virtqueue(
        &self,
        module: &str,
        address: VirtAddr,
        packed: bool,
        index: u32,
    ) -> VirtQueue {
        let mut queue = VirtQueue {
            index,
            address,
            size: 0,
            driver: None,
            ring: None,
            packed: None,
            packed_ring: None,
            error: None,
        };
        let result = (|| -> Result<()> {
            let types = self.guest()?.ntoskrnl.types();
            if packed {
                let packed = types.struct_at(&format!("{module}!virtqueue_packed"), address)?;
                queue.index = packed.embedded("vq")?.read_uint("index")? as u32;
                let shared = packed.embedded("packed")?;
                let vring = shared.embedded("vring")?;
                queue.size = vring.read_uint("num")? as u32;
                let state = PackedQueueState {
                    free: packed.read_uint("num_free")? as u32,
                    last_used: packed.read_uint("last_used_idx")? as u16,
                    used_wrap: shared.read_uint("used_wrap_counter")? != 0,
                    next_avail: shared.read_uint("next_avail_idx")? as u16,
                    avail_wrap: shared.read_uint("avail_wrap_counter")? != 0,
                    desc: vring.read_pointer("desc")?,
                    desc_state: shared.read_pointer("desc_state")?,
                    driver_event: vring.read_pointer("driver")?,
                    device_event: vring.read_pointer("device")?,
                };
                queue.packed = Some(state);
                queue.packed_ring = Some(self.packed_ring(module, queue.size, &state)?);
                return Ok(());
            }
            let split = types.struct_at(&format!("{module}!virtqueue_split"), address)?;
            queue.index = split.embedded("vq")?.read_uint("index")? as u32;
            let vring = split.embedded("vring")?;
            let size = vring.read_uint("num")? as u32;
            queue.size = size;
            queue.driver = Some(DriverQueueState {
                avail_idx: split.embedded("master_vring_avail")?.read_uint("idx")? as u16,
                last_used: split.read_uint("last_used")? as u16,
                free: split.read_uint("num_unused")? as u32,
                unkicked: split.read_uint("num_added_since_kick")? as u32,
            });
            queue.ring = Some(self.split_ring(
                size,
                vring.read_pointer("desc")?,
                vring.read_pointer("avail")?,
                vring.read_pointer("used")?,
            )?);
            Ok(())
        })();
        queue.error = result.err().map(|error| error.to_string());
        queue
    }

    /// The split ring of `size` entries at kernel addresses `desc`,
    /// `avail` and `used`, read with the layout the specification fixes.
    pub fn split_ring(
        &self,
        size: u32,
        desc: VirtAddr,
        avail: VirtAddr,
        used: VirtAddr,
    ) -> Result<SplitRing> {
        if size == 0 || size > MAX_QUEUE_SIZE {
            return Err(Error::DebugInfo(format!(
                "a ring of {size} entries is not a virtqueue (1-{MAX_QUEUE_SIZE})"
            )));
        }
        let memory = self.kernel_address_space();
        let mut avail_head = [0u8; 4];
        memory.read_bytes(avail, &mut avail_head)?;
        let mut used_head = [0u8; 4];
        memory.read_bytes(used, &mut used_head)?;
        Ok(SplitRing {
            size,
            desc,
            avail,
            used,
            avail_flags: u16::from_le_bytes([avail_head[0], avail_head[1]]),
            avail_idx: u16::from_le_bytes([avail_head[2], avail_head[3]]),
            used_flags: u16::from_le_bytes([used_head[0], used_head[1]]),
            used_idx: u16::from_le_bytes([used_head[2], used_head[3]]),
        })
    }

    /// The buffers the device holds in `ring`, each with its descriptors,
    /// at most `limit` of them.
    pub fn split_ring_outstanding(&self, ring: &SplitRing, limit: usize) -> Vec<DescChain> {
        let memory = self.kernel_address_space();
        let avail_entry = |index: u16| {
            let slot = u64::from(u32::from(index) % ring.size);
            memory.read::<u16>(ring.avail + (4 + slot * 2)).ok()
        };
        let desc = |index: u16| self.split_desc(ring, index);
        outstanding_heads(ring, limit, avail_entry)
            .into_iter()
            .map(|(avail_index, head)| match head {
                Some(head) => walk_chain(avail_index, head, ring.size, desc),
                None => DescChain {
                    avail_index,
                    head: 0,
                    descriptors: Vec::new(),
                    broken: Some("its avail entry could not be read".into()),
                },
            })
            .collect()
    }

    /// The buffers the device returned in `ring` that the driver has not
    /// taken back: the used elements from the driver's `last_used` up to
    /// the ring's used index, at most `limit` of them, each with its chain,
    /// which the driver frees only once it takes the buffer back.
    pub fn split_ring_returned(
        &self,
        ring: &SplitRing,
        last_used: u16,
        limit: usize,
    ) -> Vec<ReturnedBuffer> {
        let memory = self.kernel_address_space();
        let count = usize::from(ring.used_idx.wrapping_sub(last_used)).min(limit);
        (0..count)
            .map(|offset| {
                let used_index = last_used.wrapping_add(offset as u16);
                let slot = u64::from(u32::from(used_index) % ring.size);
                let mut element = [0u8; 8];
                let read = memory.read_bytes(ring.used + (4 + slot * 8), &mut element);
                let id = u32::from_le_bytes([element[0], element[1], element[2], element[3]]);
                let written = u32::from_le_bytes([element[4], element[5], element[6], element[7]]);
                let chain = match (read, u16::try_from(id)) {
                    (Ok(()), Ok(head)) => walk_chain(used_index, head, ring.size, |index| {
                        self.split_desc(ring, index)
                    }),
                    _ => DescChain {
                        avail_index: used_index,
                        head: 0,
                        descriptors: Vec::new(),
                        broken: Some(format!("used element {used_index} names buffer {id}")),
                    },
                };
                ReturnedBuffer {
                    used_index,
                    written,
                    chain,
                }
            })
            .collect()
    }

    /// The indirect table of `len` bytes at guest-physical `addr`, of a
    /// packed ring or a split one.
    pub fn read_indirect_table(&self, addr: u64, len: u32, packed: bool) -> Result<IndirectTable> {
        if len == 0 || !len.is_multiple_of(16) || len > MAX_QUEUE_SIZE * 16 {
            return Err(Error::DebugInfo(format!(
                "an indirect table of {len:#x} bytes is not a whole number of descriptors"
            )));
        }
        let mut table = vec![0u8; len as usize];
        self.read_physical(addr, &mut table)?;
        Ok(indirect_table(&table, packed))
    }

    /// Descriptor `index` of the split ring `ring`.
    fn split_desc(&self, ring: &SplitRing, index: u16) -> Option<VringDesc> {
        let mut bytes = [0u8; 16];
        self.kernel_address_space()
            .read_bytes(ring.desc + u64::from(index) * 16, &mut bytes)
            .ok()?;
        Some(VringDesc {
            addr: u64::from_le_bytes(bytes[0..8].try_into().ok()?),
            len: u32::from_le_bytes(bytes[8..12].try_into().ok()?),
            flags: u16::from_le_bytes([bytes[12], bytes[13]]),
            next: u16::from_le_bytes([bytes[14], bytes[15]]),
        })
    }

    /// The loaded modules whose PDB has the virtio-win `virtio_device`
    /// type, for an address given without its module.
    pub fn virtio_modules(&self) -> Vec<String> {
        let Ok(guest) = self.guest() else {
            return Vec::new();
        };
        let types = guest.ntoskrnl.types();
        self.kernel_modules()
            .unwrap_or_default()
            .into_iter()
            .map(|module| module.short_name)
            .filter(|module| types.layout(format!("{module}!virtio_device")).is_ok())
            .collect()
    }

    /// The packed ring of `size` descriptors that `state` describes, with
    /// the chain lengths from the driver's `desc_state`, typed by
    /// `module`'s PDB.
    pub fn packed_ring(
        &self,
        module: &str,
        size: u32,
        state: &PackedQueueState,
    ) -> Result<PackedRing> {
        if size == 0 || size > MAX_QUEUE_SIZE {
            return Err(Error::DebugInfo(format!(
                "a ring of {size} entries is not a virtqueue (1-{MAX_QUEUE_SIZE})"
            )));
        }
        let memory = self.kernel_address_space();
        let mut table = vec![0u8; size as usize * 16];
        memory.read_bytes(state.desc, &mut table)?;
        let types = self.guest()?.ntoskrnl.types();
        let entry = types.layout(format!("{module}!vring_desc_state_packed"))?;
        let num_offset = entry.field_offset("num")?;
        let desc = |index: u16| {
            let bytes = table.get(usize::from(index) * 16..usize::from(index) * 16 + 16)?;
            Some(PackedDesc {
                addr: u64::from_le_bytes(bytes[0..8].try_into().ok()?),
                len: u32::from_le_bytes(bytes[8..12].try_into().ok()?),
                id: u16::from_le_bytes([bytes[12], bytes[13]]),
                flags: u16::from_le_bytes([bytes[14], bytes[15]]),
            })
        };
        let chain_len = |id: u16| {
            (u32::from(id) < size)
                .then(|| state.desc_state + (u64::from(id) * entry.size as u64 + num_offset))
                .and_then(|at| memory.read::<u16>(at).ok())
        };
        Ok(read_packed_ring(
            size,
            state,
            MAX_LISTED_CHAINS,
            desc,
            chain_len,
        ))
    }

    /// Whether the queue at `address` is a packed one, from its device's
    /// `packed_ring`, typed by `module`'s PDB.
    pub fn virtqueue_is_packed(&self, module: &str, address: VirtAddr) -> Result<bool> {
        let types = self.guest()?.ntoskrnl.types();
        let device = types
            .struct_at(&format!("{module}!virtqueue"), address)?
            .read_pointer("vdev")?;
        Ok(types
            .struct_at(&format!("{module}!virtio_device"), device)?
            .read_uint("packed_ring")?
            != 0)
    }

    /// The driver whose PDB types the virtio-win structure `type_name` at
    /// `address`: the module the code or data its `pointer` field names is
    /// in (a queue's `add_buf`, a device's `device` operations), when that
    /// module has the virtio-win types.
    pub fn virtio_module_of(
        &self,
        address: VirtAddr,
        type_name: &str,
        pointer: &str,
    ) -> Option<String> {
        let types = self.guest().ok()?.ntoskrnl.types();
        self.virtio_modules().into_iter().find_map(|module| {
            let target = types
                .struct_at(&format!("{module}!{type_name}"), address)
                .and_then(|value| value.read_pointer(pointer))
                .ok()?;
            let owner = self.module_containing(target)?.short_name;
            types
                .layout(format!("{owner}!virtio_device"))
                .is_ok()
                .then_some(owner)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DeviceFields, DriverQueueState, PackedDesc, PackedQueueState, SplitRing, VRING_DESC_F_NEXT,
        VRING_DESC_F_WRITE, VRING_PACKED_DESC_F_AVAIL, VRING_PACKED_DESC_F_USED, VringDesc,
        indirect_table, locate_device, outstanding_heads, queue_verdict, read_packed_ring,
        walk_chain,
    };
    use crate::types::VirtAddr;

    /// An indirect table sums what the driver sends and what the device may
    /// write, with the flags where each ring layout keeps them.
    #[test]
    fn an_indirect_table_reads_its_flags_where_the_ring_layout_keeps_them() {
        let entry = |len: u32, flags: u16, flags_at: usize| {
            let mut bytes = [0u8; 16];
            bytes[8..12].copy_from_slice(&len.to_le_bytes());
            bytes[flags_at..flags_at + 2].copy_from_slice(&flags.to_le_bytes());
            bytes
        };
        let split = [
            entry(0x10, 0, 12),
            entry(0x1000, 0, 12),
            entry(1, VRING_DESC_F_WRITE, 12),
        ]
        .concat();
        let table = indirect_table(&split, false);
        assert_eq!(
            (table.descriptors, table.out_bytes, table.in_bytes),
            (3, 0x1010, 1)
        );
        let packed = [entry(0x10, 0, 14), entry(0x600, VRING_DESC_F_WRITE, 14)].concat();
        let table = indirect_table(&packed, true);
        assert_eq!(
            (table.descriptors, table.out_bytes, table.in_bytes),
            (2, 0x10, 0x600)
        );
    }
    /// A packed descriptor: `used` marks it used in lap `lap`, else
    /// available in that lap.
    fn packed(id: u16, lap: bool, used: bool, next: bool) -> PackedDesc {
        let avail = if lap { VRING_PACKED_DESC_F_AVAIL } else { 0 };
        let used_bit = match (used, lap) {
            (true, true) | (false, false) => VRING_PACKED_DESC_F_USED,
            _ => 0,
        };
        PackedDesc {
            addr: 0x1000 * u64::from(id),
            len: 64,
            id,
            flags: avail | used_bit | if next { VRING_DESC_F_NEXT } else { 0 },
        }
    }

    fn packed_state(free: u32, last_used: u16, used_wrap: bool) -> PackedQueueState {
        PackedQueueState {
            free,
            last_used,
            used_wrap,
            next_avail: 0,
            avail_wrap: false,
            desc: VirtAddr(0),
            desc_state: VirtAddr(0),
            driver_event: VirtAddr(0),
            device_event: VirtAddr(0),
        }
    }

    /// From the driver's last used position, a used element covers its
    /// buffer's chain, across the end of the ring into the next lap; the
    /// rest of what is in flight are available chains joined by NEXT.
    #[test]
    fn a_packed_ring_reads_used_then_available_chains_across_the_wrap() {
        // Lap 1 at 6-7: buffer 2, two descriptors, used. Lap 0 from 0:
        // buffer 3 (0-1) and buffer 4 (2) available.
        let mut ring = [packed(9, false, true, false); 8];
        ring[6] = packed(2, true, true, false);
        ring[0] = packed(3, false, false, true);
        ring[1] = packed(3, false, false, false);
        ring[2] = packed(4, false, false, false);
        let read = read_packed_ring(
            8,
            &packed_state(3, 6, true),
            64,
            |index| ring.get(usize::from(index)).copied(),
            |id| (id == 2).then_some(2),
        );
        assert_eq!(read.returned, 1);
        assert_eq!(read.with_device, 2);
        let positions: Vec<Vec<u16>> = read
            .chains
            .iter()
            .map(|chain| chain.descriptors.iter().map(|(at, _)| *at).collect())
            .collect();
        assert_eq!(positions, [vec![0, 1], vec![2]]);
        assert!(read.broken.is_none(), "{:?}", read.broken);
    }

    /// A used element from an earlier lap is not returned; one whose
    /// chain is longer than what is in flight stops the read.
    #[test]
    fn a_packed_ring_counts_only_this_laps_used_elements() {
        let stale = [packed(1, false, true, false), packed(2, true, false, false)];
        let read = read_packed_ring(
            2,
            &packed_state(1, 0, true),
            64,
            |index| stale.get(usize::from(index)).copied(),
            |_| Some(1),
        );
        assert_eq!(read.returned, 0);
        assert!(
            read.broken.is_some(),
            "a stale used element is not available"
        );
        let used = [packed(1, true, true, false), packed(2, true, false, false)];
        let read = read_packed_ring(
            2,
            &packed_state(1, 0, true),
            64,
            |index| used.get(usize::from(index)).copied(),
            |_| Some(5),
        );
        assert!(read.broken.is_some(), "a chain of 5 cannot be 1 in flight");
    }

    const FIELDS: DeviceFields = DeviceFields {
        size: 0x30,
        max_queues: 0x10,
        info: 0x18,
    };
    const BASE: u64 = 0xffff_c000_0000_0000;

    /// A context of `len` bytes with a plausible device header at
    /// `device` and a kernel pointer `pointer` at `at`.
    fn context(len: usize, device: Option<usize>, pointer: Option<(usize, u64)>) -> Vec<u8> {
        let mut bytes = vec![0u8; len];
        if let Some(offset) = device {
            bytes[offset + 0x10..offset + 0x14].copy_from_slice(&3u32.to_le_bytes());
            bytes[offset + 0x18..offset + 0x20].copy_from_slice(&(BASE + 0x9000).to_le_bytes());
        }
        if let Some((at, value)) = pointer {
            bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
        bytes
    }

    /// The device is found embedded at its offset or behind a pointer, and
    /// only where the check confirms it.
    #[test]
    fn a_device_is_found_embedded_or_behind_a_pointer() {
        let embedded = context(0x100, Some(0x40), None);
        assert_eq!(
            locate_device(&embedded, BASE, FIELDS, |at| at == BASE + 0x40),
            Some(BASE + 0x40)
        );
        assert_eq!(locate_device(&embedded, BASE, FIELDS, |_| false), None);
        let elsewhere = BASE + 0x5_0000;
        let pointed = context(0x100, None, Some((0x20, elsewhere)));
        assert_eq!(
            locate_device(&pointed, BASE, FIELDS, |at| at == elsewhere),
            Some(elsewhere)
        );
    }

    /// The driver's own pointer, early in its context, wins over a device
    /// embedded further on, which in a context read past its end can be
    /// another driver's.
    #[test]
    fn the_first_device_by_offset_wins() {
        let own = BASE + 0x5_0000;
        let bytes = context(0x200, Some(0x180), Some((0x08, own)));
        assert_eq!(
            locate_device(&bytes, BASE, FIELDS, |at| at == own || at == BASE + 0x180),
            Some(own)
        );
    }

    fn ring(avail_idx: u16, used_idx: u16) -> SplitRing {
        SplitRing {
            size: 8,
            desc: VirtAddr(0),
            avail: VirtAddr(0),
            used: VirtAddr(0),
            avail_flags: 0,
            avail_idx,
            used_flags: 0,
            used_idx,
        }
    }

    /// The device holds what the driver published past what it returned,
    /// counted across the 16-bit wrap; the driver's own counters add what
    /// it has not taken back, published or kicked.
    #[test]
    fn a_queue_verdict_counts_across_the_index_wrap() {
        assert_eq!(queue_verdict(&ring(5, 5), None), "idle");
        assert_eq!(queue_verdict(&ring(2, 0xfffe), None), "4 with the device");
        let driver = DriverQueueState {
            avail_idx: 7,
            last_used: 3,
            free: 0,
            unkicked: 2,
        };
        assert_eq!(
            queue_verdict(&ring(5, 5), Some(&driver)),
            "2 returned, not yet taken back, 2 added, not yet published, 2 not kicked"
        );
    }

    /// The outstanding heads are the avail entries from the used index on,
    /// at their ring positions modulo the size, and no more than the limit.
    #[test]
    fn outstanding_heads_follow_the_avail_ring() {
        let entries = [10u16, 11, 12, 13, 14, 15, 16, 17];
        let read = |index: u16| entries.get(usize::from(index) % 8).copied();
        let heads = outstanding_heads(&ring(0x0a, 0x06), 64, read);
        assert_eq!(
            heads,
            [(6, Some(16)), (7, Some(17)), (8, Some(10)), (9, Some(11))]
        );
        assert_eq!(outstanding_heads(&ring(0x0a, 0x06), 2, read).len(), 2);
    }

    /// A chain follows `next` while `NEXT` is set, and a loop, an index
    /// past the ring, or an unreadable descriptor ends it as broken.
    #[test]
    fn a_chain_is_walked_until_its_last_descriptor() {
        let desc = |next: Option<u16>| VringDesc {
            addr: 0x1000,
            len: 64,
            flags: if next.is_some() { VRING_DESC_F_NEXT } else { 0 },
            next: next.unwrap_or(0),
        };
        let table = [desc(Some(2)), desc(None), desc(Some(1)), desc(Some(3))];
        let read = |index: u16| table.get(usize::from(index)).copied();
        let chain = walk_chain(0, 0, 4, read);
        assert_eq!(
            chain
                .descriptors
                .iter()
                .map(|(i, _)| *i)
                .collect::<Vec<_>>(),
            [0, 2, 1]
        );
        assert!(chain.broken.is_none());
        assert!(walk_chain(0, 3, 4, read).broken.is_some(), "a loop ends");
        assert!(walk_chain(0, 9, 4, read).broken.is_some(), "past the ring");
    }
}
