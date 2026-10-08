//! Virtio devices (`!virtio`, `!vring`): the virtio PCI functions pci.sys
//! lists, the driver that runs each, and the state of its virtqueues. The
//! queues come from the driver's own structures, those of the VirtIO
//! library that every virtio-win driver links (`virtio_device`,
//! `virtqueue_split`), found through its KMDF device context and typed by
//! its PDB, and from the rings themselves in guest memory, whose layout
//! the virtio specification fixes.

use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::layout::{ParsedType, TypeInfo, Types};
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
/// A size beyond the 32768 entries the specification allows.
const MAX_QUEUE_SIZE: u32 = 32768;
/// The most queues read from one device, past any real device's.
const MAX_QUEUES: u64 = 1024;
/// The most outstanding buffers listed from one queue.
pub const MAX_LISTED_CHAINS: usize = 64;
/// How deep the search for a device's `virtio_device` goes into its
/// context's embedded structures.
const MAX_SEARCH_DEPTH: usize = 3;

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
    /// The driver's bookkeeping of a packed queue, whose ring this does
    /// not decode.
    pub packed: Option<PackedQueueState>,
    /// Why the queue or its ring could not be read.
    pub error: Option<String>,
}

/// What the driver keeps of a packed queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackedQueueState {
    /// `num_free`: free descriptors.
    pub free: u32,
    /// `last_used_idx`: where the driver takes used buffers back next.
    pub last_used: u16,
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

/// The unqualified name of a struct type (`virtio_device` for
/// `balloon!virtio_device`).
fn unqualified(name: &str) -> &str {
    name.rsplit_once('!').map_or(name, |(_, name)| name)
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
    /// `virtio_device` in the context of the WDFDEVICE its function driver
    /// made for the device.
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
        let info = self.wdf_driver_info(&service).map_err(|error| {
            fail(format!(
                "{module} is not a KMDF driver ntoseye can read: {error}"
            ))
        })?;
        let handle = info
            .devices
            .iter()
            .find(|device| device.device_object == fdo)
            .and_then(|device| device.handle)
            .ok_or_else(|| fail(format!("{module} has no WDFDEVICE for {:#x}", fdo.0)))?;
        let object = self
            .wdf_handle(handle)
            .map_err(|error| fail(error.to_string()))?;
        for context in &object.contexts {
            let Some(name) = &context.name else { continue };
            let found = [format!("{module}!{name}"), format!("{module}!_{name}")]
                .iter()
                .find_map(|type_name| {
                    let layout = types.layout(type_name.as_str()).ok()?;
                    find_virtio_device(types, &layout, context.context, MAX_SEARCH_DEPTH, self)
                });
            if let Some(device) = found {
                let driver = self
                    .virtio_device(&module, device)
                    .map_err(|error| fail(error.to_string()))?;
                return Ok((service, driver));
            }
        }
        Err(fail(format!(
            "no context of WDFDEVICE {handle:#x} holds a virtio_device"
        )))
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
            error: None,
        };
        let result = (|| -> Result<()> {
            let types = self.guest()?.ntoskrnl.types();
            if packed {
                let packed = types.struct_at(&format!("{module}!virtqueue_packed"), address)?;
                queue.index = packed.embedded("vq")?.read_uint("index")? as u32;
                queue.size = packed.embedded("packed")?.read_uint("num")? as u32;
                queue.packed = Some(PackedQueueState {
                    free: packed.read_uint("num_free")? as u32,
                    last_used: packed.read_uint("last_used_idx")? as u16,
                });
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
        let desc = |index: u16| {
            let mut bytes = [0u8; 16];
            memory
                .read_bytes(ring.desc + u64::from(index) * 16, &mut bytes)
                .ok()?;
            Some(VringDesc {
                addr: u64::from_le_bytes(bytes[0..8].try_into().ok()?),
                len: u32::from_le_bytes(bytes[8..12].try_into().ok()?),
                flags: u16::from_le_bytes([bytes[12], bytes[13]]),
                next: u16::from_le_bytes([bytes[14], bytes[15]]),
            })
        };
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
}

/// The address of the `virtio_device` in the structure `layout` at
/// `base`: an embedded one, one a pointer field names, or one inside an
/// embedded structure, at most `depth` deep.
fn find_virtio_device(
    types: Types<'_>,
    layout: &TypeInfo,
    base: VirtAddr,
    depth: usize,
    target: &Target,
) -> Option<VirtAddr> {
    let mut fields: Vec<_> = layout.fields.values().collect();
    fields.sort_by_key(|field| field.offset);
    for field in &fields {
        match &field.type_data {
            ParsedType::Struct(name) if unqualified(name) == "virtio_device" => {
                return Some(base + u64::from(field.offset));
            }
            ParsedType::Pointer(inner) if matches!(inner.as_ref(), ParsedType::Struct(name) if unqualified(name) == "virtio_device") =>
            {
                let pointer = target
                    .kernel_address_space()
                    .read::<u64>(base + u64::from(field.offset))
                    .ok()?;
                if pointer != 0 {
                    return Some(VirtAddr(pointer));
                }
            }
            _ => {}
        }
    }
    if depth == 0 {
        return None;
    }
    fields.iter().find_map(|field| match &field.type_data {
        ParsedType::Struct(name) => {
            let inner = types.layout(name.as_str()).ok()?;
            find_virtio_device(
                types,
                &inner,
                base + u64::from(field.offset),
                depth - 1,
                target,
            )
        }
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        DriverQueueState, SplitRing, VRING_DESC_F_NEXT, VringDesc, outstanding_heads,
        queue_verdict, walk_chain,
    };
    use crate::types::VirtAddr;

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
