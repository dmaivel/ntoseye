//! classpnp (`!storagekd.storclass`): the storage class devices that
//! classpnp.sys drives for disk.sys, cdrom.sys, and the other class drivers,
//! read with classpnp's public PDB. classpnp keeps every FDO's private data
//! on `classpnp!AllFdosList`; from it come the device's identity, its
//! transfer packets (the requests classpnp has sent down the stack), and the
//! last errors it logged with their SRB and sense data.

use std::collections::HashSet;
use std::sync::Arc;

use super::{Target, bounded_list_walk};
use crate::backend::MemoryOps;
use crate::cpu_state::processor_count;
use crate::error::{Error, Result};
use crate::kuser_shared::KuserSharedData;
use crate::layout::{StructRef, TypeInfo, Types, le_uint};
use crate::target::srb::Srb;
use crate::target::virtio_request::sense_text;
use crate::types::VirtAddr;

const MAX_CLASS_DEVICES: usize = 1024;
/// More transfer packets than classpnp allocates for one device.
const MAX_TRANSFER_PACKETS: usize = 8192;
/// More NUMA nodes than Windows supports.
const MAX_NODES: u64 = 64;
/// The most bytes of a `STORAGE_DEVICE_DESCRIPTOR` read for its strings.
const MAX_DESCRIPTOR: u64 = 0x1000;
/// `IO_TYPE_DEVICE`, the `Type` of a `DEVICE_OBJECT`.
const IO_TYPE_DEVICE: u64 = 3;

/// A device's transfer packets: how many classpnp allocated, how many are
/// free, and the ones it has sent down the stack.
#[derive(Debug, Clone, Default)]
pub struct ClassPackets {
    /// The packets on `AllTransferPacketsList`.
    pub total: u64,
    /// Those on a free list: a NUMA node's, a processor's, or the one
    /// packet classpnp keeps for forward progress.
    pub free: u64,
    pub in_flight: Vec<TransferPacket>,
    /// Why a walk of the packets stopped short.
    pub stopped: Vec<String>,
}

/// A transfer packet (`_TRANSFER_PACKET`) classpnp has sent down the stack
/// and not seen completed.
#[derive(Debug, Clone)]
pub struct TransferPacket {
    pub address: VirtAddr,
    /// The IRP classpnp sent down, and the client's IRP it serves.
    pub irp: VirtAddr,
    pub original_irp: VirtAddr,
    pub srb: VirtAddr,
    /// The SRB, decoded, or why it does not decode.
    pub request: std::result::Result<Srb, String>,
    pub retries: u8,
    pub timed_out: bool,
}

/// A storage class device as `!storagekd.storclass` lists it.
#[derive(Debug, Clone)]
pub struct ClassDevice {
    /// `_CLASS_PRIVATE_FDO_DATA`, the entry on `classpnp!AllFdosList`.
    pub private: VirtAddr,
    /// The FDO and its `_FUNCTIONAL_DEVICE_EXTENSION`; `None` when no
    /// transfer packet names the FDO.
    pub fdo: Option<VirtAddr>,
    pub extension: Option<VirtAddr>,
    /// The class driver's service name (`disk`).
    pub driver: Option<String>,
    pub device_number: Option<u32>,
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub revision: Option<String>,
    pub serial: Option<String>,
    /// `STORAGE_BUS_TYPE` without its `BusType` prefix.
    pub bus_type: Option<String>,
    pub removable: bool,
    pub boot_device: bool,
    pub packets: ClassPackets,
}

/// One error classpnp logged (`_CLASS_ERROR_LOG_DATA`): the SRB that failed
/// and its sense data.
#[derive(Debug, Clone)]
pub struct ClassErrorLogEntry {
    pub tick: u64,
    /// Seconds from the error to the guest's current tick count.
    pub age_seconds: Option<f64>,
    pub port: u32,
    pub paging: bool,
    pub retried: bool,
    pub unhandled: bool,
    pub srb_status: u8,
    pub scsi_status: u8,
    pub path_target_lun: (u8, u8, u8),
    pub cdb: Vec<u8>,
    pub sense: Option<String>,
}

/// One storage class device in detail.
#[derive(Debug, Clone)]
pub struct ClassDeviceDetail {
    pub device: ClassDevice,
    /// The lower device object, and the PDO under the stack.
    pub lower_device: VirtAddr,
    pub lower_pdo: VirtAddr,
    pub bytes_per_sector: u32,
    /// `PartitionLength` of partition zero: the device's capacity in bytes.
    pub length: u64,
    /// `TimeOutValue` in seconds.
    pub timeout: u32,
    pub max_retries: u8,
    pub error_count: u32,
    /// The errors still in the 16-entry log, oldest first.
    pub errors: Vec<ClassErrorLogEntry>,
}

/// The storage class devices on `classpnp!AllFdosList`.
#[derive(Debug, Clone)]
pub struct ClassDeviceList {
    pub devices: Vec<std::result::Result<ClassDevice, (VirtAddr, String)>>,
    pub stopped: Option<String>,
}

fn class_layout(types: Types<'_>, name: &str) -> Result<Arc<TypeInfo>> {
    types.layout(format!("classpnp!{name}")).map_err(|_| {
        Error::DebugInfo(format!(
            "classpnp's symbols do not describe {name}; is classpnp.sys loaded with its PDB \
             (.reload classpnp.sys)?"
        ))
    })
}

/// The NUL-terminated ASCII string at `offset` into a descriptor, trimmed;
/// `None` for offset 0 (no string) or one past the bytes read.
fn descriptor_string(bytes: &[u8], offset: u64) -> Option<String> {
    let start = usize::try_from(offset).ok().filter(|&start| start != 0)?;
    let rest = bytes.get(start..)?;
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    let text = String::from_utf8_lossy(&rest[..end]).trim().to_string();
    (!text.is_empty()).then_some(text)
}

/// classpnp's layouts, resolved once per command.
struct ClassTypes<'a> {
    types: Types<'a>,
    private: Arc<TypeInfo>,
    extension: Arc<TypeInfo>,
    packet: Arc<TypeInfo>,
}

impl<'a> ClassTypes<'a> {
    fn at(&self, layout: &Arc<TypeInfo>, address: VirtAddr) -> StructRef<'a> {
        self.types.struct_with_layout(Arc::clone(layout), address)
    }
}

impl Target {
    fn class_types(&self) -> Result<ClassTypes<'_>> {
        let types = self.types_in(self.kernel_dtb());
        Ok(ClassTypes {
            private: class_layout(types, "_CLASS_PRIVATE_FDO_DATA")?,
            extension: class_layout(types, "_FUNCTIONAL_DEVICE_EXTENSION")?,
            packet: class_layout(types, "_TRANSFER_PACKET")?,
            types,
        })
    }

    /// The `_CLASS_PRIVATE_FDO_DATA` on `classpnp!AllFdosList`, and why the
    /// walk stopped short of its head.
    fn class_private_list(
        &self,
        class: &ClassTypes<'_>,
    ) -> Result<(Vec<VirtAddr>, Option<String>)> {
        let head = self
            .symbols
            .find_symbol_across_modules(self.kernel_dtb(), "classpnp!AllFdosList")?
            .ok_or_else(|| {
                Error::DebugInfo(
                    "classpnp!AllFdosList is not in classpnp's symbols; is classpnp.sys loaded \
                     with its PDB (.reload classpnp.sys)?"
                        .into(),
                )
            })?;
        let link = class.private.field_offset("AllFdosListEntry")?;
        let memory = self.kernel_address_space();
        let (links, termination) =
            bounded_list_walk(head, MAX_CLASS_DEVICES, |at| memory.read::<VirtAddr>(at));
        Ok((
            links.into_iter().map(|at| at - link).collect(),
            termination.diagnostic(),
        ))
    }

    /// The storage class devices on `classpnp!AllFdosList`.
    pub fn classpnp_devices(&self) -> Result<ClassDeviceList> {
        let class = self.class_types()?;
        let (privates, stopped) = self.class_private_list(&class)?;
        let devices = privates
            .into_iter()
            .map(|private| {
                self.class_device(&class, private, false)
                    .map_err(|error| (private, error.to_string()))
            })
            .collect();
        Ok(ClassDeviceList { devices, stopped })
    }

    /// The class device at `address`: its FDO, its device extension, or its
    /// private data.
    pub fn classpnp_device(&self, address: VirtAddr) -> Result<ClassDeviceDetail> {
        let class = self.class_types()?;
        let (privates, _) = self.class_private_list(&class)?;
        let private = self.class_resolve(&class, &privates, address)?;
        let device = self.class_device(&class, private, true)?;
        let private_data = class.at(&class.private, private).prefetch();
        let (mut lower_device, mut lower_pdo, mut bytes_per_sector) = (VirtAddr(0), VirtAddr(0), 0);
        let (mut length, mut timeout, mut error_count) = (0, 0, 0);
        if let Some(extension) = device.extension {
            let fde = class.at(&class.extension, extension).prefetch();
            let common = fde.embedded("CommonExtension")?;
            lower_device = common.read_pointer("LowerDeviceObject")?;
            lower_pdo = fde.read_pointer("LowerPdo")?;
            bytes_per_sector = fde.embedded("DiskGeometry")?.read_uint("BytesPerSector")? as u32;
            length = common.embedded("PartitionLength")?.read_uint("QuadPart")?;
            timeout = fde.read_uint("TimeOutValue")? as u32;
            error_count = fde.read_uint("ErrorCount")? as u32;
        }
        Ok(ClassDeviceDetail {
            lower_device,
            lower_pdo,
            bytes_per_sector,
            length,
            timeout,
            max_retries: private_data.read_uint("MaxNumberOfIoRetries")? as u8,
            error_count,
            errors: self.class_error_log(&class, &private_data)?,
            device,
        })
    }

    /// The private data `address` names: one on the list, or a device
    /// object or device extension whose `PrivateFdoData` is.
    fn class_resolve(
        &self,
        class: &ClassTypes<'_>,
        privates: &[VirtAddr],
        address: VirtAddr,
    ) -> Result<VirtAddr> {
        if privates.contains(&address) {
            return Ok(address);
        }
        let listed_private = |extension: VirtAddr| -> Option<VirtAddr> {
            let private = class
                .at(&class.extension, extension)
                .read_pointer("PrivateFdoData")
                .ok()?;
            privates.contains(&private).then_some(private)
        };
        if let Some(extension) = self.device_extension_of(address)
            && let Some(private) = listed_private(extension)
        {
            return Ok(private);
        }
        if let Some(private) = listed_private(address) {
            return Ok(private);
        }
        Err(Error::DebugInfo(format!(
            "{:#x} is not a classpnp FDO, its device extension, or its private data on \
             classpnp!AllFdosList; !storagekd.storclass lists them",
            address.0
        )))
    }

    /// The `DeviceExtension` of the device object at `address`; `None` when
    /// it is not a device object.
    fn device_extension_of(&self, address: VirtAddr) -> Option<VirtAddr> {
        let device = self
            .types_in(self.kernel_dtb())
            .struct_at("_DEVICE_OBJECT", address)
            .ok()?;
        (device.read_uint("Type").ok()? == IO_TYPE_DEVICE)
            .then(|| device.read_pointer("DeviceExtension").ok())
            .flatten()
    }

    fn class_device(
        &self,
        class: &ClassTypes<'_>,
        private: VirtAddr,
        decode_requests: bool,
    ) -> Result<ClassDevice> {
        let private_data = class.at(&class.private, private).prefetch();
        let (packets, fdo) = self.class_packets(class, &private_data, decode_requests)?;
        // The FDO a packet names is this device's when its extension's
        // private data is this one.
        let extension = fdo
            .and_then(|fdo| self.device_extension_of(fdo))
            .filter(|&extension| {
                class
                    .at(&class.extension, extension)
                    .read_pointer("PrivateFdoData")
                    .is_ok_and(|back| back == private)
            });
        let fdo = extension.and(fdo);
        let mut device = ClassDevice {
            private,
            fdo,
            extension,
            driver: None,
            device_number: None,
            vendor: None,
            product: None,
            revision: None,
            serial: None,
            bus_type: None,
            removable: false,
            boot_device: private_data.read_uint("IsBootDevice")? != 0,
            packets,
        };
        if let (Some(fdo), Some(extension)) = (fdo, extension) {
            let fde = class.at(&class.extension, extension).prefetch();
            device.device_number = Some(fde.read_uint("DeviceNumber")? as u32);
            device.driver = self.class_driver_name(fdo);
            let descriptor = fde.read_pointer("DeviceDescriptor")?;
            if !descriptor.is_zero() {
                self.class_descriptor(class.types, descriptor, &mut device)?;
            }
        }
        Ok(device)
    }

    /// The service name of the driver of the device object `fdo`.
    fn class_driver_name(&self, fdo: VirtAddr) -> Option<String> {
        let types = self.types_in(self.kernel_dtb());
        let driver = types
            .struct_at("_DEVICE_OBJECT", fdo)
            .ok()?
            .read_pointer("DriverObject")
            .ok()?;
        let name = types
            .struct_at("_DRIVER_OBJECT", driver)
            .ok()?
            .unicode_string("DriverName")
            .ok()?;
        Some(name.rsplit('\\').next().unwrap_or(&name).to_string())
    }

    /// The identity strings and bus of a `STORAGE_DEVICE_DESCRIPTOR`.
    fn class_descriptor(
        &self,
        types: Types<'_>,
        address: VirtAddr,
        device: &mut ClassDevice,
    ) -> Result<()> {
        let layout = class_layout(types, "_STORAGE_DEVICE_DESCRIPTOR")?;
        let descriptor = types.struct_with_layout(layout, address).prefetch();
        let size = descriptor.read_uint("Size")?.min(MAX_DESCRIPTOR);
        let mut bytes = vec![0u8; size as usize];
        self.kernel_address_space()
            .read_bytes(address, &mut bytes)?;
        let string = |field: &str| -> Result<Option<String>> {
            Ok(descriptor_string(&bytes, descriptor.read_uint(field)?))
        };
        device.vendor = string("VendorIdOffset")?;
        device.product = string("ProductIdOffset")?;
        device.revision = string("ProductRevisionOffset")?;
        device.serial = string("SerialNumberOffset")?;
        device.removable = descriptor.read_uint("RemovableMedia")? != 0;
        let bus = descriptor.read_uint("BusType")?;
        device.bus_type = self
            .symbols
            .find_enum_across_modules(self.kernel_dtb(), "classpnp!_STORAGE_BUS_TYPE")
            .unwrap_or_default()
            .into_iter()
            .find(|(_, value)| *value as u64 == bus)
            .map(|(name, _)| name.strip_prefix("BusType").unwrap_or(&name).to_string());
        Ok(())
    }

    /// The device's transfer packets, and the FDO the first one names. A
    /// packet is free when it is on one of the per-node free lists; every
    /// other packet on `AllTransferPacketsList` is in flight.
    fn class_packets(
        &self,
        class: &ClassTypes<'_>,
        private: &StructRef<'_>,
        decode_requests: bool,
    ) -> Result<(ClassPackets, Option<VirtAddr>)> {
        let memory = self.kernel_address_space();
        let mut packets = ClassPackets::default();
        let all = private.addr() + private.layout().field_offset("AllTransferPacketsList")?;
        let list_link = class.packet.field_offset("AllPktsListEntry")?;
        let (links, termination) =
            bounded_list_walk(all, MAX_TRANSFER_PACKETS, |at| memory.read::<VirtAddr>(at));
        packets.stopped.extend(
            termination
                .diagnostic()
                .map(|why| format!("packet list: {why}")),
        );
        let all_packets: Vec<VirtAddr> = links.into_iter().map(|at| at - list_link).collect();

        // classpnp frees a packet to its processor's list, and moves packets
        // between those and the per-node lists; a packet on neither, nor
        // held for forward progress, is in flight.
        let mut free = HashSet::new();
        let slist_link = class.packet.field_offset("SlistEntry")?;
        // An SLIST_HEADER on x64 and ARM64 holds the first entry in bits
        // 4-63 of its second quadword.
        let mut walk_free = |header: &StructRef<'_>, field: &str, owner: String| -> Result<()> {
            let slist = header.read_field_bytes(field, 16)?;
            let mut entry = VirtAddr(le_uint(&slist[8..16]) & !0xf);
            let mut walked = 0;
            while !entry.is_zero() {
                walked += 1;
                if walked > MAX_TRANSFER_PACKETS {
                    packets.stopped.push(format!(
                        "{owner}'s free list runs past {MAX_TRANSFER_PACKETS} packets"
                    ));
                    break;
                }
                if !free.insert(entry - slist_link) {
                    packets
                        .stopped
                        .push(format!("{owner}'s free list repeats {:#x}", entry.0));
                    break;
                }
                match memory.read::<VirtAddr>(entry) {
                    Ok(next) => entry = next,
                    Err(error) => {
                        packets
                            .stopped
                            .push(format!("{owner}'s free list at {:#x}: {error}", entry.0));
                        break;
                    }
                }
            }
            Ok(())
        };
        let node_lists = private.read_pointer("FreeTransferPacketsLists")?;
        if !node_lists.is_zero() {
            let layout = class_layout(class.types, "_PNL_SLIST_HEADER")?;
            for node in 0..self.class_node_count().min(MAX_NODES) {
                let header = class.at(&layout, node_lists + node * layout.size as u64);
                walk_free(&header, "SListHeader", format!("node {node}"))?;
            }
        }
        let processor_lists = private.read_pointer("PerProcessorData")?;
        if !processor_lists.is_zero() {
            let layout = class_layout(class.types, "_PP_FDO_DATA")?;
            let processors = processor_count(self).map_or(1, u64::from);
            for processor in 0..processors {
                let header = class.at(&layout, processor_lists + processor * layout.size as u64);
                walk_free(&header, "FreePackets", format!("processor {processor}"))?;
            }
        }
        let reserved = private.read_pointer("ForwardProgressPacket")?;
        if !reserved.is_zero() {
            free.insert(reserved - slist_link);
        }
        packets.total = all_packets.len() as u64;
        packets.free = all_packets
            .iter()
            .filter(|packet| free.contains(packet))
            .count() as u64;

        let mut fdo = None;
        for &address in &all_packets {
            let packet = class.at(&class.packet, address).prefetch();
            if fdo.is_none() {
                fdo = packet.read_pointer("Fdo").ok().filter(|fdo| !fdo.is_zero());
            }
            if free.contains(&address) {
                continue;
            }
            let srb = packet.read_pointer("Srb")?;
            let request = if !decode_requests {
                Err(String::new())
            } else if srb.is_zero() {
                Err("no SRB".into())
            } else {
                self.decode_srb(srb).map_err(|error| error.to_string())
            };
            packets.in_flight.push(TransferPacket {
                address,
                irp: packet.read_pointer("Irp")?,
                original_irp: packet.read_pointer("OriginalIrp")?,
                srb,
                request,
                retries: packet.read_uint("NumRetries")? as u8,
                timed_out: packet.read_uint("TimedOut")? != 0,
            });
        }
        Ok((packets, fdo))
    }

    /// `nt!KeNumberNodes`, the NUMA nodes classpnp keeps a free list for;
    /// 1 when it does not read.
    fn class_node_count(&self) -> u64 {
        self.symbols
            .find_symbol_across_modules(self.kernel_dtb(), "nt!KeNumberNodes")
            .ok()
            .flatten()
            .and_then(|at| self.kernel_address_space().read::<u16>(at).ok())
            .map_or(1, |nodes| u64::from(nodes.max(1)))
    }

    /// The errors in the private data's 16-entry log, oldest first, from
    /// `ErrorLogNextIndex`, the slot classpnp writes next.
    fn class_error_log(
        &self,
        class: &ClassTypes<'_>,
        private: &StructRef<'_>,
    ) -> Result<Vec<ClassErrorLogEntry>> {
        let layout = class_layout(class.types, "_CLASS_ERROR_LOG_DATA")?;
        let entry_size = layout.size as u64;
        let logs_at = private.addr() + private.layout().field_offset("ErrorLogs")?;
        let slots = private.layout().field("ErrorLogs")?.size / entry_size.max(1);
        let next = private.read_uint("ErrorLogNextIndex")?;
        let kuser = KuserSharedData::new(self);
        let now = kuser.tick_count();
        let increment = self
            .symbols
            .find_symbol_across_modules(self.kernel_dtb(), "nt!KeMaximumIncrement")
            .ok()
            .flatten()
            .and_then(|at| self.kernel_address_space().read::<u32>(at).ok());
        let mut errors = Vec::new();
        for step in 0..slots {
            let slot = (next + step) % slots;
            let entry = class
                .types
                .struct_with_layout(Arc::clone(&layout), logs_at + slot * entry_size)
                .prefetch();
            let tick = entry.embedded("TickCount")?.read_uint("QuadPart")?;
            if tick == 0 {
                continue;
            }
            let srb = entry.embedded("Srb")?;
            let cdb_length = (srb.read_uint("CdbLength")? as usize).min(16);
            let mut cdb = srb.read_field_bytes("Cdb", 16)?;
            cdb.truncate(cdb_length);
            let sense = entry.read_field_bytes("SenseData", 18)?;
            errors.push(ClassErrorLogEntry {
                tick,
                age_seconds: now.zip(increment).and_then(|(now, increment)| {
                    (now >= tick).then(|| (now - tick) as f64 * f64::from(increment) / 10_000_000.0)
                }),
                port: entry.read_uint("PortNumber")? as u32,
                paging: entry.read_bits("ErrorPaging")? != 0,
                retried: entry.read_bits("ErrorRetried")? != 0,
                unhandled: entry.read_bits("ErrorUnhandled")? != 0,
                srb_status: srb.read_uint("SrbStatus")? as u8,
                scsi_status: srb.read_uint("ScsiStatus")? as u8,
                path_target_lun: (
                    srb.read_uint("PathId")? as u8,
                    srb.read_uint("TargetId")? as u8,
                    srb.read_uint("Lun")? as u8,
                ),
                cdb,
                sense: sense_text(&sense),
            });
        }
        Ok(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_strings_stop_at_nul_and_offset_zero_means_none() {
        let mut bytes = vec![0u8; 0x40];
        bytes[0x28..0x2d].copy_from_slice(b"QEMU ");
        bytes[0x30..0x3d].copy_from_slice(b"QEMU HARDDISK");
        assert_eq!(descriptor_string(&bytes, 0x28).as_deref(), Some("QEMU"));
        assert_eq!(
            descriptor_string(&bytes, 0x30).as_deref(),
            Some("QEMU HARDDISK")
        );
        assert_eq!(descriptor_string(&bytes, 0), None);
        // An offset past what was read, or to an empty string.
        assert_eq!(descriptor_string(&bytes, 0x80), None);
        assert_eq!(descriptor_string(&bytes, 0x3e), None);
    }
}
