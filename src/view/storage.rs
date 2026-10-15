//! Storage (`!storagekd.*`) as SDK records: StorPort's drivers, adapters,
//! units, and adapter log, SRBs, and classpnp's class devices.

use ntoseye_macros::record;

use crate::target::classpnp::{self, ClassDevice as TargetClassDevice};
use crate::target::etw::format_filetime_precise;
use crate::target::srb::{self, srb_flag_names, srb_function_name, srb_status_text};
use crate::target::storport::{self, StorEnum, adapter_verdict, log_request, unit_verdict};
use crate::target::virtio_request::scsi_command;
use crate::types::VirtAddr;

/// A value of one of storport's enums, with its name when the PDB has
/// one.
#[record]
pub struct StorEnumValue {
    #[record(hex)]
    pub value: u64,
    pub name: Option<String>,
}

/// An adapter's I/O gateway (`_STOR_IO_GATEWAY`).
#[record]
pub struct StorGateway {
    pub address: VirtAddr,
    /// Requests the miniport holds, and the most the gateway lets it.
    pub outstanding: u32,
    pub outstanding_max: u32,
    /// Requests waiting for the gateway.
    pub pending: u32,
    pub busy: u32,
    pub paused: i32,
}

/// A request the miniport holds (`_EXTENDED_REQUEST_BLOCK`).
#[record]
pub struct StorRequest {
    pub xrb: VirtAddr,
    pub irp: VirtAddr,
    pub srb: VirtAddr,
    /// The processor whose pending queue holds it.
    pub processor: u32,
}

/// A unit's device queue (`_EXTENDED_DEVICE_QUEUE`).
#[record]
pub struct StorQueue {
    pub depth: i32,
    pub pause_count: i32,
    pub busy_count: i32,
    pub frozen: bool,
    pub locked: bool,
    pub untagged: bool,
    pub power_locked: bool,
    pub bypass_count: i32,
    /// Requests waiting because the queue is full or held.
    pub waiting: usize,
    pub bypass_waiting: usize,
    pub waiting_stopped: Vec<String>,
}

/// A logical unit (`_RAID_UNIT_EXTENSION`).
#[record]
pub struct StorUnit {
    pub extension: VirtAddr,
    pub device_object: VirtAddr,
    pub adapter: VirtAddr,
    pub path: u8,
    pub target: u8,
    pub lun: u8,
    pub vendor: String,
    pub product: String,
    pub revision: String,
    pub state: StorEnumValue,
    pub device_power: StorEnumValue,
    pub flags: Vec<String>,
    /// The miniport's per-unit extension; null when it asked for none.
    pub lu_extension: VirtAddr,
    pub max_queue_depth: u32,
    pub queue: StorQueue,
    /// What holds the unit's requests, as `!storagekd.storunit` says it:
    /// `idle`, `1 with the miniport`, `frozen`, ...
    pub io: String,
    pub requests: Vec<StorRequest>,
    pub requests_stopped: Vec<String>,
}

/// A unit on an adapter's list, or why it is not shown.
#[record]
pub struct StorUnitEntry {
    pub extension: VirtAddr,
    pub unit: Option<StorUnit>,
    pub error: Option<String>,
}

/// A StorPort adapter (`_RAID_ADAPTER_EXTENSION`).
#[record]
pub struct StorAdapter {
    pub extension: VirtAddr,
    /// The `_RAID_DRIVER_EXTENSION`.
    pub driver: VirtAddr,
    pub driver_object: VirtAddr,
    pub driver_name: String,
    pub fdo: VirtAddr,
    pub pdo: VirtAddr,
    pub lower: VirtAddr,
    /// The FDO's full name, its `Device` directory included
    /// (`RaidPort0`).
    pub device_name: String,
    pub port_number: u32,
    pub miniport_name: Option<String>,
    pub adapter_id: Option<String>,
    pub state: StorEnumValue,
    pub flags: Vec<String>,
    pub interface: StorEnumValue,
    /// `bb:dd.f` of a PCI adapter.
    pub pci_location: Option<String>,
    pub virtual_miniport: bool,
    /// The miniport's own device extension (`HwDeviceExtension`).
    pub hw_device_extension: VirtAddr,
    #[record(hex)]
    pub hw_device_extension_size: Option<u64>,
    #[record(hex)]
    pub lu_extension_size: Option<u64>,
    pub system_power: StorEnumValue,
    pub device_power: StorEnumValue,
    pub paging_paths: u32,
    pub dump_paths: u32,
    pub hiber_paths: u32,
    pub pause_count: u32,
    pub busy_count: u32,
    /// What holds the adapter's requests: `idle`, `2 with the miniport`,
    /// `paused`, ...
    pub io: String,
    pub gateways: Vec<StorGateway>,
    pub gateways_error: Option<String>,
    pub units: Vec<StorUnitEntry>,
    pub units_stopped: Option<String>,
}

/// An adapter on a driver's list, or why it is not shown.
#[record]
pub struct StorAdapterEntry {
    pub extension: VirtAddr,
    pub adapter: Option<StorAdapter>,
    pub error: Option<String>,
}

/// A driver that called `StorPortInitialize`.
#[record]
pub struct StorDriver {
    pub extension: VirtAddr,
    pub driver_object: VirtAddr,
    /// The service name (`storahci`).
    pub name: String,
    pub adapters: Vec<StorAdapterEntry>,
    pub stopped: Option<String>,
}

/// storport's drivers and their adapters (`!storagekd.storadapter`).
#[record]
pub struct StorDrivers {
    /// `storport!RaidpPortData`.
    pub port_data: VirtAddr,
    pub drivers: Vec<StorDriver>,
    pub stopped: Option<String>,
}

/// An entry of an adapter's log (`_RAID_LOG_ENTRY`).
#[record]
pub struct StorLogEntry {
    /// storport numbers entries from 1 as it writes them.
    pub number: u64,
    /// When storport wrote it, a FILETIME (UTC).
    pub time: u64,
    pub time_utc: Option<String>,
    /// `_DBG_LOG_REASON` without its `Log` prefix.
    pub event: Option<String>,
    #[record(hex)]
    pub event_value: u64,
    #[record(hex)]
    pub parameters: Vec<u64>,
    /// For an entry of the request path: its IRP, SRB, CDB operation
    /// code, command, and SRB status.
    pub irp: Option<VirtAddr>,
    pub srb: Option<VirtAddr>,
    #[record(hex)]
    pub opcode: Option<u8>,
    pub command: Option<String>,
    pub srb_status: Option<String>,
}

/// An adapter's internal log (`!storagekd.storloglist`).
#[record]
pub struct StorLog {
    pub adapter: VirtAddr,
    pub driver_name: String,
    /// The ring (`RaidLogList`) and its size.
    pub ring: VirtAddr,
    pub size: u32,
    /// The number of the newest entry.
    pub newest: u64,
    /// The entries still in the ring, oldest first.
    pub entries: Vec<StorLogEntry>,
}

/// One block of an extended SRB's extended data.
#[record]
pub struct SrbExData {
    pub address: VirtAddr,
    /// `_SRBEXDATATYPE` without its prefix (`ScsiCdb16`).
    pub kind: String,
    pub length: u32,
}

/// An SRB (`!storagekd.storsrb`).
#[record]
pub struct Srb {
    pub address: VirtAddr,
    /// A `STORAGE_REQUEST_BLOCK`, rather than a `SCSI_REQUEST_BLOCK`.
    pub extended: bool,
    #[record(hex)]
    pub function: u32,
    pub function_name: Option<&'static str>,
    #[record(hex)]
    pub srb_status: u8,
    /// The status by name, with `QUEUE_FROZEN` and `AUTOSENSE_VALID`.
    pub srb_status_text: String,
    #[record(hex)]
    pub scsi_status: Option<u8>,
    #[record(hex)]
    pub flags: u32,
    pub flag_names: Vec<String>,
    /// An extended SRB's port; a legacy one has none.
    pub port: Option<u16>,
    pub path: Option<u8>,
    pub target: Option<u8>,
    pub lun: Option<u8>,
    pub data_transfer_length: u32,
    pub data_buffer: VirtAddr,
    /// Seconds.
    pub timeout: u32,
    /// `OriginalRequest`: the IRP.
    pub original_request: VirtAddr,
    pub next_srb: VirtAddr,
    #[record(hex)]
    pub request_tag: Option<u32>,
    pub priority: Option<u16>,
    pub cdb: Vec<u8>,
    /// The CDB's command, with its LBA and block count when it has them.
    pub command: Option<String>,
    pub sense_buffer: VirtAddr,
    pub sense_length: u8,
    /// The sense data, decoded, when `AUTOSENSE_VALID` says it is valid.
    pub sense: Option<String>,
    pub class_context: Option<VirtAddr>,
    pub port_context: Option<VirtAddr>,
    pub miniport_context: Option<VirtAddr>,
    pub ex_data: Vec<SrbExData>,
}

/// A transfer packet classpnp has in flight.
#[record]
pub struct ClassTransferPacket {
    pub address: VirtAddr,
    /// The IRP classpnp sent down, and the client's IRP it serves.
    pub irp: VirtAddr,
    pub original_irp: VirtAddr,
    pub srb: VirtAddr,
    /// The SRB, decoded.
    pub request: Option<Srb>,
    /// Why `request` does not decode.
    pub request_error: Option<String>,
    pub retries_left: u8,
    pub timed_out: bool,
}

/// A storage class device (`!storagekd.storclass`).
#[record]
pub struct ClassDevice {
    /// `_CLASS_PRIVATE_FDO_DATA`, its entry on `classpnp!AllFdosList`.
    pub private_data: VirtAddr,
    /// `None` when no transfer packet names the FDO.
    pub fdo: Option<VirtAddr>,
    pub extension: Option<VirtAddr>,
    /// The class driver's service name (`disk`).
    pub driver: Option<String>,
    pub device_number: Option<u32>,
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub revision: Option<String>,
    pub serial: Option<String>,
    pub bus_type: Option<String>,
    pub removable: bool,
    pub boot_device: bool,
    /// The transfer packets on `AllTransferPacketsList`, and those on a
    /// free list.
    pub packets_total: u64,
    pub packets_free: u64,
    pub in_flight: Vec<ClassTransferPacket>,
    pub packets_stopped: Vec<String>,
}

/// A class device whose private data does not read.
#[record]
pub struct ClassUnreadable {
    pub private_data: VirtAddr,
    pub error: String,
}

/// The class devices on `classpnp!AllFdosList`.
#[record]
pub struct ClassDevices {
    pub devices: Vec<ClassDevice>,
    pub unreadable: Vec<ClassUnreadable>,
    pub stopped: Option<String>,
}

/// An error classpnp logged (`_CLASS_ERROR_LOG_DATA`).
#[record]
pub struct ClassError {
    pub tick: u64,
    /// Milliseconds from the error to the guest's current tick count.
    pub age_ms: Option<u64>,
    /// `None` where classpnp did not know the port.
    pub port: Option<u32>,
    pub path: u8,
    pub target: u8,
    pub lun: u8,
    pub paging: bool,
    pub retried: bool,
    pub unhandled: bool,
    #[record(hex)]
    pub srb_status: u8,
    pub srb_status_text: String,
    #[record(hex)]
    pub scsi_status: u8,
    pub cdb: Vec<u8>,
    pub command: Option<String>,
    pub sense: Option<String>,
}

/// One class device in detail.
#[record]
pub struct ClassDeviceDetail {
    pub device: ClassDevice,
    pub lower_device: VirtAddr,
    pub lower_pdo: VirtAddr,
    pub bytes_per_sector: u32,
    /// Bytes.
    pub length: u64,
    /// Seconds.
    pub timeout: u32,
    pub max_retries: u8,
    pub error_count: u32,
    /// The errors still in the 16-entry log, oldest first.
    pub errors: Vec<ClassError>,
}

fn enum_value(value: &StorEnum) -> StorEnumValue {
    StorEnumValue {
        value: value.value,
        name: value.name.clone(),
    }
}

fn unit(unit: &storport::StorUnit) -> StorUnit {
    let queue = &unit.queue;
    StorUnit {
        extension: unit.extension,
        device_object: unit.device_object,
        adapter: unit.adapter,
        path: unit.address.path,
        target: unit.address.target,
        lun: unit.address.lun,
        vendor: unit.vendor.clone(),
        product: unit.product.clone(),
        revision: unit.revision.clone(),
        state: enum_value(&unit.state),
        device_power: enum_value(&unit.device_power),
        flags: unit.flags.clone(),
        lu_extension: unit.lu_extension,
        max_queue_depth: unit.max_queue_depth,
        queue: StorQueue {
            depth: queue.depth,
            pause_count: queue.pause_count,
            busy_count: queue.busy_count,
            frozen: queue.frozen,
            locked: queue.locked,
            untagged: queue.untagged,
            power_locked: queue.power_locked,
            bypass_count: queue.bypass_count,
            waiting: queue.waiting,
            bypass_waiting: queue.bypass_waiting,
            waiting_stopped: queue.waiting_stopped.clone(),
        },
        io: unit_verdict(queue, unit.requests.len()),
        requests: unit
            .requests
            .iter()
            .map(|request| StorRequest {
                xrb: request.xrb,
                irp: request.irp,
                srb: request.srb,
                processor: request.processor,
            })
            .collect(),
        requests_stopped: unit.requests_stopped.clone(),
    }
}

pub fn adapter(adapter: &storport::StorAdapter) -> StorAdapter {
    StorAdapter {
        extension: adapter.extension,
        driver: adapter.driver,
        driver_object: adapter.driver_object,
        driver_name: adapter.driver_name.clone(),
        fdo: adapter.fdo,
        pdo: adapter.pdo,
        lower: adapter.lower,
        device_name: adapter.device_name.clone(),
        port_number: adapter.port_number,
        miniport_name: adapter.miniport_name.clone(),
        adapter_id: adapter.adapter_id.clone(),
        state: enum_value(&adapter.state),
        flags: adapter.flags.clone(),
        interface: enum_value(&adapter.interface),
        pci_location: adapter
            .pci
            .map(|(bus, device, function)| format!("{bus:02x}:{device:02x}.{function:x}")),
        virtual_miniport: adapter.virtual_miniport,
        hw_device_extension: adapter.hw_device_extension,
        hw_device_extension_size: adapter.hw_device_extension_size,
        lu_extension_size: adapter.lu_extension_size,
        system_power: enum_value(&adapter.system_power),
        device_power: enum_value(&adapter.device_power),
        paging_paths: adapter.paging_paths,
        dump_paths: adapter.dump_paths,
        hiber_paths: adapter.hiber_paths,
        pause_count: adapter.pause_count,
        busy_count: adapter.busy_count,
        io: adapter_verdict(adapter),
        gateways: adapter
            .gateways
            .iter()
            .map(|gateway| StorGateway {
                address: gateway.address,
                outstanding: gateway.outstanding,
                outstanding_max: gateway.outstanding_max,
                pending: gateway.pending,
                busy: gateway.busy,
                paused: gateway.paused,
            })
            .collect(),
        gateways_error: adapter.gateways_error.clone(),
        units: adapter
            .units
            .iter()
            .map(|entry| match &entry.unit {
                Ok(value) => StorUnitEntry {
                    extension: entry.extension,
                    unit: Some(unit(value)),
                    error: None,
                },
                Err(error) => StorUnitEntry {
                    extension: entry.extension,
                    unit: None,
                    error: Some(error.clone()),
                },
            })
            .collect(),
        units_stopped: adapter.units_stopped.clone(),
    }
}

pub fn unit_detail(detail: &storport::StorUnit) -> StorUnit {
    unit(detail)
}

pub fn drivers(drivers: &storport::StorPortDrivers) -> StorDrivers {
    StorDrivers {
        port_data: drivers.port_data,
        drivers: drivers
            .drivers
            .iter()
            .map(|driver| StorDriver {
                extension: driver.extension,
                driver_object: driver.driver_object,
                name: driver.name.clone(),
                adapters: driver
                    .adapters
                    .iter()
                    .map(|entry| match &entry.adapter {
                        Ok(value) => StorAdapterEntry {
                            extension: entry.extension,
                            adapter: Some(adapter(value)),
                            error: None,
                        },
                        Err(error) => StorAdapterEntry {
                            extension: entry.extension,
                            adapter: None,
                            error: Some(error.clone()),
                        },
                    })
                    .collect(),
                stopped: driver.stopped.clone(),
            })
            .collect(),
        stopped: drivers.stopped.clone(),
    }
}

pub fn log(log: &storport::StorLog) -> StorLog {
    StorLog {
        adapter: log.adapter,
        driver_name: log.driver_name.clone(),
        ring: log.ring,
        size: log.size,
        newest: log.newest,
        entries: log
            .entries
            .iter()
            .map(|entry| {
                let request = log_request(entry);
                StorLogEntry {
                    number: entry.number,
                    time: entry.time,
                    time_utc: format_filetime_precise(entry.time),
                    event: entry
                        .reason
                        .name
                        .as_deref()
                        .map(|name| name.strip_prefix("Log").unwrap_or(name).to_string()),
                    event_value: entry.reason.value,
                    parameters: entry.parameters.to_vec(),
                    irp: request.map(|request| request.irp),
                    srb: request.map(|request| request.srb),
                    opcode: request.map(|request| request.opcode),
                    command: request.and_then(|request| scsi_command(&[request.opcode])),
                    srb_status: request.map(|request| srb_status_text(request.srb_status)),
                }
            })
            .collect(),
    }
}

pub fn srb(srb: &srb::Srb) -> Srb {
    let (path, target, lun) = match srb.path_target_lun {
        Some((path, target, lun)) => (Some(path), Some(target), Some(lun)),
        None => (None, None, None),
    };
    let [class_context, port_context, miniport_context] = match srb.contexts {
        Some(contexts) => contexts.map(Some),
        None => [None; 3],
    };
    Srb {
        address: srb.address,
        extended: srb.extended,
        function: srb.function,
        function_name: srb_function_name(srb.function),
        srb_status: srb.srb_status,
        srb_status_text: srb_status_text(srb.srb_status),
        scsi_status: srb.scsi_status,
        flags: srb.flags,
        flag_names: srb_flag_names(srb.flags),
        port: srb.port,
        path,
        target,
        lun,
        data_transfer_length: srb.data_transfer_length,
        data_buffer: srb.data_buffer,
        timeout: srb.timeout,
        original_request: srb.original_request,
        next_srb: srb.next_srb,
        request_tag: srb.request_tag,
        priority: srb.priority,
        cdb: srb.cdb.clone(),
        command: scsi_command(&srb.cdb),
        sense_buffer: srb.sense_buffer,
        sense_length: srb.sense_length,
        sense: srb.sense.clone(),
        class_context,
        port_context,
        miniport_context,
        ex_data: srb
            .ex_data
            .iter()
            .map(|data| SrbExData {
                address: data.address,
                kind: data.kind.clone(),
                length: data.length,
            })
            .collect(),
    }
}

fn class_device(device: &TargetClassDevice) -> ClassDevice {
    ClassDevice {
        private_data: device.private,
        fdo: device.fdo,
        extension: device.extension,
        driver: device.driver.clone(),
        device_number: device.device_number,
        vendor: device.vendor.clone(),
        product: device.product.clone(),
        revision: device.revision.clone(),
        serial: device.serial.clone(),
        bus_type: device.bus_type.clone(),
        removable: device.removable,
        boot_device: device.boot_device,
        packets_total: device.packets.total,
        packets_free: device.packets.free,
        in_flight: device
            .packets
            .in_flight
            .iter()
            .map(|packet| {
                let (request, request_error) = match &packet.request {
                    Ok(value) => (Some(srb(value)), None),
                    Err(error) => (None, Some(error.clone())),
                };
                ClassTransferPacket {
                    address: packet.address,
                    irp: packet.irp,
                    original_irp: packet.original_irp,
                    srb: packet.srb,
                    request,
                    request_error,
                    retries_left: packet.retries,
                    timed_out: packet.timed_out,
                }
            })
            .collect(),
        packets_stopped: device.packets.stopped.clone(),
    }
}

pub fn class_devices(list: &classpnp::ClassDeviceList) -> ClassDevices {
    let mut devices = Vec::new();
    let mut unreadable = Vec::new();
    for entry in &list.devices {
        match entry {
            Ok(device) => devices.push(class_device(device)),
            Err((private_data, error)) => unreadable.push(ClassUnreadable {
                private_data: *private_data,
                error: error.clone(),
            }),
        }
    }
    ClassDevices {
        devices,
        unreadable,
        stopped: list.stopped.clone(),
    }
}

pub fn class_device_detail(detail: &classpnp::ClassDeviceDetail) -> ClassDeviceDetail {
    ClassDeviceDetail {
        device: class_device(&detail.device),
        lower_device: detail.lower_device,
        lower_pdo: detail.lower_pdo,
        bytes_per_sector: detail.bytes_per_sector,
        length: detail.length,
        timeout: detail.timeout,
        max_retries: detail.max_retries,
        error_count: detail.error_count,
        errors: detail
            .errors
            .iter()
            .map(|error| {
                let (path, target, lun) = error.path_target_lun;
                ClassError {
                    tick: error.tick,
                    age_ms: error.age_seconds.map(|seconds| (seconds * 1000.0) as u64),
                    port: (error.port != u32::MAX).then_some(error.port),
                    path,
                    target,
                    lun,
                    paging: error.paging,
                    retried: error.retried,
                    unhandled: error.unhandled,
                    srb_status: error.srb_status,
                    srb_status_text: srb_status_text(error.srb_status),
                    scsi_status: error.scsi_status,
                    cdb: error.cdb.clone(),
                    command: scsi_command(&error.cdb),
                    sense: error.sense.clone(),
                }
            })
            .collect(),
    }
}
