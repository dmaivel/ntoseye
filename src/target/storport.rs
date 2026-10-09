//! StorPort (`!storagekd.storadapter`, `!storagekd.storunit`): the adapters
//! and logical units of StorPort miniports (storahci, stornvme, and the
//! virtio-win viostor and vioscsi), read from storport's own structures and
//! typed by its public PDB. storport keeps every driver that called
//! `StorPortInitialize` on the list of its port data (`RaidpPortData`), each
//! driver's adapters on the driver's extension, and each adapter's units on
//! the adapter's extension, so one walk finds every adapter in the guest.

use std::collections::HashSet;
use std::ops::Range;
use std::sync::Arc;

use super::{Target, bounded_list_walk};
use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::layout::{ParsedType, StructRef, TypeInfo, Types, le_uint, utf16le_nul_terminated};
use crate::types::VirtAddr;

const MAX_DRIVERS: usize = 256;
const MAX_ADAPTERS: usize = 256;
const MAX_UNITS: usize = 4096;
/// The most requests listed from one unit's pending queue.
pub const MAX_LISTED_REQUESTS: usize = 256;
/// The most waiting requests counted on one list of a unit's queue.
const MAX_WAITING: usize = 4096;
/// More per-processor queues than any processor count Windows supports.
const MAX_PROCESSOR_QUEUES: u64 = 2048;
/// More I/O gateways than an adapter allocates, one per hardware queue at
/// most.
const MAX_GATEWAYS: u64 = 1024;
/// The longest miniport name or adapter ID read, in characters.
const MAX_NAME_CHARS: usize = 256;
/// `IO_TYPE_DEVICE`, the `Type` of a `DEVICE_OBJECT`.
const IO_TYPE_DEVICE: u64 = 3;
/// The `_INTERFACE_TYPE` of a PCI adapter, whose bus, device, and function
/// storport records.
const INTERFACE_PCI_BUS: &str = "PCIBus";

/// A value of one of storport's enums, with its name when the PDB has one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorEnum {
    pub value: u64,
    pub name: Option<String>,
}

/// storport's drivers and their adapters, from `RaidpPortData`.
#[derive(Debug, Clone)]
pub struct StorPortDrivers {
    pub port_data: VirtAddr,
    pub drivers: Vec<StorDriver>,
    /// Why the walk of the driver list stopped short of its head.
    pub stopped: Option<String>,
}

/// A driver that called `StorPortInitialize` (`_RAID_DRIVER_EXTENSION`).
#[derive(Debug, Clone)]
pub struct StorDriver {
    pub extension: VirtAddr,
    pub driver_object: VirtAddr,
    /// The service name (`storahci`), from the driver object's name.
    pub name: String,
    pub adapters: Vec<AdapterEntry>,
    /// Why the walk of the adapter list stopped short of its head.
    pub stopped: Option<String>,
}

/// One entry of a driver's adapter list: a StorPort adapter, or why it is
/// not shown.
#[derive(Debug, Clone)]
pub struct AdapterEntry {
    pub extension: VirtAddr,
    pub adapter: std::result::Result<StorAdapter, String>,
}

/// A StorPort adapter (`_RAID_ADAPTER_EXTENSION`), the FDO storport creates
/// for each device the miniport drives.
#[derive(Debug, Clone)]
pub struct StorAdapter {
    pub extension: VirtAddr,
    pub driver: VirtAddr,
    pub driver_object: VirtAddr,
    pub driver_name: String,
    pub fdo: VirtAddr,
    pub pdo: VirtAddr,
    pub lower: VirtAddr,
    /// `\Device\RaidPort0`.
    pub device_name: String,
    /// The SCSI port number (`\\.\Scsi0:`).
    pub port_number: u32,
    pub miniport_name: Option<String>,
    pub adapter_id: Option<String>,
    pub state: StorEnum,
    pub flags: Vec<String>,
    pub interface: StorEnum,
    /// Bus, device, and function of a PCI adapter.
    pub pci: Option<(u32, u32, u32)>,
    /// The miniport registered as a virtual miniport.
    pub virtual_miniport: bool,
    /// The miniport's own device extension, the one StorPort passes to every
    /// Hw routine: the structure its private PDB describes.
    pub hw_device_extension: VirtAddr,
    pub hw_device_extension_size: Option<u64>,
    /// The size of the per-unit extension the miniport asked for.
    pub lu_extension_size: Option<u64>,
    pub system_power: StorEnum,
    pub device_power: StorEnum,
    pub paging_paths: u32,
    pub dump_paths: u32,
    pub hiber_paths: u32,
    /// `StorPortPause` calls not yet resumed.
    pub pause_count: u32,
    /// `StorPortBusy` calls not yet readied.
    pub busy_count: u32,
    pub gateways: Vec<Gateway>,
    /// Why the gateways are not all shown.
    pub gateways_error: Option<String>,
    pub units: Vec<UnitEntry>,
    /// Why the walk of the unit list stopped short of its head.
    pub units_stopped: Option<String>,
}

/// An adapter's I/O gateway (`_STOR_IO_GATEWAY`): what limits the requests
/// the adapter sends to the miniport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gateway {
    pub address: VirtAddr,
    /// Requests the miniport holds.
    pub outstanding: u32,
    /// The most the gateway lets the miniport hold.
    pub outstanding_max: u32,
    /// Requests waiting for the gateway to let them through.
    pub pending: u32,
    pub busy: u32,
    pub paused: i32,
}

/// One entry of an adapter's unit list.
#[derive(Debug, Clone)]
pub struct UnitEntry {
    pub extension: VirtAddr,
    pub unit: std::result::Result<StorUnit, String>,
}

/// A logical unit (`_RAID_UNIT_EXTENSION`), the PDO storport creates for
/// each LUN the miniport reports.
#[derive(Debug, Clone)]
pub struct StorUnit {
    pub extension: VirtAddr,
    pub device_object: VirtAddr,
    pub adapter: VirtAddr,
    pub address: UnitAddress,
    pub vendor: String,
    pub product: String,
    pub revision: String,
    pub state: StorEnum,
    pub device_power: StorEnum,
    pub flags: Vec<String>,
    /// The miniport's per-unit extension (`StorPortGetLogicalUnit`); null
    /// when the miniport asked for none.
    pub lu_extension: VirtAddr,
    pub max_queue_depth: u32,
    pub queue: UnitQueue,
    /// The requests the miniport holds for the unit, from storport's pending
    /// queue.
    pub requests: Vec<StorRequest>,
    /// Why the requests are not all listed.
    pub requests_stopped: Vec<String>,
}

/// The SCSI address of a unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnitAddress {
    pub path: u8,
    pub target: u8,
    pub lun: u8,
}

/// A unit's device queue (`_EXTENDED_DEVICE_QUEUE`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UnitQueue {
    /// How many requests the queue lets the miniport hold.
    pub depth: i32,
    /// `StorPortPauseDevice` calls not yet resumed.
    pub pause_count: i32,
    /// `StorPortDeviceBusy` calls not yet readied.
    pub busy_count: i32,
    /// Frozen after an error until the class driver releases it.
    pub frozen: bool,
    /// Locked by the class driver (`SRB_FUNCTION_LOCK_QUEUE`).
    pub locked: bool,
    pub untagged: bool,
    pub power_locked: bool,
    /// Requests that bypass the queue.
    pub bypass_count: i32,
    /// Requests waiting because the queue is full or held.
    pub waiting: usize,
    /// Requests waiting to bypass the queue.
    pub bypass_waiting: usize,
    /// Why a count of waiting requests is short.
    pub waiting_stopped: Vec<String>,
}

/// A request the miniport holds: storport's `_EXTENDED_REQUEST_BLOCK` and
/// the IRP and SRB it carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorRequest {
    pub xrb: VirtAddr,
    pub irp: VirtAddr,
    pub srb: VirtAddr,
    /// The processor whose pending queue holds it.
    pub processor: u32,
}

/// An entry of an adapter's internal log (`_RAID_LOG_ENTRY`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorLogEntry {
    /// The entry's number: storport numbers them from 1 as it writes them.
    pub number: u64,
    /// When storport wrote it, as a FILETIME (UTC).
    pub time: u64,
    /// `_DBG_LOG_REASON`.
    pub reason: StorEnum,
    pub parameters: [u64; 4],
}

/// A StorPort adapter's internal log (`!storagekd.storloglist`): a ring of
/// `RaidLogListSize` entries that storport writes as it starts, completes,
/// pauses, and resumes requests.
#[derive(Debug, Clone)]
pub struct StorLog {
    pub adapter: VirtAddr,
    pub driver_name: String,
    /// The ring (`RaidLogList`) and its size.
    pub ring: VirtAddr,
    pub size: u32,
    /// The number of the newest entry, which is how many storport wrote.
    pub newest: u64,
    /// The entries still in the ring, oldest first.
    pub entries: Vec<StorLogEntry>,
}

/// A request as a log entry of storport's request path records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorLogRequest {
    pub irp: VirtAddr,
    pub srb: VirtAddr,
    /// The CDB's operation code.
    pub opcode: u8,
    /// `SrbStatus`: `SRB_STATUS_PENDING` until the miniport completes the
    /// request.
    pub srb_status: u8,
}

/// The reasons whose entries log a request: storport's request path passes
/// the IRP as the first parameter, the SRB as the third, and the CDB's
/// operation code and the SRB status in bits 16-23 and 8-15 of the fourth.
const REQUEST_LOG_REASONS: &[&str] = &[
    "LogCallMiniportStartIo",
    "LogMiniportCompletion",
    "LogCallMiniportBuildIo",
];

/// The request `entry` logs, for an entry of storport's request path.
pub fn log_request(entry: &StorLogEntry) -> Option<StorLogRequest> {
    let reason = entry.reason.name.as_deref()?;
    if !REQUEST_LOG_REASONS.contains(&reason) {
        return None;
    }
    let [irp, _, srb, packed] = entry.parameters;
    Some(StorLogRequest {
        irp: VirtAddr(irp),
        srb: VirtAddr(srb),
        opcode: (packed >> 16) as u8,
        srb_status: (packed >> 8) as u8,
    })
}

/// The numbers of the entries a ring of `size` slots holds when entry
/// `newest` is the last written, oldest first: storport writes entry `n`
/// to slot `n % size` and starts at 1.
pub fn log_ring_numbers(newest: u64, size: u32) -> Range<u64> {
    let size = u64::from(size);
    if size == 0 {
        return 1..1;
    }
    newest.saturating_sub(size - 1).max(1)..newest + 1
}

/// What a unit's queue state means, in words: the requests the miniport
/// holds, those waiting in storport, and why the queue does not move.
pub fn unit_verdict(queue: &UnitQueue, outstanding: usize) -> String {
    let mut parts = Vec::new();
    if outstanding > 0 {
        parts.push(format!("{outstanding} with the miniport"));
    }
    let waiting = queue.waiting + queue.bypass_waiting;
    if waiting > 0 {
        parts.push(format!("{waiting} waiting"));
    }
    if queue.frozen {
        parts.push("frozen".to_string());
    }
    if queue.locked {
        parts.push("locked".to_string());
    }
    if queue.pause_count > 0 {
        parts.push(format!("paused ({})", queue.pause_count));
    }
    if queue.busy_count > 0 {
        parts.push(format!("busy ({})", queue.busy_count));
    }
    if parts.is_empty() {
        "idle".to_string()
    } else {
        parts.join(", ")
    }
}

/// What an adapter's gateways and counts mean, in words.
pub fn adapter_verdict(adapter: &StorAdapter) -> String {
    let outstanding: u64 = adapter
        .gateways
        .iter()
        .map(|gateway| u64::from(gateway.outstanding))
        .sum();
    let pending: u64 = adapter
        .gateways
        .iter()
        .map(|gateway| u64::from(gateway.pending))
        .sum();
    let paused = adapter.pause_count > 0 || adapter.gateways.iter().any(|g| g.paused > 0);
    let busy = adapter.busy_count > 0 || adapter.gateways.iter().any(|g| g.busy != 0);
    let mut parts = Vec::new();
    if outstanding > 0 {
        parts.push(format!("{outstanding} with the miniport"));
    }
    if pending > 0 {
        parts.push(format!("{pending} waiting"));
    }
    if paused {
        parts.push("paused".to_string());
    }
    if busy {
        parts.push("busy".to_string());
    }
    if parts.is_empty() {
        "idle".to_string()
    } else {
        parts.join(", ")
    }
}

/// The names of the flags set in `value`, the integer a flags structure
/// `layout` holds: each one-bit bitfield set, and each one-byte field that is
/// not zero, in bit order. storport declares its flags as bitfields over
/// single bytes, so a bit's place is its byte's offset and its position in
/// the byte.
pub fn flag_names(layout: &TypeInfo, value: u64) -> Vec<String> {
    let mut names: Vec<(u32, &String)> = layout
        .fields
        .iter()
        .filter_map(|(name, field)| {
            let byte = field.offset;
            if byte >= 8 {
                return None;
            }
            match &field.type_data {
                ParsedType::Bitfield { pos, len: 1, .. } => {
                    let bit = byte * 8 + u32::from(*pos);
                    (bit < 64 && value >> bit & 1 != 0).then_some((bit, name))
                }
                ParsedType::Bitfield { .. } => None,
                _ if field.size == 1 => {
                    (value >> (byte * 8) & 0xff != 0).then_some((byte * 8, name))
                }
                _ => None,
            }
        })
        .collect();
    names.sort();
    names.into_iter().map(|(_, name)| name.clone()).collect()
}

/// The text of a fixed `UCHAR` array, such as an inquiry's vendor field:
/// up to the first NUL, with the padding spaces trimmed.
pub fn inquiry_text(bytes: &[u8]) -> String {
    let text = &bytes[..bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len())];
    String::from_utf8_lossy(text).trim().to_string()
}

/// The name `variants` gives `value`.
fn enum_name(variants: &[(String, i64)], value: u64) -> Option<String> {
    variants
        .iter()
        .find(|(_, v)| *v as u64 == value)
        .map(|(name, _)| name.clone())
}

/// The value `variants` gives `name`.
fn enum_value(variants: &[(String, i64)], name: &str) -> Option<u64> {
    variants
        .iter()
        .find(|(variant, _)| variant == name)
        .map(|(_, value)| *value as u64)
}

/// Each link from `head` in a bounded walk, and why it stopped short.
fn walk(
    memory: &impl MemoryOps<VirtAddr>,
    head: VirtAddr,
    limit: usize,
) -> (Vec<VirtAddr>, Option<String>) {
    let (links, termination) = bounded_list_walk(head, limit, |link| memory.read::<VirtAddr>(link));
    (links, termination.diagnostic())
}

/// The kinds of object storport's extensions say they are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RaidObject {
    Adapter(VirtAddr),
    Unit(VirtAddr),
}

/// storport's layouts and enums, resolved once per command.
struct StorTypes<'a> {
    types: Types<'a>,
    adapter: Arc<TypeInfo>,
    unit: Arc<TypeInfo>,
    object_types: Vec<(String, i64)>,
    device_states: Vec<(String, i64)>,
    device_powers: Vec<(String, i64)>,
    system_powers: Vec<(String, i64)>,
    interfaces: Vec<(String, i64)>,
}

impl<'a> StorTypes<'a> {
    fn layout(&self, name: &str) -> Result<Arc<TypeInfo>> {
        stor_layout(self.types, name)
    }

    fn at(&self, layout: &Arc<TypeInfo>, address: VirtAddr) -> StructRef<'a> {
        self.types.struct_with_layout(Arc::clone(layout), address)
    }

    fn object_type(&self, name: &str) -> Option<u64> {
        enum_value(&self.object_types, name)
    }
}

fn stor_enum(variants: &[(String, i64)], value: u64) -> StorEnum {
    StorEnum {
        value,
        name: enum_name(variants, value),
    }
}

fn stor_layout(types: Types<'_>, name: &str) -> Result<Arc<TypeInfo>> {
    types.layout(format!("storport!{name}")).map_err(|_| {
        Error::DebugInfo(format!(
            "storport's symbols do not describe {name}; is storport.sys loaded with its PDB \
             (.reload storport.sys)?"
        ))
    })
}

impl Target {
    fn stor_types(&self) -> Result<StorTypes<'_>> {
        let types = self.types_in(self.kernel_dtb());
        let object_types = self.stor_enum_variants("_RAID_OBJECT_TYPE");
        if object_types.is_empty() {
            return Err(Error::DebugInfo(
                "storport's symbols do not describe _RAID_OBJECT_TYPE; is storport.sys loaded \
                 with its PDB (.reload storport.sys)?"
                    .into(),
            ));
        }
        Ok(StorTypes {
            adapter: stor_layout(types, "_RAID_ADAPTER_EXTENSION")?,
            unit: stor_layout(types, "_RAID_UNIT_EXTENSION")?,
            object_types,
            device_states: self.stor_enum_variants("_DEVICE_STATE"),
            device_powers: self.stor_enum_variants("_DEVICE_POWER_STATE"),
            system_powers: self.stor_enum_variants("_SYSTEM_POWER_STATE"),
            interfaces: self.stor_enum_variants("_INTERFACE_TYPE"),
            types,
        })
    }

    /// The variants of storport's enum `name`; empty when its PDB lacks it.
    fn stor_enum_variants(&self, name: &str) -> Vec<(String, i64)> {
        self.symbols
            .find_enum_across_modules(self.kernel_dtb(), &format!("storport!{name}"))
            .unwrap_or_default()
    }

    /// Every driver on storport's driver list, with its adapters and their
    /// units.
    pub fn storport_drivers(&self) -> Result<StorPortDrivers> {
        let stor = self.stor_types()?;
        let pointer = self
            .symbols
            .find_symbol_across_modules(self.kernel_dtb(), "storport!RaidpPortData")?
            .ok_or_else(|| {
                Error::DebugInfo(
                    "storport!RaidpPortData is not in storport's symbols; is storport.sys \
                     loaded with its PDB (.reload storport.sys)?"
                        .into(),
                )
            })?;
        let memory = self.kernel_address_space();
        let port_data = memory.read::<VirtAddr>(pointer)?;
        if port_data.is_zero() {
            return Ok(StorPortDrivers {
                port_data,
                drivers: Vec::new(),
                stopped: None,
            });
        }
        let port = stor.at(&stor.layout("_RAID_PORT_DATA")?, port_data);
        let list = port.embedded("DriverList")?;
        let head = list.addr() + list.layout().field_offset("List")?;
        let driver_layout = stor.layout("_RAID_DRIVER_EXTENSION")?;
        let link = driver_layout.field_offset("DriverLink")?;
        let (links, stopped) = walk(&memory, head, MAX_DRIVERS);
        let mut drivers = Vec::new();
        for driver_link in links {
            let extension = driver_link - link;
            drivers.push(self.stor_driver(&stor, &driver_layout, extension)?);
        }
        Ok(StorPortDrivers {
            port_data,
            drivers,
            stopped,
        })
    }

    fn stor_driver(
        &self,
        stor: &StorTypes<'_>,
        layout: &Arc<TypeInfo>,
        extension: VirtAddr,
    ) -> Result<StorDriver> {
        let driver = stor.at(layout, extension).prefetch();
        let driver_object = driver.read_pointer("DriverObject")?;
        let name = self.stor_driver_name(driver_object, &driver);
        let list = driver.embedded("AdapterList")?;
        let head = list.addr() + list.layout().field_offset("List")?;
        let link = stor.adapter.field_offset("NextAdapter")?;
        let memory = self.kernel_address_space();
        let (links, stopped) = walk(&memory, head, MAX_ADAPTERS);
        let adapters = links
            .into_iter()
            .map(|adapter_link| self.stor_adapter_entry(stor, adapter_link, link))
            .collect();
        Ok(StorDriver {
            extension,
            driver_object,
            name,
            adapters,
            stopped,
        })
    }

    /// A driver's service name: its driver object's name without
    /// `\Driver\`, or else the last part of its registry path.
    fn stor_driver_name(&self, driver_object: VirtAddr, driver: &StructRef<'_>) -> String {
        let object_name = self
            .guest()
            .ok()
            .and_then(|guest| {
                guest
                    .ntoskrnl
                    .types()
                    .struct_at("_DRIVER_OBJECT", driver_object)
                    .ok()
            })
            .and_then(|object| object.unicode_string("DriverName").ok())
            .filter(|name| !name.is_empty());
        let name = object_name.or_else(|| driver.unicode_string("RegistryPath").ok());
        match name {
            Some(name) => name.rsplit('\\').next().unwrap_or(&name).to_string(),
            None => "?".to_string(),
        }
    }

    /// The adapter on a driver's adapter list at `link`. An adapter of
    /// storport's native NVMe path has a different layout, which these
    /// commands do not read.
    fn stor_adapter_entry(
        &self,
        stor: &StorTypes<'_>,
        link: VirtAddr,
        offset: u64,
    ) -> AdapterEntry {
        let extension = link - offset;
        let adapter = self
            .stor_object_type(stor, extension)
            .map_err(|error| format!("its ObjectType is unreadable: {error}"))
            .and_then(|object_type| {
                if Some(object_type) == stor.object_type("RaidAdapterObject") {
                    self.stor_adapter_at(stor, extension)
                        .map_err(|error| error.to_string())
                } else {
                    Err(not_a_raid_adapter(stor, object_type))
                }
            });
        AdapterEntry { extension, adapter }
    }

    fn stor_object_type(&self, stor: &StorTypes<'_>, address: VirtAddr) -> Result<u64> {
        stor.at(&stor.adapter, address).read_uint("ObjectType")
    }

    /// What `address` is: a StorPort adapter or unit extension, or a device
    /// object whose extension is one.
    fn stor_resolve(&self, stor: &StorTypes<'_>, address: VirtAddr) -> Result<RaidObject> {
        let classify = |extension: VirtAddr| -> Option<RaidObject> {
            let object_type = self.stor_object_type(stor, extension).ok()?;
            if Some(object_type) == stor.object_type("RaidAdapterObject") {
                Some(RaidObject::Adapter(extension))
            } else if Some(object_type) == stor.object_type("RaidUnitObject") {
                Some(RaidObject::Unit(extension))
            } else {
                None
            }
        };
        if let Some(object) = classify(address) {
            return Ok(object);
        }
        let device_extension = self.guest().ok().and_then(|guest| {
            let device = guest
                .ntoskrnl
                .types()
                .struct_at("_DEVICE_OBJECT", address)
                .ok()?;
            (device.read_uint("Type").ok()? == IO_TYPE_DEVICE)
                .then(|| device.read_pointer("DeviceExtension").ok())
                .flatten()
        });
        if let Some(object) = device_extension.and_then(classify) {
            return Ok(object);
        }
        Err(Error::DebugInfo(format!(
            "{:#x} is not a StorPort adapter or unit extension, nor a device object of one; \
             !storagekd.storadapter lists them",
            address.0
        )))
    }

    /// The adapter at `address`: its extension, or its FDO.
    pub fn storport_adapter(&self, address: VirtAddr) -> Result<StorAdapter> {
        let stor = self.stor_types()?;
        match self.stor_resolve(&stor, address)? {
            RaidObject::Adapter(extension) => self.stor_adapter_at(&stor, extension),
            RaidObject::Unit(extension) => Err(Error::DebugInfo(format!(
                "{} a StorPort unit; use !storagekd.storunit",
                what_is(address, extension)
            ))),
        }
    }

    /// The unit at `address`: its extension, or its PDO.
    pub fn storport_unit(&self, address: VirtAddr) -> Result<StorUnit> {
        let stor = self.stor_types()?;
        match self.stor_resolve(&stor, address)? {
            RaidObject::Unit(extension) => self.stor_unit_at(&stor, extension),
            RaidObject::Adapter(extension) => Err(Error::DebugInfo(format!(
                "{} a StorPort adapter; use !storagekd.storadapter",
                what_is(address, extension)
            ))),
        }
    }

    /// The internal log of the adapter at `address`: its extension, or its
    /// FDO.
    pub fn storport_log(&self, address: VirtAddr) -> Result<StorLog> {
        let stor = self.stor_types()?;
        let extension = match self.stor_resolve(&stor, address)? {
            RaidObject::Adapter(extension) => extension,
            RaidObject::Unit(extension) => {
                return Err(Error::DebugInfo(format!(
                    "{} a StorPort unit; storport logs per adapter, so give its adapter",
                    what_is(address, extension)
                )));
            }
        };
        let adapter = stor.at(&stor.adapter, extension);
        let driver_layout = stor.layout("_RAID_DRIVER_EXTENSION")?;
        let driver_ref = stor.at(&driver_layout, adapter.read_pointer("Driver")?);
        let driver_name =
            self.stor_driver_name(driver_ref.read_pointer("DriverObject")?, &driver_ref);
        let ring = adapter.read_pointer("RaidLogList")?;
        let size = adapter.read_uint("RaidLogListSize")? as u32;
        let newest = adapter.read_uint("RaidLogListIndex")?;
        let entry_layout = stor.layout("_RAID_LOG_ENTRY")?;
        let entry_size = entry_layout.size as u64;
        let mut entries = Vec::new();
        if !ring.is_zero() && size > 0 {
            let mut bytes = vec![0u8; (entry_size * u64::from(size)) as usize];
            self.kernel_address_space()
                .read_bytes(ring, &mut bytes)
                .map_err(|error| {
                    Error::DebugInfo(format!("the log ring at {:#x}: {error}", ring.0))
                })?;
            let reasons = self.stor_enum_variants("_DBG_LOG_REASON");
            let field = |name: &str| {
                entry_layout
                    .field_offset(name)
                    .map(|offset| offset as usize)
            };
            let reason_at = field("Reason")?;
            let time_at = field("Timestamp")?;
            let parameter_at = [
                field("Parameter1")?,
                field("Parameter2")?,
                field("Parameter3")?,
                field("Parameter4")?,
            ];
            for number in log_ring_numbers(newest, size) {
                let slot = (number % u64::from(size) * entry_size) as usize;
                let entry = &bytes[slot..slot + entry_size as usize];
                let u64_at = |at: usize| le_uint(&entry[at..at + 8]);
                let time = u64_at(time_at);
                // A slot storport has not written yet holds zeros.
                if time == 0 {
                    continue;
                }
                entries.push(StorLogEntry {
                    number,
                    time,
                    reason: stor_enum(&reasons, le_uint(&entry[reason_at..reason_at + 4])),
                    parameters: parameter_at.map(u64_at),
                });
            }
        }
        Ok(StorLog {
            adapter: extension,
            driver_name,
            ring,
            size,
            newest,
            entries,
        })
    }

    fn stor_adapter_at(&self, stor: &StorTypes<'_>, extension: VirtAddr) -> Result<StorAdapter> {
        let adapter = stor.at(&stor.adapter, extension);
        let driver = adapter.read_pointer("Driver")?;
        let driver_layout = stor.layout("_RAID_DRIVER_EXTENSION")?;
        let driver_ref = stor.at(&driver_layout, driver);
        let driver_object = driver_ref.read_pointer("DriverObject")?;
        let driver_name = self.stor_driver_name(driver_object, &driver_ref);
        let mut flags = Vec::new();
        for word in ["Flags", "Flags2"] {
            let layout = adapter.embedded(word)?;
            let value = le_uint(&adapter.read_field_bytes(word, 8)?);
            flags.extend(flag_names(layout.layout(), value));
        }
        let miniport = adapter.embedded("Miniport")?;
        let interface = stor_enum(
            &stor.interfaces,
            miniport
                .embedded("PortConfiguration")?
                .read_uint("AdapterInterfaceType")?,
        );
        let pci = if interface.name.as_deref() == Some(INTERFACE_PCI_BUS) {
            Some((
                adapter.read_uint("BusNumber")? as u32,
                adapter.read_uint("Device")? as u32,
                adapter.read_uint("Function")? as u32,
            ))
        } else {
            None
        };
        let virtual_miniport = miniport
            .embedded("Flags")
            .and_then(|flags| flags.read_bits("IsVirtual"))
            .is_ok_and(|bit| bit != 0);
        let private = miniport.read_pointer("PrivateDeviceExt")?;
        let hw_device_extension = if private.is_zero() {
            private
        } else {
            private
                + stor
                    .layout("_RAID_HW_DEVICE_EXT")?
                    .field_offset("HwDeviceExtension")?
        };
        let init = miniport
            .follow("HwInitializationData")
            .ok()
            .filter(|init| !init.addr().is_zero());
        let init_size = |field: &str| init.as_ref().and_then(|init| init.read_uint(field).ok());
        let power = adapter.embedded("Power")?;
        let (gateways, gateways_error) = match self.stor_gateways(stor, &adapter) {
            Ok(gateways) => (gateways, None),
            Err(error) => (Vec::new(), Some(error.to_string())),
        };
        let unit_list = adapter.embedded("UnitList")?;
        let head = unit_list.addr() + unit_list.layout().field_offset("List")?;
        let link = stor.unit.field_offset("NextUnit")?;
        let memory = self.kernel_address_space();
        let (links, units_stopped) = walk(&memory, head, MAX_UNITS);
        let units = links
            .into_iter()
            .map(|unit_link| {
                let extension = unit_link - link;
                let unit = self
                    .stor_object_type(stor, extension)
                    .map_err(|error| format!("its ObjectType is unreadable: {error}"))
                    .and_then(|object_type| {
                        if Some(object_type) == stor.object_type("RaidUnitObject") {
                            self.stor_unit_at(stor, extension)
                                .map_err(|error| error.to_string())
                        } else {
                            Err(format!(
                                "its ObjectType is {}, not RaidUnitObject",
                                enum_name(&stor.object_types, object_type)
                                    .unwrap_or_else(|| format!("{object_type:#x}"))
                            ))
                        }
                    });
                UnitEntry { extension, unit }
            })
            .collect();
        Ok(StorAdapter {
            extension,
            driver,
            driver_object,
            driver_name,
            fdo: adapter.read_pointer("DeviceObject")?,
            pdo: adapter.read_pointer("PhysicalDeviceObject")?,
            lower: adapter.read_pointer("LowerDeviceObject")?,
            device_name: adapter.unicode_string("DeviceName")?,
            port_number: adapter.read_uint("PortNumber")? as u32,
            miniport_name: self.stor_wide_string(adapter.read_pointer("MiniportName")?),
            adapter_id: self.stor_wide_string(adapter.read_pointer("AdapterId")?),
            state: stor_enum(&stor.device_states, adapter.read_uint("DeviceState")?),
            flags,
            interface,
            pci,
            virtual_miniport,
            hw_device_extension,
            hw_device_extension_size: init_size("DeviceExtensionSize"),
            lu_extension_size: init_size("SpecificLuExtensionSize"),
            system_power: stor_enum(&stor.system_powers, power.read_uint("SystemState")?),
            device_power: stor_enum(&stor.device_powers, power.read_uint("DeviceState")?),
            paging_paths: adapter.read_uint("PagingPathCount")? as u32,
            dump_paths: adapter.read_uint("CrashDumpPathCount")? as u32,
            hiber_paths: adapter.read_uint("HiberPathCount")? as u32,
            pause_count: adapter.read_uint("AdapterPauseCount")? as u32,
            busy_count: adapter.read_uint("AdapterBusyCount")? as u32,
            gateways,
            gateways_error,
            units,
            units_stopped,
        })
    }

    /// The adapter's gateways: `InUseGatewayCount` of them in a row at
    /// `Gateway`.
    fn stor_gateways(&self, stor: &StorTypes<'_>, adapter: &StructRef<'_>) -> Result<Vec<Gateway>> {
        let first = adapter.read_pointer("Gateway")?;
        if first.is_zero() {
            return Ok(Vec::new());
        }
        let count = adapter.read_uint("InUseGatewayCount")?;
        if count > MAX_GATEWAYS {
            return Err(Error::DebugInfo(format!(
                "InUseGatewayCount is {count}, past the {MAX_GATEWAYS} an adapter can have"
            )));
        }
        let layout = stor.layout("_STOR_IO_GATEWAY")?;
        let size = layout.size as u64;
        (0..count)
            .map(|index| {
                let gateway = stor.at(&layout, first + index * size).prefetch();
                Ok(Gateway {
                    address: gateway.addr(),
                    outstanding: gateway.read_uint("Outstanding")? as u32,
                    outstanding_max: gateway.read_uint("OutstandingMax")? as u32,
                    pending: gateway.read_uint("PendingIoCount")? as u32,
                    busy: gateway.read_uint("BusyStatus")? as u32,
                    paused: gateway.read_uint("PauseCount")? as u32 as i32,
                })
            })
            .collect()
    }

    fn stor_unit_at(&self, stor: &StorTypes<'_>, extension: VirtAddr) -> Result<StorUnit> {
        let unit = stor.at(&stor.unit, extension);
        let address = unit.embedded("Address")?;
        let text = |field: &str| -> Result<String> {
            Ok(inquiry_text(&unit.read_field_bytes(field, 0x400)?))
        };
        let flags_layout = unit.embedded("Flags")?;
        let flags_value = le_uint(&unit.read_field_bytes("Flags", 8)?);
        let flags = flag_names(flags_layout.layout(), flags_value);
        let device_queue = unit
            .embedded("IoQueue")?
            .embedded("DeviceQueue")?
            .prefetch();
        let memory = self.kernel_address_space();
        let mut waiting_stopped = Vec::new();
        let mut count_list = |field: &str| -> Result<usize> {
            let head = device_queue.addr() + device_queue.layout().field_offset(field)?;
            let (links, stopped) = walk(&memory, head, MAX_WAITING);
            if let Some(stopped) = stopped {
                waiting_stopped.push(format!("{field}: {stopped}"));
            }
            Ok(links.len())
        };
        let waiting = count_list("DeviceOverflowList")?;
        let bypass_waiting = count_list("ByPassList")?;
        let flag = |field: &str| -> Result<bool> { Ok(device_queue.read_uint(field)? != 0) };
        let queue = UnitQueue {
            depth: device_queue.read_uint("Depth")? as u32 as i32,
            pause_count: device_queue.read_uint("PauseCount")? as u32 as i32,
            busy_count: device_queue.read_uint("BusyCount")? as u32 as i32,
            frozen: flag("Frozen")?,
            locked: flag("Locked")?,
            untagged: flag("Untagged")?,
            power_locked: flag("PowerLocked")?,
            bypass_count: device_queue.read_uint("ByPassCount")? as u32 as i32,
            waiting,
            bypass_waiting,
            waiting_stopped,
        };
        let (requests, requests_stopped) =
            self.stor_pending_requests(stor, extension, unit.read_pointer("PendingQueue")?)?;
        Ok(StorUnit {
            extension,
            device_object: unit.read_pointer("DeviceObject")?,
            adapter: unit.read_pointer("Adapter")?,
            address: UnitAddress {
                path: address.read_uint("PathId")? as u8,
                target: address.read_uint("TargetId")? as u8,
                lun: address.read_uint("Lun")? as u8,
            },
            vendor: text("VendorId")?,
            product: text("ProductId")?,
            revision: text("ProductRevision")?,
            state: stor_enum(&stor.device_states, unit.read_uint("DeviceState")?),
            device_power: stor_enum(
                &stor.device_powers,
                unit.embedded("Power")?.read_uint("DeviceState")?,
            ),
            flags,
            lu_extension: unit.read_pointer("UnitExtension")?,
            max_queue_depth: unit.read_uint("MaxQueueDepth")? as u32,
            queue,
            requests,
            requests_stopped,
        })
    }

    /// The requests on a unit's pending queue (`_STOR_EVENT_QUEUE`): the
    /// ones storport handed to the miniport and times out. Each processor
    /// has its own list of `_EXTENDED_REQUEST_BLOCK`s, linked through
    /// `PendingLink`; a sorted queue also links them by deadline. A block
    /// that does not name the unit ends its list.
    fn stor_pending_requests(
        &self,
        stor: &StorTypes<'_>,
        unit: VirtAddr,
        queue: VirtAddr,
    ) -> Result<(Vec<StorRequest>, Vec<String>)> {
        let mut requests = Vec::new();
        let mut stopped = Vec::new();
        if queue.is_zero() {
            return Ok((requests, stopped));
        }
        let queue_layout = stor.layout("_STOR_EVENT_QUEUE")?;
        let events = stor.at(&queue_layout, queue).prefetch();
        let count = events.read_uint("ProcessorQueueCount")?;
        if count > MAX_PROCESSOR_QUEUES {
            stopped.push(format!(
                "ProcessorQueueCount is {count}, past the {MAX_PROCESSOR_QUEUES} processors \
                 Windows supports"
            ));
            return Ok((requests, stopped));
        }
        let sorted = events.read_bits("SortedQueueEnabled").unwrap_or(0) != 0;
        let subqueue = stor.layout("_STOR_EVENT_SUBQUEUE")?;
        let entry = stor.layout("_STOR_EVENT_QUEUE_ENTRY")?;
        let xrb_layout = stor.layout("_EXTENDED_REQUEST_BLOCK")?;
        let pending_link = xrb_layout.field_offset("PendingLink")?;
        let mut lists = vec![("List", pending_link + entry.field_offset("NextLink")?)];
        if sorted {
            lists.push((
                "SortedList",
                pending_link + entry.field_offset("SortedListEntry")?,
            ));
        }
        let base = queue + queue_layout.field_offset("ProcessorQueues")?;
        let memory = self.kernel_address_space();
        let mut seen = HashSet::new();
        for processor in 0..count {
            let sub = base + processor * subqueue.size as u64;
            for &(field, offset) in &lists {
                let head = sub + subqueue.field_offset(field)?;
                let (links, why) = walk(&memory, head, MAX_LISTED_REQUESTS);
                if let Some(why) = why {
                    stopped.push(format!("processor {processor} {field}: {why}"));
                }
                for link in links {
                    let xrb = stor.at(&xrb_layout, link - offset);
                    let owner = xrb.read_pointer("Unit");
                    if owner.as_ref().ok() != Some(&unit) {
                        stopped.push(format!(
                            "processor {processor} {field}: request {:#x} names unit {}, not \
                             this one",
                            xrb.addr().0,
                            owner.map_or_else(|error| error.to_string(), |o| format!("{:#x}", o.0))
                        ));
                        break;
                    }
                    if !seen.insert(xrb.addr()) {
                        continue;
                    }
                    if requests.len() >= MAX_LISTED_REQUESTS {
                        stopped.push(format!("listed the first {MAX_LISTED_REQUESTS}"));
                        return Ok((requests, stopped));
                    }
                    requests.push(StorRequest {
                        xrb: xrb.addr(),
                        irp: xrb.read_pointer("Irp")?,
                        srb: xrb.read_pointer("Srb")?,
                        processor: processor as u32,
                    });
                }
            }
        }
        Ok((requests, stopped))
    }

    /// A NUL-terminated wide string at `address`, read a page at a time so
    /// a short string at the end of a page reads.
    fn stor_wide_string(&self, address: VirtAddr) -> Option<String> {
        if address.is_zero() {
            return None;
        }
        let memory = self.kernel_address_space();
        let mut bytes = Vec::new();
        let mut at = address;
        while bytes.len() < MAX_NAME_CHARS * 2 {
            let page_left = 0x1000 - (at.0 & 0xfff) as usize;
            let len = page_left.min(MAX_NAME_CHARS * 2 - bytes.len()) & !1;
            if len == 0 {
                break;
            }
            let mut chunk = vec![0u8; len];
            if memory.read_bytes(at, &mut chunk).is_err() {
                break;
            }
            let ended = chunk.as_chunks::<2>().0.contains(&[0, 0]);
            bytes.extend_from_slice(&chunk);
            if ended {
                break;
            }
            at += len as u64;
        }
        Some(utf16le_nul_terminated(&bytes)).filter(|text| !text.is_empty())
    }
}

/// Why an adapter-list entry whose `ObjectType` is `object_type` is not
/// shown.
fn not_a_raid_adapter(stor: &StorTypes<'_>, object_type: u64) -> String {
    match enum_name(&stor.object_types, object_type) {
        Some(name) if name == "NvmeAdapterObject" => {
            "an adapter of storport's native NVMe path (NvmeAdapterObject), whose layout these \
             commands do not read"
                .to_string()
        }
        Some(name) => format!("its ObjectType is {name}, not RaidAdapterObject"),
        None => format!("its ObjectType {object_type:#x} is no _RAID_OBJECT_TYPE"),
    }
}

/// How an error names `address`, which resolved to the extension
/// `extension`: the extension itself, or the device object it extends.
fn what_is(address: VirtAddr, extension: VirtAddr) -> String {
    if address == extension {
        format!("{:#x} is", address.0)
    } else {
        format!("{:#x} is the device object of", address.0)
    }
}

#[cfg(test)]
mod tests {
    use indexmap::IndexMap;

    use super::*;
    use crate::layout::FieldInfo;

    fn bit(offset: u32, pos: u8) -> FieldInfo {
        FieldInfo {
            offset,
            size: 1,
            type_data: ParsedType::Bitfield {
                underlying: Box::new(ParsedType::Primitive("UCHAR".into())),
                pos,
                len: 1,
            },
        }
    }

    /// The first bytes of storport's `_FLAGS`: bitfields over single bytes,
    /// two whole-byte fields, and the 64-bit view of all of them.
    fn flags_layout() -> TypeInfo {
        let mut fields = IndexMap::new();
        fields.insert(
            "AsUlonglong".to_string(),
            FieldInfo {
                offset: 0,
                size: 8,
                type_data: ParsedType::Primitive("ULONGLONG".into()),
            },
        );
        fields.insert("InitializedMiniport".to_string(), bit(0, 0));
        fields.insert("WmiInitialized".to_string(), bit(0, 2));
        fields.insert("BootAdapter".to_string(), bit(0, 7));
        fields.insert(
            "InvalidateBusRelations".to_string(),
            FieldInfo {
                offset: 1,
                size: 1,
                type_data: ParsedType::Primitive("UCHAR".into()),
            },
        );
        fields.insert("InterruptsEnabled".to_string(), bit(3, 0));
        fields.insert("D3ColdAllowed".to_string(), bit(3, 3));
        fields.insert(
            "Reserved".to_string(),
            FieldInfo {
                offset: 4,
                size: 4,
                type_data: ParsedType::Bitfield {
                    underlying: Box::new(ParsedType::Primitive("ULONG".into())),
                    pos: 1,
                    len: 31,
                },
            },
        );
        fields.insert("FindAdapterCalled".to_string(), bit(4, 6));
        TypeInfo {
            name: "_FLAGS".into(),
            size: 8,
            fields,
            pointer_size: 8,
        }
    }

    #[test]
    fn flag_names_place_bits_by_byte_offset() {
        let layout = flags_layout();
        // Byte 0 0x85, byte 3 0x09, byte 4 0x40: the live storahci adapter's
        // bits, less the ones this layout leaves out.
        let value = 0x0000_0040_0900_0085;
        assert_eq!(
            flag_names(&layout, value),
            [
                "InitializedMiniport",
                "WmiInitialized",
                "BootAdapter",
                "InterruptsEnabled",
                "D3ColdAllowed",
                "FindAdapterCalled",
            ]
        );
    }

    #[test]
    fn flag_names_show_whole_byte_fields_and_skip_wide_bitfields() {
        let layout = flags_layout();
        assert_eq!(flag_names(&layout, 0x0300), ["InvalidateBusRelations"]);
        // Bits only the 31-bit Reserved field covers name nothing.
        assert!(flag_names(&layout, 0xffff_ff00_0000_0000).is_empty());
        assert!(flag_names(&layout, 0).is_empty());
    }

    #[test]
    fn inquiry_text_trims_padding_and_stops_at_nul() {
        assert_eq!(inquiry_text(b"QEMU    \0"), "QEMU");
        assert_eq!(inquiry_text(b"HARDDISK\0garbage"), "HARDDISK");
        assert_eq!(inquiry_text(b"2.5+"), "2.5+");
        assert_eq!(inquiry_text(b"\0\0\0"), "");
    }

    #[test]
    fn log_ring_holds_the_last_size_entries_from_one() {
        // Nothing written yet; slot 0 stays empty until the ring wraps.
        assert!(log_ring_numbers(0, 256).is_empty());
        assert_eq!(log_ring_numbers(8, 256), 1..9);
        // The ring is full once the newest entry reaches its size, and
        // from then on drops the oldest.
        assert_eq!(log_ring_numbers(256, 256), 1..257);
        assert_eq!(log_ring_numbers(0x106_8568, 256), 0x106_8469..0x106_8569);
        assert!(log_ring_numbers(5, 0).is_empty());
    }

    #[test]
    fn unit_verdict_names_what_holds_the_queue() {
        let idle = UnitQueue {
            depth: 31,
            power_locked: true,
            ..UnitQueue::default()
        };
        assert_eq!(unit_verdict(&idle, 0), "idle");
        assert_eq!(unit_verdict(&idle, 2), "2 with the miniport");
        let held = UnitQueue {
            waiting: 3,
            bypass_waiting: 1,
            frozen: true,
            pause_count: 1,
            busy_count: 2,
            ..idle.clone()
        };
        assert_eq!(
            unit_verdict(&held, 1),
            "1 with the miniport, 4 waiting, frozen, paused (1), busy (2)"
        );
        let locked = UnitQueue {
            locked: true,
            ..idle
        };
        assert_eq!(unit_verdict(&locked, 0), "locked");
    }

    fn adapter_with(gateways: Vec<Gateway>, pause_count: u32, busy_count: u32) -> StorAdapter {
        let unknown = StorEnum {
            value: 0,
            name: None,
        };
        StorAdapter {
            extension: VirtAddr(0),
            driver: VirtAddr(0),
            driver_object: VirtAddr(0),
            driver_name: String::new(),
            fdo: VirtAddr(0),
            pdo: VirtAddr(0),
            lower: VirtAddr(0),
            device_name: String::new(),
            port_number: 0,
            miniport_name: None,
            adapter_id: None,
            state: unknown.clone(),
            flags: Vec::new(),
            interface: unknown.clone(),
            pci: None,
            virtual_miniport: false,
            hw_device_extension: VirtAddr(0),
            hw_device_extension_size: None,
            lu_extension_size: None,
            system_power: unknown.clone(),
            device_power: unknown,
            paging_paths: 0,
            dump_paths: 0,
            hiber_paths: 0,
            pause_count,
            busy_count,
            gateways,
            gateways_error: None,
            units: Vec::new(),
            units_stopped: None,
        }
    }

    #[test]
    fn adapter_verdict_sums_gateways() {
        let gateway = Gateway {
            address: VirtAddr(0),
            outstanding: 0,
            outstanding_max: 31,
            pending: 0,
            busy: 0,
            paused: 0,
        };
        assert_eq!(adapter_verdict(&adapter_with(vec![gateway], 0, 0)), "idle");
        let busy = Gateway {
            outstanding: 2,
            pending: 5,
            ..gateway
        };
        let paused = Gateway {
            outstanding: 1,
            paused: 1,
            ..gateway
        };
        assert_eq!(
            adapter_verdict(&adapter_with(vec![busy, paused], 0, 0)),
            "3 with the miniport, 5 waiting, paused"
        );
        assert_eq!(
            adapter_verdict(&adapter_with(vec![gateway], 1, 1)),
            "paused, busy"
        );
    }
}
