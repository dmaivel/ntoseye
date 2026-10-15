//! hardware: [`View`] builders for hang diagnosis (`!qlocks`, `!ipi`) and PCI.

use super::record::Keyed;
use crate::target::DiagnosticValue;
use ntoseye_macros::record;

use crate::target::hang::{
    self, IpiDetail, QueuedLockState, QueuedLocksDetail, ipi_frozen_name, ipi_request_type_name,
};
use crate::target::pci::{
    self, CAPABILITY_PCI_EXPRESS, PCI_CONFIG_SIZE, PciFunctionConfig, PciRawRange, capabilities,
    capability_name, class_name, command_flags, extended_capabilities, extended_capability_name,
    status_flags,
};
use crate::types::VirtAddr;

fn processor_error(error: &hang::ProcessorError) -> ProcessorError {
    ProcessorError {
        processor: error.processor,
        message: error.message.clone(),
    }
}

fn queued_lock(lock: &hang::QueuedLock) -> QueuedLock {
    let holders = lock
        .holders
        .iter()
        .map(|holder| {
            let (state, wait_order, reason) = match &holder.state {
                QueuedLockState::Owner => ("owner", None, None),
                QueuedLockState::Waiting(order) => ("waiting", Some(*order), None),
                QueuedLockState::Corrupt(reason) => ("corrupt", None, Some(reason.clone())),
            };
            QueuedLockHolder {
                processor: holder.processor,
                state,
                wait_order,
                reason,
            }
        })
        .collect();
    QueuedLock {
        number: lock.number,
        name: lock.name.clone(),
        lock: lock.lock,
        holders,
    }
}

/// Numbered queued spinlocks and the processors owning or waiting for them.
pub fn queued_locks(detail: &QueuedLocksDetail) -> QueuedLocks {
    QueuedLocks {
        processors: detail.processors.clone(),
        locks: detail.locks.iter().map(queued_lock).collect(),
        errors: detail.errors.iter().map(processor_error).collect(),
    }
}

fn ipi_request(request: &hang::IpiRequest) -> IpiRequest {
    IpiRequest {
        mailbox: request.mailbox,
        sender: request.sender,
        request_summary: request.request_summary.clone(),
        request_type: request
            .request_summary
            .map(|summary| ipi_request_type_name(*summary)),
        worker_routine: request.worker_routine.clone(),
        worker_symbol: request.worker_symbol.clone(),
        parameters: request.parameters.map(|parameters| parameters.to_vec()),
    }
}

fn ipi_processor(processor: &hang::IpiProcessor) -> IpiProcessor {
    let frozen = processor
        .fields
        .iter()
        .find(|field| field.name == "IpiFrozen")
        .map(|field| field.value.map(|value| ipi_frozen_name(*value)));
    IpiProcessor {
        processor: processor.processor,
        kprcb: processor.kprcb,
        fields: processor
            .fields
            .iter()
            .map(|field| (field.name, field.value.clone()))
            .collect(),
        frozen_state: frozen,
        pending: processor
            .pending
            .map(|requests| requests.iter().map(ipi_request).collect()),
        pending_truncated: processor.pending_truncated,
        awaiting: processor.awaiting.clone(),
    }
}

/// Per-processor IPI state.
pub fn ipi(detail: &IpiDetail) -> IpiState {
    IpiState {
        processors: detail.processors.iter().map(ipi_processor).collect(),
        errors: detail.errors.iter().map(processor_error).collect(),
    }
}

/// A processor whose state ntoseye could not read.
#[record]
pub struct ProcessorError {
    pub processor: u16,
    pub message: String,
}

/// The entry of a processor in a queued spinlock that it owns or waits for.
#[record]
pub struct QueuedLockHolder {
    pub processor: u16,
    /// `owner`, `waiting`, or `corrupt`. `corrupt` means that the bits of the
    /// entry do not agree with the queue links.
    pub state: &'static str,
    /// The 1-based position in the wait queue after the owner. `None` if the
    /// processor does not wait.
    pub wait_order: Option<u32>,
    /// How a corrupt entry does not agree with the queue links. `None` for
    /// other entries.
    pub reason: Option<String>,
}

/// A numbered queued spinlock and the processors that own it or wait for it.
#[record]
pub struct QueuedLock {
    /// The `_KSPIN_LOCK_QUEUE_NUMBER` of the lock.
    pub number: u32,
    /// The name of the queue number without the `LockQueue` prefix and the
    /// `Lock` suffix (`IoCancel`). `LockQueue[n]` if the name is not known.
    pub name: String,
    /// The spinlock, from the first processor entry that identifies it.
    pub lock: Option<VirtAddr>,
    pub holders: Vec<QueuedLockHolder>,
}

/// All numbered queued spinlocks on all processors (`!qlocks`).
#[record]
pub struct QueuedLocks {
    /// The processors whose `_KPRCB.LockQueue` ntoseye read.
    pub processors: Vec<u16>,
    pub locks: Vec<QueuedLock>,
    pub errors: Vec<ProcessorError>,
}

/// A request that a sender put in the IPI mailbox list of a processor.
#[record]
pub struct IpiRequest {
    /// The `_REQUEST_MAILBOX` slot of the sender in the array of the receiver.
    pub mailbox: VirtAddr,
    /// The processor that sent the request. `None` if the mailbox is outside
    /// the array of the receiver.
    pub sender: Option<u16>,
    #[record(hex)]
    pub request_summary: DiagnosticValue<u64>,
    /// The type of the request summary, if the type is known.
    pub request_type: DiagnosticValue<Option<&'static str>>,
    pub worker_routine: DiagnosticValue<VirtAddr>,
    /// The symbol of the worker routine, if ntoseye can resolve it.
    pub worker_symbol: Option<String>,
    /// The three parameters of the worker (`RequestPacket.CurrentPacket`).
    #[record(hex)]
    pub parameters: DiagnosticValue<Vec<u64>>,
}

/// The IPI state of one processor.
#[record]
pub struct IpiProcessor {
    pub processor: u16,
    pub kprcb: VirtAddr,
    /// The `_KPRCB` IPI fields that this build has, by name, each as a
    /// `Diagnostic` of its value.
    #[record(hex)]
    pub fields: Keyed<DiagnosticValue<u64>>,
    /// The decoded `IpiFrozen` value (`Running`, `Frozen`, ...). `None` if the
    /// build does not have the field.
    pub frozen_state: Option<DiagnosticValue<&'static str>>,
    /// The requests in the queue of this processor that are not taken yet, in
    /// list order. Unavailable on builds without a mailbox for each sender, or
    /// if ntoseye cannot read the list.
    pub pending: DiagnosticValue<Vec<IpiRequest>>,
    /// Whether the walk of the pending list stopped at its limit or at a
    /// repeated mailbox.
    pub pending_truncated: bool,
    /// The processors whose pending list holds a request from this processor.
    pub awaiting: Vec<u16>,
}

/// The interprocessor interrupt state of each processor (`!ipi`).
#[record]
pub struct IpiState {
    pub processors: Vec<IpiProcessor>,
    pub errors: Vec<ProcessorError>,
}

/// A device that pci.sys enumerated (`!pcitree`).
#[record]
pub struct PciTreeDevice {
    /// The pci.sys device extension.
    pub extension: VirtAddr,
    /// The physical device object of the device.
    pub pdo: VirtAddr,
    pub bus: u32,
    pub device: u8,
    pub function: u8,
    #[record(hex)]
    pub vendor_id: u16,
    #[record(hex)]
    pub device_id: u16,
    #[record(hex)]
    pub revision: u8,
    #[record(hex)]
    pub base_class: u8,
    #[record(hex)]
    pub sub_class: u8,
    #[record(hex)]
    pub prog_if: u8,
    /// The name of the class code, if it is known.
    pub class_name: Option<String>,
    #[record(hex)]
    pub subsystem_vendor_id: u16,
    #[record(hex)]
    pub subsystem_id: u16,
    #[record(hex)]
    pub header_type: u8,
    /// The PnP instance path of the device, if pci.sys recorded one.
    pub instance_path: Option<String>,
}

/// A bus that pci.sys enumerated, with the devices on it and the buses
/// behind its bridges.
#[record]
pub struct PciBus {
    /// The pci.sys bus extension.
    pub extension: VirtAddr,
    pub number: u32,
    /// The highest bus number behind this bus.
    pub subordinate: u32,
    /// The physical device object of the bridge. 0 for a root bus.
    pub bridge_pdo: VirtAddr,
    pub devices: Vec<PciTreeDevice>,
    pub child_buses: Vec<PciBus>,
}

/// A PCI segment and its root buses.
#[record]
pub struct PciSegment {
    /// The pci.sys segment record.
    pub address: VirtAddr,
    pub segment: u16,
    pub root_buses: Vec<PciBus>,
}

/// The PCI hierarchy that pci.sys tracks (`!pcitree`).
#[record]
pub struct PciTree {
    pub segments: Vec<PciSegment>,
    /// Whether the walk stopped at its limit before the end.
    pub truncated: bool,
    /// Each bus or function that ntoseye could not read, after which the
    /// walk does not continue in the list that holds it.
    pub errors: Vec<String>,
}

/// A base address register.
#[record]
pub struct PciBar {
    /// The BAR number (0-5).
    pub index: u8,
    /// `io`, `memory32`, or `memory64`.
    pub kind: &'static str,
    /// The decoded base address.
    #[record(hex)]
    pub address: u64,
    pub prefetchable: bool,
    /// The raw register value (both halves for a 64-bit BAR).
    #[record(hex)]
    pub raw: u64,
}

/// The bus numbers of a type 1 or type 2 header.
#[record]
pub struct PciBuses {
    pub primary: u8,
    pub secondary: u8,
    pub subordinate: u8,
}

/// An entry in a capability list.
#[record]
pub struct PciCapability {
    /// The offset of the entry in configuration space.
    #[record(hex)]
    pub offset: u16,
    #[record(hex)]
    pub id: u16,
    /// The name of the capability, if it is known.
    pub name: Option<&'static str>,
    /// The version of an extended capability. `None` for a standard capability.
    pub version: Option<u8>,
}

/// The raw configuration bytes that the caller requested.
#[record]
pub struct PciConfigBytes {
    /// The offset of the first byte.
    #[record(hex)]
    pub offset: u64,
    /// The bytes, as hex.
    pub bytes: String,
}

/// The decoded configuration space of one function.
#[record]
pub struct PciFunction {
    pub segment: u16,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    #[record(hex)]
    pub vendor_id: u16,
    #[record(hex)]
    pub device_id: u16,
    #[record(hex)]
    pub revision: u8,
    #[record(hex)]
    pub base_class: u8,
    #[record(hex)]
    pub sub_class: u8,
    #[record(hex)]
    pub prog_if: u8,
    /// The name of the class code, if it is known.
    pub class_name: Option<String>,
    #[record(hex)]
    pub header_type: u8,
    pub multifunction: bool,
    #[record(hex)]
    pub command: u16,
    /// The names of the bits that are set in the command register.
    pub command_flags: Vec<&'static str>,
    #[record(hex)]
    pub status: u16,
    /// The names of the bits that are set in the status register.
    pub status_flags: Vec<&'static str>,
    /// Type 0 and 2 headers only.
    #[record(hex)]
    pub subsystem_vendor_id: Option<u16>,
    /// Type 0 and 2 headers only.
    #[record(hex)]
    pub subsystem_id: Option<u16>,
    pub bars: Vec<PciBar>,
    /// The expansion ROM base register (types 0 and 1).
    #[record(hex)]
    pub expansion_rom: Option<u32>,
    /// Type 1 and 2 headers only.
    pub buses: Option<PciBuses>,
    #[record(hex)]
    pub interrupt_line: u8,
    /// 0 for none, 1-4 for INTA#-INTD#.
    pub interrupt_pin: u8,
    pub capabilities: Vec<PciCapability>,
    /// The PCI Express extended capabilities. Empty for a conventional
    /// function, or if ntoseye read only 256 bytes.
    pub extended_capabilities: Vec<PciCapability>,
    /// The requested raw range (`raw=True`). Otherwise `None`.
    pub config: Option<PciConfigBytes>,
}

/// The functions that a `!pci` scan found.
#[record]
pub struct PciScan {
    pub functions: Vec<PciFunction>,
    /// Whether an interrupt request stopped the scan early.
    pub interrupted: bool,
}

fn pci_tree_device(device: &pci::PciTreeDevice) -> PciTreeDevice {
    PciTreeDevice {
        extension: device.extension,
        pdo: device.device_object,
        bus: device.bus,
        device: device.device,
        function: device.function,
        vendor_id: device.vendor_id,
        device_id: device.device_id,
        revision: device.revision,
        base_class: device.base_class,
        sub_class: device.sub_class,
        prog_if: device.prog_if,
        class_name: class_name(device.base_class, device.sub_class),
        subsystem_vendor_id: device.subsystem_vendor_id,
        subsystem_id: device.subsystem_id,
        header_type: device.header_type,
        instance_path: device.instance_path.clone(),
    }
}

fn pci_bus(bus: &pci::PciTreeBus) -> PciBus {
    PciBus {
        extension: bus.extension,
        number: bus.number,
        subordinate: bus.subordinate,
        bridge_pdo: bus.bridge_pdo,
        devices: bus.devices.iter().map(pci_tree_device).collect(),
        child_buses: bus.child_buses.iter().map(pci_bus).collect(),
    }
}

/// pci.sys's hierarchy.
pub fn pci_tree(tree: &pci::PciTree) -> PciTree {
    PciTree {
        segments: tree
            .segments
            .iter()
            .map(|segment| PciSegment {
                address: segment.address,
                segment: segment.number,
                root_buses: segment.root_buses.iter().map(pci_bus).collect(),
            })
            .collect(),
        truncated: tree.truncated,
        errors: tree.errors.clone(),
    }
}

fn pci_capabilities(
    list: &[pci::PciCapability],
    name: fn(u16) -> Option<&'static str>,
) -> Vec<PciCapability> {
    list.iter()
        .map(|capability| PciCapability {
            offset: capability.offset,
            id: capability.id,
            name: name(capability.id),
            version: capability.version,
        })
        .collect()
}

fn pci_function(function: &PciFunctionConfig, raw: Option<PciRawRange>) -> PciFunction {
    let config = &function.config;
    let header = &function.header;
    let list = capabilities(header, config);
    let extended = if list
        .iter()
        .any(|capability| capability.id == CAPABILITY_PCI_EXPRESS)
        && config.len() > PCI_CONFIG_SIZE
    {
        extended_capabilities(config)
    } else {
        Vec::new()
    };
    PciFunction {
        segment: function.segment,
        bus: function.bus,
        device: function.device,
        function: function.function,
        vendor_id: header.vendor_id,
        device_id: header.device_id,
        revision: header.revision,
        base_class: header.base_class,
        sub_class: header.sub_class,
        prog_if: header.prog_if,
        class_name: class_name(header.base_class, header.sub_class),
        header_type: header.header_type,
        multifunction: header.multifunction(),
        command: header.command,
        command_flags: command_flags(header.command),
        status: header.status,
        status_flags: status_flags(header.status),
        subsystem_vendor_id: header.subsystem.map(|(vendor, _)| vendor),
        subsystem_id: header.subsystem.map(|(_, id)| id),
        bars: header
            .bars
            .iter()
            .map(|bar| PciBar {
                index: bar.index,
                kind: bar.kind.name(),
                address: bar.address,
                prefetchable: bar.prefetchable,
                raw: bar.raw,
            })
            .collect(),
        expansion_rom: header.expansion_rom,
        buses: header
            .buses
            .map(|(primary, secondary, subordinate)| PciBuses {
                primary,
                secondary,
                subordinate,
            }),
        interrupt_line: header.interrupt_line,
        interrupt_pin: header.interrupt_pin,
        capabilities: pci_capabilities(&list, capability_name),
        extended_capabilities: pci_capabilities(&extended, extended_capability_name),
        config: raw.map(|raw| {
            let end = raw.end.min(config.len());
            let start = raw.start.min(end);
            PciConfigBytes {
                offset: start as u64,
                bytes: hex::encode(&config[start..end]),
            }
        }),
    }
}

/// Configuration space of the functions a `!pci` scan found, each with the
/// requested raw range.
pub fn pci(scan: &pci::PciScan, raw: Option<PciRawRange>) -> PciScan {
    PciScan {
        functions: scan
            .functions
            .iter()
            .map(|function| pci_function(function, raw))
            .collect(),
        interrupted: scan.interrupted,
    }
}
