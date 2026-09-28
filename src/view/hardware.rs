//! hardware: [`View`] builders for hang diagnosis (`!qlocks`, `!ipi`) and PCI.

use super::shape::{Diag, Hex, Keyed, shapes};
use crate::types::VirtAddr;
use crate::target::hang::{
    self, IpiDetail, QueuedLockState, QueuedLocksDetail, ipi_frozen_name, ipi_request_type_name,
};
use crate::target::pci::{
    self, CAPABILITY_PCI_EXPRESS, PCI_CONFIG_SIZE, PciFunctionConfig, PciRawRange, capabilities,
    capability_name, class_name, command_flags, extended_capabilities, extended_capability_name,
    status_flags,
};

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
        request_type: request.request_summary.map(|summary| {
            ipi_request_type_name(*summary)
        }),
        worker_routine: request.worker_routine.clone(),
        worker_symbol: request.worker_symbol.clone(),
        parameters: request.parameters.map(|parameters| {
            parameters.to_vec()
        }),
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
        pending: processor.pending.map(|requests| {
            requests.iter().map(ipi_request).collect()
        }),
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

shapes! {
    /// A processor whose state could not be read.
    ProcessorError {
        processor: u16,
        message: String,
    }

    /// A processor's entry in a queued spinlock it owns or waits for.
    QueuedLockHolder {
        processor: u16,
        /// `owner`, `waiting`, or `corrupt` (the entry's bits and the queue
        /// links disagree).
        state: &'static str,
        /// 1-based place in the wait queue behind the owner; `None` unless
        /// waiting.
        wait_order: Option<u32>,
        /// How a corrupt entry disagrees; `None` otherwise.
        reason: Option<String>,
    }

    /// A numbered queued spinlock and the processors owning or waiting for it.
    QueuedLock {
        /// Its `_KSPIN_LOCK_QUEUE_NUMBER`.
        number: u32,
        /// The queue number's name without its `LockQueue` prefix and `Lock`
        /// suffix (`IoCancel`), or `LockQueue[n]` when unknown.
        name: String,
        /// The spinlock, from the first processor entry that names it.
        lock: Option<VirtAddr>,
        holders: Vec<QueuedLockHolder>,
    }

    /// Every numbered queued spinlock across the processors (`!qlocks`).
    QueuedLocks {
        /// Processors whose `_KPRCB.LockQueue` was read.
        processors: Vec<u16>,
        locks: Vec<QueuedLock>,
        errors: Vec<ProcessorError>,
    }

    /// A request a sender posted in a processor's IPI mailbox list.
    IpiRequest {
        /// The sender's `_REQUEST_MAILBOX` slot in the receiver's array.
        mailbox: VirtAddr,
        /// The sending processor; `None` when the mailbox lies outside the
        /// receiver's array.
        sender: Option<u16>,
        request_summary: Diag<Hex>,
        /// The request summary's type, when it is a known one.
        request_type: Diag<Option<&'static str>>,
        worker_routine: Diag<VirtAddr>,
        /// The worker routine's symbol, when it resolves.
        worker_symbol: Option<String>,
        /// `RequestPacket.CurrentPacket`: the worker's three parameters.
        parameters: Diag<Vec<Hex>>,
    }

    /// One processor's IPI state.
    IpiProcessor {
        processor: u16,
        kprcb: VirtAddr,
        /// The `_KPRCB` IPI fields this build has, by name, each a
        /// `Diagnostic` of its value.
        fields: Keyed<Diag<Hex>>,
        /// `IpiFrozen` decoded (`Running`, `Frozen`, ...); `None` when the
        /// build lacks the field.
        frozen_state: Option<Diag<&'static str>>,
        /// Requests queued to this processor and not yet taken, in list
        /// order; unavailable on builds without per-sender mailboxes or when
        /// the list cannot be read.
        pending: Diag<Vec<IpiRequest>>,
        /// Whether the pending walk stopped at its bound or a repeated
        /// mailbox.
        pending_truncated: bool,
        /// Processors whose pending list holds a request from this one.
        awaiting: Vec<u16>,
    }

    /// Interprocessor-interrupt state per processor (`!ipi`).
    IpiState {
        processors: Vec<IpiProcessor>,
        errors: Vec<ProcessorError>,
    }

    /// A device pci.sys enumerated (`!pcitree`).
    PciTreeDevice {
        /// pci.sys's device extension.
        extension: VirtAddr,
        /// The device's physical device object.
        pdo: VirtAddr,
        bus: u32,
        device: u8,
        function: u8,
        vendor_id: Hex<u16>,
        device_id: Hex<u16>,
        revision: Hex<u8>,
        base_class: Hex<u8>,
        sub_class: Hex<u8>,
        prog_if: Hex<u8>,
        /// The class code's name, when it is a known one.
        class_name: Option<String>,
        subsystem_vendor_id: Hex<u16>,
        subsystem_id: Hex<u16>,
        header_type: Hex<u8>,
        /// The device's PnP instance path, when pci.sys recorded one.
        instance_path: Option<String>,
    }

    /// A bus pci.sys enumerated, with the devices on it and the buses behind
    /// its bridges.
    PciBus {
        /// pci.sys's bus extension.
        extension: VirtAddr,
        number: u32,
        /// The highest bus number behind this one.
        subordinate: u32,
        /// The bridge's physical device object; 0 for a root bus.
        bridge_pdo: VirtAddr,
        devices: Vec<PciTreeDevice>,
        child_buses: Vec<PciBus>,
    }

    /// A PCI segment and its root buses.
    PciSegment {
        /// pci.sys's segment record.
        address: VirtAddr,
        segment: u16,
        root_buses: Vec<PciBus>,
    }

    /// The PCI hierarchy pci.sys tracks (`!pcitree`).
    PciTree {
        segments: Vec<PciSegment>,
        /// Whether the walk stopped at its bound before the end.
        truncated: bool,
        /// Each unreadable bus or function, whose list the walk left.
        errors: Vec<String>,
    }

    /// A base address register.
    PciBar {
        /// Which BAR (0-5).
        index: u8,
        /// `io`, `memory32`, or `memory64`.
        kind: &'static str,
        /// The decoded base address.
        address: Hex,
        prefetchable: bool,
        /// The register as read (both halves for a 64-bit BAR).
        raw: Hex,
    }

    /// A type 1 or 2 header's bus numbers.
    PciBuses {
        primary: u8,
        secondary: u8,
        subordinate: u8,
    }

    /// A capability-list entry.
    PciCapability {
        /// Its offset in configuration space.
        offset: Hex<u16>,
        id: Hex<u16>,
        /// The capability's name, when it is a known one.
        name: Option<&'static str>,
        /// The version of an extended capability; `None` for a standard one.
        version: Option<u8>,
    }

    /// Requested raw configuration bytes.
    PciConfigBytes {
        /// Offset of the first byte.
        offset: Hex,
        /// The bytes, as hex.
        bytes: String,
    }

    /// One function's decoded configuration space.
    PciFunction {
        segment: u16,
        bus: u8,
        device: u8,
        function: u8,
        vendor_id: Hex<u16>,
        device_id: Hex<u16>,
        revision: Hex<u8>,
        base_class: Hex<u8>,
        sub_class: Hex<u8>,
        prog_if: Hex<u8>,
        /// The class code's name, when it is a known one.
        class_name: Option<String>,
        header_type: Hex<u8>,
        multifunction: bool,
        command: Hex<u16>,
        /// The names of the command register's set bits.
        command_flags: Vec<&'static str>,
        status: Hex<u16>,
        /// The names of the status register's set bits.
        status_flags: Vec<&'static str>,
        /// Type 0 and 2 headers only.
        subsystem_vendor_id: Option<Hex<u16>>,
        /// Type 0 and 2 headers only.
        subsystem_id: Option<Hex<u16>>,
        bars: Vec<PciBar>,
        /// The expansion ROM base register (types 0 and 1).
        expansion_rom: Option<Hex<u32>>,
        /// Type 1 and 2 headers only.
        buses: Option<PciBuses>,
        interrupt_line: Hex<u8>,
        /// 0 for none, 1-4 for INTA#-INTD#.
        interrupt_pin: u8,
        capabilities: Vec<PciCapability>,
        /// PCI Express extended capabilities; empty for a conventional
        /// function, or when only 256 bytes were read.
        extended_capabilities: Vec<PciCapability>,
        /// The requested raw range (`raw=True`), else `None`.
        config: Option<PciConfigBytes>,
    }

    /// The functions a `!pci` scan found.
    PciScan {
        functions: Vec<PciFunction>,
        /// Whether an interrupt request stopped the scan early.
        interrupted: bool,
    }
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
