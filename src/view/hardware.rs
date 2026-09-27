//! hardware: [`View`] builders for hang diagnosis (`!qlocks`, `!ipi`) and PCI.

use super::shape::{Hex, Omit, ViewValue, shapes};
use super::{View, diagnostic};
use crate::target::hang::{
    IpiDetail, IpiProcessor, IpiRequest, ProcessorError, QueuedLock, QueuedLockState,
    QueuedLocksDetail, ipi_frozen_name, ipi_request_type_name,
};
use crate::target::pci::{
    self, CAPABILITY_PCI_EXPRESS, PCI_CONFIG_SIZE, PciFunctionConfig, PciRawRange, capabilities,
    capability_name, class_name, command_flags, extended_capabilities, extended_capability_name,
    status_flags,
};

fn processor_error(error: &ProcessorError) -> View {
    View::Object(vec![
        ("processor", View::Num(error.processor.into())),
        ("message", View::Str(error.message.clone())),
    ])
}

fn queued_lock(lock: &QueuedLock) -> View {
    let holders = lock
        .holders
        .iter()
        .map(|holder| {
            let (state, order, reason) = match &holder.state {
                QueuedLockState::Owner => ("owner", None, None),
                QueuedLockState::Waiting(order) => ("waiting", Some(u64::from(*order)), None),
                QueuedLockState::Corrupt(reason) => ("corrupt", None, Some(reason.clone())),
            };
            View::Object(vec![
                ("processor", View::Num(holder.processor.into())),
                ("state", View::Str(state.into())),
                ("wait_order", View::OptNum(order)),
                ("reason", View::OptStr(reason)),
            ])
        })
        .collect();
    View::Object(vec![
        ("number", View::Num(lock.number.into())),
        ("name", View::Str(lock.name.clone())),
        ("lock", View::OptHex(lock.lock.map(|lock| lock.0))),
        ("holders", View::List(holders)),
    ])
}

/// Numbered queued spinlocks; top-level keys: `processors`, `locks`, `errors`.
pub fn queued_locks(detail: &QueuedLocksDetail) -> View {
    View::Object(vec![
        (
            "processors",
            View::List(
                detail
                    .processors
                    .iter()
                    .map(|processor| View::Num((*processor).into()))
                    .collect(),
            ),
        ),
        (
            "locks",
            View::List(detail.locks.iter().map(queued_lock).collect()),
        ),
        (
            "errors",
            View::List(detail.errors.iter().map(processor_error).collect()),
        ),
    ])
}

fn ipi_request(request: &IpiRequest) -> View {
    View::Object(vec![
        ("mailbox", View::Hex(request.mailbox.0)),
        ("sender", View::OptNum(request.sender.map(u64::from))),
        (
            "request_summary",
            diagnostic(&request.request_summary, |summary| View::Hex(*summary)),
        ),
        (
            "request_type",
            diagnostic(&request.request_summary, |summary| {
                View::OptStr(ipi_request_type_name(*summary).map(str::to_string))
            }),
        ),
        (
            "worker_routine",
            diagnostic(&request.worker_routine, |routine| View::Hex(routine.0)),
        ),
        ("worker_symbol", View::OptStr(request.worker_symbol.clone())),
        (
            "parameters",
            diagnostic(&request.parameters, |parameters| {
                View::List(parameters.iter().map(|value| View::Hex(*value)).collect())
            }),
        ),
    ])
}

fn ipi_processor(processor: &IpiProcessor) -> View {
    let frozen = processor
        .fields
        .iter()
        .find(|field| field.name == "IpiFrozen")
        .map(|field| {
            diagnostic(&field.value, |value| {
                View::Str(ipi_frozen_name(*value).into())
            })
        })
        .unwrap_or(View::Null);
    View::Object(vec![
        ("processor", View::Num(processor.processor.into())),
        ("kprcb", View::Hex(processor.kprcb.0)),
        (
            "fields",
            View::Object(
                processor
                    .fields
                    .iter()
                    .map(|field| {
                        (
                            field.name,
                            diagnostic(&field.value, |value| View::Hex(*value)),
                        )
                    })
                    .collect(),
            ),
        ),
        ("frozen_state", frozen),
        (
            "pending",
            diagnostic(&processor.pending, |requests| {
                View::List(requests.iter().map(ipi_request).collect())
            }),
        ),
        ("pending_truncated", View::Bool(processor.pending_truncated)),
        (
            "awaiting",
            View::List(
                processor
                    .awaiting
                    .iter()
                    .map(|processor| View::Num((*processor).into()))
                    .collect(),
            ),
        ),
    ])
}

/// Per-processor IPI state; top-level keys: `processors`, `errors`.
pub fn ipi(detail: &IpiDetail) -> View {
    View::Object(vec![
        (
            "processors",
            View::List(detail.processors.iter().map(ipi_processor).collect()),
        ),
        (
            "errors",
            View::List(detail.errors.iter().map(processor_error).collect()),
        ),
    ])
}

shapes! {
    /// A device pci.sys enumerated (`!pcitree`).
    PciTreeDevice {
        /// pci.sys's device extension.
        extension: Hex,
        /// The device's physical device object.
        pdo: Hex,
        bus: u32,
        device: u8,
        function: u8,
        vendor_id: Hex,
        device_id: Hex,
        revision: Hex,
        base_class: Hex,
        sub_class: Hex,
        prog_if: Hex,
        /// The class code's name, when it is a known one.
        class_name: Option<String>,
        subsystem_vendor_id: Hex,
        subsystem_id: Hex,
        header_type: Hex,
        /// The device's PnP instance path, when pci.sys recorded one.
        instance_path: Option<String>,
    }

    /// A bus pci.sys enumerated, with the devices on it and the buses behind
    /// its bridges.
    PciBus {
        /// pci.sys's bus extension.
        extension: Hex,
        number: u32,
        /// The highest bus number behind this one.
        subordinate: u32,
        /// The bridge's physical device object; 0 for a root bus.
        bridge_pdo: Hex,
        devices: Vec<PciTreeDevice>,
        child_buses: Vec<PciBus>,
    }

    /// A PCI segment and its root buses.
    PciSegment {
        /// pci.sys's segment record.
        address: Hex,
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
        offset: Hex,
        id: Hex,
        /// The capability's name, when it is a known one.
        name: Option<&'static str>,
        /// The version of an extended capability; absent for a standard one.
        version: Omit<u8>,
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
        vendor_id: Hex,
        device_id: Hex,
        revision: Hex,
        base_class: Hex,
        sub_class: Hex,
        prog_if: Hex,
        /// The class code's name, when it is a known one.
        class_name: Option<String>,
        header_type: Hex,
        multifunction: bool,
        command: Hex,
        /// The names of the command register's set bits.
        command_flags: Vec<&'static str>,
        status: Hex,
        /// The names of the status register's set bits.
        status_flags: Vec<&'static str>,
        /// Type 0 and 2 headers only.
        subsystem_vendor_id: Option<Hex>,
        /// Type 0 and 2 headers only.
        subsystem_id: Option<Hex>,
        bars: Vec<PciBar>,
        /// The expansion ROM base register (types 0 and 1).
        expansion_rom: Option<Hex>,
        /// Type 1 and 2 headers only.
        buses: Option<PciBuses>,
        interrupt_line: Hex,
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
        extension: Hex(device.extension.0),
        pdo: Hex(device.device_object.0),
        bus: device.bus,
        device: device.device,
        function: device.function,
        vendor_id: Hex(device.vendor_id.into()),
        device_id: Hex(device.device_id.into()),
        revision: Hex(device.revision.into()),
        base_class: Hex(device.base_class.into()),
        sub_class: Hex(device.sub_class.into()),
        prog_if: Hex(device.prog_if.into()),
        class_name: class_name(device.base_class, device.sub_class),
        subsystem_vendor_id: Hex(device.subsystem_vendor_id.into()),
        subsystem_id: Hex(device.subsystem_id.into()),
        header_type: Hex(device.header_type.into()),
        instance_path: device.instance_path.clone(),
    }
}

fn pci_bus(bus: &pci::PciTreeBus) -> PciBus {
    PciBus {
        extension: Hex(bus.extension.0),
        number: bus.number,
        subordinate: bus.subordinate,
        bridge_pdo: Hex(bus.bridge_pdo.0),
        devices: bus.devices.iter().map(pci_tree_device).collect(),
        child_buses: bus.child_buses.iter().map(pci_bus).collect(),
    }
}

/// pci.sys's hierarchy.
pub fn pci_tree(tree: &pci::PciTree) -> View {
    PciTree {
        segments: tree
            .segments
            .iter()
            .map(|segment| PciSegment {
                address: Hex(segment.address.0),
                segment: segment.number,
                root_buses: segment.root_buses.iter().map(pci_bus).collect(),
            })
            .collect(),
        truncated: tree.truncated,
        errors: tree.errors.clone(),
    }
    .view()
}

fn pci_capabilities(
    list: &[pci::PciCapability],
    name: fn(u16) -> Option<&'static str>,
) -> Vec<PciCapability> {
    list.iter()
        .map(|capability| PciCapability {
            offset: Hex(capability.offset.into()),
            id: Hex(capability.id.into()),
            name: name(capability.id),
            version: Omit(capability.version),
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
        vendor_id: Hex(header.vendor_id.into()),
        device_id: Hex(header.device_id.into()),
        revision: Hex(header.revision.into()),
        base_class: Hex(header.base_class.into()),
        sub_class: Hex(header.sub_class.into()),
        prog_if: Hex(header.prog_if.into()),
        class_name: class_name(header.base_class, header.sub_class),
        header_type: Hex(header.header_type.into()),
        multifunction: header.multifunction(),
        command: Hex(header.command.into()),
        command_flags: command_flags(header.command),
        status: Hex(header.status.into()),
        status_flags: status_flags(header.status),
        subsystem_vendor_id: header.subsystem.map(|(vendor, _)| Hex(vendor.into())),
        subsystem_id: header.subsystem.map(|(_, id)| Hex(id.into())),
        bars: header
            .bars
            .iter()
            .map(|bar| PciBar {
                index: bar.index,
                kind: bar.kind.name(),
                address: Hex(bar.address),
                prefetchable: bar.prefetchable,
                raw: Hex(bar.raw),
            })
            .collect(),
        expansion_rom: header.expansion_rom.map(|rom| Hex(rom.into())),
        buses: header
            .buses
            .map(|(primary, secondary, subordinate)| PciBuses {
                primary,
                secondary,
                subordinate,
            }),
        interrupt_line: Hex(header.interrupt_line.into()),
        interrupt_pin: header.interrupt_pin,
        capabilities: pci_capabilities(&list, capability_name),
        extended_capabilities: pci_capabilities(&extended, extended_capability_name),
        config: raw.map(|raw| {
            let end = raw.end.min(config.len());
            let start = raw.start.min(end);
            PciConfigBytes {
                offset: Hex(start as u64),
                bytes: hex::encode(&config[start..end]),
            }
        }),
    }
}

/// Configuration space of the functions a `!pci` scan found, each with the
/// requested raw range.
pub fn pci(scan: &pci::PciScan, raw: Option<PciRawRange>) -> View {
    PciScan {
        functions: scan
            .functions
            .iter()
            .map(|function| pci_function(function, raw))
            .collect(),
        interrupted: scan.interrupted,
    }
    .view()
}
