//! hardware: [`View`] builders for hang diagnosis (`!qlocks`, `!ipi`) and PCI.

use super::{View, diagnostic};
use crate::target::hang::{
    IpiDetail, IpiProcessor, IpiRequest, ProcessorError, QueuedLock, QueuedLockState,
    QueuedLocksDetail, ipi_frozen_name, ipi_request_type_name,
};
use crate::target::pci::{
    CAPABILITY_PCI_EXPRESS, PCI_CONFIG_SIZE, PciCapability, PciFunctionConfig, PciRawRange,
    PciScan, PciTree, PciTreeBus, PciTreeDevice, capabilities, capability_name, class_name,
    command_flags, extended_capabilities, extended_capability_name, parse_header, status_flags,
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

fn pci_tree_device(device: &PciTreeDevice) -> View {
    View::Object(vec![
        ("extension", View::Hex(device.extension.0)),
        ("pdo", View::Hex(device.device_object.0)),
        ("bus", View::Num(device.bus.into())),
        ("device", View::Num(device.device.into())),
        ("function", View::Num(device.function.into())),
        ("vendor_id", View::Hex(device.vendor_id.into())),
        ("device_id", View::Hex(device.device_id.into())),
        ("revision", View::Hex(device.revision.into())),
        ("base_class", View::Hex(device.base_class.into())),
        ("sub_class", View::Hex(device.sub_class.into())),
        ("prog_if", View::Hex(device.prog_if.into())),
        (
            "class_name",
            View::OptStr(class_name(device.base_class, device.sub_class)),
        ),
        (
            "subsystem_vendor_id",
            View::Hex(device.subsystem_vendor_id.into()),
        ),
        ("subsystem_id", View::Hex(device.subsystem_id.into())),
        ("header_type", View::Hex(device.header_type.into())),
        ("instance_path", View::OptStr(device.instance_path.clone())),
    ])
}

fn pci_tree_bus(bus: &PciTreeBus) -> View {
    View::Object(vec![
        ("extension", View::Hex(bus.extension.0)),
        ("number", View::Num(bus.number.into())),
        ("subordinate", View::Num(bus.subordinate.into())),
        ("bridge_pdo", View::Hex(bus.bridge_pdo.0)),
        (
            "devices",
            View::List(bus.devices.iter().map(pci_tree_device).collect()),
        ),
        (
            "child_buses",
            View::List(bus.child_buses.iter().map(pci_tree_bus).collect()),
        ),
    ])
}

/// pci.sys's hierarchy; top-level keys: `segments` (each with `root_buses`,
/// which nest `child_buses`), `truncated`, `errors` (each unreadable bus or
/// function, whose list the walk left).
pub fn pci_tree(tree: &PciTree) -> View {
    let segments = tree
        .segments
        .iter()
        .map(|segment| {
            View::Object(vec![
                ("address", View::Hex(segment.address.0)),
                ("segment", View::Num(segment.number.into())),
                (
                    "root_buses",
                    View::List(segment.root_buses.iter().map(pci_tree_bus).collect()),
                ),
            ])
        })
        .collect();
    View::Object(vec![
        ("segments", View::List(segments)),
        ("truncated", View::Bool(tree.truncated)),
        (
            "errors",
            View::List(tree.errors.iter().map(|e| View::Str(e.clone())).collect()),
        ),
    ])
}

fn pci_capabilities(list: &[PciCapability], name: fn(u16) -> Option<&'static str>) -> View {
    View::List(
        list.iter()
            .map(|capability| {
                let mut fields = vec![
                    ("offset", View::Hex(capability.offset.into())),
                    ("id", View::Hex(capability.id.into())),
                    (
                        "name",
                        View::OptStr(name(capability.id).map(str::to_string)),
                    ),
                ];
                if let Some(version) = capability.version {
                    fields.push(("version", View::Num(version.into())));
                }
                View::Object(fields)
            })
            .collect(),
    )
}

fn pci_function(function: &PciFunctionConfig, raw: Option<PciRawRange>) -> View {
    let config = &function.config;
    let mut fields = vec![
        ("segment", View::Num(function.segment.into())),
        ("bus", View::Num(function.bus.into())),
        ("device", View::Num(function.device.into())),
        ("function", View::Num(function.function.into())),
    ];
    if let Some(header) = parse_header(config) {
        let list = capabilities(&header, config);
        let extended = if list
            .iter()
            .any(|capability| capability.id == CAPABILITY_PCI_EXPRESS)
            && config.len() > PCI_CONFIG_SIZE
        {
            extended_capabilities(config)
        } else {
            Vec::new()
        };
        let bars = header
            .bars
            .iter()
            .map(|bar| {
                View::Object(vec![
                    ("index", View::Num(bar.index.into())),
                    ("kind", View::Str(bar.kind.name().into())),
                    ("address", View::Hex(bar.address)),
                    ("prefetchable", View::Bool(bar.prefetchable)),
                    ("raw", View::Hex(bar.raw)),
                ])
            })
            .collect();
        let names = |flags: Vec<&'static str>| {
            View::List(
                flags
                    .into_iter()
                    .map(|flag| View::Str(flag.into()))
                    .collect(),
            )
        };
        fields.extend([
            ("vendor_id", View::Hex(header.vendor_id.into())),
            ("device_id", View::Hex(header.device_id.into())),
            ("revision", View::Hex(header.revision.into())),
            ("base_class", View::Hex(header.base_class.into())),
            ("sub_class", View::Hex(header.sub_class.into())),
            ("prog_if", View::Hex(header.prog_if.into())),
            (
                "class_name",
                View::OptStr(class_name(header.base_class, header.sub_class)),
            ),
            ("header_type", View::Hex(header.header_type.into())),
            ("multifunction", View::Bool(header.multifunction())),
            ("command", View::Hex(header.command.into())),
            ("command_flags", names(command_flags(header.command))),
            ("status", View::Hex(header.status.into())),
            ("status_flags", names(status_flags(header.status))),
            (
                "subsystem_vendor_id",
                View::OptHex(header.subsystem.map(|(vendor, _)| vendor.into())),
            ),
            (
                "subsystem_id",
                View::OptHex(header.subsystem.map(|(_, id)| id.into())),
            ),
            ("bars", View::List(bars)),
            (
                "expansion_rom",
                View::OptHex(header.expansion_rom.map(u64::from)),
            ),
            (
                "buses",
                header
                    .buses
                    .map_or(View::Null, |(primary, secondary, subordinate)| {
                        View::Object(vec![
                            ("primary", View::Num(primary.into())),
                            ("secondary", View::Num(secondary.into())),
                            ("subordinate", View::Num(subordinate.into())),
                        ])
                    }),
            ),
            ("interrupt_line", View::Hex(header.interrupt_line.into())),
            ("interrupt_pin", View::Num(header.interrupt_pin.into())),
            ("capabilities", pci_capabilities(&list, capability_name)),
            (
                "extended_capabilities",
                pci_capabilities(&extended, extended_capability_name),
            ),
        ]);
    }
    let raw = raw.map(|raw| {
        let end = raw.end.min(config.len());
        let start = raw.start.min(end);
        View::Object(vec![
            ("offset", View::Hex(start as u64)),
            ("bytes", View::Str(hex::encode(&config[start..end]))),
        ])
    });
    fields.push(("config", raw.unwrap_or(View::Null)));
    View::Object(fields)
}

/// Configuration space of the functions a `!pci` scan found; top-level keys:
/// `functions` (each decoded, with `config` holding the requested raw range
/// as hex or null), `interrupted`.
pub fn pci(scan: &PciScan, raw: Option<PciRawRange>) -> View {
    View::Object(vec![
        (
            "functions",
            View::List(
                scan.functions
                    .iter()
                    .map(|function| pci_function(function, raw))
                    .collect(),
            ),
        ),
        ("interrupted", View::Bool(scan.interrupted)),
    ])
}
