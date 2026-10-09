//! NDIS (`!ndiskd.*`): network miniports, their filter stacks, protocol
//! bindings, and pending OID requests, and the miniport drivers.

use std::fmt::Display;

use tabled::builder::Builder;

use crate::error::Result;
use crate::ntstatus::ntstatus_name;
use crate::repl::memory_view::{AsciiCell, MemoryDisplayMode, row_ascii, row_items};
use crate::repl::*;
use crate::target::Target;
use crate::target::ndis::{
    MAX_NET_BUFFER_DATA, NdisDriver, NdisDriverList, NdisFilterDetail, NdisFilterDriver,
    NdisFilterDriverList, NdisFilterListEntry, NdisMiniport, NdisMiniportDetail,
    NdisMiniportListEntry, NdisNbl, NdisOidOwner, NdisOidRequest, NdisPendingOids,
    NdisProtocolDetail, NdisProtocolList, link_speed_text, nbl_flag_names, oid_name,
};
use crate::types::VirtAddr;
use crate::ui;

repl_command! {
    cmd_ndiskd_miniports();
    names: ["!ndiskd.miniports"],
    usage: "!ndiskd.miniports",
    summary: "List the NDIS miniports (network adapters).",
    details: "Walks ndis!ndisMiniportList and shows one line per miniport: the address of its _NDIS_MINIPORT_BLOCK, which !ndiskd.miniport takes, the service of its miniport driver, the miniport state (Running, Pausing, Paused, Restarting, Initializing, Halted), the media connect state with the transmit link speed (and the receive speed when it differs), the device power state, the interface index, and the friendly name. Virtual miniports, such as Hyper-V's adapters, are on the list too. The command needs the PDB for ndis.sys.",
}

repl_command! {
    cmd_ndiskd_miniport;
    names: ["!ndiskd.miniport"],
    usage: "!ndiskd.miniport [<miniport>]",
    summary: "Show an NDIS miniport: its driver, state, filter stack, bindings, and pending OID.",
    details: "Give the address that !ndiskd.miniports lists. The command shows the device name and instance ID, the miniport driver with its image and versions, the adapter context (MiniportAdapterContext, the driver's own context, which you can dt with the driver's PDB), the FDO and PDO (none for a virtual miniport), the miniport, PnP, and power states, the medium and link, the interface index and NetLuid, the reference count, the reset counts and the status of the last reset, the pending OID request with its OID, type, and buffer, and PendingReturnNBLCount. Then it shows the filter stack from the top down along each filter's LowerFilter link, with each filter's state, driver image, module context, and pending OID request, and the protocols bound to the miniport. A filter whose HigherFilter does not lead back ends the stack walk with the reason. Without an address, the command lists the miniports as !ndiskd.miniports does.",
    completion: Expression,
}

repl_command! {
    cmd_ndiskd_minidriver;
    names: ["!ndiskd.minidriver"],
    usage: "!ndiskd.minidriver [<minidriver>]",
    summary: "List the NDIS miniport drivers, or show one and its miniports.",
    details: "Without an address, walks ndis!ndisMiniDriverList and shows each miniport driver's _NDIS_M_DRIVER_BLOCK, service name, image, NDIS version, driver version, and number of miniports. With the address of a driver block, as this list or !ndiskd.miniport shows it, the command shows the driver's DRIVER_OBJECT, the module its code is in, its versions, and its miniports.",
    completion: Expression,
}

repl_command! {
    cmd_ndiskd_protocol;
    names: ["!ndiskd.protocol"],
    usage: "!ndiskd.protocol [<protocol>]",
    summary: "List the NDIS protocol drivers, or show one and its bindings.",
    details: "Without an address, walks ndis!ndisProtocolList and shows each protocol's _NDIS_PROTOCOL_BLOCK, name, image, NDIS version, driver version, and number of bindings. With the address of a protocol block, as this list or !ndiskd.miniport shows it, the command shows the protocol's driver context, flags, and BindAdapterHandlerEx, and each binding (_NDIS_OPEN_BLOCK) with the miniport it opened and the protocol's binding context. The command needs the PDB for ndis.sys.",
    completion: Expression,
}

repl_command! {
    cmd_ndiskd_filterdriver;
    names: ["!ndiskd.filterdriver"],
    usage: "!ndiskd.filterdriver [<filterdriver>]",
    summary: "List the NDIS filter drivers, or show one and its filter modules.",
    details: "Without an address, walks ndis!ndisFilterDriverList and shows each filter driver's _NDIS_FILTER_DRIVER_BLOCK, friendly name, service, image, NDIS version, driver version, and number of filter modules. With the address of a filter driver block, the command shows the driver's unique name (its GUID), DRIVER_OBJECT, the module its code is in, its driver context and flags, and its filter modules, one for each miniport it is attached to. The command needs the PDB for ndis.sys.",
    completion: Expression,
}

repl_command! {
    cmd_ndiskd_filter;
    names: ["!ndiskd.filter"],
    usage: "!ndiskd.filter [<filter>]",
    summary: "List the NDIS filter modules, or show one.",
    details: "Without an address, walks ndis!ndisGlobalFilterList and shows each filter module of every miniport: its _NDIS_FILTER_BLOCK, state, driver image, miniport, and name. With the address of a filter block, as this list or !ndiskd.miniport shows it, the command shows the filter driver, the miniport, the filter modules above and below it on the miniport's stack, the module context (FilterModuleContext, which you can dt with the driver's PDB), the link the filter last saw indicated, the reference count, the NBLs and status indications NDIS dropped because the filter was not running, and the pending OID request. The command needs the PDB for ndis.sys.",
    completion: Expression,
}

repl_command! {
    cmd_ndiskd_oid();
    names: ["!ndiskd.oid"],
    usage: "!ndiskd.oid",
    summary: "Show the OID requests that miniports and filters have not completed.",
    details: "Reads the PendingOidRequest of every miniport on ndis!ndisMiniportList and every filter module on ndis!ndisGlobalFilterList, and shows each request with its owner, type, OID by its ntddndis.h name, and buffer. NDIS passes a miniport or filter one OID request at a time, apart from direct OID requests, so a request that stays here holds up the ones behind it. The command needs the PDB for ndis.sys.",
}

repl_command! {
    cmd_ndiskd_nbl;
    names: ["!ndiskd.nbl"],
    usage: "!ndiskd.nbl <nbl> [-chain] [-data]",
    summary: "Show a NET_BUFFER_LIST and its NET_BUFFERs.",
    details: "Shows the _NET_BUFFER_LIST at the address: its next and parent NBLs, its source handle with the miniport, filter module, or binding it names, its pool, context, Flags and NblFlags (by NDIS_NBL_FLAGS_ name), status, and child reference count, and each NET_BUFFER with its data length, data offset, current MDL and offset into it, and MDL chain. -chain lists every NBL on the Next chain from the address, with its NET_BUFFERs, bytes, source, and status. -data dumps each NET_BUFFER's data, up to 64 KiB of it, read through the MDLs' PFNs, so a buffer that is not mapped into system space reads too. The command needs the PDB for ndis.sys.",
    completion: Expression,
}

/// A labeled line of a detail view.
fn field(label: &str, value: impl Display) {
    outln!("{} {value}", ui::label(&format!("{label:<20}")));
}

/// An address, or a muted `none` for a null pointer that means there is
/// none, such as the end of a chain.
fn addr_or_none(value: VirtAddr) -> String {
    if value.is_zero() {
        ui::muted("none")
    } else {
        ui::addr(value.0)
    }
}

fn print_stopped(what: &str, stopped: &Option<String>) {
    if let Some(stopped) = stopped {
        outln!("({what} stopped: {stopped})");
    }
}

/// The media connect state, with the link speed of a connected miniport:
/// the transmit speed, and the receive speed when it differs.
fn media_text(miniport: &NdisMiniport) -> String {
    if !miniport.connected {
        return miniport.media_connect.clone();
    }
    if miniport.xmit_link_speed == miniport.rcv_link_speed {
        format!(
            "{} {}",
            miniport.media_connect,
            link_speed_text(miniport.xmit_link_speed)
        )
    } else {
        format!(
            "{} {} / {}",
            miniport.media_connect,
            link_speed_text(miniport.xmit_link_speed),
            link_speed_text(miniport.rcv_link_speed)
        )
    }
}

fn version_text((major, minor): (u8, u8)) -> String {
    format!("{major}.{minor}")
}

fn oid_text(request: &NdisOidRequest) -> String {
    let name = oid_name(request.oid).unwrap_or("unknown OID");
    let mut text = format!(
        "{}  {} {name} ({:#x})  buffer {} {:#x} bytes",
        ui::addr(request.address.0),
        request.request_type,
        request.oid,
        ui::addr_opt(request.buffer),
        request.buffer_length
    );
    if let Some((output_length, method_id)) = request.method {
        text.push_str(&format!(
            ", output {output_length:#x} bytes, method {method_id:#x}"
        ));
    }
    if request.port != 0 {
        text.push_str(&format!(", port {}", request.port));
    }
    if request.timeout != 0 {
        text.push_str(&format!(", timeout {}s", request.timeout));
    }
    text
}

fn pending_oid_text(pending: &Option<std::result::Result<NdisOidRequest, String>>) -> String {
    match pending {
        None => ui::muted("none"),
        Some(Ok(request)) => oid_text(request),
        Some(Err(error)) => ui::muted(error),
    }
}

fn print_miniport_table(miniports: &[NdisMiniportListEntry]) {
    let mut builder = Builder::default();
    builder.push_record([
        "Miniport", "Driver", "State", "Media", "Power", "IfIndex", "Name",
    ]);
    for entry in miniports {
        match entry {
            Ok(miniport) => builder.push_record([
                ui::addr(miniport.address.0),
                miniport.driver_name.clone().unwrap_or_else(|| "?".into()),
                miniport.state.clone(),
                media_text(miniport),
                miniport.power.clone(),
                miniport.if_index.to_string(),
                miniport
                    .friendly_name
                    .clone()
                    .unwrap_or_else(|| miniport.name.clone()),
            ]),
            Err(unreadable) => builder.push_record([
                ui::addr(unreadable.address.0),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                ui::muted(&format!("unreadable: {}", unreadable.error)),
            ]),
        }
    }
    print_padded_table(builder);
}

fn print_driver_fields(driver: &NdisDriver) {
    field("Service", &driver.service_name);
    field(
        "Image",
        match &driver.module {
            Some(module) => format!("{}  (module {module})", driver.image_name),
            None => driver.image_name.clone(),
        },
    );
    field("DRIVER_OBJECT", ui::addr_opt(driver.driver_object));
    field("NDIS version", version_text(driver.ndis_version));
    if let Some(version) = driver.driver_version {
        field("Driver version", version_text(version));
    }
}

fn print_minidrivers(list: &NdisDriverList) {
    let mut builder = Builder::default();
    builder.push_record([
        "Driver block",
        "Service",
        "Image",
        "NDIS",
        "Version",
        "Miniports",
    ]);
    for entry in &list.drivers {
        match entry {
            Ok(driver) => builder.push_record([
                ui::addr(driver.address.0),
                driver.service_name.clone(),
                driver.image_name.clone(),
                version_text(driver.ndis_version),
                driver.driver_version.map(version_text).unwrap_or_default(),
                driver.miniports.len().to_string(),
            ]),
            Err(unreadable) => builder.push_record([
                ui::addr(unreadable.address.0),
                ui::muted(&format!("unreadable: {}", unreadable.error)),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            ]),
        }
    }
    print_padded_table(builder);
    print_stopped("driver list", &list.stopped);
}

fn print_minidriver(driver: &NdisDriver, miniports: &[NdisMiniportListEntry]) {
    field("Driver block", ui::addr(driver.address.0));
    print_driver_fields(driver);
    outln!();
    outln!("{} ({})", ui::label("Miniports"), miniports.len());
    if !miniports.is_empty() {
        print_miniport_table(miniports);
    }
    print_stopped("miniport list", &driver.miniports_stopped);
}

fn print_miniport(detail: &NdisMiniportDetail) {
    let miniport = &detail.summary;
    field(
        "Miniport",
        format!(
            "{}  {}",
            ui::addr(miniport.address.0),
            miniport.friendly_name.as_deref().unwrap_or_default()
        ),
    );
    if !detail.listed {
        field(
            "Note",
            ui::muted("not on ndis!ndisMiniportList (being added or removed, or not a miniport)"),
        );
    }
    field("Device name", &miniport.name);
    if let Some(instance_id) = &detail.instance_id {
        field("Instance ID", instance_id);
    }
    field("NDIS version", version_text(detail.ndis_version));
    match &detail.driver {
        Ok(driver) => {
            let mut text = format!("{}  {}", ui::addr(driver.address.0), driver.service_name);
            if !driver.image_name.is_empty() {
                text.push_str(&format!(" ({})", driver.image_name));
            }
            if let Some(version) = driver.driver_version {
                text.push_str(&format!(" v{}", version_text(version)));
            }
            field("Driver", text);
            field("DRIVER_OBJECT", ui::addr_opt(driver.driver_object));
        }
        Err(error) => field("Driver", ui::muted(error)),
    }
    // A driver without a DRIVER_OBJECT has no module to look up; its image
    // name without the extension is the module name its PDB goes by.
    let module = detail.driver.as_ref().ok().and_then(|driver| {
        driver.module.as_deref().or_else(|| {
            driver
                .image_name
                .rsplit_once('.')
                .map(|(stem, _)| stem)
                .filter(|stem| !stem.is_empty())
        })
    });
    field(
        "Adapter context",
        if detail.adapter_context.is_zero() {
            ui::muted("none")
        } else {
            format!(
                "{}  {}",
                ui::addr(detail.adapter_context.0),
                ui::muted(&format!(
                    "(dt {}!<adapter type> {:x})",
                    module.unwrap_or("<driver>"),
                    detail.adapter_context.0
                ))
            )
        },
    );
    if detail.device_object.is_zero() && detail.pdo.is_zero() {
        field("Device objects", ui::muted("none (a virtual miniport)"));
    } else {
        field(
            "Device objects",
            format!(
                "FDO {}  PDO {}",
                ui::addr_opt(detail.device_object),
                ui::addr_opt(detail.pdo)
            ),
        );
    }
    outln!();
    field("State", &miniport.state);
    field("PnP state", &miniport.pnp_state);
    field("Power", &miniport.power);
    field(
        "Media",
        format!(
            "{}, {} duplex, medium {}, physical {}",
            miniport.media_connect, detail.duplex, detail.medium, detail.physical_medium
        ),
    );
    field(
        "Link speed",
        format!(
            "{} transmit, {} receive",
            link_speed_text(miniport.xmit_link_speed),
            link_speed_text(miniport.rcv_link_speed)
        ),
    );
    field(
        "Interface",
        format!(
            "IfIndex {}, NetLuid {:#x}, {}",
            miniport.if_index, detail.net_luid, detail.oper_status
        ),
    );
    field(
        "References",
        detail
            .references
            .map_or_else(|| ui::muted("unreadable"), |count| count.to_string()),
    );
    field(
        "Resets",
        format!(
            "internal {}, miniport {}, last status {:#x}",
            detail.resets.0, detail.resets.1, detail.reset_status
        ),
    );
    field("Pending OID", pending_oid_text(&detail.pending_oid));
    field("Pending return NBLs", detail.pending_return_nbls);
    field(
        "Flags",
        format!("{:#x}, PnP flags {:#x}", detail.flags, detail.pnp_flags),
    );

    outln!();
    outln!(
        "{} ({}, top first)",
        ui::label("Filters"),
        detail.filters.len()
    );
    if !detail.filters.is_empty() {
        let mut builder = Builder::default();
        builder.push_record(["Filter", "State", "Driver", "Context", "Name"]);
        for filter in &detail.filters {
            builder.push_record([
                ui::addr(filter.address.0),
                filter.state.clone(),
                filter.driver_image.clone().unwrap_or_else(|| "?".into()),
                ui::addr_opt(filter.context),
                filter.name.clone().unwrap_or_default(),
            ]);
        }
        print_padded_table(builder);
        for filter in &detail.filters {
            if filter.pending_oid.is_some() {
                outln!(
                    "filter {} pending OID: {}",
                    ui::addr(filter.address.0),
                    pending_oid_text(&filter.pending_oid)
                );
            }
        }
    }
    print_stopped("filter stack", &detail.filters_stopped);

    outln!();
    outln!(
        "{} ({}, NumOpens {})",
        ui::label("Protocol bindings"),
        detail.opens.len(),
        detail.num_opens
    );
    if !detail.opens.is_empty() {
        let mut builder = Builder::default();
        builder.push_record(["Open", "Protocol", "Protocol block", "Context"]);
        for open in &detail.opens {
            builder.push_record([
                ui::addr(open.address.0),
                open.protocol_name.clone().unwrap_or_else(|| "?".into()),
                ui::addr_opt(open.protocol),
                ui::addr_opt(open.context),
            ]);
        }
        print_padded_table(builder);
    }
    print_stopped("binding list", &detail.opens_stopped);
}

fn print_filter_table(filters: &[NdisFilterListEntry]) {
    let mut builder = Builder::default();
    builder.push_record(["Filter", "State", "Driver", "Miniport", "Name"]);
    for entry in filters {
        match entry {
            Ok(filter) => builder.push_record([
                ui::addr(filter.address.0),
                filter.state.clone(),
                filter.driver_image.clone().unwrap_or_else(|| "?".into()),
                ui::addr_opt(filter.miniport),
                filter.name.clone().unwrap_or_default(),
            ]),
            Err(unreadable) => builder.push_record([
                ui::addr(unreadable.address.0),
                String::new(),
                String::new(),
                String::new(),
                ui::muted(&format!("unreadable: {}", unreadable.error)),
            ]),
        }
    }
    print_padded_table(builder);
}

fn print_filter(detail: &NdisFilterDetail) {
    let filter = &detail.filter;
    field(
        "Filter",
        format!(
            "{}  {}",
            ui::addr(filter.address.0),
            filter.name.as_deref().unwrap_or_default()
        ),
    );
    if !detail.listed {
        field(
            "Note",
            ui::muted("not on ndis!ndisGlobalFilterList (being attached or detached)"),
        );
    }
    let mut driver = ui::addr_opt(filter.driver);
    if let Some(name) = &detail.driver_name {
        driver.push_str(&format!("  {name}"));
    }
    if let Some(image) = &filter.driver_image {
        driver.push_str(&format!(" ({image})"));
    }
    field("Filter driver", driver);
    field(
        "Miniport",
        format!(
            "{}  {}",
            ui::addr_opt(filter.miniport),
            filter.miniport_name.as_deref().unwrap_or_default()
        ),
    );
    let module = filter
        .driver_image
        .as_deref()
        .and_then(|image| image.rsplit_once('.').map(|(stem, _)| stem))
        .unwrap_or("<driver>");
    field(
        "Module context",
        if filter.context.is_zero() {
            ui::muted("none")
        } else {
            format!(
                "{}  {}",
                ui::addr(filter.context.0),
                ui::muted(&format!(
                    "(dt {module}!<context type> {:x})",
                    filter.context.0
                ))
            )
        },
    );
    field(
        "Stack",
        format!(
            "higher {}, lower {}",
            if detail.higher.is_zero() {
                ui::muted("none (top)")
            } else {
                ui::addr(detail.higher.0)
            },
            if detail.lower.is_zero() {
                ui::muted("none (bottom, above the miniport)")
            } else {
                ui::addr(detail.lower.0)
            }
        ),
    );
    outln!();
    field("State", &filter.state);
    field(
        "Link",
        format!(
            "{}, {} transmit, {} receive",
            detail.media_connect,
            link_speed_text(detail.xmit_link_speed),
            link_speed_text(detail.rcv_link_speed)
        ),
    );
    field("IfIndex", detail.if_index);
    field(
        "References",
        detail
            .references
            .map_or_else(|| ui::muted("unreadable"), |count| count.to_string()),
    );
    field(
        "Dropped",
        format!(
            "{} receive NBLs, {} send NBLs, {} status indications",
            detail.dropped_receive_nbls,
            detail.dropped_send_nbls,
            detail.dropped_status_indications
        ),
    );
    field("Pending OID", pending_oid_text(&filter.pending_oid));
    field("Flags", format!("{:#x}", detail.flags));
}

fn print_filter_drivers(list: &NdisFilterDriverList) {
    let mut builder = Builder::default();
    builder.push_record([
        "Driver block",
        "Name",
        "Service",
        "Image",
        "NDIS",
        "Version",
        "Filters",
    ]);
    for entry in &list.drivers {
        match entry {
            Ok(driver) => builder.push_record([
                ui::addr(driver.address.0),
                driver.friendly_name.clone(),
                driver.service_name.clone(),
                driver.image_name.clone(),
                version_text(driver.ndis_version),
                version_text(driver.driver_version),
                driver.filters.len().to_string(),
            ]),
            Err(unreadable) => builder.push_record([
                ui::addr(unreadable.address.0),
                ui::muted(&format!("unreadable: {}", unreadable.error)),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            ]),
        }
    }
    print_padded_table(builder);
    print_stopped("filter driver list", &list.stopped);
}

fn print_filter_driver(driver: &NdisFilterDriver, filters: &[NdisFilterListEntry]) {
    field("Driver block", ui::addr(driver.address.0));
    field("Name", &driver.friendly_name);
    field("Unique name", &driver.unique_name);
    field("Service", &driver.service_name);
    field(
        "Image",
        match &driver.module {
            Some(module) => format!("{}  (module {module})", driver.image_name),
            None => driver.image_name.clone(),
        },
    );
    field("DRIVER_OBJECT", ui::addr_opt(driver.driver_object));
    field("Driver context", addr_or_none(driver.context));
    field("NDIS version", version_text(driver.ndis_version));
    field("Driver version", version_text(driver.driver_version));
    field("Flags", format!("{:#x}", driver.flags));
    outln!();
    outln!("{} ({})", ui::label("Filter modules"), filters.len());
    if !filters.is_empty() {
        print_filter_table(filters);
    }
    print_stopped("filter module list", &driver.filters_stopped);
}

fn print_protocols(list: &NdisProtocolList) {
    let mut builder = Builder::default();
    builder.push_record([
        "Protocol block",
        "Name",
        "Image",
        "NDIS",
        "Version",
        "Bindings",
    ]);
    for entry in &list.protocols {
        match entry {
            Ok(protocol) => builder.push_record([
                ui::addr(protocol.address.0),
                protocol.name.clone(),
                protocol.image_name.clone().unwrap_or_default(),
                version_text(protocol.ndis_version),
                version_text(protocol.driver_version),
                protocol.opens.len().to_string(),
            ]),
            Err(unreadable) => builder.push_record([
                ui::addr(unreadable.address.0),
                ui::muted(&format!("unreadable: {}", unreadable.error)),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            ]),
        }
    }
    print_padded_table(builder);
    print_stopped("protocol list", &list.stopped);
}

fn print_protocol(detail: &NdisProtocolDetail) {
    let protocol = &detail.protocol;
    field(
        "Protocol block",
        format!("{}  {}", ui::addr(protocol.address.0), protocol.name),
    );
    if !detail.listed {
        field(
            "Note",
            ui::muted("not on ndis!ndisProtocolList (being registered or deregistered)"),
        );
    }
    if let Some(image) = &protocol.image_name {
        field("Image", image);
    }
    field("NDIS version", version_text(protocol.ndis_version));
    field("Driver version", version_text(protocol.driver_version));
    field("Driver context", addr_or_none(protocol.context));
    field(
        "BindAdapterHandlerEx",
        match &detail.bind_handler_name {
            Some(name) => format!("{}  {name}", ui::addr(protocol.bind_handler.0)),
            None => addr_or_none(protocol.bind_handler),
        },
    );
    field("Flags", format!("{:#x}", protocol.flags));
    outln!();
    outln!("{} ({})", ui::label("Bindings"), detail.bindings.len());
    if !detail.bindings.is_empty() {
        let mut builder = Builder::default();
        builder.push_record(["Open", "Miniport", "Context", "Name"]);
        for binding in &detail.bindings {
            builder.push_record([
                ui::addr(binding.open.0),
                ui::addr_opt(binding.miniport),
                ui::addr_opt(binding.context),
                binding.miniport_name.clone().unwrap_or_default(),
            ]);
        }
        print_padded_table(builder);
    }
    print_stopped("binding list", &detail.bindings_stopped);
}

fn print_pending_oids(oids: &NdisPendingOids) {
    if oids.pending.is_empty() {
        outln!(
            "No pending OID requests on {} miniports and {} filter modules.",
            oids.miniports,
            oids.filters
        );
    } else {
        let mut builder = Builder::default();
        builder.push_record(["Owner", "Address", "Request", "Name"]);
        for pending in &oids.pending {
            builder.push_record([
                match pending.owner {
                    NdisOidOwner::Miniport => "miniport".to_string(),
                    NdisOidOwner::Filter => "filter".to_string(),
                },
                ui::addr(pending.address.0),
                match &pending.request {
                    Ok(request) => oid_text(request),
                    Err(error) => ui::muted(error),
                },
                pending.name.clone().unwrap_or_default(),
            ]);
        }
        print_padded_table(builder);
    }
    for problem in &oids.problems {
        outln!("({problem})");
    }
}

fn status_text(status: u32) -> String {
    match ntstatus_name(status) {
        Some(name) => format!("{status:#x} ({name})"),
        None => format!("{status:#x}"),
    }
}

fn print_nbl(nbl: &NdisNbl) {
    field("NBL", ui::addr(nbl.address.0));
    field("Next", addr_or_none(nbl.next));
    field("Parent", addr_or_none(nbl.parent));
    field(
        "Source",
        match &nbl.source {
            Some(source) => format!("{}  {source}", ui::addr(nbl.source_handle.0)),
            None => addr_or_none(nbl.source_handle),
        },
    );
    field("Pool", addr_or_none(nbl.pool));
    field("Context", addr_or_none(nbl.context));
    let names = nbl_flag_names(nbl.nbl_flags);
    field(
        "Flags",
        format!(
            "{:#x}, NblFlags {:#x}{}",
            nbl.flags,
            nbl.nbl_flags,
            if names.is_empty() {
                String::new()
            } else {
                format!(" ({})", names.join(" "))
            }
        ),
    );
    field("Status", status_text(nbl.status));
    field("Child references", nbl.child_ref_count);
    outln!();
    outln!("{} ({})", ui::label("NET_BUFFERs"), nbl.net_buffers.len());
    if !nbl.net_buffers.is_empty() {
        let mut builder = Builder::default();
        builder.push_record([
            "NET_BUFFER",
            "Length",
            "Offset",
            "Current MDL",
            "MDL offset",
            "MDL chain",
        ]);
        for nb in &nbl.net_buffers {
            builder.push_record([
                ui::addr(nb.address.0),
                format!("{:#x}", nb.data_length),
                format!("{:#x}", nb.data_offset),
                addr_or_none(nb.current_mdl),
                format!("{:#x}", nb.current_mdl_offset),
                addr_or_none(nb.mdl_chain),
            ]);
        }
        print_padded_table(builder);
    }
    print_stopped("NET_BUFFER chain", &nbl.net_buffers_stopped);
}

fn print_nbl_chain(nbls: &[NdisNbl], stopped: &Option<String>) {
    let mut builder = Builder::default();
    builder.push_record(["NBL", "NET_BUFFERs", "Bytes", "Status", "Source"]);
    for nbl in nbls {
        let bytes: u64 = nbl
            .net_buffers
            .iter()
            .map(|nb| u64::from(nb.data_length))
            .sum();
        builder.push_record([
            ui::addr(nbl.address.0),
            nbl.net_buffers.len().to_string(),
            format!("{bytes:#x}"),
            status_text(nbl.status),
            nbl.source
                .clone()
                .unwrap_or_else(|| addr_or_none(nbl.source_handle)),
        ]);
    }
    print_padded_table(builder);
    print_stopped("NBL chain", stopped);
}

/// Each NET_BUFFER's data as rows of 16 bytes, by offset into the frame.
fn print_nbl_data(target: &Target, nbl: &NdisNbl) {
    let mode = MemoryDisplayMode::bytes();
    for nb in &nbl.net_buffers {
        let shown = (nb.data_length as usize).min(MAX_NET_BUFFER_DATA);
        let mut title = format!(
            "{} {} ({:#x} bytes",
            ui::label("Data of NET_BUFFER"),
            ui::addr(nb.address.0),
            nb.data_length
        );
        if shown < nb.data_length as usize {
            title.push_str(&format!(", the first {shown:#x} shown"));
        }
        outln!("{title})");
        let data = match target.ndis_net_buffer_data(nb, MAX_NET_BUFFER_DATA) {
            Ok(data) => data,
            Err(error) => {
                error!("NET_BUFFER {:#x}: {error}", nb.address.0);
                continue;
            }
        };
        for (row, chunk) in data.chunks(mode.bytes_per_row()).enumerate() {
            out!("{:04x}  ", row * mode.bytes_per_row());
            row_items(row, chunk, None, &mode, |_, text| out!("{text}"));
            out!(" ");
            row_ascii(row, chunk, None, &mode, |cell| match cell {
                AsciiCell::Unreadable => out!("?"),
                AsciiCell::Char(character) => out!("{character}"),
                AsciiCell::Dot => out!("{}", ui::muted(".")),
            });
            outln!();
        }
        outln!();
    }
}

impl ReplState<'_> {
    fn cmd_ndiskd_miniports(&mut self) -> Result<()> {
        match self.ctx.target.ndis_miniports() {
            Ok(list) => {
                print_miniport_table(&list.miniports);
                print_stopped("miniport list", &list.stopped);
            }
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_ndiskd_miniport(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(address) = invocation.arg(0) else {
            return self.cmd_ndiskd_miniports();
        };
        let Some(address) = self.eval_or_report(address) else {
            return Ok(());
        };
        match self.ctx.target.ndis_miniport(address) {
            Ok(detail) => print_miniport(&detail),
            Err(error) => error!("!ndiskd.miniport {:#x}: {error}", address.0),
        }
        Ok(())
    }

    fn cmd_ndiskd_minidriver(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(address) = invocation.arg(0) else {
            match self.ctx.target.ndis_minidrivers() {
                Ok(list) => print_minidrivers(&list),
                Err(error) => error!("{error}"),
            }
            return Ok(());
        };
        let Some(address) = self.eval_or_report(address) else {
            return Ok(());
        };
        match self.ctx.target.ndis_minidriver(address) {
            Ok((driver, miniports)) => print_minidriver(&driver, &miniports),
            Err(error) => error!("!ndiskd.minidriver {:#x}: {error}", address.0),
        }
        Ok(())
    }

    fn cmd_ndiskd_protocol(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(address) = invocation.arg(0) else {
            match self.ctx.target.ndis_protocols() {
                Ok(list) => print_protocols(&list),
                Err(error) => error!("{error}"),
            }
            return Ok(());
        };
        let Some(address) = self.eval_or_report(address) else {
            return Ok(());
        };
        match self.ctx.target.ndis_protocol_detail(address) {
            Ok(detail) => print_protocol(&detail),
            Err(error) => error!("!ndiskd.protocol {:#x}: {error}", address.0),
        }
        Ok(())
    }

    fn cmd_ndiskd_filterdriver(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(address) = invocation.arg(0) else {
            match self.ctx.target.ndis_filter_drivers() {
                Ok(list) => print_filter_drivers(&list),
                Err(error) => error!("{error}"),
            }
            return Ok(());
        };
        let Some(address) = self.eval_or_report(address) else {
            return Ok(());
        };
        match self.ctx.target.ndis_filter_driver_detail(address) {
            Ok((driver, filters)) => print_filter_driver(&driver, &filters),
            Err(error) => error!("!ndiskd.filterdriver {:#x}: {error}", address.0),
        }
        Ok(())
    }

    fn cmd_ndiskd_filter(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(address) = invocation.arg(0) else {
            match self.ctx.target.ndis_filters_all() {
                Ok(list) => {
                    print_filter_table(&list.filters);
                    print_stopped("filter list", &list.stopped);
                }
                Err(error) => error!("{error}"),
            }
            return Ok(());
        };
        let Some(address) = self.eval_or_report(address) else {
            return Ok(());
        };
        match self.ctx.target.ndis_filter_detail(address) {
            Ok(detail) => print_filter(&detail),
            Err(error) => error!("!ndiskd.filter {:#x}: {error}", address.0),
        }
        Ok(())
    }

    fn cmd_ndiskd_oid(&mut self) -> Result<()> {
        match self.ctx.target.ndis_pending_oids() {
            Ok(oids) => print_pending_oids(&oids),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_ndiskd_nbl(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let mut chain = false;
        let mut data = false;
        let mut address = None;
        for arg in &invocation.argv {
            match arg.as_ref() {
                "-chain" => chain = true,
                "-data" => data = true,
                flag if flag.len() > 1
                    && flag.starts_with('-')
                    && flag[1..].chars().all(|ch| ch.is_ascii_alphabetic()) =>
                {
                    error!(
                        "!ndiskd.nbl: unknown option {flag}; usage: !ndiskd.nbl <nbl> [-chain] [-data]"
                    );
                    return Ok(());
                }
                text if address.is_none() => address = Some(text.to_string()),
                text => {
                    error!(
                        "!ndiskd.nbl: unexpected argument {text}; usage: !ndiskd.nbl <nbl> [-chain] [-data]"
                    );
                    return Ok(());
                }
            }
        }
        let Some(address) = address else {
            error!("usage: !ndiskd.nbl <nbl> [-chain] [-data]");
            return Ok(());
        };
        let Some(address) = self.eval_or_report(&address) else {
            return Ok(());
        };
        let target = &self.ctx.target;
        if chain {
            match target.ndis_nbl_chain(address) {
                Ok((nbls, stopped)) => {
                    print_nbl_chain(&nbls, &stopped);
                    if data {
                        for nbl in &nbls {
                            print_nbl_data(target, nbl);
                        }
                    }
                }
                Err(error) => error!("!ndiskd.nbl {:#x}: {error}", address.0),
            }
            return Ok(());
        }
        match target.ndis_nbl(address) {
            Ok(nbl) => {
                print_nbl(&nbl);
                if data {
                    print_nbl_data(target, &nbl);
                }
            }
            Err(error) => error!("!ndiskd.nbl {:#x}: {error}", address.0),
        }
        Ok(())
    }
}
