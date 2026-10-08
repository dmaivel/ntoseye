//! NDIS (`!ndiskd.*`): network miniports, their filter stacks, protocol
//! bindings, and pending OID requests, and the miniport drivers.

use std::fmt::Display;

use tabled::builder::Builder;

use crate::error::Result;
use crate::repl::*;
use crate::target::ndis::{
    NdisDriver, NdisDriverList, NdisMiniport, NdisMiniportDetail, NdisMiniportListEntry,
    NdisOidRequest, link_speed_text, oid_name,
};
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

/// A labeled line of a detail view.
fn field(label: &str, value: impl Display) {
    outln!("{} {value}", ui::label(&format!("{label:<20}")));
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
}
