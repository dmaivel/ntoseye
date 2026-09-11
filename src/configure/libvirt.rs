use std::{
    fs,
    io::ErrorKind,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    DEFAULT_GDB_ADDR, DEFAULT_KD_SOCKET as KD_SOCKET,
    error::{Error, Result},
};

use super::{
    Action, ApplyResult, BackendSelection, ConfigurationPlan, Configurator, ConfigureRequest,
    ConfiguredTarget, Guest, GuestInspection, Instructions, ProbeStatus, backup_file,
    kdnet_instructions, shell_quote,
};

const QEMU_NS: &str = "http://libvirt.org/schemas/domain/qemu/1.0";
const BACKENDS: &[BackendSelection] = &[
    BackendSelection::Kd,
    BackendSelection::KdNet,
    BackendSelection::Gdb,
    BackendSelection::KdAndGdb,
    BackendSelection::Memory,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DebugTransport {
    Kd,
    KdNet,
    Gdb,
}

struct XmlPlan {
    xml: String,
    changes: Vec<String>,
}

pub struct Libvirt;

impl Configurator for Libvirt {
    fn name(&self) -> &'static str {
        "KVM/libvirt"
    }

    fn probe(&self) -> ProbeStatus {
        match Command::new("virsh").arg("--version").output() {
            Err(error) if error.kind() == ErrorKind::NotFound => ProbeStatus::NotDetected,
            Err(error) => ProbeStatus::Unavailable(error.to_string()),
            Ok(output) if !output.status.success() => {
                ProbeStatus::Unavailable(command_detail(&output))
            }
            Ok(_) => match list_domains() {
                Ok(domains) => ProbeStatus::Detected(format!(
                    "{} virtual machine{}",
                    domains.len(),
                    if domains.len() == 1 { "" } else { "s" }
                )),
                Err(error) => ProbeStatus::Unavailable(error.to_string()),
            },
        }
    }

    fn guests(&self) -> Result<Vec<Guest>> {
        list_domains()
    }

    fn inspect(&self, guest: &Guest) -> Result<GuestInspection> {
        Ok(inspect_xml(&dump_xml(&guest.id)?))
    }

    fn supported_backends(&self) -> &'static [BackendSelection] {
        BACKENDS
    }

    fn supports_vmcoreinfo(&self) -> bool {
        true
    }

    fn plan(&self, guest: &Guest, request: ConfigureRequest) -> Result<Box<dyn ConfigurationPlan>> {
        let original = dump_xml(&guest.id)?;
        let xml_plan = match request.action {
            Action::Configure => {
                let backend = request.backend.ok_or_else(|| {
                    Error::DebugInfo("configure request is missing a backend".to_string())
                })?;
                let mut transports = Vec::with_capacity(2);
                if backend.kd() {
                    transports.push(DebugTransport::Kd);
                }
                if backend == BackendSelection::KdNet {
                    transports.push(DebugTransport::KdNet);
                }
                if backend.gdb() {
                    transports.push(DebugTransport::Gdb);
                }
                apply_transport_config(&original, &transports, KD_SOCKET, request.vmcoreinfo)?
            }
            Action::Remove => remove_debug_transports(&original),
        };
        let instructions = libvirt_instructions(&xml_plan.xml, request, &guest.id);
        Ok(Box::new(LibvirtPlan {
            domain: guest.id.clone(),
            original,
            planned: xml_plan,
            request,
            instructions,
        }))
    }
}

struct LibvirtPlan {
    domain: String,
    original: String,
    planned: XmlPlan,
    request: ConfigureRequest,
    instructions: Instructions,
}

impl ConfigurationPlan for LibvirtPlan {
    fn changes(&self) -> &[String] {
        &self.planned.changes
    }

    fn instructions(&self) -> &Instructions {
        &self.instructions
    }

    fn apply(&self) -> Result<ApplyResult> {
        let backup = backup_file("libvirt", &self.domain, "xml", self.original.as_bytes())?;
        let define_path = write_define_xml(&self.domain, &self.planned.xml)?;
        let define_result = virsh(["define", define_path.to_string_lossy().as_ref()]);
        let _ = fs::remove_file(&define_path);
        define_result?;

        let applied = dump_xml(&self.domain)?;
        if let Err(error) = verify_applied_config(&applied, self.request) {
            return Err(Error::DebugInfo(format!(
                "{error}; original configuration is backed up at {}",
                backup.display()
            )));
        }
        Ok(ApplyResult { backup })
    }
}

fn list_domains() -> Result<Vec<Guest>> {
    let names = virsh(["list", "--all", "--name"])?;
    let mut domains = Vec::new();
    for name in names.lines().map(str::trim).filter(|name| !name.is_empty()) {
        let state = virsh(["domstate", name])?
            .lines()
            .next()
            .unwrap_or("unknown")
            .trim()
            .to_string();
        domains.push(Guest {
            id: name.to_string(),
            name: name.to_string(),
            stopped: state.eq_ignore_ascii_case("shut off"),
            state,
        });
    }
    Ok(domains)
}

fn dump_xml(domain: &str) -> Result<String> {
    virsh(["dumpxml", "--inactive", domain]).or_else(|_| virsh(["dumpxml", domain]))
}

fn virsh<const N: usize>(args: [&str; N]) -> Result<String> {
    let output = Command::new("virsh").args(args).output().map_err(|error| {
        Error::DebugInfo(format!(
            "failed to run virsh: {error}; install libvirt clients or adjust PATH"
        ))
    })?;
    if !output.status.success() {
        return Err(Error::DebugInfo(format!(
            "virsh failed: {}",
            command_detail(&output)
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn command_detail(output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if stderr.is_empty() {
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    } else {
        stderr
    }
}

fn write_define_xml(domain: &str, xml: &str) -> Result<PathBuf> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| Error::DebugInfo(format!("system clock error: {error}")))?
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "ntoseye-{}-{timestamp}.xml",
        sanitize_filename(domain)
    ));
    fs::write(&path, xml)?;
    Ok(path)
}

fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn libvirt_instructions(xml: &str, request: ConfigureRequest, domain: &str) -> Instructions {
    if request.action == Action::Remove {
        return Instructions::default();
    }
    let backend = request.backend.expect("configure requests have a backend");
    let mut instructions = Instructions::default();
    if backend == BackendSelection::KdNet {
        instructions = kdnet_instructions(request, false);
    }
    if backend.kd() {
        let debug_port = debug_port_for_socket(xml, KD_SOCKET).unwrap_or(1);
        instructions.guest = vec![
            "bcdedit /debug on".to_string(),
            format!("bcdedit /dbgsettings serial debugport:{debug_port} baudrate:115200"),
            "Restart-Computer".to_string(),
        ];
        instructions
            .run
            .push(ConfiguredTarget::kd(KD_SOCKET, debug_port, false).run_command());
    }
    if backend.gdb() {
        instructions
            .run
            .push(ConfiguredTarget::gdb(DEFAULT_GDB_ADDR).run_command());
    }
    if request.vmcoreinfo {
        instructions.notes.push(
            "Install the virtio-win 'fwcfg' driver in the guest for crash dumps.".to_string(),
        );
        instructions.run.push(format!(
            "virsh dump {} /tmp/win.dmp --memory-only --format=win-dmp",
            shell_quote(domain)
        ));
        instructions
            .run
            .push("ntoseye --dump /tmp/win.dmp".to_string());
    }
    instructions
}

fn verify_applied_config(xml: &str, request: ConfigureRequest) -> Result<()> {
    let has_kd = debug_port_for_socket(xml, KD_SOCKET).is_some();
    let has_gdb = has_qemu_arg(xml, "-s") && has_qemu_arg(xml, "-S");
    match request.action {
        Action::Remove if has_kd || has_gdb => Err(Error::DebugInfo(
            "libvirt did not remove every ntoseye transport".to_string(),
        )),
        Action::Remove => Ok(()),
        Action::Configure => {
            let backend = request.backend.expect("configure requests have a backend");
            if has_kd != backend.kd() || has_gdb != backend.gdb() {
                return Err(Error::DebugInfo(
                    "libvirt did not retain the requested debug transports".to_string(),
                ));
            }
            if backend == BackendSelection::KdNet && !kdnet_vendor_ready(xml) {
                return Err(Error::DebugInfo(
                    "libvirt did not retain the KDNET Hyper-V vendor override".to_string(),
                ));
            }
            if request.vmcoreinfo && !xml.contains("<vmcoreinfo state=\"on\"") {
                return Err(Error::DebugInfo(
                    "libvirt did not retain vmcoreinfo".to_string(),
                ));
            }
            Ok(())
        }
    }
}

fn inspect_xml(xml: &str) -> GuestInspection {
    let mut targets = Vec::with_capacity(2);
    if let Some(port) = debug_port_for_socket(xml, KD_SOCKET) {
        targets.push(ConfiguredTarget::kd(KD_SOCKET, port, false));
    }
    if has_qemu_arg(xml, "-s") && has_qemu_arg(xml, "-S") {
        targets.push(ConfiguredTarget::gdb(DEFAULT_GDB_ADDR));
    }
    GuestInspection { targets }
}

fn debug_port_for_socket(xml: &str, socket: &str) -> Option<usize> {
    let mut cursor = 0;
    while let Some((start, end)) = find_tag_block(xml, cursor, "serial") {
        let serial = &xml[start..end];
        if serial_source_path(serial).as_deref() == Some(socket) {
            let (target_start, target_end) = find_tag_block(serial, 0, "target")?;
            let port = tag_attr(&serial[target_start..target_end], "port")?;
            return port.parse::<usize>().ok().map(|port| port + 1);
        }
        cursor = end;
    }
    None
}

fn serial_source_path(serial: &str) -> Option<String> {
    let (start, end) = find_tag_block(serial, 0, "source")?;
    tag_attr(&serial[start..end], "path")
}

fn apply_transport_config(
    xml: &str,
    transports: &[DebugTransport],
    kd_socket: &str,
    vmcoreinfo: bool,
) -> Result<XmlPlan> {
    let mut changes = Vec::new();
    let mut out = xml.to_string();

    if transports.contains(&DebugTransport::Gdb) {
        out = ensure_qemu_namespace(&out, &mut changes)?;
        out = ensure_qemu_args(&out, &["-s", "-S"], &mut changes)?;
    } else {
        out = remove_qemu_args(&out, &["-s", "-S"], &mut changes);
        out = remove_empty_qemu_commandline(&out, &mut changes);
    }

    if transports.contains(&DebugTransport::Kd) {
        out = ensure_kd_serial(&out, kd_socket, &mut changes)?;
    } else {
        out = remove_ntoseye_kd_devices(&out, &mut changes);
    }

    if transports.contains(&DebugTransport::KdNet) {
        out = ensure_kdnet_vendor(&out, &mut changes)?;
    }

    // Declining is a no-op rather than a removal: vmcoreinfo isn't
    // ntoseye-owned, so a later reconfigure shouldn't silently strip it
    if vmcoreinfo {
        out = ensure_vmcoreinfo(&out, &mut changes)?;
    }

    Ok(XmlPlan { xml: out, changes })
}

fn ensure_kdnet_vendor(xml: &str, changes: &mut Vec<String>) -> Result<String> {
    let Some((hyperv_start, hyperv_end)) = find_tag_block(xml, 0, "hyperv") else {
        return Ok(xml.to_string());
    };
    let hyperv = &xml[hyperv_start..hyperv_end];
    let opening_end = hyperv
        .find('>')
        .ok_or_else(|| Error::DebugInfo("malformed libvirt <hyperv> feature block".to_string()))?;
    if tag_attr(&hyperv[..=opening_end], "state").as_deref() == Some("off")
        || kdnet_vendor_ready_block(hyperv)
    {
        return Ok(xml.to_string());
    }

    let mut out = xml.to_string();
    if let Some((vendor_start, vendor_end)) = find_tag_block(hyperv, 0, "vendor_id") {
        out.replace_range(
            hyperv_start + vendor_start..hyperv_start + vendor_end,
            r#"<vendor_id state="on" value="KVMKVMKVM"/>"#,
        );
    } else {
        let indent = line_indent(xml, hyperv_start);
        let child_indent = format!("{indent}  ");
        if hyperv.trim_end().ends_with("/>") {
            let opening = hyperv
                .trim_end()
                .strip_suffix("/>")
                .expect("self-closing hyperv block")
                .trim_end();
            out.replace_range(
                hyperv_start..hyperv_end,
                &format!(
                    "{opening}>\n{child_indent}<vendor_id state=\"on\" value=\"KVMKVMKVM\"/>\n{indent}</hyperv>"
                ),
            );
        } else {
            let closing = hyperv.rfind("</hyperv>").ok_or_else(|| {
                Error::DebugInfo("malformed libvirt <hyperv> feature block".to_string())
            })?;
            let line_start = hyperv[..closing]
                .rfind('\n')
                .map_or(closing, |newline| newline + 1);
            let (insert_at, insertion) = if hyperv[line_start..closing].trim().is_empty() {
                (
                    line_start,
                    format!("{child_indent}<vendor_id state=\"on\" value=\"KVMKVMKVM\"/>\n"),
                )
            } else {
                (
                    closing,
                    format!(
                        "\n{child_indent}<vendor_id state=\"on\" value=\"KVMKVMKVM\"/>\n{indent}"
                    ),
                )
            };
            out.insert_str(hyperv_start + insert_at, &insertion);
        }
    }
    changes.push("set Hyper-V vendor ID to KVMKVMKVM for KDNET".to_string());
    Ok(out)
}

fn kdnet_vendor_ready(xml: &str) -> bool {
    let Some((start, end)) = find_tag_block(xml, 0, "hyperv") else {
        return true;
    };
    let hyperv = &xml[start..end];
    let Some(opening_end) = hyperv.find('>') else {
        return false;
    };
    tag_attr(&hyperv[..=opening_end], "state").as_deref() == Some("off")
        || kdnet_vendor_ready_block(hyperv)
}

fn kdnet_vendor_ready_block(hyperv: &str) -> bool {
    let Some((start, end)) = find_tag_block(hyperv, 0, "vendor_id") else {
        return false;
    };
    let vendor = &hyperv[start..end];
    tag_attr(vendor, "state").as_deref() != Some("off")
        && tag_attr(vendor, "value")
            .is_some_and(|value| !value.is_empty() && value != "Microsoft Hv")
}

/// Enable the domain's `vmcoreinfo` feature, which QEMU's Windows crash-dump
/// writer (`virsh dump --format=win-dmp`) requires. The guest half is the
/// virtio-win `fwcfg` driver; without either, QEMU reports "invalid vmcoreinfo
/// note size".
fn ensure_vmcoreinfo(xml: &str, changes: &mut Vec<String>) -> Result<String> {
    if xml.contains("<vmcoreinfo") {
        return Ok(xml.to_string());
    }

    if let Some(close) = xml.find("</features>") {
        let indent = line_indent(xml, close);
        let line_start = xml[..close].rfind('\n').map(|idx| idx + 1).unwrap_or(0);
        let insert = format!("{indent}  <vmcoreinfo state=\"on\"/>\n");
        let mut out = String::with_capacity(xml.len() + insert.len());
        out.push_str(&xml[..line_start]);
        out.push_str(&insert);
        out.push_str(&xml[line_start..]);
        changes.push("enable vmcoreinfo (crash-dump generation)".to_string());
        return Ok(out);
    }

    let domain_close = xml
        .find("</domain>")
        .ok_or_else(|| Error::DebugInfo("domain XML missing </domain>".to_string()))?;
    let block = "  <features>\n    <vmcoreinfo state=\"on\"/>\n  </features>\n";
    let mut out = String::with_capacity(xml.len() + block.len());
    out.push_str(&xml[..domain_close]);
    out.push_str(block);
    out.push_str(&xml[domain_close..]);
    changes.push("enable vmcoreinfo (crash-dump generation)".to_string());
    Ok(out)
}

fn remove_debug_transports(xml: &str) -> XmlPlan {
    let mut changes = Vec::new();
    let mut out = remove_qemu_args(xml, &["-s", "-S"], &mut changes);
    out = remove_empty_qemu_commandline(&out, &mut changes);
    out = remove_ntoseye_kd_devices(&out, &mut changes);
    XmlPlan { xml: out, changes }
}

fn ensure_qemu_namespace(xml: &str, changes: &mut Vec<String>) -> Result<String> {
    if xml.contains("xmlns:qemu=") {
        return Ok(xml.to_string());
    }
    let start = xml
        .find("<domain")
        .ok_or_else(|| Error::DebugInfo("domain XML missing <domain>".to_string()))?;
    let end = xml[start..]
        .find('>')
        .map(|offset| start + offset)
        .ok_or_else(|| Error::DebugInfo("domain XML has unterminated <domain>".to_string()))?;
    let mut out = String::with_capacity(xml.len() + QEMU_NS.len() + 16);
    out.push_str(&xml[..end]);
    out.push_str(" xmlns:qemu=\"");
    out.push_str(QEMU_NS);
    out.push('"');
    out.push_str(&xml[end..]);
    changes.push("add qemu XML namespace".to_string());
    Ok(out)
}

fn ensure_qemu_args(xml: &str, args: &[&str], changes: &mut Vec<String>) -> Result<String> {
    let missing = args
        .iter()
        .filter(|arg| !has_qemu_arg(xml, arg))
        .copied()
        .collect::<Vec<_>>();
    if missing.is_empty() {
        return Ok(xml.to_string());
    }

    if let Some(close) = xml.find("</qemu:commandline>") {
        let indent = line_indent(xml, close);
        let child_indent = format!("{indent}  ");
        let mut insert = String::new();
        for arg in &missing {
            insert.push_str(&format!(
                "{child_indent}<qemu:arg value=\"{}\"/>\n",
                escape_attr(arg)
            ));
        }
        let mut out = String::with_capacity(xml.len() + insert.len());
        out.push_str(&xml[..close]);
        out.push_str(&insert);
        out.push_str(&xml[close..]);
        changes.push(format!("add qemu args: {}", missing.join(" ")));
        return Ok(out);
    }

    let domain_close = xml
        .find("</domain>")
        .ok_or_else(|| Error::DebugInfo("domain XML missing </domain>".to_string()))?;
    let mut block = String::new();
    block.push_str("  <qemu:commandline>\n");
    for arg in &missing {
        block.push_str(&format!("    <qemu:arg value=\"{}\"/>\n", escape_attr(arg)));
    }
    block.push_str("  </qemu:commandline>\n");

    let mut out = String::with_capacity(xml.len() + block.len());
    out.push_str(&xml[..domain_close]);
    out.push_str(&block);
    out.push_str(&xml[domain_close..]);
    changes.push(format!("add qemu args: {}", missing.join(" ")));
    Ok(out)
}

fn has_qemu_arg(xml: &str, value: &str) -> bool {
    let mut cursor = 0;
    while let Some((start, end)) = find_tag_block(xml, cursor, "qemu:arg") {
        if tag_attr(&xml[start..end], "value").as_deref() == Some(value) {
            return true;
        }
        cursor = end;
    }
    false
}

fn remove_qemu_args(xml: &str, values: &[&str], changes: &mut Vec<String>) -> String {
    let mut out = String::with_capacity(xml.len());
    let mut cursor = 0;
    let mut removed = Vec::new();
    while let Some((start, end)) = find_tag_block(xml, cursor, "qemu:arg") {
        out.push_str(&xml[cursor..start]);
        let block = &xml[start..end];
        if let Some(value) = tag_attr(block, "value")
            && values.contains(&value.as_str())
        {
            removed.push(value);
        } else {
            out.push_str(block);
        }
        cursor = end;
    }
    out.push_str(&xml[cursor..]);
    if !removed.is_empty() {
        changes.push(format!("remove qemu args: {}", removed.join(" ")));
    }
    out
}

fn remove_empty_qemu_commandline(xml: &str, changes: &mut Vec<String>) -> String {
    let Some(start) = xml.find("<qemu:commandline") else {
        return xml.to_string();
    };
    let Some(end) = xml[start..]
        .find("</qemu:commandline>")
        .map(|offset| start + offset + "</qemu:commandline>".len())
    else {
        return xml.to_string();
    };
    let block = &xml[start..end];
    if block.contains("<qemu:arg") {
        return xml.to_string();
    }
    let mut out = String::with_capacity(xml.len() - block.len());
    out.push_str(&xml[..start]);
    out.push_str(&xml[end..]);
    changes.push("remove empty qemu commandline".to_string());
    out
}

fn ensure_kd_serial(xml: &str, socket: &str, changes: &mut Vec<String>) -> Result<String> {
    let mut used_ports = Vec::new();
    let mut cursor = 0;
    while let Some((start, end)) = find_tag_block(xml, cursor, "serial") {
        let serial = &xml[start..end];
        if serial_source_path(serial).as_deref() == Some(socket) {
            return Ok(xml.to_string());
        }
        if let Some((target_start, target_end)) = find_tag_block(serial, 0, "target")
            && let Some(port) = tag_attr(&serial[target_start..target_end], "port")
                .and_then(|port| port.parse::<usize>().ok())
        {
            used_ports.push(port);
        }
        cursor = end;
    }

    let port = (0..)
        .find(|port| !used_ports.contains(port))
        .expect("an unused serial port exists");
    let serial = kd_serial_xml("    ", socket, port);
    let devices_close = xml
        .find("</devices>")
        .ok_or_else(|| Error::DebugInfo("domain XML missing </devices>".to_string()))?;
    let mut out = String::with_capacity(xml.len() + serial.len());
    out.push_str(&xml[..devices_close]);
    out.push_str(&serial);
    out.push_str(&xml[devices_close..]);
    changes.push(format!(
        "add KD serial socket {socket} (COM{}) while preserving existing serial devices",
        port + 1
    ));
    Ok(out)
}

fn remove_ntoseye_kd_devices(xml: &str, changes: &mut Vec<String>) -> String {
    let out = remove_ntoseye_kd_tag(xml, "serial", "serial device", changes);
    remove_ntoseye_kd_tag(&out, "console", "console device", changes)
}

fn remove_ntoseye_kd_tag(
    xml: &str,
    tag: &str,
    description: &str,
    changes: &mut Vec<String>,
) -> String {
    let mut out = String::with_capacity(xml.len());
    let mut cursor = 0;
    let mut removed = 0usize;
    while let Some((start, end)) = find_tag_block(xml, cursor, tag) {
        out.push_str(&xml[cursor..start]);
        let block = &xml[start..end];
        if device_uses_kd_socket(block) {
            removed += 1;
        } else {
            out.push_str(block);
        }
        cursor = end;
    }
    out.push_str(&xml[cursor..]);
    if removed > 0 {
        changes.push(format!("remove {removed} ntoseye KD {description}(s)"));
    }
    out
}

fn device_uses_kd_socket(device: &str) -> bool {
    let mut cursor = 0;
    while let Some((start, end)) = find_tag_block(device, cursor, "source") {
        if tag_attr(&device[start..end], "path").as_deref() == Some(KD_SOCKET) {
            return true;
        }
        cursor = end;
    }
    false
}

fn kd_serial_xml(indent: &str, socket: &str, port: usize) -> String {
    format!(
        "{indent}<serial type=\"unix\">\n\
{indent}  <source mode=\"bind\" path=\"{}\"/>\n\
{indent}  <target type=\"isa-serial\" port=\"{port}\"/>\n\
{indent}</serial>\n",
        escape_attr(socket)
    )
}

fn find_tag_block(xml: &str, cursor: usize, tag: &str) -> Option<(usize, usize)> {
    let open = format!("<{tag}");
    let start = xml[cursor..].find(&open).map(|offset| cursor + offset)?;
    let after = xml[start + open.len()..].chars().next()?;
    if !matches!(after, ' ' | '\n' | '\r' | '\t' | '/' | '>') {
        return find_tag_block(xml, start + open.len(), tag);
    }
    let open_end = xml[start..].find('>').map(|offset| start + offset + 1)?;
    if xml[start..open_end].trim_end().ends_with("/>") {
        return Some((start, open_end));
    }
    let close = format!("</{tag}>");
    let end = xml[open_end..]
        .find(&close)
        .map(|offset| open_end + offset + close.len())?;
    Some((start, end))
}

fn tag_attr(tag: &str, attr: &str) -> Option<String> {
    let needle = format!("{attr}=");
    let start = tag.find(&needle)? + needle.len();
    let quote = tag[start..].chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let value_start = start + quote.len_utf8();
    let value_end = tag[value_start..]
        .find(quote)
        .map(|offset| value_start + offset)?;
    Some(tag[value_start..value_end].to_string())
}

fn line_indent(text: &str, offset: usize) -> String {
    let line_start = text[..offset].rfind('\n').map(|idx| idx + 1).unwrap_or(0);
    text[line_start..offset]
        .chars()
        .take_while(|ch| matches!(ch, ' ' | '\t'))
        .collect()
}

fn escape_attr(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE_XML: &str = r#"<domain type="kvm">
  <name>windows</name>
  <devices>
    <serial type="pty">
      <target type="isa-serial" port="0"/>
    </serial>
  </devices>
</domain>
"#;

    #[test]
    fn kd_preserves_existing_serial_and_uses_next_port() {
        let plan =
            apply_transport_config(BASE_XML, &[DebugTransport::Kd], KD_SOCKET, false).unwrap();
        assert!(plan.xml.contains(r#"<serial type="unix">"#));
        assert!(plan.xml.contains(r#"path="/tmp/ntoseye-kd.sock""#));
        assert!(plan.xml.contains(r#"port="1""#));
        assert!(plan.xml.contains(r#"<serial type="pty">"#));
        assert_eq!(debug_port_for_socket(&plan.xml, KD_SOCKET), Some(2));
    }

    #[test]
    fn kd_configuration_is_idempotent() {
        let once =
            apply_transport_config(BASE_XML, &[DebugTransport::Kd], KD_SOCKET, false).unwrap();
        let twice =
            apply_transport_config(&once.xml, &[DebugTransport::Kd], KD_SOCKET, false).unwrap();
        assert_eq!(twice.xml, once.xml);
        assert!(twice.changes.is_empty());
    }

    #[test]
    fn kdnet_sets_qemu_hyperv_vendor_and_is_idempotent() {
        let xml = r#"<domain type="kvm">
  <features>
    <hyperv mode="custom">
      <relaxed state="on"/>
    </hyperv>
  </features>
  <devices/>
</domain>
"#;
        let once = apply_transport_config(xml, &[DebugTransport::KdNet], KD_SOCKET, false).unwrap();
        assert!(
            once.xml
                .contains("      <vendor_id state=\"on\" value=\"KVMKVMKVM\"/>\n    </hyperv>")
        );
        assert!(kdnet_vendor_ready(&once.xml));
        let request = ConfigureRequest {
            action: Action::Configure,
            backend: Some(BackendSelection::KdNet),
            kdnet_host: Some("192.168.122.1".parse().unwrap()),
            vmcoreinfo: false,
        };
        verify_applied_config(&once.xml, request).unwrap();
        assert_eq!(
            libvirt_instructions(&once.xml, request, "windows").run,
            ["ntoseye --backend kdnet --kdnet-key KEY"]
        );
        let twice =
            apply_transport_config(&once.xml, &[DebugTransport::KdNet], KD_SOCKET, false).unwrap();
        assert_eq!(twice.xml, once.xml);
        assert!(twice.changes.is_empty());
    }

    #[test]
    fn kdnet_preserves_existing_custom_hyperv_vendor() {
        let xml = r#"<domain type="kvm">
  <features>
    <hyperv mode="custom">
      <vendor_id state="on" value="customvendor"/>
    </hyperv>
  </features>
  <devices/>
</domain>
"#;
        let plan = apply_transport_config(xml, &[DebugTransport::KdNet], KD_SOCKET, false).unwrap();
        assert_eq!(plan.xml, xml);
        assert!(plan.changes.is_empty());
    }

    #[test]
    fn inspection_recovers_configured_transports() {
        let plan = apply_transport_config(
            BASE_XML,
            &[DebugTransport::Kd, DebugTransport::Gdb],
            KD_SOCKET,
            false,
        )
        .unwrap();
        assert_eq!(
            inspect_xml(&plan.xml).targets,
            [
                ConfiguredTarget::kd(KD_SOCKET, 2, false),
                ConfiguredTarget::gdb(DEFAULT_GDB_ADDR),
            ]
        );
    }

    #[test]
    fn launch_commands_omit_default_backend_and_endpoints() {
        let instructions = libvirt_instructions(
            BASE_XML,
            ConfigureRequest {
                action: Action::Configure,
                backend: Some(BackendSelection::KdAndGdb),
                kdnet_host: None,
                vmcoreinfo: false,
            },
            "windows",
        );
        assert_eq!(instructions.run, ["ntoseye", "ntoseye --backend gdb"]);
    }

    #[test]
    fn gdb_adds_qemu_namespace_and_args() {
        let plan =
            apply_transport_config(BASE_XML, &[DebugTransport::Gdb], KD_SOCKET, false).unwrap();
        assert!(
            plan.xml
                .contains(r#"xmlns:qemu="http://libvirt.org/schemas/domain/qemu/1.0""#)
        );
        assert!(plan.xml.contains(r#"<qemu:arg value="-s"/>"#));
        assert!(plan.xml.contains(r#"<qemu:arg value="-S"/>"#));
    }

    #[test]
    fn remove_debug_transports_removes_ntoseye_debug_transport() {
        let kd = apply_transport_config(BASE_XML, &[DebugTransport::Kd], KD_SOCKET, false).unwrap();
        let memory = remove_debug_transports(&kd.xml);
        assert!(!memory.xml.contains("ntoseye-kd.sock"));
        assert!(memory.xml.contains(r#"<serial type="pty">"#));
    }

    #[test]
    fn remove_debug_transports_removes_kd_serial_with_nested_target() {
        let xml = r#"<domain type="kvm">
  <name>windows</name>
  <devices>
    <serial type="unix">
      <source mode="bind" path="/tmp/ntoseye-kd.sock"/>
      <target type="isa-serial" port="0">
        <model name="isa-serial"/>
      </target>
    </serial>
  </devices>
</domain>
"#;
        let memory = remove_debug_transports(xml);
        assert!(!memory.xml.contains("ntoseye-kd.sock"));
        assert!(!memory.xml.contains(r#"<serial type="unix">"#));
        assert_eq!(memory.changes, ["remove 1 ntoseye KD serial device(s)"]);
    }

    #[test]
    fn remove_debug_transports_removes_libvirt_kd_serial_and_console() {
        let xml = r#"<domain type="kvm">
  <name>windows</name>
  <devices>
    <serial type="unix">
      <source mode="bind" path="/tmp/ntoseye-kd.sock"/>
      <target type="isa-serial" port="0">
        <model name="isa-serial"/>
      </target>
    </serial>
    <console type="unix">
      <source mode="bind" path="/tmp/ntoseye-kd.sock"/>
      <target type="serial" port="0"/>
    </console>
  </devices>
</domain>
"#;
        let memory = remove_debug_transports(xml);
        assert!(!memory.xml.contains("ntoseye-kd.sock"));
        assert!(!memory.xml.contains(r#"<serial type="unix">"#));
        assert!(!memory.xml.contains(r#"<console type="unix">"#));
        assert_eq!(
            memory.changes,
            [
                "remove 1 ntoseye KD serial device(s)",
                "remove 1 ntoseye KD console device(s)"
            ]
        );
    }

    #[test]
    fn switching_to_kd_removes_gdbstub_args() {
        let gdb =
            apply_transport_config(BASE_XML, &[DebugTransport::Gdb], KD_SOCKET, false).unwrap();
        let kd = apply_transport_config(&gdb.xml, &[DebugTransport::Kd], KD_SOCKET, false).unwrap();
        assert!(!kd.xml.contains(r#"<qemu:arg value="-s"/>"#));
        assert!(!kd.xml.contains(r#"<qemu:arg value="-S"/>"#));
    }

    #[test]
    fn selected_transports_can_enable_kd_and_gdb_together() {
        let plan = apply_transport_config(
            BASE_XML,
            &[DebugTransport::Kd, DebugTransport::Gdb],
            KD_SOCKET,
            false,
        )
        .unwrap();
        assert!(plan.xml.contains(r#"<serial type="unix">"#));
        assert!(plan.xml.contains(r#"<qemu:arg value="-s"/>"#));
        assert!(plan.xml.contains(r#"<qemu:arg value="-S"/>"#));
    }

    #[test]
    fn vmcoreinfo_inserted_into_existing_features() {
        let xml = r#"<domain type="kvm">
  <name>windows</name>
  <features>
    <acpi/>
    <apic/>
  </features>
  <devices>
  </devices>
</domain>
"#;
        let plan = apply_transport_config(xml, &[DebugTransport::Kd], KD_SOCKET, true).unwrap();
        assert!(
            plan.xml
                .contains("    <vmcoreinfo state=\"on\"/>\n  </features>")
        );
        assert!(
            plan.changes
                .contains(&"enable vmcoreinfo (crash-dump generation)".to_string())
        );
    }

    #[test]
    fn vmcoreinfo_creates_features_block_when_missing() {
        let plan =
            apply_transport_config(BASE_XML, &[DebugTransport::Kd], KD_SOCKET, true).unwrap();
        assert!(plan.xml.contains("<features>"));
        assert!(plan.xml.contains(r#"<vmcoreinfo state="on"/>"#));
    }

    #[test]
    fn vmcoreinfo_is_idempotent_and_never_removed() {
        let once =
            apply_transport_config(BASE_XML, &[DebugTransport::Kd], KD_SOCKET, true).unwrap();
        // Re-run with vmcoreinfo enabled: no duplicate, no change recorded
        let twice =
            apply_transport_config(&once.xml, &[DebugTransport::Kd], KD_SOCKET, true).unwrap();
        assert_eq!(twice.xml.matches("<vmcoreinfo").count(), 1);
        assert!(
            !twice
                .changes
                .contains(&"enable vmcoreinfo (crash-dump generation)".to_string())
        );
        // Declining later leaves the existing feature alone
        let declined =
            apply_transport_config(&once.xml, &[DebugTransport::Kd], KD_SOCKET, false).unwrap();
        assert!(declined.xml.contains(r#"<vmcoreinfo state="on"/>"#));
    }

    #[test]
    fn escape_attr_escapes_xml_sensitive_characters() {
        assert_eq!(
            escape_attr(r#"/tmp/a&b"c<d>"#),
            "/tmp/a&amp;b&quot;c&lt;d&gt;"
        );
    }

    #[test]
    fn tag_attr_reads_single_and_double_quoted_values() {
        assert_eq!(
            tag_attr(r#"<qemu:arg value="-s"/>"#, "value").as_deref(),
            Some("-s")
        );
        assert_eq!(
            tag_attr(r#"<qemu:arg value='-S'/>"#, "value").as_deref(),
            Some("-S")
        );
    }

    #[test]
    fn sanitize_filename_removes_path_characters() {
        assert_eq!(sanitize_filename("win/11 test"), "win_11_test");
    }

    #[test]
    fn find_tag_block_handles_self_closing_tags() {
        let xml = r#"<domain><devices><serial type="pty"/></devices></domain>"#;
        let (start, end) = find_tag_block(xml, 0, "serial").unwrap();
        assert_eq!(&xml[start..end], r#"<serial type="pty"/>"#);
    }

    #[test]
    fn find_tag_block_ignores_prefix_matches() {
        let xml = r#"<domain><devices><serialport/><serial type="pty"/></devices></domain>"#;
        let (start, end) = find_tag_block(xml, 0, "serial").unwrap();
        assert_eq!(&xml[start..end], r#"<serial type="pty"/>"#);
    }

    #[test]
    fn replace_first_serial_inserts_when_missing() {
        let xml = r#"<domain><devices></devices></domain>"#;
        let plan = apply_transport_config(xml, &[DebugTransport::Kd], KD_SOCKET, false).unwrap();
        assert!(plan.xml.contains(r#"<serial type="unix">"#));
        assert!(plan.xml.contains(r#"path="/tmp/ntoseye-kd.sock""#));
    }

    #[test]
    fn remove_qemu_args_preserves_other_qemu_args() {
        let xml = r#"<domain xmlns:qemu="http://libvirt.org/schemas/domain/qemu/1.0">
  <qemu:commandline>
    <qemu:arg value="-s"/>
    <qemu:arg value="-name"/>
  </qemu:commandline>
  <devices/>
</domain>
"#;
        let mut changes = Vec::new();
        let out = remove_qemu_args(xml, &["-s"], &mut changes);
        assert!(!out.contains(r#"<qemu:arg value="-s"/>"#));
        assert!(out.contains(r#"<qemu:arg value="-name"/>"#));
    }
}
