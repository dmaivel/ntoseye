use std::{
    fs,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use dialoguer::{Confirm, Select};

use crate::{
    error::{Error, Result},
    symbols,
};

const KD_SOCKET: &str = "/tmp/ntoseye-kd.sock";
const QEMU_NS: &str = "http://libvirt.org/schemas/domain/qemu/1.0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VirshAction {
    Configure,
    Remove,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VirshTransport {
    Kd,
    Gdb,
}

impl VirshTransport {
    fn label(self) -> &'static str {
        match self {
            Self::Kd => "kd",
            Self::Gdb => "gdb",
        }
    }

    fn description(self) -> &'static str {
        match self {
            Self::Kd => "KDCOM serial socket",
            Self::Gdb => "QEMU gdbstub",
        }
    }
}

#[derive(Debug)]
struct Domain {
    name: String,
    state: String,
}

struct XmlPlan {
    xml: String,
    changes: Vec<String>,
}

pub fn run_interactive() -> Result<()> {
    let domains = list_domains()?;
    if domains.is_empty() {
        return Err(Error::DebugInfo("virsh reported no domains".to_string()));
    }

    let domain_items = domains
        .iter()
        .map(|domain| format!("{} ({})", domain.name, domain.state))
        .collect::<Vec<_>>();
    let Some(domain_idx) = prompt_select("Domain", &domain_items)? else {
        return cancel_virsh_edit();
    };
    let domain = &domains[domain_idx];
    if !domain.state.eq_ignore_ascii_case("shut off") {
        return Err(Error::DebugInfo(format!(
            "domain '{}' is {}; shut it down before editing persistent XML",
            domain.name, domain.state
        )));
    }

    let action_items = vec![
        "configure debug transports".to_string(),
        "remove ntoseye debug transports".to_string(),
    ];
    let action = match prompt_select("Action", &action_items)? {
        Some(0) => VirshAction::Configure,
        Some(1) => VirshAction::Remove,
        _ => return cancel_virsh_edit(),
    };

    let xml = dump_xml(&domain.name)?;
    let (plan, transports, vmcoreinfo) = match action {
        VirshAction::Configure => {
            let Some(transports) = prompt_transports()? else {
                return cancel_virsh_edit();
            };
            let vmcoreinfo = prompt_confirm(
                "Enable crash-dump generation (vmcoreinfo, used by 'virsh dump --format=win-dmp')?",
            )?;
            (
                apply_transport_config(&xml, &transports, KD_SOCKET, vmcoreinfo)?,
                transports,
                vmcoreinfo,
            )
        }
        VirshAction::Remove => (remove_debug_transports(&xml), Vec::new(), false),
    };
    if plan.xml == xml {
        println!("No XML changes needed for '{}'.", domain.name);
        print_next_steps(action, &transports, vmcoreinfo, &domain.name);
        return Ok(());
    }

    println!("changes");
    for change in &plan.changes {
        println!("  - {change}");
    }
    println!();

    let backup_path = backup_path(&domain.name)?;
    println!("backup: {}", backup_path.display());
    println!("changes apply to the next VM start");
    if !prompt_confirm("Apply changes?")? {
        return cancel_virsh_edit();
    }

    fs::write(&backup_path, &xml)?;
    let define_path = write_define_xml(&domain.name, &plan.xml)?;
    let define_result = virsh(["define", define_path.to_string_lossy().as_ref()]);
    let _ = fs::remove_file(&define_path);
    define_result?;

    println!("defined '{}'", domain.name);
    println!("backup saved: {}", backup_path.display());
    print_next_steps(action, &transports, vmcoreinfo, &domain.name);
    Ok(())
}

fn cancel_virsh_edit() -> Result<()> {
    println!("cancelled");
    Ok(())
}

fn list_domains() -> Result<Vec<Domain>> {
    let names = virsh(["list", "--all", "--name"])?;
    let mut domains = Vec::new();
    for name in names.lines().map(str::trim).filter(|name| !name.is_empty()) {
        let state = virsh(["domstate", name])?
            .lines()
            .next()
            .unwrap_or("unknown")
            .trim()
            .to_string();
        domains.push(Domain {
            name: name.to_string(),
            state,
        });
    }
    Ok(domains)
}

fn dump_xml(domain: &str) -> Result<String> {
    virsh(["dumpxml", "--inactive", domain]).or_else(|_| virsh(["dumpxml", domain]))
}

fn virsh<const N: usize>(args: [&str; N]) -> Result<String> {
    let output = Command::new("virsh").args(args).output().map_err(|err| {
        Error::DebugInfo(format!(
            "failed to run virsh: {err}; install libvirt clients or adjust PATH"
        ))
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let detail = if stderr.is_empty() { stdout } else { stderr };
        return Err(Error::DebugInfo(format!("virsh failed: {detail}")));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn prompt_select(prompt: &str, items: &[String]) -> Result<Option<usize>> {
    let mut choices = items.to_vec();
    choices.push("cancel".to_string());
    let selected = Select::new()
        .with_prompt(prompt)
        .items(&choices)
        .default(0)
        .interact()
        .map_err(prompt_error)?;
    if selected == items.len() {
        Ok(None)
    } else {
        Ok(Some(selected))
    }
}

fn prompt_transports() -> Result<Option<Vec<VirshTransport>>> {
    let items = vec![
        format!(
            "{} ({})",
            VirshTransport::Kd.label(),
            VirshTransport::Kd.description()
        ),
        format!(
            "{} ({})",
            VirshTransport::Gdb.label(),
            VirshTransport::Gdb.description()
        ),
        format!(
            "{} + {}",
            VirshTransport::Kd.label(),
            VirshTransport::Gdb.label()
        ),
    ];
    match prompt_select("Debug transport", &items)? {
        Some(0) => Ok(Some(vec![VirshTransport::Kd])),
        Some(1) => Ok(Some(vec![VirshTransport::Gdb])),
        Some(2) => Ok(Some(vec![VirshTransport::Kd, VirshTransport::Gdb])),
        _ => Ok(None),
    }
}

fn prompt_confirm(prompt: &str) -> Result<bool> {
    Confirm::new()
        .with_prompt(prompt)
        .default(false)
        .interact()
        .map_err(prompt_error)
}

fn prompt_error(error: dialoguer::Error) -> Error {
    Error::DebugInfo(format!("interactive prompt failed: {error}"))
}

fn backup_path(domain: &str) -> Result<PathBuf> {
    let root = symbols::ntoseye_home().ok_or(Error::StorageNotFound)?;
    let dir = root.join("virsh-backups");
    fs::create_dir_all(&dir)?;
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| Error::DebugInfo(format!("system clock error: {err}")))?
        .as_secs();
    Ok(dir.join(format!("{}-{ts}.xml", sanitize_filename(domain))))
}

fn write_define_xml(domain: &str, xml: &str) -> Result<PathBuf> {
    let path = std::env::temp_dir().join(format!(
        "ntoseye-{}-{}.xml",
        sanitize_filename(domain),
        std::process::id()
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

fn print_next_steps(
    action: VirshAction,
    transports: &[VirshTransport],
    vmcoreinfo: bool,
    domain: &str,
) {
    match action {
        VirshAction::Configure => {
            if transports.contains(&VirshTransport::Kd) {
                println!();
                println!("guest setup still required for KD:");
                println!("  bcdedit /debug on");
                println!("  bcdedit /dbgsettings serial debugport:1 baudrate:115200");
                println!("  Restart-Computer");
            }
            if vmcoreinfo {
                println!();
                println!("guest setup still required for crash dumps:");
                println!("  install the virtio-win 'fwcfg' driver (QEMU FWCfg Device)");
            }
            println!();
            println!("run:");
            if transports.contains(&VirshTransport::Kd) {
                println!("  ntoseye");
            }
            if transports.contains(&VirshTransport::Gdb) {
                println!("  ntoseye --backend gdb");
            }
            if vmcoreinfo {
                println!();
                println!("generate and open a dump:");
                println!("  virsh dump {domain} /tmp/win.dmp --memory-only --format=win-dmp");
                println!("  ntoseye --dump /tmp/win.dmp");
            }
        }
        VirshAction::Remove => {
            println!();
            println!("run:");
            println!("  ntoseye --backend memory");
        }
    }
}

fn apply_transport_config(
    xml: &str,
    transports: &[VirshTransport],
    kd_socket: &str,
    vmcoreinfo: bool,
) -> Result<XmlPlan> {
    let mut changes = Vec::new();
    let mut out = xml.to_string();

    if transports.contains(&VirshTransport::Gdb) {
        out = ensure_qemu_namespace(&out, &mut changes)?;
        out = ensure_qemu_args(&out, &["-s", "-S"], &mut changes)?;
    } else {
        out = remove_qemu_args(&out, &["-s", "-S"], &mut changes);
        out = remove_empty_qemu_commandline(&out, &mut changes);
    }

    if transports.contains(&VirshTransport::Kd) {
        out = replace_first_serial_or_insert(&out, kd_socket, &mut changes)?;
    } else {
        out = remove_ntoseye_kd_devices(&out, &mut changes);
    }

    // Declining is a no-op rather than a removal: vmcoreinfo isn't
    // ntoseye-owned, so a later reconfigure shouldn't silently strip it
    if vmcoreinfo {
        out = ensure_vmcoreinfo(&out, &mut changes)?;
    }

    Ok(XmlPlan { xml: out, changes })
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

fn replace_first_serial_or_insert(
    xml: &str,
    socket: &str,
    changes: &mut Vec<String>,
) -> Result<String> {
    let serial = kd_serial_xml("    ", socket);
    if let Some((start, end)) = find_tag_block(xml, 0, "serial") {
        let indent = line_indent(xml, start);
        let replacement = kd_serial_xml(&indent, socket);
        let mut out = String::with_capacity(xml.len() - (end - start) + replacement.len());
        out.push_str(&xml[..start]);
        out.push_str(&replacement);
        out.push_str(&xml[end..]);
        changes.push(format!(
            "replace first serial device with KD socket {socket} (COM1)"
        ));
        return Ok(out);
    }

    let devices_close = xml
        .find("</devices>")
        .ok_or_else(|| Error::DebugInfo("domain XML missing </devices>".to_string()))?;
    let mut out = String::with_capacity(xml.len() + serial.len());
    out.push_str(&xml[..devices_close]);
    out.push_str(&serial);
    out.push_str(&xml[devices_close..]);
    changes.push(format!("add KD serial socket {socket} (COM1)"));
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

fn kd_serial_xml(indent: &str, socket: &str) -> String {
    format!(
        "{indent}<serial type=\"unix\">\n\
{indent}  <source mode=\"bind\" path=\"{}\"/>\n\
{indent}  <target type=\"isa-serial\" port=\"0\"/>\n\
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
    fn kd_replaces_first_serial_with_unix_socket() {
        let plan =
            apply_transport_config(BASE_XML, &[VirshTransport::Kd], KD_SOCKET, false).unwrap();
        assert!(plan.xml.contains(r#"<serial type="unix">"#));
        assert!(plan.xml.contains(r#"path="/tmp/ntoseye-kd.sock""#));
        assert!(plan.xml.contains(r#"port="0""#));
        assert!(!plan.xml.contains(r#"<serial type="pty">"#));
    }

    #[test]
    fn gdb_adds_qemu_namespace_and_args() {
        let plan =
            apply_transport_config(BASE_XML, &[VirshTransport::Gdb], KD_SOCKET, false).unwrap();
        assert!(
            plan.xml
                .contains(r#"xmlns:qemu="http://libvirt.org/schemas/domain/qemu/1.0""#)
        );
        assert!(plan.xml.contains(r#"<qemu:arg value="-s"/>"#));
        assert!(plan.xml.contains(r#"<qemu:arg value="-S"/>"#));
    }

    #[test]
    fn remove_debug_transports_removes_ntoseye_debug_transport() {
        let kd = apply_transport_config(BASE_XML, &[VirshTransport::Kd], KD_SOCKET, false).unwrap();
        let memory = remove_debug_transports(&kd.xml);
        assert!(!memory.xml.contains("ntoseye-kd.sock"));
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
            apply_transport_config(BASE_XML, &[VirshTransport::Gdb], KD_SOCKET, false).unwrap();
        let kd = apply_transport_config(&gdb.xml, &[VirshTransport::Kd], KD_SOCKET, false).unwrap();
        assert!(!kd.xml.contains(r#"<qemu:arg value="-s"/>"#));
        assert!(!kd.xml.contains(r#"<qemu:arg value="-S"/>"#));
    }

    #[test]
    fn selected_transports_can_enable_kd_and_gdb_together() {
        let plan = apply_transport_config(
            BASE_XML,
            &[VirshTransport::Kd, VirshTransport::Gdb],
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
        let plan = apply_transport_config(xml, &[VirshTransport::Kd], KD_SOCKET, true).unwrap();
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
            apply_transport_config(BASE_XML, &[VirshTransport::Kd], KD_SOCKET, true).unwrap();
        assert!(plan.xml.contains("<features>"));
        assert!(plan.xml.contains(r#"<vmcoreinfo state="on"/>"#));
    }

    #[test]
    fn vmcoreinfo_is_idempotent_and_never_removed() {
        let once =
            apply_transport_config(BASE_XML, &[VirshTransport::Kd], KD_SOCKET, true).unwrap();
        // Re-run with vmcoreinfo enabled: no duplicate, no change recorded
        let twice =
            apply_transport_config(&once.xml, &[VirshTransport::Kd], KD_SOCKET, true).unwrap();
        assert_eq!(twice.xml.matches("<vmcoreinfo").count(), 1);
        assert!(
            !twice
                .changes
                .contains(&"enable vmcoreinfo (crash-dump generation)".to_string())
        );
        // Declining later leaves the existing feature alone
        let declined =
            apply_transport_config(&once.xml, &[VirshTransport::Kd], KD_SOCKET, false).unwrap();
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
        let plan = apply_transport_config(xml, &[VirshTransport::Kd], KD_SOCKET, false).unwrap();
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
