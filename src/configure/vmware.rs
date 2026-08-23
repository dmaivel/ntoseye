use std::{
    collections::BTreeSet,
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use crate::{
    DEFAULT_GDB_ADDR, DEFAULT_KD_SOCKET as KD_SOCKET,
    error::{Error, Result},
};

use super::{
    Action, ApplyResult, BackendSelection, ConfigurationPlan, Configurator, ConfigureRequest,
    ConfiguredTarget, Guest, GuestInspection, Instructions, ProbeStatus, atomic_replace,
    backup_file,
};

const BACKENDS: &[BackendSelection] = &[
    BackendSelection::Kd,
    BackendSelection::Gdb,
    BackendSelection::KdAndGdb,
    BackendSelection::Memory,
];
const GDB_ENABLED: &str = "debugStub.listen.guest64";
const GDB_PORT: &str = "debugStub.port.guest64";

pub(super) struct Vmware;

impl Configurator for Vmware {
    fn name(&self) -> &'static str {
        "VMware Workstation"
    }

    fn probe(&self) -> ProbeStatus {
        match vmrun(&["listRegisteredVM"]) {
            Err(VmrunError::NotFound) => ProbeStatus::NotDetected,
            Err(VmrunError::Failed(reason)) => ProbeStatus::Unavailable(reason),
            Ok(output) => {
                let count = vmx_paths(&output).len();
                ProbeStatus::Detected(format!(
                    "{count} virtual machine{}",
                    if count == 1 { "" } else { "s" }
                ))
            }
        }
    }

    fn guests(&self) -> Result<Vec<Guest>> {
        let registered = vmrun_result(&["listRegisteredVM"])?;
        let running = vmrun_result(&["list"])?;
        let running = vmx_paths(&running)
            .into_iter()
            .map(normalized_path)
            .collect::<BTreeSet<_>>();
        vmx_paths(&registered)
            .into_iter()
            .map(|path| {
                let contents = fs::read_to_string(&path)?;
                let name = vmx_value(&contents, "displayName")
                    .filter(|name| !name.is_empty())
                    .unwrap_or_else(|| {
                        Path::new(&path)
                            .file_stem()
                            .and_then(|name| name.to_str())
                            .unwrap_or(&path)
                            .to_string()
                    });
                let stopped = !running.contains(&normalized_path(path.clone()));
                Ok(Guest {
                    id: path,
                    name,
                    state: if stopped { "stopped" } else { "running" }.to_string(),
                    stopped,
                })
            })
            .collect()
    }

    fn inspect(&self, guest: &Guest) -> Result<GuestInspection> {
        Ok(inspect_vmx(&fs::read_to_string(&guest.id)?))
    }

    fn supported_backends(&self) -> &'static [BackendSelection] {
        BACKENDS
    }

    fn plan(&self, guest: &Guest, request: ConfigureRequest) -> Result<Box<dyn ConfigurationPlan>> {
        let path = PathBuf::from(&guest.id);
        let original = fs::read_to_string(&path)?;
        let (configured, changes, debug_port) = plan_vmx(&original, request)?;
        let instructions = vmware_instructions(request, debug_port);
        Ok(Box::new(VmwarePlan {
            guest_name: guest.name.clone(),
            path,
            original,
            configured,
            changes,
            instructions,
        }))
    }
}

struct VmwarePlan {
    guest_name: String,
    path: PathBuf,
    original: String,
    configured: String,
    changes: Vec<String>,
    instructions: Instructions,
}

impl ConfigurationPlan for VmwarePlan {
    fn changes(&self) -> &[String] {
        &self.changes
    }

    fn instructions(&self) -> &Instructions {
        &self.instructions
    }

    fn apply(&self) -> Result<ApplyResult> {
        let running = vmrun_result(&["list"])?;
        if vmx_paths(&running).into_iter().any(|path| {
            normalized_path(path) == normalized_path(self.path.to_string_lossy().into())
        }) {
            return Err(Error::DebugInfo(format!(
                "'{}' started after configuration was inspected; stop it and retry",
                self.guest_name
            )));
        }
        let backup = backup_file("vmware", &self.guest_name, "vmx", self.original.as_bytes())?;
        atomic_replace(&self.path, self.configured.as_bytes())?;
        let applied = fs::read_to_string(&self.path)?;
        if applied != self.configured {
            return Err(Error::DebugInfo(format!(
                "VMware configuration verification failed; original configuration is backed up at {}",
                backup.display()
            )));
        }
        Ok(ApplyResult { backup })
    }
}

fn inspect_vmx(contents: &str) -> GuestInspection {
    let editor = VmxEditor::new(contents);
    let mut targets = Vec::with_capacity(2);
    if let Some(index) = managed_serials(&editor).first() {
        targets.push(ConfiguredTarget::kd(KD_SOCKET, index + 1, false));
    }
    if editor
        .value(GDB_ENABLED)
        .is_some_and(|value| value.eq_ignore_ascii_case("TRUE"))
    {
        let endpoint = editor
            .value(GDB_PORT)
            .map(|port| format!("127.0.0.1:{port}"))
            .unwrap_or_else(|| DEFAULT_GDB_ADDR.to_string());
        targets.push(ConfiguredTarget::gdb(endpoint));
    }
    GuestInspection { targets }
}

fn plan_vmx(
    original: &str,
    request: ConfigureRequest,
) -> Result<(String, Vec<String>, Option<usize>)> {
    let mut editor = VmxEditor::new(original);
    let managed = managed_serials(&editor);
    let mut changes = Vec::new();
    let mut debug_port = None;

    match request.action {
        Action::Remove => {
            for index in managed {
                editor.remove_serial(index);
                changes.push(format!("remove ntoseye KD serial device serial{index}"));
            }
            if editor.remove_key(GDB_ENABLED) | editor.remove_key(GDB_PORT) {
                changes.push("remove VMware GDB stub configuration".to_string());
            }
        }
        Action::Configure => {
            let backend = request.backend.ok_or_else(|| {
                Error::DebugInfo("configure request is missing a backend".to_string())
            })?;
            if backend.kd() {
                let index = managed
                    .first()
                    .copied()
                    .unwrap_or_else(|| first_free_serial(&editor));
                let changed = editor.configure_kd_serial(index);
                if changed {
                    changes.push(format!(
                        "configure KD socket {KD_SOCKET} as serial{index} (COM{})",
                        index + 1
                    ));
                }
                for duplicate in managed.into_iter().filter(|candidate| *candidate != index) {
                    editor.remove_serial(duplicate);
                    changes.push(format!(
                        "remove duplicate ntoseye KD serial device serial{duplicate}"
                    ));
                }
                debug_port = Some(index + 1);
            } else {
                for index in managed {
                    editor.remove_serial(index);
                    changes.push(format!("remove ntoseye KD serial device serial{index}"));
                }
            }

            if backend.gdb() {
                if editor.set_key(GDB_ENABLED, "TRUE") | editor.set_key(GDB_PORT, "1234") {
                    changes.push("enable VMware GDB stub on 127.0.0.1:1234".to_string());
                }
            } else if editor.remove_key(GDB_ENABLED) | editor.remove_key(GDB_PORT) {
                changes.push("remove VMware GDB stub configuration".to_string());
            }
        }
    }

    Ok((editor.finish(), changes, debug_port))
}

fn vmware_instructions(request: ConfigureRequest, debug_port: Option<usize>) -> Instructions {
    if request.action == Action::Remove {
        return Instructions::default();
    }
    let backend = request.backend.expect("configure requests have a backend");
    let mut instructions = Instructions::default();
    if backend.kd() {
        let debug_port = debug_port.expect("KD configuration has a serial port");
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
    instructions
}

#[derive(Debug)]
enum VmrunError {
    NotFound,
    Failed(String),
}

fn vmrun(args: &[&str]) -> std::result::Result<String, VmrunError> {
    let output = Command::new("vmrun")
        .args(["-T", "ws"])
        .args(args)
        .output()
        .map_err(|error| {
            if error.kind() == ErrorKind::NotFound {
                VmrunError::NotFound
            } else {
                VmrunError::Failed(error.to_string())
            }
        })?;
    if !output.status.success() {
        return Err(VmrunError::Failed(command_detail(&output)));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn vmrun_result(args: &[&str]) -> Result<String> {
    vmrun(args).map_err(|error| match error {
        VmrunError::NotFound => Error::DebugInfo(
            "vmrun was not found; install VMware Workstation or adjust PATH".to_string(),
        ),
        VmrunError::Failed(reason) => Error::DebugInfo(format!("vmrun failed: {reason}")),
    })
}

fn command_detail(output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if stderr.is_empty() {
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    } else {
        stderr
    }
}

fn vmx_paths(output: &str) -> Vec<String> {
    output
        .lines()
        .map(str::trim)
        .filter(|line| line.to_ascii_lowercase().ends_with(".vmx"))
        .map(str::to_string)
        .collect()
}

fn normalized_path(path: String) -> String {
    fs::canonicalize(&path)
        .unwrap_or_else(|_| PathBuf::from(path))
        .to_string_lossy()
        .into_owned()
}

fn vmx_value(contents: &str, wanted: &str) -> Option<String> {
    contents.lines().find_map(|line| {
        let (key, value) = parse_assignment(line)?;
        key.eq_ignore_ascii_case(wanted).then_some(value)
    })
}

fn parse_assignment(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let (key, value) = line.split_once('=')?;
    let key = key.trim();
    let value = value.trim();
    let value = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(value);
    Some((key.to_string(), value.to_string()))
}

struct VmxEditor {
    lines: Vec<String>,
    trailing_newline: bool,
}

impl VmxEditor {
    fn new(contents: &str) -> Self {
        Self {
            lines: contents.lines().map(str::to_string).collect(),
            trailing_newline: contents.ends_with('\n'),
        }
    }

    fn value(&self, wanted: &str) -> Option<String> {
        self.lines.iter().find_map(|line| {
            let (key, value) = parse_assignment(line)?;
            key.eq_ignore_ascii_case(wanted).then_some(value)
        })
    }

    fn keys(&self) -> impl Iterator<Item = String> + '_ {
        self.lines
            .iter()
            .filter_map(|line| parse_assignment(line).map(|(key, _)| key))
    }

    fn set_key(&mut self, key: &str, value: &str) -> bool {
        let replacement = format!(r#"{key} = "{value}""#);
        if let Some((index, current)) = self.lines.iter().enumerate().find_map(|(index, line)| {
            let (current_key, current_value) = parse_assignment(line)?;
            current_key
                .eq_ignore_ascii_case(key)
                .then_some((index, current_value))
        }) {
            if current == value {
                return false;
            }
            self.lines[index] = replacement;
            return true;
        }
        self.lines.push(replacement);
        true
    }

    fn remove_key(&mut self, wanted: &str) -> bool {
        let before = self.lines.len();
        self.lines.retain(|line| {
            parse_assignment(line)
                .map(|(key, _)| !key.eq_ignore_ascii_case(wanted))
                .unwrap_or(true)
        });
        self.lines.len() != before
    }

    fn remove_serial(&mut self, index: usize) {
        let prefix = format!("serial{index}.");
        self.lines.retain(|line| {
            parse_assignment(line)
                .map(|(key, _)| !key.to_ascii_lowercase().starts_with(&prefix))
                .unwrap_or(true)
        });
    }

    fn configure_kd_serial(&mut self, index: usize) -> bool {
        let prefix = format!("serial{index}");
        self.set_key(&format!("{prefix}.present"), "TRUE")
            | self.set_key(&format!("{prefix}.fileType"), "pipe")
            | self.set_key(&format!("{prefix}.fileName"), KD_SOCKET)
            | self.set_key(&format!("{prefix}.pipe.endPoint"), "server")
            | self.set_key(&format!("{prefix}.startConnected"), "TRUE")
            | self.set_key(&format!("{prefix}.yieldOnMsrRead"), "TRUE")
    }

    fn finish(self) -> String {
        let mut output = self.lines.join("\n");
        if self.trailing_newline {
            output.push('\n');
        }
        output
    }
}

fn serial_indices(editor: &VmxEditor) -> BTreeSet<usize> {
    editor
        .keys()
        .filter_map(|key| {
            let key = key.to_ascii_lowercase();
            let suffix = key.strip_prefix("serial")?;
            let (index, _) = suffix.split_once('.')?;
            index.parse().ok()
        })
        .collect()
}

fn managed_serials(editor: &VmxEditor) -> Vec<usize> {
    serial_indices(editor)
        .into_iter()
        .filter(|index| {
            editor.value(&format!("serial{index}.fileName")).as_deref() == Some(KD_SOCKET)
        })
        .collect()
}

fn first_free_serial(editor: &VmxEditor) -> usize {
    let used = serial_indices(editor);
    (0..)
        .find(|index| !used.contains(index))
        .expect("an unused serial port exists")
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE_VMX: &str = r#".encoding = "UTF-8"
displayName = "Windows 11"
serial0.present = "TRUE"
serial0.fileType = "file"
serial0.fileName = "/tmp/console.log"
"#;

    fn request(action: Action, backend: Option<BackendSelection>) -> ConfigureRequest {
        ConfigureRequest {
            action,
            backend,
            vmcoreinfo: false,
        }
    }

    #[test]
    fn kd_preserves_existing_serial_and_uses_next_slot() {
        let (configured, changes, port) = plan_vmx(
            BASE_VMX,
            request(Action::Configure, Some(BackendSelection::Kd)),
        )
        .unwrap();
        assert!(configured.contains(r#"serial0.fileName = "/tmp/console.log""#));
        assert!(configured.contains(r#"serial1.fileName = "/tmp/ntoseye-kd.sock""#));
        assert_eq!(port, Some(2));
        assert_eq!(changes.len(), 1);
    }

    #[test]
    fn configure_is_idempotent() {
        let request = request(Action::Configure, Some(BackendSelection::KdAndGdb));
        let (once, _, _) = plan_vmx(BASE_VMX, request).unwrap();
        let (twice, changes, port) = plan_vmx(&once, request).unwrap();
        assert_eq!(twice, once);
        assert!(changes.is_empty());
        assert_eq!(port, Some(2));
    }

    #[test]
    fn inspection_recovers_configured_transports() {
        let (configured, _, _) = plan_vmx(
            BASE_VMX,
            request(Action::Configure, Some(BackendSelection::KdAndGdb)),
        )
        .unwrap();
        assert_eq!(
            inspect_vmx(&configured).targets,
            [
                ConfiguredTarget::kd(KD_SOCKET, 2, false),
                ConfiguredTarget::gdb(DEFAULT_GDB_ADDR),
            ]
        );
    }

    #[test]
    fn launch_commands_omit_default_backend_and_endpoints() {
        let instructions = vmware_instructions(
            request(Action::Configure, Some(BackendSelection::KdAndGdb)),
            Some(2),
        );
        assert_eq!(instructions.run, ["ntoseye", "ntoseye --backend gdb"]);
    }

    #[test]
    fn remove_only_deletes_managed_serial_group_and_gdb_keys() {
        let configure_request = request(Action::Configure, Some(BackendSelection::KdAndGdb));
        let (configured, _, _) = plan_vmx(BASE_VMX, configure_request).unwrap();
        let (removed, changes, _) = plan_vmx(&configured, request(Action::Remove, None)).unwrap();
        assert!(removed.contains(r#"serial0.fileName = "/tmp/console.log""#));
        assert!(!removed.contains("serial1."));
        assert!(!removed.contains("debugStub."));
        assert_eq!(changes.len(), 2);
    }

    #[test]
    fn gdb_configuration_preserves_unrelated_lines() {
        let (configured, _, _) = plan_vmx(
            BASE_VMX,
            request(Action::Configure, Some(BackendSelection::Gdb)),
        )
        .unwrap();
        assert!(configured.contains(r#"displayName = "Windows 11""#));
        assert!(configured.contains(r#"debugStub.listen.guest64 = "TRUE""#));
        assert!(configured.contains(r#"debugStub.port.guest64 = "1234""#));
    }
}
