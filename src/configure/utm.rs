#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use std::{
    io::ErrorKind,
    path::PathBuf,
    process::{Command, Output},
};

use crate::error::{Error, Result};

use super::{
    Action, ApplyResult, BackendSelection, ConfigurationPlan, Configurator, ConfigureRequest,
    ConfiguredTarget, Guest, GuestInspection, Instructions, ProbeStatus, backup_file,
};

const BACKENDS: &[BackendSelection] = &[BackendSelection::Kd, BackendSelection::Memory];
const RECORD_SEPARATOR: char = '\u{1e}';
const FIELD_SEPARATOR: char = '\u{1f}';

const LIST_SCRIPT: &str = r#"
tell application "UTM"
    set rows to {}
    repeat with vm in virtual machines
        set row to (id of vm) & (character id 31) & (name of vm) & (character id 31) & (status of vm as text) & (character id 31) & (backend of vm as text)
        set end of rows to row
    end repeat
    set AppleScript's text item delimiters to character id 30
    return rows as text
end tell
"#;

const READ_ARGUMENTS_SCRIPT: &str = r#"
on run argv
    set vmId to item 1 of argv
    tell application "UTM"
        set matches to every virtual machine whose id is vmId
        if (count of matches) is 0 then error "UTM virtual machine was not found"
        set vm to item 1 of matches
        set config to configuration of vm
        set values to {}
        repeat with argumentValue in qemu additional arguments of config
            set end of values to argument string of argumentValue
        end repeat
        set AppleScript's text item delimiters to character id 30
        return values as text
    end tell
end run
"#;

const WRITE_ARGUMENTS_SCRIPT: &str = r#"
on run argv
    set vmId to item 1 of argv
    tell application "UTM"
        set values to {}
        if (count of argv) > 1 then
            repeat with argumentIndex from 2 to count of argv
                set end of values to {argument string:(item argumentIndex of argv)}
            end repeat
        end if
        set matches to every virtual machine whose id is vmId
        if (count of matches) is 0 then error "UTM virtual machine was not found"
        set vm to item 1 of matches
        if status of vm is not stopped then error "UTM virtual machine must be stopped"
        set config to configuration of vm
        set qemu additional arguments of config to values
        update configuration of vm with config
    end tell
end run
"#;

pub(super) struct Utm;

impl Configurator for Utm {
    fn name(&self) -> &'static str {
        "UTM"
    }

    fn probe(&self) -> ProbeStatus {
        if !cfg!(target_os = "macos") {
            return ProbeStatus::NotDetected;
        }
        match osascript("id of application \"UTM\"", &[]) {
            Err(AppleScriptError::NotFound) => ProbeStatus::NotDetected,
            Err(AppleScriptError::Failed(_)) => ProbeStatus::NotDetected,
            Ok(_) => match list_utm_guests() {
                Ok(guests) => ProbeStatus::Detected(format!(
                    "{} QEMU virtual machine{}",
                    guests.len(),
                    if guests.len() == 1 { "" } else { "s" }
                )),
                Err(error) => ProbeStatus::Unavailable(error.to_string()),
            },
        }
    }

    fn guests(&self) -> Result<Vec<Guest>> {
        list_utm_guests()
    }

    fn inspect(&self, guest: &Guest) -> Result<GuestInspection> {
        let arguments = read_arguments(&guest.id)?;
        let targets = ntoseye_socket(&arguments)
            .map(|socket| vec![ConfiguredTarget::kd(socket, 1, true)])
            .unwrap_or_default();
        Ok(GuestInspection { targets })
    }

    fn supported_backends(&self) -> &'static [BackendSelection] {
        BACKENDS
    }

    fn plan(&self, guest: &Guest, request: ConfigureRequest) -> Result<Box<dyn ConfigurationPlan>> {
        let original = read_arguments(&guest.id)?;
        let socket = utm_socket_path()?;
        let configured = plan_arguments(&original, request, &socket)?;
        let changes = if configured == original {
            Vec::new()
        } else {
            match request.action {
                Action::Configure => vec![format!(
                    "configure UTM KD serial socket {} as guest COM1",
                    socket.display()
                )],
                Action::Remove => vec!["remove ntoseye KD arguments from UTM".to_string()],
            }
        };
        let instructions = utm_instructions(request, &socket);
        Ok(Box::new(UtmPlan {
            guest_id: guest.id.clone(),
            guest_name: guest.name.clone(),
            original,
            configured,
            changes,
            instructions,
        }))
    }
}

struct UtmPlan {
    guest_id: String,
    guest_name: String,
    original: Vec<String>,
    configured: Vec<String>,
    changes: Vec<String>,
    instructions: Instructions,
}

impl ConfigurationPlan for UtmPlan {
    fn changes(&self) -> &[String] {
        &self.changes
    }

    fn instructions(&self) -> &Instructions {
        &self.instructions
    }

    fn apply(&self) -> Result<ApplyResult> {
        let backup_contents = self.original.join(&RECORD_SEPARATOR.to_string());
        let backup = backup_file(
            "utm",
            &self.guest_name,
            "qemu-args",
            backup_contents.as_bytes(),
        )?;
        write_arguments(&self.guest_id, &self.configured)?;
        let applied = read_arguments(&self.guest_id)?;
        if applied != self.configured {
            return Err(Error::DebugInfo(format!(
                "UTM configuration verification failed; original arguments are backed up at {}",
                backup.display()
            )));
        }
        Ok(ApplyResult { backup })
    }
}

fn list_utm_guests() -> Result<Vec<Guest>> {
    let output = osascript_result(LIST_SCRIPT, &[])?;
    output
        .split(RECORD_SEPARATOR)
        .filter(|row| !row.trim().is_empty())
        .filter_map(|row| {
            let fields = row.split(FIELD_SEPARATOR).collect::<Vec<_>>();
            if fields.len() != 4 || !fields[3].eq_ignore_ascii_case("qemu") {
                return None;
            }
            let state = fields[2].to_string();
            Some(Ok(Guest {
                id: fields[0].to_string(),
                name: fields[1].to_string(),
                stopped: state.eq_ignore_ascii_case("stopped"),
                state,
            }))
        })
        .collect()
}

fn read_arguments(guest_id: &str) -> Result<Vec<String>> {
    let output = osascript_result(READ_ARGUMENTS_SCRIPT, &[guest_id])?;
    if output.is_empty() {
        Ok(Vec::new())
    } else {
        Ok(output.split(RECORD_SEPARATOR).map(str::to_string).collect())
    }
}

fn write_arguments(guest_id: &str, arguments: &[String]) -> Result<()> {
    let mut argv = Vec::with_capacity(arguments.len() + 1);
    argv.push(guest_id);
    argv.extend(arguments.iter().map(String::as_str));
    osascript_result(WRITE_ARGUMENTS_SCRIPT, &argv).map(|_| ())
}

fn plan_arguments(
    original: &[String],
    request: ConfigureRequest,
    socket: &PathBuf,
) -> Result<Vec<String>> {
    let mut arguments = remove_managed_arguments(original);
    if request.action == Action::Configure {
        let backend = request.backend.ok_or_else(|| {
            Error::DebugInfo("configure request is missing a backend".to_string())
        })?;
        if !backend.kd() {
            return Err(Error::DebugInfo(
                "UTM only supports automatic configuration for the KD backend".to_string(),
            ));
        }
        arguments.extend([
            "-chardev".to_string(),
            format!(
                "socket,id=kd,path={},server=on,wait=off",
                socket.to_string_lossy()
            ),
            "-serial".to_string(),
            "chardev:kd".to_string(),
        ]);
    }
    Ok(arguments)
}

fn remove_managed_arguments(arguments: &[String]) -> Vec<String> {
    let mut output = Vec::with_capacity(arguments.len());
    let mut index = 0;
    while index < arguments.len() {
        if arguments.get(index).map(String::as_str) == Some("-chardev")
            && arguments
                .get(index + 1)
                .is_some_and(|value| is_ntoseye_chardev(value))
        {
            index += 2;
            if arguments.get(index).map(String::as_str) == Some("-serial")
                && arguments.get(index + 1).map(String::as_str) == Some("chardev:kd")
            {
                index += 2;
            }
            continue;
        }
        output.push(arguments[index].clone());
        index += 1;
    }
    output
}

fn ntoseye_socket(arguments: &[String]) -> Option<String> {
    arguments.windows(2).find_map(|pair| {
        if pair[0] != "-chardev" || !is_ntoseye_chardev(&pair[1]) {
            return None;
        }
        pair[1]
            .split(',')
            .find_map(|part| part.strip_prefix("path=").map(str::to_string))
    })
}

fn is_ntoseye_chardev(value: &str) -> bool {
    value.starts_with("socket,")
        && value.split(',').any(|part| part == "id=kd")
        && value.contains("ntoseye-kd.sock")
}

fn utm_socket_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| {
        Error::DebugInfo("HOME is not set; cannot locate UTM's container".to_string())
    })?;
    Ok(home
        .join("Library")
        .join("Containers")
        .join("com.utmapp.QEMUHelper")
        .join("Data")
        .join("tmp")
        .join("ntoseye-kd.sock"))
}

fn utm_instructions(request: ConfigureRequest, socket: &PathBuf) -> Instructions {
    if request.action == Action::Remove {
        return Instructions::default();
    }
    let mut instructions = Instructions {
        guest: vec![
            "bcdedit /debug on".to_string(),
            "bcdedit /dbgsettings serial debugport:1 baudrate:115200".to_string(),
            "Restart-Computer".to_string(),
        ],
        run: vec![ConfiguredTarget::kd(socket.to_string_lossy(), 1, true).run_command()],
        notes: Vec::new(),
    };
    instructions.notes.push(
        "Secure Boot must be disabled in UTM before Windows allows kernel debugging.".to_string(),
    );
    instructions
}

#[derive(Debug)]
enum AppleScriptError {
    NotFound,
    Failed(String),
}

fn osascript(script: &str, arguments: &[&str]) -> std::result::Result<String, AppleScriptError> {
    let output = Command::new("osascript")
        .args(["-e", script, "--"])
        .args(arguments)
        .output()
        .map_err(|error| {
            if error.kind() == ErrorKind::NotFound {
                AppleScriptError::NotFound
            } else {
                AppleScriptError::Failed(error.to_string())
            }
        })?;
    if !output.status.success() {
        return Err(AppleScriptError::Failed(command_detail(&output)));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .trim_end_matches(['\r', '\n'])
        .to_string())
}

fn osascript_result(script: &str, arguments: &[&str]) -> Result<String> {
    osascript(script, arguments).map_err(|error| match error {
        AppleScriptError::NotFound => Error::DebugInfo(
            "osascript was not found; UTM configuration requires macOS".to_string(),
        ),
        AppleScriptError::Failed(reason) => {
            Error::DebugInfo(format!("UTM AppleScript failed: {reason}"))
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn request(action: Action) -> ConfigureRequest {
        ConfigureRequest {
            action,
            backend: (action == Action::Configure).then_some(BackendSelection::Kd),
            vmcoreinfo: false,
        }
    }

    #[test]
    fn configuration_preserves_unrelated_arguments() {
        let original = vec!["-display".to_string(), "cocoa".to_string()];
        let socket = PathBuf::from("/Users/test/Library/ntoseye-kd.sock");
        let planned = plan_arguments(&original, request(Action::Configure), &socket).unwrap();
        assert_eq!(&planned[..2], original);
        assert_eq!(&planned[2], "-chardev");
        assert!(planned[3].contains("ntoseye-kd.sock"));
        assert_eq!(&planned[4..], ["-serial", "chardev:kd"]);
    }

    #[test]
    fn configuration_is_idempotent() {
        let socket = PathBuf::from("/Users/test/Library/ntoseye-kd.sock");
        let once = plan_arguments(&[], request(Action::Configure), &socket).unwrap();
        let twice = plan_arguments(&once, request(Action::Configure), &socket).unwrap();
        assert_eq!(twice, once);
    }

    #[test]
    fn inspection_recovers_managed_socket() {
        let socket = PathBuf::from("/Users/test/Library/ntoseye-kd.sock");
        let arguments = plan_arguments(&[], request(Action::Configure), &socket).unwrap();
        assert_eq!(
            ntoseye_socket(&arguments).as_deref(),
            Some("/Users/test/Library/ntoseye-kd.sock")
        );
    }

    #[test]
    fn launch_command_omits_default_kd_backend() {
        let socket = PathBuf::from("/Users/test/Library/ntoseye-kd.sock");
        let instructions = utm_instructions(request(Action::Configure), &socket);
        assert_eq!(
            instructions.run,
            ["sudo ntoseye --connect '/Users/test/Library/ntoseye-kd.sock'"]
        );
    }

    #[test]
    fn removal_only_deletes_managed_argument_sequence() {
        let socket = PathBuf::from("/Users/test/Library/ntoseye-kd.sock");
        let configured = plan_arguments(
            &["-nodefaults".to_string()],
            request(Action::Configure),
            &socket,
        )
        .unwrap();
        let removed = plan_arguments(&configured, request(Action::Remove), &socket).unwrap();
        assert_eq!(removed, ["-nodefaults"]);
    }
}
