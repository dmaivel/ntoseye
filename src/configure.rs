use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(target_os = "linux")]
use std::path::Path;

use dialoguer::{Confirm, Select};
use owo_colors::OwoColorize;

#[cfg(any(target_os = "linux", test))]
use crate::DEFAULT_GDB_ADDR;
use crate::{
    DEFAULT_KD_SOCKET,
    error::{Error, Result},
    symbols,
};

#[cfg(target_os = "linux")]
mod libvirt;
#[cfg(any(target_os = "macos", test))]
mod utm;
#[cfg(target_os = "linux")]
mod vmware;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Action {
    Configure,
    Remove,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BackendSelection {
    Kd,
    #[cfg(any(target_os = "linux", test))]
    Gdb,
    #[cfg(any(target_os = "linux", test))]
    KdAndGdb,
    Memory,
}

impl BackendSelection {
    pub(super) fn kd(self) -> bool {
        match self {
            Self::Kd => true,
            #[cfg(any(target_os = "linux", test))]
            Self::KdAndGdb => true,
            _ => false,
        }
    }

    #[cfg(any(target_os = "linux", test))]
    pub(super) fn gdb(self) -> bool {
        matches!(self, Self::Gdb | Self::KdAndGdb)
    }
}

#[derive(Clone, Debug)]
pub(super) struct Guest {
    pub id: String,
    pub name: String,
    pub state: String,
    pub stopped: bool,
}

#[derive(Clone, Debug)]
pub(super) enum ProbeStatus {
    Detected(String),
    Unavailable(String),
    NotDetected,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ConfigureRequest {
    pub action: Action,
    pub backend: Option<BackendSelection>,
    #[cfg(any(target_os = "linux", test))]
    pub vmcoreinfo: bool,
}

#[derive(Clone, Debug, Default)]
pub(super) struct Instructions {
    pub guest: Vec<String>,
    pub run: Vec<String>,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct GuestInspection {
    pub targets: Vec<ConfiguredTarget>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ConfiguredTarget {
    pub backend: BackendSelection,
    pub endpoint: String,
    pub guest_port: Option<usize>,
    pub elevated: bool,
}

impl ConfiguredTarget {
    pub(super) fn kd(endpoint: impl Into<String>, guest_port: usize, elevated: bool) -> Self {
        Self {
            backend: BackendSelection::Kd,
            endpoint: endpoint.into(),
            guest_port: Some(guest_port),
            elevated,
        }
    }

    #[cfg(any(target_os = "linux", test))]
    pub(super) fn gdb(endpoint: impl Into<String>) -> Self {
        Self {
            backend: BackendSelection::Gdb,
            endpoint: endpoint.into(),
            guest_port: None,
            elevated: false,
        }
    }

    fn label(&self) -> &'static str {
        match self.backend {
            BackendSelection::Kd => "KD",
            #[cfg(any(target_os = "linux", test))]
            BackendSelection::Gdb => "GDB",
            #[cfg(any(target_os = "linux", test))]
            BackendSelection::KdAndGdb => {
                unreachable!("status targets represent one configured backend")
            }
            BackendSelection::Memory => {
                unreachable!("status targets represent one configured backend")
            }
        }
    }

    fn run_command(&self) -> String {
        let executable = if self.elevated {
            "sudo ntoseye"
        } else {
            "ntoseye"
        };
        match self.backend {
            BackendSelection::Kd if self.endpoint == DEFAULT_KD_SOCKET => executable.to_string(),
            BackendSelection::Kd => {
                format!("{executable} --connect {}", shell_quote(&self.endpoint))
            }
            #[cfg(any(target_os = "linux", test))]
            BackendSelection::Gdb if self.endpoint == DEFAULT_GDB_ADDR => {
                format!("{executable} --backend gdb")
            }
            #[cfg(any(target_os = "linux", test))]
            BackendSelection::Gdb => format!(
                "{executable} --backend gdb --connect {}",
                shell_quote(&self.endpoint)
            ),
            #[cfg(any(target_os = "linux", test))]
            BackendSelection::KdAndGdb => {
                unreachable!("status targets represent one configured backend")
            }
            BackendSelection::Memory => {
                unreachable!("status targets represent one configured backend")
            }
        }
    }
}

pub(super) struct ApplyResult {
    pub backup: PathBuf,
}

pub(super) trait ConfigurationPlan {
    fn changes(&self) -> &[String];
    fn instructions(&self) -> &Instructions;
    fn apply(&self) -> Result<ApplyResult>;
}

pub(super) trait Configurator {
    fn name(&self) -> &'static str;
    fn probe(&self) -> ProbeStatus;
    fn guests(&self) -> Result<Vec<Guest>>;
    fn inspect(&self, guest: &Guest) -> Result<GuestInspection>;
    fn supported_backends(&self) -> &'static [BackendSelection];
    #[cfg(any(target_os = "linux", test))]
    fn supports_vmcoreinfo(&self) -> bool {
        false
    }
    fn plan(&self, guest: &Guest, request: ConfigureRequest) -> Result<Box<dyn ConfigurationPlan>>;
}

pub fn run_interactive() -> Result<()> {
    let configurators = host_configurators();
    let probes = configurators
        .iter()
        .map(|configurator| configurator.probe())
        .collect::<Vec<_>>();
    let hypervisor_items = configurators
        .iter()
        .zip(&probes)
        .map(|(configurator, probe)| format_probe(configurator.name(), probe))
        .collect::<Vec<_>>();

    let Some(hypervisor_idx) = prompt_select("Hypervisor", &hypervisor_items)? else {
        return cancelled();
    };
    let configurator = &configurators[hypervisor_idx];
    match &probes[hypervisor_idx] {
        ProbeStatus::Detected(_) => {}
        ProbeStatus::Unavailable(reason) => {
            return Err(Error::DebugInfo(format!(
                "{} was detected but is unavailable: {reason}",
                configurator.name()
            )));
        }
        ProbeStatus::NotDetected => {
            return Err(Error::DebugInfo(format!(
                "{} was not detected on this host",
                configurator.name()
            )));
        }
    }

    let guests = configurator.guests()?;
    if guests.is_empty() {
        return Err(Error::DebugInfo(format!(
            "{} reported no virtual machines",
            configurator.name()
        )));
    }
    let guest_items = guests
        .iter()
        .map(|guest| format!("{} ({})", guest.name, guest.state))
        .collect::<Vec<_>>();
    let Some(guest_idx) = prompt_select("Virtual machine", &guest_items)? else {
        return cancelled();
    };
    let guest = &guests[guest_idx];
    if !guest.stopped {
        return Err(Error::DebugInfo(format!(
            "'{}' is {}; shut it down before changing its configuration",
            guest.name, guest.state
        )));
    }

    let action_items = vec![
        "configure debug backend".to_string(),
        "remove ntoseye debug configuration".to_string(),
    ];
    let action = match prompt_select("Action", &action_items)? {
        Some(0) => Action::Configure,
        Some(1) => Action::Remove,
        _ => return cancelled(),
    };

    let backend = if action == Action::Configure {
        let supported = configurator.supported_backends();
        let items = supported
            .iter()
            .map(|backend| backend_label(*backend))
            .collect::<Vec<_>>();
        let Some(selected) = prompt_select("Backend", &items)? else {
            return cancelled();
        };
        let backend = supported[selected];
        if backend == BackendSelection::Memory {
            println!();
            println!(
                "{}",
                "No host or guest configuration is required for memory introspection.".green()
            );
            println!("run:");
            println!("  ntoseye --backend memory");
            return Ok(());
        }
        Some(backend)
    } else {
        None
    };

    #[cfg(any(target_os = "linux", test))]
    let vmcoreinfo = action == Action::Configure
        && configurator.supports_vmcoreinfo()
        && prompt_confirm(
            "Enable crash-dump generation (vmcoreinfo, used by 'virsh dump --format=win-dmp')?",
        )?;
    let plan = configurator.plan(
        guest,
        ConfigureRequest {
            action,
            backend,
            #[cfg(any(target_os = "linux", test))]
            vmcoreinfo,
        },
    )?;

    if plan.changes().is_empty() {
        println!();
        println!("No configuration changes needed for '{}'.", guest.name);
        print_instructions(plan.instructions());
        return Ok(());
    }

    println!();
    println!("{}", "Planned changes".bold());
    for change in plan.changes() {
        println!("  {} {change}", "+".green());
    }
    println!();
    if !prompt_confirm("Apply changes?")? {
        return cancelled();
    }

    let applied = plan.apply()?;
    println!();
    println!("{}", "Configuration applied.".green());
    println!("backup: {}", applied.backup.display());
    print_instructions(plan.instructions());
    Ok(())
}

pub fn print_status() -> Result<()> {
    let configurators = host_configurators();
    for (index, configurator) in configurators.iter().enumerate() {
        if index > 0 {
            println!();
        }
        let probe = configurator.probe();
        println!("{}", format_probe(configurator.name(), &probe).bold());
        if !matches!(probe, ProbeStatus::Detected(_)) {
            continue;
        }

        let guests = match configurator.guests() {
            Ok(guests) => guests,
            Err(error) => {
                println!("  unavailable: {error}");
                continue;
            }
        };
        if guests.is_empty() {
            println!("  no virtual machines");
            continue;
        }
        for guest in &guests {
            match configurator.inspect(guest) {
                Ok(inspection) => print!("{}", render_guest_status(guest, &inspection)),
                Err(error) => {
                    println!("  {} ({})", guest.name, guest.state);
                    println!("    inspection failed: {error}");
                }
            }
        }
    }
    Ok(())
}

fn render_guest_status(guest: &Guest, inspection: &GuestInspection) -> String {
    let mut output = format!("  {} ({})\n", guest.name, guest.state);
    if inspection.targets.is_empty() {
        output.push_str("    Debug backend: not configured\n");
        return output;
    }

    for target in &inspection.targets {
        output.push_str(&format!("    {}\n", target.label()));
        if let Some(port) = target.guest_port {
            output.push_str(&format!("      Guest port: COM{port}\n"));
        }
        output.push_str(&format!("      Endpoint: {}\n", target.endpoint));
    }
    output.push_str("    Run\n");
    for target in &inspection.targets {
        output.push_str(&format!("      {}\n", target.run_command()));
    }
    output
}

fn host_configurators() -> Vec<Box<dyn Configurator>> {
    #[cfg(target_os = "linux")]
    {
        vec![Box::new(libvirt::Libvirt), Box::new(vmware::Vmware)]
    }
    #[cfg(target_os = "macos")]
    {
        vec![Box::new(utm::Utm)]
    }
}

fn format_probe(name: &str, status: &ProbeStatus) -> String {
    match status {
        ProbeStatus::Detected(detail) if detail.is_empty() => {
            format!("{name} ({})", "detected".green())
        }
        ProbeStatus::Detected(detail) => {
            format!("{name} ({}: {detail})", "detected".green())
        }
        ProbeStatus::Unavailable(reason) => {
            format!("{name} ({}: {reason})", "unavailable".yellow())
        }
        ProbeStatus::NotDetected => format!("{name} ({})", "not detected".dimmed()),
    }
}

fn backend_label(backend: BackendSelection) -> String {
    match backend {
        BackendSelection::Kd => {
            format!("KD (Windows kernel debugging) {}", "(recommended)".green())
        }
        #[cfg(any(target_os = "linux", test))]
        BackendSelection::Gdb => "GDB (hypervisor debug stub)".to_string(),
        #[cfg(any(target_os = "linux", test))]
        BackendSelection::KdAndGdb => "KD + GDB (configure both transports)".to_string(),
        BackendSelection::Memory => "Memory (passive introspection, no configuration)".to_string(),
    }
}

fn print_instructions(instructions: &Instructions) {
    if !instructions.guest.is_empty() {
        println!();
        println!("{}", "Guest setup".bold());
        for line in &instructions.guest {
            println!("  {line}");
        }
    }
    if !instructions.notes.is_empty() {
        println!();
        for note in &instructions.notes {
            println!("{} {note}", "note:".cyan().bold());
        }
    }
    if !instructions.run.is_empty() {
        println!();
        println!("{}", "Run".bold());
        for line in &instructions.run {
            println!("  {line}");
        }
    }
}

pub(super) fn prompt_select(prompt: &str, items: &[String]) -> Result<Option<usize>> {
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

pub(super) fn prompt_confirm(prompt: &str) -> Result<bool> {
    Confirm::new()
        .with_prompt(prompt)
        .default(false)
        .interact()
        .map_err(prompt_error)
}

fn prompt_error(error: dialoguer::Error) -> Error {
    Error::DebugInfo(format!("interactive prompt failed: {error}"))
}

fn cancelled() -> Result<()> {
    println!("cancelled");
    Ok(())
}

pub(super) fn backup_file(
    hypervisor: &str,
    guest: &str,
    extension: &str,
    contents: &[u8],
) -> Result<PathBuf> {
    let root = symbols::ntoseye_home().ok_or(Error::StorageNotFound)?;
    let dir = root
        .join("config-backups")
        .join(sanitize_filename(hypervisor))
        .join(sanitize_filename(guest));
    fs::create_dir_all(&dir)?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| Error::DebugInfo(format!("system clock error: {err}")))?
        .as_secs();
    let path = dir.join(format!("{timestamp}.{extension}"));
    fs::write(&path, contents)?;
    Ok(path)
}

#[cfg(target_os = "linux")]
pub(super) fn atomic_replace(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        Error::DebugInfo(format!(
            "configuration path has no parent: {}",
            path.display()
        ))
    })?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            Error::DebugInfo(format!("invalid configuration path: {}", path.display()))
        })?;
    let temporary = parent.join(format!(".{name}.ntoseye.tmp"));
    fs::copy(path, &temporary)?;
    if let Err(error) = fs::write(&temporary, contents) {
        let _ = fs::remove_file(&temporary);
        return Err(error.into());
    }
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error.into());
    }
    Ok(())
}

pub(super) fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_names_are_path_safe() {
        assert_eq!(sanitize_filename("win/11 test"), "win_11_test");
    }

    #[test]
    fn shell_values_are_quoted() {
        assert_eq!(shell_quote("it's here"), "'it'\\''s here'");
    }

    #[test]
    fn default_targets_produce_minimal_run_commands() {
        assert_eq!(
            ConfiguredTarget::kd(DEFAULT_KD_SOCKET, 1, false).run_command(),
            "ntoseye"
        );
        assert_eq!(
            ConfiguredTarget::gdb(DEFAULT_GDB_ADDR).run_command(),
            "ntoseye --backend gdb"
        );
    }

    #[test]
    fn status_renders_configured_targets_and_commands() {
        let guest = Guest {
            id: "windows".to_string(),
            name: "Windows".to_string(),
            state: "running".to_string(),
            stopped: false,
        };
        let inspection = GuestInspection {
            targets: vec![
                ConfiguredTarget::kd(DEFAULT_KD_SOCKET, 2, false),
                ConfiguredTarget::gdb(DEFAULT_GDB_ADDR),
            ],
        };
        assert_eq!(
            render_guest_status(&guest, &inspection),
            concat!(
                "  Windows (running)\n",
                "    KD\n",
                "      Guest port: COM2\n",
                "      Endpoint: /tmp/ntoseye-kd.sock\n",
                "    GDB\n",
                "      Endpoint: 127.0.0.1:1234\n",
                "    Run\n",
                "      ntoseye\n",
                "      ntoseye --backend gdb\n",
            )
        );
    }

    #[test]
    fn status_marks_guests_without_managed_transports() {
        let guest = Guest {
            id: "windows".to_string(),
            name: "Windows".to_string(),
            state: "stopped".to_string(),
            stopped: true,
        };
        assert_eq!(
            render_guest_status(&guest, &GuestInspection::default()),
            "  Windows (stopped)\n    Debug backend: not configured\n"
        );
    }
}
