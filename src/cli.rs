use clap::{Args, CommandFactory, Parser, Subcommand};
use owo_colors::OwoColorize;
use std::ffi::OsString;
use std::mem::take;

use std::path::PathBuf;

#[cfg(feature = "dap")]
use crate::dap;
#[cfg(feature = "gdbserver")]
use crate::gdbserver;
#[cfg(feature = "mcp")]
use crate::mcp;
use crate::{
    Backend, TargetSpec, configure, diagnostics,
    error::{Error, Result},
    kd::KdMemorySource,
    repl::{command_reference_json, json_string, start_plain_repl, start_repl},
    session::Session,
    symbols,
};

#[derive(Parser)]
#[command(name = "ntoseye", about)]
struct Cli {
    /// Print version information
    #[arg(short = 'v', long)]
    version: bool,

    /// Print how to enable QEMU's gdbstub for the gdb backend
    #[arg(long)]
    gdbstub_instructions: bool,

    /// Print how to enable KD over serial in QEMU and Windows
    #[arg(long)]
    kd_instructions: bool,

    /// Use a line-oriented REPL without terminal cursor queries, completion,
    /// or history
    #[arg(long)]
    plain_repl: bool,

    /// Print the command-line and REPL command help as JSON for the
    /// documentation build
    #[arg(long, hide = true)]
    dump_command_reference: bool,

    #[command(flatten)]
    target: TargetOptions,

    #[command(subcommand)]
    command: Option<Command>,
}

/// What to attach to and where symbols come from. Global, so they go before
/// or after a subcommand: `ntoseye gdbserver --backend gdb` and
/// `ntoseye --backend gdb gdbserver` are the same.
#[derive(Args)]
struct TargetOptions {
    /// Debugger backend: 'kd' (Windows KD over serial, default), 'kdnet'
    /// (Windows KD over UDP), 'gdb' (QEMU GDB stub), or 'memory' (passive
    /// live-VM introspection)
    #[arg(short = 'b', long, global = true)]
    backend: Option<Backend>,

    /// Backend target: GDB address, KD socket path, or KDNET listen address;
    /// unused by memory
    #[arg(long, global = true)]
    connect: Option<String>,

    /// KDNET encryption key (four base-36 components); required by the kdnet
    /// backend
    #[arg(long, global = true)]
    kdnet_key: Option<String>,

    /// KD/KDNET memory source: auto (validated host memory, then KD
    /// fallback), host, or kd
    #[arg(long, global = true)]
    memory_source: Option<KdMemorySource>,

    /// Open a Windows kernel crash dump (.dmp) for offline analysis instead of
    /// attaching to a live VM
    #[arg(long, global = true)]
    dump: Option<PathBuf>,

    /// Additional PDB symbol server URL (repeatable; tried before the
    /// Microsoft default), using the standard symbol-server path convention:
    /// {server}/{filename}/{guid}{age}/{filename}
    #[arg(long, global = true)]
    pdb_server: Vec<String>,

    /// Force redownloading of symbols
    #[arg(long = "force-download-symbols", global = true)]
    redownload_symbols: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Interactively configure a supported hypervisor for ntoseye
    Configure,
    /// Inspect configured hypervisor transports and recover launch commands
    Status,
    /// Run as an MCP server, exposing the debugger as tools
    ///
    /// Attaches at launch when --backend/--connect/--dump name a target;
    /// otherwise the client attaches with the 'open' tool. Defaults to the
    /// stdio transport (the client launches this binary); pass --http to serve
    /// over the network.
    #[cfg(feature = "mcp")]
    Mcp(McpCommand),
    /// Run as a Debug Adapter Protocol server for editor integration
    ///
    /// Attaches at launch when --backend/--connect/--dump name a target;
    /// otherwise the client's launch/attach arguments do. Defaults to stdio;
    /// pass --port to serve one client over loopback TCP instead.
    #[cfg(feature = "dap")]
    Dap(DapCommand),
    /// Serve the session over the GDB remote protocol, for IDA, Binary Ninja,
    /// Ghidra, gdb, and lldb
    ///
    /// Attaches to the target --backend/--connect/--dump name, then serves one
    /// client at a time until interrupted.
    #[cfg(feature = "gdbserver")]
    Gdbserver(GdbserverCommand),
}

#[cfg(feature = "mcp")]
#[derive(Args)]
struct McpCommand {
    /// Serve the Streamable HTTP transport on this address (e.g.
    /// 127.0.0.1:8080) instead of stdio, for web MCP clients that connect over
    /// the network
    #[arg(long)]
    http: Option<String>,

    /// Allow Streamable HTTP to bind to a non-loopback address and accept any
    /// browser origin (CORS); exposes debugger control tools to the network,
    /// so only use on trusted hosts/networks. Without it, HTTP is
    /// loopback-only and cross-origin requests are restricted to loopback
    /// origins.
    #[arg(long)]
    unsafe_http: bool,
}

#[cfg(feature = "dap")]
#[derive(Args)]
struct DapCommand {
    /// Serve one DAP client on 127.0.0.1:<port> instead of stdio, for clients
    /// configured with a debugServer port
    #[arg(long)]
    port: Option<u16>,
}

#[cfg(feature = "gdbserver")]
#[derive(Args)]
struct GdbserverCommand {
    /// Address to listen on
    #[arg(long, default_value = gdbserver::DEFAULT_LISTEN)]
    listen: String,
}

static GDBSTUB_INSTRUCTIONS: &str = "The gdb backend talks to QEMU's gdbstub instead of Windows KD.
It does not require Windows debug mode, but it loses Windows-native
KD behavior such as debug output and KD reboot signaling. A bugcheck is
still caught: the debugger breaks on nt!KeBugCheckEx and reads the code
from the call itself.

To enable it, pass the following arguments to QEMU:

-s -S

Then run ntoseye with:

ntoseye --backend gdb

If you are running QEMU via commandline, simply append the arguments
to your existing command.

If you are running QEMU via virt-manager, you must edit the libvirt
XML file, which can be done through their GUI. Once there, add:

<domain xmlns:qemu=\"http://libvirt.org/schemas/domain/qemu/1.0\" type=\"kvm\">
  ...
  <qemu:commandline>
    <qemu:arg value=\"-s\"/>
    <qemu:arg value=\"-S\"/>
  </qemu:commandline>
</domain>";

static KD_INSTRUCTIONS: &str = "The KD backend is ntoseye's default backend.
It speaks the same wire protocol WinDbg uses, over a serial pipe
between QEMU and ntoseye. It requires Windows to be booted in debug
mode (which removes the 'stealth' property of the gdb backend:
anti-debug code, PatchGuard, and even some Windows behaviors change
when /debug is on).

GUEST: enable kernel debugging over a serial port (run as
Administrator, then reboot):

bcdedit /debug on
bcdedit /dbgsettings serial debugport:1 baudrate:115200

If your hypervisor wires the KD serial as COM2 (see the libvirt
note below), use 'debugport:2' instead.

QEMU (commandline): route COM1 to a host-side Unix socket. The
path here matches ntoseye's default; adjust both sides if you pick
a different one:

-chardev socket,id=kd,path=/tmp/ntoseye-kd.sock,server=on,wait=off -serial chardev:kd

QEMU via virt-manager / libvirt: virt-manager auto-adds a <serial>
console device on every VM, and it claims COM1. Either replace or
remove that device so the KD chardev becomes COM1 (recommended), or
leave it in place and the KD chardev will be COM2 (use 'debugport:2'
in bcdedit instead of 'debugport:1').

OPTION A (recommended): replace the auto-added <serial> with one
that points at our Unix socket. KD is COM1, 'debugport:1' is correct.

<serial type=\"unix\">
  <source mode=\"bind\" path=\"/tmp/ntoseye-kd.sock\"/>
  <target type=\"isa-serial\" port=\"0\"/>
</serial>

OPTION B: leave the auto-added serial alone and append the KD
chardev via qemu:commandline. KD ends up as COM2, so use
'debugport:2' in bcdedit.

<domain xmlns:qemu=\"http://libvirt.org/schemas/domain/qemu/1.0\" type=\"kvm\">
  ...
  <qemu:commandline>
    <qemu:arg value=\"-chardev\"/>
    <qemu:arg value=\"socket,id=kd,path=/tmp/ntoseye-kd.sock,server=on,wait=off\"/>
    <qemu:arg value=\"-serial\"/>
    <qemu:arg value=\"chardev:kd\"/>
  </qemu:commandline>
</domain>

Once the guest is booting (or already booted and waiting for the
debugger), run:

ntoseye --connect /tmp/ntoseye-kd.sock

ntoseye waits 8 seconds for the initial KD handshake by default.
For unusually slow guests, override it with:

NTOSEYE_KD_TIMEOUT=20 ntoseye

macOS (UTM): UTM sandboxes QEMU (even the unsigned build), so the
socket must live inside UTM's QEMUHelper container instead of /tmp.
In the VM settings, add to 'Arguments (QEMU)':

-chardev socket,id=kd,path=/Users/YOU/Library/Containers/com.utmapp.QEMUHelper/Data/tmp/ntoseye-kd.sock,server=on,wait=off -serial chardev:kd

then connect to that path as root:

sudo ntoseye --backend kd --connect \"$HOME/Library/Containers/com.utmapp.QEMUHelper/Data/tmp/ntoseye-kd.sock\"

Windows ARM64 is supported (machine 0xAA64). Secure Boot must be
disabled for bcdedit /debug on to work.";

pub fn main() {
    std::process::exit(run_with_args(std::env::args_os()));
}

/// `{"cli": [{"name", "help"}], "commands": [...]}`: `ntoseye --help` and
/// each subcommand's, as clap renders them, then every REPL command (see
/// [`command_reference_json`]).
fn reference_json() -> String {
    let mut root = Cli::command();
    root.build();
    let mut pages = vec![("ntoseye".to_string(), root.render_long_help().to_string())];
    for sub in root
        .get_subcommands()
        .filter(|sub| sub.get_name() != "help")
    {
        let name = format!("ntoseye {}", sub.get_name());
        pages.push((name, sub.clone().render_long_help().to_string()));
    }
    let cli: Vec<String> = pages
        .iter()
        .map(|(name, help)| {
            format!(
                "{{\"name\":{},\"help\":{}}}",
                json_string(name),
                json_string(help)
            )
        })
        .collect();
    format!(
        "{{\"cli\":[{}],\n\"commands\":{}}}",
        cli.join(",\n"),
        command_reference_json()
    )
}

/// Run the CLI on `args` (the program name first) and return the process
/// exit status. The wheel's `ntoseye` script calls this with `sys.argv`.
pub fn run_with_args(args: impl IntoIterator<Item = OsString>) -> i32 {
    match run(Cli::parse_from(args)) {
        Ok(()) => 0,
        Err(error) => {
            diagnostics::print_error(error);
            1
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    let Cli {
        version,
        gdbstub_instructions,
        kd_instructions,
        plain_repl,
        dump_command_reference,
        target: mut args,
        command,
    } = cli;
    if version {
        println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if dump_command_reference {
        println!("{}", reference_json());
        return Ok(());
    }
    if gdbstub_instructions {
        println!("{}", GDBSTUB_INSTRUCTIONS);
        return Ok(());
    }

    if kd_instructions {
        println!("{}", KD_INSTRUCTIONS);
        return Ok(());
    }

    let backend = args.backend.unwrap_or(Backend::Kd);
    if backend != Backend::KdNet && args.kdnet_key.is_some() {
        return Err(Error::DebugInfo(
            "--kdnet-key is only valid with --backend kdnet".to_string(),
        ));
    }
    if !matches!(backend, Backend::Kd | Backend::KdNet) && args.memory_source.is_some() {
        return Err(Error::DebugInfo(
            "--memory-source is only valid with --backend kd or --backend kdnet".to_string(),
        ));
    }
    // A protocol server may start without a target and be pointed at one by
    // its client, which is where the KDNET key arrives instead.
    let may_defer_kdnet_key = match &command {
        #[cfg(feature = "mcp")]
        Some(Command::Mcp(_)) => true,
        #[cfg(feature = "dap")]
        Some(Command::Dap(_)) => true,
        _ => false,
    };
    if backend == Backend::KdNet && args.kdnet_key.is_none() && !may_defer_kdnet_key {
        return Err(Error::DebugInfo(
            "--backend kdnet requires --kdnet-key <w.x.y.z>".to_string(),
        ));
    }

    symbols::FORCE_DOWNLOADS
        .set(args.redownload_symbols)
        .map_err(|_| {
            Error::DebugInfo("symbol download flag was initialized before startup".into())
        })?;

    let pdb_servers = take(&mut args.pdb_server);
    if !pdb_servers.is_empty() {
        symbols::PDB_SERVERS.set(pdb_servers).map_err(|_| {
            Error::DebugInfo("PDB server list was initialized before startup".into())
        })?;
    }

    if args.dump.is_some() && args.connect.is_some() {
        return Err(Error::DebugInfo(
            "--dump opens a crash dump and does not use --connect".to_string(),
        ));
    }
    if backend == Backend::Memory && args.connect.is_some() {
        return Err(Error::DebugInfo(
            "memory backend does not use --connect".to_string(),
        ));
    }

    if let Some(command) = command {
        return match command {
            Command::Configure => configure::run_interactive(),
            Command::Status => configure::print_status(),
            #[cfg(feature = "mcp")]
            Command::Mcp(mcp_args) => {
                let spec = server_startup_spec(
                    "ntoseye-mcp",
                    "use the 'open' tool after launch",
                    &args,
                    backend,
                );
                mcp::run(spec, mcp_args.http, mcp_args.unsafe_http)
                    .map_err(|e| Error::DebugInfo(e.to_string()))
            }
            #[cfg(feature = "dap")]
            Command::Dap(dap_args) => {
                let spec = server_startup_spec(
                    "ntoseye-dap",
                    "name the target in the client's launch/attach arguments",
                    &args,
                    backend,
                );
                dap::run(spec, dap_args.port)
            }
            // The protocol has no attach request, so the command line names
            // the target, at the same default endpoint the REPL would use.
            #[cfg(feature = "gdbserver")]
            Command::Gdbserver(gdbserver_args) => {
                let spec = match args.dump.as_ref() {
                    Some(dump) => TargetSpec::Dump(dump.clone()),
                    None => live_spec(&args, backend),
                };
                gdbserver::run(spec, &gdbserver_args.listen)
            }
        };
    }

    let spec = match args.dump.as_ref() {
        Some(dump) => TargetSpec::Dump(dump.clone()),
        None => live_spec(&args, backend),
    };
    let mut ctx = Session::open_with_progress(&spec, &mut |line| {
        eprintln!("{}", line.bright_black());
    })?;
    if plain_repl {
        start_plain_repl(&mut ctx)
    } else {
        start_repl(&mut ctx)
    }
}

fn live_spec(args: &TargetOptions, backend: Backend) -> TargetSpec {
    TargetSpec::Live {
        backend,
        connect: args.connect.clone(),
        kdnet_key: args.kdnet_key.clone(),
        memory_source: args.memory_source.unwrap_or(KdMemorySource::Auto),
    }
}

/// The target a protocol server (MCP, DAP) attaches at startup: one pinned by
/// the command line, or `None` when the client is expected to name it in its
/// own attach request.
#[cfg(any(feature = "mcp", feature = "dap"))]
fn server_startup_spec(
    tool: &str,
    client_attach_hint: &str,
    args: &TargetOptions,
    backend: Backend,
) -> Option<TargetSpec> {
    if let Some(dump) = args.dump.clone() {
        return Some(TargetSpec::Dump(dump));
    }
    // Naming a backend is the operator saying what to attach to, so it
    // attaches, at the same default endpoint the REPL would use. KDNET is the
    // exception: its key is not guessable. Without `--backend` the default is
    // KD, which must not grab a socket nobody asked about.
    if args.connect.is_some()
        || (args.backend.is_some() && backend != Backend::KdNet)
        || (backend == Backend::KdNet && args.kdnet_key.is_some())
    {
        return Some(live_spec(args, backend));
    }
    if backend == Backend::KdNet {
        eprintln!(
            "{tool}: note: --backend kdnet needs --kdnet-key to auto-attach at startup; {client_attach_hint}"
        );
    } else {
        eprintln!(
            "{tool}: note: pass --connect {DEFAULT_KD_SOCKET} to auto-attach at startup, \
             or {client_attach_hint}",
            DEFAULT_KD_SOCKET = crate::DEFAULT_KD_SOCKET
        );
    }
    None
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::Cli;

    #[test]
    fn command_definition_is_valid() {
        Cli::command().debug_assert();
    }

    /// Target options name the target whichever side of a server subcommand
    /// they are on.
    #[cfg(feature = "gdbserver")]
    #[test]
    fn target_options_parse_before_and_after_the_subcommand() {
        use clap::Parser;

        let options = [
            "--backend",
            "kdnet",
            "--connect",
            "0.0.0.0:50000",
            "--kdnet-key",
            "1.2.3.4",
            "--memory-source",
            "kd",
            "--pdb-server",
            "https://symbols.example",
            "--force-download-symbols",
        ];
        let after = Cli::try_parse_from(["ntoseye", "gdbserver"].into_iter().chain(options))
            .unwrap()
            .target;
        let before =
            Cli::try_parse_from(["ntoseye"].into_iter().chain(options).chain(["gdbserver"]))
                .unwrap()
                .target;
        for target in [after, before] {
            assert_eq!(target.backend, Some(crate::Backend::KdNet));
            assert_eq!(target.connect.as_deref(), Some("0.0.0.0:50000"));
            assert_eq!(target.kdnet_key.as_deref(), Some("1.2.3.4"));
            assert_eq!(target.memory_source, Some(crate::kd::KdMemorySource::Kd));
            assert_eq!(target.pdb_server, ["https://symbols.example"]);
            assert!(target.redownload_symbols);
        }
    }
}
