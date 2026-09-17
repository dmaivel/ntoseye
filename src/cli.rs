use argh::from_env;
use argh::{FromArgValue, FromArgs};
use std::mem::take;

use std::path::PathBuf;

#[cfg(feature = "dap")]
use crate::dap;
#[cfg(feature = "mcp")]
use crate::mcp;
use crate::{
    Backend, DEFAULT_KD_SOCKET, TargetSpec, configure, diagnostics,
    error::{Error, Result},
    kd::KdMemorySource,
    repl::{start_plain_repl, start_repl},
    session::Session,
    symbols,
};

/// argh needs a local type for `FromArgValue`; the parse itself is the crate's.
#[derive(Clone, Copy, PartialEq, Eq)]
struct BackendArg(Backend);

impl FromArgValue for BackendArg {
    fn from_arg_value(value: &str) -> std::result::Result<Self, String> {
        value.parse().map(Self)
    }
}

#[derive(FromArgs)]
/// Windows kernel debugger for Linux (KVM/QEMU, VMware) and macOS (UTM) hosts
/// running Windows. WinDbg for Linux and macOS.
struct Args {
    /// print version information
    #[argh(switch, short = 'v', long = "version")]
    version: bool,

    /// force redownloading of symbols
    #[argh(switch, long = "force-download-symbols")]
    redownload_symbols: bool,

    /// additional PDB symbol server URL (repeatable; tried before the Microsoft
    /// default). Uses the standard symbol-server path convention:
    /// {server}/{filename}/{guid}{age}/{filename}
    #[argh(option, long = "pdb-server")]
    pdb_server: Vec<String>,

    /// help instructions with enabling gdbstub in qemu
    #[argh(switch, long = "gdbstub-instructions")]
    gdbstub_instructions: bool,

    /// help instructions with enabling kd-over-serial in qemu/windows
    #[argh(switch, long = "kd-instructions")]
    kd_instructions: bool,

    /// debugger backend: 'kd' (Windows KD over serial, default), 'kdnet' (Windows KD over UDP), 'gdb' (QEMU GDB stub), or 'memory' (passive live-VM introspection)
    #[argh(
        option,
        short = 'b',
        long = "backend",
        default = "BackendArg(Backend::Kd)"
    )]
    backend: BackendArg,

    /// backend target: GDB address, KD socket path, or KDNET listen address; unused by memory
    #[argh(option, long = "connect")]
    connect: Option<String>,

    /// KDNET encryption key (four base-36 components); required by the kdnet backend
    #[argh(option, long = "kdnet-key")]
    kdnet_key: Option<String>,

    /// KD/KDNET memory source: auto (validated host memory, then KD fallback), host, or kd
    #[argh(option, long = "memory-source")]
    memory_source: Option<KdMemorySource>,

    /// use a line-oriented REPL without terminal cursor queries, completion, or history
    #[argh(switch, long = "plain-repl")]
    plain_repl: bool,
    /// open a Windows kernel crash dump (.dmp) for offline analysis instead of attaching to a live VM
    #[argh(option, long = "dump")]
    dump: Option<PathBuf>,

    #[argh(subcommand)]
    command: Option<Command>,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum Command {
    Configure(ConfigureCommand),
    Status(StatusCommand),
    #[cfg(feature = "mcp")]
    Mcp(McpCommand),
    #[cfg(feature = "dap")]
    Dap(DapCommand),
}

#[cfg(feature = "mcp")]
#[derive(FromArgs)]
#[argh(subcommand, name = "mcp")]
/// run as an MCP server, exposing the debugger as tools (reads the top-level
/// --backend/--connect/--dump to choose how to attach). Defaults to the stdio
/// transport (the client launches this binary); pass --http to serve over the
/// network.
struct McpCommand {
    /// serve the Streamable HTTP transport on this address (e.g. 127.0.0.1:8080)
    /// instead of stdio, for web MCP clients that connect over the network
    #[argh(option, long = "http")]
    http: Option<String>,

    /// allow Streamable HTTP to bind to a non-loopback address and accept any
    /// browser origin (CORS); exposes debugger control tools to the network, so
    /// only use on trusted hosts/networks. Without it, HTTP is loopback-only and
    /// cross-origin requests are restricted to loopback origins.
    #[argh(switch, long = "unsafe-http")]
    unsafe_http: bool,

    /// additional PDB symbol server URL (repeatable; tried before the Microsoft
    /// default). Same as the top-level --pdb-server; can be placed before or
    /// after the 'mcp' subcommand.
    #[argh(option, long = "pdb-server")]
    pdb_server: Vec<String>,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "configure")]
/// interactively configure a supported hypervisor for ntoseye
struct ConfigureCommand {}

#[cfg(feature = "dap")]
#[derive(FromArgs)]
#[argh(subcommand, name = "dap")]
/// run as a Debug Adapter Protocol server for editor integration. Reads the
/// top-level --backend/--connect/--dump to choose how to attach. Defaults to
/// stdio; pass --port to serve one client over loopback TCP instead.
struct DapCommand {
    /// serve one DAP client on 127.0.0.1:<port> instead of stdio, for clients
    /// configured with a debugServer port
    #[argh(option, long = "port")]
    port: Option<u16>,

    /// additional PDB symbol server URL (repeatable; tried before the
    /// Microsoft default). Same as the top-level --pdb-server; can be placed
    /// before or after the 'dap' subcommand.
    #[argh(option, long = "pdb-server")]
    pdb_server: Vec<String>,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "status")]
/// inspect configured hypervisor transports and recover launch commands
struct StatusCommand {}

static GDBSTUB_INSTRUCTIONS: &str = "The gdb backend talks to QEMU's gdbstub instead of Windows KD.
It does not require Windows debug mode, but it loses Windows-native
KD behavior such as bugcheck debug text and KD reboot signaling.

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
    if let Err(e) = run() {
        diagnostics::print_error(e);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut args: Args = from_env();
    if args.version {
        println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if args.gdbstub_instructions {
        println!("{}", GDBSTUB_INSTRUCTIONS);
        return Ok(());
    }

    if args.kd_instructions {
        println!("{}", KD_INSTRUCTIONS);
        return Ok(());
    }

    let backend = args.backend.0;
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
    let may_defer_kdnet_key = match &args.command {
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

    // Merge top-level and subcommand --pdb-server lists (the subcommand may
    // carry its own, e.g. `ntoseye mcp --pdb-server URL`).
    let mut pdb_servers = take(&mut args.pdb_server);
    #[cfg(feature = "mcp")]
    if let Some(Command::Mcp(ref mcp_args)) = args.command {
        pdb_servers.extend(mcp_args.pdb_server.clone());
    }
    #[cfg(feature = "dap")]
    if let Some(Command::Dap(ref dap_args)) = args.command {
        pdb_servers.extend(dap_args.pdb_server.clone());
    }
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

    if let Some(command) = args.command.take() {
        return match command {
            Command::Configure(_) => configure::run_interactive(),
            Command::Status(_) => configure::print_status(),
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
        };
    }

    let spec = match args.dump.as_ref() {
        Some(dump) => TargetSpec::Dump(dump.clone()),
        None => live_spec(&args, backend),
    };
    let mut ctx = Session::open(&spec)?;
    if args.plain_repl {
        start_plain_repl(&mut ctx)
    } else {
        start_repl(&mut ctx)
    }
}

fn live_spec(args: &Args, backend: Backend) -> TargetSpec {
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
    args: &Args,
    backend: Backend,
) -> Option<TargetSpec> {
    if let Some(dump) = args.dump.clone() {
        return Some(TargetSpec::Dump(dump));
    }
    if args.connect.is_some()
        || backend == Backend::Memory
        || (backend == Backend::KdNet && args.kdnet_key.is_some())
    {
        return Some(live_spec(args, backend));
    }
    if backend == Backend::Kd {
        eprintln!(
            "{tool}: note: pass --connect {DEFAULT_KD_SOCKET} to auto-attach at startup, \
             or {client_attach_hint}"
        );
    } else {
        eprintln!(
            "{tool}: note: --backend {backend} has no effect without --connect; \
             {client_attach_hint}, or pass --connect to auto-attach at startup"
        );
    }
    None
}
