use argh::{FromArgValue, FromArgs};

use std::path::PathBuf;
use std::sync::Arc;

use crate::{
    dbg_backend::DebugBackend,
    diagnostics,
    dmp::DmpBackend,
    error::{Error, Result},
    gdb::GdbClient,
    kd::KdBackend,
    memory_backend::MemoryBackend,
    phys::PhysMem,
    repl::start_repl,
    session, symbols, virsh,
};
#[cfg(feature = "mcp")]
use crate::mcp;

#[derive(Clone, Copy, PartialEq, Eq)]
enum BackendKind {
    Gdb,
    Kd,
    Memory,
}

impl FromArgValue for BackendKind {
    fn from_arg_value(value: &str) -> std::result::Result<Self, String> {
        match value {
            "gdb" => Ok(BackendKind::Gdb),
            "kd" => Ok(BackendKind::Kd),
            "memory" => Ok(BackendKind::Memory),
            other => Err(format!(
                "unknown backend '{other}': expected 'kd', 'gdb', or 'memory'"
            )),
        }
    }
}

#[derive(FromArgs)]
/// Windows kernel debugger for Linux hosts running Windows under KVM/QEMU
struct Args {
    /// print version information
    #[argh(switch, short = 'v', long = "version")]
    version: bool,

    /// force redownloading of symbols
    #[argh(switch, long = "force-download-symbols")]
    redownload_symbols: bool,

    /// help instructions with enabling gdbstub in qemu
    #[argh(switch, long = "gdbstub-instructions")]
    gdbstub_instructions: bool,

    /// help instructions with enabling kd-over-serial in qemu/windows
    #[argh(switch, long = "kd-instructions")]
    kd_instructions: bool,

    /// debugger backend: 'kd' (Windows KD over serial pipe, default), 'gdb' (QEMU gdbstub), or 'memory' (passive /dev/kvm introspection)
    #[argh(option, short = 'b', long = "backend", default = "BackendKind::Kd")]
    backend: BackendKind,

    /// backend connection target. Defaults: '127.0.0.1:1234' for gdb, '/tmp/ntoseye-kd.sock' for kd; unused by memory.
    #[argh(option, long = "connect")]
    connect: Option<String>,

    /// open a Windows kernel crash dump (.dmp) for offline analysis instead of attaching to a live VM
    #[argh(option, long = "dump")]
    dump: Option<PathBuf>,

    #[argh(subcommand)]
    command: Option<Command>,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum Command {
    Virsh(VirshCommand),
    #[cfg(feature = "mcp")]
    Mcp(McpCommand),
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
}

#[derive(FromArgs)]
#[argh(subcommand, name = "virsh")]
/// interactively edit libvirt XML for ntoseye debug backends
struct VirshCommand {}

static GDBSTUB_INSTRUCTIONS: &str = "The gdb backend talks to QEMU's gdbstub instead of Windows KD.
It does not require Windows debug mode, but it loses Windows-native
KD behavior such as bugcheck debug text and KD reboot signalling.

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

NTOSEYE_KD_TIMEOUT=20 ntoseye";

pub fn main() {
    if let Err(e) = run() {
        diagnostics::print_error(e);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args: Args = argh::from_env();
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

    print_home_migration();

    symbols::FORCE_DOWNLOADS
        .set(args.redownload_symbols)
        .map_err(|_| {
            Error::DebugInfo("symbol download flag was initialized before startup".into())
        })?;

    if args.dump.is_some() && args.connect.is_some() {
        return Err(Error::DebugInfo(
            "--dump opens a crash dump and does not use --connect".to_string(),
        ));
    }

    if let Some(command) = args.command {
        return match command {
            Command::Virsh(_) => virsh::run_interactive(),
            #[cfg(feature = "mcp")]
            Command::Mcp(mcp_args) => {
                let backend = match args.backend {
                    BackendKind::Gdb => "gdb",
                    BackendKind::Kd => "kd",
                    BackendKind::Memory => "memory",
                };
                mcp::run(
                    backend.to_string(),
                    args.connect.clone(),
                    args.dump.clone(),
                    mcp_args.http.clone(),
                    mcp_args.unsafe_http,
                )
                .map_err(|e| Error::DebugInfo(e.to_string()))
            }
        };
    }

    if let Some(dump_path) = &args.dump {
        let phys = Arc::new(PhysMem::dmp(dump_path)?);
        let info = phys
            .dmp_info()
            .expect("dmp_info must be Some for DMP backend")
            .clone();
        // A dump is read-only, so no per-target lock: any number of sessions
        // can analyse dumps alongside a live debugger.
        let mut ctx = session::Session::connect(
            phys,
            None,
            || -> Result<Box<dyn DebugBackend>> { Ok(Box::new(DmpBackend::new(&info))) },
        )?;
        return start_repl(&mut ctx);
    }

    // kd/gdb take a per-target instance lock so a second ntoseye can't
    // attach to the same backend resource; passive memory introspection
    // passes None and coexists with anything.
    let backend_str = match args.backend {
        BackendKind::Gdb => "gdb",
        BackendKind::Kd => "kd",
        BackendKind::Memory => "memory",
    };
    let target = crate::resolve_target(backend_str, args.connect.as_deref());
    let phys = Arc::new(PhysMem::kvm()?);
    let mut ctx = session::Session::connect(
        phys,
        target.as_deref(),
        || -> Result<Box<dyn DebugBackend>> {
            Ok(match args.backend {
                BackendKind::Gdb => {
                    Box::new(GdbClient::connect(target.as_deref().unwrap())?)
                }
                BackendKind::Kd => {
                    Box::new(KdBackend::connect(target.as_deref().unwrap())?)
                }
                BackendKind::Memory => {
                    if args.connect.is_some() {
                        return Err(Error::DebugInfo(
                            "memory backend does not use --connect".to_string(),
                        ));
                    }
                    Box::new(MemoryBackend::new())
                }
            })
        },
    )?;
    start_repl(&mut ctx)
}

fn print_home_migration() {
    if let Some((old, new)) = symbols::home_migration() {
        diagnostics::eprint_note(format!(
            "migrated ntoseye home from {} to {}",
            old.display(),
            new.display()
        ));
    }
}
