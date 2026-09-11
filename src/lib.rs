#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("This application only runs on Linux and macOS hosts.");

pub const DEFAULT_GDB_ADDR: &str = "127.0.0.1:1234";
pub const DEFAULT_KD_SOCKET: &str = "/tmp/ntoseye-kd.sock";
pub const DEFAULT_KDNET_ADDR: &str = "0.0.0.0:50000";

pub fn resolve_target(backend: &str, connect: Option<&str>) -> Option<String> {
    match backend {
        "gdb" => Some(connect.unwrap_or(DEFAULT_GDB_ADDR).to_string()),
        "kd" => Some(connect.unwrap_or(DEFAULT_KD_SOCKET).to_string()),
        "kdnet" => Some(connect.unwrap_or(DEFAULT_KDNET_ADDR).to_string()),
        "memory" => None,
        other => {
            eprintln!(
                "warning: unknown backend \"{other}\"; instance locking disabled \
                 (add it to resolve_target)"
            );
            None
        }
    }
}

/// A live debug transport. The one enum every host (CLI, MCP, Python SDK)
/// parses its backend choice into; [`session::Session::open`] builds from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    /// KD over a serial pipe (Unix socket).
    Kd,
    /// KD over UDP (KDNET); needs a key.
    KdNet,
    /// QEMU GDB stub.
    Gdb,
    /// Passive host-memory introspection, no debug transport.
    Memory,
}

impl Backend {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Kd => "kd",
            Self::KdNet => "kdnet",
            Self::Gdb => "gdb",
            Self::Memory => "memory",
        }
    }

    /// The transport endpoint used when the host passes no `connect`; `None`
    /// for the passive memory backend, which has no endpoint at all.
    pub const fn default_endpoint(self) -> Option<&'static str> {
        match self {
            Self::Kd => Some(DEFAULT_KD_SOCKET),
            Self::KdNet => Some(DEFAULT_KDNET_ADDR),
            Self::Gdb => Some(DEFAULT_GDB_ADDR),
            Self::Memory => None,
        }
    }
}

impl std::str::FromStr for Backend {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "kd" => Ok(Self::Kd),
            "kdnet" => Ok(Self::KdNet),
            "gdb" => Ok(Self::Gdb),
            "memory" => Ok(Self::Memory),
            other => Err(format!(
                "unknown backend '{other}': expected 'kd', 'kdnet', 'gdb', or 'memory'"
            )),
        }
    }
}

impl std::fmt::Display for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// What to attach to: a crash dump, or a live VM over one [`Backend`].
#[derive(Clone, Debug)]
pub enum TargetSpec {
    Dump(std::path::PathBuf),
    Live {
        backend: Backend,
        /// Transport endpoint; `None` means the backend's default.
        connect: Option<String>,
        /// KDNET encryption key (four base-36 components).
        kdnet_key: Option<String>,
        memory_source: kd::KdMemorySource,
    },
}

impl TargetSpec {
    /// Reject argument combinations that cannot work before touching any
    /// transport, with the same wording for every host.
    pub fn validate(&self) -> std::result::Result<(), String> {
        let Self::Live {
            backend,
            connect,
            kdnet_key,
            memory_source,
        } = self
        else {
            return Ok(());
        };
        match backend {
            Backend::KdNet if kdnet_key.is_none() => {
                return Err("kdnet backend requires a key".into());
            }
            Backend::Kd | Backend::Gdb | Backend::Memory if kdnet_key.is_some() => {
                return Err("key is only valid for the kdnet backend".into());
            }
            Backend::Memory if connect.is_some() => {
                return Err("memory backend does not use a connect endpoint".into());
            }
            _ => {}
        }
        if !matches!(backend, Backend::Kd | Backend::KdNet)
            && *memory_source != kd::KdMemorySource::Auto
        {
            return Err("memory_source is only valid for kd and kdnet backends".into());
        }
        Ok(())
    }

    /// The resolved transport endpoint for a live spec (`None` for dumps and
    /// the memory backend).
    pub fn endpoint(&self) -> Option<&str> {
        match self {
            Self::Dump(_) => None,
            Self::Live {
                backend, connect, ..
            } => connect.as_deref().or(backend.default_endpoint()),
        }
    }
}

#[macro_use]
pub mod output;

pub mod backend;
pub mod bugchecks;
#[cfg(feature = "cli")]
pub mod cli;
#[cfg(feature = "cli")]
pub mod configure;
pub mod dbg_backend;
pub mod debugger_data;
pub mod diagnostics;
pub mod disasm;
pub mod dmp;
pub mod error;
pub mod expr;
pub mod gdb;
pub mod guest;
pub mod host;
pub mod kd;
#[cfg(feature = "mcp")]
pub mod mcp;
pub mod memory;
pub mod memory_backend;
pub mod phys;
#[cfg(feature = "python")]
pub mod python;
pub mod repl;
pub mod session;
pub mod symbols;
pub mod target;
pub mod trapframe;
pub mod triage;
pub mod triage_report;
pub mod types;
pub mod ui;
pub mod unwind;
#[cfg(any(feature = "mcp", feature = "python"))]
pub mod view;
