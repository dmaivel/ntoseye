#[cfg(not(target_os = "linux"))]
compile_error!("This application only runs on Linux hosts.");

pub const DEFAULT_GDB_ADDR: &str = "127.0.0.1:1234";
pub const DEFAULT_KD_SOCKET: &str = "/tmp/ntoseye-kd.sock";

pub fn resolve_target(backend: &str, connect: Option<&str>) -> Option<String> {
    match backend {
        "gdb" => Some(connect.unwrap_or(DEFAULT_GDB_ADDR).to_string()),
        "kd" => Some(connect.unwrap_or(DEFAULT_KD_SOCKET).to_string()),
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

pub mod backend;
pub mod bugchecks;
#[cfg(feature = "cli")]
pub mod cli;
pub mod dbg_backend;
pub mod dmp;
pub mod diagnostics;
pub mod disasm;
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
pub mod types;
pub mod ui;
#[cfg(any(feature = "mcp", feature = "python"))]
pub mod view;
pub mod unwind;
#[cfg(feature = "cli")]
pub mod virsh;
