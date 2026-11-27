//! GDB Remote Serial Protocol server over one kernel-debugging session.
//!
//! Any GDB-protocol client (IDA, Binary Ninja, lldb, and gdb, which Ghidra
//! drives) controls the target: registers, memory, software and hardware
//! breakpoints, and run control, with `monitor` running ntoseye's own
//! commands. It also publishes what a hypervisor stub cannot: the
//! loaded-module list, so a client can rebase its database, a memory map,
//! so it knows which addresses to show, and the process list, whose
//! processes gdb can attach to as inspection contexts.
//!
//! RSP threads are vCPUs, and every stop halts the whole target, as in the DAP
//! server. The session stays on the serving thread; clients are served one
//! at a time, and each one's breakpoints are removed when it leaves.
//!
//! The protocol's wire format is `gdb_remote`'s: bytes from the socket are
//! decoded into packets ([`connection`]), each parsed into a request and
//! answered by the server ([`dispatch`]), whose reply goes back framed.

mod access;
mod breakpoints;
mod connection;
mod dispatch;
mod host_io;
mod layout;
mod metadata;
mod monitor;
mod processes;
#[cfg(test)]
mod replay;
mod run_control;

use std::collections::HashMap;
use std::io;
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::sleep;
use std::time::Duration;

use gdb_remote::request::BreakpointType;
use gdb_remote::stop::Signalled;

use crate::TargetSpec;
use crate::arch::Arch;
use crate::backend::dbg_backend::DebugCapability;
use crate::base::error::{Error, Result};
use crate::hosts::repl::{ReplStore, open_session};
use crate::hosts::termination;
use crate::session::{Cancel, Motion, Session, Stop};

use connection::{Connection, Incoming, connection_error};
use dispatch::Flow;
use host_io::OpenFile;
use layout::Layout;
use run_control::Wait;

/// Where the server listens unless told otherwise. QEMU's own stub owns
/// `:1234`, which the `gdb` backend may be using, so this takes gdbserver's
/// conventional port instead.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:2345";
/// How long a blocking read or accept waits before checking for a
/// termination signal and servicing a halted target's transport.
const IDLE_POLL: Duration = Duration::from_millis(50);
/// Largest packet the client may send or receive. Memory reads are cut
/// to fit, so this bounds round trips for large reads.
const PACKET_SIZE: usize = 0x4000;
/// The process id threads carry until a client attaches to a Windows
/// process: the kernel, which no Windows process id names (they are
/// multiples of four).
const KERNEL_PID: u64 = 1;

/// Attach to `spec` and serve GDB clients on `listen` until a termination
/// signal arrives, then release the target.
pub fn run(spec: TargetSpec, listen: &str) -> Result<()> {
    let listener = TcpListener::bind(listen)
        .map_err(|error| Error::DebugInfo(format!("failed to bind {listen}: {error}")))?;
    let addr = listener
        .local_addr()
        .map_err(|error| Error::DebugInfo(error.to_string()))?;
    let mut session = open_session(&spec, &mut |line| eprintln!("{line}"))?;
    // IDA opens the kernel's file over the connection on every attach and
    // waits one second for the answer, so have it cached before a client
    // asks: a download inside that request would time the client out.
    match session.target.module_image_or_fetch_later("nt") {
        Ok(Some(_)) => {}
        Ok(None) => eprintln!("ntoseye-gdbserver: fetching the kernel image in the background"),
        Err(error) => eprintln!("ntoseye-gdbserver: kernel image unavailable: {error}"),
    }
    // The session's own interrupt request: a single step waits on that
    // request alone, so a termination signal must raise it to end a step
    // whose stop never arrives.
    let cancel = Arc::clone(&session.target.interrupt);
    let terminating = termination::install(&cancel);
    eprintln!("ntoseye-gdbserver: listening on {addr}");
    serve(&mut session, &listener, &cancel, &terminating)?;
    eprintln!("ntoseye-gdbserver: shutting down; releasing the target");
    session.cleanup_for_exit()
}

/// Accept clients one at a time until `terminating` is raised.
fn serve(
    session: &mut Session,
    listener: &TcpListener,
    cancel: &Arc<AtomicBool>,
    terminating: &Arc<AtomicBool>,
) -> Result<()> {
    listener
        .set_nonblocking(true)
        .map_err(|error| Error::DebugInfo(error.to_string()))?;
    while !terminating.load(Ordering::SeqCst) {
        let (stream, peer) = match listener.accept() {
            Ok(accepted) => accepted,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                sleep(IDLE_POLL);
                continue;
            }
            Err(error) => return Err(Error::DebugInfo(format!("accept failed: {error}"))),
        };
        eprintln!("ntoseye-gdbserver: client connected from {peer}");
        let connection = Connection::new(stream, Arc::clone(terminating))
            .map_err(|error| Error::DebugInfo(error.to_string()))?;
        match serve_client(session, connection, cancel, terminating) {
            Ok(reason) => eprintln!("ntoseye-gdbserver: client {peer} {reason}"),
            Err(error) => eprintln!("ntoseye-gdbserver: client {peer} dropped: {error}"),
        }
    }
    Ok(())
}

/// Serve one client until it detaches or disconnects, then remove its
/// breakpoints and let the guest run, as a detaching gdb would.
fn serve_client(
    session: &mut Session,
    connection: Connection,
    cancel: &Arc<AtomicBool>,
    terminating: &Arc<AtomicBool>,
) -> Result<&'static str> {
    halt_for_client(session);
    let mut server = Server::new(session, Arc::clone(cancel), Arc::clone(terminating));
    let result = drive(&mut server, connection);
    server.release();
    result
}

/// A GDB client attaches to a stopped target: it reads registers before it
/// resumes anything. A passive backend cannot stop the guest, so its
/// client inspects memory live.
fn halt_for_client(session: &mut Session) {
    if session.backend.is_running()
        && session.backend.supports(DebugCapability::InterruptTarget)
        && let Err(error) = session.run(Motion::Break, &Cancel::NEVER)
    {
        eprintln!("ntoseye-gdbserver: could not halt the target for the client: {error}");
    }
}

/// Answer the client until it leaves: requests while the target is halted,
/// and, while it runs, its stop or the client's interrupt. An idle wait
/// keeps a halted target's transport serviced and notices a termination
/// signal.
fn drive(server: &mut Server<'_>, mut connection: Connection) -> Result<&'static str> {
    let mut running = false;
    loop {
        if running {
            let reply = match server.wait(&mut connection).map_err(connection_error)? {
                Wait::Stopped(reply) => reply,
                Wait::Interrupted => server.interrupt(),
                Wait::Terminating => return Ok("released by a termination signal"),
            };
            server
                .flush_console(&mut connection)
                .map_err(connection_error)?;
            connection.send(&reply).map_err(connection_error)?;
            running = false;
            continue;
        }
        match connection.next(IDLE_POLL).map_err(connection_error)? {
            Some(Incoming::Packet(body)) => {
                match server
                    .handle(&mut connection, &body)
                    .map_err(connection_error)?
                {
                    Flow::Halted => {}
                    Flow::Running => running = true,
                    Flow::Leave(reason) => return Ok(reason),
                }
            }
            // A stray interrupt while halted: there is nothing to stop.
            Some(Incoming::Interrupt) => {}
            None => {
                if server.terminating() {
                    return Ok("released by a termination signal");
                }
                server.session.service_idle();
            }
        }
    }
}

/// A breakpoint the client planted, and the session breakpoint behind it.
struct Planted {
    kind: BreakpointType,
    address: u64,
    /// The watched length, for a watchpoint; the client's `kind`.
    len: u64,
    id: u32,
    /// The session breakpoint's serial: `id` alone is reused once the
    /// session's table empties, by a `monitor bp` the client never planted.
    serial: u64,
}

/// One client's view of the session: the protocol state it negotiated,
/// what it planted, and snapshots of what it reads in pieces.
struct Server<'a> {
    session: &'a mut Session,
    arch: Arch,
    layout: Layout,
    /// The REPL state `monitor` commands run in, kept between commands so
    /// aliases and caches persist.
    repl: Option<ReplStore>,
    /// Backend vCPU ids; RSP thread `n` is `threads[n - 1]`.
    threads: Vec<String>,
    planted: Vec<Planted>,
    /// The client negotiated `multiprocess+`, so thread ids carry a pid.
    multiprocess: bool,
    /// The client asked for extended mode (`!`): detaching leaves it
    /// connected, and it may attach to processes.
    extended: bool,
    /// The process thread ids name: [`KERNEL_PID`], or the Windows process
    /// the client attached to.
    pid: u64,
    /// The thread `g`, `G`, `p` and `P` read and write (`Hg`); `None`: the
    /// stopped vCPU.
    general_thread: Option<usize>,
    /// The thread a step names no thread for steps (`Hc`); `None`: the
    /// stopped vCPU.
    resume_thread: Option<usize>,
    /// A stop that already happened (a completed step, a refused resume),
    /// reported by the next wait.
    pending: Option<Stop>,
    /// The pending stop is a resume that failed: the target did not move, so
    /// it is reported as `SIGINT`, which ends a client's stepping loop, not
    /// as a trap the client would take for a step.
    resume_refused: bool,
    /// The last stop reported, and the thread (index) it was on, for `?` and
    /// lldb's `qThreadStopInfo`.
    last_stop: Option<(usize, Signalled<'static>)>,
    /// Console lines for the client, sent before the next stop report.
    notes: Vec<String>,
    debug_seq: u64,
    /// The last copy of each `qXfer` object served, by object and annex,
    /// so a client reading one in pieces sees one snapshot. Rebuilt when a
    /// read starts over at offset zero.
    snapshots: HashMap<(String, String), Vec<u8>>,
    /// Files the client opened with `vFile:open`, by descriptor.
    files: HashMap<u64, OpenFile>,
    next_fd: u64,
    cancel: Arc<AtomicBool>,
    terminating: Arc<AtomicBool>,
}

impl<'a> Server<'a> {
    fn new(
        session: &'a mut Session,
        cancel: Arc<AtomicBool>,
        terminating: Arc<AtomicBool>,
    ) -> Self {
        let arch = session.target.arch();
        let held = if session.target.is_user_target() {
            arch.context_size()
        } else {
            arch.register_buffer_size()
        };
        let layout = Layout::new(arch, &session.register_map, held);
        let debug_seq = session.read_debug_output(u64::MAX).next_seq;
        let mut server = Self {
            session,
            arch,
            layout,
            repl: None,
            threads: Vec::new(),
            planted: Vec::new(),
            multiprocess: false,
            extended: false,
            pid: KERNEL_PID,
            general_thread: None,
            resume_thread: None,
            pending: None,
            resume_refused: false,
            last_stop: None,
            notes: Vec::new(),
            debug_seq,
            snapshots: HashMap::new(),
            files: HashMap::new(),
            next_fd: 0,
            cancel,
            terminating,
        };
        server.sync_threads();
        server
    }

    fn terminating(&self) -> bool {
        self.terminating.load(Ordering::SeqCst)
    }

    /// Remove the client's breakpoints and resume a halted guest: what a
    /// detaching gdb leaves behind. The session and its own breakpoints
    /// (set through `monitor`) stay for the next client. A breakpoint that
    /// cannot be removed leaves the guest halted, as `q` and a DAP
    /// disconnect do (see [`Session::cleanup_for_exit`]): resumed, it would
    /// trap with no debugger to handle it. It stays in the session, for the
    /// shutdown cleanup or a later client to remove.
    fn release(&mut self) {
        if self.remove_planted() {
            self.resume_guest();
        }
    }

    /// Let a halted guest run, unless the server is shutting down (whose
    /// cleanup resumes it).
    fn resume_guest(&mut self) {
        if self.terminating() || self.session.backend.is_running() {
            return;
        }
        // Not `Session::run`: the driver resumes to reach and report the
        // next stop, and returns a parked stop instead of resuming. A detach
        // reports nothing and must leave the guest running either way.
        if self
            .session
            .backend
            .supports(DebugCapability::ExecutionControl)
            && let Err(error) = self.session.resume()
        {
            eprintln!("ntoseye-gdbserver: could not resume the guest: {error}");
        }
    }

    /// Remove every breakpoint the client planted, halting a running guest
    /// for the edit. Whether they are all gone; a failure is reported on
    /// the server's console, and a breakpoint that could not be removed
    /// stays the client's, so its hits are still reported and a later
    /// release neither forgets it nor resumes the guest over it.
    fn remove_planted(&mut self) -> bool {
        if self.planted.is_empty() {
            return true;
        }
        // Not `with_target_halted`, which resumes a break-in whatever
        // its edit returns.
        if self.session.backend.is_running()
            && let Err(error) = self.session.interrupt()
        {
            eprintln!(
                "ntoseye-gdbserver: could not halt the guest to remove the client's \
                 breakpoints: {error}"
            );
            return false;
        }
        let mut failures = Vec::new();
        let session = &mut *self.session;
        self.planted.retain(|&Planted { id, serial, .. }| {
            // Cleared through `monitor` already: no site is left, and a
            // breakpoint that reused the id is not the client's.
            if session.breakpoints.live(id, serial).is_none() {
                return false;
            }
            match session.remove_breakpoint(id) {
                Ok(()) | Err(Error::BPNotFound(_)) => false,
                Err(error) => {
                    failures.push(format!("#{id}: {error}"));
                    true
                }
            }
        });
        if failures.is_empty() {
            return true;
        }
        eprintln!(
            "ntoseye-gdbserver: could not remove the client's breakpoints, so the guest \
             stays halted: {}",
            failures.join("; ")
        );
        false
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    use gdb_remote::request::BreakpointType;

    use super::{Planted, Server};
    use crate::arch::{Arch, RegisterMap};
    use crate::backend::dbg_backend::{DebugBackend, StopEvent};
    use crate::base::error::{Error, Result};
    use crate::base::types::VirtAddr;
    use crate::session::{Session, session_over_memory};

    /// A halted live guest that refuses to lift the breakpoint at `refused`,
    /// counting its resumes.
    struct Guest {
        register_map: RegisterMap,
        refused: u64,
        continues: Arc<AtomicUsize>,
    }

    impl DebugBackend for Guest {
        fn register_map(&self) -> &RegisterMap {
            &self.register_map
        }
        fn read_registers(&mut self) -> Result<Vec<u8>> {
            Err(Error::NotSupported)
        }
        fn write_registers(&mut self, _data: &[u8]) -> Result<()> {
            Err(Error::NotSupported)
        }
        fn set_breakpoint(&mut self, _addr: u64) -> Result<()> {
            Ok(())
        }
        fn remove_breakpoint(&mut self, addr: u64) -> Result<()> {
            if addr == self.refused {
                return Err(Error::Breakpoint("the stub refused".into()));
            }
            Ok(())
        }
        fn continue_execution(&mut self) -> Result<()> {
            self.continues.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn step(&mut self) -> Result<()> {
            Err(Error::NotSupported)
        }
        fn interrupt(&mut self) -> Result<StopEvent> {
            Err(Error::NotSupported)
        }
        fn wait_for_stop(&mut self) -> Result<StopEvent> {
            Err(Error::NotSupported)
        }
        fn try_wait_for_stop(&mut self, _timeout: Duration) -> Result<Option<StopEvent>> {
            Ok(None)
        }
        fn thread_list(&mut self) -> Result<Vec<String>> {
            Ok(vec!["1".to_string()])
        }
        fn set_current_thread(&mut self, _thread_id: &str) -> Result<()> {
            Ok(())
        }
        fn stopped_thread_id(&mut self) -> Result<String> {
            Ok("1".to_string())
        }
        fn is_running(&self) -> bool {
            false
        }
    }

    /// A session whose guest refuses to lift the breakpoint at `refused`,
    /// holding a kernel breakpoint at each `(id, address)` of `sites`.
    fn session(refused: u64, sites: &[(u32, u64)]) -> (Session, Arc<AtomicUsize>) {
        let continues = Arc::new(AtomicUsize::new(0));
        let mut session = session_over_memory(0x1000, &[0x90; 0x40]);
        session.register_map = Arch::Amd64.register_map().clone();
        session.backend = Box::new(Guest {
            register_map: session.register_map.clone(),
            refused,
            continues: Arc::clone(&continues),
        });
        for &(id, address) in sites {
            session
                .breakpoints
                .edit()
                .insert_for_test(id, VirtAddr(address), true, None);
        }
        (session, continues)
    }

    /// Let a client that planted the breakpoints `ids`, as the session
    /// holds them now, leave.
    fn release(session: &mut Session, ids: &[u32]) {
        let planted = ids
            .iter()
            .map(|&id| {
                let serial = session.breakpoints.get(id).map_or(0, |bp| bp.serial);
                (id, serial)
            })
            .collect::<Vec<_>>();
        release_planted(session, &planted);
    }

    /// Let a client that planted the `(id, serial)` breakpoints leave.
    fn release_planted(session: &mut Session, planted: &[(u32, u64)]) {
        server_with(session, planted).release();
    }

    /// A server whose client planted the `(id, serial)` breakpoints.
    fn server_with<'s>(session: &'s mut Session, planted: &[(u32, u64)]) -> Server<'s> {
        let flag = || Arc::new(AtomicBool::new(false));
        let mut server = Server::new(session, flag(), flag());
        server.planted = planted
            .iter()
            .map(|&(id, serial)| Planted {
                kind: BreakpointType::Software,
                address: 0,
                len: 1,
                id,
                serial,
            })
            .collect();
        server
    }

    #[test]
    fn a_client_breakpoint_left_in_the_guest_keeps_it_halted() {
        let (mut session, continues) = session(0x1000, &[(1, 0x1000), (2, 0x1008)]);
        release(&mut session, &[1, 2]);

        assert_eq!(continues.load(Ordering::SeqCst), 0);
        // The one that could be removed is; the other is left for the
        // shutdown cleanup to retry.
        assert!(session.breakpoints.get(1).is_some());
        assert!(session.breakpoints.get(2).is_none());
    }

    #[test]
    fn a_client_breakpoint_cleared_through_monitor_does_not_keep_the_guest_halted() {
        let (mut session, continues) = session(u64::MAX, &[(1, 0x1000)]);
        // Breakpoint 2 was the client's until `monitor bc 2`.
        release(&mut session, &[1, 2]);

        assert_eq!(continues.load(Ordering::SeqCst), 1);
        assert!(session.breakpoints.get(1).is_none());
    }

    #[test]
    fn a_monitor_breakpoint_that_reused_a_client_id_survives_the_detach() {
        let (mut session, _) = session(u64::MAX, &[(1, 0x1000)]);
        // The client's breakpoint 1 was cleared through `monitor bc`, and
        // `monitor bp` then created another breakpoint 1.
        let serial = session.breakpoints.get(1).unwrap().serial;
        release_planted(&mut session, &[(1, serial.wrapping_add(1))]);

        assert!(session.breakpoints.get(1).is_some());
    }

    /// In extended mode a client gives up its process (`D`, `vKill`) and
    /// stays connected. A breakpoint it could not remove then must stay its
    /// own: forgotten, the release when it leaves would resume the guest
    /// with the breakpoint still in it.
    #[test]
    fn a_breakpoint_left_when_the_process_is_forgotten_stays_the_clients() {
        let (mut session, continues) = session(0x1000, &[(1, 0x1000), (2, 0x1008)]);
        let serial = |session: &Session, id| session.breakpoints.get(id).unwrap().serial;
        let planted = [(1, serial(&session, 1)), (2, serial(&session, 2))];
        let mut server = server_with(&mut session, &planted);

        assert!(!server.forget_process());
        assert_eq!(
            server
                .planted
                .iter()
                .map(|planted| planted.id)
                .collect::<Vec<_>>(),
            [1]
        );
        server.release();
        assert_eq!(server.planted.len(), 1);
        drop(server);

        assert_eq!(continues.load(Ordering::SeqCst), 0);
        assert!(session.breakpoints.get(1).is_some());
    }
}
