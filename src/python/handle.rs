//! Session access for every SDK object: the [`Debugger`] owns (or borrows) the
//! `Session`, and every handle reaches it through [`Owner`], which also refuses
//! handles minted before the guest was rebuilt (a reboot).

use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{JoinHandle, ThreadId};
use std::time::Duration;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyAny;

use super::context::{Context, in_context};
use super::{ErrorKind, err, error, raise};
use crate::dbg_backend::halt_unreachable_reason;
use crate::error::{Error, Result as CoreResult};
use crate::repl::ReplStore;
use crate::session::Session;

/// How often an idle owner thread services the guest (see [`Actor`]); the
/// MCP server uses the same cadence.
const SERVICE_TICK: Duration = Duration::from_millis(20);

/// How often a Python thread waiting on the owner thread checks for signals
/// (Ctrl+C).
const SIGNAL_POLL: Duration = Duration::from_millis(100);

// An attached session lives on its own owner thread ([`Actor`]) and every
// call waits for it with the GIL released. A borrowed one (a REPL custom
// command's) is only valid on the REPL's thread for the command's span. An
// owned session's single-instance lock is released when the debugger is
// dropped, not by `close()`.
/// A live debugging session. As a context manager, leaving the `with` block
/// closes it (`close()`): every breakpoint is removed, the target resumes, and
/// the session ends.
///
/// Usable from any Python thread: calls are serialized on the session's own
/// thread, and a call that waits (`run()`, `wait()`) releases the GIL. Ctrl+C
/// (`KeyboardInterrupt`) during a call ends a wait, step, or trace early and
/// raises; during a resuming `command()` it breaks in, as in the REPL. Between
/// calls the session keeps servicing the guest, resuming wrong-process and
/// false-condition breakpoint hits so the guest never sits frozen. A debugger
/// handed to a REPL custom command is valid only on the REPL's thread, for
/// that command.
#[pyclass(frozen, module = "ntoseye")]
pub struct Debugger {
    inner: SessionHandle,
    /// REPL-side state (aliases, radix, `ls` cursor, completion caches) that
    /// `command()` keeps between calls, like the MCP `command` tool does.
    pub repl_store: Shared<Option<ReplStore>>,
    /// Python `when=` breakpoint conditions by breakpoint id. These can
    /// capture the debugger itself, so they are exposed to the GC through
    /// `__traverse__`/`__clear__`; otherwise the cycle would leak the session
    /// and its single-instance lock.
    pub conditions: Shared<HashMap<u32, Py<PyAny>>>,
    /// The target's rebuild count ([`crate::target::Target::generation`]),
    /// shared with the session so staleness checks need no trip to it.
    generation: Arc<AtomicU64>,
}

/// A mutex that shrugs off poisoning: a panic in one SDK call must not make
/// the debugger unusable. Never held across a call into Python.
#[derive(Default)]
pub struct Shared<T>(Mutex<T>);

impl<T> Shared<T> {
    pub fn new(value: T) -> Self {
        Shared(Mutex::new(value))
    }

    pub fn lock(&self) -> MutexGuard<'_, T> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The guard unless another thread holds it (for the GC hooks, which
    /// must not block).
    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        self.0.try_lock().ok()
    }
}

/// The `Session` a [`Debugger`] drives: one its owner thread holds (from
/// `attach`), or the REPL's, borrowed for one custom command
/// ([`Debugger::from_session_ref`]).
pub enum SessionHandle {
    Owned(Actor),
    /// A session owned by the REPL. The pointer is valid only while `valid`
    /// reads true (the dispatcher flips it false when the command returns) and
    /// only on `thread`, the REPL's, so a stashed or smuggled handle raises
    /// instead of dereferencing a dangling or concurrently used session.
    Borrowed {
        ptr: NonNull<Session>,
        valid: Arc<AtomicBool>,
        thread: ThreadId,
        busy: AtomicBool,
    },
}

// SAFETY: `Owned` is a channel and a join handle. `Borrowed` is only
// dereferenced after checking the current thread is the REPL's own `thread`
// and `busy` guards against re-entry there, so the pointer is never touched
// from two threads or aliased mutably.
unsafe impl Send for SessionHandle {}
unsafe impl Sync for SessionHandle {}

/// Panic message when a borrowed handle is used after its command returned.
pub const STALE_BORROW: &str = "ntoseye: use of a Debugger (or any handle derived from it) after the REPL command \
     that created it returned; borrowed handles are valid only inside that command and must \
     not be stashed across calls";

/// A job for the owner thread. Lifetime-erased: see [`Actor::run`].
type Job = Box<dyn FnOnce(&mut Session) + Send + 'static>;

/// The owner thread of an attached session. The `Session` is opened on that
/// thread and never leaves it (it is not `Send`); callers ship closures over
/// a channel. Between jobs it services the guest every [`SERVICE_TICK`], so a
/// wrong-process or false-condition breakpoint hit is resumed (and a real stop
/// parked for the next wait) even while no Python code is calling in.
pub struct Actor {
    /// `None` once [`Actor::shutdown`] closed the session.
    jobs: Shared<Option<Sender<Job>>>,
    /// The session's interrupt request ([`crate::target::Target::interrupt`]),
    /// raised when the waiting Python thread gets a `KeyboardInterrupt`, as
    /// the REPL's Ctrl+C does: waits, steps, and traces end early.
    interrupt: Arc<AtomicBool>,
    generation: Arc<AtomicU64>,
    thread: Shared<Option<JoinHandle<()>>>,
}

impl Actor {
    /// Spawn the owner thread and open the session on it with `open`,
    /// returning once it is open (or failed to open).
    pub fn spawn(open: impl FnOnce() -> CoreResult<Session> + Send + 'static) -> CoreResult<Actor> {
        let (jobs, inbox) = mpsc::channel::<Job>();
        let (opened, open_result) = mpsc::sync_channel(1);
        let thread = std::thread::Builder::new()
            .name("ntoseye-session".to_string())
            .spawn(move || {
                let mut session = match open() {
                    Ok(session) => {
                        let _ = opened.send(Ok((
                            Arc::clone(&session.target.interrupt),
                            session.target.generation_counter(),
                        )));
                        session
                    }
                    Err(error) => {
                        let _ = opened.send(Err(error));
                        return;
                    }
                };
                loop {
                    match inbox.recv_timeout(SERVICE_TICK) {
                        Ok(job) => job(&mut session),
                        Err(RecvTimeoutError::Timeout) => session.service_idle(),
                        Err(RecvTimeoutError::Disconnected) => break,
                    }
                }
            })?;
        match open_result.recv() {
            Ok(Ok((interrupt, generation))) => Ok(Actor {
                jobs: Shared::new(Some(jobs)),
                interrupt,
                generation,
                thread: Shared::new(Some(thread)),
            }),
            Ok(Err(error)) => {
                let _ = thread.join();
                Err(error)
            }
            Err(_) => {
                let _ = thread.join();
                Err(Error::DebugInfo(
                    "debugger session thread exited while opening".into(),
                ))
            }
        }
    }

    /// Run `f` on the owner thread and wait for its result with the GIL
    /// released, so other Python threads run meanwhile. A `KeyboardInterrupt`
    /// while waiting raises the session's interrupt request, lets the job end,
    /// and is then raised in place of its result.
    fn run<R: Send>(&self, f: impl FnOnce(&mut Session) -> PyResult<R> + Send) -> PyResult<R> {
        let (reply, result) = mpsc::sync_channel::<PyResult<R>>(1);
        let job: Box<dyn FnOnce(&mut Session) + Send + '_> = Box::new(move |session| {
            let _ = reply.send(f(session));
        });
        // SAFETY: the job borrows from this stack frame, and this function
        // does not return until the job has run or been dropped: `result`
        // yields once the job sends, or errors once its `reply` sender is
        // dropped (the job discarded unrun, or unwound by a panic). A job the
        // channel refuses comes back in the error and is dropped here.
        let job: Job = unsafe { std::mem::transmute(job) };
        {
            let jobs = self.jobs.lock();
            let sender = jobs
                .as_ref()
                .ok_or_else(|| raise("the debugger is closed"))?;
            if sender.send(job).is_err() {
                return Err(raise("debugger session thread has exited"));
            }
        }
        Python::attach(|py| self.wait(py, result))
    }

    fn wait<R: Send>(&self, py: Python<'_>, mut result: Receiver<PyResult<R>>) -> PyResult<R> {
        let mut signal = None;
        loop {
            let received;
            (result, received) = py.detach(move || {
                let received = result.recv_timeout(SIGNAL_POLL);
                (result, received)
            });
            match received {
                Ok(value) => {
                    return match signal {
                        Some(error) => {
                            self.interrupt.store(false, Ordering::SeqCst);
                            Err(error)
                        }
                        None => value,
                    };
                }
                Err(RecvTimeoutError::Timeout) => {
                    if signal.is_none()
                        && let Err(error) = py.check_signals()
                    {
                        self.interrupt.store(true, Ordering::SeqCst);
                        signal = Some(error);
                    }
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(raise("debugger session thread dropped the request"));
                }
            }
        }
    }
}

impl Actor {
    /// Close the channel and wait for the owner thread, so the session (its
    /// transport and single-instance lock) is gone when this returns. Later
    /// calls raise. A no-op once closed.
    fn shutdown(&self) {
        drop(self.jobs.lock().take());
        // Join without holding the GIL when there is one to release: the
        // owner thread may need it to finish (a job raising a Python error).
        let mut thread = self.thread.lock().take();
        let _ = Python::try_attach(|py| py.detach(|| thread.take().map(JoinHandle::join)));
        if let Some(thread) = thread {
            let _ = thread.join();
        }
    }
}

impl Drop for Actor {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl Debugger {
    fn with_handle(inner: SessionHandle, generation: Arc<AtomicU64>) -> Self {
        Debugger {
            inner,
            repl_store: Shared::new(None),
            conditions: Shared::new(HashMap::new()),
            generation,
        }
    }

    /// A debugger whose session lives on `actor` (the `attach()` path).
    pub fn owned(actor: Actor) -> Self {
        let generation = Arc::clone(&actor.generation);
        Debugger::with_handle(SessionHandle::Owned(actor), generation)
    }

    /// A debugger borrowing the REPL's live `Session`. The caller must set
    /// `valid` false when the borrow ends; the handle (and anything derived
    /// from it) panics on use after that, and raises from any other thread.
    pub fn from_session_ref(session: &mut Session, valid: Arc<AtomicBool>) -> Self {
        let generation = session.target.generation_counter();
        Debugger::with_handle(
            SessionHandle::Borrowed {
                ptr: NonNull::from(session),
                valid,
                thread: std::thread::current().id(),
                busy: AtomicBool::new(false),
            },
            generation,
        )
    }

    /// Whether this debugger owns its session (and so cleans it up on close).
    pub fn is_owned(&self) -> bool {
        matches!(self.inner, SessionHandle::Owned(_))
    }

    /// Whether [`Self::shutdown`] ended this debugger's session.
    pub fn is_closed(&self) -> bool {
        match &self.inner {
            SessionHandle::Owned(actor) => actor.jobs.lock().is_none(),
            SessionHandle::Borrowed { .. } => false,
        }
    }

    /// End an owned session now rather than when the debugger is collected:
    /// its transport and single-instance lock are released, and every later
    /// call raises. A borrowed session belongs to the REPL and is left alone.
    pub fn shutdown(&self) {
        if let SessionHandle::Owned(actor) = &self.inner {
            actor.shutdown();
        }
    }

    /// Run `f` against the session: on the owner thread with the GIL released,
    /// or inline on the REPL's thread for a borrowed session. The one path to
    /// the session; `f` must not call back into Python.
    pub fn with_session<R: Send>(
        &self,
        f: impl FnOnce(&mut Session) -> PyResult<R> + Send,
    ) -> PyResult<R> {
        match &self.inner {
            SessionHandle::Owned(actor) => actor.run(f),
            SessionHandle::Borrowed {
                ptr,
                valid,
                thread,
                busy,
            } => {
                assert!(valid.load(Ordering::Acquire), "{STALE_BORROW}");
                if std::thread::current().id() != *thread {
                    return Err(raise(
                        "a REPL command's debugger can only be used on the REPL's thread",
                    ));
                }
                if busy.swap(true, Ordering::Acquire) {
                    return Err(raise("re-entrant debugger session access"));
                }
                struct Release<'a>(&'a AtomicBool);
                impl Drop for Release<'_> {
                    fn drop(&mut self) {
                        self.0.store(false, Ordering::Release);
                    }
                }
                let _release = Release(busy);
                // SAFETY: `valid` says the REPL's borrow is live, we are on its
                // thread, and `busy` makes this the only reference.
                f(unsafe { &mut *ptr.as_ptr() })
            }
        }
    }

    /// The target's rebuild count; see [`crate::target::Target::generation`].
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }
}

/// Require a halted target before an operation that reads registers or
/// patches guest/backend state, raising `TargetRunningError` otherwise.
pub fn require_halted(session: &mut Session, operation: &str) -> PyResult<()> {
    // KD can leave is_running() stale-true while the VM is physically halted
    // (a caught-but-undrained stop); settle it first.
    session.settle_pending_stop().map_err(err)?;
    if !session.backend.is_running() {
        return Ok(());
    }
    Err(match halt_unreachable_reason(&*session.backend) {
        Some(reason) => error(
            ErrorKind::TargetRunning,
            format!("{operation} needs a halted target; {reason}"),
        ),
        None => error(
            ErrorKind::TargetRunning,
            format!("{operation} requires the VM to be halted; call interrupt() first"),
        ),
    })
}

/// How a handle reaches its debugger. A `stamped` owner remembers the target
/// generation it was minted in and raises `StaleHandleError` once the guest
/// has been rebuilt (addresses from the old kernel mean nothing now); an
/// unstamped one (namespaces like `dbg.memory`, which resolve their space on
/// every call) never goes stale.
pub struct Owner {
    dbg: Py<Debugger>,
    generation: Option<u64>,
}

impl Owner {
    /// An owner stamped with the current generation, for handles that carry
    /// guest addresses (processes, threads, modules, cursors, stops).
    pub fn stamped(py: Python<'_>, dbg: &Py<Debugger>) -> Self {
        Owner {
            dbg: dbg.clone_ref(py),
            generation: Some(dbg.get().generation()),
        }
    }

    /// An owner that never goes stale, for namespaces that resolve their
    /// address space on each call.
    pub fn unstamped(py: Python<'_>, dbg: &Py<Debugger>) -> Self {
        Owner {
            dbg: dbg.clone_ref(py),
            generation: None,
        }
    }

    pub fn clone_ref(&self, py: Python<'_>) -> Self {
        Owner {
            dbg: self.dbg.clone_ref(py),
            generation: self.generation,
        }
    }

    /// The debugger this handle belongs to.
    pub fn dbg(&self) -> &Py<Debugger> {
        &self.dbg
    }

    /// A stamped owner for a handle derived from this one: it inherits this
    /// owner's stamp, or takes the current generation when unstamped.
    pub fn derive(&self, py: Python<'_>) -> Self {
        match self.generation {
            Some(_) => self.clone_ref(py),
            None => Owner::stamped(py, &self.dbg),
        }
    }

    /// Raise `StaleHandleError` if the guest was rebuilt since this handle was
    /// minted. Reads the shared counter; no trip to the session.
    pub fn check(&self, _py: Python<'_>) -> PyResult<()> {
        stale_check(self.generation, self.dbg.get().generation())
    }

    /// Whether `other` belongs to the same debugger.
    pub fn same_debugger(&self, other: &Owner) -> bool {
        self.dbg.as_ptr() == other.dbg.as_ptr()
    }

    /// Accept this handle as an argument to a call on `dbg`: it must be that
    /// debugger's and current. `what` names it in the `ValueError`.
    pub fn require_argument_of(&self, py: Python<'_>, dbg: &Owner, what: &str) -> PyResult<()> {
        if !self.same_debugger(dbg) {
            return Err(PyValueError::new_err(format!(
                "{what} belongs to a different debugger"
            )));
        }
        self.check(py)
    }

    /// A `__hash__` for a handle identified by `key` within its debugger.
    /// It never touches the session, so a stale handle stays hashable (and
    /// removable from the set or dict holding it).
    pub fn identity_hash(&self, key: impl Hash) -> isize {
        let mut hasher = DefaultHasher::new();
        (self.dbg.as_ptr() as usize).hash(&mut hasher);
        key.hash(&mut hasher);
        hasher.finish() as isize
    }

    /// Run `f` against the session after the staleness check, both in one
    /// trip to the owner thread.
    pub fn with<R: Send>(
        &self,
        py: Python<'_>,
        f: impl FnOnce(&mut Session) -> PyResult<R> + Send,
    ) -> PyResult<R> {
        // Checked again on the session thread: a reload may land in between.
        self.check(py)?;
        let generation = self.generation;
        self.dbg.bind(py).get().with_session(move |session| {
            stale_check(generation, session.target.generation())?;
            f(session)
        })
    }

    /// Run `f` scoped to `ctx` after the staleness check.
    pub fn with_in<R: Send>(
        &self,
        py: Python<'_>,
        ctx: &Context,
        f: impl FnOnce(&mut Session) -> PyResult<R> + Send,
    ) -> PyResult<R> {
        self.with(py, |session| in_context(session, ctx, f))
    }
}

fn stale_check(minted: Option<u64>, current: u64) -> PyResult<()> {
    match minted {
        Some(minted) if minted != current => Err(error(
            ErrorKind::StaleHandle,
            "handle is from before the target was reloaded (a reboot); re-query it",
        )),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "must not be stashed")]
    fn invalidated_borrow_panics_instead_of_dereferencing() {
        let dbg = Debugger::with_handle(
            SessionHandle::Borrowed {
                ptr: NonNull::<Session>::dangling(),
                valid: Arc::new(AtomicBool::new(false)),
                thread: std::thread::current().id(),
                busy: AtomicBool::new(false),
            },
            Arc::new(AtomicU64::new(0)),
        );
        let _ = dbg.with_session(|_| Ok(()));
    }

    #[test]
    fn borrowed_session_refuses_other_threads() {
        let dbg = Debugger::with_handle(
            SessionHandle::Borrowed {
                ptr: NonNull::<Session>::dangling(),
                valid: Arc::new(AtomicBool::new(true)),
                thread: std::thread::current().id(),
                busy: AtomicBool::new(false),
            },
            Arc::new(AtomicU64::new(0)),
        );
        std::thread::scope(|scope| {
            let refused = scope
                .spawn(|| Python::attach(|_| dbg.with_session(|_| Ok(())).is_err()))
                .join()
                .unwrap();
            assert!(
                refused,
                "another thread reached the REPL's borrowed session"
            );
        });
    }
}
