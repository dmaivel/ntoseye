//! Termination signals for the protocol servers (DAP, GDB).
//!
//! A server owns a live target when a signal arrives: it must remove its
//! breakpoints and resume the guest before the process dies. The handler only
//! raises flags; the server loop notices them and detaches.

#[cfg(unix)]
use libc::{SIGHUP, SIGINT, SIGTERM, c_int, sighandler_t, signal as install_signal};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, OnceLock};

/// Raised by a termination signal, so the loop can release the target before
/// the process dies. The handler only stores into it, and [`install`] forces
/// initialization before installing the handler, so the store never
/// allocates.
static TERMINATION: LazyLock<Arc<AtomicBool>> = LazyLock::new(|| Arc::new(AtomicBool::new(false)));

/// The run-control cancel flag, published for [`note_termination`]. Its value
/// only exists once a session is being served, so it cannot be a `LazyLock`.
static RUN_CANCEL: OnceLock<Arc<AtomicBool>> = OnceLock::new();

/// Raise the shared flags from a signal handler. Signal-handler safe: two
/// atomic stores through already-initialized statics, no allocation, no locks.
#[cfg(unix)]
extern "C" fn note_termination(_signal: c_int) {
    TERMINATION.store(true, Ordering::SeqCst);
    // Also cancel any run control the loop is blocked inside, so it reaches
    // the flag instead of waiting for the target to stop on its own.
    if let Some(cancel) = RUN_CANCEL.get() {
        cancel.store(true, Ordering::SeqCst);
    }
}

/// Raise the shared flags from a console event: Ctrl+C, Ctrl+Break, a closed
/// console, or a logoff/shutdown. The system runs it on a thread of its own.
///
/// Windows ends the process as soon as a close, logoff, or shutdown handler
/// returns, so the handler holds those events: the server loop detaches and
/// the process exits from it, or Windows' timeout for the event ends the
/// process first. Ctrl+C and Ctrl+Break are handled at once and leave the
/// process to the loop.
#[cfg(windows)]
unsafe extern "system" fn console_handler(event: u32) -> i32 {
    use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, CTRL_C_EVENT};

    TERMINATION.store(true, Ordering::SeqCst);
    if let Some(cancel) = RUN_CANCEL.get() {
        cancel.store(true, Ordering::SeqCst);
    }
    if event != CTRL_C_EVENT && event != CTRL_BREAK_EVENT {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }
    1
}

/// Install detach handlers for SIGTERM, SIGHUP, and SIGINT — the console
/// events Ctrl+C, Ctrl+Break, close, and logoff/shutdown on Windows — and
/// return the flag the server loop polls. `cancel` is raised too, so a
/// blocking run gives up promptly.
pub fn install(cancel: &Arc<AtomicBool>) -> Arc<AtomicBool> {
    // Initialize before the handler can run: a store into an initialized
    // `LazyLock` is a plain atomic write.
    let flag = Arc::clone(&TERMINATION);
    let _ = RUN_CANCEL.set(Arc::clone(cancel));
    #[cfg(unix)]
    for signal in [SIGTERM, SIGHUP, SIGINT] {
        // SAFETY: the handler only performs atomic stores.
        unsafe {
            install_signal(signal, note_termination as *const () as sighandler_t);
        }
    }
    // SAFETY: the handler only stores atomics and sleeps.
    #[cfg(windows)]
    unsafe {
        windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(console_handler), 1);
    }
    flag
}
