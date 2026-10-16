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

/// Install detach handlers for SIGTERM, SIGHUP, and SIGINT, and return the
/// flag the server loop polls. `cancel` is raised too, so a blocking run
/// gives up promptly.
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
    flag
}
