//! `Debugger.command()`: one REPL line through the remote command runner
//! MCP shares, with the REPL state kept between calls.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use pyo3::prelude::*;

use super::handle::Debugger;
use super::{raise, timeout_arg};
use crate::repl::{RemoteClient, StopWaitBudget, run_remote_command};

/// Run `line`; a command that resumes the target waits up to `timeout`
/// seconds (`None`: until it stops) and its stop becomes `dbg.stop`. A
/// `KeyboardInterrupt` breaks in, as Ctrl+C does in the REPL.
pub fn command(dbg: &Bound<'_, Debugger>, line: &str, timeout: Option<f64>) -> PyResult<String> {
    let cancel = Arc::new(AtomicBool::new(false));
    let budget = match timeout_arg(timeout)? {
        Some(timeout) => StopWaitBudget::new(timeout, cancel),
        None => StopWaitBudget::unbounded(cancel),
    };
    let debugger = dbg.get();
    // Taken out for the call: a guard must not cross to the owner thread.
    let mut store = debugger.repl_store.lock().take();
    let output = debugger.with_session(|session| {
        Ok(run_remote_command(
            session,
            &mut store,
            RemoteClient::Sdk,
            line,
            budget,
            |_, _| None,
        ))
    });
    *debugger.repl_store.lock() = store;
    let output = output?;
    if output.ok {
        Ok(output.text)
    } else {
        Err(raise(output.text))
    }
}
