//! ntoseye commands run for the client: `monitor` lines and the
//! `bp ... do "..."` actions set through them.

use gdbstub::target::ext::monitor_cmd::{ConsoleOutput, MonitorCmd};

use crate::output;
use crate::repl::{DispatchContext, Flow, RemoteClient, ReplState, ReplStore};

use super::GdbTarget;

impl GdbTarget<'_> {
    /// Run a `bp ... do "..."` action set through `monitor`. Returns whether
    /// it resumed the target (a trailing `gc`), in which case the stop is not
    /// reported.
    pub(super) fn run_breakpoint_action(&mut self, action: &str) -> bool {
        let store = ReplStore::new(self.session, DispatchContext::BreakpointAction);
        let mut state = ReplState::attach(self.session, store);
        state.line = action.to_string();
        let (result, text) = output::capture(|| state.dispatch_breakpoint_action(action));
        drop(state.detach());
        if !text.is_empty() {
            self.notes.push(text.trim_end().to_string());
        }
        match result {
            Ok(true) => match self.session.resume() {
                Ok(()) => true,
                Err(error) => {
                    self.note(format!(
                        "breakpoint action could not resume the target: {error}"
                    ));
                    false
                }
            },
            Ok(false) => false,
            Err(error) => {
                self.note(format!("breakpoint action failed: {error}"));
                false
            }
        }
    }
}

impl MonitorCmd for GdbTarget<'_> {
    fn handle_monitor_cmd(
        &mut self,
        cmd: &[u8],
        mut out: ConsoleOutput<'_>,
    ) -> std::result::Result<(), Self::Error> {
        let line = String::from_utf8_lossy(cmd).trim().to_string();
        let store = self.repl.take().unwrap_or_else(|| {
            ReplStore::new(self.session, DispatchContext::Remote(RemoteClient::Gdb))
        });
        let mut state = ReplState::attach(self.session, store);
        state.line = line.clone();
        let (result, mut text) = output::capture(|| state.dispatch_line(&line));
        self.repl = Some(state.detach());
        match result {
            Ok(Flow::Denied) if text.is_empty() => {
                text = "this command would move the target; use the client's controls\n".into();
            }
            Err(error) => text.push_str(&format!("{error}\n")),
            Ok(_) => {}
        }
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        out.write_raw(text.as_bytes());
        Ok(())
    }
}
