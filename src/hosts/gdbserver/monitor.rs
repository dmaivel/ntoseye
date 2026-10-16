//! ntoseye commands run for the client: `monitor` lines.

use gdbstub::target::ext::monitor_cmd::{ConsoleOutput, MonitorCmd};

use std::sync::Arc;

use crate::base::output;
use crate::hosts::repl::{
    DispatchContext, Flow, RemoteClient, ReplState, ReplStore, StopWaitBudget,
};

use super::GdbTarget;

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
        // Shutdown ends a command loop or `.sleep`.
        state.stop_wait = Some(StopWaitBudget::unbounded(Arc::clone(&self.cancel)));
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
