//! ntoseye commands run for the client: `monitor` lines (`qRcmd`), and
//! the REPL state they share with the server's context changes.

use std::sync::Arc;

use crate::base::output;
use crate::hosts::repl::{
    DispatchContext, Flow, RemoteClient, ReplState, ReplStore, StopWaitBudget,
};

use super::Server;

impl Server<'_> {
    /// Run `edit` on the REPL state `monitor` commands share, kept between
    /// commands so aliases and caches persist and follow context changes.
    pub(super) fn in_repl<T>(&mut self, edit: impl FnOnce(&mut ReplState<'_>) -> T) -> T {
        let store = self.repl.take().unwrap_or_else(|| {
            ReplStore::new(self.session, DispatchContext::Remote(RemoteClient::Gdb))
        });
        let mut state = ReplState::attach(self.session, store);
        let result = edit(&mut state);
        self.repl = Some(state.detach());
        result
    }

    /// Run the command line `command` and return what it printed, its
    /// error included, ending in a newline.
    pub(super) fn monitor(&mut self, command: &[u8]) -> String {
        let line = String::from_utf8_lossy(command).trim().to_string();
        // Shutdown ends a command loop or `.sleep`.
        let budget = StopWaitBudget::unbounded(Arc::clone(&self.cancel));
        let (result, mut text) = self.in_repl(|state| {
            state.stop_wait = Some(budget);
            state.line = line.clone();
            output::capture(|| state.dispatch_line(&line))
        });
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
        text
    }
}
