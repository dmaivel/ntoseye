use crate::diagnostics;
use crate::output;
use crate::session::{RunStatus, Session};

use super::{DispatchContext, Flow, RemoteClient, ReplState, ReplStore, StopWaitBudget};

/// Host-neutral result of one remote REPL dispatch. Rendering policy (MCP's
/// trailer and debug output, or the SDK's exception conversion) stays with the
/// host.
pub struct RemoteCommandResult {
    pub ok: bool,
    /// A command on the line reported an error, though the line ran to its
    /// end or to that command. The SDK returns the text either way; MCP
    /// marks the result an error.
    pub reported_error: bool,
    pub text: String,
    pub status: RunStatus,
}

/// Run one line with persistent REPL state, shared by MCP and the Python SDK.
pub fn run_remote_command(
    session: &mut Session,
    store_slot: &mut Option<ReplStore>,
    client: RemoteClient,
    line: &str,
    budget: StopWaitBudget,
) -> RemoteCommandResult {
    let store = store_slot
        .take()
        .unwrap_or_else(|| ReplStore::new(session, DispatchContext::Remote(client)));
    let mut state = ReplState::attach(session, store);
    state.stop_wait = Some(budget);
    state.line = line.trim().to_string();

    let errors = diagnostics::errors_reported();
    let (flow, mut text) = output::capture(|| {
        let line = state.line.clone();
        if let Some(flow) = state.begin_remote_line(&line)? {
            return Ok(flow);
        }
        state.dispatch_line(&line)
    });
    let ok = match flow {
        Ok(Flow::Continue | Flow::Quit | Flow::Jump(_)) => true,
        Ok(Flow::Denied) => false,
        Err(error) => {
            text.push_str(&format!("error: {error}\n"));
            false
        }
    };

    let status = state.ctx.run_status();
    // run_status can ingest a stop that arrived at the end of dispatch. Surface
    // it in this result rather than deferring it to the next remote call.
    let (_, late) = output::capture(|| state.surface_parked_stop());
    text.push_str(&late);
    let reported_error = diagnostics::errors_reported() != errors;

    let result = RemoteCommandResult {
        ok,
        reported_error,
        text,
        status,
    };
    *store_slot = Some(state.detach());
    result
}
