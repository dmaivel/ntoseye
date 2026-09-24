use crate::error::Result;
use crate::output;
use crate::session::{RunStatus, Session};

use super::{DispatchContext, Flow, RemoteClient, ReplState, ReplStore, StopWaitBudget};

/// Host-neutral result of one remote REPL dispatch. Rendering policy (MCP's
/// trailer/debug-output/JSON, or the SDK's exception conversion) stays with
/// the host.
pub struct RemoteCommandResult {
    pub ok: bool,
    pub text: String,
    pub status: RunStatus,
}

/// Run one line with persistent REPL state, shared by MCP and the Python SDK.
/// `custom_dispatch` lets a host answer a line itself (MCP's structured JSON
/// renderings) before the textual REPL command, reusing the lifecycle,
/// parked-stop handling, output capture, and run-status collection; `None`
/// falls through to the REPL.
pub fn run_remote_command<F>(
    session: &mut Session,
    store_slot: &mut Option<ReplStore>,
    client: RemoteClient,
    line: &str,
    budget: StopWaitBudget,
    custom_dispatch: F,
) -> RemoteCommandResult
where
    F: FnOnce(&mut ReplState<'_>, &str) -> Option<Result<Flow>>,
{
    let store = store_slot
        .take()
        .unwrap_or_else(|| ReplStore::new(session, DispatchContext::Remote(client)));
    let mut state = ReplState::attach(session, store);
    state.stop_wait = Some(budget);
    state.line = line.trim().to_string();

    let (flow, mut text) = output::capture(|| {
        let line = state.line.clone();
        if let Some(flow) = state.begin_remote_line(&line)? {
            return Ok(flow);
        }
        if let Some(flow) = custom_dispatch(&mut state, &line) {
            return flow;
        }
        state.dispatch_line(&line)
    });
    let ok = match flow {
        Ok(Flow::Continue | Flow::Quit) => true,
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

    let result = RemoteCommandResult { ok, text, status };
    *store_slot = Some(state.detach());
    result
}
