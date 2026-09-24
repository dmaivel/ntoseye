//! Process and thread listings.

use super::Args;
use crate::error::Result;
use crate::view::{self, View};

pub(super) fn command(name: &str, args: &mut Args<'_, '_>) -> Option<Result<View>> {
    let argv = args.argv;
    Some(match name {
        "ps" => args
            .target()
            .matching_processes(argv.first().copied())
            .map(|processes| View::List(processes.iter().map(view::process::process).collect())),
        "!process" if argv.first().is_some_and(|arg| *arg == "0") => args
            .target()
            .matching_processes(argv.get(2).copied())
            .map(|processes| View::List(processes.iter().map(view::process::process).collect())),
        "threads" => args.state.ctx.windows_threads().map(|(threads, active)| {
            View::List(
                threads
                    .iter()
                    .map(|thread| {
                        view::process::thread(
                            thread,
                            active.get(&thread.ethread.0).map(String::as_str),
                        )
                    })
                    .collect(),
            )
        }),
        _ => return None,
    })
}
