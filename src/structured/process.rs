//! Process and thread listings, job objects, global flags, and zombies.

use super::Args;
use crate::error::Result;
use crate::target::zombies::ZombieKinds;
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
        "!job" | "job" => (|| {
            let target = args.target();
            let job = target.job_address(args.opt_addr(0)?)?;
            Ok(view::process::job(&target.inspect_job(job)?))
        })(),
        "!zombies" | "zombies" => (|| {
            let kinds = ZombieKinds::from_flags(args.opt_value(0)?.unwrap_or(1))?;
            Ok(view::process::zombies(&args.target().zombies(kinds)?))
        })(),
        // Only the display form; a change falls through to the REPL command.
        "!gflag" | "gflag" if argv.is_empty() => args
            .target()
            .global_flags()
            .map(|detail| view::process::global_flags(&detail)),
        _ => return None,
    })
}
