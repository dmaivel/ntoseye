//! Scheduler state: running threads, ready queues, DPCs, timers, APCs,
//! and stacks, plus `!apc` target resolution.

use super::Args;
use crate::error::{Error, Result};
use crate::target::sched::ApcSelector;
use crate::view::{self, View};

pub(super) fn command(name: &str, args: &mut Args<'_, '_>) -> Option<Result<View>> {
    let argv = args.argv;
    Some(match name {
        "!running" | "running" => {
            let include_idle = argv.contains(&"-i");
            let include_stacks = argv.contains(&"-t");
            args.state
                .ctx
                .inspect_running(include_idle, include_stacks)
                .map(|detail| view::sched::running(&detail))
        }
        "!ready" | "ready" => args.opt_u16_value(0, "processor").and_then(|processor| {
            let detail = args.target().inspect_ready_queues(processor)?;
            Ok(view::sched::ready_queues(&detail))
        }),
        "!dpcs" | "dpcs" => args
            .target()
            .inspect_dpc_queues()
            .map(|detail| view::sched::dpc_queues(&detail)),
        "!timer" | "timer" => match args.opt_addr(0) {
            Ok(Some(address)) => args
                .target()
                .inspect_timer(address)
                .map(|detail| view::sched::timer(&detail)),
            Ok(None) => args
                .target()
                .timer_list()
                .map(|detail| view::sched::timer_list(&detail)),
            Err(error) => Err(error),
        },
        "!apc" | "apc" => args.apc_selector().and_then(|selector| {
            let detail = args.state.ctx.inspect_apcs(selector)?;
            Ok(view::sched::apcs(&detail))
        }),
        "!stacks" | "stacks" => {
            let (level, filter) = match argv.first() {
                Some(&"0") | None => (0, argv.get(1..).map(|rest| rest.join(" "))),
                Some(&"1") => (1, argv.get(1..).map(|rest| rest.join(" "))),
                Some(&"2") => (2, argv.get(1..).map(|rest| rest.join(" "))),
                Some(_) => (0, Some(argv.join(" "))),
            };
            let filter = filter.filter(|text| !text.is_empty());
            args.state
                .ctx
                .inspect_stacks(level, filter.as_deref())
                .map(|detail| view::sched::stacks(&detail))
        }
        _ => return None,
    })
}

impl Args<'_, '_> {
    /// `!apc [.|*|<thread|process>]`, resolved like the REPL: threads first,
    /// then a pid/EPROCESS, then a process-name substring.
    fn apc_selector(&mut self) -> Result<ApcSelector> {
        let Some(text) = self.argv.first() else {
            return Ok(ApcSelector::CurrentThread);
        };
        match *text {
            "." => return Ok(ApcSelector::CurrentThread),
            "*" => return Ok(ApcSelector::All),
            _ => {}
        }
        if let Ok(value) = self.eval(text) {
            return Ok(ApcSelector::Number(value.0));
        }
        let processes = self.target().matching_processes(Some(text))?;
        match processes.as_slice() {
            [process] => Ok(ApcSelector::Process(process.pid)),
            [] => Err(Error::DebugInfo(format!("no process matches '{text}'"))),
            many => Err(Error::DebugInfo(format!(
                "ambiguous process '{text}': {} matches",
                many.len()
            ))),
        }
    }
}
