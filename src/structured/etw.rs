//! ETW commands (`!wmitrace.*`): trace sessions, their buffers and events.

use super::Args;
use crate::error::{Error, Result};
use crate::target::etw::LogDumpArguments;
use crate::view::{self, View};

pub fn command(name: &str, args: &mut Args<'_, '_>) -> Option<Result<View>> {
    let argv = args.argv;
    let radix = args.state.radix;
    let missing = || Error::InvalidArgument("missing argument 1 (a logger id or name)".into());
    Some(match name.trim_start_matches('!') {
        "wmitrace.strdump" => match argv.first() {
            None => args
                .target()
                .etw_loggers()
                .map(|table| view::etw::logger_table(&table)),
            Some(logger) => args
                .target()
                .etw_logger_buffers(logger, radix)
                .map(|detail| view::etw::logger_buffers(&detail)),
        },
        "wmitrace.logger" => argv.first().ok_or_else(missing).and_then(|logger| {
            let logger = args.target().etw_logger(logger, radix)?;
            Ok(view::etw::logger(&logger))
        }),
        "wmitrace.logdump" => LogDumpArguments::parse(argv.iter().copied())
            .and_then(|arguments| arguments.ok_or_else(missing))
            .and_then(|arguments| {
                let dump =
                    args.target()
                        .etw_log_dump(&arguments.logger, radix, arguments.most_recent)?;
                Ok(view::etw::event_dump(&dump))
            }),
        _ => return None,
    })
}
