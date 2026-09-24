//! Target metadata and diagnosis: crash triage, Driver Verifier, version,
//! time, and error codes.

use super::Args;
use crate::error::Result;
use crate::target::meta::decode_error_code;
use crate::triage_report::TriageReport;
use crate::view::{self, View};

pub(super) fn command(name: &str, args: &mut Args<'_, '_>) -> Option<Result<View>> {
    let argv = args.argv;
    Some(match name {
        "!analyze" | "analyze" if !argv.iter().any(|arg| *arg == "-show" || *arg == "-hang") => {
            let report = TriageReport::build(args.state.ctx);
            Ok(view::triage::triage_report(&report, 64))
        }
        "!verifier" | "verifier" => match argv.first() {
            Some(module) => args
                .target()
                .verifier_driver(module)
                .map(|detail| view::meta::verifier_driver(&detail)),
            None => args
                .target()
                .verifier_status()
                .map(|detail| view::meta::verifier(&detail)),
        },
        "vertarget" | "version" => args
            .state
            .ctx
            .target_version()
            .map(|detail| view::meta::target_version(&detail)),
        ".time" => args
            .target()
            .target_time()
            .map(|detail| view::meta::target_time(&detail)),
        "!error" | "!ntstatus" => args
            .value(0)
            .map(|code| view::meta::error_code(&decode_error_code(code))),
        _ => return None,
    })
}
