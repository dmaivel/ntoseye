//! Hang diagnosis from the processor blocks (`!qlocks`, `!ipi`).

use super::Args;
use crate::error::Result;
use crate::view::{self, View};

pub(super) fn command(name: &str, args: &mut Args<'_, '_>) -> Option<Result<View>> {
    Some(match name {
        "!qlocks" | "qlocks" => args
            .target()
            .queued_locks()
            .map(|detail| view::hardware::queued_locks(&detail)),
        "!ipi" | "ipi" => args.opt_u16_value(0, "processor").and_then(|processor| {
            let detail = args.target().ipi_state(processor)?;
            Ok(view::hardware::ipi(&detail))
        }),
        _ => return None,
    })
}
