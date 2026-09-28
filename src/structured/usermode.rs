//! User-mode process state: PEB, TEB, loader modules, last error, and
//! image integrity.

use super::Args;
use crate::error::{Error, Result};
use crate::view::{self, View};

pub(super) fn command(name: &str, args: &mut Args<'_, '_>) -> Option<Result<View>> {
    let argv = args.argv;
    Some(match name {
        "!peb" | "peb" => args.opt_addr(0).and_then(|address| {
            let detail = args.target().inspect_peb(address)?;
            Ok(view::usermode::peb(&detail).into_view())
        }),
        "!teb" | "teb" => args.opt_addr(0).and_then(|address| {
            let detail = args.target().inspect_teb(address)?;
            Ok(view::usermode::teb(&detail).into_view())
        }),
        "!dlls" | "dlls" => {
            let containing = match argv.iter().position(|arg| *arg == "-c") {
                Some(index) => match argv.get(index + 1) {
                    Some(text) => args.eval(text).map(Some),
                    None => Err(Error::DebugInfo("-c requires an address".into())),
                },
                None => Ok(None),
            };
            containing.and_then(|containing| {
                let detail = args.target().loader_modules(containing)?;
                Ok(view::usermode::loader_modules(&detail).into_view())
            })
        }
        "!gle" | "gle" => args
            .target()
            .last_error()
            .map(|detail| view::usermode::last_error(&detail).into_view()),
        "!chkimg" | "chkimg" => {
            let include_diffs = argv.contains(&"-d");
            match argv.iter().find(|arg| !arg.starts_with('-')) {
                Some(module) => args
                    .state
                    .ctx
                    .check_image(module, include_diffs)
                    .map(|detail| view::usermode::image_check(&detail).into_view()),
                None => Err(Error::DebugInfo("missing module name".into())),
            }
        }
        _ => return None,
    })
}
