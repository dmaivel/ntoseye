//! Module listings, type layouts, and symbol lookup.

use super::Args;
use crate::error::{Error, Result};
use crate::view::{self, View};

pub(super) fn command(name: &str, args: &mut Args<'_, '_>) -> Option<Result<View>> {
    let argv = args.argv;
    Some(match name {
        "lm" => {
            let kernel_only = argv.contains(&"k");
            let modules = if kernel_only {
                args.target().kernel_modules_with_versions()
            } else {
                args.target().modules_with_versions()
            };
            modules.map(|modules| View::List(modules.iter().map(view::module::module).collect()))
        }
        "dt" if argv.len() == 1 && !argv[0].starts_with('-') => {
            let target = args.target();
            let dtb = target.current_dtb();
            match target.symbols.find_type_across_modules(dtb, argv[0]) {
                Some(info) => Ok(view::symbols::type_layout(argv[0], &info)),
                None => Err(Error::DebugInfo(
                    target.symbols.unresolved_type_message(dtb, argv[0]),
                )),
            }
        }
        "ln" => args.addr(0).map(|address| {
            view::symbols::nearest_symbol(
                address,
                args.target().nearest_symbol_current_context(address),
            )
        }),
        "x" if !args.raw_tail.is_empty() => Ok(View::List(
            args.target()
                .search_symbols(args.raw_tail, 50)
                .iter()
                .map(view::symbols::symbol_search_match)
                .collect(),
        )),
        _ => return None,
    })
}
