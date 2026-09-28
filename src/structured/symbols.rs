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
            modules.map(|modules| View::list(modules.iter().map(view::module::module)))
        }
        "dt" if argv.len() == 1 && !argv[0].starts_with('-') => {
            let target = args.target();
            let dtb = target.current_dtb();
            match target.symbols.find_type_across_modules(dtb, argv[0]) {
                Some(info) => Ok(view::symbols::type_layout(argv[0], &info).into_view()),
                None => Err(Error::DebugInfo(
                    target.symbols.unresolved_type_message(dtb, argv[0]),
                )),
            }
        }
        "!dh" | "dh" => args
            .target()
            .inspect_image_headers(argv, |text| args.eval(text))
            .map(|detail| view::module::image_headers(&detail).into_view()),
        "!lmi" | "lmi" => match argv {
            [text] => args
                .target()
                .module_image_info(text, |text| args.eval(text))
                .map(|detail| view::module::module_image_info(args.target(), &detail).into_view()),
            _ => Err(Error::InvalidArgument(
                "!lmi takes one module name or address".into(),
            )),
        },
        "ln" => args.addr(0).map(|address| {
            args.target()
                .nearest_symbol_current_context(address)
                .map_or(View::Null, |(module, name, offset)| {
                    view::symbols::symbol(address, module, name, offset).into_view()
                })
        }),
        "x" if !args.raw_tail.is_empty() => Ok(View::list(
            args.target()
                .search_symbols(args.raw_tail, 50)
                .iter()
                .map(view::symbols::symbol_search_match),
        )),
        _ => return None,
    })
}
