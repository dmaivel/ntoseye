//! User-mode heap summaries, heap decoding, and block search.

use super::Args;
use crate::error::{Error, Result};
use crate::target::heap::HeapSelector;
use crate::types::VirtAddr;
use crate::view::{self, View};

pub(super) fn command(name: &str, args: &mut Args<'_, '_>) -> Option<Result<View>> {
    Some(match name {
        "!heap" | "heap" => args.heap(),
        _ => return None,
    })
}

impl Args<'_, '_> {
    /// `!heap [-s] | [-h|-a] <heap> | -x <address> | -p -a <address>`.
    fn heap(&self) -> Result<View> {
        let target = self.target();
        let argv = self.argv;
        if argv.is_empty() || argv == ["-s"] {
            return target
                .heap_summary()
                .map(|detail| view::heap::heap_summary(&detail));
        }
        if argv.first().is_some_and(|arg| *arg == "-x")
            || (argv.first().is_some_and(|arg| *arg == "-p")
                && argv.get(1).is_some_and(|arg| *arg == "-a"))
        {
            let text = argv
                .iter()
                .find(|arg| !arg.starts_with('-'))
                .ok_or_else(|| Error::DebugInfo("missing address".into()))?;
            let address = self.eval(text)?;
            return target
                .find_heap_block(address)
                .map(|detail| view::heap::heap_block_search(&detail));
        }
        let list_entries = argv.first().is_some_and(|arg| *arg == "-a");
        let text = argv
            .iter()
            .find(|arg| !arg.starts_with('-'))
            .ok_or_else(|| Error::DebugInfo("missing heap index or address".into()))?;
        let value = self.eval(text)?.0;
        let summary = target.heap_summary()?;
        let selector = if (value as usize) < summary.heaps.len() {
            HeapSelector::Index(value as usize)
        } else {
            HeapSelector::Address(VirtAddr(value))
        };
        target
            .inspect_heap(selector, list_entries)
            .map(|detail| view::heap::heap(&detail))
    }
}
