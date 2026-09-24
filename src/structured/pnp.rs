//! Plug and Play device nodes, device stacks, and triage.

use super::Args;
use crate::error::Result;
use crate::view::{self, View};

pub(super) fn command(name: &str, args: &mut Args<'_, '_>) -> Option<Result<View>> {
    let argv = args.argv;
    Some(match name {
        "!devnode" | "devnode" => {
            let recurse = argv.iter().any(|arg| *arg == "-r" || *arg == "1");
            let node = argv
                .iter()
                .find(|arg| **arg != "-r" && **arg != "1")
                .map(|text| args.eval(text))
                .transpose();
            node.and_then(|node| {
                let node = node.filter(|address| !address.is_zero());
                let detail = args.target().inspect_devnode(node, recurse)?;
                Ok(view::pnp::devnode(&detail))
            })
        }
        "!devstack" | "devstack" => args.addr(0).and_then(|address| {
            let detail = args.target().inspect_device_stack(address)?;
            Ok(view::pnp::device_stack(&detail))
        }),
        "!pnptriage" | "pnptriage" => args
            .target()
            .pnp_triage()
            .map(|detail| view::pnp::pnp_triage(&detail)),
        _ => return None,
    })
}
