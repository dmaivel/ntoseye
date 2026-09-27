//! File-system commands: control areas, VPBs, and the file cache.

use super::Args;
use crate::error::Result;
use crate::view::{self, View};

pub(super) fn command(name: &str, args: &mut Args<'_, '_>) -> Option<Result<View>> {
    Some(match name {
        "!ca" | "ca" => args.addr(0).and_then(|address| {
            let detail = args.target().inspect_control_area(address)?;
            Ok(view::fs::control_area(&detail))
        }),
        "!vpb" | "vpb" => args.addr(0).and_then(|address| {
            let detail = args.target().inspect_vpb(address)?;
            Ok(view::fs::vpb(&detail))
        }),
        "!filecache" | "filecache" => args
            .target()
            .file_cache()
            .map(|detail| view::fs::file_cache(&detail)),
        _ => return None,
    })
}
