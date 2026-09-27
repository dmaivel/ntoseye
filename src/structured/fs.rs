//! File-system commands: control areas, VPBs, the file cache, and the
//! filter manager.

use super::Args;
use crate::error::Result;
use crate::view::{self, View};

pub(super) fn command(name: &str, args: &mut Args<'_, '_>) -> Option<Result<View>> {
    let argv = args.argv;
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
        "!fltkd.filters" => args
            .target()
            .flt_filters()
            .map(|detail| view::fs::flt_filters(&detail)),
        "!fltkd.instances" => args
            .target()
            .flt_instances(argv.first().copied(), |text| args.eval(text))
            .map(|detail| view::fs::flt_instances(&detail)),
        "!fltkd.volumes" => args
            .target()
            .flt_volumes()
            .map(|detail| view::fs::flt_volumes(&detail)),
        _ => return None,
    })
}
