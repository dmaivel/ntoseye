//! KMDF commands (`!wdfkd.*`): client drivers, handles, devices, queues, and
//! In-Flight Recorder logs.

use super::Args;
use crate::error::{Error, Result};
use crate::view::{self, View};

pub(super) fn command(name: &str, args: &mut Args<'_, '_>) -> Option<Result<View>> {
    Some(match name {
        "!wdfkd.wdfldr" => args
            .target()
            .wdf_loader()
            .map(|detail| view::wdf::loader(&detail).into_view()),
        "!wdfkd.wdfdriverinfo" => driver_name(args).and_then(|driver| {
            let detail = args.target().wdf_driver_info(driver)?;
            Ok(view::wdf::driver_info(&detail).into_view())
        }),
        "!wdfkd.wdfhandle" => args.value(0).and_then(|handle| {
            let detail = args.target().wdf_handle(handle)?;
            Ok(view::wdf::handle(&detail).into_view())
        }),
        "!wdfkd.wdfdevice" => args.value(0).and_then(|handle| {
            let detail = args.target().wdf_device(handle)?;
            Ok(view::wdf::device(&detail).into_view())
        }),
        "!wdfkd.wdfqueue" => args.value(0).and_then(|handle| {
            let detail = args.target().wdf_queue(handle)?;
            Ok(view::wdf::queue(&detail).into_view())
        }),
        "!wdfkd.wdflogdump" => driver_name(args).and_then(|driver| {
            let detail = args.target().wdf_log_dump(driver)?;
            Ok(view::wdf::log(&detail).into_view())
        }),
        _ => return None,
    })
}

fn driver_name<'s>(args: &Args<'s, '_>) -> Result<&'s str> {
    args.argv
        .first()
        .copied()
        .ok_or_else(|| Error::InvalidArgument("missing argument 1 (a KMDF driver name)".into()))
}
