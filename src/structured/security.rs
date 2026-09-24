//! Security commands: tokens, security descriptors, ACLs, SIDs, and
//! logon sessions.

use super::Args;
use crate::error::Result;
use crate::view::{self, View};

pub(super) fn command(name: &str, args: &mut Args<'_, '_>) -> Option<Result<View>> {
    let argv = args.argv;
    Some(match name {
        "!token" => args
            .target()
            .inspect_process_token()
            .map(|token| view::security::token(&token)),
        "!sd" | "sd" => args.addr(0).and_then(|address| {
            let annotate = argv.get(1).is_some_and(|arg| *arg == "1");
            let detail = args
                .target()
                .inspect_security_descriptor(address, annotate)?;
            Ok(view::security::security_descriptor(&detail))
        }),
        "!acl" | "acl" => args.addr(0).and_then(|address| {
            let detail = args.target().inspect_acl(address)?;
            Ok(view::security::acl(&detail))
        }),
        "!sid" | "sid" => args.addr(0).and_then(|address| {
            let detail = args.target().inspect_sid(address)?;
            Ok(view::security::sid(&detail))
        }),
        "!objsd" | "objsd" => args.addr(0).and_then(|object| {
            let detail = args.target().inspect_object_security(object)?;
            Ok(view::security::object_security(&detail))
        }),
        "!session" | "session" => {
            let session = argv
                .iter()
                .position(|arg| *arg == "-s")
                .and_then(|index| argv.get(index + 1))
                .and_then(|text| text.parse::<i64>().ok());
            args.target()
                .sessions(session)
                .map(|detail| view::security::sessions(&detail))
        }
        "!sprocess" | "sprocess" => {
            let session = argv.first().and_then(|text| text.parse::<i64>().ok());
            let detailed = argv
                .get(1)
                .and_then(|text| args.eval(text).ok())
                .is_some_and(|flags| flags.0 != 0);
            args.target()
                .session_processes(session, detailed, argv.get(2).copied())
                .map(|detail| view::security::session_processes(&detail))
        }
        _ => return None,
    })
}
