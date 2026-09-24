//! security: [`View`](super::View) builders for the structured inspectors.

use super::process::process;
use super::{View, diagnostic};
use crate::target::security::{
    AceDetail, AclDetail, ObjectSecurityDetail, PrivilegeInfo, SecurityDescriptorDetail,
    SessionDetail, SessionProcessDetail, SessionProcessesDetail, SessionsDetail, SidAndAttributes,
    SidDetail, TokenDetail,
};

/// Build a SID view; top-level keys are `address`, `sid`, `revision`,
/// `authority`, `sub_authorities`, and `well_known`.
pub fn sid(detail: &SidDetail) -> View {
    View::Object(vec![
        ("address", View::Hex(detail.address.0)),
        ("sid", View::Str(detail.sid.clone())),
        ("revision", View::Num(detail.revision.into())),
        ("authority", View::Num(detail.authority)),
        (
            "sub_authorities",
            View::List(
                detail
                    .sub_authorities
                    .iter()
                    .copied()
                    .map(u64::from)
                    .map(View::Num)
                    .collect(),
            ),
        ),
        ("well_known", View::OptStr(detail.well_known.clone())),
    ])
}

fn ace(detail: &AceDetail) -> View {
    View::Object(vec![
        ("index", View::Num(detail.index as u64)),
        ("type", View::Num(detail.ace_type.into())),
        ("type_name", View::Str(detail.type_name.clone())),
        ("flags", View::Hex(detail.flags.into())),
        ("flag_names", View::Str(detail.flag_names.clone())),
        (
            "access_mask",
            diagnostic(&detail.access_mask, |value| View::Hex((*value).into())),
        ),
        ("sid", diagnostic(&detail.sid, sid)),
    ])
}

/// Build an ACL view; top-level keys are `address`, `revision`, `size`,
/// `ace_count`, `bounded`, `unknown_revision`, and `aces`.
pub fn acl(detail: &AclDetail) -> View {
    View::Object(vec![
        ("address", View::Hex(detail.address.0)),
        ("revision", View::Num(detail.revision.into())),
        ("size", View::Num(detail.size.into())),
        ("ace_count", View::Num(detail.ace_count.into())),
        ("bounded", View::Bool(detail.bounded)),
        ("unknown_revision", View::Bool(detail.unknown_revision)),
        ("aces", View::List(detail.aces.iter().map(ace).collect())),
    ])
}

fn optional_sid(value: &Option<SidDetail>) -> View {
    value.as_ref().map_or(View::Null, sid)
}

fn optional_acl(value: &Option<AclDetail>) -> View {
    value.as_ref().map_or(View::Null, acl)
}

/// Build a security-descriptor view; top-level keys are `address`, `revision`,
/// `control`, `control_names`, `self_relative`, `owner`, `group`, `dacl`,
/// `sacl`, and `unsupported_revision`.
pub fn security_descriptor(detail: &SecurityDescriptorDetail) -> View {
    View::Object(vec![
        ("address", View::Hex(detail.address.0)),
        (
            "revision",
            diagnostic(&detail.revision, |value| View::Num((*value).into())),
        ),
        (
            "control",
            diagnostic(&detail.control, |value| View::Hex((*value).into())),
        ),
        (
            "control_names",
            diagnostic(&detail.control_names, |value| View::Str(value.clone())),
        ),
        (
            "self_relative",
            diagnostic(&detail.self_relative, |value| View::Bool(*value)),
        ),
        ("owner", diagnostic(&detail.owner, optional_sid)),
        ("group", diagnostic(&detail.group, optional_sid)),
        ("dacl", diagnostic(&detail.dacl, optional_acl)),
        ("sacl", diagnostic(&detail.sacl, optional_acl)),
        (
            "unsupported_revision",
            View::Bool(detail.unsupported_revision),
        ),
    ])
}

/// Build an object-security view; top-level keys are `object`, `header`,
/// `fast_reference`, `descriptor_address`, and `descriptor`.
pub fn object_security(detail: &ObjectSecurityDetail) -> View {
    View::Object(vec![
        ("object", View::Hex(detail.object.0)),
        ("header", View::Hex(detail.header.0)),
        ("fast_reference", View::Hex(detail.fast_reference)),
        ("descriptor_address", View::Hex(detail.descriptor_address.0)),
        (
            "descriptor",
            detail
                .descriptor
                .as_ref()
                .map_or(View::Null, security_descriptor),
        ),
    ])
}

fn session(detail: &SessionDetail) -> View {
    View::Object(vec![
        ("id", View::OptNum(detail.id)),
        (
            "processes",
            View::List(detail.processes.iter().map(process).collect()),
        ),
    ])
}

/// Build a sessions view; top-level keys are `selected_session`, `sessions`,
/// `process_count`, and `truncated`.
pub fn sessions(detail: &SessionsDetail) -> View {
    View::Object(vec![
        ("selected_session", View::OptNum(detail.selected_session)),
        (
            "sessions",
            View::List(detail.sessions.iter().map(session).collect()),
        ),
        ("process_count", View::Num(detail.process_count as u64)),
        ("truncated", View::Bool(detail.truncated)),
    ])
}

fn session_process(detail: &SessionProcessDetail) -> View {
    View::Object(vec![
        ("process", process(&detail.process)),
        ("session", View::OptNum(detail.session)),
    ])
}

/// Build a session-process view; top-level keys are `selected_session`,
/// `detailed`, `image_glob`, `processes`, `process_count`, and `truncated`.
pub fn session_processes(detail: &SessionProcessesDetail) -> View {
    View::Object(vec![
        ("selected_session", View::OptNum(detail.selected_session)),
        ("detailed", View::Bool(detail.detailed)),
        ("image_glob", View::OptStr(detail.image_glob.clone())),
        (
            "processes",
            View::List(detail.processes.iter().map(session_process).collect()),
        ),
        ("process_count", View::Num(detail.process_count as u64)),
        ("truncated", View::Bool(detail.truncated)),
    ])
}

fn sid_and_attributes(sid: &SidAndAttributes) -> View {
    View::Object(vec![
        ("sid", View::Str(sid.sid.clone())),
        ("attributes", View::Hex(sid.attributes.into())),
    ])
}

fn privilege(privilege: &PrivilegeInfo) -> View {
    View::Object(vec![
        ("luid", View::Hex(privilege.luid)),
        ("attributes", View::Hex(privilege.attributes.into())),
    ])
}

pub fn token(token: &TokenDetail) -> View {
    View::Object(vec![
        ("process", process(&token.process)),
        ("token", View::Hex(token.token.0)),
        (
            "token_id",
            diagnostic(&token.token_id, |value| View::Hex(*value)),
        ),
        (
            "authentication_id",
            diagnostic(&token.authentication_id, |value| View::Hex(*value)),
        ),
        (
            "token_type",
            diagnostic(&token.token_type, |value| View::Num((*value).into())),
        ),
        (
            "impersonation_level",
            diagnostic(&token.impersonation_level, |value| {
                View::Num((*value).into())
            }),
        ),
        (
            "flags",
            diagnostic(&token.flags, |value| View::Hex((*value).into())),
        ),
        (
            "user",
            diagnostic(&token.user, |user| {
                user.as_ref().map(sid_and_attributes).unwrap_or(View::Null)
            }),
        ),
        (
            "groups",
            diagnostic(&token.groups, |groups| {
                View::List(groups.iter().map(sid_and_attributes).collect())
            }),
        ),
        (
            "privileges",
            diagnostic(&token.privileges, |privileges| {
                View::List(privileges.iter().map(privilege).collect())
            }),
        ),
    ])
}
