//! security: [`View`] builders for the structured inspectors.

use crate::target::DiagnosticValue;
use ntoseye_macros::record;

use super::process::process;
use crate::target::security::{
    self, AceDetail, AclDetail, ObjectSecurityDetail, PrivilegeInfo, SecurityDescriptorDetail,
    SessionDetail, SessionsDetail, SidDetail, TokenDetail,
};
use crate::types::VirtAddr;

/// A decoded SID (`!sid`).
#[record]
pub struct Sid {
    pub address: VirtAddr,
    /// The canonical string form (`S-1-5-18`).
    pub sid: String,
    pub revision: u8,
    /// The identifier authority.
    pub authority: u64,
    pub sub_authorities: Vec<u32>,
    /// The built-in name, if the SID is a well-known SID.
    pub well_known: Option<String>,
}

/// An ACE in an ACL. ntoseye reads the mask and the SID separately, so a
/// damaged body does not hide the type and flags of the header.
#[record]
pub struct Ace {
    /// The position of the ACE in the ACL.
    pub index: usize,
    pub r#type: u8,
    pub type_name: String,
    /// The inheritance flags.
    #[record(hex)]
    pub flags: u8,
    pub flag_names: String,
    #[record(hex)]
    pub access_mask: DiagnosticValue<u32>,
    pub sid: DiagnosticValue<Sid>,
}

/// A decoded ACL header and its ACEs (`!acl`).
#[record]
pub struct Acl {
    pub address: VirtAddr,
    pub revision: u8,
    /// The size in bytes.
    pub size: u16,
    pub ace_count: u16,
    /// Whether `ace_count` is more than the decoder limit, in which case
    /// `aces` contains only the first ACEs.
    pub bounded: bool,
    /// Whether the decoder does not recognize `revision`, in which case
    /// `aces` is empty.
    pub unknown_revision: bool,
    pub aces: Vec<Ace>,
}

/// A decoded absolute or self-relative security descriptor (`!sd`).
#[record]
pub struct SecurityDescriptor {
    pub address: VirtAddr,
    pub revision: DiagnosticValue<u8>,
    /// `SECURITY_DESCRIPTOR.Control`.
    #[record(hex)]
    pub control: DiagnosticValue<u16>,
    /// The names of the control bits that are set.
    pub control_names: DiagnosticValue<String>,
    /// Whether `control` has `SE_SELF_RELATIVE`.
    pub self_relative: DiagnosticValue<bool>,
    /// The owner SID. Its value is `None` for a null owner.
    pub owner: DiagnosticValue<Option<Sid>>,
    /// The group SID. Its value is `None` for a null group.
    pub group: DiagnosticValue<Option<Sid>>,
    /// Its value is `None` if the DACL is absent or is a null (unrestricted) ACL.
    pub dacl: DiagnosticValue<Option<Acl>>,
    /// Its value is `None` if the SACL is absent or is a null ACL.
    pub sacl: DiagnosticValue<Option<Acl>>,
    /// Whether the revision is not 1.
    pub unsupported_revision: bool,
}

/// The security descriptor of an object, from its header (`!objsd`).
#[record]
pub struct ObjectSecurity {
    pub object: VirtAddr,
    /// The `_OBJECT_HEADER`.
    pub header: VirtAddr,
    /// `SecurityDescriptor`, a fast reference whose low bits hold a
    /// reference count.
    #[record(hex)]
    pub fast_reference: u64,
    /// `fast_reference` without its count bits.
    pub descriptor_address: VirtAddr,
    /// `None` if the object has no descriptor.
    pub descriptor: Option<SecurityDescriptor>,
}

/// A session and its processes.
#[record]
pub struct Session {
    /// `None` for processes whose session is unknown.
    pub id: Option<u64>,
    /// The processes in the session.
    pub processes: Vec<super::process::ProcessIdentity>,
}

/// Sessions and their processes (`!session`).
#[record]
pub struct Sessions {
    /// The requested session. `None` if you requested all sessions, or if the
    /// selected process has no known ID.
    pub selected_session: Option<u64>,
    pub sessions: Vec<Session>,
    pub process_count: usize,
    /// Whether the process walk stopped at its limit.
    pub truncated: bool,
}

/// A token SID and its `SE_GROUP_*` attributes.
#[record]
pub struct SidAndAttributes {
    pub sid: String,
    #[record(hex)]
    pub attributes: u32,
}

/// A token privilege and its `SE_PRIVILEGE_*` attributes.
#[record]
pub struct TokenPrivilege {
    #[record(hex)]
    pub luid: u64,
    #[record(hex)]
    pub attributes: u32,
}

/// The primary token of a process (`!token`).
#[record]
pub struct Token {
    /// The process record.
    pub process: super::process::ProcessIdentity,
    /// The `_TOKEN`.
    pub token: VirtAddr,
    #[record(hex)]
    pub token_id: DiagnosticValue<u64>,
    /// The LUID of the logon session.
    #[record(hex)]
    pub authentication_id: DiagnosticValue<u64>,
    /// `TOKEN_TYPE`: 1 is primary, 2 is impersonation.
    pub token_type: DiagnosticValue<u32>,
    /// `SECURITY_IMPERSONATION_LEVEL`.
    pub impersonation_level: DiagnosticValue<u32>,
    /// `TokenFlags`.
    #[record(hex)]
    pub flags: DiagnosticValue<u32>,
    /// Its value is `None` if the token does not name a user.
    pub user: DiagnosticValue<Option<SidAndAttributes>>,
    pub groups: DiagnosticValue<Vec<SidAndAttributes>>,
    pub privileges: DiagnosticValue<Vec<TokenPrivilege>>,
}

/// Render `!sid`.
pub fn sid(detail: &SidDetail) -> Sid {
    Sid {
        address: detail.address,
        sid: detail.sid.clone(),
        revision: detail.revision,
        authority: detail.authority,
        sub_authorities: detail.sub_authorities.clone(),
        well_known: detail.well_known.clone(),
    }
}

fn ace(detail: &AceDetail) -> Ace {
    Ace {
        index: detail.index,
        r#type: detail.ace_type,
        type_name: detail.type_name.clone(),
        flags: detail.flags,
        flag_names: detail.flag_names.clone(),
        access_mask: detail.access_mask.map(|value| *value),
        sid: detail.sid.map(sid),
    }
}

/// Render `!acl`.
pub fn acl(detail: &AclDetail) -> Acl {
    Acl {
        address: detail.address,
        revision: detail.revision,
        size: detail.size,
        ace_count: detail.ace_count,
        bounded: detail.bounded,
        unknown_revision: detail.unknown_revision,
        aces: detail.aces.iter().map(ace).collect(),
    }
}

/// Render `!sd`.
pub fn security_descriptor(detail: &SecurityDescriptorDetail) -> SecurityDescriptor {
    SecurityDescriptor {
        address: detail.address,
        revision: detail.revision.clone(),
        control: detail.control.map(|value| *value),
        control_names: detail.control_names.map(String::clone),
        self_relative: detail.self_relative.clone(),
        owner: detail.owner.map(|value| value.as_ref().map(sid)),
        group: detail.group.map(|value| value.as_ref().map(sid)),
        dacl: detail.dacl.map(|value| value.as_ref().map(acl)),
        sacl: detail.sacl.map(|value| value.as_ref().map(acl)),
        unsupported_revision: detail.unsupported_revision,
    }
}

/// Render `!objsd`.
pub fn object_security(detail: &ObjectSecurityDetail) -> ObjectSecurity {
    ObjectSecurity {
        object: detail.object,
        header: detail.header,
        fast_reference: detail.fast_reference,
        descriptor_address: detail.descriptor_address,
        descriptor: detail.descriptor.as_ref().map(security_descriptor),
    }
}

fn session(detail: &SessionDetail) -> Session {
    Session {
        id: detail.id,
        processes: detail.processes.iter().map(process).collect(),
    }
}

/// Render `!session`.
pub fn sessions(detail: &SessionsDetail) -> Sessions {
    Sessions {
        selected_session: detail.selected_session,
        sessions: detail.sessions.iter().map(session).collect(),
        process_count: detail.process_count,
        truncated: detail.truncated,
    }
}

fn sid_and_attributes(sid: &security::SidAndAttributes) -> SidAndAttributes {
    SidAndAttributes {
        sid: sid.sid.clone(),
        attributes: sid.attributes,
    }
}

fn privilege(privilege: &PrivilegeInfo) -> TokenPrivilege {
    TokenPrivilege {
        luid: privilege.luid,
        attributes: privilege.attributes,
    }
}

/// Render `!token`: the current process's primary token.
pub fn token(token: &TokenDetail) -> Token {
    Token {
        process: process(&token.process),
        token: token.token,
        token_id: token.token_id.clone(),
        authentication_id: token.authentication_id.clone(),
        token_type: token.token_type.clone(),
        impersonation_level: token.impersonation_level.clone(),
        flags: token.flags.map(|value| *value),
        user: token.user.map(|user| user.as_ref().map(sid_and_attributes)),
        groups: token
            .groups
            .map(|groups| groups.iter().map(sid_and_attributes).collect()),
        privileges: token
            .privileges
            .map(|privileges| privileges.iter().map(privilege).collect()),
    }
}
