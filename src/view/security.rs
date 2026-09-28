//! security: [`View`] builders for the structured inspectors.

use super::process::process;
use super::shape::{Diag, Hex, shapes};
use crate::types::VirtAddr;
use crate::target::security::{
    self, AceDetail, AclDetail, ObjectSecurityDetail, PrivilegeInfo, SecurityDescriptorDetail,
    SessionDetail, SessionProcessDetail, SessionProcessesDetail, SessionsDetail, SidDetail,
    TokenDetail,
};

shapes! {
    /// A decoded SID (`!sid`).
    Sid {
        address: VirtAddr,
        /// The canonical string form (`S-1-5-18`).
        sid: String,
        revision: u8,
        /// The identifier authority.
        authority: u64,
        sub_authorities: Vec<u32>,
        /// The built-in name, when it is a well-known SID.
        well_known: Option<String>,
    }

    /// An ACE in an ACL. The mask and SID read on their own, so a damaged
    /// body does not hide the header's type and flags.
    Ace {
        /// Its position in the ACL.
        index: usize,
        r#type: u8,
        type_name: String,
        /// The inheritance flags.
        flags: Hex<u8>,
        flag_names: String,
        access_mask: Diag<Hex<u32>>,
        sid: Diag<Sid>,
    }

    /// A decoded ACL header and its ACEs (`!acl`).
    Acl {
        address: VirtAddr,
        revision: u8,
        /// Bytes.
        size: u16,
        ace_count: u16,
        /// Whether `ace_count` exceeds the decoder's bound, so only the
        /// first ACEs are listed.
        bounded: bool,
        /// Whether `revision` is not one this decoder knows; `aces` is then
        /// empty.
        unknown_revision: bool,
        aces: Vec<Ace>,
    }

    /// A decoded absolute or self-relative security descriptor (`!sd`).
    SecurityDescriptor {
        address: VirtAddr,
        revision: Diag<u8>,
        /// `SECURITY_DESCRIPTOR.Control`.
        control: Diag<Hex<u16>>,
        /// The names of the control bits set.
        control_names: Diag<String>,
        /// Whether `control` has `SE_SELF_RELATIVE`.
        self_relative: Diag<bool>,
        /// The owner SID; its value is `None` for a null owner.
        owner: Diag<Option<Sid>>,
        /// The group SID; its value is `None` for a null group.
        group: Diag<Option<Sid>>,
        /// Its value is `None` when absent or a null (unrestricted) ACL.
        dacl: Diag<Option<Acl>>,
        /// Its value is `None` when absent or a null ACL.
        sacl: Diag<Option<Acl>>,
        /// Whether the revision is not 1.
        unsupported_revision: bool,
    }

    /// An object's security descriptor, from its header (`!objsd`).
    ObjectSecurity {
        object: VirtAddr,
        /// The `_OBJECT_HEADER`.
        header: VirtAddr,
        /// `SecurityDescriptor`, a fast reference (reference count in the
        /// low bits).
        fast_reference: Hex,
        /// `fast_reference` without its count bits.
        descriptor_address: VirtAddr,
        /// `None` when the object has no descriptor.
        descriptor: Option<SecurityDescriptor>,
    }

    /// A session and its processes.
    Session {
        /// `None` for processes whose session is unknown.
        id: Option<u64>,
        /// Each a process record.
        processes: Vec<super::process::ProcessIdentity>,
    }

    /// Sessions and their processes (`!session`).
    Sessions {
        /// The session requested; `None` when all were (or the selected
        /// process has no known id).
        selected_session: Option<u64>,
        sessions: Vec<Session>,
        process_count: usize,
        /// Whether the process walk stopped at its bound.
        truncated: bool,
    }

    /// A process and its session id.
    SessionProcess {
        /// The process record.
        process: super::process::ProcessIdentity,
        /// `None` when neither `_EPROCESS` nor the primary token yields one.
        session: Option<u64>,
    }

    /// The processes of a session, optionally matching an image glob
    /// (`!sprocess`).
    SessionProcesses {
        /// `None` for all sessions.
        selected_session: Option<u64>,
        /// Whether the detailed listing (`-f`) was requested.
        detailed: bool,
        image_glob: Option<String>,
        processes: Vec<SessionProcess>,
        process_count: usize,
        /// Whether the process walk stopped at its bound.
        truncated: bool,
    }

    /// A token SID and its `SE_GROUP_*` attributes.
    SidAndAttributes {
        sid: String,
        attributes: Hex<u32>,
    }

    /// A token privilege and its `SE_PRIVILEGE_*` attributes.
    TokenPrivilege {
        luid: Hex,
        attributes: Hex<u32>,
    }

    /// A process's primary token (`!token`).
    Token {
        /// The process record.
        process: super::process::ProcessIdentity,
        /// The `_TOKEN`.
        token: VirtAddr,
        token_id: Diag<Hex>,
        /// The logon session's LUID.
        authentication_id: Diag<Hex>,
        /// `TOKEN_TYPE`: 1 primary, 2 impersonation.
        token_type: Diag<u32>,
        /// `SECURITY_IMPERSONATION_LEVEL`.
        impersonation_level: Diag<u32>,
        /// `TokenFlags`.
        flags: Diag<Hex<u32>>,
        /// Its value is `None` when the token names no user.
        user: Diag<Option<SidAndAttributes>>,
        groups: Diag<Vec<SidAndAttributes>>,
        privileges: Diag<Vec<TokenPrivilege>>,
    }
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

fn session_process(detail: &SessionProcessDetail) -> SessionProcess {
    SessionProcess {
        process: process(&detail.process),
        session: detail.session,
    }
}

/// Render `!sprocess`.
pub fn session_processes(detail: &SessionProcessesDetail) -> SessionProcesses {
    SessionProcesses {
        selected_session: detail.selected_session,
        detailed: detail.detailed,
        image_glob: detail.image_glob.clone(),
        processes: detail.processes.iter().map(session_process).collect(),
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
        groups: token.groups.map(|groups| {
            groups.iter().map(sid_and_attributes).collect()
        }),
        privileges: token.privileges.map(|privileges| {
            privileges.iter().map(privilege).collect()
        }),
    }
}
