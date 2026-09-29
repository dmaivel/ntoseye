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
        /// The built-in name, if the SID is a well-known SID.
        well_known: Option<String>,
    }

    /// An ACE in an ACL. ntoseye reads the mask and the SID separately. So a
    /// damaged body does not hide the type and flags of the header.
    Ace {
        /// The position of the ACE in the ACL.
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
        /// The size in bytes.
        size: u16,
        ace_count: u16,
        /// Whether `ace_count` is more than the decoder limit. If true, `aces`
        /// contains only the first ACEs.
        bounded: bool,
        /// Whether the decoder does not recognize `revision`. If true, `aces` is
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
        /// The names of the control bits that are set.
        control_names: Diag<String>,
        /// Whether `control` has `SE_SELF_RELATIVE`.
        self_relative: Diag<bool>,
        /// The owner SID. Its value is `None` for a null owner.
        owner: Diag<Option<Sid>>,
        /// The group SID. Its value is `None` for a null group.
        group: Diag<Option<Sid>>,
        /// Its value is `None` if the DACL is absent or is a null (unrestricted) ACL.
        dacl: Diag<Option<Acl>>,
        /// Its value is `None` if the SACL is absent or is a null ACL.
        sacl: Diag<Option<Acl>>,
        /// Whether the revision is not 1.
        unsupported_revision: bool,
    }

    /// The security descriptor of an object, from its header (`!objsd`).
    ObjectSecurity {
        object: VirtAddr,
        /// The `_OBJECT_HEADER`.
        header: VirtAddr,
        /// `SecurityDescriptor`, a fast reference. The low bits hold a reference
        /// count.
        fast_reference: Hex,
        /// `fast_reference` without its count bits.
        descriptor_address: VirtAddr,
        /// `None` if the object has no descriptor.
        descriptor: Option<SecurityDescriptor>,
    }

    /// A session and its processes.
    Session {
        /// `None` for processes whose session is unknown.
        id: Option<u64>,
        /// The processes in the session.
        processes: Vec<super::process::ProcessIdentity>,
    }

    /// Sessions and their processes (`!session`).
    Sessions {
        /// The requested session. `None` if you requested all sessions, or if the
        /// selected process has no known ID.
        selected_session: Option<u64>,
        sessions: Vec<Session>,
        process_count: usize,
        /// Whether the process walk stopped at its limit.
        truncated: bool,
    }

    /// A process and its session ID.
    SessionProcess {
        /// The process record.
        process: super::process::ProcessIdentity,
        /// `None` if ntoseye cannot get the ID from `_EPROCESS` or from the primary
        /// token.
        session: Option<u64>,
    }

    /// The processes of a session, with an optional image glob filter
    /// (`!sprocess`).
    SessionProcesses {
        /// `None` for all sessions.
        selected_session: Option<u64>,
        /// Whether you requested the detailed list (`-f`).
        detailed: bool,
        image_glob: Option<String>,
        processes: Vec<SessionProcess>,
        process_count: usize,
        /// Whether the process walk stopped at its limit.
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

    /// The primary token of a process (`!token`).
    Token {
        /// The process record.
        process: super::process::ProcessIdentity,
        /// The `_TOKEN`.
        token: VirtAddr,
        token_id: Diag<Hex>,
        /// The LUID of the logon session.
        authentication_id: Diag<Hex>,
        /// `TOKEN_TYPE`. 1 is primary, 2 is impersonation.
        token_type: Diag<u32>,
        /// `SECURITY_IMPERSONATION_LEVEL`.
        impersonation_level: Diag<u32>,
        /// `TokenFlags`.
        flags: Diag<Hex<u32>>,
        /// Its value is `None` if the token does not name a user.
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
