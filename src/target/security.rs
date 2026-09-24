//! security: structured inspector data (shared by the REPL, Python SDK, and MCP).

use std::collections::BTreeMap;

use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::guest::ProcessInfo;
use crate::layout::{StructRef, TypeInfo};
use crate::symbols::glob_matches;
use crate::target::{DiagnosticValue, Target, fast_ref_address};
use crate::types::VirtAddr;

const MAX_SESSION_PROCESSES: usize = 4096;

/// A process and its decoded session id (`None` when neither `_EPROCESS`
/// nor the primary token yields one).
type SessionProcessRow = (ProcessInfo, Option<u64>);
const MAX_ACE_COUNT: usize = 1024;
const SE_DACL_PRESENT: u16 = 0x0004;
const SE_SACL_PRESENT: u16 = 0x0010;
const SE_SELF_RELATIVE: u16 = 0x8000;

/// A decoded SID.  `sid` is the canonical string form used by WinDbg, and
/// `well_known` is populated for the built-in names recognized by this tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidDetail {
    pub address: VirtAddr,
    pub sid: String,
    pub revision: u8,
    pub authority: u64,
    pub sub_authorities: Vec<u32>,
    pub well_known: Option<String>,
}

/// One ACE in an ACL.  The mask and SID are independent reads so a damaged
/// ACE does not hide the type and inheritance flags that were decoded.
#[derive(Debug, Clone)]
pub struct AceDetail {
    pub index: usize,
    pub ace_type: u8,
    pub type_name: String,
    pub flags: u8,
    pub flag_names: String,
    /// The access mask read from the ACE body; unavailable when that body
    /// cannot be read independently of its header.
    pub access_mask: DiagnosticValue<u32>,
    /// The SID decoded from the ACE body; unavailable for a truncated or
    /// unreadable SID while the ACE header remains usable.
    pub sid: DiagnosticValue<SidDetail>,
}

/// A decoded ACL header and its bounded ACE list.
#[derive(Debug, Clone)]
pub struct AclDetail {
    pub address: VirtAddr,
    pub revision: u8,
    pub size: u16,
    pub ace_count: u16,
    pub aces: Vec<AceDetail>,
    pub bounded: bool,
    pub unknown_revision: bool,
}

/// A decoded absolute or self-relative security descriptor.
#[derive(Debug, Clone)]
pub struct SecurityDescriptorDetail {
    pub address: VirtAddr,
    /// The descriptor revision; unavailable when the Revision field cannot be
    /// read from the descriptor image.
    pub revision: DiagnosticValue<u8>,
    /// Raw SECURITY_DESCRIPTOR.Control; unavailable only when that field read
    /// fails, independently of owner/group and ACL reads.
    pub control: DiagnosticValue<u16>,
    /// Names corresponding to the raw control bits; unavailable with Control.
    pub control_names: DiagnosticValue<String>,
    /// Whether Control has SE_SELF_RELATIVE; unavailable with Control.
    pub self_relative: DiagnosticValue<bool>,
    /// Owner SID, or Available(None) for a null owner pointer.
    pub owner: DiagnosticValue<Option<SidDetail>>,
    /// Group SID, or Available(None) for a null group pointer.
    pub group: DiagnosticValue<Option<SidDetail>>,
    /// DACL, or Available(None) when it is absent or a null unrestricted ACL.
    pub dacl: DiagnosticValue<Option<AclDetail>>,
    /// SACL, or Available(None) when it is absent or a null unrestricted ACL.
    pub sacl: DiagnosticValue<Option<AclDetail>>,
    pub unsupported_revision: bool,
}

/// Security metadata read from an object header and its fast-reference.
#[derive(Debug, Clone)]
pub struct ObjectSecurityDetail {
    pub object: VirtAddr,
    pub header: VirtAddr,
    pub fast_reference: u64,
    pub descriptor_address: VirtAddr,
    pub descriptor: Option<SecurityDescriptorDetail>,
}

/// One session group returned by [`Target::sessions`].
#[derive(Debug, Clone)]
pub struct SessionDetail {
    pub id: Option<u64>,
    pub processes: Vec<ProcessInfo>,
}

/// Sessions and their processes.  `selected_session` is `None` when all
/// sessions were requested (or when the selected process has no known ID).
#[derive(Debug, Clone)]
pub struct SessionsDetail {
    pub selected_session: Option<u64>,
    pub sessions: Vec<SessionDetail>,
    pub process_count: usize,
    pub truncated: bool,
}

/// A process row carrying the session ID used by `!sprocess -f` output.
#[derive(Debug, Clone)]
pub struct SessionProcessDetail {
    pub process: ProcessInfo,
    pub session: Option<u64>,
}

/// Processes selected by a session and optional image glob.
#[derive(Debug, Clone)]
pub struct SessionProcessesDetail {
    pub selected_session: Option<u64>,
    pub detailed: bool,
    pub image_glob: Option<String>,
    pub processes: Vec<SessionProcessDetail>,
    pub process_count: usize,
    pub truncated: bool,
}

fn diagnostic<T>(result: Result<T>) -> DiagnosticValue<T> {
    match result {
        Ok(value) => DiagnosticValue::Available(value),
        Err(error) => DiagnosticValue::Unavailable(error.to_string()),
    }
}

fn sid_name(text: &str) -> Option<&'static str> {
    const NAMES: &[(&str, &str)] = &[
        ("S-1-0-0", "SECURITY_NULL_SID"),
        ("S-1-1-0", "Everyone"),
        ("S-1-2-0", "LOCAL"),
        ("S-1-3-0", "CREATOR_OWNER"),
        ("S-1-3-1", "CREATOR_GROUP"),
        ("S-1-5-7", "ANONYMOUS LOGON"),
        ("S-1-5-11", "Authenticated Users"),
        ("S-1-5-18", "LOCAL SYSTEM"),
        ("S-1-5-19", "LOCAL SERVICE"),
        ("S-1-5-20", "NETWORK SERVICE"),
        ("S-1-5-32", "BUILTIN"),
        ("S-1-5-32-544", "Administrators"),
        ("S-1-5-32-545", "Users"),
        ("S-1-5-32-546", "Guests"),
        ("S-1-5-32-547", "Power Users"),
        ("S-1-5-32-548", "Account Operators"),
        ("S-1-5-32-549", "Server Operators"),
        ("S-1-5-32-550", "Print Operators"),
        ("S-1-5-32-551", "Backup Operators"),
        ("S-1-5-32-552", "Replicator"),
        ("S-1-5-32-554", "Pre-Windows 2000 Compatible Access"),
        ("S-1-5-32-555", "Remote Desktop Users"),
        ("S-1-5-32-556", "Network Configuration Operators"),
        ("S-1-5-32-557", "Incoming Forest Trust Builders"),
        ("S-1-5-32-558", "Performance Monitor Users"),
        ("S-1-5-32-559", "Performance Log Users"),
        ("S-1-5-32-560", "Windows Authorization Access Group"),
        ("S-1-5-32-561", "Terminal Server License Servers"),
        ("S-1-5-32-562", "Distributed COM Users"),
        ("S-1-5-32-568", "IIS_IUSRS"),
        ("S-1-5-32-569", "Cryptographic Operators"),
        ("S-1-5-32-573", "Event Log Readers"),
        ("S-1-5-32-574", "Certificate Service DCOM Access"),
        ("S-1-5-32-575", "RDS Remote Access Servers"),
        ("S-1-5-32-576", "RDS Endpoint Servers"),
        ("S-1-5-32-577", "RDS Management Servers"),
        ("S-1-5-32-578", "Hyper-V Administrators"),
        ("S-1-5-32-579", "Access Control Assistance Operators"),
        ("S-1-5-32-580", "Remote Management Users"),
    ];
    NAMES
        .iter()
        .find(|(sid, _)| *sid == text)
        .map(|(_, name)| *name)
}

fn read_sid_bounded<M: MemoryOps<VirtAddr>>(
    memory: &M,
    address: VirtAddr,
    max_len: usize,
    annotate_well_known: bool,
) -> Result<SidDetail> {
    if max_len < 8 {
        return Err(Error::DebugInfo(format!(
            "SID at {:#x} has only {max_len} bytes available",
            address.0
        )));
    }
    let mut header = [0u8; 8];
    memory.read_bytes(address, &mut header)?;
    let revision = header[0];
    let count = usize::from(header[1]);
    if revision != 1 || count > 15 {
        return Err(Error::DebugInfo(format!(
            "invalid SID header at {:#x} (revision {}, sub-authorities {})",
            address.0, revision, count
        )));
    }
    let sid_len = 8usize + count * 4;
    if sid_len > max_len {
        return Err(Error::DebugInfo(format!(
            "SID at {:#x} requires {sid_len} bytes, only {max_len} are available",
            address.0
        )));
    }
    let authority = header[2..8]
        .iter()
        .fold(0u64, |value, byte| (value << 8) | u64::from(*byte));
    let mut sid = format!("S-{revision}-{authority}");
    let mut sub_authorities = Vec::with_capacity(count);
    for index in 0..count {
        let value: u32 = memory.read(address + 8u64 + (index as u64) * 4)?;
        sub_authorities.push(value);
        sid.push('-');
        sid.push_str(&value.to_string());
    }
    let well_known = annotate_well_known
        .then(|| sid_name(&sid).map(str::to_string))
        .flatten();
    Ok(SidDetail {
        address,
        sid,
        revision,
        authority,
        sub_authorities,
        well_known,
    })
}

fn ace_type_name(kind: u8) -> &'static str {
    match kind {
        0 => "ACCESS_ALLOWED",
        1 => "ACCESS_DENIED",
        2 => "SYSTEM_AUDIT",
        3 => "SYSTEM_ALARM",
        4 => "ACCESS_ALLOWED_COMPOUND",
        5 => "ACCESS_ALLOWED_OBJECT",
        6 => "ACCESS_DENIED_OBJECT",
        7 => "SYSTEM_AUDIT_OBJECT",
        8 => "SYSTEM_ALARM_OBJECT",
        9 => "ACCESS_ALLOWED_CALLBACK",
        10 => "ACCESS_DENIED_CALLBACK",
        11 => "ACCESS_ALLOWED_CALLBACK_OBJECT",
        12 => "ACCESS_DENIED_CALLBACK_OBJECT",
        13 => "SYSTEM_AUDIT_CALLBACK",
        14 => "SYSTEM_ALARM_CALLBACK",
        15 => "SYSTEM_AUDIT_CALLBACK_OBJECT",
        16 => "SYSTEM_ALARM_CALLBACK_OBJECT",
        17 => "SYSTEM_MANDATORY_LABEL",
        18 => "SYSTEM_RESOURCE_ATTRIBUTE",
        19 => "SYSTEM_SCOPED_POLICY_ID",
        20 => "SYSTEM_PROCESS_TRUST_LABEL",
        21 => "SYSTEM_ACCESS_FILTER",
        _ => "UNKNOWN",
    }
}

fn ace_flags(flags: u8) -> String {
    const FLAGS: &[(u8, &str)] = &[
        (0x01, "OBJECT_INHERIT"),
        (0x02, "CONTAINER_INHERIT"),
        (0x04, "NO_PROPAGATE_INHERIT"),
        (0x08, "INHERIT_ONLY"),
        (0x10, "INHERITED"),
        (0x40, "SUCCESSFUL_ACCESS"),
        (0x80, "FAILED_ACCESS"),
    ];
    let names: Vec<_> = FLAGS
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, name)| *name)
        .collect();
    if names.is_empty() {
        "-".to_string()
    } else {
        names.join("|")
    }
}

fn object_ace(kind: u8) -> bool {
    matches!(kind, 5 | 6 | 7 | 8 | 11 | 12 | 15 | 16)
}

fn ace_minimum_size(kind: u8) -> usize {
    if kind == 4 || object_ace(kind) { 12 } else { 8 }
}

fn decode_acl<M: MemoryOps<VirtAddr>>(
    memory: &M,
    address: VirtAddr,
    annotate_well_known: bool,
) -> Result<AclDetail> {
    let mut header = [0u8; 8];
    memory.read_bytes(address, &mut header)?;
    let revision = header[0];
    let size = u16::from_le_bytes([header[2], header[3]]);
    let ace_count = u16::from_le_bytes([header[4], header[5]]);
    if usize::from(size) < 8 {
        return Err(Error::DebugInfo(format!("invalid ACL size {size:#x}")));
    }
    if !matches!(revision, 2 | 4) {
        return Ok(AclDetail {
            address,
            revision,
            size,
            ace_count,
            aces: Vec::new(),
            bounded: false,
            unknown_revision: true,
        });
    }

    let mut offset = 8usize;
    let mut aces = Vec::new();
    for index in 0..usize::from(ace_count).min(MAX_ACE_COUNT) {
        if offset
            .checked_add(4)
            .is_none_or(|end| end > usize::from(size))
        {
            break;
        }
        let ace_address = address + offset as u64;
        let mut ace_header = [0u8; 4];
        if let Err(error) = memory.read_bytes(ace_address, &mut ace_header) {
            let error = error.to_string();
            aces.push(AceDetail {
                index,
                ace_type: 0xff,
                type_name: ace_type_name(0xff).to_string(),
                flags: 0,
                flag_names: ace_flags(0),
                access_mask: DiagnosticValue::Unavailable(error.clone()),
                sid: DiagnosticValue::Unavailable(error),
            });
            break;
        }
        let kind = ace_header[0];
        let flags = ace_header[1];
        let ace_size = usize::from(u16::from_le_bytes([ace_header[2], ace_header[3]]));
        let minimum_size = ace_minimum_size(kind);
        if ace_size < minimum_size
            || offset
                .checked_add(ace_size)
                .is_none_or(|end| end > usize::from(size))
        {
            return Err(Error::DebugInfo(format!(
                "invalid ACE size {ace_size:#x} at ACL offset {offset:#x} (minimum {minimum_size:#x})"
            )));
        }
        let access_mask = diagnostic(memory.read::<u32>(ace_address + 4u64));
        let sid_offset = if kind == 4 {
            12usize
        } else if object_ace(kind) {
            let object_flags = match memory.read::<u32>(ace_address + 8u64) {
                Ok(value) => value,
                Err(error) => {
                    aces.push(AceDetail {
                        index,
                        ace_type: kind,
                        type_name: ace_type_name(kind).to_string(),
                        flags,
                        flag_names: ace_flags(flags),
                        access_mask,
                        sid: DiagnosticValue::Unavailable(error.to_string()),
                    });
                    offset += ace_size;
                    continue;
                }
            };
            12usize
                .saturating_add(if object_flags & 1 != 0 { 16 } else { 0 })
                .saturating_add(if object_flags & 2 != 0 { 16 } else { 0 })
        } else {
            8usize
        };
        let sid = if sid_offset <= ace_size {
            diagnostic(read_sid_bounded(
                memory,
                ace_address + sid_offset as u64,
                ace_size - sid_offset,
                annotate_well_known,
            ))
        } else {
            DiagnosticValue::Unavailable(format!(
                "ACE SID offset {sid_offset:#x} exceeds ACE size {ace_size:#x}"
            ))
        };
        aces.push(AceDetail {
            index,
            ace_type: kind,
            type_name: ace_type_name(kind).to_string(),
            flags,
            flag_names: ace_flags(flags),
            access_mask,
            sid,
        });
        offset += ace_size;
    }
    Ok(AclDetail {
        address,
        revision,
        size,
        ace_count,
        aces,
        bounded: usize::from(ace_count) > MAX_ACE_COUNT,
        unknown_revision: false,
    })
}

fn control_flags(control: u16) -> String {
    const FLAGS: &[(u16, &str)] = &[
        (0x0001, "SE_OWNER_DEFAULTED"),
        (0x0002, "SE_GROUP_DEFAULTED"),
        (SE_DACL_PRESENT, "SE_DACL_PRESENT"),
        (0x0008, "SE_DACL_DEFAULTED"),
        (SE_SACL_PRESENT, "SE_SACL_PRESENT"),
        (0x0020, "SE_SACL_DEFAULTED"),
        (0x0040, "SE_DACL_TRUSTED"),
        (0x0080, "SE_SERVER_SECURITY"),
        (0x0100, "SE_DACL_AUTO_INHERIT_REQ"),
        (0x0200, "SE_SACL_AUTO_INHERIT_REQ"),
        (0x0400, "SE_DACL_AUTO_INHERITED"),
        (0x0800, "SE_SACL_AUTO_INHERITED"),
        (0x1000, "SE_DACL_PROTECTED"),
        (0x2000, "SE_SACL_PROTECTED"),
        (0x4000, "SE_RM_CONTROL_VALID"),
        (SE_SELF_RELATIVE, "SE_SELF_RELATIVE"),
    ];
    let names: Vec<_> = FLAGS
        .iter()
        .filter(|(bit, _)| control & bit != 0)
        .map(|(_, name)| *name)
        .collect();
    if names.is_empty() {
        "-".to_string()
    } else {
        names.join("|")
    }
}

fn descriptor_component(raw: u64, base: VirtAddr, self_relative: bool) -> Option<VirtAddr> {
    if raw == 0 {
        None
    } else if self_relative {
        Some(base + (raw as u32 as u64))
    } else {
        Some(VirtAddr(raw))
    }
}

fn descriptor_field(
    descriptor: &StructRef<'_>,
    relative: Option<&StructRef<'_>>,
    relative_error: Option<&str>,
    field_name: &str,
) -> Result<u64> {
    if let Some(error) = relative_error {
        Err(Error::DebugInfo(format!(
            "_SECURITY_DESCRIPTOR_RELATIVE unavailable: {error}"
        )))
    } else if let Some(relative) = relative {
        relative.read_field::<u32>(field_name).map(u64::from)
    } else {
        descriptor
            .read_field::<VirtAddr>(field_name)
            .map(|value| value.0)
    }
}

fn sid_component<M: MemoryOps<VirtAddr>>(
    memory: &M,
    raw: Result<u64>,
    base: VirtAddr,
    self_relative: bool,
    annotate_well_known: bool,
) -> DiagnosticValue<Option<SidDetail>> {
    match raw {
        Err(error) => DiagnosticValue::Unavailable(error.to_string()),
        Ok(raw) => match descriptor_component(raw, base, self_relative) {
            None => DiagnosticValue::Available(None),
            Some(address) => {
                match read_sid_bounded(memory, address, usize::MAX, annotate_well_known) {
                    Ok(sid) => DiagnosticValue::Available(Some(sid)),
                    Err(error) => {
                        DiagnosticValue::Unavailable(format!("{:#x}: {error}", address.0))
                    }
                }
            }
        },
    }
}

fn acl_component<M: MemoryOps<VirtAddr>>(
    memory: &M,
    raw: Result<u64>,
    base: VirtAddr,
    self_relative: bool,
    annotate_well_known: bool,
) -> DiagnosticValue<Option<AclDetail>> {
    match raw {
        Err(error) => DiagnosticValue::Unavailable(error.to_string()),
        Ok(raw) => match descriptor_component(raw, base, self_relative) {
            None => DiagnosticValue::Available(None),
            Some(address) => match decode_acl(memory, address, annotate_well_known) {
                Ok(acl) => DiagnosticValue::Available(Some(acl)),
                Err(error) => DiagnosticValue::Unavailable(format!("{:#x}: {error}", address.0)),
            },
        },
    }
}

impl Target {
    fn inspect_security_descriptor_in<M: MemoryOps<VirtAddr>>(
        &self,
        memory: &M,
        address: VirtAddr,
        annotate_well_known: bool,
    ) -> Result<SecurityDescriptorDetail> {
        let types = self.guest()?.ntoskrnl.types_in(self.kernel_dtb());
        let descriptor = types.struct_at("_SECURITY_DESCRIPTOR", address)?;
        let revision = diagnostic(descriptor.read_field::<u8>("Revision"));
        let control = diagnostic(descriptor.read_field::<u16>("Control"));
        let control_names = match &control {
            DiagnosticValue::Available(value) => DiagnosticValue::Available(control_flags(*value)),
            DiagnosticValue::Unavailable(error) => DiagnosticValue::Unavailable(error.clone()),
        };
        let self_relative = match &control {
            DiagnosticValue::Available(value) => {
                DiagnosticValue::Available(*value & SE_SELF_RELATIVE != 0)
            }
            DiagnosticValue::Unavailable(error) => DiagnosticValue::Unavailable(error.clone()),
        };
        let (relative, relative_error) = match &self_relative {
            DiagnosticValue::Available(true) => {
                match types.struct_at("_SECURITY_DESCRIPTOR_RELATIVE", address) {
                    Ok(relative) => (Some(relative), None),
                    Err(error) => (None, Some(error.to_string())),
                }
            }
            _ => (None, None),
        };
        let self_relative_value = matches!(&self_relative, DiagnosticValue::Available(true));
        let owner = sid_component(
            memory,
            descriptor_field(
                &descriptor,
                relative.as_ref(),
                relative_error.as_deref(),
                "Owner",
            ),
            address,
            self_relative_value,
            annotate_well_known,
        );
        let group = sid_component(
            memory,
            descriptor_field(
                &descriptor,
                relative.as_ref(),
                relative_error.as_deref(),
                "Group",
            ),
            address,
            self_relative_value,
            annotate_well_known,
        );
        let dacl = match &control {
            DiagnosticValue::Available(value) if value & SE_DACL_PRESENT == 0 => {
                DiagnosticValue::Available(None)
            }
            DiagnosticValue::Available(_) => acl_component(
                memory,
                descriptor_field(
                    &descriptor,
                    relative.as_ref(),
                    relative_error.as_deref(),
                    "Dacl",
                ),
                address,
                self_relative_value,
                annotate_well_known,
            ),
            DiagnosticValue::Unavailable(error) => {
                DiagnosticValue::Unavailable(format!("Control could not be read: {error}"))
            }
        };
        let sacl = match &control {
            DiagnosticValue::Available(value) if value & SE_SACL_PRESENT == 0 => {
                DiagnosticValue::Available(None)
            }
            DiagnosticValue::Available(_) => acl_component(
                memory,
                descriptor_field(
                    &descriptor,
                    relative.as_ref(),
                    relative_error.as_deref(),
                    "Sacl",
                ),
                address,
                self_relative_value,
                annotate_well_known,
            ),
            DiagnosticValue::Unavailable(error) => {
                DiagnosticValue::Unavailable(format!("Control could not be read: {error}"))
            }
        };
        let unsupported_revision =
            matches!(&revision, DiagnosticValue::Available(value) if *value != 1);
        Ok(SecurityDescriptorDetail {
            address,
            revision,
            control,
            control_names,
            self_relative,
            owner,
            group,
            dacl,
            sacl,
            unsupported_revision,
        })
    }

    /// Decode an absolute or self-relative `SECURITY_DESCRIPTOR`.  Revision
    /// and control reads are independent diagnostics; owner/group failures are
    /// reported in their own fields, while `dacl`/`sacl` report ACL-header or
    /// ACE failures without discarding the other descriptor components.  The
    /// `annotate_well_known` flag controls names on all nested SIDs.
    pub fn inspect_security_descriptor(
        &self,
        address: VirtAddr,
        annotate_well_known: bool,
    ) -> Result<SecurityDescriptorDetail> {
        let memory = self.context_memory();
        self.inspect_security_descriptor_in(&memory, address, annotate_well_known)
    }

    /// Decode an ACL header and up to 1024 ACEs at `address`.  A malformed ACL
    /// header or ACE size is fatal; each ACE's access mask and SID are
    /// independent diagnostics when their individual reads are unavailable.
    pub fn inspect_acl(&self, address: VirtAddr) -> Result<AclDetail> {
        let memory = self.context_memory();
        decode_acl(&memory, address, false)
    }

    /// Decode a SID, including its revision, identifier authority,
    /// sub-authorities, canonical string, and recognized well-known name.
    pub fn inspect_sid(&self, address: VirtAddr) -> Result<SidDetail> {
        let memory = self.context_memory();
        read_sid_bounded(&memory, address, usize::MAX, true)
    }

    /// Read `_OBJECT_HEADER.SecurityDescriptor`, mask its fast-reference low
    /// bits, and decode the referenced descriptor in the kernel address space.
    /// A null fast-reference yields `descriptor: None`; header and fast-ref
    /// reads remain fatal because no meaningful object-security detail exists.
    pub fn inspect_object_security(&self, object: VirtAddr) -> Result<ObjectSecurityDetail> {
        let header = self.inspect_object_header(object)?;
        let object_header = self
            .guest()?
            .ntoskrnl
            .types()
            .struct_at("_OBJECT_HEADER", header.header)?;
        let fast_reference = object_header.read_field::<u64>("SecurityDescriptor")?;
        let descriptor_address = fast_ref_address(fast_reference);
        let descriptor = if descriptor_address.is_zero() {
            None
        } else {
            let memory = self.kernel_address_space();
            Some(self.inspect_security_descriptor_in(&memory, descriptor_address, true)?)
        };
        Ok(ObjectSecurityDetail {
            object,
            header: header.header,
            fast_reference,
            descriptor_address,
            descriptor,
        })
    }

    fn process_session_id(&self, eprocess: VirtAddr) -> Option<u32> {
        let kernel_dtb = self.kernel_dtb();
        let types = self.guest().ok()?.ntoskrnl.types_in(kernel_dtb);
        let eprocess = types.struct_at("_EPROCESS", eprocess).ok()?;
        if let Some(session) = eprocess
            .read_field::<VirtAddr>("Session")
            .ok()
            .filter(|address| !address.is_zero())
            && let Ok(session) = types.struct_at("_MM_SESSION_SPACE", session)
            && let Ok(id) = session.read_field::<u32>("SessionId")
        {
            return Some(id);
        }

        let token = eprocess
            .read_field::<u64>("Token")
            .ok()
            .map(fast_ref_address)
            .filter(|address| !address.is_zero())?;
        let token = types.struct_at("_TOKEN", token).ok()?;
        token.read_field::<u32>("SessionId").ok()
    }

    /// Every process paired with its session id (when decodable), plus
    /// whether the walk hit the process bound.
    fn collect_sessions(&self) -> Result<(Vec<SessionProcessRow>, bool)> {
        let processes = self.matching_processes(None)?;
        let bounded = processes.len() >= MAX_SESSION_PROCESSES;
        let processes = processes
            .into_iter()
            .take(MAX_SESSION_PROCESSES)
            .map(|process| {
                let session = self.process_session_id(process.eprocess_va).map(u64::from);
                (process, session)
            })
            .collect();
        Ok((processes, bounded))
    }

    fn current_session_id(&self, processes: &[SessionProcessRow]) -> Option<u64> {
        self.attached_process()
            .and_then(|current| {
                processes
                    .iter()
                    .find(|(process, _)| process.eprocess_va == current.eprocess_va)
                    .and_then(|(_, session)| *session)
            })
            .or_else(|| {
                self.windows_thread_selection
                    .as_ref()
                    .and_then(|thread| thread.eprocess)
                    .and_then(|eprocess| {
                        processes
                            .iter()
                            .find(|(process, _)| process.eprocess_va == eprocess)
                            .and_then(|(_, session)| *session)
                    })
            })
    }

    fn resolve_session_selector(
        &self,
        selector: i64,
        processes: &[(ProcessInfo, Option<u64>)],
    ) -> Result<Option<u64>> {
        match selector {
            -1 | -2 => self
                .current_session_id(processes)
                .map(Some)
                .ok_or_else(|| Error::DebugInfo("current session is unavailable".into())),
            -4 => Ok(None),
            value if value >= 0 => Ok(Some(value as u64)),
            value => Err(Error::DebugInfo(format!(
                "invalid session selector {value}; expected a non-negative ID, -1, -2, or -4"
            ))),
        }
    }

    /// Enumerate up to 4096 processes, group them by session, and optionally
    /// select one session.  `Some(-1)`/`Some(-2)` selects the current session,
    /// `Some(-4)` selects all sessions, and non-negative values select an ID;
    /// unknown session IDs remain valid empty results.  Session IDs first use
    /// `_EPROCESS.Session`/`_MM_SESSION_SPACE` and fall back to `_TOKEN.SessionId`.
    pub fn sessions(&self, session: Option<i64>) -> Result<SessionsDetail> {
        let (processes, truncated) = self.collect_sessions()?;
        let selected_session = match session {
            Some(selector) => self.resolve_session_selector(selector, &processes)?,
            None => None,
        };
        let mut groups: BTreeMap<Option<u64>, Vec<ProcessInfo>> = BTreeMap::new();
        for (process, process_session) in processes {
            if selected_session.is_none_or(|id| process_session == Some(id)) {
                groups.entry(process_session).or_default().push(process);
            }
        }
        let sessions: Vec<SessionDetail> = groups
            .into_iter()
            .map(|(id, processes)| SessionDetail { id, processes })
            .collect();
        let process_count = sessions.iter().map(|session| session.processes.len()).sum();
        Ok(SessionsDetail {
            selected_session,
            sessions,
            process_count,
            truncated,
        })
    }

    /// Enumerate up to 4096 processes, selecting the current session by
    /// default, and apply the optional case-insensitive image glob.  A
    /// non-zero `detailed` flag is represented by the returned boolean; it
    /// does not alter which processes are selected.  `Some(-1)`/`Some(-2)`
    /// selects the current session and `Some(-4)` selects all sessions.
    pub fn session_processes(
        &self,
        session: Option<i64>,
        detailed: bool,
        image_glob: Option<&str>,
    ) -> Result<SessionProcessesDetail> {
        let (processes, truncated) = self.collect_sessions()?;
        let selected_session = match session {
            Some(selector) => self.resolve_session_selector(selector, &processes)?,
            None => self.current_session_id(&processes),
        };
        let image_glob = image_glob.map(str::to_string);
        let processes: Vec<_> = processes
            .into_iter()
            .filter(|(process, process_session)| {
                selected_session.is_none_or(|id| *process_session == Some(id))
                    && image_glob
                        .as_deref()
                        .is_none_or(|pattern| glob_matches(pattern, &process.name, true))
            })
            .map(|(process, session)| SessionProcessDetail { process, session })
            .collect();
        let process_count = processes.len();
        Ok(SessionProcessesDetail {
            selected_session,
            detailed,
            image_glob,
            processes,
            process_count,
            truncated,
        })
    }
}

/// Resolve one process's session ID using session-space metadata and the
/// primary-token fallback used by the session inspectors.
pub fn process_session_id(target: &Target, eprocess: VirtAddr) -> Option<u32> {
    target.process_session_id(eprocess)
}

#[cfg(test)]
mod tests {
    use super::{DiagnosticValue, decode_acl, read_sid_bounded};
    use crate::backend::MemoryOps;
    use crate::error::{Error, Result};
    use crate::session::session_over_memory;
    use crate::types::VirtAddr;

    struct TestMemory(Vec<u8>);

    impl MemoryOps<VirtAddr> for TestMemory {
        fn read_bytes(&self, address: VirtAddr, output: &mut [u8]) -> Result<()> {
            let start = usize::try_from(address.0)
                .map_err(|_| Error::DebugInfo("test address overflow".to_string()))?;
            let end = start
                .checked_add(output.len())
                .ok_or_else(|| Error::DebugInfo("test read overflow".to_string()))?;
            let source = self
                .0
                .get(start..end)
                .ok_or_else(|| Error::DebugInfo("test read out of range".to_string()))?;
            output.copy_from_slice(source);
            Ok(())
        }

        fn write_bytes(&self, _address: VirtAddr, _input: &[u8]) -> Result<()> {
            Err(Error::DebugInfo("test memory is read-only".to_string()))
        }
    }

    #[test]
    fn decodes_sid_authority_sub_authorities_and_well_known_name() {
        let memory = TestMemory(vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]);
        let sid = read_sid_bounded(&memory, VirtAddr(0), usize::MAX, true).unwrap();
        assert_eq!(sid.sid, "S-1-5-18");
        assert_eq!(sid.revision, 1);
        assert_eq!(sid.authority, 5);
        assert_eq!(sid.sub_authorities, vec![18]);
        assert_eq!(sid.well_known.as_deref(), Some("LOCAL SYSTEM"));
        let unannotated = read_sid_bounded(&memory, VirtAddr(0), usize::MAX, false).unwrap();
        assert_eq!(unannotated.well_known, None);
    }

    #[test]
    fn token_sids_are_validated_like_descriptor_sids() {
        let sid = |revision| [revision, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        let session = session_over_memory(0x1000, &sid(1));
        assert_eq!(
            session.target.read_sid(VirtAddr(0x1000)).unwrap(),
            "S-1-5-18"
        );
        let session = session_over_memory(0x1000, &sid(2));
        assert!(session.target.read_sid(VirtAddr(0x1000)).is_err());
    }

    #[test]
    fn decodes_allow_ace_mask_flags_and_sid() {
        let mut bytes = vec![0u8; 28];
        bytes[..8].copy_from_slice(&[2, 0, 28, 0, 1, 0, 0, 0]);
        bytes[8..28].copy_from_slice(&[
            0, 0x10, 20, 0, 0x34, 0x12, 0, 0, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
        ]);
        let acl = decode_acl(&TestMemory(bytes), VirtAddr(0), true).unwrap();
        assert_eq!(acl.revision, 2);
        assert_eq!(acl.ace_count, 1);
        assert!(!acl.bounded);
        let ace = &acl.aces[0];
        assert_eq!(ace.ace_type, 0);
        assert_eq!(ace.type_name, "ACCESS_ALLOWED");
        assert_eq!(ace.flag_names, "INHERITED");
        assert!(matches!(
            &ace.access_mask,
            DiagnosticValue::Available(value) if *value == 0x1234
        ));
        let DiagnosticValue::Available(sid) = &ace.sid else {
            panic!("ACE SID should decode");
        };
        assert_eq!(sid.sid, "S-1-5-18");
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidAndAttributes {
    pub sid: String,
    pub attributes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivilegeInfo {
    pub luid: u64,
    pub attributes: u32,
}

#[derive(Debug, Clone)]
pub struct TokenDetail {
    pub process: ProcessInfo,
    pub token: VirtAddr,
    pub token_id: DiagnosticValue<u64>,
    pub authentication_id: DiagnosticValue<u64>,
    pub token_type: DiagnosticValue<u32>,
    pub impersonation_level: DiagnosticValue<u32>,
    pub flags: DiagnosticValue<u32>,
    pub user: DiagnosticValue<Option<SidAndAttributes>>,
    pub groups: DiagnosticValue<Vec<SidAndAttributes>>,
    pub privileges: DiagnosticValue<Vec<PrivilegeInfo>>,
}

const SE_PRIVILEGE_ENABLED_BY_DEFAULT: u32 = 0x1;
const SE_PRIVILEGE_ENABLED: u32 = 0x2;

fn decode_token_privilege_bitmaps(
    present: u64,
    enabled: u64,
    enabled_by_default: u64,
) -> Vec<PrivilegeInfo> {
    let mut remaining = present;
    let mut privileges = Vec::with_capacity(present.count_ones() as usize);
    while remaining != 0 {
        let bit = remaining.trailing_zeros();
        let mask = 1u64 << bit;
        let mut attributes = 0;
        if enabled_by_default & mask != 0 {
            attributes |= SE_PRIVILEGE_ENABLED_BY_DEFAULT;
        }
        if enabled & mask != 0 {
            attributes |= SE_PRIVILEGE_ENABLED;
        }
        privileges.push(PrivilegeInfo {
            luid: u64::from(bit),
            attributes,
        });
        remaining &= remaining - 1;
    }
    privileges
}

impl Target {
    fn read_luid(&self, layout: &TypeInfo, base: VirtAddr) -> Result<u64> {
        let low: u32 = self.read_layout_field(layout, base, "LowPart")?;
        let high: i32 = self.read_layout_field(layout, base, "HighPart")?;
        Ok(((high as u32 as u64) << 32) | u64::from(low))
    }

    fn read_sid(&self, address: VirtAddr) -> Result<String> {
        if address.is_zero() {
            return Err(Error::DebugInfo("SID pointer is null".to_string()));
        }
        let memory = self.context_memory();
        read_sid_bounded(&memory, address, usize::MAX, false).map(|sid| sid.sid)
    }

    fn read_token_id_field(
        &self,
        token_layout: &TypeInfo,
        luid_layout: &TypeInfo,
        token: VirtAddr,
        name: &str,
    ) -> Result<u64> {
        self.read_luid(luid_layout, token + token_layout.field_offset(name)?)
    }

    /// Decode the selected/current process primary token.  Independently
    /// unavailable optional fields retain their exact layout/read error.
    pub fn inspect_process_token(&self) -> Result<TokenDetail> {
        const MAX_TOKEN_ITEMS: usize = 256;
        let process = self.selected_process_info()?;
        let types = self.guest()?.ntoskrnl.types_in(process.dtb);
        let eprocess_layout = types.layout("_EPROCESS")?;
        let raw_token: u64 =
            self.read_layout_field(&eprocess_layout, process.eprocess_va, "Token")?;
        let token = fast_ref_address(raw_token);
        if token.is_zero() {
            return Err(Error::DebugInfo("_EPROCESS.Token is null".to_string()));
        }
        let token_layout = types.layout("_TOKEN")?;
        let luid_layout = types.layout("_LUID")?;

        let token_id = DiagnosticValue::from_result(self.read_token_id_field(
            &token_layout,
            &luid_layout,
            token,
            "TokenId",
        ));
        let authentication_id = DiagnosticValue::from_result(self.read_token_id_field(
            &token_layout,
            &luid_layout,
            token,
            "AuthenticationId",
        ));
        let token_type =
            DiagnosticValue::from_result(self.read_layout_field(&token_layout, token, "TokenType"));
        let impersonation_level = DiagnosticValue::from_result(self.read_layout_field(
            &token_layout,
            token,
            "ImpersonationLevel",
        ));
        let flags = DiagnosticValue::from_result(self.read_layout_field(
            &token_layout,
            token,
            "TokenFlags",
        ));

        let sid_items = (|| -> Result<Vec<SidAndAttributes>> {
            let count: u32 = self.read_layout_field(&token_layout, token, "UserAndGroupCount")?;
            if count as usize > MAX_TOKEN_ITEMS {
                return Err(Error::DebugInfo(format!(
                    "_TOKEN.UserAndGroupCount {count} exceeds bound {MAX_TOKEN_ITEMS}"
                )));
            }
            let array: VirtAddr = self.read_layout_field(&token_layout, token, "UserAndGroups")?;
            if count != 0 && array.is_zero() {
                return Err(Error::DebugInfo(
                    "_TOKEN.UserAndGroups is null with nonzero count".to_string(),
                ));
            }
            let item_layout = types.layout("_SID_AND_ATTRIBUTES")?;
            let mut items = Vec::with_capacity(count as usize);
            for index in 0..count as usize {
                let base = array + (index * item_layout.size) as u64;
                let sid: VirtAddr = self.read_layout_field(&item_layout, base, "Sid")?;
                let attributes: u32 = self.read_layout_field(&item_layout, base, "Attributes")?;
                items.push(SidAndAttributes {
                    sid: self.read_sid(sid)?,
                    attributes,
                });
            }
            Ok(items)
        })();
        let (user, groups) = match sid_items {
            Ok(items) => (
                DiagnosticValue::Available(items.first().cloned()),
                DiagnosticValue::Available(items.into_iter().skip(1).collect()),
            ),
            Err(error) => (
                DiagnosticValue::Unavailable(error.to_string()),
                DiagnosticValue::Unavailable(error.to_string()),
            ),
        };

        let privileges = DiagnosticValue::from_result((|| -> Result<Vec<PrivilegeInfo>> {
            let privileges = token + token_layout.field_offset("Privileges")?;
            let privileges_layout = types.layout("_SEP_TOKEN_PRIVILEGES")?;
            let present: u64 = self.read_layout_field(&privileges_layout, privileges, "Present")?;
            let enabled: u64 = self.read_layout_field(&privileges_layout, privileges, "Enabled")?;
            let enabled_by_default: u64 =
                self.read_layout_field(&privileges_layout, privileges, "EnabledByDefault")?;
            Ok(decode_token_privilege_bitmaps(
                present,
                enabled,
                enabled_by_default,
            ))
        })());

        Ok(TokenDetail {
            process,
            token,
            token_id,
            authentication_id,
            token_type,
            impersonation_level,
            flags,
            user,
            groups,
            privileges,
        })
    }
}

#[cfg(test)]
mod moved_token_privilege_tests {
    use super::*;

    #[test]
    fn token_privilege_bitmaps_preserve_ids_and_attributes() {
        let privileges =
            decode_token_privilege_bitmaps((1 << 2) | (1 << 20), 1 << 20, (1 << 2) | (1 << 20));
        assert_eq!(
            privileges,
            vec![
                super::PrivilegeInfo {
                    luid: 2,
                    attributes: super::SE_PRIVILEGE_ENABLED_BY_DEFAULT,
                },
                super::PrivilegeInfo {
                    luid: 20,
                    attributes: super::SE_PRIVILEGE_ENABLED_BY_DEFAULT
                        | super::SE_PRIVILEGE_ENABLED,
                },
            ]
        );
    }
}
