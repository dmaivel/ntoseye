//! ALPC ports and messages (`!alpc`): an `_ALPC_PORT`'s owner, the
//! connection it belongs to (`_ALPC_COMMUNICATION_INFO`), its state bits and
//! queues; a `_KALPC_MESSAGE`; and the ports a process holds handles to.
//! Every field comes from nt's PDB. A port's kind is read from which slot
//! of its communication info points back at it.

use std::collections::{HashMap, HashSet};

use crate::error::{Error, Result};
use crate::guest::ProcessInfo;
use crate::layout::{StructRef, Types};
use crate::target::sched::walk_list_nodes;
use crate::target::{DiagnosticValue, ListTermination, Target};
use crate::types::VirtAddr;

/// The object type name of an ALPC port.
const ALPC_PORT_TYPE: &str = "ALPC Port";
/// How deep one port queue or connection list is walked.
const MAX_LIST_ENTRIES: usize = 4096;
/// How many handle-table slots `/lpp` scans.
const MAX_PROCESS_HANDLES: usize = 1 << 16;

/// What an `_ALPC_PORT` is within its connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlpcPortKind {
    /// The named port a server listens on.
    Connection,
    /// The server's end of one connection.
    ServerCommunication,
    /// The client's end of one connection.
    ClientCommunication,
}

impl AlpcPortKind {
    /// WinDbg's name for the kind.
    pub fn name(self) -> &'static str {
        match self {
            Self::Connection => "ALPC_CONNECTION_PORT",
            Self::ServerCommunication => "ALPC_SERVER_COMMUNICATION_PORT",
            Self::ClientCommunication => "ALPC_CLIENT_COMMUNICATION_PORT",
        }
    }
}

/// `PORT_MESSAGE.u2.s2.Type`'s message kind (its low byte), by the
/// `LPC_*` name ntlpcapi.h gives it.
pub fn lpc_message_type_name(message_type: u64) -> Option<&'static str> {
    Some(match message_type & 0xff {
        1 => "LPC_REQUEST",
        2 => "LPC_REPLY",
        3 => "LPC_DATAGRAM",
        4 => "LPC_LOST_REPLY",
        5 => "LPC_PORT_CLOSED",
        6 => "LPC_CLIENT_DIED",
        7 => "LPC_EXCEPTION",
        8 => "LPC_DEBUG_EVENT",
        9 => "LPC_ERROR_EVENT",
        10 => "LPC_CONNECTION_REQUEST",
        _ => return None,
    })
}

/// `_ALPC_PORT` queues, as (list head, length field, key, record type, link
/// in the record). The wait queue holds the threads waiting to receive.
const PORT_QUEUES: &[(&str, &str, &str, &str, &str)] = &[
    (
        "MainQueue",
        "MainQueueLength",
        "main",
        "_KALPC_MESSAGE",
        "Entry",
    ),
    (
        "LargeMessageQueue",
        "LargeMessageQueueLength",
        "large_message",
        "_KALPC_MESSAGE",
        "Entry",
    ),
    (
        "PendingQueue",
        "PendingQueueLength",
        "pending",
        "_KALPC_MESSAGE",
        "Entry",
    ),
    (
        "CanceledQueue",
        "CanceledQueueLength",
        "canceled",
        "_KALPC_MESSAGE",
        "Entry",
    ),
    (
        "WaitQueue",
        "WaitQueueLength",
        "wait",
        "_ETHREAD",
        "AlpcWaitListEntry",
    ),
];

/// The queues whose messages count as a port's queued messages.
const MESSAGE_QUEUE_LENGTHS: [&str; 3] = [
    "MainQueueLength",
    "LargeMessageQueueLength",
    "PendingQueueLength",
];

/// One `_ALPC_PORT` queue.
#[derive(Debug, Clone)]
pub struct AlpcQueue {
    /// The PDB list head, e.g. `PendingQueue`.
    pub field: &'static str,
    pub key: &'static str,
    /// The port's count for the queue (`<field>Length`).
    pub length: Option<u64>,
    /// The queued `_KALPC_MESSAGE`s, or for the wait queue the waiting
    /// `_ETHREAD`s.
    pub entries: Vec<VirtAddr>,
    pub termination: ListTermination,
}

/// One connection to a connection port: its communication info and the two
/// ports it joins.
#[derive(Debug, Clone)]
pub struct AlpcConnection {
    pub communication_info: VirtAddr,
    pub server_port: VirtAddr,
    /// Messages queued on the server port (main, large, and pending).
    pub server_queued: Option<u64>,
    pub client_port: VirtAddr,
    pub client_queued: Option<u64>,
    pub client_owner: VirtAddr,
    pub client_owner_name: Option<String>,
}

/// A decoded `_ALPC_PORT`.
#[derive(Debug, Clone)]
pub struct AlpcPortDetail {
    pub address: VirtAddr,
    pub name: Option<String>,
    pub pointer_count: i64,
    pub handle_count: i64,
    pub kind: Option<AlpcPortKind>,
    /// `u1.State`; `port_type` is its `Type` bits.
    pub state: Option<u64>,
    pub port_type: Option<u64>,
    /// The one-bit `u1.s1` state flags set, by their PDB names.
    pub state_flags: Vec<String>,
    pub owner: VirtAddr,
    pub owner_name: Option<String>,
    pub communication_info: VirtAddr,
    pub connection_port: Option<VirtAddr>,
    pub server_port: Option<VirtAddr>,
    pub client_port: Option<VirtAddr>,
    pub sequence_no: Option<u64>,
    pub completion_port: Option<VirtAddr>,
    pub completion_list: Option<VirtAddr>,
    pub port_context: Option<VirtAddr>,
    /// `PortAttributes.Flags` and `.MaxMessageLength`.
    pub attribute_flags: Option<u64>,
    pub max_message_length: Option<u64>,
    pub queues: Vec<AlpcQueue>,
    pub direct_queue_length: Option<u64>,
    /// A connection port's connections (`CommunicationInfo.CommunicationList`).
    pub connections: Vec<AlpcConnection>,
    pub connection_termination: Option<ListTermination>,
}

/// One `_KALPC_MESSAGE` pointer field, as (PDB path, key, value).
#[derive(Debug, Clone, Copy)]
pub struct AlpcField {
    pub field: &'static str,
    pub key: &'static str,
    pub value: VirtAddr,
}

/// `_KALPC_MESSAGE` pointer fields, as (PDB field, key).
const MESSAGE_POINTERS: &[(&str, &str)] = &[
    ("WaitingThread", "waiting_thread"),
    ("ServerThread", "server_thread"),
    ("ConnectionPort", "connection_port"),
    ("QuotaProcess", "quota_process"),
    ("CancelSequencePort", "cancel_sequence_port"),
    ("CancelQueuePort", "cancel_queue_port"),
    ("DataUserVa", "data_user_va"),
    ("ExtensionBuffer", "extension_buffer"),
];

/// `_KALPC_MESSAGE_ATTRIBUTES` fields, as (PDB field, key).
const MESSAGE_ATTRIBUTES: &[(&str, &str)] = &[
    ("ClientContext", "client_context"),
    ("ServerContext", "server_context"),
    ("PortContext", "port_context"),
    ("CancelPortContext", "cancel_port_context"),
    ("SecurityData", "security_data"),
    ("View", "view"),
    ("HandleData", "handle_data"),
];

/// A decoded `_KALPC_MESSAGE`.
#[derive(Debug, Clone)]
pub struct AlpcMessageDetail {
    pub address: VirtAddr,
    pub message_id: Option<u64>,
    pub callback_id: Option<u64>,
    pub sequence_no: Option<u64>,
    /// `PortMessage.u2.s2.Type`.
    pub message_type: Option<u64>,
    pub data_length: Option<u64>,
    pub total_length: Option<u64>,
    /// `PortMessage.ClientId`: the sender.
    pub client_process_id: Option<u64>,
    pub client_thread_id: Option<u64>,
    /// `u1.State` and its `QueueType`/`QueuePortType` bits.
    pub state: Option<u64>,
    pub queue_type: Option<u64>,
    pub queue_port_type: Option<u64>,
    /// The one-bit `u1.s1` state flags set, by their PDB names.
    pub state_flags: Vec<String>,
    pub owner_port: VirtAddr,
    pub owner_port_kind: Option<AlpcPortKind>,
    /// The port whose queue holds the message, and its owner.
    pub port_queue: VirtAddr,
    pub port_queue_kind: Option<AlpcPortKind>,
    pub port_queue_owner: Option<VirtAddr>,
    pub port_queue_owner_name: Option<String>,
    pub cancel_sequence_no: Option<u64>,
    pub extension_buffer_size: Option<u64>,
    /// [`MESSAGE_POINTERS`] fields this build has.
    pub pointers: Vec<AlpcField>,
    /// [`MESSAGE_ATTRIBUTES`] fields this build has.
    pub attributes: Vec<AlpcField>,
}

/// A connection port a process owns, and its connections.
#[derive(Debug, Clone)]
pub struct AlpcOwnedPort {
    pub handle: u64,
    pub port: VirtAddr,
    pub name: Option<String>,
    pub connections: Vec<AlpcConnection>,
    pub termination: ListTermination,
}

/// A client communication port a process holds: what it is connected to.
#[derive(Debug, Clone)]
pub struct AlpcClientPort {
    pub handle: u64,
    pub port: VirtAddr,
    pub queued: Option<u64>,
    pub connection_port: VirtAddr,
    pub connection_name: Option<String>,
    pub server_port: VirtAddr,
    pub server_queued: Option<u64>,
    pub server_owner: Option<VirtAddr>,
    pub server_owner_name: Option<String>,
}

/// The ALPC ports a process holds handles to (`!alpc /lpp`).
#[derive(Debug, Clone)]
pub struct AlpcProcessPorts {
    pub process: ProcessInfo,
    /// Connection ports the process owns.
    pub created: Vec<AlpcOwnedPort>,
    /// Client ports the process holds.
    pub connected: Vec<AlpcClientPort>,
    /// Server communication ports it holds (its ends of connections to its
    /// own ports).
    pub server_ports: usize,
    pub scanned_handles: usize,
    pub advertised_handles: usize,
    pub skipped_entries: usize,
}

/// The pieces of an `_ALPC_PORT` every view needs.
struct PortCore<'a> {
    port: StructRef<'a>,
    kind: Option<AlpcPortKind>,
    owner: VirtAddr,
    communication_info: VirtAddr,
    /// `ConnectionPort`, `ServerCommunicationPort`, `ClientCommunicationPort`.
    ends: Option<[VirtAddr; 3]>,
}

impl PortCore<'_> {
    /// Messages on the main, large-message, and pending queues.
    fn queued(&self) -> Option<u64> {
        MESSAGE_QUEUE_LENGTHS
            .iter()
            .map(|field| self.port.read_uint(field).ok())
            .sum()
    }
}

/// Owner process names, read once each.
#[derive(Default)]
struct OwnerNames(HashMap<VirtAddr, Option<String>>);

impl OwnerNames {
    fn get(&mut self, target: &Target, eprocess: VirtAddr) -> Option<String> {
        if eprocess.is_zero() {
            return None;
        }
        self.0
            .entry(eprocess)
            .or_insert_with(|| {
                target
                    .guest()
                    .and_then(|guest| guest.process_at(eprocess))
                    .ok()
                    .map(|process| process.name)
            })
            .clone()
    }
}

/// The `u1` state word of an `_ALPC_PORT` or `_KALPC_MESSAGE`, the bits named
/// `fields` in it, and its one-bit flags by name.
fn state_bits<const N: usize>(
    record: &StructRef<'_>,
    fields: [&str; N],
) -> (Option<u64>, [Option<u64>; N], Vec<String>) {
    let Ok(u1) = record.embedded("u1") else {
        return (None, [None; N], Vec::new());
    };
    let state = u1.read_uint("State").ok();
    let (Some(state), Ok(s1)) = (state, u1.embedded("s1")) else {
        return (state, [None; N], Vec::new());
    };
    let layout = s1.layout();
    let values = fields.map(|name| layout.field(name).ok().map(|field| field.decode(state)));
    // Every s1 bitfield sits at offset 0; the first named one anchors them.
    let flags = layout.set_bit_names(fields[0], state);
    (Some(state), values, flags)
}

impl Target {
    fn alpc_port_core<'a>(&self, types: Types<'a>, address: VirtAddr) -> Result<PortCore<'a>> {
        let port = types.struct_at("_ALPC_PORT", address)?.prefetch();
        let owner = port.read_pointer("OwnerProcess")?;
        let communication_info = port.read_pointer("CommunicationInfo")?;
        let ends = (!communication_info.is_zero())
            .then(|| {
                let info = types
                    .struct_at("_ALPC_COMMUNICATION_INFO", communication_info)
                    .ok()?
                    .prefetch();
                Some([
                    info.read_pointer("ConnectionPort").ok()?,
                    info.read_pointer("ServerCommunicationPort").ok()?,
                    info.read_pointer("ClientCommunicationPort").ok()?,
                ])
            })
            .flatten();
        let kind = ends.and_then(|[connection, server, client]| {
            [
                (connection, AlpcPortKind::Connection),
                (server, AlpcPortKind::ServerCommunication),
                (client, AlpcPortKind::ClientCommunication),
            ]
            .into_iter()
            .find_map(|(end, kind)| (end == address).then_some(kind))
        });
        Ok(PortCore {
            port,
            kind,
            owner,
            communication_info,
            ends,
        })
    }

    /// The object at `address` (its body or header) when it is an ALPC port:
    /// its body, name, and counts.
    fn alpc_port_object(&self, address: VirtAddr) -> Result<(VirtAddr, Option<String>, i64, i64)> {
        let header = self.inspect_object_header(address).map_err(|error| {
            Error::InvalidArgument(format!(
                "{:#x} is not an ALPC port object ({error})",
                address.0
            ))
        })?;
        if header.type_name.as_deref() != Some(ALPC_PORT_TYPE) {
            return Err(Error::InvalidArgument(format!(
                "{:#x} is not an ALPC port (its object type is {})",
                address.0,
                header.type_name.as_deref().unwrap_or("unknown")
            )));
        }
        Ok((
            header.body,
            header.name,
            header.pointer_count,
            header.handle_count,
        ))
    }

    /// The connections of the connection port whose communication info is
    /// `info`.
    fn alpc_connections(
        &self,
        types: Types<'_>,
        info: VirtAddr,
        owners: &mut OwnerNames,
    ) -> (Vec<AlpcConnection>, ListTermination) {
        let Ok(link) = types
            .layout("_ALPC_COMMUNICATION_INFO")
            .and_then(|layout| layout.field_offset("CommunicationList"))
        else {
            return (
                Vec::new(),
                ListTermination::Corrupt("no CommunicationList".into()),
            );
        };
        let (links, termination) = walk_list_nodes(self, info + link, MAX_LIST_ENTRIES);
        let connections = links
            .into_iter()
            .map(|at| {
                let communication_info = at - link;
                let info = types
                    .struct_at("_ALPC_COMMUNICATION_INFO", communication_info)
                    .map(StructRef::prefetch);
                let end = |name| {
                    info.as_ref()
                        .ok()
                        .and_then(|info| info.read_pointer(name).ok())
                        .unwrap_or(VirtAddr(0))
                };
                let (server_port, client_port) = (
                    end("ServerCommunicationPort"),
                    end("ClientCommunicationPort"),
                );
                let core = |port: VirtAddr| {
                    (!port.is_zero())
                        .then(|| self.alpc_port_core(types, port).ok())
                        .flatten()
                };
                let (server, client) = (core(server_port), core(client_port));
                let client_owner = client.as_ref().map_or(VirtAddr(0), |core| core.owner);
                AlpcConnection {
                    communication_info,
                    server_port,
                    server_queued: server.as_ref().and_then(PortCore::queued),
                    client_port,
                    client_queued: client.as_ref().and_then(PortCore::queued),
                    client_owner,
                    client_owner_name: owners.get(self, client_owner),
                }
            })
            .collect();
        (connections, termination)
    }

    /// Decode the ALPC port at `address` (its object body or header).
    pub fn alpc_port(&self, address: VirtAddr) -> Result<AlpcPortDetail> {
        let (body, name, pointer_count, handle_count) = self.alpc_port_object(address)?;
        let types = self.guest()?.ntoskrnl.types();
        let core = self.alpc_port_core(types, body)?;
        let port = &core.port;
        let (state, [port_type], state_flags) = state_bits(port, ["Type"]);
        let pointer = |name| port.read_pointer(name).ok();
        let attributes = port.embedded("PortAttributes").ok();
        let attribute = |name| attributes.as_ref().and_then(|a| a.read_uint(name).ok());
        let queues = PORT_QUEUES
            .iter()
            .map(|&(field, length, key, record, link)| {
                let (entries, termination) = match (
                    port.layout().field_offset(field),
                    types.layout(record).and_then(|ti| ti.field_offset(link)),
                ) {
                    (Ok(head), Ok(link)) => {
                        let (links, termination) =
                            walk_list_nodes(self, body + head, MAX_LIST_ENTRIES);
                        (links.into_iter().map(|at| at - link).collect(), termination)
                    }
                    _ => (
                        Vec::new(),
                        ListTermination::Corrupt(format!("no {field} list")),
                    ),
                };
                AlpcQueue {
                    field,
                    key,
                    length: port.read_uint(length).ok(),
                    entries,
                    termination,
                }
            })
            .collect();
        let mut owners = OwnerNames::default();
        let (connections, connection_termination) = match core.kind {
            Some(AlpcPortKind::Connection) => {
                let (connections, termination) =
                    self.alpc_connections(types, core.communication_info, &mut owners);
                (connections, Some(termination))
            }
            _ => (Vec::new(), None),
        };
        let [connection_port, server_port, client_port] =
            core.ends.map_or([None; 3], |ends| ends.map(Some));
        Ok(AlpcPortDetail {
            address: body,
            name,
            pointer_count,
            handle_count,
            kind: core.kind,
            state,
            port_type,
            state_flags,
            owner: core.owner,
            owner_name: owners.get(self, core.owner),
            communication_info: core.communication_info,
            connection_port,
            server_port,
            client_port,
            sequence_no: port.read_uint("SequenceNo").ok(),
            completion_port: pointer("CompletionPort"),
            completion_list: pointer("CompletionList"),
            port_context: pointer("PortContext"),
            attribute_flags: attribute("Flags"),
            max_message_length: attribute("MaxMessageLength"),
            queues,
            direct_queue_length: port.read_uint("DirectQueueLength").ok(),
            connections,
            connection_termination,
        })
    }

    /// Decode the `_KALPC_MESSAGE` at `address`. Its owner port, when set,
    /// must be an ALPC port.
    pub fn alpc_message(&self, address: VirtAddr) -> Result<AlpcMessageDetail> {
        let types = self.guest()?.ntoskrnl.types();
        let message = types.struct_at("_KALPC_MESSAGE", address)?.prefetch();
        let owner_port = message.read_pointer("OwnerPort").map_err(|error| {
            Error::InvalidArgument(format!(
                "{:#x} is not a readable ALPC message: {error}",
                address.0
            ))
        })?;
        let port_queue = message.read_pointer("PortQueue")?;
        let port_kind = |port: VirtAddr| -> Result<Option<(AlpcPortKind, VirtAddr)>> {
            if port.is_zero() {
                return Ok(None);
            }
            let (body, ..) = self.alpc_port_object(port)?;
            let core = self.alpc_port_core(types, body)?;
            Ok(core.kind.map(|kind| (kind, core.owner)))
        };
        let owner = port_kind(owner_port).map_err(|_| {
            Error::InvalidArgument(format!(
                "{:#x} is not an ALPC message (its OwnerPort {:#x} is not an ALPC port)",
                address.0, owner_port.0
            ))
        })?;
        let queue = port_kind(port_queue).ok().flatten();
        let (state, [queue_type, queue_port_type], state_flags) =
            state_bits(&message, ["QueueType", "QueuePortType"]);
        let port_message = message.embedded("PortMessage").ok();
        let nested = |union: &str, inner: &str, field: &str| {
            port_message
                .as_ref()?
                .embedded(union)
                .ok()?
                .embedded(inner)
                .ok()?
                .read_uint(field)
                .ok()
        };
        let direct = |field: &str| port_message.as_ref()?.read_uint(field).ok();
        let client_id = |field: &str| {
            port_message
                .as_ref()?
                .embedded("ClientId")
                .ok()?
                .read_uint(field)
                .ok()
        };
        let pointers = |record: Option<&StructRef<'_>>, table: &[(&'static str, &'static str)]| {
            table
                .iter()
                .filter_map(|&(field, key)| {
                    let value = record?.read_pointer(field).ok()?;
                    Some(AlpcField { field, key, value })
                })
                .collect()
        };
        let attributes = message.embedded("MessageAttributes").ok();
        let port_queue_owner = queue.map(|(_, owner)| owner);
        Ok(AlpcMessageDetail {
            address,
            message_id: direct("MessageId"),
            callback_id: direct("CallbackId"),
            sequence_no: message.read_uint("SequenceNo").ok(),
            message_type: nested("u2", "s2", "Type"),
            data_length: nested("u1", "s1", "DataLength"),
            total_length: nested("u1", "s1", "TotalLength"),
            client_process_id: client_id("UniqueProcess"),
            client_thread_id: client_id("UniqueThread"),
            state,
            queue_type,
            queue_port_type,
            state_flags,
            owner_port,
            owner_port_kind: owner.map(|(kind, _)| kind),
            port_queue,
            port_queue_kind: queue.map(|(kind, _)| kind),
            port_queue_owner,
            port_queue_owner_name: port_queue_owner
                .and_then(|owner| OwnerNames::default().get(self, owner)),
            cancel_sequence_no: message.read_uint("CancelSequenceNo").ok(),
            extension_buffer_size: message.read_uint("ExtensionBufferSize").ok(),
            pointers: pointers(Some(&message), MESSAGE_POINTERS),
            attributes: pointers(attributes.as_ref(), MESSAGE_ATTRIBUTES),
        })
    }

    /// The ALPC ports `process` holds handles to: the connection ports it
    /// owns with their connections, and the client ports it is connected
    /// through.
    pub fn alpc_process_ports(&self, process: ProcessInfo) -> Result<AlpcProcessPorts> {
        let handles = self.enumerate_process_handles(process, MAX_PROCESS_HANDLES)?;
        let types = self.guest()?.ntoskrnl.types();
        let body_offset = types.layout("_OBJECT_HEADER")?.field_offset("Body")?;
        let mut owners = OwnerNames::default();
        let mut seen = HashSet::new();
        let mut created = Vec::new();
        let mut connected = Vec::new();
        let mut server_ports = 0;
        for entry in &handles.entries {
            // The walk decoded each entry's object header (`entry.object`).
            let (
                DiagnosticValue::Available(header),
                DiagnosticValue::Available(Some(type_name)),
                DiagnosticValue::Available(name),
            ) = (&entry.object, &entry.type_name, &entry.name)
            else {
                continue;
            };
            if type_name != ALPC_PORT_TYPE {
                continue;
            }
            let port = *header + body_offset;
            if !seen.insert(port) {
                continue;
            }
            let Ok(core) = self.alpc_port_core(types, port) else {
                continue;
            };
            match (core.kind, core.ends) {
                (Some(AlpcPortKind::Connection), _) => {
                    if core.owner != handles.process.eprocess_va {
                        continue;
                    }
                    let (connections, termination) =
                        self.alpc_connections(types, core.communication_info, &mut owners);
                    created.push(AlpcOwnedPort {
                        handle: entry.handle,
                        port,
                        name: name.clone(),
                        connections,
                        termination,
                    });
                }
                (Some(AlpcPortKind::ClientCommunication), Some([connection, server, _])) => {
                    let server_core = (!server.is_zero())
                        .then(|| self.alpc_port_core(types, server).ok())
                        .flatten();
                    let connection_name = (!connection.is_zero())
                        .then(|| self.alpc_port_object(connection).ok())
                        .flatten()
                        .and_then(|(_, name, ..)| name);
                    let server_owner = server_core.as_ref().map(|core| core.owner);
                    connected.push(AlpcClientPort {
                        handle: entry.handle,
                        port,
                        queued: core.queued(),
                        connection_port: connection,
                        connection_name,
                        server_port: server,
                        server_queued: server_core.as_ref().and_then(PortCore::queued),
                        server_owner,
                        server_owner_name: server_owner.and_then(|owner| owners.get(self, owner)),
                    });
                }
                (Some(AlpcPortKind::ServerCommunication), _) => server_ports += 1,
                _ => {}
            }
        }
        Ok(AlpcProcessPorts {
            process: handles.process,
            created,
            connected,
            server_ports,
            scanned_handles: handles.scanned_handles,
            advertised_handles: handles.advertised_handles,
            skipped_entries: handles.skipped_entries,
        })
    }
}
