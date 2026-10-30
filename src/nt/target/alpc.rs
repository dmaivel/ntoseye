//! ALPC ports and messages (`!alpc`): an `_ALPC_PORT`'s owner, the
//! connection it belongs to (`_ALPC_COMMUNICATION_INFO`), its state bits and
//! queues; a `_KALPC_MESSAGE`; and the ports a process holds handles to.
//! Every field comes from nt's PDB. A port's kind is read from which slot
//! of its communication info points back at it.

use std::collections::{HashMap, HashSet};

use crate::base::error::{Error, Result};
use crate::base::types::VirtAddr;
use crate::nt::guest::ProcessInfo;
use crate::nt::layout::{StructRef, Types};
use crate::nt::target::sched::walk_list_records;
use crate::nt::target::{DiagnosticValue, ListTermination, Target};
use ntoseye_macros::record;

/// The object type name of an ALPC port.
const ALPC_PORT_TYPE: &str = "ALPC Port";
/// How deep one port queue or connection list is walked.
const MAX_LIST_ENTRIES: usize = 4096;
/// How many handle-table slots `/lpp` scans.
const MAX_PROCESS_HANDLES: usize = 1 << 16;

/// What an `_ALPC_PORT` is within its connection, by WinDbg's port type
/// name (`ALPC_CONNECTION_PORT`, ...).
#[record]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlpcPortKind {
    /// The named port a server listens on.
    #[record(label = "ALPC_CONNECTION_PORT")]
    Connection,
    /// The server's end of one connection.
    #[record(label = "ALPC_SERVER_COMMUNICATION_PORT")]
    ServerCommunication,
    /// The client's end of one connection.
    #[record(label = "ALPC_CLIENT_COMMUNICATION_PORT")]
    ClientCommunication,
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

/// One message queue of an ALPC port, or its wait queue.
#[record]
pub struct AlpcQueue {
    /// The `_ALPC_PORT` list head, for example `PendingQueue`.
    pub field: &'static str,
    /// The snake_case name of the queue.
    pub key: &'static str,
    /// The count that the port keeps for the queue (`<field>Length`). None if
    /// the port keeps no count.
    pub length: Option<u64>,
    /// The queued `_KALPC_MESSAGE`s. For the wait queue, the waiting
    /// `_ETHREAD`s.
    pub entries: Vec<VirtAddr>,
    pub termination: ListTermination,
}

/// A connection to an ALPC connection port, with its communication info
/// and the two ports that it connects.
#[record]
pub struct AlpcConnection {
    pub communication_info: VirtAddr,
    pub server_port: VirtAddr,
    /// The number of messages queued on the server port (main, large, and
    /// pending). None if ntoseye cannot read it.
    pub server_queued: Option<u64>,
    pub client_port: VirtAddr,
    /// The number of messages queued on the client port. None if ntoseye cannot
    /// read it.
    pub client_queued: Option<u64>,
    /// The `_EPROCESS` of the client.
    pub client_owner: VirtAddr,
    pub client_owner_name: Option<String>,
}

/// An `_ALPC_PORT` (`!alpc /p`). A field is None if this Windows build does
/// not have it, or if ntoseye cannot read it.
#[record]
pub struct AlpcPort {
    pub address: VirtAddr,
    pub name: Option<String>,
    pub pointer_count: i64,
    pub handle_count: i64,
    pub kind: Option<AlpcPortKind>,
    /// `u1.State`.
    #[record(hex)]
    pub state: Option<u64>,
    /// The `Type` bits of `u1.State`.
    pub port_type: Option<u64>,
    /// The PDB names of the one-bit `u1.s1` state flags that are set.
    pub state_flags: Vec<String>,
    /// The `_EPROCESS` that owns the port.
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
    /// `PortAttributes.Flags`.
    #[record(hex)]
    pub attribute_flags: Option<u64>,
    /// `PortAttributes.MaxMessageLength`.
    pub max_message_length: Option<u64>,
    pub queues: Vec<AlpcQueue>,
    pub direct_queue_length: Option<u64>,
    /// The connections of a connection port
    /// (`CommunicationInfo.CommunicationList`).
    pub connections: Vec<AlpcConnection>,
    /// How the walk of the connection list ended. None if there was no walk.
    pub connection_termination: Option<ListTermination>,
}

/// One `_KALPC_MESSAGE` pointer field: its PDB name, its snake_case name, and
/// its value.
#[record]
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

/// A `_KALPC_MESSAGE` (`!alpc /m`). A field is None if this Windows build
/// does not have it, or if ntoseye cannot read it.
#[record(impl)]
pub struct AlpcMessage {
    pub address: VirtAddr,
    pub message_id: Option<u64>,
    pub callback_id: Option<u64>,
    pub sequence_no: Option<u64>,
    /// `PortMessage.u2.s2.Type`.
    #[record(hex)]
    pub message_type: Option<u64>,
    pub data_length: Option<u64>,
    pub total_length: Option<u64>,
    /// `PortMessage.ClientId`, the sender.
    pub client_process_id: Option<u64>,
    pub client_thread_id: Option<u64>,
    /// `u1.State`.
    #[record(hex)]
    pub state: Option<u64>,
    /// The `QueueType` bits of `u1.State`.
    pub queue_type: Option<u64>,
    /// The `QueuePortType` bits of `u1.State`.
    pub queue_port_type: Option<u64>,
    /// The PDB names of the one-bit `u1.s1` state flags that are set.
    pub state_flags: Vec<String>,
    pub owner_port: VirtAddr,
    /// The port type of the owner port.
    pub owner_port_kind: Option<AlpcPortKind>,
    /// The port whose queue holds the message.
    pub port_queue: VirtAddr,
    pub port_queue_kind: Option<AlpcPortKind>,
    /// The `_EPROCESS` that owns the queue port.
    pub port_queue_owner: Option<VirtAddr>,
    pub port_queue_owner_name: Option<String>,
    pub cancel_sequence_no: Option<u64>,
    pub extension_buffer_size: Option<u64>,
    /// The pointer fields of the message that this build has.
    pub pointers: Vec<AlpcField>,
    /// The `_KALPC_MESSAGE_ATTRIBUTES` fields that this build has.
    pub attributes: Vec<AlpcField>,
}

#[record]
impl AlpcMessage {
    /// The `LPC_*` name of the low byte of the message type.
    #[record(getter)]
    pub fn message_type_name(&self) -> Option<&'static str> {
        self.message_type.and_then(lpc_message_type_name)
    }
}

/// A connection port that a process owns, and its connections.
#[record]
pub struct AlpcOwnedPort {
    #[record(hex)]
    pub handle: u64,
    pub port: VirtAddr,
    pub name: Option<String>,
    pub connections: Vec<AlpcConnection>,
    pub termination: ListTermination,
}

/// A client communication port that a process holds, and the ports that it
/// is connected to.
#[record]
pub struct AlpcClientPort {
    #[record(hex)]
    pub handle: u64,
    pub port: VirtAddr,
    /// The number of messages queued on the port. None if ntoseye cannot read it.
    pub queued: Option<u64>,
    pub connection_port: VirtAddr,
    pub connection_name: Option<String>,
    pub server_port: VirtAddr,
    /// The number of messages queued on the server port. None if ntoseye cannot
    /// read it.
    pub server_queued: Option<u64>,
    /// The `_EPROCESS` of the server. None if ntoseye cannot read it.
    pub server_owner: Option<VirtAddr>,
    pub server_owner_name: Option<String>,
}

/// The ALPC ports that a process holds handles to (`!alpc /lpp`).
#[record]
pub struct AlpcProcessPorts {
    pub process: ProcessInfo,
    /// The connection ports that the process owns.
    pub created: Vec<AlpcOwnedPort>,
    /// The client ports that the process holds.
    pub connected: Vec<AlpcClientPort>,
    /// The number of server communication ports that the process holds,
    /// which are its ends of connections to its own ports.
    pub server_ports: usize,
    pub scanned_handles: usize,
    /// The handle count that the table reports.
    pub advertised_handles: usize,
    /// The number of handle-table entries that ntoseye could not read.
    pub skipped_entries: usize,
    /// The number of ALPC port handles left out of `created` and `connected`
    /// because ntoseye could not read the port's kind or its connection.
    pub unreadable_ports: usize,
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
        let kind = ends
            .and_then(|[connection, server, client]| {
                [
                    (connection, AlpcPortKind::Connection),
                    (server, AlpcPortKind::ServerCommunication),
                    (client, AlpcPortKind::ClientCommunication),
                ]
                .into_iter()
                .find_map(|(end, kind)| (end == address).then_some(kind))
            })
            // The communication info can be paged out; the state word's Type
            // bits say the same.
            .or_else(|| match state_bits(&port, ["Type"]).1 {
                [Some(1)] => Some(AlpcPortKind::Connection),
                [Some(2)] => Some(AlpcPortKind::ClientCommunication),
                [Some(3)] => Some(AlpcPortKind::ServerCommunication),
                _ => None,
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
        // The type's name lives in paged pool, which a KD memory source may
        // not reach; the type object itself is `nt!AlpcPortObjectType`.
        let is_port = match header.type_name.as_deref() {
            Some(name) => name == ALPC_PORT_TYPE,
            None => header.type_object.is_some_and(|object| {
                self.guest()
                    .and_then(|guest| guest.ntoskrnl.symbol("AlpcPortObjectType"))
                    .and_then(|symbol| symbol.read_pointer())
                    .is_ok_and(|port_type| port_type == object)
            }),
        };
        if !is_port {
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
        let (infos, termination) = walk_list_records(self, info + link, link, MAX_LIST_ENTRIES);
        let connections = infos
            .into_iter()
            .map(|communication_info| {
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
    pub fn alpc_port(&self, address: VirtAddr) -> Result<AlpcPort> {
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
                        walk_list_records(self, body + head, link, MAX_LIST_ENTRIES)
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
        Ok(AlpcPort {
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
    pub fn alpc_message(&self, address: VirtAddr) -> Result<AlpcMessage> {
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
        Ok(AlpcMessage {
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
        let mut owners = OwnerNames::default();
        let mut seen = HashSet::new();
        let mut created = Vec::new();
        let mut connected = Vec::new();
        let mut server_ports = 0;
        let mut unreadable_ports = 0;
        for entry in &handles.entries {
            let (
                DiagnosticValue::Available(port),
                DiagnosticValue::Available(Some(type_name)),
                DiagnosticValue::Available(name),
            ) = (&entry.object, &entry.type_name, &entry.name)
            else {
                continue;
            };
            if type_name != ALPC_PORT_TYPE {
                continue;
            }
            let port = *port;
            if !seen.insert(port) {
                continue;
            }
            let Ok(core) = self.alpc_port_core(types, port) else {
                unreadable_ports += 1;
                continue;
            };
            match (core.kind, core.ends) {
                (Some(AlpcPortKind::Connection), _) => {
                    if core.owner != handles.process.eprocess {
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
                _ => unreadable_ports += 1,
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
            unreadable_ports,
        })
    }
}
