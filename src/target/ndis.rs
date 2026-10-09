//! NDIS (`!ndiskd.*`): the miniports ndis.sys keeps on its global list, the
//! miniport drivers, and for one miniport its driver, filter stack, protocol
//! bindings, and pending OID request, decoded with ndis.sys's own PDB types.

use std::sync::Arc;

use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::layout::{StructRef, TypeInfo, Types, utf16le_lossy};
use crate::target::{ListCursor, ListTermination, Target};
use crate::types::VirtAddr;

const MAX_MINIPORTS: usize = 512;
const MAX_DRIVERS: usize = 256;
const MAX_FILTERS: usize = 64;
const MAX_OPENS: usize = 256;
const MAX_PROTOCOLS: usize = 256;
/// The filter modules of every miniport, on `ndis!ndisGlobalFilterList`.
const MAX_GLOBAL_FILTERS: usize = 4096;
const MAX_NBL_CHAIN: usize = 4096;
const MAX_NET_BUFFERS: usize = 1024;
/// The most MDLs of one NET_BUFFER's chain read for its data.
const MAX_NET_BUFFER_MDLS: usize = 256;
/// The most bytes of a NET_BUFFER's data `!ndiskd.nbl -data` reads.
pub const MAX_NET_BUFFER_DATA: usize = 0x10000;
/// The most UTF-16 units of a PnP instance ID read; Windows caps device
/// instance IDs at 200 characters (`MAX_DEVICE_ID_LEN`).
const MAX_INSTANCE_ID: usize = 256;
const PAGE_SIZE: u64 = 0x1000;

/// `NDIS_LINK_SPEED_UNKNOWN`: a link speed the miniport has not reported.
pub const LINK_SPEED_UNKNOWN: u64 = u64::MAX;

/// ndis.sys's list heads, each a pointer to the first block. The public
/// x64 PDB names these C++ globals only by their decorated names; the plain
/// name comes first for a PDB that has it.
const MINIPORT_LIST: &[&str] = &[
    "ndis!ndisMiniportList",
    "ndis!?ndisMiniportList@@3PEAU_NDIS_MINIPORT_BLOCK@@EA",
];
const DRIVER_LIST: &[&str] = &[
    "ndis!ndisMiniDriverList",
    "ndis!?ndisMiniDriverList@@3PEAU_NDIS_M_DRIVER_BLOCK@@EA",
];
const PROTOCOL_LIST: &[&str] = &[
    "ndis!ndisProtocolList",
    "ndis!?ndisProtocolList@@3PEAU_NDIS_PROTOCOL_BLOCK@@EA",
];
const FILTER_DRIVER_LIST: &[&str] = &[
    "ndis!ndisFilterDriverList",
    "ndis!?ndisFilterDriverList@@3PEAU_NDIS_FILTER_DRIVER_BLOCK@@EA",
];
const GLOBAL_FILTER_LIST: &[&str] = &[
    "ndis!ndisGlobalFilterList",
    "ndis!?ndisGlobalFilterList@@3PEAU_NDIS_FILTER_BLOCK@@EA",
];

/// The `NDIS_NBL_FLAGS_*` bits of an NBL's `NblFlags`, from `nbl.h`.
const NBL_FLAG_NAMES: &[(u32, &str)] = &[
    (0x0000_0001, "SEND_READ_ONLY"),
    (0x0000_0002, "RECV_READ_ONLY"),
    (0x0000_0100, "HD_SPLIT"),
    (0x0000_0200, "IS_IPV4"),
    (0x0000_0400, "IS_IPV6"),
    (0x0000_0800, "IS_TCP"),
    (0x0000_1000, "IS_UDP"),
    (0x0000_2000, "SPLIT_AT_UPPER_LAYER_PROTOCOL_HEADER"),
    (0x0000_4000, "SPLIT_AT_UPPER_LAYER_PROTOCOL_PAYLOAD"),
    (0x0000_8000, "IS_LOOPBACK_PACKET"),
];

/// The `NDIS_NBL_FLAGS_*` names of the bits set in `flags`, without the
/// prefix, then the bits `nbl.h` does not name in hex.
pub fn nbl_flag_names(flags: u32) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest = flags;
    for &(bit, name) in NBL_FLAG_NAMES {
        if flags & bit != 0 {
            names.push(name.to_string());
            rest &= !bit;
        }
    }
    if rest != 0 {
        names.push(format!("{rest:#x}"));
    }
    names
}

/// The OIDs of `ntddndis.h` a miniport sees most, by value, sorted for a
/// binary search. The header defines them as macros, so no PDB has them.
const OID_NAMES: &[(u32, &str)] = &[
    (0x00010101, "OID_GEN_SUPPORTED_LIST"),
    (0x00010102, "OID_GEN_HARDWARE_STATUS"),
    (0x00010103, "OID_GEN_MEDIA_SUPPORTED"),
    (0x00010104, "OID_GEN_MEDIA_IN_USE"),
    (0x00010105, "OID_GEN_MAXIMUM_LOOKAHEAD"),
    (0x00010106, "OID_GEN_MAXIMUM_FRAME_SIZE"),
    (0x00010107, "OID_GEN_LINK_SPEED"),
    (0x00010108, "OID_GEN_TRANSMIT_BUFFER_SPACE"),
    (0x00010109, "OID_GEN_RECEIVE_BUFFER_SPACE"),
    (0x0001010a, "OID_GEN_TRANSMIT_BLOCK_SIZE"),
    (0x0001010b, "OID_GEN_RECEIVE_BLOCK_SIZE"),
    (0x0001010c, "OID_GEN_VENDOR_ID"),
    (0x0001010d, "OID_GEN_VENDOR_DESCRIPTION"),
    (0x0001010e, "OID_GEN_CURRENT_PACKET_FILTER"),
    (0x0001010f, "OID_GEN_CURRENT_LOOKAHEAD"),
    (0x00010110, "OID_GEN_DRIVER_VERSION"),
    (0x00010111, "OID_GEN_MAXIMUM_TOTAL_SIZE"),
    (0x00010112, "OID_GEN_PROTOCOL_OPTIONS"),
    (0x00010113, "OID_GEN_MAC_OPTIONS"),
    (0x00010114, "OID_GEN_MEDIA_CONNECT_STATUS"),
    (0x00010115, "OID_GEN_MAXIMUM_SEND_PACKETS"),
    (0x00010116, "OID_GEN_VENDOR_DRIVER_VERSION"),
    (0x00010117, "OID_GEN_SUPPORTED_GUIDS"),
    (0x00010118, "OID_GEN_NETWORK_LAYER_ADDRESSES"),
    (0x00010119, "OID_GEN_TRANSPORT_HEADER_OFFSET"),
    (0x00010201, "OID_GEN_MEDIA_CAPABILITIES"),
    (0x00010202, "OID_GEN_PHYSICAL_MEDIUM"),
    (0x00010203, "OID_GEN_RECEIVE_SCALE_CAPABILITIES"),
    (0x00010204, "OID_GEN_RECEIVE_SCALE_PARAMETERS"),
    (0x00010205, "OID_GEN_MAC_ADDRESS"),
    (0x00010206, "OID_GEN_MAX_LINK_SPEED"),
    (0x00010207, "OID_GEN_LINK_STATE"),
    (0x00010208, "OID_GEN_LINK_PARAMETERS"),
    (0x00010209, "OID_GEN_INTERRUPT_MODERATION"),
    (0x0001020d, "OID_GEN_ENUMERATE_PORTS"),
    (0x0001020e, "OID_GEN_PORT_STATE"),
    (0x0001020f, "OID_GEN_PORT_AUTHENTICATION_PARAMETERS"),
    (0x00010210, "OID_GEN_TIMEOUT_DPC_REQUEST_CAPABILITIES"),
    (0x00010211, "OID_GEN_PCI_DEVICE_CUSTOM_PROPERTIES"),
    (0x00010213, "OID_GEN_PHYSICAL_MEDIUM_EX"),
    (0x0001021a, "OID_GEN_MACHINE_NAME"),
    (0x0001021b, "OID_GEN_RNDIS_CONFIG_PARAMETER"),
    (0x0001021c, "OID_GEN_VLAN_ID"),
    (0x0001021d, "OID_GEN_MINIPORT_RESTART_ATTRIBUTES"),
    (0x0001021e, "OID_GEN_HD_SPLIT_PARAMETERS"),
    (0x0001021f, "OID_GEN_RECEIVE_HASH"),
    (0x00010220, "OID_GEN_HD_SPLIT_CURRENT_CONFIG"),
    (0x00010221, "OID_RECEIVE_FILTER_HARDWARE_CAPABILITIES"),
    (0x00010222, "OID_RECEIVE_FILTER_GLOBAL_PARAMETERS"),
    (0x00010223, "OID_RECEIVE_FILTER_ALLOCATE_QUEUE"),
    (0x00010224, "OID_RECEIVE_FILTER_FREE_QUEUE"),
    (0x00010225, "OID_RECEIVE_FILTER_ENUM_QUEUES"),
    (0x00010226, "OID_RECEIVE_FILTER_QUEUE_PARAMETERS"),
    (0x00010227, "OID_RECEIVE_FILTER_SET_FILTER"),
    (0x00010228, "OID_RECEIVE_FILTER_CLEAR_FILTER"),
    (0x00010229, "OID_RECEIVE_FILTER_ENUM_FILTERS"),
    (0x0001022a, "OID_RECEIVE_FILTER_PARAMETERS"),
    (0x0001022b, "OID_RECEIVE_FILTER_QUEUE_ALLOCATION_COMPLETE"),
    (0x0001022d, "OID_RECEIVE_FILTER_CURRENT_CAPABILITIES"),
    (0x0001022e, "OID_NIC_SWITCH_HARDWARE_CAPABILITIES"),
    (0x0001022f, "OID_NIC_SWITCH_CURRENT_CAPABILITIES"),
    (0x00010230, "OID_RECEIVE_FILTER_MOVE_FILTER"),
    (0x00010237, "OID_NIC_SWITCH_CREATE_SWITCH"),
    (0x00010238, "OID_NIC_SWITCH_PARAMETERS"),
    (0x00010239, "OID_NIC_SWITCH_DELETE_SWITCH"),
    (0x00010240, "OID_NIC_SWITCH_ENUM_SWITCHES"),
    (0x00010241, "OID_NIC_SWITCH_CREATE_VPORT"),
    (0x00010242, "OID_NIC_SWITCH_VPORT_PARAMETERS"),
    (0x00010243, "OID_NIC_SWITCH_ENUM_VPORTS"),
    (0x00010244, "OID_NIC_SWITCH_DELETE_VPORT"),
    (0x00010245, "OID_NIC_SWITCH_ALLOCATE_VF"),
    (0x00010246, "OID_NIC_SWITCH_FREE_VF"),
    (0x00010247, "OID_NIC_SWITCH_VF_PARAMETERS"),
    (0x00010248, "OID_NIC_SWITCH_ENUM_VFS"),
    (0x00010280, "OID_GEN_PROMISCUOUS_MODE"),
    (0x00010281, "OID_GEN_LAST_CHANGE"),
    (0x00010282, "OID_GEN_DISCONTINUITY_TIME"),
    (0x00010283, "OID_GEN_OPERATIONAL_STATUS"),
    (0x00010284, "OID_GEN_XMIT_LINK_SPEED"),
    (0x00010285, "OID_GEN_RCV_LINK_SPEED"),
    (0x00010286, "OID_GEN_UNKNOWN_PROTOS"),
    (0x00010287, "OID_GEN_INTERFACE_INFO"),
    (0x00010288, "OID_GEN_ADMIN_STATUS"),
    (0x00010289, "OID_GEN_ALIAS"),
    (0x0001028a, "OID_GEN_MEDIA_CONNECT_STATUS_EX"),
    (0x0001028b, "OID_GEN_LINK_SPEED_EX"),
    (0x0001028c, "OID_GEN_MEDIA_DUPLEX_STATE"),
    (0x0001028d, "OID_GEN_IP_OPER_STATUS"),
    (0x00020101, "OID_GEN_XMIT_OK"),
    (0x00020102, "OID_GEN_RCV_OK"),
    (0x00020103, "OID_GEN_XMIT_ERROR"),
    (0x00020104, "OID_GEN_RCV_ERROR"),
    (0x00020105, "OID_GEN_RCV_NO_BUFFER"),
    (0x00020106, "OID_GEN_STATISTICS"),
    (0x00020120, "OID_GEN_CO_MINIMUM_LINK_SPEED"),
    (0x00020201, "OID_GEN_DIRECTED_BYTES_XMIT"),
    (0x00020202, "OID_GEN_DIRECTED_FRAMES_XMIT"),
    (0x00020203, "OID_GEN_MULTICAST_BYTES_XMIT"),
    (0x00020204, "OID_GEN_MULTICAST_FRAMES_XMIT"),
    (0x00020205, "OID_GEN_BROADCAST_BYTES_XMIT"),
    (0x00020206, "OID_GEN_BROADCAST_FRAMES_XMIT"),
    (0x00020207, "OID_GEN_DIRECTED_BYTES_RCV"),
    (0x00020208, "OID_GEN_DIRECTED_FRAMES_RCV"),
    (0x00020209, "OID_GEN_MULTICAST_BYTES_RCV"),
    (0x0002020a, "OID_GEN_MULTICAST_FRAMES_RCV"),
    (0x0002020b, "OID_GEN_BROADCAST_BYTES_RCV"),
    (0x0002020c, "OID_GEN_BROADCAST_FRAMES_RCV"),
    (0x0002020d, "OID_GEN_RCV_CRC_ERROR"),
    (0x0002020e, "OID_GEN_TRANSMIT_QUEUE_LENGTH"),
    (0x0002020f, "OID_GEN_GET_TIME_CAPS"),
    (0x00020210, "OID_GEN_GET_NETCARD_TIME"),
    (0x00020211, "OID_GEN_NETCARD_LOAD"),
    (0x00020212, "OID_GEN_DEVICE_PROFILE"),
    (0x00020213, "OID_GEN_INIT_TIME_MS"),
    (0x00020214, "OID_GEN_RESET_COUNTS"),
    (0x00020215, "OID_GEN_MEDIA_SENSE_COUNTS"),
    (0x00020216, "OID_GEN_FRIENDLY_NAME"),
    (0x00020219, "OID_GEN_BYTES_RCV"),
    (0x0002021a, "OID_GEN_BYTES_XMIT"),
    (0x0002021b, "OID_GEN_RCV_DISCARDS"),
    (0x0002021c, "OID_GEN_XMIT_DISCARDS"),
    (0x0002021d, "OID_TCP_RSC_STATISTICS"),
    (0x00020221, "OID_GEN_CO_BYTES_XMIT_OUTSTANDING"),
    (0x01010101, "OID_802_3_PERMANENT_ADDRESS"),
    (0x01010102, "OID_802_3_CURRENT_ADDRESS"),
    (0x01010103, "OID_802_3_MULTICAST_LIST"),
    (0x01010104, "OID_802_3_MAXIMUM_LIST_SIZE"),
    (0x01010105, "OID_802_3_MAC_OPTIONS"),
    (0x0101010a, "OID_OFFLOAD_ENCAPSULATION"),
    (0x01010208, "OID_802_3_ADD_MULTICAST_ADDRESS"),
    (0x01010209, "OID_802_3_DELETE_MULTICAST_ADDRESS"),
    (0x01020101, "OID_802_3_RCV_ERROR_ALIGNMENT"),
    (0x01020102, "OID_802_3_XMIT_ONE_COLLISION"),
    (0x01020103, "OID_802_3_XMIT_MORE_COLLISIONS"),
    (0x01020201, "OID_802_3_XMIT_DEFERRED"),
    (0x01020202, "OID_802_3_XMIT_MAX_COLLISIONS"),
    (0x01020203, "OID_802_3_RCV_OVERRUN"),
    (0x01020204, "OID_802_3_XMIT_UNDERRUN"),
    (0x01020205, "OID_802_3_XMIT_HEARTBEAT_FAILURE"),
    (0x01020206, "OID_802_3_XMIT_TIMES_CRS_LOST"),
    (0x01020207, "OID_802_3_XMIT_LATE_COLLISIONS"),
    (0xfc010201, "OID_TCP_TASK_OFFLOAD"),
    (0xfc01020b, "OID_TCP_OFFLOAD_CURRENT_CONFIG"),
    (0xfc01020c, "OID_TCP_OFFLOAD_PARAMETERS"),
    (0xfc01020d, "OID_TCP_OFFLOAD_HARDWARE_CAPABILITIES"),
    (0xfc050001, "OID_QOS_HARDWARE_CAPABILITIES"),
    (0xfc050002, "OID_QOS_CURRENT_CAPABILITIES"),
    (0xfc050003, "OID_QOS_PARAMETERS"),
    (0xfc050004, "OID_QOS_OPERATIONAL_PARAMETERS"),
    (0xfc050005, "OID_QOS_REMOTE_PARAMETERS"),
    (0xfd010100, "OID_PNP_CAPABILITIES"),
    (0xfd010101, "OID_PNP_SET_POWER"),
    (0xfd010102, "OID_PNP_QUERY_POWER"),
    (0xfd010103, "OID_PNP_ADD_WAKE_UP_PATTERN"),
    (0xfd010104, "OID_PNP_REMOVE_WAKE_UP_PATTERN"),
    (0xfd010105, "OID_PNP_WAKE_UP_PATTERN_LIST"),
    (0xfd010106, "OID_PNP_ENABLE_WAKE_UP"),
    (0xfd010107, "OID_PM_CURRENT_CAPABILITIES"),
    (0xfd010108, "OID_PM_HARDWARE_CAPABILITIES"),
    (0xfd010109, "OID_PM_PARAMETERS"),
    (0xfd01010a, "OID_PM_ADD_WOL_PATTERN"),
    (0xfd01010b, "OID_PM_REMOVE_WOL_PATTERN"),
    (0xfd01010c, "OID_PM_WOL_PATTERN_LIST"),
    (0xfd01010d, "OID_PM_ADD_PROTOCOL_OFFLOAD"),
    (0xfd01010e, "OID_PM_GET_PROTOCOL_OFFLOAD"),
    (0xfd01010f, "OID_PM_REMOVE_PROTOCOL_OFFLOAD"),
    (0xfd010110, "OID_PM_PROTOCOL_OFFLOAD_LIST"),
    (0xfd020200, "OID_PNP_WAKE_UP_OK"),
    (0xfd020201, "OID_PNP_WAKE_UP_ERROR"),
];

/// The `ntddndis.h` name of `oid`, when it is one of [`OID_NAMES`].
pub fn oid_name(oid: u32) -> Option<&'static str> {
    OID_NAMES
        .binary_search_by_key(&oid, |&(value, _)| value)
        .ok()
        .map(|index| OID_NAMES[index].1)
}

/// A link speed in bits per second, as NDIS keeps it, in the largest unit
/// it reaches, with up to two decimals: `10 Gbps`, `2.5 Gbps`, `100 Mbps`.
pub fn link_speed_text(bits_per_second: u64) -> String {
    if bits_per_second == LINK_SPEED_UNKNOWN {
        return "unknown".into();
    }
    for (unit, name) in [
        (1_000_000_000_000, "Tbps"),
        (1_000_000_000, "Gbps"),
        (1_000_000, "Mbps"),
        (1_000, "kbps"),
    ] {
        if bits_per_second >= unit {
            let whole = bits_per_second / unit;
            // Hundredths, truncated: a link is never faster than it says.
            let hundredths = bits_per_second % unit / (unit / 100);
            return match hundredths {
                0 => format!("{whole} {name}"),
                h if h % 10 == 0 => format!("{whole}.{} {name}", h / 10),
                h => format!("{whole}.{h:02} {name}"),
            };
        }
    }
    format!("{bits_per_second} bps")
}

/// The name `variants` gives `value` without `prefix` (`Running` for
/// `NdisMiniportRunning`), as `!ndiskd` shows states; the whole name when
/// nothing would be left, and the value in hex when the enum has no name
/// for it.
pub fn enum_text(variants: &[(String, i64)], value: u64, prefix: &str) -> String {
    let Some((name, _)) = variants
        .iter()
        .find(|(_, variant)| i64::try_from(value).is_ok_and(|value| value == *variant))
    else {
        return format!("{value:#x}");
    };
    match name.strip_prefix(prefix) {
        Some(rest) if !rest.is_empty() => rest.to_string(),
        _ => name.clone(),
    }
}

/// Why a walk of a NULL-terminated chain stopped short; reaching the null
/// link that ends the chain is no reason.
fn chain_stop(termination: ListTermination) -> Option<String> {
    match termination {
        ListTermination::Null | ListTermination::Head => None,
        other => other.diagnostic(),
    }
}

/// A miniport as `!ndiskd.miniports` lists it.
#[derive(Debug, Clone)]
pub struct NdisMiniport {
    pub address: VirtAddr,
    /// `MiniportName`, the adapter's device name (`\DEVICE\{GUID}`).
    pub name: String,
    /// `pAdapterInstanceName`, the adapter's friendly name.
    pub friendly_name: Option<String>,
    pub driver: VirtAddr,
    /// The driver's service name, from its `_NDIS_M_DRIVER_BLOCK`.
    pub driver_name: Option<String>,
    pub state: String,
    pub pnp_state: String,
    pub media_connect: String,
    pub connected: bool,
    pub xmit_link_speed: u64,
    pub rcv_link_speed: u64,
    pub power: String,
    pub if_index: u32,
}

/// A miniport the list names but whose block does not read.
#[derive(Debug, Clone)]
pub struct NdisUnreadable {
    pub address: VirtAddr,
    pub error: String,
}

/// A miniport as a list shows it, or why its block does not read.
pub type NdisMiniportListEntry = std::result::Result<NdisMiniport, NdisUnreadable>;

/// The miniports on `ndis!ndisMiniportList` (`!ndiskd.miniports`).
#[derive(Debug, Clone)]
pub struct NdisMiniportList {
    pub miniports: Vec<NdisMiniportListEntry>,
    /// Why the walk stopped before the end of the list.
    pub stopped: Option<String>,
}

/// A miniport driver (`_NDIS_M_DRIVER_BLOCK`).
#[derive(Debug, Clone)]
pub struct NdisDriver {
    pub address: VirtAddr,
    pub service_name: String,
    pub image_name: String,
    /// The loaded module the driver's code is in, the name its PDB's types
    /// go by.
    pub module: Option<String>,
    pub driver_object: VirtAddr,
    pub ndis_version: (u8, u8),
    /// The driver's own version, from its NDIS 6 characteristics.
    pub driver_version: Option<(u8, u8)>,
    /// The miniports on the driver's `MiniportQueue`.
    pub miniports: Vec<VirtAddr>,
    pub miniports_stopped: Option<String>,
}

/// The miniport drivers on `ndis!ndisMiniDriverList` (`!ndiskd.minidriver`).
#[derive(Debug, Clone)]
pub struct NdisDriverList {
    pub drivers: Vec<std::result::Result<NdisDriver, NdisUnreadable>>,
    pub stopped: Option<String>,
}

/// An `_NDIS_OID_REQUEST`.
#[derive(Debug, Clone)]
pub struct NdisOidRequest {
    pub address: VirtAddr,
    /// `RequestType` without its `NdisRequest` prefix (`QueryInformation`).
    pub request_type: String,
    pub oid: u32,
    pub port: u32,
    /// `Timeout` in seconds; 0 lets NDIS pick one.
    pub timeout: u32,
    pub buffer: VirtAddr,
    /// `InformationBufferLength`, or a method request's `InputBufferLength`.
    pub buffer_length: u32,
    /// A method request's `OutputBufferLength` and `MethodId`.
    pub method: Option<(u32, u32)>,
}

/// A filter module on a miniport's stack (`_NDIS_FILTER_BLOCK`).
#[derive(Debug, Clone)]
pub struct NdisFilter {
    pub address: VirtAddr,
    /// `FilterFriendlyName`.
    pub name: Option<String>,
    pub driver: VirtAddr,
    /// The filter driver's `ImageName`.
    pub driver_image: Option<String>,
    /// The miniport the filter module is attached to.
    pub miniport: VirtAddr,
    /// That miniport's friendly name.
    pub miniport_name: Option<String>,
    pub state: String,
    /// `FilterModuleContext`, the filter driver's own context.
    pub context: VirtAddr,
    pub pending_oid: Option<std::result::Result<NdisOidRequest, String>>,
}

/// A protocol's binding to a miniport (`_NDIS_OPEN_BLOCK`).
#[derive(Debug, Clone)]
pub struct NdisOpen {
    pub address: VirtAddr,
    pub protocol: VirtAddr,
    pub protocol_name: Option<String>,
    /// `ProtocolBindingContext`, the protocol driver's own context.
    pub context: VirtAddr,
}

/// One miniport in detail (`!ndiskd.miniport`).
#[derive(Debug, Clone)]
pub struct NdisMiniportDetail {
    pub summary: NdisMiniport,
    /// Whether the miniport is on `ndis!ndisMiniportList`.
    pub listed: bool,
    pub ndis_version: (u8, u8),
    /// `MiniportAdapterContext`, the context the miniport driver gave
    /// NdisMSetMiniportAttributes.
    pub adapter_context: VirtAddr,
    pub driver: std::result::Result<NdisDriver, String>,
    /// The functional device object NDIS created; none for a virtual
    /// miniport.
    pub device_object: VirtAddr,
    pub pdo: VirtAddr,
    pub instance_id: Option<String>,
    pub medium: String,
    pub physical_medium: String,
    pub duplex: String,
    pub oper_status: String,
    pub net_luid: u64,
    pub flags: u32,
    pub pnp_flags: u32,
    pub references: Option<u64>,
    /// `ResetStatus`, the NTSTATUS of the last reset.
    pub reset_status: u32,
    /// `InternalResetCount` and `MiniportResetCount`.
    pub resets: (u64, u64),
    pub pending_oid: Option<std::result::Result<NdisOidRequest, String>>,
    pub pending_return_nbls: u32,
    pub filters: Vec<NdisFilter>,
    pub filters_stopped: Option<String>,
    pub num_opens: u32,
    pub opens: Vec<NdisOpen>,
    pub opens_stopped: Option<String>,
}

/// A filter module as a list shows it, or why its block does not read.
pub type NdisFilterListEntry = std::result::Result<NdisFilter, NdisUnreadable>;

/// The filter modules on `ndis!ndisGlobalFilterList` (`!ndiskd.filter`).
#[derive(Debug, Clone)]
pub struct NdisFilterList {
    pub filters: Vec<NdisFilterListEntry>,
    pub stopped: Option<String>,
}

/// One filter module in detail (`!ndiskd.filter <filter>`).
#[derive(Debug, Clone)]
pub struct NdisFilterDetail {
    pub filter: NdisFilter,
    /// Whether the filter is on `ndis!ndisGlobalFilterList`.
    pub listed: bool,
    /// The filter driver's friendly name.
    pub driver_name: Option<String>,
    /// The filter modules above and below it on the miniport's stack; null
    /// at the top and at the bottom.
    pub higher: VirtAddr,
    pub lower: VirtAddr,
    /// The link the filter last saw indicated from below.
    pub media_connect: String,
    pub xmit_link_speed: u64,
    pub rcv_link_speed: u64,
    pub if_index: u32,
    pub flags: u32,
    pub references: Option<u64>,
    /// NBLs and status indications NDIS dropped because the filter was not
    /// running.
    pub dropped_receive_nbls: i32,
    pub dropped_send_nbls: i32,
    pub dropped_status_indications: u32,
}

/// A filter driver (`_NDIS_FILTER_DRIVER_BLOCK`).
#[derive(Debug, Clone)]
pub struct NdisFilterDriver {
    pub address: VirtAddr,
    /// `FriendlyName`, `UniqueName` (the filter's GUID), and `ServiceName`
    /// from the characteristics the driver registered.
    pub friendly_name: String,
    pub unique_name: String,
    pub service_name: String,
    pub image_name: String,
    pub module: Option<String>,
    pub driver_object: VirtAddr,
    /// `FilterDriverContext`, the context the driver gave
    /// NdisFRegisterFilterDriver.
    pub context: VirtAddr,
    pub flags: u32,
    pub ndis_version: (u8, u8),
    pub driver_version: (u8, u8),
    /// The filter modules on the driver's `FilterQueue`.
    pub filters: Vec<VirtAddr>,
    pub filters_stopped: Option<String>,
}

/// The filter drivers on `ndis!ndisFilterDriverList`
/// (`!ndiskd.filterdriver`).
#[derive(Debug, Clone)]
pub struct NdisFilterDriverList {
    pub drivers: Vec<std::result::Result<NdisFilterDriver, NdisUnreadable>>,
    pub stopped: Option<String>,
}

/// A protocol driver (`_NDIS_PROTOCOL_BLOCK`).
#[derive(Debug, Clone)]
pub struct NdisProtocol {
    pub address: VirtAddr,
    pub name: String,
    pub image_name: Option<String>,
    pub ndis_version: (u8, u8),
    pub driver_version: (u8, u8),
    /// `ProtocolDriverContext`, the context the driver gave
    /// NdisRegisterProtocolDriver.
    pub context: VirtAddr,
    pub flags: u32,
    /// `BindAdapterHandlerEx`, which places the protocol's code.
    pub bind_handler: VirtAddr,
    /// The bindings on its `OpenQueue`, along `ProtocolNextOpen`.
    pub opens: Vec<VirtAddr>,
    pub opens_stopped: Option<String>,
}

/// The protocol drivers on `ndis!ndisProtocolList` (`!ndiskd.protocol`).
#[derive(Debug, Clone)]
pub struct NdisProtocolList {
    pub protocols: Vec<std::result::Result<NdisProtocol, NdisUnreadable>>,
    pub stopped: Option<String>,
}

/// A protocol's binding as the protocol sees it: the miniport it opened.
#[derive(Debug, Clone)]
pub struct NdisProtocolBinding {
    pub open: VirtAddr,
    pub miniport: VirtAddr,
    pub miniport_name: Option<String>,
    /// `ProtocolBindingContext`, the protocol's own context for the binding.
    pub context: VirtAddr,
}

/// One protocol driver in detail (`!ndiskd.protocol <protocol>`).
#[derive(Debug, Clone)]
pub struct NdisProtocolDetail {
    pub protocol: NdisProtocol,
    /// Whether the protocol is on `ndis!ndisProtocolList`.
    pub listed: bool,
    /// `BindAdapterHandlerEx` as a symbol.
    pub bind_handler_name: Option<String>,
    pub bindings: Vec<NdisProtocolBinding>,
    /// Why the binding walk stopped short.
    pub bindings_stopped: Option<String>,
}

/// Whose OID request NDIS is waiting on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NdisOidOwner {
    Miniport,
    Filter,
}

/// An OID request a miniport or filter has not completed (`!ndiskd.oid`).
#[derive(Debug, Clone)]
pub struct NdisPendingOid {
    pub owner: NdisOidOwner,
    pub address: VirtAddr,
    /// The miniport's friendly name, or the filter module's.
    pub name: Option<String>,
    pub request: std::result::Result<NdisOidRequest, String>,
}

/// The pending OID requests of every miniport and filter module.
#[derive(Debug, Clone)]
pub struct NdisPendingOids {
    pub pending: Vec<NdisPendingOid>,
    pub miniports: usize,
    pub filters: usize,
    /// Why a walk stopped short, or a block that did not read.
    pub problems: Vec<String>,
}

/// A `_NET_BUFFER`: one frame of a NET_BUFFER_LIST.
#[derive(Debug, Clone)]
pub struct NdisNetBuffer {
    pub address: VirtAddr,
    pub next: VirtAddr,
    /// The MDL the data starts in, and where in it.
    pub current_mdl: VirtAddr,
    pub current_mdl_offset: u32,
    pub data_length: u32,
    /// Where the data starts from the start of `mdl_chain`; the bytes
    /// before it are the backfill.
    pub data_offset: u32,
    pub mdl_chain: VirtAddr,
}

/// A `_NET_BUFFER_LIST` and its NET_BUFFERs (`!ndiskd.nbl`).
#[derive(Debug, Clone)]
pub struct NdisNbl {
    pub address: VirtAddr,
    pub next: VirtAddr,
    pub parent: VirtAddr,
    pub context: VirtAddr,
    pub pool: VirtAddr,
    /// `SourceHandle`, the NDIS handle of the miniport, filter module, or
    /// binding that owns the NBL on its way.
    pub source_handle: VirtAddr,
    /// What `source_handle` is, when it is a miniport, filter module, or
    /// binding NDIS knows.
    pub source: Option<String>,
    pub flags: u32,
    pub nbl_flags: u32,
    pub child_ref_count: i32,
    /// `Status`, the NDIS_STATUS the NBL completes with.
    pub status: u32,
    pub net_buffers: Vec<NdisNetBuffer>,
    pub net_buffers_stopped: Option<String>,
}

/// ndis.sys's layouts and enums the commands share, resolved once per
/// command.
struct NdisTypes<'a> {
    types: Types<'a>,
    miniport: Arc<TypeInfo>,
    driver: Arc<TypeInfo>,
    miniport_state: Vec<(String, i64)>,
    pnp_state: Vec<(String, i64)>,
    connect_state: Vec<(String, i64)>,
    duplex_state: Vec<(String, i64)>,
    power_state: Vec<(String, i64)>,
    medium: Vec<(String, i64)>,
    physical_medium: Vec<(String, i64)>,
    oper_status: Vec<(String, i64)>,
    filter_state: Vec<(String, i64)>,
    request_type: Vec<(String, i64)>,
}

impl<'a> NdisTypes<'a> {
    fn at(&self, name: &str, address: VirtAddr) -> Result<StructRef<'a>> {
        Ok(self
            .types
            .struct_with_layout(ndis_layout(self.types, name)?, address)
            .prefetch())
    }

    fn miniport_at(&self, address: VirtAddr) -> StructRef<'a> {
        self.types
            .struct_with_layout(Arc::clone(&self.miniport), address)
    }

    fn driver_at(&self, address: VirtAddr) -> StructRef<'a> {
        self.types
            .struct_with_layout(Arc::clone(&self.driver), address)
            .prefetch()
    }

    /// The `_UNICODE_STRING` a pointer field names; `None` for a null one.
    fn string_behind(&self, block: &StructRef<'_>, field: &str) -> Result<Option<String>> {
        let pointer = block.read_pointer(field)?;
        if pointer.is_zero() {
            return Ok(None);
        }
        Ok(Some(
            self.at("_UNICODE_STRING", pointer)?.read_unicode_string()?,
        ))
    }
}

/// The NDIS object header (`Type`, `Size`) of each kind of block an NBL's
/// `SourceHandle` can be, read from a block of that kind on NDIS's lists;
/// `None` when no such block reads.
struct NdisHandleOwners {
    miniport: Option<(u64, u64)>,
    filter: Option<(u64, u64)>,
    open: Option<(u64, u64)>,
}

fn ndis_layout(types: Types<'_>, name: &str) -> Result<Arc<TypeInfo>> {
    types.layout(format!("ndis!{name}")).map_err(|_| {
        Error::DebugInfo(format!(
            "ndis's symbols do not describe {name}; is ndis.sys loaded with its PDB? (.reload)"
        ))
    })
}

/// A string that is `None` when empty.
fn non_empty(text: String) -> Option<String> {
    (!text.is_empty()).then_some(text)
}

impl Target {
    fn ndis_types(&self) -> Result<NdisTypes<'_>> {
        let types = self.types_in(self.kernel_dtb());
        Ok(NdisTypes {
            miniport: ndis_layout(types, "_NDIS_MINIPORT_BLOCK")?,
            driver: ndis_layout(types, "_NDIS_M_DRIVER_BLOCK")?,
            miniport_state: self.ndis_enum("_NDIS_MINIPORT_STATE"),
            pnp_state: self.ndis_enum("_NDIS_PNP_DEVICE_STATE"),
            connect_state: self.ndis_enum("_NET_IF_MEDIA_CONNECT_STATE"),
            duplex_state: self.ndis_enum("_NET_IF_MEDIA_DUPLEX_STATE"),
            power_state: self.ndis_enum("_DEVICE_POWER_STATE"),
            medium: self.ndis_enum("_NDIS_MEDIUM"),
            physical_medium: self.ndis_enum("_NDIS_PHYSICAL_MEDIUM"),
            oper_status: self.ndis_enum("_NET_IF_OPER_STATUS"),
            filter_state: self.ndis_enum("_NDIS_FILTER_STATE"),
            request_type: self.ndis_enum("_NDIS_REQUEST_TYPE"),
            types,
        })
    }

    /// The variants of ndis.sys's enum `name`; empty when its PDB lacks it,
    /// which leaves the values in hex.
    fn ndis_enum(&self, name: &str) -> Vec<(String, i64)> {
        self.symbols
            .find_enum_across_modules(self.kernel_dtb(), &format!("ndis!{name}"))
            .unwrap_or_default()
    }

    /// The first block of the ndis.sys list whose head pointer `names` name.
    fn ndis_list_first(&self, names: &[&str]) -> Result<VirtAddr> {
        for name in names {
            if let Some(head) = self
                .symbols
                .find_symbol_across_modules(self.kernel_dtb(), name)?
            {
                return self.kernel_address_space().read::<VirtAddr>(head);
            }
        }
        Err(Error::DebugInfo(format!(
            "{} is not in ndis's symbols; is ndis.sys loaded with its PDB? (.reload)",
            names[0]
        )))
    }

    /// The blocks of a NULL-terminated chain from `first`, each linked to
    /// the next by its pointer field `next`, and why the walk stopped short.
    fn ndis_chain(
        &self,
        ndis: &NdisTypes<'_>,
        layout: &Arc<TypeInfo>,
        first: VirtAddr,
        next: &str,
        limit: usize,
    ) -> (Vec<VirtAddr>, Option<String>) {
        let mut blocks = Vec::new();
        let mut cursor = ListCursor::from_first(first, limit);
        while let Some(block) = cursor.take_current() {
            blocks.push(block);
            let link = ndis
                .types
                .struct_with_layout(Arc::clone(layout), block)
                .read_pointer(next)
                .map_err(|error| error.to_string());
            cursor.advance(link);
        }
        (blocks, chain_stop(cursor.finish()))
    }

    fn ndis_miniport_list(&self, ndis: &NdisTypes<'_>) -> Result<(Vec<VirtAddr>, Option<String>)> {
        let first = self.ndis_list_first(MINIPORT_LIST)?;
        Ok(self.ndis_chain(
            ndis,
            &ndis.miniport,
            first,
            "NextGlobalMiniport",
            MAX_MINIPORTS,
        ))
    }

    /// The miniports on `ndis!ndisMiniportList`. One whose block does not
    /// read is listed with the error.
    pub fn ndis_miniports(&self) -> Result<NdisMiniportList> {
        let ndis = self.ndis_types()?;
        let (addresses, stopped) = self.ndis_miniport_list(&ndis)?;
        let miniports = addresses
            .into_iter()
            .map(|address| {
                self.ndis_miniport_summary(&ndis, address)
                    .map_err(|error| NdisUnreadable {
                        address,
                        error: error.to_string(),
                    })
            })
            .collect();
        Ok(NdisMiniportList { miniports, stopped })
    }

    fn ndis_miniport_summary(
        &self,
        ndis: &NdisTypes<'_>,
        address: VirtAddr,
    ) -> Result<NdisMiniport> {
        let block = ndis.miniport_at(address);
        let driver = block.read_pointer("DriverHandle")?;
        let driver_name = if driver.is_zero() {
            None
        } else {
            ndis.driver_at(driver)
                .unicode_string("ServiceName")
                .ok()
                .and_then(non_empty)
        };
        let connect = block.read_uint("MediaConnectState")?;
        let connected = ndis
            .connect_state
            .iter()
            .any(|(name, value)| name == "MediaConnectStateConnected" && *value as u64 == connect);
        Ok(NdisMiniport {
            address,
            name: block.unicode_string("MiniportName")?,
            friendly_name: ndis
                .string_behind(&block, "pAdapterInstanceName")?
                .and_then(non_empty),
            driver,
            driver_name,
            state: enum_text(
                &ndis.miniport_state,
                block.read_uint("State")?,
                "NdisMiniport",
            ),
            pnp_state: enum_text(
                &ndis.pnp_state,
                block.read_uint("PnPDeviceState")?,
                "NdisPnPDevice",
            ),
            media_connect: enum_text(&ndis.connect_state, connect, "MediaConnectState"),
            connected,
            xmit_link_speed: block.read_uint("XmitLinkSpeed")?,
            rcv_link_speed: block.read_uint("RcvLinkSpeed")?,
            power: enum_text(
                &ndis.power_state,
                block.read_uint("CurrentDevicePowerState")?,
                "PowerDevice",
            ),
            if_index: block.read_uint("IfIndex")? as u32,
        })
    }

    /// The miniport at `address` in detail. A miniport that is not on
    /// `ndis!ndisMiniportList` (one being added or removed) is still decoded
    /// when its NDIS object header is a miniport block's; its `listed` is
    /// false.
    pub fn ndis_miniport(&self, address: VirtAddr) -> Result<NdisMiniportDetail> {
        let ndis = self.ndis_types()?;
        let (listed_miniports, _) = self.ndis_miniport_list(&ndis)?;
        let listed = listed_miniports.contains(&address);
        if !listed {
            self.ndis_check_header(
                &ndis,
                &ndis.miniport,
                address,
                listed_miniports.first().copied(),
                "a miniport",
                "ndis!ndisMiniportList",
            )?;
        }
        let summary = self.ndis_miniport_summary(&ndis, address)?;
        let block = ndis.miniport_at(address);

        let driver = if summary.driver.is_zero() {
            Err("the miniport has no driver block (DriverHandle is null)".to_string())
        } else {
            self.ndis_driver(&ndis, summary.driver)
                .map_err(|error| format!("driver block {:#x}: {error}", summary.driver.0))
        };
        let instance_id = block.read_pointer("PnPInstanceId")?;
        let instance_id = if instance_id.is_zero() {
            None
        } else {
            self.ndis_wide_string(instance_id, MAX_INSTANCE_ID)
                .ok()
                .and_then(non_empty)
        };
        let pending_oid = self.ndis_pending_oid(&ndis, &block)?;
        let (filters, filters_stopped) = self.ndis_filters(&ndis, &block)?;
        let (opens, opens_stopped) = self.ndis_opens(&ndis, &block, address)?;

        Ok(NdisMiniportDetail {
            listed,
            ndis_version: (
                block.read_uint("MajorNdisVersion")? as u8,
                block.read_uint("MinorNdisVersion")? as u8,
            ),
            adapter_context: block.read_pointer("MiniportAdapterContext")?,
            driver,
            device_object: block.read_pointer("DeviceObject")?,
            pdo: block.read_pointer("PhysicalDeviceObject")?,
            instance_id,
            medium: enum_text(&ndis.medium, block.read_uint("MediaType")?, "NdisMedium"),
            physical_medium: enum_text(
                &ndis.physical_medium,
                block.read_uint("PhysicalMediumType")?,
                "NdisPhysicalMedium",
            ),
            duplex: enum_text(
                &ndis.duplex_state,
                block.read_uint("MediaDuplexState")?,
                "MediaDuplexState",
            ),
            oper_status: enum_text(
                &ndis.oper_status,
                block.read_uint("OperStatus")?,
                "NET_IF_OPER_STATUS_",
            ),
            net_luid: block.embedded("NetLuid")?.read_uint("Value")?,
            flags: block.read_uint("Flags")? as u32,
            pnp_flags: block.read_uint("PnPFlags")? as u32,
            references: block
                .embedded("Ref")
                .and_then(|reference| reference.read_uint("ReferenceCount"))
                .ok(),
            reset_status: block.read_uint("ResetStatus")? as u32,
            resets: (
                block.read_uint("InternalResetCount")?,
                block.read_uint("MiniportResetCount")?,
            ),
            pending_oid,
            pending_return_nbls: block.read_uint("PendingReturnNBLCount")? as u32,
            filters,
            filters_stopped,
            num_opens: block.read_uint("NumOpens")? as u32,
            opens,
            opens_stopped,
            summary,
        })
    }

    /// The `PendingOidRequest` of a miniport or filter block, decoded, or
    /// why it does not decode.
    fn ndis_pending_oid(
        &self,
        ndis: &NdisTypes<'_>,
        block: &StructRef<'_>,
    ) -> Result<Option<std::result::Result<NdisOidRequest, String>>> {
        let request = block.read_pointer("PendingOidRequest")?;
        if request.is_zero() {
            return Ok(None);
        }
        Ok(Some(self.ndis_oid_request(ndis, request).map_err(
            |error| format!("OID request {:#x}: {error}", request.0),
        )))
    }

    fn ndis_oid_request(&self, ndis: &NdisTypes<'_>, address: VirtAddr) -> Result<NdisOidRequest> {
        let request = ndis.at("_NDIS_OID_REQUEST", address)?;
        let request_type = request.read_uint("RequestType")?;
        let type_name = enum_text(&ndis.request_type, request_type, "");
        let data = request.embedded("DATA")?;
        // The request type selects the member of the DATA union; a method
        // request has two buffer lengths and a method ID.
        let (buffer, buffer_length, method) = if type_name == "NdisRequestMethod" {
            let method = data.embedded("METHOD_INFORMATION")?;
            (
                method.read_pointer("InformationBuffer")?,
                method.read_uint("InputBufferLength")? as u32,
                Some((
                    method.read_uint("OutputBufferLength")? as u32,
                    method.read_uint("MethodId")? as u32,
                )),
            )
        } else {
            let member = if type_name == "NdisRequestSetInformation" {
                "SET_INFORMATION"
            } else {
                "QUERY_INFORMATION"
            };
            let member = data.embedded(member)?;
            (
                member.read_pointer("InformationBuffer")?,
                member.read_uint("InformationBufferLength")? as u32,
                None,
            )
        };
        Ok(NdisOidRequest {
            address,
            request_type: enum_text(&ndis.request_type, request_type, "NdisRequest"),
            oid: data.embedded("QUERY_INFORMATION")?.read_uint("Oid")? as u32,
            port: request.read_uint("PortNumber")? as u32,
            timeout: request.read_uint("Timeout")? as u32,
            buffer,
            buffer_length,
            method,
        })
    }

    /// The filter stack from `HighestFilter` down along `LowerFilter`,
    /// checking that each filter's `HigherFilter` leads back and that the
    /// walk ends at `LowestFilter`.
    fn ndis_filters(
        &self,
        ndis: &NdisTypes<'_>,
        miniport: &StructRef<'_>,
    ) -> Result<(Vec<NdisFilter>, Option<String>)> {
        let lowest = miniport.read_pointer("LowestFilter")?;
        let mut filters = Vec::new();
        let mut cursor =
            ListCursor::from_first(miniport.read_pointer("HighestFilter")?, MAX_FILTERS);
        let mut higher = VirtAddr(0);
        let mut broken = None;
        while let Some(address) = cursor.take_current() {
            let block = match ndis.at("_NDIS_FILTER_BLOCK", address) {
                Ok(block) => block,
                Err(error) => {
                    broken = Some(format!("filter {:#x}: {error}", address.0));
                    break;
                }
            };
            match block.read_pointer("HigherFilter") {
                Ok(back) if back == higher => {}
                Ok(back) => {
                    broken = Some(format!(
                        "filter {:#x}'s HigherFilter is {:#x}, not the filter above it {:#x}",
                        address.0, back.0, higher.0
                    ));
                    break;
                }
                Err(error) => {
                    broken = Some(format!("filter {:#x}: {error}", address.0));
                    break;
                }
            }
            match self.ndis_filter(ndis, &block) {
                Ok(filter) => filters.push(filter),
                Err(error) => {
                    broken = Some(format!("filter {:#x}: {error}", address.0));
                    break;
                }
            }
            higher = address;
            cursor.advance(
                block
                    .read_pointer("LowerFilter")
                    .map_err(|error| error.to_string()),
            );
        }
        let stopped = broken.or_else(|| chain_stop(cursor.finish())).or_else(|| {
            (higher != lowest).then(|| {
                format!(
                    "the walk ended at {:#x}, but the miniport's LowestFilter is {:#x}",
                    higher.0, lowest.0
                )
            })
        });
        Ok((filters, stopped))
    }

    fn ndis_filter(&self, ndis: &NdisTypes<'_>, block: &StructRef<'_>) -> Result<NdisFilter> {
        let driver = block.read_pointer("FilterDriver")?;
        let driver_image = if driver.is_zero() {
            None
        } else {
            ndis.at("_NDIS_FILTER_DRIVER_BLOCK", driver)?
                .unicode_string("ImageName")
                .ok()
                .and_then(non_empty)
        };
        let miniport = block.read_pointer("Miniport")?;
        Ok(NdisFilter {
            address: block.addr(),
            name: ndis
                .string_behind(block, "FilterFriendlyName")?
                .and_then(non_empty),
            driver,
            driver_image,
            miniport,
            miniport_name: self.ndis_miniport_name(ndis, miniport),
            state: enum_text(&ndis.filter_state, block.read_uint("State")?, "NdisFilter"),
            context: block.read_pointer("FilterModuleContext")?,
            pending_oid: self.ndis_pending_oid(ndis, block)?,
        })
    }

    /// The protocol bindings on the miniport's `OpenQueue`, along
    /// `MiniportNextOpen`.
    fn ndis_opens(
        &self,
        ndis: &NdisTypes<'_>,
        miniport: &StructRef<'_>,
        address: VirtAddr,
    ) -> Result<(Vec<NdisOpen>, Option<String>)> {
        let open_layout = ndis_layout(ndis.types, "_NDIS_OPEN_BLOCK")?;
        let (addresses, mut stopped) = self.ndis_chain(
            ndis,
            &open_layout,
            miniport.read_pointer("OpenQueue")?,
            "MiniportNextOpen",
            MAX_OPENS,
        );
        let mut opens = Vec::with_capacity(addresses.len());
        for open in addresses {
            let block = ndis
                .types
                .struct_with_layout(Arc::clone(&open_layout), open);
            let read = || -> Result<NdisOpen> {
                let owner = block.read_pointer("MiniportHandle")?;
                if owner != address {
                    return Err(Error::DebugInfo(format!(
                        "its MiniportHandle is {:#x}, not this miniport",
                        owner.0
                    )));
                }
                let protocol = block.read_pointer("ProtocolHandle")?;
                let protocol_name = if protocol.is_zero() {
                    None
                } else {
                    ndis.at("_NDIS_PROTOCOL_BLOCK", protocol)?
                        .unicode_string("Name")
                        .ok()
                        .and_then(non_empty)
                };
                Ok(NdisOpen {
                    address: open,
                    protocol,
                    protocol_name,
                    context: block.read_pointer("ProtocolBindingContext")?,
                })
            };
            match read() {
                Ok(entry) => opens.push(entry),
                Err(error) => {
                    stopped = Some(format!("open {:#x}: {error}", open.0));
                    break;
                }
            }
        }
        Ok((opens, stopped))
    }

    fn ndis_driver(&self, ndis: &NdisTypes<'_>, address: VirtAddr) -> Result<NdisDriver> {
        let block = ndis.driver_at(address);
        let ndis_version = (
            block.read_uint("MajorNdisVersion")? as u8,
            block.read_uint("MinorNdisVersion")? as u8,
        );
        // The characteristics are a union of the NDIS 5 and NDIS 6 forms;
        // only an NDIS 6 driver's have its version here.
        let driver_version = if ndis_version.0 >= 6 {
            block
                .embedded("MiniportDriverCharacteristics")
                .and_then(|chars| {
                    Ok((
                        chars.read_uint("MajorDriverVersion")? as u8,
                        chars.read_uint("MinorDriverVersion")? as u8,
                    ))
                })
                .ok()
        } else {
            None
        };
        let driver_object = block.read_pointer("DriverObject")?;
        // The module where the driver starts names its PDB, which need not
        // match the service name.
        let module = self.ndis_driver_module(ndis, driver_object);
        let (miniports, miniports_stopped) = self.ndis_chain(
            ndis,
            &ndis.miniport,
            block.read_pointer("MiniportQueue")?,
            "NextMiniport",
            MAX_MINIPORTS,
        );
        Ok(NdisDriver {
            address,
            service_name: block.unicode_string("ServiceName")?,
            image_name: block.unicode_string("ImageName")?,
            module,
            driver_object,
            ndis_version,
            driver_version,
            miniports,
            miniports_stopped,
        })
    }

    /// The miniport drivers on `ndis!ndisMiniDriverList`.
    pub fn ndis_minidrivers(&self) -> Result<NdisDriverList> {
        let ndis = self.ndis_types()?;
        let (addresses, stopped) = self.ndis_driver_list(&ndis)?;
        let drivers = addresses
            .into_iter()
            .map(|address| {
                self.ndis_driver(&ndis, address)
                    .map_err(|error| NdisUnreadable {
                        address,
                        error: error.to_string(),
                    })
            })
            .collect();
        Ok(NdisDriverList { drivers, stopped })
    }

    fn ndis_driver_list(&self, ndis: &NdisTypes<'_>) -> Result<(Vec<VirtAddr>, Option<String>)> {
        let first = self.ndis_list_first(DRIVER_LIST)?;
        Ok(self.ndis_chain(ndis, &ndis.driver, first, "NextDriver", MAX_DRIVERS))
    }

    /// Refuse a block that is not on its ndis.sys list `list` unless its
    /// NDIS object header (`Type`, `Size`) is that of `reference`, a block
    /// on the list. ndis.sys stamps each kind of block with its own header,
    /// so a mistyped address fails here instead of decoding garbage.
    fn ndis_check_header(
        &self,
        ndis: &NdisTypes<'_>,
        layout: &Arc<TypeInfo>,
        address: VirtAddr,
        reference: Option<VirtAddr>,
        what: &str,
        list: &str,
    ) -> Result<()> {
        let header = |at: VirtAddr| -> Result<(u64, u64)> {
            let header = ndis
                .types
                .struct_with_layout(Arc::clone(layout), at)
                .embedded("Header")?;
            Ok((header.read_uint("Type")?, header.read_uint("Size")?))
        };
        let Some(reference) = reference else {
            return Err(Error::DebugInfo(format!(
                "{:#x} is not on {list}, which is empty",
                address.0
            )));
        };
        let expected = header(reference)?;
        let found = header(address)?;
        if found != expected {
            return Err(Error::DebugInfo(format!(
                "{:#x} is not {what}: it is not on {list}, and its NDIS object header (type \
                 {:#x}, size {:#x}) is not that of one (type {:#x}, size {:#x})",
                address.0, found.0, found.1, expected.0, expected.1
            )));
        }
        Ok(())
    }

    /// The miniport driver whose `_NDIS_M_DRIVER_BLOCK` is at `address`,
    /// and its miniports.
    pub fn ndis_minidriver(
        &self,
        address: VirtAddr,
    ) -> Result<(NdisDriver, Vec<NdisMiniportListEntry>)> {
        let ndis = self.ndis_types()?;
        let (drivers, _) = self.ndis_driver_list(&ndis)?;
        if !drivers.contains(&address) {
            self.ndis_check_header(
                &ndis,
                &ndis.driver,
                address,
                drivers.first().copied(),
                "a miniport driver block",
                "ndis!ndisMiniDriverList",
            )?;
        }
        let driver = self.ndis_driver(&ndis, address)?;
        let miniports = driver
            .miniports
            .iter()
            .map(|&miniport| {
                self.ndis_miniport_summary(&ndis, miniport)
                    .map_err(|error| NdisUnreadable {
                        address: miniport,
                        error: error.to_string(),
                    })
            })
            .collect();
        Ok((driver, miniports))
    }

    /// The friendly name of the miniport at `miniport`; `None` for a null
    /// pointer or a name that does not read.
    fn ndis_miniport_name(&self, ndis: &NdisTypes<'_>, miniport: VirtAddr) -> Option<String> {
        if miniport.is_zero() {
            return None;
        }
        ndis.string_behind(&ndis.miniport_at(miniport), "pAdapterInstanceName")
            .ok()
            .flatten()
            .and_then(non_empty)
    }

    fn ndis_global_filter_list(
        &self,
        ndis: &NdisTypes<'_>,
    ) -> Result<(Arc<TypeInfo>, Vec<VirtAddr>, Option<String>)> {
        let layout = ndis_layout(ndis.types, "_NDIS_FILTER_BLOCK")?;
        let first = self.ndis_list_first(GLOBAL_FILTER_LIST)?;
        let (filters, stopped) =
            self.ndis_chain(ndis, &layout, first, "NextGlobalFilter", MAX_GLOBAL_FILTERS);
        Ok((layout, filters, stopped))
    }

    fn ndis_filter_entries(
        &self,
        ndis: &NdisTypes<'_>,
        addresses: &[VirtAddr],
    ) -> Result<Vec<NdisFilterListEntry>> {
        let layout = ndis_layout(ndis.types, "_NDIS_FILTER_BLOCK")?;
        Ok(addresses
            .iter()
            .map(|&address| {
                let block = ndis
                    .types
                    .struct_with_layout(Arc::clone(&layout), address)
                    .prefetch();
                self.ndis_filter(ndis, &block)
                    .map_err(|error| NdisUnreadable {
                        address,
                        error: error.to_string(),
                    })
            })
            .collect())
    }

    /// The filter modules of every miniport, on `ndis!ndisGlobalFilterList`.
    pub fn ndis_filters_all(&self) -> Result<NdisFilterList> {
        let ndis = self.ndis_types()?;
        let (_, addresses, stopped) = self.ndis_global_filter_list(&ndis)?;
        Ok(NdisFilterList {
            filters: self.ndis_filter_entries(&ndis, &addresses)?,
            stopped,
        })
    }

    /// The filter module at `address` in detail. One that is not on
    /// `ndis!ndisGlobalFilterList` is decoded only when its NDIS object
    /// header is a filter block's.
    pub fn ndis_filter_detail(&self, address: VirtAddr) -> Result<NdisFilterDetail> {
        let ndis = self.ndis_types()?;
        let (layout, listed_filters, _) = self.ndis_global_filter_list(&ndis)?;
        let listed = listed_filters.contains(&address);
        if !listed {
            self.ndis_check_header(
                &ndis,
                &layout,
                address,
                listed_filters.first().copied(),
                "a filter module",
                "ndis!ndisGlobalFilterList",
            )?;
        }
        let block = ndis.types.struct_with_layout(layout, address).prefetch();
        let filter = self.ndis_filter(&ndis, &block)?;
        let driver_name = if filter.driver.is_zero() {
            None
        } else {
            ndis.at("_NDIS_FILTER_DRIVER_BLOCK", filter.driver)?
                .embedded("DefaultFilterCharacteristics")
                .and_then(|chars| chars.unicode_string("FriendlyName"))
                .ok()
                .and_then(non_empty)
        };
        Ok(NdisFilterDetail {
            listed,
            driver_name,
            higher: block.read_pointer("HigherFilter")?,
            lower: block.read_pointer("LowerFilter")?,
            media_connect: enum_text(
                &ndis.connect_state,
                block.read_uint("MediaConnectState")?,
                "MediaConnectState",
            ),
            xmit_link_speed: block.read_uint("XmitLinkSpeed")?,
            rcv_link_speed: block.read_uint("RcvLinkSpeed")?,
            if_index: block.read_uint("IfIndex")? as u32,
            flags: block.read_uint("Flags")? as u32,
            references: block
                .embedded("Ref")
                .and_then(|reference| reference.read_uint("ReferenceCount"))
                .ok(),
            dropped_receive_nbls: block.read_uint("DroppedReceiveNbls")? as i32,
            dropped_send_nbls: block.read_uint("DroppedSendNbls")? as i32,
            dropped_status_indications: block.read_uint("DroppedStatusIndications")? as u32,
            filter,
        })
    }

    fn ndis_filter_driver_list(
        &self,
        ndis: &NdisTypes<'_>,
    ) -> Result<(Arc<TypeInfo>, Vec<VirtAddr>, Option<String>)> {
        let layout = ndis_layout(ndis.types, "_NDIS_FILTER_DRIVER_BLOCK")?;
        let first = self.ndis_list_first(FILTER_DRIVER_LIST)?;
        let (drivers, stopped) =
            self.ndis_chain(ndis, &layout, first, "NextFilterDriver", MAX_DRIVERS);
        Ok((layout, drivers, stopped))
    }

    fn ndis_filter_driver(
        &self,
        ndis: &NdisTypes<'_>,
        layout: &Arc<TypeInfo>,
        address: VirtAddr,
    ) -> Result<NdisFilterDriver> {
        let block = ndis
            .types
            .struct_with_layout(Arc::clone(layout), address)
            .prefetch();
        let chars = block.embedded("DefaultFilterCharacteristics")?;
        let driver_object = block.read_pointer("DriverObject")?;
        let filter_layout = ndis_layout(ndis.types, "_NDIS_FILTER_BLOCK")?;
        let (filters, filters_stopped) = self.ndis_chain(
            ndis,
            &filter_layout,
            block.read_pointer("FilterQueue")?,
            "NextFilter",
            MAX_GLOBAL_FILTERS,
        );
        Ok(NdisFilterDriver {
            address,
            friendly_name: chars.unicode_string("FriendlyName")?,
            unique_name: chars.unicode_string("UniqueName")?,
            service_name: chars.unicode_string("ServiceName")?,
            image_name: block.unicode_string("ImageName")?,
            module: self.ndis_driver_module(ndis, driver_object),
            driver_object,
            context: block.read_pointer("FilterDriverContext")?,
            flags: block.read_uint("Flags")? as u32,
            ndis_version: (
                chars.read_uint("MajorNdisVersion")? as u8,
                chars.read_uint("MinorNdisVersion")? as u8,
            ),
            driver_version: (
                chars.read_uint("MajorDriverVersion")? as u8,
                chars.read_uint("MinorDriverVersion")? as u8,
            ),
            filters,
            filters_stopped,
        })
    }

    /// The filter drivers on `ndis!ndisFilterDriverList`.
    pub fn ndis_filter_drivers(&self) -> Result<NdisFilterDriverList> {
        let ndis = self.ndis_types()?;
        let (layout, addresses, stopped) = self.ndis_filter_driver_list(&ndis)?;
        let drivers = addresses
            .into_iter()
            .map(|address| {
                self.ndis_filter_driver(&ndis, &layout, address)
                    .map_err(|error| NdisUnreadable {
                        address,
                        error: error.to_string(),
                    })
            })
            .collect();
        Ok(NdisFilterDriverList { drivers, stopped })
    }

    /// The filter driver whose `_NDIS_FILTER_DRIVER_BLOCK` is at `address`,
    /// and its filter modules.
    pub fn ndis_filter_driver_detail(
        &self,
        address: VirtAddr,
    ) -> Result<(NdisFilterDriver, Vec<NdisFilterListEntry>)> {
        let ndis = self.ndis_types()?;
        let (layout, drivers, _) = self.ndis_filter_driver_list(&ndis)?;
        if !drivers.contains(&address) {
            self.ndis_check_header(
                &ndis,
                &layout,
                address,
                drivers.first().copied(),
                "a filter driver block",
                "ndis!ndisFilterDriverList",
            )?;
        }
        let driver = self.ndis_filter_driver(&ndis, &layout, address)?;
        let filters = self.ndis_filter_entries(&ndis, &driver.filters)?;
        Ok((driver, filters))
    }

    /// The short name of the module where the driver of `driver_object`
    /// starts, the name its PDB's types go by.
    fn ndis_driver_module(&self, ndis: &NdisTypes<'_>, driver_object: VirtAddr) -> Option<String> {
        if driver_object.is_zero() {
            return None;
        }
        ndis.types
            .struct_at("_DRIVER_OBJECT", driver_object)
            .and_then(|object| object.read_pointer("DriverStart"))
            .ok()
            .and_then(|start| self.module_containing(start))
            .map(|module| module.short_name)
    }

    fn ndis_protocol_list(
        &self,
        ndis: &NdisTypes<'_>,
    ) -> Result<(Arc<TypeInfo>, Vec<VirtAddr>, Option<String>)> {
        let layout = ndis_layout(ndis.types, "_NDIS_PROTOCOL_BLOCK")?;
        let first = self.ndis_list_first(PROTOCOL_LIST)?;
        let (protocols, stopped) =
            self.ndis_chain(ndis, &layout, first, "NextProtocol", MAX_PROTOCOLS);
        Ok((layout, protocols, stopped))
    }

    fn ndis_protocol(
        &self,
        ndis: &NdisTypes<'_>,
        layout: &Arc<TypeInfo>,
        address: VirtAddr,
    ) -> Result<NdisProtocol> {
        let block = ndis
            .types
            .struct_with_layout(Arc::clone(layout), address)
            .prefetch();
        let open_layout = ndis_layout(ndis.types, "_NDIS_OPEN_BLOCK")?;
        let (opens, opens_stopped) = self.ndis_chain(
            ndis,
            &open_layout,
            block.read_pointer("OpenQueue")?,
            "ProtocolNextOpen",
            MAX_OPENS,
        );
        Ok(NdisProtocol {
            address,
            name: block.unicode_string("Name")?,
            image_name: block.unicode_string("ImageName").ok().and_then(non_empty),
            ndis_version: (
                block.read_uint("MajorNdisVersion")? as u8,
                block.read_uint("MinorNdisVersion")? as u8,
            ),
            driver_version: (
                block.read_uint("MajorDriverVersion")? as u8,
                block.read_uint("MinorDriverVersion")? as u8,
            ),
            context: block.read_pointer("ProtocolDriverContext")?,
            flags: block.read_uint("Flags")? as u32,
            bind_handler: block.read_pointer("BindAdapterHandlerEx")?,
            opens,
            opens_stopped,
        })
    }

    /// The protocol drivers on `ndis!ndisProtocolList`.
    pub fn ndis_protocols(&self) -> Result<NdisProtocolList> {
        let ndis = self.ndis_types()?;
        let (layout, addresses, stopped) = self.ndis_protocol_list(&ndis)?;
        let protocols = addresses
            .into_iter()
            .map(|address| {
                self.ndis_protocol(&ndis, &layout, address)
                    .map_err(|error| NdisUnreadable {
                        address,
                        error: error.to_string(),
                    })
            })
            .collect();
        Ok(NdisProtocolList { protocols, stopped })
    }

    /// The protocol driver at `address` in detail, with the miniport of each
    /// binding. A binding whose `ProtocolHandle` is not this protocol ends
    /// the walk there.
    pub fn ndis_protocol_detail(&self, address: VirtAddr) -> Result<NdisProtocolDetail> {
        let ndis = self.ndis_types()?;
        let (layout, protocols, _) = self.ndis_protocol_list(&ndis)?;
        let listed = protocols.contains(&address);
        if !listed {
            self.ndis_check_header(
                &ndis,
                &layout,
                address,
                protocols.first().copied(),
                "a protocol block",
                "ndis!ndisProtocolList",
            )?;
        }
        let protocol = self.ndis_protocol(&ndis, &layout, address)?;
        let open_layout = ndis_layout(ndis.types, "_NDIS_OPEN_BLOCK")?;
        let mut bindings = Vec::with_capacity(protocol.opens.len());
        let mut bindings_stopped = protocol.opens_stopped.clone();
        for &open in &protocol.opens {
            let block = ndis
                .types
                .struct_with_layout(Arc::clone(&open_layout), open);
            let read = || -> Result<NdisProtocolBinding> {
                let owner = block.read_pointer("ProtocolHandle")?;
                if owner != address {
                    return Err(Error::DebugInfo(format!(
                        "its ProtocolHandle is {:#x}, not this protocol",
                        owner.0
                    )));
                }
                let miniport = block.read_pointer("MiniportHandle")?;
                Ok(NdisProtocolBinding {
                    open,
                    miniport,
                    miniport_name: self.ndis_miniport_name(&ndis, miniport),
                    context: block.read_pointer("ProtocolBindingContext")?,
                })
            };
            match read() {
                Ok(binding) => bindings.push(binding),
                Err(error) => {
                    bindings_stopped = Some(format!("open {:#x}: {error}", open.0));
                    break;
                }
            }
        }
        Ok(NdisProtocolDetail {
            listed,
            bind_handler_name: (!protocol.bind_handler.is_zero())
                .then(|| self.format_code_address(self.kernel_dtb(), protocol.bind_handler))
                .flatten(),
            protocol,
            bindings,
            bindings_stopped,
        })
    }

    /// The OID requests that every miniport and filter module has not
    /// completed: each block's `PendingOidRequest`.
    pub fn ndis_pending_oids(&self) -> Result<NdisPendingOids> {
        let ndis = self.ndis_types()?;
        let mut problems = Vec::new();
        let mut pending = Vec::new();
        let (miniports, stopped) = self.ndis_miniport_list(&ndis)?;
        problems.extend(stopped.map(|reason| format!("miniport list: {reason}")));
        for &address in &miniports {
            let block = ndis.miniport_at(address);
            match self.ndis_pending_oid(&ndis, &block) {
                Ok(None) => {}
                Ok(Some(request)) => pending.push(NdisPendingOid {
                    owner: NdisOidOwner::Miniport,
                    address,
                    name: self.ndis_miniport_name(&ndis, address),
                    request,
                }),
                Err(error) => problems.push(format!("miniport {:#x}: {error}", address.0)),
            }
        }
        let (layout, filters, stopped) = self.ndis_global_filter_list(&ndis)?;
        problems.extend(stopped.map(|reason| format!("filter list: {reason}")));
        for &address in &filters {
            let block = ndis.types.struct_with_layout(Arc::clone(&layout), address);
            match self.ndis_pending_oid(&ndis, &block) {
                Ok(None) => {}
                Ok(Some(request)) => pending.push(NdisPendingOid {
                    owner: NdisOidOwner::Filter,
                    address,
                    name: ndis
                        .string_behind(&block, "FilterFriendlyName")
                        .ok()
                        .flatten()
                        .and_then(non_empty),
                    request,
                }),
                Err(error) => problems.push(format!("filter {:#x}: {error}", address.0)),
            }
        }
        Ok(NdisPendingOids {
            pending,
            miniports: miniports.len(),
            filters: filters.len(),
            problems,
        })
    }

    /// The NET_BUFFER_LIST at `address` and its NET_BUFFERs.
    pub fn ndis_nbl(&self, address: VirtAddr) -> Result<NdisNbl> {
        let ndis = self.ndis_types()?;
        let nbl_layout = ndis_layout(ndis.types, "_NET_BUFFER_LIST")?;
        let nb_layout = ndis_layout(ndis.types, "_NET_BUFFER")?;
        let owners = self.ndis_handle_owners(&ndis);
        self.ndis_nbl_at(&ndis, &nbl_layout, &nb_layout, &owners, address)
    }

    /// The NET_BUFFER_LISTs on the `Next` chain from `first`, and why the
    /// walk stopped short.
    pub fn ndis_nbl_chain(&self, first: VirtAddr) -> Result<(Vec<NdisNbl>, Option<String>)> {
        let ndis = self.ndis_types()?;
        let nbl_layout = ndis_layout(ndis.types, "_NET_BUFFER_LIST")?;
        let nb_layout = ndis_layout(ndis.types, "_NET_BUFFER")?;
        let owners = self.ndis_handle_owners(&ndis);
        let (addresses, mut stopped) =
            self.ndis_chain(&ndis, &nbl_layout, first, "Next", MAX_NBL_CHAIN);
        let mut nbls = Vec::with_capacity(addresses.len());
        for address in addresses {
            match self.ndis_nbl_at(&ndis, &nbl_layout, &nb_layout, &owners, address) {
                Ok(nbl) => nbls.push(nbl),
                Err(error) => {
                    stopped = Some(format!("NBL {:#x}: {error}", address.0));
                    break;
                }
            }
        }
        Ok((nbls, stopped))
    }

    fn ndis_nbl_at(
        &self,
        ndis: &NdisTypes<'_>,
        nbl_layout: &Arc<TypeInfo>,
        nb_layout: &Arc<TypeInfo>,
        owners: &NdisHandleOwners,
        address: VirtAddr,
    ) -> Result<NdisNbl> {
        let nbl = ndis
            .types
            .struct_with_layout(Arc::clone(nbl_layout), address)
            .prefetch();
        let (addresses, mut net_buffers_stopped) = self.ndis_chain(
            ndis,
            nb_layout,
            nbl.read_pointer("FirstNetBuffer")?,
            "Next",
            MAX_NET_BUFFERS,
        );
        let mut net_buffers = Vec::with_capacity(addresses.len());
        for nb in addresses {
            let block = ndis
                .types
                .struct_with_layout(Arc::clone(nb_layout), nb)
                .prefetch();
            let read = || -> Result<NdisNetBuffer> {
                Ok(NdisNetBuffer {
                    address: nb,
                    next: block.read_pointer("Next")?,
                    current_mdl: block.read_pointer("CurrentMdl")?,
                    current_mdl_offset: block.read_uint("CurrentMdlOffset")? as u32,
                    data_length: block.read_uint("DataLength")? as u32,
                    data_offset: block.read_uint("DataOffset")? as u32,
                    mdl_chain: block.read_pointer("MdlChain")?,
                })
            };
            match read() {
                Ok(net_buffer) => net_buffers.push(net_buffer),
                Err(error) => {
                    net_buffers_stopped = Some(format!("NET_BUFFER {:#x}: {error}", nb.0));
                    break;
                }
            }
        }
        let source_handle = nbl.read_pointer("SourceHandle")?;
        Ok(NdisNbl {
            address,
            next: nbl.read_pointer("Next")?,
            parent: nbl.read_pointer("ParentNetBufferList")?,
            context: nbl.read_pointer("Context")?,
            pool: nbl.read_pointer("NdisPoolHandle")?,
            source_handle,
            source: self.ndis_handle_owner(ndis, owners, source_handle),
            flags: nbl.read_uint("Flags")? as u32,
            nbl_flags: nbl.read_uint("NblFlags")? as u32,
            child_ref_count: nbl.read_uint("ChildRefCount")? as i32,
            status: nbl.read_uint("Status")? as u32,
            net_buffers,
            net_buffers_stopped,
        })
    }

    /// The NDIS object headers of a miniport, a filter module, and a
    /// binding NDIS keeps, to tell what an NBL's `SourceHandle` is.
    fn ndis_handle_owners(&self, ndis: &NdisTypes<'_>) -> NdisHandleOwners {
        let header = |layout: &Arc<TypeInfo>, at: VirtAddr| -> Option<(u64, u64)> {
            if at.is_zero() {
                return None;
            }
            let header = ndis
                .types
                .struct_with_layout(Arc::clone(layout), at)
                .embedded("Header")
                .ok()?;
            Some((
                header.read_uint("Type").ok()?,
                header.read_uint("Size").ok()?,
            ))
        };
        let first_miniport = self.ndis_list_first(MINIPORT_LIST).unwrap_or_default();
        let first_filter = self.ndis_list_first(GLOBAL_FILTER_LIST).unwrap_or_default();
        let first_open = ndis
            .miniport_at(first_miniport)
            .read_pointer("OpenQueue")
            .unwrap_or_default();
        let layout = |name: &str| ndis_layout(ndis.types, name).ok();
        NdisHandleOwners {
            miniport: header(&ndis.miniport, first_miniport),
            filter: layout("_NDIS_FILTER_BLOCK").and_then(|layout| header(&layout, first_filter)),
            open: layout("_NDIS_OPEN_BLOCK").and_then(|layout| header(&layout, first_open)),
        }
    }

    /// What the NDIS handle `handle` is, by its object header: a miniport,
    /// a filter module, or a protocol's binding, with its name.
    fn ndis_handle_owner(
        &self,
        ndis: &NdisTypes<'_>,
        owners: &NdisHandleOwners,
        handle: VirtAddr,
    ) -> Option<String> {
        if handle.is_zero() {
            return None;
        }
        let mut header = [0u8; 4];
        self.kernel_address_space()
            .read_bytes(handle, &mut header)
            .ok()?;
        // _NDIS_OBJECT_HEADER: UCHAR Type, UCHAR Revision, USHORT Size.
        let found = (
            u64::from(header[0]),
            u64::from(u16::from_le_bytes([header[2], header[3]])),
        );
        if owners.miniport == Some(found) {
            let name = self.ndis_miniport_name(ndis, handle);
            return Some(
                format!("miniport {}", name.unwrap_or_default())
                    .trim_end()
                    .into(),
            );
        }
        if owners.filter == Some(found) {
            let name = ndis
                .at("_NDIS_FILTER_BLOCK", handle)
                .and_then(|block| ndis.string_behind(&block, "FilterFriendlyName"))
                .ok()
                .flatten();
            return Some(
                format!("filter {}", name.unwrap_or_default())
                    .trim_end()
                    .into(),
            );
        }
        if owners.open == Some(found) {
            let open = ndis.at("_NDIS_OPEN_BLOCK", handle).ok()?;
            let protocol = open
                .read_pointer("ProtocolHandle")
                .ok()
                .filter(|protocol| !protocol.is_zero())
                .and_then(|protocol| ndis.at("_NDIS_PROTOCOL_BLOCK", protocol).ok())
                .and_then(|protocol| protocol.unicode_string("Name").ok());
            let miniport = open
                .read_pointer("MiniportHandle")
                .ok()
                .and_then(|miniport| self.ndis_miniport_name(ndis, miniport));
            return Some(format!(
                "binding of {} to {}",
                protocol.as_deref().unwrap_or("?"),
                miniport.as_deref().unwrap_or("?")
            ));
        }
        None
    }

    /// Up to `max` bytes of a NET_BUFFER's data, from `CurrentMdl` at
    /// `CurrentMdlOffset` along the MDL chain, read through each MDL's
    /// PFNs so an MDL not mapped into system space reads too.
    pub fn ndis_net_buffer_data(&self, net_buffer: &NdisNetBuffer, max: usize) -> Result<Vec<u8>> {
        let wanted = (net_buffer.data_length as usize).min(max);
        let mut data = Vec::with_capacity(wanted);
        let mut mdl = net_buffer.current_mdl;
        let mut skip = u64::from(net_buffer.current_mdl_offset);
        let mut walked = 0;
        while data.len() < wanted {
            if mdl.is_zero() {
                return Err(Error::DebugInfo(format!(
                    "the MDL chain ends after {:#x} of the {:#x} bytes of data",
                    data.len(),
                    net_buffer.data_length
                )));
            }
            walked += 1;
            if walked > MAX_NET_BUFFER_MDLS {
                return Err(Error::DebugInfo(format!(
                    "the MDL chain runs past {MAX_NET_BUFFER_MDLS} MDLs"
                )));
            }
            let detail = self.inspect_mdl(mdl, None)?;
            let byte_count = u64::from(detail.byte_count);
            if skip < byte_count {
                let take = ((byte_count - skip) as usize).min(wanted - data.len());
                let mut offset = u64::from(detail.byte_offset) + skip;
                let end = data.len() + take;
                while data.len() < end {
                    let page = (offset / PAGE_SIZE) as usize;
                    let pfn = detail.pfns.get(page).copied().ok_or_else(|| {
                        Error::DebugInfo(format!("MDL {:#x} has no PFN for page {page}", mdl.0))
                    })?;
                    let in_page = offset % PAGE_SIZE;
                    let chunk = ((PAGE_SIZE - in_page) as usize).min(end - data.len());
                    let start = data.len();
                    data.resize(start + chunk, 0);
                    self.read_physical(pfn * PAGE_SIZE + in_page, &mut data[start..])?;
                    offset += chunk as u64;
                }
                skip = 0;
            } else {
                skip -= byte_count;
            }
            mdl = detail.next;
        }
        Ok(data)
    }

    /// A NUL-terminated UTF-16 string of at most `max_units` units, read a
    /// page at a time so a short string at the end of a page reads.
    fn ndis_wide_string(&self, address: VirtAddr, max_units: usize) -> Result<String> {
        let memory = self.kernel_address_space();
        let max_bytes = max_units * 2;
        let mut bytes = Vec::new();
        while bytes.len() < max_bytes {
            let at = address + bytes.len() as u64;
            let chunk = ((PAGE_SIZE - at.page_offset()) as usize).min(max_bytes - bytes.len());
            let start = bytes.len();
            bytes.resize(start + chunk, 0);
            memory.read_bytes(at, &mut bytes[start..])?;
            if let Some(end) = bytes
                .as_chunks::<2>()
                .0
                .iter()
                .position(|unit| unit == &[0, 0])
            {
                bytes.truncate(end * 2);
                break;
            }
        }
        Ok(utf16le_lossy(&bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_speeds_take_the_largest_unit_and_keep_two_decimals() {
        assert_eq!(link_speed_text(0x2540be400), "10 Gbps");
        assert_eq!(link_speed_text(1_000_000_000), "1 Gbps");
        assert_eq!(link_speed_text(2_500_000_000), "2.5 Gbps");
        assert_eq!(link_speed_text(999_999_999), "999.99 Mbps");
        assert_eq!(link_speed_text(1_050), "1.05 kbps");
        assert_eq!(link_speed_text(999), "999 bps");
        assert_eq!(link_speed_text(0), "0 bps");
        assert_eq!(link_speed_text(LINK_SPEED_UNKNOWN), "unknown");
    }

    #[test]
    fn enum_names_lose_their_prefix_unless_nothing_is_left() {
        let variants = vec![
            ("NdisMiniportPaused".to_string(), 6),
            ("NdisMiniport".to_string(), 7),
        ];
        assert_eq!(enum_text(&variants, 6, "NdisMiniport"), "Paused");
        assert_eq!(enum_text(&variants, 7, "NdisMiniport"), "NdisMiniport");
        assert_eq!(enum_text(&variants, 6, "Other"), "NdisMiniportPaused");
        assert_eq!(enum_text(&variants, 9, "NdisMiniport"), "0x9");
        assert_eq!(enum_text(&[], 1, "NdisMiniport"), "0x1");
    }

    #[test]
    fn oid_names_are_found_by_binary_search() {
        assert!(OID_NAMES.windows(2).all(|pair| pair[0].0 < pair[1].0));
        assert_eq!(oid_name(0x0001010e), Some("OID_GEN_CURRENT_PACKET_FILTER"));
        assert_eq!(oid_name(0xfd010101), Some("OID_PNP_SET_POWER"));
        assert_eq!(oid_name(0x00010101), Some("OID_GEN_SUPPORTED_LIST"));
        assert_eq!(oid_name(0xfd020201), Some("OID_PNP_WAKE_UP_ERROR"));
        assert_eq!(oid_name(0x00010100), None);
    }
}
