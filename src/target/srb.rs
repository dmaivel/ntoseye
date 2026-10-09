//! SCSI request blocks (`!storagekd.storsrb`): a `STORAGE_REQUEST_BLOCK`,
//! the extended SRB that StorPort and classpnp pass on Windows 8 and later,
//! or a legacy `SCSI_REQUEST_BLOCK`, typed by storport's public PDB, with
//! the names of `srb.h` and `storport.h` for its function, status, and
//! flags.

use std::sync::Arc;

use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::layout::{StructRef, TypeInfo, Types};
use crate::target::Target;
use crate::target::virtio_request::sense_text;
use crate::types::VirtAddr;

/// `SRB_FUNCTION_STORAGE_REQUEST_BLOCK`: the `Function` of every extended
/// SRB, whose own function is `SrbFunction`.
pub const SRB_FUNCTION_STORAGE_REQUEST_BLOCK: u8 = 0x28;
/// `SRB_SIGNATURE`, `"XBRS"` in memory.
const SRB_SIGNATURE: u64 = 0x5352_4258;
/// `STOR_ADDRESS_TYPE_BTL8`.
const STOR_ADDRESS_TYPE_BTL8: u64 = 1;
/// `SRB_STATUS_QUEUE_FROZEN` and `SRB_STATUS_AUTOSENSE_VALID`, the flags
/// over the status in `SrbStatus`.
const SRB_STATUS_QUEUE_FROZEN: u8 = 0x40;
const SRB_STATUS_AUTOSENSE_VALID: u8 = 0x80;
/// More extended data blocks than any SRB carries.
const MAX_SRB_EX_DATA: u64 = 16;
/// The most CDB bytes read from a variable-length CDB.
const MAX_CDB: usize = 64;

/// The `SRB_FUNCTION_*` name of `function`, without the prefix.
pub fn srb_function_name(function: u32) -> Option<&'static str> {
    Some(match function {
        0x00 => "EXECUTE_SCSI",
        0x01 => "CLAIM_DEVICE",
        0x02 => "IO_CONTROL",
        0x03 => "RECEIVE_EVENT",
        0x04 => "RELEASE_QUEUE",
        0x05 => "ATTACH_DEVICE",
        0x06 => "RELEASE_DEVICE",
        0x07 => "SHUTDOWN",
        0x08 => "FLUSH",
        0x09 => "PROTOCOL_COMMAND",
        0x10 => "ABORT_COMMAND",
        0x11 => "RELEASE_RECOVERY",
        0x12 => "RESET_BUS",
        0x13 => "RESET_DEVICE",
        0x14 => "TERMINATE_IO",
        0x15 => "FLUSH_QUEUE",
        0x16 => "REMOVE_DEVICE",
        0x17 => "WMI",
        0x18 => "LOCK_QUEUE",
        0x19 => "UNLOCK_QUEUE",
        0x1a => "QUIESCE_DEVICE",
        0x20 => "RESET_LOGICAL_UNIT",
        0x21 => "SET_LINK_TIMEOUT",
        0x22 => "LINK_TIMEOUT_OCCURRED",
        0x23 => "LINK_TIMEOUT_COMPLETE",
        0x24 => "POWER",
        0x25 => "PNP",
        0x26 => "DUMP_POINTERS",
        0x27 => "FREE_DUMP_POINTERS",
        0x28 => "STORAGE_REQUEST_BLOCK",
        0x29 => "CRYPTO_OPERATION",
        0x2a => "GET_DUMP_INFO",
        0x2b => "FREE_DUMP_INFO",
        _ => return None,
    })
}

/// An `SrbStatus` byte: the `SRB_STATUS_*` name of its low six bits, then
/// `QUEUE_FROZEN` and `AUTOSENSE_VALID` when those flags are set.
pub fn srb_status_text(status: u8) -> String {
    let code = status & !(SRB_STATUS_QUEUE_FROZEN | SRB_STATUS_AUTOSENSE_VALID);
    let mut text = match code {
        0x00 => "PENDING".to_string(),
        0x01 => "SUCCESS".to_string(),
        0x02 => "ABORTED".to_string(),
        0x03 => "ABORT_FAILED".to_string(),
        0x04 => "ERROR".to_string(),
        0x05 => "BUSY".to_string(),
        0x06 => "INVALID_REQUEST".to_string(),
        0x07 => "INVALID_PATH_ID".to_string(),
        0x08 => "NO_DEVICE".to_string(),
        0x09 => "TIMEOUT".to_string(),
        0x0a => "SELECTION_TIMEOUT".to_string(),
        0x0b => "COMMAND_TIMEOUT".to_string(),
        0x0d => "MESSAGE_REJECTED".to_string(),
        0x0e => "BUS_RESET".to_string(),
        0x0f => "PARITY_ERROR".to_string(),
        0x10 => "REQUEST_SENSE_FAILED".to_string(),
        0x11 => "NO_HBA".to_string(),
        0x12 => "DATA_OVERRUN".to_string(),
        0x13 => "UNEXPECTED_BUS_FREE".to_string(),
        0x14 => "PHASE_SEQUENCE_FAILURE".to_string(),
        0x15 => "BAD_SRB_BLOCK_LENGTH".to_string(),
        0x16 => "REQUEST_FLUSHED".to_string(),
        0x20 => "INVALID_LUN".to_string(),
        0x21 => "INVALID_TARGET_ID".to_string(),
        0x22 => "BAD_FUNCTION".to_string(),
        0x23 => "ERROR_RECOVERY".to_string(),
        0x24 => "NOT_POWERED".to_string(),
        0x25 => "LINK_DOWN".to_string(),
        0x26 => "INSUFFICIENT_RESOURCES".to_string(),
        0x27 => "THROTTLED_REQUEST".to_string(),
        0x28 => "INVALID_PARAMETER".to_string(),
        other => format!("{other:#04x}"),
    };
    if status & SRB_STATUS_QUEUE_FROZEN != 0 {
        text.push_str(", QUEUE_FROZEN");
    }
    if status & SRB_STATUS_AUTOSENSE_VALID != 0 {
        text.push_str(", AUTOSENSE_VALID");
    }
    text
}

/// The `SRB_FLAGS_*` bits of `srb.h`, without the prefix. The top byte
/// belongs to the class driver and the one below it to the port driver.
const SRB_FLAG_NAMES: &[(u32, &str)] = &[
    (0x0000_0002, "QUEUE_ACTION_ENABLE"),
    (0x0000_0004, "DISABLE_DISCONNECT"),
    (0x0000_0008, "DISABLE_SYNCH_TRANSFER"),
    (0x0000_0010, "BYPASS_FROZEN_QUEUE"),
    (0x0000_0020, "DISABLE_AUTOSENSE"),
    (0x0000_0040, "DATA_IN"),
    (0x0000_0080, "DATA_OUT"),
    (0x0000_0100, "NO_QUEUE_FREEZE"),
    (0x0000_0200, "ADAPTER_CACHE_ENABLE"),
    (0x0000_0400, "FREE_SENSE_BUFFER"),
    (0x0000_0800, "D3_PROCESSING"),
    (0x0000_1000, "SEQUENTIAL_REQUIRED"),
    (0x0001_0000, "IS_ACTIVE"),
    (0x0002_0000, "ALLOCATED_FROM_ZONE"),
    (0x0004_0000, "SGLIST_FROM_POOL"),
    (0x0008_0000, "BYPASS_LOCKED_QUEUE"),
    (0x0010_0000, "NO_KEEP_AWAKE"),
    (0x0020_0000, "PORT_DRIVER_ALLOCSENSE"),
    (0x0040_0000, "PORT_DRIVER_SENSEHASPORT"),
    (0x0080_0000, "DONT_START_NEXT_PACKET"),
];
const SRB_FLAGS_PORT_DRIVER_RESERVED: u32 = 0x0f00_0000;
const SRB_FLAGS_CLASS_DRIVER_RESERVED: u32 = 0xf000_0000;

/// The names of the `SRB_FLAGS_*` bits set in `flags`; the reserved bytes
/// show as `PORT_DRIVER_RESERVED` and `CLASS_DRIVER_RESERVED` with their
/// bits, and bits `srb.h` does not name in hex.
pub fn srb_flag_names(flags: u32) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest = flags;
    for &(bit, name) in SRB_FLAG_NAMES {
        if flags & bit != 0 {
            names.push(name.to_string());
            rest &= !bit;
        }
    }
    for (mask, name) in [
        (SRB_FLAGS_PORT_DRIVER_RESERVED, "PORT_DRIVER_RESERVED"),
        (SRB_FLAGS_CLASS_DRIVER_RESERVED, "CLASS_DRIVER_RESERVED"),
    ] {
        if flags & mask != 0 {
            names.push(format!("{name}({:#x})", flags & mask));
            rest &= !mask;
        }
    }
    if rest != 0 {
        names.push(format!("{rest:#x}"));
    }
    names
}

/// One block of an extended SRB's extended data (`SRBEX_DATA`).
#[derive(Debug, Clone)]
pub struct SrbExData {
    pub address: VirtAddr,
    /// `_SRBEXDATATYPE` without its `SrbExDataType` prefix (`ScsiCdb16`).
    pub kind: String,
    pub length: u32,
}

/// A decoded SRB (`!storagekd.storsrb`).
#[derive(Debug, Clone)]
pub struct Srb {
    pub address: VirtAddr,
    /// A `STORAGE_REQUEST_BLOCK`, rather than a `SCSI_REQUEST_BLOCK`.
    pub extended: bool,
    /// `SrbFunction` of an extended SRB, else `Function`.
    pub function: u32,
    pub srb_status: u8,
    pub scsi_status: Option<u8>,
    pub flags: u32,
    /// Port, path, target, and LUN; a legacy SRB has no port.
    pub port: Option<u16>,
    pub path_target_lun: Option<(u8, u8, u8)>,
    pub data_transfer_length: u32,
    pub data_buffer: VirtAddr,
    pub timeout: u32,
    /// `OriginalRequest`: the IRP the SRB carries.
    pub original_request: VirtAddr,
    pub next_srb: VirtAddr,
    pub request_tag: Option<u32>,
    pub priority: Option<u16>,
    pub cdb: Vec<u8>,
    pub sense_buffer: VirtAddr,
    pub sense_length: u8,
    /// The sense data, decoded, when `SRB_STATUS_AUTOSENSE_VALID` says it
    /// holds some.
    pub sense: Option<String>,
    /// The contexts an extended SRB keeps for the class driver, the port
    /// driver, and the miniport.
    pub contexts: Option<[VirtAddr; 3]>,
    pub ex_data: Vec<SrbExData>,
}

fn srb_layout(types: Types<'_>, name: &str) -> Result<Arc<TypeInfo>> {
    types.layout(format!("storport!{name}")).map_err(|_| {
        Error::DebugInfo(format!(
            "storport's symbols do not describe {name}; is storport.sys loaded with its PDB \
             (.reload storport.sys)?"
        ))
    })
}

/// The CDB-carrying fields of an `SRBEX_DATA_SCSI_CDB*` block.
struct CdbBlock {
    scsi_status: u8,
    sense_length: u8,
    sense_buffer: VirtAddr,
    cdb: Vec<u8>,
}

impl Target {
    /// The SRB at `address`: an extended SRB when its `Function` is
    /// `SRB_FUNCTION_STORAGE_REQUEST_BLOCK` and its `Signature` is
    /// `SRB_SIGNATURE`, else a legacy SRB when its `Length` is that of a
    /// `SCSI_REQUEST_BLOCK`. Anything else is refused.
    pub fn decode_srb(&self, address: VirtAddr) -> Result<Srb> {
        let types = self.types_in(self.kernel_dtb());
        let mut header = [0u8; 4];
        self.kernel_address_space()
            .read_bytes(address, &mut header)
            .map_err(|error| Error::DebugInfo(format!("{:#x}: {error}", address.0)))?;
        let length = u16::from_le_bytes([header[0], header[1]]);
        let function = header[2];
        if function == SRB_FUNCTION_STORAGE_REQUEST_BLOCK {
            let layout = srb_layout(types, "_STORAGE_REQUEST_BLOCK")?;
            let srb = types.struct_with_layout(layout, address).prefetch();
            let signature = srb.read_uint("Signature")?;
            if signature != SRB_SIGNATURE {
                return Err(Error::DebugInfo(format!(
                    "{:#x} is not an SRB: its Function is STORAGE_REQUEST_BLOCK, but its \
                     Signature is {signature:#x}, not SRB_SIGNATURE ({SRB_SIGNATURE:#x})",
                    address.0
                )));
            }
            return self.extended_srb(types, &srb);
        }
        let layout = srb_layout(types, "_SCSI_REQUEST_BLOCK")?;
        if u64::from(length) != layout.size as u64 {
            return Err(Error::DebugInfo(format!(
                "{:#x} is not an SRB: its Function {function:#x} is not STORAGE_REQUEST_BLOCK, \
                 and its Length {length:#x} is not that of a SCSI_REQUEST_BLOCK ({:#x})",
                address.0, layout.size
            )));
        }
        let srb = types.struct_with_layout(layout, address).prefetch();
        let srb_status = srb.read_uint("SrbStatus")? as u8;
        let cdb_length = (srb.read_uint("CdbLength")? as usize).min(16);
        let mut cdb = srb.read_field_bytes("Cdb", 16)?;
        cdb.truncate(cdb_length);
        let sense_buffer = srb.read_pointer("SenseInfoBuffer")?;
        let sense_length = srb.read_uint("SenseInfoBufferLength")? as u8;
        Ok(Srb {
            address,
            extended: false,
            function: u32::from(function),
            srb_status,
            scsi_status: Some(srb.read_uint("ScsiStatus")? as u8),
            flags: srb.read_uint("SrbFlags")? as u32,
            port: None,
            path_target_lun: Some((
                srb.read_uint("PathId")? as u8,
                srb.read_uint("TargetId")? as u8,
                srb.read_uint("Lun")? as u8,
            )),
            data_transfer_length: srb.read_uint("DataTransferLength")? as u32,
            data_buffer: srb.read_pointer("DataBuffer")?,
            timeout: srb.read_uint("TimeOutValue")? as u32,
            original_request: srb.read_pointer("OriginalRequest")?,
            next_srb: srb.read_pointer("NextSrb")?,
            request_tag: None,
            priority: None,
            cdb,
            sense: self.srb_sense(srb_status, sense_buffer, sense_length),
            sense_buffer,
            sense_length,
            contexts: None,
            ex_data: Vec::new(),
        })
    }

    fn extended_srb(&self, types: Types<'_>, srb: &StructRef<'_>) -> Result<Srb> {
        let address = srb.addr();
        let srb_status = srb.read_uint("SrbStatus")? as u8;
        let kinds = self
            .symbols
            .find_enum_across_modules(self.kernel_dtb(), "storport!_SRBEXDATATYPE")
            .unwrap_or_default();
        let kind_name = |value: u64| -> String {
            kinds
                .iter()
                .find(|(_, variant)| *variant as u64 == value)
                .map(|(name, _)| {
                    name.strip_prefix("SrbExDataType")
                        .unwrap_or(name)
                        .to_string()
                })
                .unwrap_or_else(|| format!("{value:#x}"))
        };
        let memory = self.kernel_address_space();
        let offsets_at = address + srb.layout().field_offset("SrbExDataOffset")?;
        let count = srb.read_uint("NumSrbExData")?.min(MAX_SRB_EX_DATA);
        let mut ex_data = Vec::new();
        let mut cdb_block = None;
        for index in 0..count {
            let offset = memory.read::<u32>(offsets_at + index * 4)?;
            if offset == 0 {
                continue;
            }
            let at = address + u64::from(offset);
            let block = types.struct_at("storport!_SRBEX_DATA", at)?;
            let kind = block.read_uint("Type")?;
            let kind = kind_name(kind);
            if cdb_block.is_none() {
                cdb_block = self.srb_cdb_block(types, &kind, at)?;
            }
            ex_data.push(SrbExData {
                address: at,
                length: block.read_uint("Length")? as u32,
                kind,
            });
        }
        let address_offset = srb.read_uint("AddressOffset")?;
        let (port, path_target_lun) = if address_offset == 0 {
            (None, None)
        } else {
            let btl = types.struct_at("storport!_STOR_ADDR_BTL8", address + address_offset)?;
            if btl.read_uint("Type")? == STOR_ADDRESS_TYPE_BTL8 {
                (
                    Some(btl.read_uint("Port")? as u16),
                    Some((
                        btl.read_uint("Path")? as u8,
                        btl.read_uint("Target")? as u8,
                        btl.read_uint("Lun")? as u8,
                    )),
                )
            } else {
                (None, None)
            }
        };
        let (scsi_status, sense_buffer, sense_length, cdb) = match cdb_block {
            Some(block) => (
                Some(block.scsi_status),
                block.sense_buffer,
                block.sense_length,
                block.cdb,
            ),
            None => (None, VirtAddr(0), 0, Vec::new()),
        };
        Ok(Srb {
            address,
            extended: true,
            function: srb.read_uint("SrbFunction")? as u32,
            srb_status,
            scsi_status,
            flags: srb.read_uint("SrbFlags")? as u32,
            port,
            path_target_lun,
            data_transfer_length: srb.read_uint("DataTransferLength")? as u32,
            data_buffer: srb.read_pointer("DataBuffer")?,
            timeout: srb.read_uint("TimeOutValue")? as u32,
            original_request: srb.read_pointer("OriginalRequest")?,
            next_srb: srb.read_pointer("NextSrb")?,
            request_tag: Some(srb.read_uint("RequestTag")? as u32),
            priority: Some(srb.read_uint("RequestPriority")? as u16),
            cdb,
            sense: self.srb_sense(srb_status, sense_buffer, sense_length),
            sense_buffer,
            sense_length,
            contexts: Some([
                srb.read_pointer("ClassContext")?,
                srb.read_pointer("PortContext")?,
                srb.read_pointer("MiniportContext")?,
            ]),
            ex_data,
        })
    }

    /// The CDB, SCSI status, and sense buffer of an extended data block of
    /// kind `kind` at `at`; `None` for a block that carries no CDB.
    fn srb_cdb_block(
        &self,
        types: Types<'_>,
        kind: &str,
        at: VirtAddr,
    ) -> Result<Option<CdbBlock>> {
        let (layout, variable) = match kind {
            "ScsiCdb16" => ("_SRBEX_DATA_SCSI_CDB16", false),
            "ScsiCdb32" => ("_SRBEX_DATA_SCSI_CDB32", false),
            "ScsiCdbVar" => ("_SRBEX_DATA_SCSI_CDB_VAR", true),
            _ => return Ok(None),
        };
        let block = types
            .struct_with_layout(srb_layout(types, layout)?, at)
            .prefetch();
        let cdb_length = block.read_uint("CdbLength")? as usize;
        let cdb = if variable {
            let mut cdb = vec![0u8; cdb_length.min(MAX_CDB)];
            self.kernel_address_space()
                .read_bytes(at + block.layout().field_offset("Cdb")?, &mut cdb)?;
            cdb
        } else {
            let mut cdb = block.read_field_bytes("Cdb", 32)?;
            cdb.truncate(cdb_length);
            cdb
        };
        Ok(Some(CdbBlock {
            scsi_status: block.read_uint("ScsiStatus")? as u8,
            sense_length: block.read_uint("SenseInfoBufferLength")? as u8,
            sense_buffer: block.read_pointer("SenseInfoBuffer")?,
            cdb,
        }))
    }

    /// The sense data an SRB's status says is valid, decoded.
    fn srb_sense(&self, srb_status: u8, buffer: VirtAddr, length: u8) -> Option<String> {
        if srb_status & SRB_STATUS_AUTOSENSE_VALID == 0 || buffer.is_zero() || length == 0 {
            return None;
        }
        let mut sense = vec![0u8; usize::from(length)];
        self.kernel_address_space()
            .read_bytes(buffer, &mut sense)
            .ok()?;
        sense_text(&sense)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn srb_status_names_the_code_then_its_flags() {
        assert_eq!(srb_status_text(0x01), "SUCCESS");
        // An error with sense and a frozen queue, as a disk's medium error
        // completes.
        assert_eq!(
            srb_status_text(0xc4),
            "ERROR, QUEUE_FROZEN, AUTOSENSE_VALID"
        );
        assert_eq!(srb_status_text(0x3f), "0x3f");
    }

    #[test]
    fn srb_flags_name_the_reserved_bytes_with_their_bits() {
        // A read classpnp sent through storport, seen live on build 26200.
        assert_eq!(
            srb_flag_names(0x4020_0342),
            [
                "QUEUE_ACTION_ENABLE",
                "DATA_IN",
                "NO_QUEUE_FREEZE",
                "ADAPTER_CACHE_ENABLE",
                "PORT_DRIVER_ALLOCSENSE",
                "CLASS_DRIVER_RESERVED(0x40000000)",
            ]
        );
        assert_eq!(srb_flag_names(0x1), ["0x1"]);
    }
}
