//! The WPP recorder (`!rcdrkd.*`): the in-flight logs that WppRecorder.sys
//! keeps for each driver built with WPP's recorder (the IFR of drivers that
//! are not KMDF's, and of KMDF drivers' own WPP messages), read with
//! WppRecorder's public PDB.
//!
//! The recorder keeps no global list of the drivers it serves. It registers
//! a bugcheck reason callback for each driver's context
//! (`WppAutoLogpBugCheckCallbackForDriver`) so the logs reach a crash dump,
//! and that callback record, on `nt!KeBugCheckReasonCallbackListHead`, is
//! how these commands find each driver. A driver's logs are on its
//! context's `LogListHead`. Each log has a normal and an error partition,
//! each a ring of records in KMDF's IFR record format.

use std::sync::Arc;

use super::{Target, bounded_list_walk};
use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::layout::{TypeInfo, Types, le_uint};
use crate::target::wdf::{IfrEnd, IfrRecordLayout, WdfLogEntry, walk_ifr};
use crate::types::VirtAddr;

const MAX_CALLBACKS: usize = 8192;
const MAX_LOGS: usize = 1024;
/// More bytes than a partition's USHORT offsets reach.
const MAX_PARTITION: u64 = 0x10000;
const DRIVER_CALLBACK: &str = "wpprecorder!WppAutoLogpBugCheckCallbackForDriver";
const CALLBACK_LIST: &str = "nt!KeBugCheckReasonCallbackListHead";

/// A driver the WPP recorder serves (`_WPP_AUTOLOG_CONTEXT`).
#[derive(Debug, Clone)]
pub struct RcdrDriver {
    pub context: VirtAddr,
    /// `FileBaseName`: the driver's image name without its extension.
    pub name: String,
    pub image: VirtAddr,
    pub image_size: u32,
    /// The logs on its `LogListHead`.
    pub logs: Vec<VirtAddr>,
    pub logs_stopped: Option<String>,
    /// `DefaultAutoLogHeader`, the log `WppRecorderLogGetDefault` returns.
    pub default_log: VirtAddr,
    /// The context's `Sequence`: the last sequence number a record of any of
    /// its logs took.
    pub sequence: i32,
}

/// A partition of a recorder log: the ring its records go to.
#[derive(Debug, Clone)]
pub struct RcdrPartition {
    /// `normal` or `error`.
    pub name: &'static str,
    pub base: VirtAddr,
    pub size: u32,
    /// `Offset.Current`, where the next record goes, and `Offset.Previous`,
    /// the newest record.
    pub current: u16,
    pub previous: u16,
}

/// A recorder log (`_WPP_AUTOLOG_HEADER`).
#[derive(Debug, Clone)]
pub struct RcdrLog {
    pub header: VirtAddr,
    /// `LogIdentifier`, with `LogIdentifierAppendValue` after it when the
    /// driver set one.
    pub identifier: String,
    pub id_number: u16,
    pub size: u32,
    pub deleted: bool,
    /// Records are 'L2', with a timestamp.
    pub timestamps: bool,
    pub partitions: Vec<RcdrPartition>,
}

/// A log as a list shows it, or its header's address and why it does not
/// read.
pub type RcdrLogEntry = std::result::Result<RcdrLog, (VirtAddr, String)>;

/// A record of a log's partition, formatted.
#[derive(Debug, Clone)]
pub struct RcdrEntry {
    /// The index of its log in [`RcdrLogDump::logs`], and its partition.
    pub log: usize,
    pub partition: &'static str,
    pub entry: WdfLogEntry,
}

/// A driver's recorder logs, their records merged in sequence order
/// (`!rcdrkd.rcdrlogdump`).
#[derive(Debug, Clone)]
pub struct RcdrLogDump {
    pub driver: RcdrDriver,
    pub logs: Vec<RcdrLog>,
    pub entries: Vec<RcdrEntry>,
    /// How each walk of a partition ended: its log index, partition, and
    /// end.
    pub ends: Vec<(usize, &'static str, IfrEnd)>,
}

/// The drivers the recorder serves, and why the callback walk stopped
/// short.
#[derive(Debug, Clone)]
pub struct RcdrDriverList {
    pub drivers: Vec<std::result::Result<RcdrDriver, (VirtAddr, String)>>,
    pub stopped: Option<String>,
}

fn rcdr_layout(types: Types<'_>, name: &str) -> Result<Arc<TypeInfo>> {
    types.layout(format!("wpprecorder!{name}")).map_err(|_| {
        Error::DebugInfo(format!(
            "WppRecorder's symbols do not describe {name}; is WppRecorder.sys loaded with its \
             PDB (.reload wpprecorder.sys)?"
        ))
    })
}

/// A NUL-terminated ANSI `CHAR` array.
fn ansi(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// Where `_WPP_AUTOLOG_RECORD`'s fields sit: KMDF's IFR record.
fn record_layout(types: Types<'_>) -> Result<IfrRecordLayout> {
    let record = rcdr_layout(types, "_WPP_AUTOLOG_RECORD")?;
    let at = |name: &str| -> Result<usize> { Ok(record.field_offset(name)? as usize) };
    Ok(IfrRecordLayout {
        size: record.size,
        signature: at("Signature")?,
        length: at("Length")?,
        sequence: at("Sequence")?,
        prev_offset: at("PrevOffset")?,
        message_number: at("MessageNumber")?,
        message_guid: at("MessageGuid")?,
        timestamp: at("TimeStamp")?,
    })
}

impl Target {
    /// The driver contexts whose bugcheck callback the recorder registered.
    fn rcdr_contexts(&self, types: Types<'_>) -> Result<(Vec<VirtAddr>, Option<String>)> {
        let lookup = |name: &str| -> Result<VirtAddr> {
            self.symbols
                .find_symbol_across_modules(self.kernel_dtb(), name)?
                .ok_or_else(|| {
                    Error::DebugInfo(format!(
                        "{name} is not in the symbols; is WppRecorder.sys loaded with its PDB \
                         (.reload wpprecorder.sys)?"
                    ))
                })
        };
        let routine = lookup(DRIVER_CALLBACK)?;
        let head = lookup(CALLBACK_LIST)?;
        let record = rcdr_layout(types, "_KBUGCHECK_REASON_CALLBACK_RECORD")?;
        let routine_at = record.field_offset("CallbackRoutine")?;
        let context = rcdr_layout(types, "_WPP_AUTOLOG_CONTEXT")?;
        let record_at = context.field_offset("DriverBugCheckCallbackRecord")?;
        let memory = self.kernel_address_space();
        let (links, termination) =
            bounded_list_walk(head, MAX_CALLBACKS, |at| memory.read::<VirtAddr>(at));
        // `Entry` is the record's first field, so a link is its record.
        let contexts = links
            .into_iter()
            .filter(|&link| {
                memory
                    .read::<VirtAddr>(link + routine_at)
                    .is_ok_and(|callback| callback == routine)
            })
            .map(|link| link - record_at)
            .collect();
        Ok((contexts, termination.diagnostic()))
    }

    fn rcdr_driver(&self, types: Types<'_>, address: VirtAddr) -> Result<RcdrDriver> {
        let context = types
            .struct_with_layout(rcdr_layout(types, "_WPP_AUTOLOG_CONTEXT")?, address)
            .prefetch();
        let header = rcdr_layout(types, "_WPP_AUTOLOG_HEADER")?;
        let link = header.field_offset("LogListEntry")?;
        let head = address + context.layout().field_offset("LogListHead")?;
        let memory = self.kernel_address_space();
        let (links, termination) =
            bounded_list_walk(head, MAX_LOGS, |at| memory.read::<VirtAddr>(at));
        Ok(RcdrDriver {
            context: address,
            name: ansi(&context.read_field_bytes("FileBaseName", 64)?),
            image: context.read_pointer("ImageAddress")?,
            image_size: context.read_uint("ImageSize")? as u32,
            logs: links.into_iter().map(|at| at - link).collect(),
            logs_stopped: termination.diagnostic(),
            default_log: context.read_pointer("DefaultAutoLogHeader")?,
            sequence: context.read_uint("Sequence")? as u32 as i32,
        })
    }

    /// The drivers the WPP recorder serves.
    pub fn rcdr_drivers(&self) -> Result<RcdrDriverList> {
        let types = self.types_in(self.kernel_dtb());
        let (contexts, stopped) = self.rcdr_contexts(types)?;
        let drivers = contexts
            .into_iter()
            .map(|context| {
                self.rcdr_driver(types, context)
                    .map_err(|error| (context, error.to_string()))
            })
            .collect();
        Ok(RcdrDriverList { drivers, stopped })
    }

    /// The driver the recorder serves that `name` names: its
    /// `FileBaseName` or its module's name, with or without `.sys`, in any
    /// case, or the address of its context.
    pub fn rcdr_driver_named(&self, name: &str) -> Result<RcdrDriver> {
        let list = self.rcdr_drivers()?;
        let wanted = name.trim_end_matches(".sys").trim_end_matches(".SYS");
        let parsed = u64::from_str_radix(name.trim_start_matches("0x"), 16).ok();
        let mut known = Vec::new();
        for driver in list.drivers.into_iter().flatten() {
            let module = self
                .module_containing(driver.image)
                .map(|module| module.short_name);
            if driver.name.eq_ignore_ascii_case(wanted)
                || module
                    .as_deref()
                    .is_some_and(|module| module.eq_ignore_ascii_case(wanted))
                || parsed == Some(driver.context.0)
            {
                return Ok(driver);
            }
            known.push(driver.name);
        }
        known.sort_unstable_by_key(|name| name.to_ascii_lowercase());
        Err(Error::DebugInfo(format!(
            "the WPP recorder has no logs for {name}; it serves {}",
            if known.is_empty() {
                "no drivers".to_string()
            } else {
                known.join(", ")
            }
        )))
    }

    fn rcdr_log(&self, types: Types<'_>, header: VirtAddr) -> Result<RcdrLog> {
        let log = types
            .struct_with_layout(rcdr_layout(types, "_WPP_AUTOLOG_HEADER")?, header)
            .prefetch();
        let mut identifier = ansi(&log.read_field_bytes("LogIdentifier", 16)?);
        if log.read_uint("LogIdentifierAppendValueSet")? != 0 {
            identifier.push_str(&format!(" {}", log.read_uint("LogIdentifierAppendValue")?));
        }
        let mut partitions = Vec::new();
        for (name, field) in [("normal", "NormalPartition"), ("error", "ErrorPartition")] {
            let partition = log.embedded(field)?;
            // `Offset` is `{USHORT Current; USHORT Previous}` read as one
            // LONG, as KMDF's IFR header keeps it.
            let offset = le_uint(&partition.read_field_bytes("Offset", 4)?) as u32;
            partitions.push(RcdrPartition {
                name,
                base: partition.read_pointer("Base")?,
                size: partition.read_uint("Size")? as u32,
                current: offset as u16,
                previous: (offset >> 16) as u16,
            });
        }
        Ok(RcdrLog {
            header,
            identifier,
            id_number: log.read_uint("LogIdNumber")? as u16,
            size: log.read_uint("Size")? as u32,
            deleted: log.read_uint("Deleted")? != 0,
            timestamps: log.read_uint("UseTimeStamp")? != 0,
            partitions,
        })
    }

    /// The logs of the driver `name` names, each with its partitions.
    pub fn rcdr_logs(&self, name: &str) -> Result<(RcdrDriver, Vec<RcdrLogEntry>)> {
        let types = self.types_in(self.kernel_dtb());
        let driver = self.rcdr_driver_named(name)?;
        let logs = driver
            .logs
            .iter()
            .map(|&header| {
                self.rcdr_log(types, header)
                    .map_err(|error| (header, error.to_string()))
            })
            .collect();
        Ok((driver, logs))
    }

    /// The records of the driver `name` names, from every log, or only the
    /// log whose header is at `only`, merged in sequence order and
    /// formatted with the TMF messages loaded PDBs declare.
    pub fn rcdr_log_dump(&self, name: &str, only: Option<VirtAddr>) -> Result<RcdrLogDump> {
        let types = self.types_in(self.kernel_dtb());
        let driver = self.rcdr_driver_named(name)?;
        let headers: Vec<VirtAddr> = match only {
            Some(header) if driver.logs.contains(&header) => vec![header],
            Some(header) => {
                return Err(Error::DebugInfo(format!(
                    "{:#x} is not one of {}'s logs; !rcdrkd.rcdrloglist {} lists them",
                    header.0, driver.name, driver.name
                )));
            }
            None => driver.logs.clone(),
        };
        let layout = record_layout(types)?;
        let pointer_size = rcdr_layout(types, "_WPP_AUTOLOG_RECORD")?.pointer_size;
        let mut logs = Vec::new();
        let mut entries = Vec::new();
        let mut ends = Vec::new();
        for header in headers {
            let log = self.rcdr_log(types, header)?;
            let index = logs.len();
            for partition in &log.partitions {
                if partition.base.is_zero() || partition.size == 0 {
                    continue;
                }
                if u64::from(partition.size) > MAX_PARTITION {
                    ends.push((
                        index,
                        partition.name,
                        IfrEnd::Corrupt(format!(
                            "its Size {:#x} is more than its offsets reach",
                            partition.size
                        )),
                    ));
                    continue;
                }
                let mut bytes = vec![0u8; partition.size as usize];
                if let Err(error) = self
                    .kernel_address_space()
                    .read_bytes(partition.base, &mut bytes)
                {
                    ends.push((
                        index,
                        partition.name,
                        IfrEnd::Corrupt(format!("{:#x}: {error}", partition.base.0)),
                    ));
                    continue;
                }
                let walk = walk_ifr(
                    &bytes,
                    usize::from(partition.current),
                    usize::from(partition.previous),
                    &layout,
                );
                ends.push((index, partition.name, walk.end));
                entries.extend(
                    self.wdf_log_entries(walk.records, pointer_size)
                        .into_iter()
                        .map(|entry| RcdrEntry {
                            log: index,
                            partition: partition.name,
                            entry,
                        }),
                );
            }
            logs.push(log);
        }
        // The driver's logs draw from one sequence counter, so its order is
        // the order the driver logged in; it wraps as an i32.
        let newest = driver.sequence;
        entries.sort_by_key(|entry| newest.wrapping_sub(entry.entry.record.sequence) as u32);
        entries.reverse();
        Ok(RcdrLogDump {
            driver,
            logs,
            entries,
            ends,
        })
    }
}
