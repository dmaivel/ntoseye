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

use ntoseye_macros::record;

use super::{Target, bounded_list_walk, bounded_record_list_walk};
use crate::bytes::c_string_lossy;
use crate::error::{Error, Result};
use crate::layout::{TypeInfo, Types, le_uint};
use crate::memory::MemoryOps;
use crate::target::wdf::{IfrEnd, IfrRecordLayout, WdfLogEntry, walk_ifr};
use crate::types::VirtAddr;

const MAX_CALLBACKS: usize = 8192;
const MAX_LOGS: usize = 1024;
/// More bytes than a partition's USHORT offsets reach.
const MAX_PARTITION: u64 = 0x10000;
const DRIVER_CALLBACK: &str = "wpprecorder!WppAutoLogpBugCheckCallbackForDriver";
const CALLBACK_LIST: &str = "nt!KeBugCheckReasonCallbackListHead";

/// A driver the WPP recorder serves (`_WPP_AUTOLOG_CONTEXT`).
#[record]
#[derive(Debug, Clone)]
pub struct RcdrDriver {
    pub context: VirtAddr,
    /// `FileBaseName`: the driver's image name without its extension.
    pub name: String,
    pub image: VirtAddr,
    #[record(hex)]
    pub image_size: u32,
    /// The `_WPP_AUTOLOG_HEADER` of each of its logs (its `LogListHead`).
    pub logs: Vec<VirtAddr>,
    pub logs_stopped: Option<String>,
    /// `DefaultAutoLogHeader`, the log `WppRecorderLogGetDefault` returns.
    pub default_log: VirtAddr,
    /// The context's `Sequence`: the last sequence number a record of any of
    /// its logs took.
    pub sequence: i32,
}

/// A recorder context or log header that does not read.
#[record]
#[derive(Debug, Clone)]
pub struct RcdrUnreadable {
    pub address: VirtAddr,
    pub error: String,
}

/// The drivers the recorder serves (`!rcdrkd.rcdrloglist`).
#[record]
#[derive(Debug, Clone)]
pub struct RcdrDriverList {
    pub drivers: Vec<RcdrDriver>,
    /// The contexts that do not read.
    pub unreadable: Vec<RcdrUnreadable>,
    /// Why the walk of the bugcheck callback list stopped short.
    pub stopped: Option<String>,
}

/// A partition of a recorder log: the ring its records go to.
#[record]
#[derive(Debug, Clone)]
pub struct RcdrPartition {
    /// `normal` or `error`.
    pub name: &'static str,
    pub base: VirtAddr,
    #[record(hex)]
    pub size: u32,
    /// `Offset.Current`, where the next record goes.
    #[record(hex)]
    pub current: u16,
    /// `Offset.Previous`, the newest record.
    #[record(hex)]
    pub previous: u16,
}

/// A recorder log (`_WPP_AUTOLOG_HEADER`).
#[record]
#[derive(Debug, Clone)]
pub struct RcdrLog {
    pub header: VirtAddr,
    /// `LogIdentifier`, with `LogIdentifierAppendValue` after it when the
    /// driver set one.
    pub identifier: String,
    pub id_number: u16,
    #[record(hex)]
    pub size: u32,
    pub deleted: bool,
    /// Records are 'L2', with a timestamp.
    pub timestamps: bool,
    /// Whether it is the driver's default log.
    pub default: bool,
    pub partitions: Vec<RcdrPartition>,
}

/// A driver's logs (`!rcdrkd.rcdrloglist <driver>`).
#[record]
#[derive(Debug, Clone)]
pub struct RcdrLogs {
    pub driver: RcdrDriver,
    pub logs: Vec<RcdrLog>,
    /// The log headers that do not read.
    pub unreadable: Vec<RcdrUnreadable>,
}

/// A record of a log's partition, formatted.
#[record]
#[derive(Debug, Clone)]
pub struct RcdrEntry {
    /// The index of its log in `RcdrLogDump.logs`.
    pub log: usize,
    /// `normal` or `error`.
    pub partition: &'static str,
    pub entry: WdfLogEntry,
}

/// How the walk of one partition ended.
#[record]
#[derive(Debug, Clone)]
pub struct RcdrWalkEnd {
    /// The index of its log in `RcdrLogDump.logs`.
    pub log: usize,
    /// `normal` or `error`.
    pub partition: &'static str,
    pub end: IfrEnd,
}

/// A driver's records from its logs, merged in the order the driver logged
/// them, oldest first (`!rcdrkd.rcdrlogdump`).
#[record]
#[derive(Debug, Clone)]
pub struct RcdrLogDump {
    pub driver: RcdrDriver,
    pub logs: Vec<RcdrLog>,
    pub entries: Vec<RcdrEntry>,
    /// How each walk of a partition ended.
    pub ends: Vec<RcdrWalkEnd>,
}

fn rcdr_layout(types: Types<'_>, name: &str) -> Result<Arc<TypeInfo>> {
    types.layout(format!("wpprecorder!{name}")).map_err(|_| {
        Error::DebugInfo(format!(
            "WppRecorder's symbols do not describe {name}; is WppRecorder.sys loaded with its \
             PDB (.reload wpprecorder.sys)?"
        ))
    })
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
        let (logs, termination) =
            bounded_record_list_walk(head, link, MAX_LOGS, |at| memory.read::<VirtAddr>(at));
        Ok(RcdrDriver {
            context: address,
            name: c_string_lossy(&context.read_field_bytes("FileBaseName", 64)?),
            image: context.read_pointer("ImageAddress")?,
            image_size: context.read_uint("ImageSize")? as u32,
            logs,
            logs_stopped: termination.diagnostic(),
            default_log: context.read_pointer("DefaultAutoLogHeader")?,
            sequence: context.read_uint("Sequence")? as u32 as i32,
        })
    }

    /// The drivers the WPP recorder serves.
    pub fn rcdr_drivers(&self) -> Result<RcdrDriverList> {
        let types = self.types_in(self.kernel_dtb());
        let (contexts, stopped) = self.rcdr_contexts(types)?;
        let mut drivers = Vec::new();
        let mut unreadable = Vec::new();
        for context in contexts {
            match self.rcdr_driver(types, context) {
                Ok(driver) => drivers.push(driver),
                Err(error) => unreadable.push(RcdrUnreadable {
                    address: context,
                    error: error.to_string(),
                }),
            }
        }
        Ok(RcdrDriverList {
            drivers,
            unreadable,
            stopped,
        })
    }

    /// The driver the recorder serves that `name` names: its
    /// `FileBaseName` or its module's name, with or without `.sys`, in any
    /// case, or the address of its context.
    pub fn rcdr_driver_named(&self, name: &str) -> Result<RcdrDriver> {
        let list = self.rcdr_drivers()?;
        let wanted = name.trim_end_matches(".sys").trim_end_matches(".SYS");
        let parsed = u64::from_str_radix(name.trim_start_matches("0x"), 16).ok();
        let mut known = Vec::new();
        for driver in list.drivers {
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

    /// The log whose header is at `header`, of the driver whose default log
    /// is `default_log`.
    fn rcdr_log(
        &self,
        types: Types<'_>,
        header: VirtAddr,
        default_log: VirtAddr,
    ) -> Result<RcdrLog> {
        let log = types
            .struct_with_layout(rcdr_layout(types, "_WPP_AUTOLOG_HEADER")?, header)
            .prefetch();
        let mut identifier = c_string_lossy(&log.read_field_bytes("LogIdentifier", 16)?);
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
            default: header == default_log,
            partitions,
        })
    }

    /// The logs of the driver `name` names, each with its partitions.
    pub fn rcdr_logs(&self, name: &str) -> Result<RcdrLogs> {
        let types = self.types_in(self.kernel_dtb());
        let driver = self.rcdr_driver_named(name)?;
        let mut logs = Vec::new();
        let mut unreadable = Vec::new();
        for &header in &driver.logs {
            match self.rcdr_log(types, header, driver.default_log) {
                Ok(log) => logs.push(log),
                Err(error) => unreadable.push(RcdrUnreadable {
                    address: header,
                    error: error.to_string(),
                }),
            }
        }
        Ok(RcdrLogs {
            driver,
            logs,
            unreadable,
        })
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
            let log = self.rcdr_log(types, header, driver.default_log)?;
            let index = logs.len();
            for partition in &log.partitions {
                if partition.base.is_zero() || partition.size == 0 {
                    continue;
                }
                if u64::from(partition.size) > MAX_PARTITION {
                    ends.push(RcdrWalkEnd {
                        log: index,
                        partition: partition.name,
                        end: IfrEnd::Corrupt(format!(
                            "its Size {:#x} is more than its offsets reach",
                            partition.size
                        )),
                    });
                    continue;
                }
                let mut bytes = vec![0u8; partition.size as usize];
                if let Err(error) = self
                    .kernel_address_space()
                    .read_bytes(partition.base, &mut bytes)
                {
                    ends.push(RcdrWalkEnd {
                        log: index,
                        partition: partition.name,
                        end: IfrEnd::Corrupt(format!("{:#x}: {error}", partition.base.0)),
                    });
                    continue;
                }
                let walk = walk_ifr(
                    &bytes,
                    usize::from(partition.current),
                    usize::from(partition.previous),
                    &layout,
                );
                ends.push(RcdrWalkEnd {
                    log: index,
                    partition: partition.name,
                    end: walk.end,
                });
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
