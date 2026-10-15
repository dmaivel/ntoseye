//! The WPP recorder (`!rcdrkd.*`) as SDK records: the drivers it serves,
//! their logs, and the records of those logs.

use ntoseye_macros::record;

use super::wdf::{WdfLogRecord, log_record};
use crate::target::rcdr as target;
use crate::target::wdf::IfrEnd;
use crate::types::VirtAddr;

/// A driver the WPP recorder serves (`_WPP_AUTOLOG_CONTEXT`).
#[record]
pub struct RcdrDriver {
    pub context: VirtAddr,
    /// `FileBaseName`: the image name without its extension.
    pub name: String,
    pub image: VirtAddr,
    #[record(hex)]
    pub image_size: u32,
    /// The `_WPP_AUTOLOG_HEADER` of each of its logs.
    pub logs: Vec<VirtAddr>,
    pub logs_stopped: Option<String>,
    /// The log `WppRecorderLogGetDefault` returns.
    pub default_log: VirtAddr,
    /// The last sequence number a record of its logs took.
    pub sequence: i32,
}

/// A recorder context that does not read.
#[record]
pub struct RcdrUnreadable {
    pub address: VirtAddr,
    pub error: String,
}

/// The drivers the recorder serves (`!rcdrkd.rcdrloglist`).
#[record]
pub struct RcdrDrivers {
    pub drivers: Vec<RcdrDriver>,
    pub unreadable: Vec<RcdrUnreadable>,
    /// Why the walk of the bugcheck callback list stopped short.
    pub stopped: Option<String>,
}

/// A partition of a log: the ring its records go to.
#[record]
pub struct RcdrPartition {
    /// `normal` or `error`.
    pub name: &'static str,
    pub base: VirtAddr,
    #[record(hex)]
    pub size: u32,
    /// Where the next record goes, and the newest record.
    #[record(hex)]
    pub current: u16,
    #[record(hex)]
    pub previous: u16,
}

/// A recorder log (`_WPP_AUTOLOG_HEADER`).
#[record]
pub struct RcdrLog {
    pub header: VirtAddr,
    /// `LogIdentifier`, with its append value when the driver set one.
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
pub struct RcdrLogs {
    pub driver: RcdrDriver,
    pub logs: Vec<RcdrLog>,
    pub unreadable: Vec<RcdrUnreadable>,
}

/// A record of a recorder log.
#[record]
pub struct RcdrRecord {
    /// The log's `_WPP_AUTOLOG_HEADER` and identifier.
    pub log: VirtAddr,
    pub log_identifier: String,
    /// `normal` or `error`.
    pub partition: &'static str,
    pub record: WdfLogRecord,
}

/// How the walk of one partition ended.
#[record]
pub struct RcdrWalkEnd {
    pub log: VirtAddr,
    pub partition: &'static str,
    /// `empty`, `first_record`, `overwritten`, or `corrupt`.
    pub end: &'static str,
    pub corruption: Option<String>,
}

/// A driver's records from its logs, oldest first
/// (`!rcdrkd.rcdrlogdump`).
#[record]
pub struct RcdrDump {
    pub driver: RcdrDriver,
    pub logs: Vec<RcdrLog>,
    pub records: Vec<RcdrRecord>,
    pub ends: Vec<RcdrWalkEnd>,
}

fn driver(driver: &target::RcdrDriver) -> RcdrDriver {
    RcdrDriver {
        context: driver.context,
        name: driver.name.clone(),
        image: driver.image,
        image_size: driver.image_size,
        logs: driver.logs.clone(),
        logs_stopped: driver.logs_stopped.clone(),
        default_log: driver.default_log,
        sequence: driver.sequence,
    }
}

fn log(log: &target::RcdrLog, default_log: VirtAddr) -> RcdrLog {
    RcdrLog {
        header: log.header,
        identifier: log.identifier.clone(),
        id_number: log.id_number,
        size: log.size,
        deleted: log.deleted,
        timestamps: log.timestamps,
        default: log.header == default_log,
        partitions: log
            .partitions
            .iter()
            .map(|partition| RcdrPartition {
                name: partition.name,
                base: partition.base,
                size: partition.size,
                current: partition.current,
                previous: partition.previous,
            })
            .collect(),
    }
}

pub fn drivers(list: &target::RcdrDriverList) -> RcdrDrivers {
    let mut drivers = Vec::new();
    let mut unreadable = Vec::new();
    for entry in &list.drivers {
        match entry {
            Ok(value) => drivers.push(driver(value)),
            Err((address, error)) => unreadable.push(RcdrUnreadable {
                address: *address,
                error: error.clone(),
            }),
        }
    }
    RcdrDrivers {
        drivers,
        unreadable,
        stopped: list.stopped.clone(),
    }
}

pub fn logs(owner: &target::RcdrDriver, entries: &[target::RcdrLogEntry]) -> RcdrLogs {
    let mut logs = Vec::new();
    let mut unreadable = Vec::new();
    for entry in entries {
        match entry {
            Ok(value) => logs.push(log(value, owner.default_log)),
            Err((address, error)) => unreadable.push(RcdrUnreadable {
                address: *address,
                error: error.clone(),
            }),
        }
    }
    RcdrLogs {
        driver: driver(owner),
        logs,
        unreadable,
    }
}

pub fn dump(dump: &target::RcdrLogDump) -> RcdrDump {
    RcdrDump {
        driver: driver(&dump.driver),
        logs: dump
            .logs
            .iter()
            .map(|entry| log(entry, dump.driver.default_log))
            .collect(),
        records: dump
            .entries
            .iter()
            .map(|entry| {
                let owner = &dump.logs[entry.log];
                RcdrRecord {
                    log: owner.header,
                    log_identifier: owner.identifier.clone(),
                    partition: entry.partition,
                    record: log_record(&entry.entry),
                }
            })
            .collect(),
        ends: dump
            .ends
            .iter()
            .map(|(index, partition, end)| {
                let (end, corruption) = match end {
                    IfrEnd::Empty => ("empty", None),
                    IfrEnd::FirstRecord => ("first_record", None),
                    IfrEnd::Overwritten => ("overwritten", None),
                    IfrEnd::Corrupt(why) => ("corrupt", Some(why.clone())),
                };
                RcdrWalkEnd {
                    log: dump.logs.get(*index).map_or(VirtAddr(0), |log| log.header),
                    partition,
                    end,
                    corruption,
                }
            })
            .collect(),
    }
}
