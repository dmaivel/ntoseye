//! The WPP recorder (`!rcdrkd.*`) as SDK records: the drivers it serves,
//! their logs, and the records of those logs.

use super::shape::{Hex, shapes};
use super::wdf::{WdfLogRecord, log_record};
use crate::target::rcdr as target;
use crate::target::wdf::IfrEnd;
use crate::types::VirtAddr;

shapes! {
    /// A driver the WPP recorder serves (`_WPP_AUTOLOG_CONTEXT`).
    RcdrDriver {
        context: VirtAddr,
        /// `FileBaseName`: the image name without its extension.
        name: String,
        image: VirtAddr,
        image_size: Hex<u32>,
        /// The `_WPP_AUTOLOG_HEADER` of each of its logs.
        logs: Vec<VirtAddr>,
        logs_stopped: Option<String>,
        /// The log `WppRecorderLogGetDefault` returns.
        default_log: VirtAddr,
        /// The last sequence number a record of its logs took.
        sequence: i32,
    }

    /// A recorder context that does not read.
    RcdrUnreadable {
        address: VirtAddr,
        error: String,
    }

    /// The drivers the recorder serves (`!rcdrkd.rcdrloglist`).
    RcdrDrivers {
        drivers: Vec<RcdrDriver>,
        unreadable: Vec<RcdrUnreadable>,
        /// Why the walk of the bugcheck callback list stopped short.
        stopped: Option<String>,
    }

    /// A partition of a log: the ring its records go to.
    RcdrPartition {
        /// `normal` or `error`.
        name: &'static str,
        base: VirtAddr,
        size: Hex<u32>,
        /// Where the next record goes, and the newest record.
        current: Hex<u16>,
        previous: Hex<u16>,
    }

    /// A recorder log (`_WPP_AUTOLOG_HEADER`).
    RcdrLog {
        header: VirtAddr,
        /// `LogIdentifier`, with its append value when the driver set one.
        identifier: String,
        id_number: u16,
        size: Hex<u32>,
        deleted: bool,
        /// Records are 'L2', with a timestamp.
        timestamps: bool,
        /// Whether it is the driver's default log.
        default: bool,
        partitions: Vec<RcdrPartition>,
    }

    /// A driver's logs (`!rcdrkd.rcdrloglist <driver>`).
    RcdrLogs {
        driver: RcdrDriver,
        logs: Vec<RcdrLog>,
        unreadable: Vec<RcdrUnreadable>,
    }

    /// A record of a recorder log.
    RcdrRecord {
        /// The log's `_WPP_AUTOLOG_HEADER` and identifier.
        log: VirtAddr,
        log_identifier: String,
        /// `normal` or `error`.
        partition: &'static str,
        record: WdfLogRecord,
    }

    /// How the walk of one partition ended.
    RcdrWalkEnd {
        log: VirtAddr,
        partition: &'static str,
        /// `empty`, `first_record`, `overwritten`, or `corrupt`.
        end: &'static str,
        corruption: Option<String>,
    }

    /// A driver's records from its logs, oldest first
    /// (`!rcdrkd.rcdrlogdump`).
    RcdrDump {
        driver: RcdrDriver,
        logs: Vec<RcdrLog>,
        records: Vec<RcdrRecord>,
        ends: Vec<RcdrWalkEnd>,
    }
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
