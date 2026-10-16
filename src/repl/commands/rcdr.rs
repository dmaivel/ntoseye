//! The WPP recorder (`!rcdrkd.rcdrloglist`, `!rcdrkd.rcdrlogdump`): the
//! in-flight logs WppRecorder.sys keeps for drivers.

use ntoseye_macros::{command, record};
use tabled::builder::Builder;

use super::wdf::ifr_entry_line;
use crate::error::{Error, Result};
use crate::repl::args::{ArgCursor, ArgCx, ArgError};
use crate::repl::*;
use crate::session::Session;
use crate::target::Target;
use crate::target::rcdr::{RcdrDriver, RcdrDriverList, RcdrLog, RcdrLogDump, RcdrLogs};
use crate::target::wdf::IfrEnd;
use crate::types::VirtAddr;
use crate::ui;

const LOG_DUMP_USAGE: &str = "!rcdrkd.rcdrlogdump <driver> [-a <log>]";

/// List the drivers the WPP recorder keeps logs for, or one driver's logs.
///
/// WppRecorder.sys keeps in-flight logs for each driver built with WPP's
/// recorder, such as the inbox USB, storage, and network drivers, and KMDF
/// drivers' own WPP messages. Without an argument, lists those drivers: each
/// one's recorder context (_WPP_AUTOLOG_CONTEXT), name, image base, and number
/// of logs. With a driver, given by its name (with or without .sys) or its
/// context, lists its logs: each _WPP_AUTOLOG_HEADER, its identifier, size, and
/// the offsets of its normal and error partitions, and marks the default log
/// and a deleted one. The recorder keeps no list of its drivers; the command
/// finds each through the bugcheck callback the recorder registers for it, so
/// it needs the PDB for WppRecorder.sys.
#[command(
    names = ["!rcdrkd.rcdrloglist"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    python = Inspect,
    usage = "!rcdrkd.rcdrloglist [<driver>]"
)]
fn rcdr_log_list(
    session: &Session,
    #[arg(complete = Driver)] driver: Option<String>,
) -> Result<RcdrLogList> {
    let target = &session.target;
    match driver {
        None => target.rcdr_drivers().map(RcdrLogList::Drivers),
        Some(name) => target.rcdr_logs(&name).map(RcdrLogList::Logs),
    }
    .map_err(|error| Error::DebugInfo(format!("!rcdrkd.rcdrloglist: {error}")))
}

/// What `!rcdrkd.rcdrloglist` shows: the drivers the recorder serves, or
/// one driver's logs.
#[record]
pub enum RcdrLogList {
    Drivers(RcdrDriverList),
    Logs(RcdrLogs),
}

impl Render for RcdrLogList {
    fn render(&self, repl: &mut ReplState<'_>, (): ()) {
        let target = &repl.ctx.target;
        match self {
            Self::Drivers(list) => print_drivers(target, list),
            Self::Logs(logs) => print_logs(target, logs),
        }
    }
}

/// Show a driver's WPP recorder log records, oldest first.
///
/// Walks each of the driver's recorder logs, both the normal and the error
/// partition, back from the newest record, and shows the records of all of them
/// merged in the order the driver logged them (their sequence numbers come from
/// one counter per driver). -a shows only the log whose _WPP_AUTOLOG_HEADER you
/// give, as !rcdrkd.rcdrloglist lists it. Each record shows its sequence
/// number, its time when the log keeps timestamps, the log it is in, and its
/// message formatted from the trace message format (TMF) annotations in a
/// loaded PDB, or else the message GUID and number and the argument bytes.
/// Microsoft's public PDBs carry no TMF annotations; add your driver's private
/// PDB to the symbol path for its messages. The walk is !wdfkd.wdflogdump's:
/// the records share KMDF's IFR format.
#[command(
    names = ["!rcdrkd.rcdrlogdump"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    python = Inspect,
    usage = "!rcdrkd.rcdrlogdump <driver> [-a <log>]"
)]
fn rcdr_log(
    session: &Session,
    #[arg(parse = log_dump_driver, complete = Driver)] driver: String,
    #[arg(parse = log_dump_only)] log: Option<VirtAddr>,
) -> Result<RcdrLogDump> {
    session
        .target
        .rcdr_log_dump(&driver, log)
        .map_err(|error| Error::DebugInfo(format!("!rcdrkd.rcdrlogdump: {error}")))
}

/// `!rcdrkd.rcdrlogdump`'s driver: the word that is not `-a <log>`. The
/// line is checked here, in its order, as it always was: an `-a` without a
/// log, a log that does not evaluate, a second driver. The `-a` words are
/// left for [`log_dump_only`].
fn log_dump_driver(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<String, ArgError> {
    let mut name = None;
    let mut words = cursor.words().enumerate();
    while let Some((index, word)) = words.next() {
        if word == "-a" {
            let Some((_, log)) = words.next() else {
                return Err(ArgError::Message(format!(
                    "!rcdrkd.rcdrlogdump: -a needs a log address; usage: {LOG_DUMP_USAGE}"
                )));
            };
            cx.eval(log)?;
        } else if name.is_none() {
            name = Some(index);
        } else {
            return Err(ArgError::Message(format!(
                "!rcdrkd.rcdrlogdump: unexpected argument {word}; usage: {LOG_DUMP_USAGE}"
            )));
        }
    }
    drop(words);
    let name = name.ok_or(ArgError::Missing)?;
    Ok(cursor.word_at(name).ok_or(ArgError::Missing)?.into_owned())
}

/// `!rcdrkd.rcdrlogdump`'s `-a <log>`, the last one given; the line is
/// [`log_dump_driver`]'s check, so only `-a` and logs are left.
fn log_dump_only(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<Option<VirtAddr>, ArgError> {
    let mut only = None;
    while cursor.word().is_some() {
        let log = cursor.word().ok_or(ArgError::Missing)?;
        only = Some(cx.eval(&log)?);
    }
    Ok(only)
}

impl Render for RcdrLogDump {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_dump(self);
    }
}

/// A log's partitions as `normal current/previous of size`.
fn partitions_text(log: &RcdrLog) -> String {
    log.partitions
        .iter()
        .map(|partition| {
            format!(
                "{} {:#x}/{:#x} of {:#x}",
                partition.name, partition.current, partition.previous, partition.size
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn print_drivers(target: &Target, list: &RcdrDriverList) {
    let mut builder = Builder::default();
    builder.push_record(["Context", "Driver", "Image", "Logs"]);
    for driver in &list.drivers {
        builder.push_record([
            ui::addr(driver.context.0),
            driver.name.clone(),
            image_text(target, driver),
            driver.logs.len().to_string(),
        ]);
    }
    if list.drivers.is_empty() && list.unreadable.is_empty() {
        outln!("{}\n", ui::muted("the WPP recorder serves no drivers"));
    } else {
        print_padded_table(builder);
    }
    for context in &list.unreadable {
        outln!(
            "{}",
            ui::muted(&format!(
                "context {}: {}",
                ui::addr(context.address.0),
                context.error
            ))
        );
    }
    if let Some(stopped) = &list.stopped {
        outln!(
            "{}",
            ui::muted(&format!("(bugcheck callback list stopped: {stopped})"))
        );
    }
}

/// The image base, with the module name when it is a loaded module.
fn image_text(target: &Target, driver: &RcdrDriver) -> String {
    match target.module_containing(driver.image) {
        Some(module) => format!("{}  {}", ui::addr(driver.image.0), module.short_name),
        None => ui::addr(driver.image.0),
    }
}

fn print_logs(target: &Target, logs: &RcdrLogs) {
    let driver = &logs.driver;
    outln!(
        "{} {}  context {}  image {}",
        ui::label("WPP recorder logs of"),
        driver.name,
        ui::addr(driver.context.0),
        image_text(target, driver)
    );
    let mut builder = Builder::default();
    builder.push_record(["Log", "Identifier", "Size", "Partitions", "Notes"]);
    for log in &logs.logs {
        let mut notes = Vec::new();
        if log.default {
            notes.push("default");
        }
        if log.deleted {
            notes.push("deleted");
        }
        if log.timestamps {
            notes.push("timestamps");
        }
        builder.push_record([
            ui::addr(log.header.0),
            log.identifier.clone(),
            format!("{:#x}", log.size),
            partitions_text(log),
            notes.join(" "),
        ]);
    }
    if logs.logs.is_empty() && logs.unreadable.is_empty() {
        outln!("{}\n", ui::muted("no logs"));
    } else {
        print_padded_table(builder);
    }
    for log in &logs.unreadable {
        outln!(
            "{}",
            ui::muted(&format!("log {}: {}", ui::addr(log.address.0), log.error))
        );
    }
    if let Some(stopped) = &driver.logs_stopped {
        outln!("{}", ui::muted(&format!("(log list stopped: {stopped})")));
    }
}

fn print_dump(dump: &RcdrLogDump) {
    outln!(
        "{} {} ({} logs, sequence {})",
        ui::label("WPP recorder log of"),
        dump.driver.name,
        dump.logs.len(),
        dump.driver.sequence
    );
    let several = dump.logs.len() > 1;
    for entry in &dump.entries {
        let line = ifr_entry_line(&entry.entry);
        let log = &dump.logs[entry.log];
        let place = match (several, entry.partition) {
            (true, "normal") => format!("[{}] ", log.identifier),
            (true, partition) => format!("[{} {partition}] ", log.identifier),
            (false, "normal") => String::new(),
            (false, partition) => format!("[{partition}] "),
        };
        // The sequence number leads the line; the log goes after it.
        match line.split_once(": ") {
            Some((sequence, rest)) => outln!("{sequence}: {}{rest}", ui::muted(&place)),
            None => outln!("{line}"),
        }
    }
    for walk in &dump.ends {
        if let IfrEnd::Corrupt(why) = &walk.end {
            let partition = walk.partition;
            match dump.logs.get(walk.log) {
                Some(log) => error!(
                    "log {} ({}) {partition} partition: {why}",
                    log.identifier,
                    ui::addr(log.header.0)
                ),
                None => error!("{partition} partition: {why}"),
            }
        }
    }
    outln!(
        "{}",
        ui::muted(&format!("({} records)", dump.entries.len()))
    );
    outln!();
}
