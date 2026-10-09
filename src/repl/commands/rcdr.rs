//! The WPP recorder (`!rcdrkd.rcdrloglist`, `!rcdrkd.rcdrlogdump`): the
//! in-flight logs WppRecorder.sys keeps for drivers.

use tabled::builder::Builder;

use super::wdf::ifr_entry_line;
use crate::error::Result;
use crate::repl::*;
use crate::target::Target;
use crate::target::rcdr::{RcdrDriver, RcdrDriverList, RcdrLog, RcdrLogDump, RcdrLogEntry};
use crate::target::wdf::IfrEnd;
use crate::ui;

repl_command! {
    cmd_rcdrkd_rcdrloglist;
    names: ["!rcdrkd.rcdrloglist"],
    usage: "!rcdrkd.rcdrloglist [<driver>]",
    summary: "List the drivers the WPP recorder keeps logs for, or one driver's logs.",
    details: "WppRecorder.sys keeps in-flight logs for each driver built with WPP's recorder, such as the inbox USB, storage, and network drivers, and KMDF drivers' own WPP messages. Without an argument, lists those drivers: each one's recorder context (_WPP_AUTOLOG_CONTEXT), name, image base, and number of logs. With a driver, given by its name (with or without .sys) or its context, lists its logs: each _WPP_AUTOLOG_HEADER, its identifier, size, and the offsets of its normal and error partitions, and marks the default log and a deleted one. The recorder keeps no list of its drivers; the command finds each through the bugcheck callback the recorder registers for it, so it needs the PDB for WppRecorder.sys.",
    completion: Driver,
}

repl_command! {
    cmd_rcdrkd_rcdrlogdump;
    names: ["!rcdrkd.rcdrlogdump"],
    usage: "!rcdrkd.rcdrlogdump <driver> [-a <log>]",
    summary: "Show a driver's WPP recorder log records, oldest first.",
    details: "Walks each of the driver's recorder logs, both the normal and the error partition, back from the newest record, and shows the records of all of them merged in the order the driver logged them (their sequence numbers come from one counter per driver). -a shows only the log whose _WPP_AUTOLOG_HEADER you give, as !rcdrkd.rcdrloglist lists it. Each record shows its sequence number, its time when the log keeps timestamps, the log it is in, and its message formatted from the trace message format (TMF) annotations in a loaded PDB, or else the message GUID and number and the argument bytes. Microsoft's public PDBs carry no TMF annotations; add your driver's private PDB to the symbol path for its messages. The walk is !wdfkd.wdflogdump's: the records share KMDF's IFR format.",
    completion: Driver,
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
    let mut problems = Vec::new();
    for entry in &list.drivers {
        match entry {
            Ok(driver) => builder.push_record([
                ui::addr(driver.context.0),
                driver.name.clone(),
                image_text(target, driver),
                driver.logs.len().to_string(),
            ]),
            Err((context, error)) => {
                problems.push(format!("context {}: {error}", ui::addr(context.0)))
            }
        }
    }
    if list.drivers.is_empty() {
        outln!("{}\n", ui::muted("the WPP recorder serves no drivers"));
    } else {
        print_padded_table(builder);
    }
    for problem in problems {
        outln!("{}", ui::muted(&problem));
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

fn print_logs(target: &Target, driver: &RcdrDriver, logs: &[RcdrLogEntry]) {
    outln!(
        "{} {}  context {}  image {}",
        ui::label("WPP recorder logs of"),
        driver.name,
        ui::addr(driver.context.0),
        image_text(target, driver)
    );
    let mut builder = Builder::default();
    builder.push_record(["Log", "Identifier", "Size", "Partitions", "Notes"]);
    let mut problems = Vec::new();
    for entry in logs {
        match entry {
            Ok(log) => {
                let mut notes = Vec::new();
                if log.header == driver.default_log {
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
            Err((header, error)) => problems.push(format!("log {}: {error}", ui::addr(header.0))),
        }
    }
    if logs.is_empty() {
        outln!("{}\n", ui::muted("no logs"));
    } else {
        print_padded_table(builder);
    }
    for problem in problems {
        outln!("{}", ui::muted(&problem));
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
    for (log, partition, end) in &dump.ends {
        if let IfrEnd::Corrupt(why) = end {
            match dump.logs.get(*log) {
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

impl ReplState<'_> {
    fn cmd_rcdrkd_rcdrloglist(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let target = &self.ctx.target;
        let Some(name) = invocation.arg(0) else {
            match target.rcdr_drivers() {
                Ok(list) => print_drivers(target, &list),
                Err(error) => error!("!rcdrkd.rcdrloglist: {error}"),
            }
            return Ok(());
        };
        match target.rcdr_logs(name) {
            Ok((driver, logs)) => print_logs(target, &driver, &logs),
            Err(error) => error!("!rcdrkd.rcdrloglist: {error}"),
        }
        Ok(())
    }

    fn cmd_rcdrkd_rcdrlogdump(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        const USAGE: &str = "!rcdrkd.rcdrlogdump <driver> [-a <log>]";
        let mut name = None;
        let mut only = None;
        let mut args = invocation.argv.iter().map(|arg| arg.as_ref());
        while let Some(arg) = args.next() {
            match arg {
                "-a" => {
                    let Some(text) = args.next() else {
                        error!("!rcdrkd.rcdrlogdump: -a needs a log address; usage: {USAGE}");
                        return Ok(());
                    };
                    let Some(address) = self.eval_or_report(text) else {
                        return Ok(());
                    };
                    only = Some(address);
                }
                text if name.is_none() => name = Some(text),
                text => {
                    error!("!rcdrkd.rcdrlogdump: unexpected argument {text}; usage: {USAGE}");
                    return Ok(());
                }
            }
        }
        let Some(name) = name else {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        };
        match self.ctx.target.rcdr_log_dump(name, only) {
            Ok(dump) => print_dump(&dump),
            Err(error) => error!("!rcdrkd.rcdrlogdump: {error}"),
        }
        Ok(())
    }
}
