//! Process-state inspectors: job objects and global flags.

use crate::error::Result;
use crate::expr::Expr;
use crate::repl::*;
use crate::target::DiagnosticValue;
use crate::target::gflag::{GLOBAL_FLAGS, GlobalFlagChange, GlobalFlagsDetail, global_flags_set};
use crate::target::job::{JobDetail, job_limit_flag_names};
use crate::types::VirtAddr;
use crate::ui;

repl_command! {
    cmd_job;
    names: ["!job", "job"],
    usage: "!job [address [flags]]",
    summary: "Show a job object: accounting, limits, nesting, and its processes.",
    details: "The address is a job, or a process or thread whose job is shown; omitted or 0, the current process's job. Flags: 1 (the default) shows the job's accounting, limits, and flags; 2 lists the processes assigned to it (from ProcessListHead). Child jobs, the parent and root job, and silo state are shown with 1.",
    completion: Expression,
}

repl_command! {
    cmd_gflag;
    names: ["!gflag", "gflag"],
    usage: "!gflag [[+|-]value | {+|-}abbreviation | -?]",
    summary: "Show or change nt!NtGlobalFlag; also shows the current process's PEB flags.",
    details: "Without an argument, decodes nt!NtGlobalFlag and the current process's _PEB.NtGlobalFlag by the GFlags names. `+` sets and `-` clears the bits of a value or of one flag named by its three-letter abbreviation (`!gflag +ust`); a bare value replaces nt!NtGlobalFlag. A change is one 4-byte write to nt!NtGlobalFlag, as `ed` makes; the PEB copy is not changed. `-?` lists the flags and their abbreviations.",
    completion: Expression,
}

impl ReplState<'_> {
    fn cmd_gflag(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let target = &self.ctx.target;
        match invocation.arg(0) {
            Some("-?") => {
                for flag in &GLOBAL_FLAGS {
                    outln!(
                        "  {:#010x} {:<3} {}",
                        flag.bit,
                        flag.abbreviation,
                        flag.description
                    );
                }
                outln!();
                return Ok(());
            }
            Some(text) => {
                let change = GlobalFlagChange::parse(text, |text| {
                    Expr::eval_with_radix(text, target, self.radix).map(|value| value.0)
                });
                match change.and_then(|change| target.change_global_flag(change)) {
                    Ok((old, new)) => outln!("NtGlobalFlag {old:#010x} -> {new:#010x}"),
                    Err(error) => {
                        error!("{error}");
                        return Ok(());
                    }
                }
            }
            None => {}
        }
        match target.global_flags() {
            Ok(detail) => print_global_flags(&detail),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_job(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let mut values = [None, Some(1)];
        for (slot, arg) in values.iter_mut().zip(&invocation.argv) {
            match self.eval_or_report(arg.as_ref()) {
                Some(VirtAddr(value)) => *slot = Some(value),
                None => return Ok(()),
            }
        }
        let [address, flags] = values;
        let target = &self.ctx.target;
        match target
            .job_address(address.map(VirtAddr))
            .and_then(|job| target.inspect_job(job))
        {
            Ok(job) => print_job(&job, flags.unwrap_or(1)),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }
}

fn print_job(job: &JobDetail, flags: u64) {
    outln!("Job at {}", ui::addr(job.address.0));
    let optional = |value: Option<u64>| value.map_or("-".to_string(), |value| value.to_string());
    outln!(
        "  JobId {}  SessionId {}",
        optional(job.job_id),
        optional(job.session_id)
    );
    if flags & 1 != 0 {
        outln!("  Basic Accounting Information");
        for field in &job.accounting {
            outln!("    {:<28} {:#x}", format!("{}:", field.field), field.value);
        }
        outln!(
            "  Job Flags ({})",
            job.job_flags
                .map_or("-".to_string(), |flags| format!("{flags:#x}"))
        );
        for name in &job.job_flag_names {
            outln!("    [{name}]");
        }
        outln!("  Limit Information");
        for field in &job.limits {
            let names = if field.field.ends_with("LimitFlags") {
                format!(" {}", job_limit_flag_names(field.value).join(" "))
            } else {
                String::new()
            };
            outln!(
                "    {:<28} {:#x}{names}",
                format!("{}:", field.field),
                field.value
            );
        }
        let job_link =
            |link: Option<VirtAddr>| link.map_or("-".to_string(), |link| ui::addr(link.0));
        outln!(
            "  Nesting: depth {}  parent {}  root {}",
            optional(job.nesting_depth),
            job_link(job.parent_job),
            job_link(job.root_job)
        );
        for child in &job.child_jobs {
            outln!("    child job {}", ui::addr(child.0));
        }
        if job.silo {
            outln!(
                "  Silo: ServerSiloGlobals {}",
                job_link(job.server_silo_globals)
            );
        }
    }
    if flags & 2 != 0 {
        outln!("  Processes assigned to this job:");
        for process in &job.processes {
            outln!(
                "    PROCESS {}  Cid: {:04x}  Image: {}",
                ui::addr(process.eprocess_va.0),
                process.pid,
                process.name
            );
        }
        for eprocess in &job.unreadable_processes {
            outln!("    PROCESS {}  (unreadable)", ui::addr(eprocess.0));
        }
        if let Some(why) = job.process_termination.diagnostic() {
            outln!("    process list ended early: {why}");
        }
    }
    outln!();
}

fn print_global_flags(detail: &GlobalFlagsDetail) {
    let print_flags = |value: u32| {
        for flag in global_flags_set(value) {
            let abbreviation = if flag.abbreviation.is_empty() {
                format!("{:#x}", flag.bit)
            } else {
                flag.abbreviation.to_string()
            };
            outln!("    {abbreviation} - {}", flag.description);
        }
    };
    outln!(
        "NtGlobalFlag at {}: {:#010x}",
        ui::addr(detail.kernel_address.0),
        detail.kernel
    );
    print_flags(detail.kernel);
    if let Some(process) = &detail.process {
        match &detail.process_flags {
            DiagnosticValue::Available(flags) => {
                outln!(
                    "PEB NtGlobalFlag of {} (PID {}): {flags:#010x}",
                    process.name,
                    process.pid
                );
                print_flags(*flags);
            }
            DiagnosticValue::Unavailable(error) => outln!(
                "PEB NtGlobalFlag of {} (PID {}): unavailable ({error})",
                process.name,
                process.pid
            ),
        }
    }
    outln!();
}
