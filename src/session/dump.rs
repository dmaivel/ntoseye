//! The header metadata of a full kernel dump of a live session (`.dump`),
//! which [`write_kernel_dump`](crate::dump_writer::write_kernel_dump) writes
//! with the target's physical memory.

use crate::bugchecks::current_bugcheck;
use crate::dump_writer::{DumpException, DumpMetadata, context_from_registers, physical_runs};
use crate::error::Result;
use crate::session::Session;
use crate::target::Target;
use crate::types::MAX_PROCESSORS;

const WINDOWS_MAJOR_VERSION: u32 = 0xf;

fn symbol_address(target: &Target, name: &str) -> u64 {
    target
        .guest()
        .ok()
        .and_then(|guest| guest.ntoskrnl.symbol(name).ok())
        .map(|symbol| symbol.address().0)
        .unwrap_or(0)
}

fn read_kernel_build_number(target: &Target) -> u32 {
    target
        .guest()
        .ok()
        .and_then(|guest| guest.ntoskrnl.symbol("NtBuildNumber").ok())
        .and_then(|symbol| symbol.read::<u16>().ok())
        .map(u32::from)
        .unwrap_or(0)
}

/// Gather the header metadata for a full kernel dump of the halted target:
/// the current CONTEXT, processor count, physical runs, kernel globals, and
/// the bugcheck/exception of the last stop when there is one.
pub fn collect_dump_metadata(session: &mut Session) -> Result<DumpMetadata> {
    let registers = session.read_registers()?;
    let context = if session.backend.registers_are_context() {
        registers
    } else {
        context_from_registers(session.target.arch(), &session.register_map, &registers)
    };
    let processor_count = session
        .backend
        .thread_list()
        .map(|threads| threads.len().clamp(1, usize::from(MAX_PROCESSORS)) as u32)
        .unwrap_or(1);
    let runs = physical_runs(&session.target)?;
    let major_version = WINDOWS_MAJOR_VERSION;
    let minor_version = read_kernel_build_number(&session.target);

    let debugger_data = session.target.debugger_data();
    let ps_loaded_module_list = debugger_data
        .and_then(|data| data.ps_loaded_module_list())
        .map(|value| value.value.0)
        .filter(|&address| address != 0)
        .unwrap_or_else(|| symbol_address(&session.target, "PsLoadedModuleList"));
    let ps_active_process_head = debugger_data
        .and_then(|data| data.ps_active_process_head())
        .map(|value| value.value.0)
        .filter(|&address| address != 0)
        .unwrap_or_else(|| symbol_address(&session.target, "PsActiveProcessHead"));
    let pfn_database = symbol_address(&session.target, "MmPfnDatabase");
    let kd_debugger_data_block = debugger_data.map(|data| data.address.0).unwrap_or(0);

    let mut bug_check_code = 0;
    let mut bug_check_parameters = [0u64; 4];
    let mut exception = None;
    if let Some(stop) = session.last_event.as_ref().map(|event| &event.stop) {
        if stop.is_bugcheck
            && let Some(info) = &stop.bugcheck
        {
            bug_check_code = info.code;
            bug_check_parameters = info.parameters;
        } else if stop.is_bugcheck
            && let Some(analysis) = current_bugcheck(&session.target)
        {
            bug_check_code = analysis.code;
            for (index, argument) in analysis.args.iter().take(4).enumerate() {
                bug_check_parameters[index] = argument.value;
            }
        }
        if let Some(code) = stop.exception_code {
            exception = Some(DumpException {
                code,
                flags: 0,
                address: stop.exception_address.or(stop.program_counter).unwrap_or(0),
                ..DumpException::default()
            });
        }
    }

    Ok(DumpMetadata {
        arch: session.target.arch(),
        major_version,
        minor_version,
        directory_table_base: session.target.kernel_dtb(),
        pfn_database,
        ps_loaded_module_list,
        ps_active_process_head,
        number_processors: processor_count,
        bug_check_code,
        bug_check_parameters,
        kd_debugger_data_block,
        context,
        exception,
        runs,
    })
}
