use crate::backend::MemoryOps;
use crate::dbg_backend::DebugCapability;
use crate::dump_writer::{
    DumpException, DumpMetadata, MAX_PHYSICAL_MEMORY_RUNS, write_kernel_dump,
};
use crate::error::{Error, Result};
use crate::phys::PhysMem;
use crate::repl::*;
use crate::symbols::ParsedType;
use crate::types::{Arch, VirtAddr};
use indicatif::{ProgressBar, ProgressStyle};
use std::sync::atomic::Ordering;

const WINDOWS_MAJOR_VERSION: u32 = 0xf;

repl_command! {
    cmd_reboot();
    names: [".reboot", "reboot", ".restart", "restart"],
    usage: ".reboot",
    summary: "Reboot the debug target and reload its kernel context.",
    details: "The reboot is sent without confirmation. The next KD state-change is handled by the normal target-reload path.",
    run_state: Halted,
    run: Run,
}

repl_command! {
    cmd_crash();
    names: [".crash", "crash"],
    usage: ".crash",
    summary: "Force a MANUALLY_INITIATED_CRASH (bugcheck 0xE2).",
    details: "Windows writes its crash dump first (often a minute, during which the target ignores break-ins), then reboots or, with automatic restart disabled, breaks in. Ctrl+C stops waiting.",
    run_state: Halted,
    run: Run,
}

repl_command! {
    cmd_dump;
    names: [".dump", "dump"],
    usage: ".dump [/f] [/ma] <file>",
    summary: "Write a full PAGEDU64 kernel dump from the halted target.",
    details: "Both /f and /ma are accepted as WinDbg-compatible full-dump switches. The dump is streamed page by page and can be cancelled with Ctrl+C.",
    completion: None,
    run_state: Halted,
}

fn target_control_available(state: &ReplState<'_>) -> bool {
    let capabilities = state.ctx.capabilities();
    if supports_capability(&capabilities, DebugCapability::TargetControl) {
        true
    } else {
        error!(
            "target control is not supported by the {} backend",
            state.ctx.backend.name()
        );
        false
    }
}

impl ReplState<'_> {
    fn cmd_reboot(&mut self) -> Result<()> {
        if !target_control_available(self) {
            return Ok(());
        }
        if let Err(error) = self.ctx.backend.reboot_target() {
            error!("failed to reboot target: {error}");
            return Ok(());
        }
        self.clear_selected_frame();
        self.ctx.clear_resume_state();
        outln!("Target is rebooting; waiting for target reload.");
        self.wait_for_stop_after_resume()
    }

    fn cmd_crash(&mut self) -> Result<()> {
        if !target_control_available(self) {
            return Ok(());
        }
        if let Err(error) = self.ctx.backend.cause_bugcheck() {
            error!("failed to force target bugcheck: {error}");
            return Ok(());
        }
        self.clear_selected_frame();
        self.ctx.clear_resume_state();
        outln!(
            "Forcing target bugcheck 0xE2 (MANUALLY_INITIATED_CRASH); the target writes its crash dump before rebooting or breaking in."
        );
        self.wait_for_stop_after_resume()
    }

    fn cmd_dump(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(path) = parse_dump_arguments(&invocation) else {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        };

        let capabilities = self.ctx.capabilities();
        if !supports_capability(&capabilities, DebugCapability::MemoryIntrospection) {
            error!(
                "dump writing is not supported by the {} backend",
                self.ctx.backend.name()
            );
            return Ok(());
        }

        if matches!(&*self.ctx.target.phys, PhysMem::Dmp(_)) {
            error!(".dump is not applicable to a static crash dump");
            return Ok(());
        }

        let (metadata, total_pages) = match collect_dump_metadata(self)
            .and_then(|metadata| metadata.total_pages().map(|pages| (metadata, pages)))
        {
            Ok(prepared) => prepared,
            Err(error) => {
                error!("cannot prepare dump: {error}");
                return Ok(());
            }
        };
        let memory = &*self.ctx.target.phys;
        let progress = ProgressBar::new(total_pages);
        progress.set_style(
            ProgressStyle::with_template("Writing dump [{bar:40}] {pos}/{len}")?
                .progress_chars("#-"),
        );
        INTERRUPT_REQUESTED.store(false, Ordering::SeqCst);
        let result = write_kernel_dump(
            path,
            memory,
            &metadata,
            || INTERRUPT_REQUESTED.swap(false, Ordering::SeqCst),
            || progress.inc(1),
        );
        progress.finish_and_clear();
        match result {
            Ok(unreadable_pages) => {
                if unreadable_pages != 0 {
                    outln!("{unreadable_pages} pages unreadable (zero-filled)");
                }
                outln!("Wrote full kernel dump to {}.", path)
            }
            Err(error) => error!("failed to write dump: {error}"),
        }
        Ok(())
    }
}

fn parse_dump_arguments<'a>(invocation: &'a CommandInvocation<'a>) -> Option<&'a str> {
    let mut path = None;
    for argument in &invocation.argv {
        let argument = argument.as_ref();
        if argument.starts_with('/') {
            match argument.to_ascii_lowercase().as_str() {
                "/f" | "/ma" => {}
                // Unix absolute paths also start with `/`; once both known
                // switches are excluded, treat the first such token as the
                // requested file rather than rejecting `/tmp/out.dmp`.
                _ if path.is_none() => path = Some(argument),
                _ => return None,
            }
        } else if path.replace(argument).is_some() {
            return None;
        }
    }
    path
}

fn symbol_address(target: &crate::target::Target, name: &str) -> u64 {
    target
        .guest()
        .ok()
        .and_then(|guest| guest.ntoskrnl.symbol(name).ok())
        .map(|symbol| symbol.address().0)
        .unwrap_or(0)
}

fn read_kernel_build_number(target: &crate::target::Target) -> u32 {
    target
        .guest()
        .ok()
        .and_then(|guest| guest.ntoskrnl.symbol("NtBuildNumber").ok())
        .and_then(|symbol| symbol.read::<u16>().ok())
        .map(u32::from)
        .unwrap_or(0)
}

fn physical_runs_from_symbol(target: &crate::target::Target) -> Result<Option<Vec<(u64, u64)>>> {
    let guest = match target.guest() {
        Ok(guest) => guest,
        Err(Error::NtoskrnlNotFound) => return Ok(None),
        Err(error) => return Err(error),
    };
    let symbol = match guest.ntoskrnl.symbol("MmPhysicalMemoryBlock") {
        Ok(symbol) => symbol,
        Err(Error::SymbolNotFound(_)) | Err(Error::ExpectedSymbols) => return Ok(None),
        Err(error) => return Err(error),
    };
    let descriptor_address: VirtAddr = symbol.read()?;
    if descriptor_address.is_zero() {
        return Err(Error::DebugInfo("nt!MmPhysicalMemoryBlock is null".into()));
    }

    let types = guest.ntoskrnl.types();
    let layout = types.layout("_PHYSICAL_MEMORY_DESCRIPTOR")?;
    let number_of_runs = layout
        .fields
        .get("NumberOfRuns")
        .ok_or_else(|| Error::FieldNotFound("NumberOfRuns".into()))?;
    let run = layout
        .fields
        .get("Run")
        .ok_or_else(|| Error::FieldNotFound("Run".into()))?;

    let element_type = match &run.type_data {
        ParsedType::Array(inner, _) => inner.as_ref(),
        element => element,
    };
    let element_name = match element_type {
        ParsedType::Struct(name) | ParsedType::Union(name) => name,
        _ => {
            return Err(Error::DebugInfo(
                "physical descriptor Run element has no struct layout".into(),
            ));
        }
    };
    let run_layout = types.layout(element_name)?;
    let base_page = run_layout
        .fields
        .get("BasePage")
        .ok_or_else(|| Error::FieldNotFound("BasePage".into()))?;
    let page_count = run_layout
        .fields
        .get("PageCount")
        .ok_or_else(|| Error::FieldNotFound("PageCount".into()))?;
    let run_stride = run_layout.size;
    if run_stride == 0 {
        return Err(Error::DebugInfo(
            "physical descriptor Run element has zero size".into(),
        ));
    }
    let (base_page_offset, base_page_size, page_count_offset, page_count_size) = (
        usize::try_from(base_page.offset)
            .map_err(|_| Error::DebugInfo("physical run BasePage offset overflows usize".into()))?,
        usize::try_from(base_page.size)
            .map_err(|_| Error::DebugInfo("physical run BasePage size overflows usize".into()))?,
        usize::try_from(page_count.offset).map_err(|_| {
            Error::DebugInfo("physical run PageCount offset overflows usize".into())
        })?,
        usize::try_from(page_count.size)
            .map_err(|_| Error::DebugInfo("physical run PageCount size overflows usize".into()))?,
    );
    for (name, offset, size) in [
        ("BasePage", base_page_offset, base_page_size),
        ("PageCount", page_count_offset, page_count_size),
    ] {
        let end = offset.checked_add(size).ok_or_else(|| {
            Error::DebugInfo(format!("physical run {name} field range overflows usize"))
        })?;
        if end > run_stride || !matches!(size, 1 | 2 | 4 | 8) {
            return Err(Error::DebugInfo(format!(
                "invalid physical run {name} field layout (offset={offset}, size={size}, stride={run_stride})"
            )));
        }
    }

    let field_end = |field: &crate::symbols::FieldInfo| -> Result<usize> {
        let offset = usize::try_from(field.offset).map_err(|_| {
            Error::DebugInfo("physical descriptor field offset overflows usize".into())
        })?;
        let size = usize::try_from(field.size).map_err(|_| {
            Error::DebugInfo("physical descriptor field size overflows usize".into())
        })?;
        offset.checked_add(size).ok_or_else(|| {
            Error::DebugInfo("physical descriptor field range overflows usize".into())
        })
    };
    let read_integer = |bytes: &[u8], offset: usize, size: usize, name: &str| {
        let end = offset
            .checked_add(size)
            .ok_or_else(|| Error::DebugInfo(format!("{name} field range overflows usize")))?;
        let value = bytes.get(offset..end).ok_or_else(|| {
            Error::DebugInfo(format!("{name} field exceeds physical descriptor prefix"))
        })?;
        match size {
            1 => Ok(u64::from(value[0])),
            2 => Ok(u64::from(u16::from_le_bytes(value.try_into().unwrap()))),
            4 => Ok(u64::from(u32::from_le_bytes(value.try_into().unwrap()))),
            8 => Ok(u64::from_le_bytes(value.try_into().unwrap())),
            _ => Err(Error::DebugInfo(format!(
                "unsupported {name} field size {size}"
            ))),
        }
    };

    let run_offset = usize::try_from(run.offset)
        .map_err(|_| Error::DebugInfo("physical descriptor run offset overflows usize".into()))?;
    let prefix_len = run_offset.max(field_end(number_of_runs)?);
    let mut prefix = vec![0u8; prefix_len];
    target
        .kernel_address_space()
        .read_bytes(descriptor_address, &mut prefix)?;
    let run_count = read_integer(
        &prefix,
        usize::try_from(number_of_runs.offset)
            .map_err(|_| Error::DebugInfo("NumberOfRuns offset overflows usize".into()))?,
        usize::try_from(number_of_runs.size)
            .map_err(|_| Error::DebugInfo("NumberOfRuns size overflows usize".into()))?,
        "NumberOfRuns",
    )?;
    let run_count = usize::try_from(run_count).unwrap_or(usize::MAX);
    // Rejected rather than truncated: a dump missing runs would still claim
    // to be complete.
    if run_count > MAX_PHYSICAL_MEMORY_RUNS {
        return Err(Error::DebugInfo(format!(
            "physical descriptor reports {run_count} runs, but the dump header supports at most {MAX_PHYSICAL_MEMORY_RUNS}"
        )));
    }
    let runs_len = run_count
        .checked_mul(run_stride)
        .and_then(|size| run_offset.checked_add(size))
        .ok_or_else(|| Error::DebugInfo("physical descriptor run list overflows usize".into()))?;
    let mut bytes = prefix;
    if bytes.len() < runs_len {
        bytes.resize(runs_len, 0);
        target
            .kernel_address_space()
            .read_bytes(descriptor_address, &mut bytes)?;
    }

    let mut runs = Vec::with_capacity(run_count);
    for index in 0..run_count {
        let offset = run_offset + index * run_stride;
        let run_bytes = &bytes[offset..offset + run_stride];
        let base_page = read_integer(run_bytes, base_page_offset, base_page_size, "BasePage")?;
        let page_count = read_integer(run_bytes, page_count_offset, page_count_size, "PageCount")?;
        runs.push((base_page, page_count));
    }
    Ok(Some(runs))
}

fn physical_runs(target: &crate::target::Target) -> Result<Vec<(u64, u64)>> {
    if let Some(runs) = physical_runs_from_symbol(target)? {
        return Ok(runs);
    }

    // A live VM exposes its hypervisor's RAM mapping, including the 32-bit PCI
    // hole, through this accessor. KD has no equivalent host map, so an absent
    // symbol there remains an actionable discovery error below.
    let runs = target.phys.ram_runs();
    let page_size = crate::memory::PAGE_SIZE as u64;
    if !runs.is_empty() {
        return runs
            .into_iter()
            .map(|(base, length)| {
                if !base.is_multiple_of(page_size) || !length.is_multiple_of(page_size) {
                    return Err(Error::DebugInfo(format!(
                        "physical RAM run is not page-aligned (base={base:#x}, size={length:#x})"
                    )));
                }
                let page_count = length / page_size;
                (page_count != 0)
                    .then_some((base / page_size, page_count))
                    .ok_or_else(|| Error::DebugInfo("physical RAM run has no pages".into()))
            })
            .collect();
    }

    let base = target.phys.ram_base();
    let length = target.phys.ram_size();
    if !base.is_multiple_of(page_size) || !length.is_multiple_of(page_size) {
        return Err(Error::DebugInfo(format!(
            "physical RAM range is not page-aligned (base={base:#x}, size={length:#x})"
        )));
    }
    let page_count = length / page_size;
    if page_count == 0 {
        return Err(Error::DebugInfo(
            "target did not expose physical memory runs".into(),
        ));
    }
    Ok(vec![(base / page_size, page_count)])
}

fn collect_dump_metadata(state: &mut ReplState<'_>) -> Result<DumpMetadata> {
    if state.ctx.target.arch() != Arch::Amd64 {
        return Err(Error::UnsupportedArchitecture(
            "full dump writing is currently supported only for AMD64".into(),
        ));
    }
    let context = state.ctx.backend.read_registers()?;
    let processor_count = state
        .ctx
        .backend
        .thread_list()
        .map(|threads| {
            threads
                .len()
                .clamp(1, usize::from(crate::cpu_state::MAX_PROCESSORS)) as u32
        })
        .unwrap_or(1);
    let runs = physical_runs(&state.ctx.target)?;
    let major_version = WINDOWS_MAJOR_VERSION;
    let minor_version = read_kernel_build_number(&state.ctx.target);

    let debugger_data = state.ctx.target.debugger_data();
    let ps_loaded_module_list = debugger_data
        .and_then(|data| data.ps_loaded_module_list())
        .map(|value| value.value.0)
        .filter(|&address| address != 0)
        .unwrap_or_else(|| symbol_address(&state.ctx.target, "PsLoadedModuleList"));
    let ps_active_process_head = debugger_data
        .and_then(|data| data.ps_active_process_head())
        .map(|value| value.value.0)
        .filter(|&address| address != 0)
        .unwrap_or_else(|| symbol_address(&state.ctx.target, "PsActiveProcessHead"));
    let pfn_database = symbol_address(&state.ctx.target, "MmPfnDatabase");
    let kd_debugger_data_block = debugger_data.map(|data| data.address.0).unwrap_or(0);

    let mut bug_check_code = 0;
    let mut bug_check_parameters = [0u64; 4];
    let mut exception = None;
    if let Some(stop) = state.ctx.last_event.as_ref().map(|event| &event.stop) {
        if stop.is_bugcheck
            && let Some(info) = &stop.bugcheck
        {
            bug_check_code = info.code;
            bug_check_parameters = info.parameters;
        } else if stop.is_bugcheck
            && let Some(analysis) = crate::bugchecks::current_bugcheck(&state.ctx.target)
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
        major_version,
        minor_version,
        directory_table_base: state.ctx.target.kernel_dtb(),
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
