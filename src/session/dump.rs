//! What `.dump` writes: the header metadata of a full kernel dump of a live
//! session, which [`write_kernel_dump`](crate::nt::dump_writer::write_kernel_dump)
//! writes with the target's physical memory; and, for `.dump /u`, the model
//! of a user-mode minidump of one process, which
//! [`write_minidump`](crate::nt::userdump::write::write_minidump) writes.

use std::collections::HashMap;
use std::ops::{ControlFlow, Range};

use pelite::image::{IMAGE_DEBUG_TYPE_CODEVIEW, IMAGE_DIRECTORY_ENTRY_DEBUG};

use crate::arch::Arch;
use crate::backend::phys::PhysMem;
use crate::base::bytes::write_u32;
use crate::base::error::Result;
use crate::base::memory::{AddressSpace, MemoryOps, PAGE_SIZE};
use crate::base::types::{MAX_PROCESSORS, VirtAddr};
use crate::nt::bugchecks::current_bugcheck;
use crate::nt::dump_writer::{DumpException, DumpMetadata, context_from_registers, physical_runs};
use crate::nt::guest::{ModuleInfo, ProcessInfo};
use crate::nt::kuser_shared::KuserSharedData;
use crate::nt::pe::headers::{MAX_CODEVIEW_BYTES, decode_headers, read_debug_directory};
use crate::nt::pe::read_pe_header_page;
use crate::nt::target::mm::{
    MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE, MEM_RESERVE, MemoryRegionInfo, VadType,
    page_protection,
};
use crate::nt::target::{KTHREAD_STATE_TERMINATED, Target, ThreadInfo};
use crate::nt::unwind::{RecoveredStackTrace, build_parked_thread_recovered_stack};
use crate::nt::userdump::write::{
    MinidumpModule, MinidumpProcess, MinidumpRegion, MinidumpSystem, MinidumpThread,
};
use crate::session::Session;

/// Frames walked to find where a thread's user-mode code was.
const USER_FRAME_SEARCH: usize = 256;
/// A region at most this large is captured page by page, which also takes
/// its pages in transition and the shared pages of a view this process has
/// not touched; a larger one (a reservation such as the CFG bitmap) only
/// where its pages are present.
const PAGE_BY_PAGE_REGION: u64 = 64 << 20;
/// FILETIME (100 ns units since 1601) at the Unix epoch.
const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;
const FILETIME_SECOND: u64 = 10_000_000;
/// `NT_TIB64.StackBase`.
const NT_TIB_STACK_BASE: u64 = 8;

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

/// Seconds since 1970 of a FILETIME.
fn unix_seconds(filetime: u64) -> Option<u32> {
    filetime
        .checked_sub(FILETIME_UNIX_EPOCH)
        .and_then(|since| u32::try_from(since / FILETIME_SECOND).ok())
}

/// A `CONTEXT` from the registers a walk recovered by name, claiming the
/// control and integer state. AMD64's segments are a 64-bit user thread's
/// when the walk did not recover them.
fn context_from_named_registers(arch: Arch, registers: &HashMap<String, u64>) -> Vec<u8> {
    let map = arch.register_map();
    let mut context = vec![0u8; arch.context_size()];
    for (name, value) in registers {
        if map.contains(name) {
            let _ = map.write_u64(name, &mut context, *value);
        }
    }
    let flags = arch.context_flags();
    let mut claimed = flags.control | flags.integer;
    if arch == Arch::Amd64 {
        for (segment, selector) in [("cs", 0x33), ("ss", 0x2b)] {
            if !registers.contains_key(segment) {
                let _ = map.write_u64(segment, &mut context, selector);
            }
        }
        claimed |= flags.segments;
    }
    write_u32(&mut context, flags.offset, claimed);
    context
}

/// The registers of the first frame of `trace` in user mode, with its
/// instruction and stack pointers.
fn user_frame_registers(arch: Arch, trace: &RecoveredStackTrace) -> Option<HashMap<String, u64>> {
    let paging = arch.paging();
    trace
        .frames
        .iter()
        .find(|frame| frame.frame.ip != 0 && !paging.is_kernel_address(VirtAddr(frame.frame.ip)))
        .map(|frame| {
            let mut registers = frame.registers.clone();
            registers.insert(arch.pc_register().to_string(), frame.frame.ip);
            registers.insert(arch.sp_register().to_string(), frame.frame.sp);
            registers
        })
}

/// The CodeView record of the image at `base`, as its debug directory in
/// `memory` holds it.
fn codeview_record(memory: &AddressSpace<'_, PhysMem>, base: VirtAddr) -> Option<Vec<u8>> {
    let headers = read_pe_header_page(base, memory).ok()?;
    let headers = decode_headers(&headers[..]).ok()?;
    let directory = headers.directory(IMAGE_DIRECTORY_ENTRY_DEBUG)?;
    let read = |rva: u32, len: usize, _: &str| {
        let mut bytes = vec![0u8; len];
        memory.read_bytes(base + u64::from(rva), &mut bytes)?;
        Ok(std::borrow::Cow::Owned(bytes))
    };
    let entry = read_debug_directory(directory.rva, directory.size, read)
        .ok()?
        .into_iter()
        .find(|entry| entry.kind == IMAGE_DEBUG_TYPE_CODEVIEW && entry.address_of_raw_data != 0)?;
    let size = entry.size_of_data as usize;
    (size <= MAX_CODEVIEW_BYTES)
        .then(|| read(entry.address_of_raw_data, size, "CodeView record").ok())
        .flatten()
        .map(std::borrow::Cow::into_owned)
}

/// A module of the loader lists as the module list records it: its full
/// path, and the header's timestamp and checksum when the loader entry has
/// none.
fn minidump_module(memory: &AddressSpace<'_, PhysMem>, module: &ModuleInfo) -> MinidumpModule {
    let headers = (module.time_date_stamp.is_none() || module.checksum.is_none())
        .then(|| {
            read_pe_header_page(module.base_address, memory)
                .ok()
                .and_then(|page| decode_headers(&page[..]).ok())
        })
        .flatten();
    MinidumpModule {
        base: module.base_address.0,
        size: module.size,
        checksum: module
            .checksum
            .or_else(|| headers.as_ref().map(|headers| headers.optional.checksum))
            .unwrap_or(0),
        time_date_stamp: module
            .time_date_stamp
            .or_else(|| headers.as_ref().map(|headers| headers.file.time_date_stamp))
            .unwrap_or(0),
        path: module.path.clone().unwrap_or_else(|| module.name.clone()),
        codeview: codeview_record(memory, module.base_address),
    }
}

/// A VAD too large to scan page by page (a reservation such as the CFG
/// bitmap) as regions: the runs of its pages that are present, committed
/// with its protection, and the rest reserved. A committed page that is
/// paged out shows as reserved.
fn present_runs(memory: &AddressSpace<'_, PhysMem>, vad: &MemoryRegionInfo) -> Vec<MinidumpRegion> {
    let page = PAGE_SIZE as u64;
    let protect = vad.protection_value().map_or(0, page_protection);
    let kind = if vad.vad_type == Some(VadType::ImageMap) {
        MEM_IMAGE
    } else if vad.private_memory == Some(true) {
        MEM_PRIVATE
    } else {
        MEM_MAPPED
    };
    let region = |base: u64, end: u64, committed: bool| MinidumpRegion {
        base,
        allocation_base: vad.start.0,
        allocation_protect: protect,
        size: end - base,
        state: if committed { MEM_COMMIT } else { MEM_RESERVE },
        protect: if committed { protect } else { 0 },
        kind,
    };
    let mut present: Vec<Range<u64>> = Vec::new();
    let _ = memory.for_each_present_page(vad.start, vad.end, |va, _, length| {
        let start = va.0 & !(page - 1);
        let end = (va.0 + length).next_multiple_of(page);
        match present.last_mut() {
            Some(last) if last.end == start => last.end = end,
            _ => present.push(start..end),
        }
        ControlFlow::Continue(())
    });
    let mut regions = Vec::new();
    let mut at = vad.start.0;
    for run in present {
        if run.start > at {
            regions.push(region(at, run.start, false));
        }
        regions.push(region(run.start, run.end, true));
        at = run.end;
    }
    if at < vad.end.0 {
        regions.push(region(at, vad.end.0, false));
    }
    regions
}

/// Where a thread's user stack is in use: from `sp` to its TEB's
/// `StackBase`, when that is above `sp`.
fn used_stack(memory: &AddressSpace<'_, PhysMem>, teb: u64, sp: u64) -> Option<Range<u64>> {
    let base = memory.read::<u64>(VirtAddr(teb + NT_TIB_STACK_BASE)).ok()?;
    (sp < base && base - sp <= 1 << 30).then_some(sp..base)
}

/// The memory a minidump of the process captures in `regions`: each region
/// of at most [`PAGE_BY_PAGE_REGION`] wherever its pages translate, which
/// takes pages in transition and shared pages not yet touched too; each
/// larger one where its pages are present.
fn captured_memory(
    memory: &AddressSpace<'_, PhysMem>,
    regions: &[MinidumpRegion],
) -> Vec<Range<u64>> {
    let page = PAGE_SIZE as u64;
    let mut ranges: Vec<Range<u64>> = Vec::new();
    let mut add = |start: u64, end: u64| match ranges.last_mut() {
        Some(last) if last.end == start => last.end = end,
        _ => ranges.push(start..end),
    };
    for region in regions.iter().filter(|region| region.state == MEM_COMMIT) {
        let end = region.base + region.size;
        if region.size <= PAGE_BY_PAGE_REGION {
            for address in (region.base..end).step_by(PAGE_SIZE) {
                if matches!(memory.virt_to_phys(VirtAddr(address)), Ok(Some(_))) {
                    add(address, address + page);
                }
            }
        } else {
            let _ = memory.for_each_present_page(
                VirtAddr(region.base),
                VirtAddr(end),
                |va, _, length| {
                    let start = va.0 & !(page - 1);
                    add(start, (va.0 + length).next_multiple_of(page));
                    ControlFlow::Continue(())
                },
            );
        }
    }
    ranges
}

/// The model of a user-mode minidump of `process` (`.dump /u`), from a
/// halted kernel target: the system; the process's ID and times; each of
/// its threads, with the user-mode registers its stack walk recovers (a
/// running one's from its processor), its TEB, the used part of its stack,
/// and its times; each module of its loader lists, with its CodeView
/// record; its regions as `VirtualQuery` reports them; and the memory to
/// capture.
pub fn collect_process_minidump(
    session: &mut Session,
    process: &ProcessInfo,
) -> Result<MinidumpProcess> {
    let arch = session.target.arch();
    let version = session.target_version()?;
    // The walks of the threads that run on a processor need the session;
    // every other read only the target.
    let threads: Vec<ThreadInfo> = session
        .target
        .enumerate_threads_for_process_info(process)?
        .into_iter()
        .filter(|thread| thread.state != Some(KTHREAD_STATE_TERMINATED))
        .collect();
    let running: HashMap<u64, Option<HashMap<String, u64>>> = session
        .active_thread_map()
        .into_iter()
        .filter(|(ethread, _)| threads.iter().any(|thread| thread.ethread.0 == *ethread))
        .map(|(ethread, (vcpu, _))| {
            let registers = session
                .recovered_vcpu_backtrace(&vcpu, USER_FRAME_SEARCH)
                .ok()
                .and_then(|(trace, _, _)| user_frame_registers(arch, &trace));
            (ethread, registers)
        })
        .collect();
    let kuser = KuserSharedData::new(&session.target);
    let product_type = kuser.nt_product_type().unwrap_or(1) as u8;
    let now = kuser.system_time();
    let system = MinidumpSystem {
        arch,
        major: version.major_version.unwrap_or(0) as u32,
        minor: version.minor_version.unwrap_or(0) as u32,
        build: version.build_number.unwrap_or(0) as u32,
        processors: version.processors.unwrap_or(1).min(u16::from(u8::MAX)) as u8,
        product_type,
    };

    let guest = session.target.guest()?;
    let eprocess = guest.ntoskrnl.types().layout("_EPROCESS")?;
    let kernel = session.target.kernel_address_space();
    let read_field = |offset: Option<u64>| {
        offset.and_then(|offset| kernel.read::<u64>(process.eprocess + offset).ok())
    };
    let tick = u64::from(guest.ntoskrnl.symbol("KeMaximumIncrement")?.read::<u32>()?);
    let create_time = read_field(eprocess.field_offset("CreateTime").ok());
    // `KPROCESS.UserTime` and `KernelTime` count clock ticks.
    let cpu_seconds = |name: &str| {
        eprocess
            .field_offset("Pcb")
            .ok()
            .and_then(|pcb| {
                guest
                    .ntoskrnl
                    .types()
                    .layout("_KPROCESS")
                    .ok()?
                    .field_offset(name)
                    .ok()
                    .map(|offset| pcb + offset)
            })
            .and_then(|offset| kernel.read::<u32>(process.eprocess + offset).ok())
            .map(|ticks| (u64::from(ticks) * tick / FILETIME_SECOND) as u32)
    };
    let times = create_time.and_then(unix_seconds).map(|create| {
        (
            create,
            cpu_seconds("UserTime").unwrap_or(0),
            cpu_seconds("KernelTime").unwrap_or(0),
        )
    });
    let suspend_offset = guest
        .ntoskrnl
        .types()
        .layout("_KTHREAD")
        .ok()
        .and_then(|kthread| kthread.field_offset("SuspendCount").ok());

    let thread_times = session.target.kernel_thread_times_of(&threads)?;
    let user = session.target.address_space(process.dtb);
    let mut minidump_threads = Vec::with_capacity(threads.len());
    for (thread, times) in threads.iter().zip(thread_times) {
        let registers = match running.get(&thread.ethread.0) {
            Some(registers) => registers.clone(),
            None => build_parked_thread_recovered_stack(&session.target, thread, USER_FRAME_SEARCH)
                .ok()
                .and_then(|stack| user_frame_registers(arch, &stack.stacktrace)),
        };
        let sp = registers
            .as_ref()
            .and_then(|registers| registers.get(arch.sp_register()).copied());
        let teb = thread.teb.map_or(0, |teb| teb.0);
        minidump_threads.push(MinidumpThread {
            tid: thread.tid.unwrap_or(0) as u32,
            teb,
            priority: 0,
            priority_class: 0,
            suspend_count: suspend_offset
                .and_then(|offset| kernel.read::<u8>(thread.kthread + offset).ok())
                .map_or(0, u32::from),
            context: registers
                .as_ref()
                .map(|registers| context_from_named_registers(arch, registers)),
            stack: sp
                .filter(|_| teb != 0)
                .and_then(|sp| used_stack(&user, teb, sp)),
            create_time: times.create_time.unwrap_or(0),
            exit_time: times.exit_time.unwrap_or(0),
            kernel_time: times.kernel_time.unwrap_or(0),
            user_time: times.user_time.unwrap_or(0),
            start_address: thread
                .win32_start_address
                .or(thread.start_address)
                .map_or(0, |address| address.0),
        });
    }

    let modules = guest
        .process_modules(process)?
        .iter()
        .map(|module| minidump_module(&user, module))
        .collect();

    let vads = session
        .target
        .enumerate_vad_regions_for_process_info(process)?;
    let mut regions = Vec::new();
    for vad in &vads {
        if vad.size() <= PAGE_BY_PAGE_REGION {
            regions.extend(
                session
                    .target
                    .virtual_query_regions(process, std::slice::from_ref(vad))?
                    .into_iter()
                    .map(|region| MinidumpRegion {
                        base: region.base_address.0,
                        allocation_base: region.allocation_base.0,
                        allocation_protect: region.allocation_protect,
                        size: region.region_size,
                        state: region.state,
                        protect: region.protect,
                        kind: region.kind,
                    }),
            );
        } else {
            regions.extend(present_runs(&user, vad));
        }
    }
    let memory = captured_memory(&user, &regions);

    Ok(MinidumpProcess {
        system,
        time_date_stamp: now.and_then(unix_seconds).unwrap_or(0),
        pid: process.pid as u32,
        times,
        threads: minidump_threads,
        modules,
        regions,
        memory,
    })
}
