//! Assembling a recovered trace from a seed register context: the unwind
//! loop, per-frame register recovery, and lazy symbol loading for its frames.

use std::collections::{HashMap, HashSet};

use super::{
    FrameRegisters, FrameSource, MAX_UNWIND_FRAMES, RecoveredFrame, RecoveredStackTrace,
    StackTracer, ThreadTraceContext, Unwound, expand_frame,
};
use crate::arch::Arch;
use crate::{
    base::types::{Dtb, VirtAddr},
    nt::{
        guest::{Guest, ModuleInfo},
        target::Target,
    },
};

pub(super) fn build_recovered_stacktrace_seeded(
    debugger: &Target,
    trace: &ThreadTraceContext,
    mut context: FrameRegisters,
    initial_source: FrameSource,
    limit: usize,
    initial_registers: HashMap<String, u64>,
) -> RecoveredStackTrace {
    let limit = limit.max(1);
    let mut raw: Vec<(FrameRegisters, FrameSource, Option<u64>)> = Vec::new();
    let mut tracer = StackTracer::new(debugger, trace);
    let mut seen = HashSet::from([context.pc]);
    raw.push((
        context.clone(),
        initial_source,
        tracer.frame_base_for(&context),
    ));

    // RSP normally advances every step. A trap/interrupt frame or a function
    // that switches stacks can move it to a different stack, so the hard
    // frame cap remains the final corruption guard.
    let mut reached_end = false;
    for _ in 0..MAX_UNWIND_FRAMES {
        if raw.len() >= limit {
            break;
        }
        // A Windows hypervisor stack starts at a VM-exit entry: nothing
        // above its frame belongs to the stack, and its unwind data names no
        // caller.
        if tracer.at_hypervisor_stack_base(&context) {
            reached_end = true;
            break;
        }
        let previous_rip = context.pc;
        let previous_rsp = context.sp;

        let (stack_switch, source) = match tracer.unwind_once(&mut context) {
            Unwound::Stop => break,
            Unwound::Frame { stack_switch } => (stack_switch, FrameSource::Unwind),
            Unwound::Prolog => (false, FrameSource::Prolog),
        };

        // A zero return address is the thread's initial frame: nothing above
        // it belongs to the thread, so there is nothing to scan either.
        if context.pc == 0 {
            reached_end = true;
            break;
        }
        // The hypervisor's root maps no NT code, and its own stacks hold only
        // its own return addresses: an unwind that leaves its image has gone
        // past the stack's base.
        if trace
            .foreign_image
            .as_ref()
            .is_some_and(|image| !image.contains_address(VirtAddr(context.pc)))
        {
            reached_end = true;
            break;
        }
        // A frame that returns to its own address is a recursive call when
        // the stack moved, and a walk going nowhere when it did not.
        if context.pc == previous_rip && context.sp == previous_rsp {
            unwind_trace!("unwind: frame returns to itself without moving -> scan");
            break;
        }
        // Nothing runs in the never-mapped first 64 KiB or at a non-canonical
        // address, so a value there is no return address: the unwind went
        // wrong (a context short of registers, a stale slot), and the stack is
        // scanned from here instead of listing it as a frame.
        if !could_be_return_address(context.pc, debugger.arch()) {
            unwind_trace!("unwind: {:#x} is no return address -> scan", context.pc);
            break;
        }
        // A return that pops its address always climbs the stack; a leaf
        // returning through a link register leaves sp where it was. Only a
        // move to another of the processor's stacks goes down.
        let stack_regressed = if debugger.arch().return_pops_address() {
            context.sp <= previous_rsp
        } else {
            context.sp < previous_rsp
        };
        if !stack_switch && stack_regressed {
            if !tracer.switched_stacks(previous_rsp, context.sp) {
                unwind_trace!(
                    "unwind: sp went from {previous_rsp:#x} back to {:#x} -> scan",
                    context.sp
                );
                break;
            }
            unwind_trace!(
                "unwind: sp moved from {previous_rsp:#x} to another of the processor's stacks at {:#x}",
                context.sp
            );
        }
        seen.insert(context.pc);
        raw.push((context.clone(), source, tracer.frame_base_for(&context)));
    }

    let remaining = if reached_end {
        0
    } else {
        limit.saturating_sub(raw.len())
    };
    for (sp, ip) in tracer.scan_stack(context.sp, &seen, remaining) {
        let mut scan_context = FrameRegisters::new(debugger.arch(), ip, sp);
        // A scan only accepts slots holding return addresses.
        scan_context.after_call = true;
        raw.push((
            scan_context.clone(),
            FrameSource::Scan,
            tracer.frame_base_for(&scan_context),
        ));
    }

    ensure_module_symbols(
        debugger,
        trace,
        raw.iter().map(|(context, _, _)| context.pc),
    );

    let mut stacktrace = RecoveredStackTrace::new(trace);
    for (index, (context, source, frame_base)) in raw.into_iter().enumerate() {
        let mut registers;
        if index == 0 {
            registers = initial_registers.clone();
        } else {
            registers = HashMap::new();
            if let Some(dtb) = initial_registers.get(debugger.arch().dtb_register()) {
                let name = debugger.arch().dtb_register();
                registers.insert(name.to_string(), *dtb);
            }
        }
        for (name, value) in context.named_values() {
            registers.insert(name.to_string(), value);
        }

        let frames = expand_frame(
            debugger,
            trace,
            context.pc,
            context.sp,
            source,
            context.machine_frame,
            context.after_call,
        );
        let physical = frames.len() - 1;
        for (position, frame) in frames.into_iter().enumerate() {
            // Inline frames share the physical frame's registers.
            let registers = if position == physical {
                std::mem::take(&mut registers)
            } else {
                registers.clone()
            };
            record_recovered_frame(
                &mut stacktrace,
                limit,
                RecoveredFrame {
                    frame,
                    registers,
                    frame_base,
                },
            );
        }
    }
    stacktrace
}

/// Lazily load symbols for the modules `ips` fall in: a backtrace's frames up
/// front, or one address [`super::try_format_symbol`] could not name. Only modules with no
/// prior load attempt are considered (so kernel modules, loaded on stop, and an
/// attached process's modules are skipped), and each is attempted once per
/// session. PDBs already on disk are indexed now; anything that needs the
/// network is fetched in the background, because this runs inside a stop
/// render that a host may be waiting on with a client timeout, and a frame
/// shown as `module+offset` is worth more than a stalled stop.
pub(super) fn ensure_module_symbols(
    debugger: &Target,
    trace: &ThreadTraceContext,
    ips: impl Iterator<Item = u64>,
) {
    let mut by_dtb: HashMap<Dtb, Vec<ModuleInfo>> = HashMap::new();
    let mut seen: HashSet<(Dtb, u64)> = HashSet::new();
    for ip in ips {
        let Some(module) = trace.module_for_address(ip) else {
            continue;
        };
        if trace
            .foreign_image
            .as_ref()
            .is_some_and(|image| image.base_address == module.info.base_address)
        {
            continue;
        }
        let key = (module.dtb, module.info.base_address.0);
        if seen.insert(key)
            && debugger
                .symbols
                .module_symbol_status(module.dtb, module.info.base_address)
                .is_none()
        {
            by_dtb.entry(module.dtb).or_default().push(module.info);
        }
    }

    for (dtb, modules) in by_dtb {
        Guest::load_module_symbols_or_fetch_later(
            &debugger.phys,
            &debugger.symbols,
            modules,
            dtb,
            debugger.arch(),
        );
    }
}

/// Whether `address` could hold code: above the first 64 KiB, which Windows
/// never maps, and a pointer by its upper bits.
fn could_be_return_address(address: u64, arch: Arch) -> bool {
    address >= 0x1_0000 && arch.paging().could_be_pointer(address)
}

pub(super) fn record_recovered_frame(
    stacktrace: &mut RecoveredStackTrace,
    limit: usize,
    frame: RecoveredFrame,
) {
    if stacktrace.frames.len() < limit {
        stacktrace.frames.push(frame);
    } else {
        stacktrace.truncated += 1;
    }
}
