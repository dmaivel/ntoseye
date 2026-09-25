//! Assembling a recovered trace from a seed register context: the unwind
//! loop, per-frame register recovery, and lazy symbol loading for its frames.

use std::collections::{HashMap, HashSet};

use super::{
    FrameSource, MAX_UNWIND_FRAMES, RecoveredFrame, RecoveredStackTrace, RegisterContext,
    StackFrame, StackTracer, ThreadTraceContext, Unwound, format_symbol, frame_source_location,
};
use crate::{
    guest::{Guest, ModuleInfo},
    target::Target,
    types::{Arch, Dtb},
};

pub(super) fn build_recovered_stacktrace_seeded(
    debugger: &Target,
    trace: &ThreadTraceContext,
    mut context: RegisterContext,
    initial_source: FrameSource,
    limit: usize,
    initial_registers: HashMap<String, u64>,
) -> RecoveredStackTrace {
    let limit = limit.max(1);
    let mut raw: Vec<(RegisterContext, FrameSource, Option<u64>)> = Vec::new();
    let mut tracer = StackTracer::new(debugger, trace);
    let mut seen = HashSet::from([context.rip]);
    raw.push((
        context.clone(),
        initial_source,
        tracer.frame_base_for(&context),
    ));

    // RSP normally advances every step. A trap/interrupt frame can switch to a
    // different stack, so the hard frame cap remains the final corruption guard.
    for _ in 0..MAX_UNWIND_FRAMES {
        if raw.len() >= limit {
            break;
        }
        let previous_rip = context.rip;
        let previous_rsp = context.rsp;

        let stack_switch = match tracer.unwind_once(&mut context) {
            Unwound::Stop => break,
            Unwound::Frame { stack_switch } => stack_switch,
        };

        if context.rip == 0 || context.rip == previous_rip {
            break;
        }
        // An x64 return pops its address, so sp always climbs; an ARM64 leaf
        // returns through lr and leaves sp where it was.
        let stack_regressed = match debugger.arch() {
            Arch::Amd64 => context.rsp <= previous_rsp,
            Arch::Arm64 => context.rsp < previous_rsp,
        };
        if !stack_switch && stack_regressed {
            break;
        }
        seen.insert(context.rip);
        raw.push((
            context.clone(),
            FrameSource::Unwind,
            tracer.frame_base_for(&context),
        ));
    }

    let remaining = limit.saturating_sub(raw.len());
    for (sp, ip) in tracer.scan_stack(context.rsp, &seen, remaining) {
        let mut scan_context = RegisterContext::new(ip, sp);
        // A scan only accepts slots holding return addresses.
        scan_context.after_call = true;
        raw.push((
            scan_context.clone(),
            FrameSource::Scan,
            tracer.frame_base_for(&scan_context),
        ));
    }

    ensure_frame_module_symbols(
        debugger,
        trace,
        raw.iter().map(|(context, _, _)| context.rip),
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
        for (name, value) in context.named_values(debugger.arch()) {
            registers.insert(name.to_string(), value);
        }

        let frame = StackFrame {
            sp: context.rsp,
            ip: context.rip,
            symbol: format_symbol(debugger, trace, context.rip),
            source,
            source_location: frame_source_location(debugger, trace, context.rip),
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
    stacktrace
}

/// Lazily load symbols for the modules a backtrace touches. Only modules with no
/// prior load attempt are considered (so kernel modules, loaded on stop, and an
/// attached process's modules are skipped), and each is attempted once per
/// session. PDBs already on disk are indexed now; anything that needs the
/// network is fetched in the background, because this runs inside a stop
/// render that a host may be waiting on with a client timeout, and a frame
/// shown as `module+offset` is worth more than a stalled stop.
pub(super) fn ensure_frame_module_symbols(
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
