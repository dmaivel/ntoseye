use tabled::builder::Builder;
use tabled::settings::object::Rows;
use tabled::settings::{Alignment, Modify, Panel};

use owo_colors::OwoColorize;

use crate::error::{Error, Result};
use crate::expr::Expr;
use crate::symbols::LocalVariableLocation;
use crate::target::{irp_major_function_name, kthread_state_name, wait_reason_name};
use crate::trapframe::read_ktrap_frame_at_or_current;
use crate::types::VirtAddr;
use crate::ui;
use crate::unwind::{
    RecoveredStackTrace, StackTrace, build_stacktrace_with_context,
    build_stacktrace_with_register_values, format_symbol, resolve_thread_trace_context,
};

use crate::repl::*;

repl_command! {
    cmd_pte;
    names: ["!pte", "pte"],
    usage: "!pte <address>",
    summary: "Display page table entries for an address.",
    completion: Expression,
}

repl_command! {
    cmd_pool;
    names: ["!pool", "pool"],
    usage: "!pool <address-expression>",
    summary: "Inspect the pool page containing an address.",
    completion: Expression,
}

repl_command! {
    cmd_registers;
    names: ["r", "registers"],
    usage: "r [register[=expression]]",
    summary: "Display CPU registers or assign one register.",
    run_state: Halted,
}

repl_command! {
    cmd_k;
    names: ["kn", "k", "kb", "kp", "kv"],
    usage: "kn|k|kb|kp|kv [count]",
    summary: "Display a stack; kp adds PDB parameter locations and kv provenance.",
    run_state: Halted,
}

repl_command! {
    cmd_status();
    names: ["status"],
    usage: "status",
    summary: "Display current VM status.",
}

repl_command! {
    cmd_capabilities();
    names: ["capabilities"],
    usage: "capabilities",
    summary: "Display backend capabilities.",
}

repl_command! {
    cmd_dbgprint;
    names: ["dbgprint"],
    usage: "dbgprint [count]",
    summary: "Show captured guest debug output (DbgPrint).",
}

repl_command! {
    cmd_irp;
    names: ["!irp", "irp"],
    usage: "!irp <address-expression>",
    summary: "Inspect an IRP and its current IO_STACK_LOCATION.",
    completion: Expression,
}

repl_command! {
    cmd_irps;
    names: ["irps"],
    usage: "irps [process-filter|driver-filter]",
    summary: "Discover in-flight IRPs from thread IrpLists and device CurrentIrp.",
    completion: Process,
}

repl_command! {
    cmd_drvobj;
    names: ["!drvobj", "drvobj"],
    usage: "!drvobj <driver-object-expression-or-name>",
    summary: "Inspect a DRIVER_OBJECT, its device chain and dispatch table.",
    completion: Driver,
}

repl_command! {
    cmd_devobj;
    names: ["!devobj", "devobj"],
    usage: "!devobj <device-object-expression>",
    summary: "Inspect a DEVICE_OBJECT and its attached stack.",
    completion: Expression,
}

repl_command! {
    cmd_object;
    names: ["!object", "object"],
    usage: "!object <object-expression>",
    summary: "Inspect an executive object header and body.",
    completion: Expression,
}

repl_command! {
    cmd_callbacks;
    names: ["callbacks"],
    usage: "callbacks [symbol-filter]",
    summary: "Enumerate process/thread/image notification callbacks.",
    completion: Symbol,
}

repl_command! {
    cmd_ssdt();
    names: ["ssdt"],
    usage: "ssdt",
    summary: "Dump the SSDT and shadow SSDT.",
}

repl_command! {
    cmd_address;
    names: ["address"],
    usage: "address <address-expression>",
    summary: "Describe what an address belongs to (module+section, or VAD region).",
    completion: Expression,
}

repl_command! {
    cmd_trap;
    names: [".trap", "trap"],
    usage: ".trap [address-expression]",
    summary: "Decode and display a _KTRAP_FRAME (defaults to the current thread's saved frame).",
    completion: Expression,
}

impl ReplState<'_> {
    fn cmd_pte(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let expr = require_arg!(invocation, 0, "pte");
        let address = match Expr::eval_with_radix(expr, &self.ctx.target, self.radix) {
            Ok(a) => a,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };
        match self.ctx.target.pte_traverse(address) {
            Ok(result) => {
                let mut levels = vec![result.pxe, result.ppe];

                if let Some(x) = result.pde {
                    levels.push(x);
                }

                if let Some(x) = result.pte {
                    levels.push(x);
                }

                let header = format!(
                    "VA {}  DTB {}",
                    ui::addr(result.address.0),
                    ui::addr(result.dtb)
                );
                let mut builder = Builder::default();

                let row_strings: Vec<String> = levels.iter().map(|l| l.to_string()).collect();
                builder.push_record(row_strings);

                let mut table = builder.build();
                table
                    .with(Panel::header(header))
                    .with(Modify::new(Rows::first()).with(Alignment::center()))
                    .with(tabled::settings::Style::empty());

                outln!("{}\n", table);
            }
            Err(e) => {
                error!("{}\n", e);
            }
        }

        Ok(())
    }

    fn cmd_trap(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let address = match invocation.arg(0) {
            Some(expr) => match Expr::eval_with_radix(expr, &self.ctx.target, self.radix) {
                Ok(address) => Some(address),
                Err(e) => {
                    error!("{}", e);
                    return Ok(());
                }
            },
            None => None,
        };
        if address.is_none()
            && self
                .ctx
                .target
                .current_thread_pseudo_register("trapframe")
                .is_none()
        {
            self.clear_selected_frame();
            outln!("selected context reset\n");
            return Ok(());
        }
        match read_ktrap_frame_at_or_current(&self.ctx.target, address) {
            Ok(frame) => {
                // Trap frames are kernel structures; resolve the interrupted
                // rip against the kernel address space like the bugcheck
                // analysis does.
                let trace =
                    resolve_thread_trace_context(&self.ctx.target, self.ctx.target.kernel_dtb());
                let symbol = format_symbol(&self.ctx.target, &trace, frame.instruction_pointer());
                print_ktrap_frame(&frame, Some(&symbol));
                let registers = super::frames::registers_from_trap_frame(&frame);
                let selected = self.select_register_values(0, registers);
                outln!("selected trap context frame 00 at {}", ui::addr(selected));
                outln!();
            }
            Err(e) => {
                error!("{}", e);
            }
        }

        Ok(())
    }

    fn cmd_pool(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(expr) = invocation.arg(0) else {
            outln!("{}\n", command_help("pool"));
            return Ok(());
        };

        let target = match Expr::eval_with_radix(expr, &self.ctx.target, self.radix) {
            Ok(target) => target,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };

        let layout = match pool_layout(&self.ctx.target) {
            Ok(l) => l,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };

        if target.0 & (POOL_PAGE_SIZE - 1) == 0
            && let Some(big) = find_big_pool(&self.ctx.target, &layout, target)
        {
            print_big_pool(target, &big);
            return Ok(());
        }

        let region = classify_pool_region(&self.ctx.target, target);
        let (blocks, idx, base) = locate_pool_block_in_page(&self.ctx.target, &layout, target);
        outln!("pool page {}", ui::addr(base.0));
        outln!("  target        : {}", ui::addr(target.0));
        if let Some((name, start, end)) = region {
            outln!(
                "  region        : {} [{} - {}]",
                name,
                ui::addr(start.0),
                ui::addr(end.0)
            );
        }
        if let Some(idx) = idx {
            outln!(
                "  blocks in run : {} (target is #{})",
                blocks.len(),
                idx + 1
            );
        }
        outln!();
        print_pool_page_listing(&blocks, idx, target);

        if idx.is_none() {
            if let Some(big) = find_big_pool(&self.ctx.target, &layout, target) {
                outln!();
                print_big_pool(target, &big);
                return Ok(());
            }
            outln!("  address does not lie inside a recognizable _POOL_HEADER block.");
            outln!("  it may be segment heap, special pool, a mapped view, or image/stack.");
            if let Some(hint) = segment_heap_hint(&self.ctx.target) {
                outln!("  hint          : {}", hint);
            }
            if let Some(near) = annotate_near_symbol(&self.ctx.target, target) {
                outln!("  near symbol   : {}", near);
            }
        }

        Ok(())
    }

    fn cmd_registers(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if let Some(frame) = self.ctx.target.selected_frame.as_ref() {
            let tail = invocation.raw_tail.trim();
            if tail.contains('=') {
                error!(
                    "cannot assign registers while frame {} is selected; use `.cxr`/`.frame` reset first",
                    frame.index
                );
                return Ok(());
            }
            if !tail.is_empty() && tail.split_whitespace().count() != 1 {
                outln!("{}\n", command_help(invocation.name));
                return Ok(());
            }
            outln!("registers (frame {})", frame.index);
            if !tail.is_empty() {
                let name = tail.trim_start_matches('@');
                let lowered_name = name.to_ascii_lowercase();
                let requested = match lowered_name.as_str() {
                    "efl" | "rflags" => "eflags",
                    name => name,
                };
                if let Some(value) = crate::target::lookup_register(&frame.registers, requested) {
                    outln!("{}={}", requested, ui::addr(value));
                } else {
                    error!(
                        "register not recovered in frame {}: {}",
                        frame.index, requested
                    );
                }
            } else {
                print_selected_registers(&frame.registers);
            }
            outln!();
            return Ok(());
        }
        if self.ctx.parked_windows_thread().is_some() {
            error!(
                "selected Windows thread is parked and has no coherent register context; use `vcpu <id>`"
            );
            return Ok(());
        }
        if let Err(e) = self
            .ctx
            .backend
            .set_current_thread(&self.ctx.current_thread)
        {
            error!("failed to select execution context: {:?}", e);
            return Ok(());
        }

        let mut regs = match self.ctx.read_registers() {
            Ok(r) => r,
            Err(e) => {
                error!("failed to read registers: {:?}", e);
                return Ok(());
            }
        };
        self.ctx.target.registers = Some(self.ctx.register_map.to_hashmap(&regs));

        if !invocation.raw_tail.trim().is_empty() {
            let tail = invocation.raw_tail.trim();
            let Some((name, expression)) = tail.split_once('=') else {
                if tail.split_whitespace().count() != 1 {
                    outln!("{}\n", command_help(invocation.name));
                    return Ok(());
                }
                let requested_name = tail.trim_start_matches('@').to_ascii_lowercase();
                let name = match requested_name.as_str() {
                    "efl" | "rflags" => "eflags",
                    name => name,
                };
                match self.ctx.register_map.read_u64(name, &regs) {
                    Ok(value) => outln!("{name}={}", ui::addr(value)),
                    Err(e) => error!("{e}"),
                }
                return Ok(());
            };
            let requested_name = name.trim().trim_start_matches('@').to_ascii_lowercase();
            let name = match requested_name.as_str() {
                "efl" | "rflags" => "eflags",
                name => name,
            };
            let expression = expression.trim();
            if name.is_empty() || expression.is_empty() {
                outln!("{}\n", command_help(invocation.name));
                return Ok(());
            }
            let value = match Expr::eval_with_radix(expression, &self.ctx.target, self.radix) {
                Ok(value) => value.0,
                Err(e) => {
                    error!("{}", e);
                    return Ok(());
                }
            };
            if let Err(e) = self.ctx.write_register(name, value) {
                error!("failed to write register {name}: {e}");
                return Ok(());
            }
            regs = match self.ctx.read_registers() {
                Ok(regs) => regs,
                Err(e) => {
                    error!("register written, but refresh failed: {e}");
                    return Ok(());
                }
            };
            self.ctx.target.registers = Some(self.ctx.register_map.to_hashmap(&regs));
            outln!("@{name} = {}\n", ui::addr(value));
        }

        print_registers(&self.ctx.register_map, &regs, false);
        // Control registers match the GP-register cluster's
        // styling; segment selectors are 16-bit, so render
        // them as 4 digits rather than padding to 64-bit
        let read_cr = |name: &str| -> String {
            self.ctx
                .register_map
                .read_u64(name, &regs)
                .map(ui::addr)
                .unwrap_or_else(|_| "N/A".to_string())
        };
        let read_seg = |name: &str| -> String {
            self.ctx
                .register_map
                .read_u64(name, &regs)
                .map(|v| format!("{:04x}", v))
                .unwrap_or_else(|_| "N/A".to_string())
        };

        outln!();
        outln!(
            "  cr0 {}   cr2 {}   cr3 {}",
            read_cr("cr0"),
            read_cr("cr2"),
            read_cr("cr3")
        );
        outln!("  cr4 {}   cr8 {}", read_cr("cr4"), read_cr("cr8"));
        outln!();

        outln!(
            "  cs  {}   ds  {}   es  {}",
            read_seg("cs"),
            read_seg("ds"),
            read_seg("es")
        );
        outln!(
            "  fs  {}   gs  {}   ss  {}",
            read_seg("fs"),
            read_seg("gs"),
            read_seg("ss")
        );
        outln!();

        Ok(())
    }

    fn print_stack_parameters(&self, trace: &StackTrace, frame_offset: usize) -> Result<()> {
        let mut printed_header = false;
        for (index, frame) in trace.frames.iter().enumerate() {
            let address = VirtAddr(frame.ip);
            let Some(locals) = self.ctx.target.procedure_locals(address)? else {
                continue;
            };
            let parameters: Vec<_> = locals
                .into_iter()
                .filter(|local| local.is_parameter)
                .collect();
            if parameters.is_empty() {
                continue;
            }
            if !printed_header {
                outln!("{}", ui::label("parameters (PDB locations)"));
                printed_header = true;
            }
            for parameter in parameters {
                let location = match parameter.location {
                    LocalVariableLocation::Register { register } => register,
                    LocalVariableLocation::RegisterRelative { register, offset } => {
                        if offset >= 0 {
                            format!("[{register}+{offset:#x}]")
                        } else {
                            format!("[{register}-{:#x}]", offset.unsigned_abs())
                        }
                    }
                    LocalVariableLocation::FrameRelative { offset } => {
                        if offset >= 0 {
                            format!("[frame+{offset:#x}]")
                        } else {
                            format!("[frame-{:#x}]", offset.unsigned_abs())
                        }
                    }
                    LocalVariableLocation::Unavailable { reason } => {
                        format!("unavailable: {reason}")
                    }
                };
                outln!(
                    "  #{:02}  {:<24} {:<20} {}",
                    index + frame_offset,
                    parameter.name,
                    parameter.type_name,
                    location
                );
            }
        }
        if !printed_header {
            outln!(
                "{}",
                ui::muted("parameter locations unavailable from loaded private symbols")
            );
        }
        Ok(())
    }

    fn cmd_k(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let frame_limit = match invocation.arg(0) {
            Some(count) => match Expr::eval_with_radix(count, &self.ctx.target, self.radix) {
                Ok(count) => usize::try_from(count.0).unwrap_or(usize::MAX).min(4096),
                Err(e) => {
                    error!("{}", e);
                    return Ok(());
                }
            },
            None => 64,
        };
        if self.ctx.parked_windows_thread().is_some() {
            let trace = match self.ctx.backtrace(frame_limit) {
                Ok(trace) => trace,
                Err(error) => {
                    error!("failed to unwind parked thread stack: {error}");
                    return Ok(());
                }
            };
            if invocation.name.eq_ignore_ascii_case("kv") {
                print_stacktrace_data_with_provenance(&trace, frame_limit, false);
            } else {
                print_stacktrace_data(&trace, frame_limit, false);
            }
            if invocation.name.eq_ignore_ascii_case("kp") {
                self.print_stack_parameters(&trace, 0)?;
            }
            outln!();
            return Ok(());
        }

        let trace = if let Some(selected) = self.ctx.target.selected_frame.as_ref() {
            build_stacktrace_with_register_values(
                &self.ctx.target,
                &self.ctx.register_map,
                &selected.registers,
                frame_limit,
            )
        } else {
            if let Err(e) = self
                .ctx
                .backend
                .set_current_thread(&self.ctx.current_thread)
            {
                error!("failed to select execution context: {:?}", e);
                return Ok(());
            }
            let regs = match self.ctx.read_registers() {
                Ok(r) => r,
                Err(e) => {
                    error!("failed to read registers: {:?}", e);
                    return Ok(());
                }
            };
            build_stacktrace_with_context(
                &self.ctx.target,
                &self.ctx.register_map,
                &regs,
                frame_limit,
            )
        };
        let offset = self
            .ctx
            .target
            .selected_frame
            .as_ref()
            .map(|frame| frame.index)
            .unwrap_or(0);
        print_indexed_stacktrace(
            &trace,
            frame_limit,
            offset,
            invocation.name.eq_ignore_ascii_case("kv"),
            self.ctx.target.selected_frame.as_ref().map(|_| offset),
        );
        if invocation.name.eq_ignore_ascii_case("kp") {
            let plain = StackTrace {
                frames: trace
                    .frames
                    .iter()
                    .map(|frame| frame.frame.clone())
                    .collect(),
                truncated: trace.truncated,
            };
            self.print_stack_parameters(&plain, offset)?;
        }
        outln!();

        Ok(())
    }

    fn cmd_status(&mut self) -> Result<()> {
        if self.ctx.backend.is_running() {
            outln!("VM is running\n");
        } else {
            if let Err(e) = self
                .ctx
                .backend
                .set_current_thread(&self.ctx.current_thread)
            {
                error!("failed to select execution context: {:?}", e);
                return Ok(());
            }
            print_stop_separator();
            print_break_context(
                &mut *self.ctx.backend,
                &self.ctx.register_map,
                &mut self.ctx.target,
                &self.ctx.breakpoints,
                &self.ctx.current_thread,
            );
        }

        Ok(())
    }

    fn cmd_capabilities(&mut self) -> Result<()> {
        print_backend_capabilities(&self.ctx.capabilities());

        Ok(())
    }

    /// Show captured guest debug output (DbgPrint). The stream also prints live
    /// to the terminal as it arrives; this shows the retained history, last
    /// `count` lines (default 50, or all retained when `count` is 0).
    fn cmd_dbgprint(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        const DEFAULT_TAIL: usize = 50;
        let count = match invocation.arg(0) {
            Some(arg) => arg
                .parse::<usize>()
                .map_err(|_| Error::DebugInfo(format!("invalid count: {arg}")))?,
            None => DEFAULT_TAIL,
        };

        let page = self.ctx.read_debug_output(0);
        if page.lines.is_empty() {
            outln!("{}\n", ui::muted("no debug output captured"));
            return Ok(());
        }

        let start = if count == 0 {
            0
        } else {
            page.lines.len().saturating_sub(count)
        };
        for line in &page.lines[start..] {
            outln!(
                "{} {}",
                ui::muted(&fmt_timestamp(line.timestamp_ms)),
                line.text
            );
        }
        outln!();

        Ok(())
    }
    fn cmd_irp(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(expr) = invocation.arg(0) else {
            outln!("{}\n", command_help("irp"));
            return Ok(());
        };

        let addr = match Expr::eval_with_radix(expr, &self.ctx.target, self.radix) {
            Ok(a) => a,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };

        let irp = match self.ctx.target.inspect_irp(addr) {
            Ok(irp) => irp,
            Err(e) => {
                error!("{} is not a readable _IRP: {}", ui::addr(addr.0), e);
                return Ok(());
            }
        };

        let mode = if irp.requestor_mode == 0 {
            "KernelMode"
        } else {
            "UserMode"
        };

        outln!("irp {}", ui::addr(irp.address.0));
        outln!("  type          : {:#x}", irp.irp_type);
        outln!("  size          : {:#x}", irp.size);
        outln!("  stack count   : {}", irp.stack_count);
        outln!("  current loc   : {}", irp.current_location);
        outln!(
            "  pending       : {}",
            if irp.pending_returned { "yes" } else { "no" }
        );
        outln!("  requestor mode: {} ({:#x})", mode, irp.requestor_mode);
        if let Some(status) = irp.io_status {
            outln!("  io status     : {:#x}", status);
        }
        outln!("  user event    : {}", ui::addr(irp.user_event.0));
        outln!("  user buffer   : {}", ui::addr(irp.user_buffer.0));
        outln!("  mdl           : {}", ui::addr(irp.mdl_address.0));
        outln!("  thread        : {}", ui::addr(irp.thread.0));

        match irp.current_stack {
            Some(ios) => {
                outln!("  current stack : {}", ui::addr(ios.address.0));
                outln!(
                    "    major       : IRP_MJ_{} ({:#x})",
                    irp_major_function_name(ios.major_function),
                    ios.major_function
                );
                outln!("    minor       : {:#x}", ios.minor_function);
                outln!("    device      : {}", ui::addr(ios.device_object.0));
                outln!("    file        : {}", ui::addr(ios.file_object.0));
                let completion = self
                    .ctx
                    .target
                    .closest_symbol_current_context(ios.completion_routine)
                    .unwrap_or_else(|| format!("{:#x}", ios.completion_routine.0));
                outln!("    completion  : {}", completion);
                outln!("    context     : {}", ui::addr(ios.context.0));
            }
            None => outln!("  current stack : {}", "unavailable".bright_black()),
        }
        outln!();

        Ok(())
    }

    /// Render a kernel address as its nearest symbol (styled), falling back to
    /// the bare address when nothing resolves.
    fn fmt_kernel_symbol(&self, a: VirtAddr) -> String {
        let dtb = self.ctx.target.kernel_dtb();
        self.ctx
            .target
            .symbols
            .format_closest_symbol_for_address(dtb, a)
            .map(|s| ui::symbol(&s))
            .unwrap_or_else(|| ui::addr(a.0))
    }

    fn resolve_driver_by_name(&self, name: &str) -> Option<VirtAddr> {
        let full;
        let needle = if name.starts_with("\\Driver\\") {
            name
        } else {
            full = format!("\\Driver\\{name}");
            full.as_str()
        };
        self.ctx
            .target
            .enumerate_driver_objects()
            .ok()?
            .into_iter()
            .find(|d| d.name.eq_ignore_ascii_case(needle))
            .map(|d| d.object)
    }

    fn cmd_drvobj(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(expr) = invocation.arg(0) else {
            outln!("{}\n", command_help("drvobj"));
            return Ok(());
        };

        // An expression wins; otherwise treat the argument as a driver name.
        let input = match Expr::eval_with_radix(expr, &self.ctx.target, self.radix) {
            Ok(a) => Some(a),
            Err(_) => self.resolve_driver_by_name(expr),
        };
        let Some(input) = input else {
            error!("unknown driver object expression or name: {}", expr);
            return Ok(());
        };

        let drv = match self.ctx.target.inspect_driver_object(input) {
            Ok(drv) => drv,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };

        let mode = if drv.via_pointer { "pointer" } else { "direct" };
        outln!("driver object {} ({})", ui::addr(drv.object.0), mode);
        if let Some(name) = &drv.name {
            outln!("  name          : {}", name);
        }
        outln!("  driver start  : {}", ui::addr(drv.driver_start.0));
        outln!("  driver size   : {:#x}", drv.driver_size);
        outln!("  driver section: {}", ui::addr(drv.driver_section.0));
        outln!(
            "  driver unload : {}",
            self.fmt_kernel_symbol(drv.driver_unload)
        );

        outln!("  devices:");
        if drv.device_chain.is_empty() {
            outln!("    {}", "(none)".bright_black());
        } else {
            for d in &drv.device_chain {
                outln!(
                    "    {} type={:#x} flags={:#x} characteristics={:#x} attached={} next={}",
                    ui::addr(d.device.0),
                    d.device_type,
                    d.flags,
                    d.characteristics,
                    ui::addr(d.attached.0),
                    ui::addr(d.next.0)
                );
            }
        }

        outln!("  dispatch table:");
        for (i, fn_ptr) in drv.dispatch.iter().enumerate() {
            outln!(
                "    IRP_MJ_{:<28} {}",
                irp_major_function_name(i as u8),
                self.fmt_kernel_symbol(*fn_ptr)
            );
        }
        outln!();

        Ok(())
    }

    fn cmd_devobj(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(expr) = invocation.arg(0) else {
            outln!("{}\n", command_help("devobj"));
            return Ok(());
        };

        let addr = match Expr::eval_with_radix(expr, &self.ctx.target, self.radix) {
            Ok(a) => a,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };

        let dev = match self.ctx.target.inspect_device_object(addr) {
            Ok(dev) => dev,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };

        outln!("device object {}", ui::addr(dev.object.0));
        outln!("    type            : {:#x}", dev.device_type);
        outln!("    flags           : {:#x}", dev.flags);
        outln!("    characteristics : {:#x}", dev.characteristics);
        outln!("    driver object   : {}", ui::addr(dev.driver_object.0));
        outln!("    attached device : {}", ui::addr(dev.attached_device.0));
        outln!("    next device     : {}", ui::addr(dev.next_device.0));
        outln!("    current irp     : {}", ui::addr(dev.current_irp.0));
        outln!("    device extension: {}", ui::addr(dev.device_extension.0));

        if !dev.attached_stack.is_empty() {
            outln!("attached stack:");
            for (i, e) in dev.attached_stack.iter().enumerate() {
                outln!(
                    "  #{} {} driver={} type={:#x} flags={:#x}",
                    i + 1,
                    ui::addr(e.device.0),
                    self.fmt_kernel_symbol(e.driver_object),
                    e.device_type,
                    e.flags
                );
            }
        }
        outln!();

        Ok(())
    }

    fn cmd_object(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(expr) = invocation.arg(0) else {
            outln!("{}\n", command_help("object"));
            return Ok(());
        };

        let addr = match Expr::eval_with_radix(expr, &self.ctx.target, self.radix) {
            Ok(a) => a,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };

        let o = match self.ctx.target.inspect_object_header(addr) {
            Ok(o) => o,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };

        outln!("object {}", ui::addr(o.body.0));
        outln!("  input         : {} ({})", ui::addr(o.input.0), o.mode);
        outln!("  header        : {}", ui::addr(o.header.0));
        outln!("  pointer count : {}", o.pointer_count);
        outln!("  handle count  : {}", o.handle_count);
        if let Some(ti) = o.type_index {
            outln!("  type index    : {:#x}", ti);
        }
        if let Some(to) = o.type_object {
            outln!("  type object   : {}", ui::addr(to.0));
        }
        if let Some(tn) = &o.type_name {
            outln!("  type name     : {}", tn);
        }
        if let Some(mask) = o.info_mask {
            outln!("  info mask     : {:#x}", mask);
        }
        if let Some(ni) = o.name_info {
            outln!("  name info     : {}", ui::addr(ni.0));
        }
        if let Some(name) = &o.name {
            outln!("  name          : {}", name);
        }
        outln!();

        Ok(())
    }

    fn cmd_callbacks(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let filter = invocation.arg(0).map(|s| s.to_lowercase());

        let callbacks = match self.ctx.target.enumerate_notify_callbacks() {
            Ok(c) => c,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };

        let dtb = self.ctx.target.kernel_dtb();
        let mut printed = 0;
        let mut last_kind = "";
        for c in &callbacks {
            let target = self
                .ctx
                .target
                .symbols
                .format_closest_symbol_for_address(dtb, c.function)
                .unwrap_or_else(|| format!("0x{:x}", c.function.0));
            if let Some(f) = &filter
                && !target.to_lowercase().contains(f)
            {
                continue;
            }
            if c.kind != last_kind {
                outln!("{} callbacks:", c.kind);
                last_kind = c.kind;
            }
            outln!(
                "  [{:02}] fn={}  block={}  raw={}  ctx={}",
                c.index,
                ui::symbol(&target),
                ui::addr(c.block.0),
                ui::addr(c.raw.0),
                ui::addr(c.context.0)
            );
            printed += 1;
        }

        if printed == 0 {
            match invocation.arg(0) {
                Some(f) => outln!("no callbacks matching '{}'", f),
                None => outln!("no registered callbacks found"),
            }
        }
        outln!();

        Ok(())
    }

    fn cmd_ssdt(&mut self) -> Result<()> {
        let tables = match self.ctx.target.dump_ssdt() {
            Ok(t) => t,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };

        for (i, t) in tables.iter().enumerate() {
            if i > 0 {
                outln!();
            }
            outln!("{}: base={} limit={}", t.label, ui::addr(t.base.0), t.limit);
            let expected = if t.label.contains("win32k") {
                "win32k"
            } else {
                "nt"
            };
            let mut hooks = 0;
            for e in &t.entries {
                let display = e
                    .symbol
                    .as_deref()
                    .map(ui::symbol)
                    .unwrap_or_else(|| ui::addr(e.target.0));
                let hooked = e
                    .module
                    .as_deref()
                    .map(|m| !m.to_lowercase().contains(expected))
                    .unwrap_or(false);
                let mark = if hooked {
                    hooks += 1;
                    "  [HOOK]".red().to_string()
                } else {
                    String::new()
                };
                outln!("  [{:4}] {}{}", e.index, display, mark);
            }
            if hooks > 0 {
                outln!("  {} hook(s) detected", hooks);
            }
        }
        outln!();

        Ok(())
    }

    fn cmd_irps(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let filter = invocation.arg(0);

        let hits = match self.ctx.target.discover_irps(filter) {
            Ok(h) => h,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };

        if hits.is_empty() {
            match filter {
                Some(f) => outln!("  {}", format!("no IRPs found for '{}'", f).bright_black()),
                None => outln!("  {}", "no IRPs found".bright_black()),
            }
            outln!();
            return Ok(());
        }

        outln!("  {:<16} {:<7} Details", "IRP", "Source");
        for h in &hits {
            let details = if h.source == "thread" {
                format!(
                    "pid={} tid={} ethread={} state={} wait={}",
                    h.pid.map(|p| p.to_string()).unwrap_or_else(|| "?".into()),
                    h.tid.map(|t| t.to_string()).unwrap_or_else(|| "?".into()),
                    h.ethread
                        .map(|e| ui::addr(e.0))
                        .unwrap_or_else(|| "?".into()),
                    h.state.map(kthread_state_name).unwrap_or("?"),
                    h.wait_reason.map(wait_reason_name).unwrap_or("?"),
                )
            } else {
                format!(
                    "driver={} device={}",
                    h.driver.as_deref().unwrap_or("?"),
                    h.device
                        .map(|d| ui::addr(d.0))
                        .unwrap_or_else(|| "?".into()),
                )
            };
            outln!(
                "  {} {:<7} stack={:<2} current={:<2} {}",
                ui::addr(h.irp.0),
                h.source,
                h.stack_count,
                h.current_location,
                details
            );
        }
        outln!();

        Ok(())
    }
    fn cmd_address(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(expr) = invocation.arg(0) else {
            outln!("{}\n", command_help("address"));
            return Ok(());
        };

        let addr = match Expr::eval_with_radix(expr, &self.ctx.target, self.radix) {
            Ok(a) => a,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };

        let d = match self.ctx.target.describe_address(addr) {
            Ok(d) => d,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };

        outln!("address {}", ui::addr(d.address.0));
        outln!("  kind    : {}", d.kind);
        if let Some(m) = &d.module {
            outln!(
                "  module  : {}+{:#x}  (base {}, size {:#x})",
                m.name,
                m.offset,
                ui::addr(m.base.0),
                m.size
            );
        }
        if let Some(s) = &d.section {
            outln!("  section : {}", s);
        }
        if let Some(va) = &d.va_type {
            outln!("  region  : {}", va);
        }
        if let Some(r) = &d.region {
            outln!(
                "  region  : {} - {}",
                ui::addr(r.start.0),
                ui::addr(r.end.0)
            );
            if let Some(p) = r.protection {
                outln!("    protection : {:#x}", p);
            }
            if let Some(t) = r.vad_type {
                outln!("    vad type   : {:#x}", t);
            }
            if let Some(pm) = r.private_memory {
                outln!("    private    : {}", pm);
            }
            if let Some(det) = &r.details {
                outln!("    details    : {}", det);
            }
        }
        if d.module.is_none() && d.region.is_none() && d.va_type.is_none() {
            outln!(
                "  {}",
                "not inside any loaded module, kernel region, or VAD".bright_black()
            );
        }
        outln!();

        Ok(())
    }
}

fn print_selected_registers(registers: &std::collections::HashMap<String, u64>) {
    let mut names: Vec<_> = registers.keys().collect();
    names.sort();
    for name in names {
        outln!("  {:<8} {}", name, ui::addr(registers[name]));
    }
}

fn print_indexed_stacktrace(
    trace: &RecoveredStackTrace,
    display_limit: usize,
    frame_offset: usize,
    show_provenance: bool,
    selected_index: Option<usize>,
) {
    for (index, recovered) in trace.frames.iter().take(display_limit).enumerate() {
        let frame = &recovered.frame;
        let global_index = frame_offset + index;
        let marker = if selected_index == Some(global_index) {
            "*"
        } else {
            " "
        };
        let symbol = if frame.symbol.starts_with("0x") {
            frame.symbol.clone()
        } else {
            ui::symbol(&frame.symbol)
        };
        let provenance = if show_provenance {
            format!("  [{}]", frame.source.as_str())
        } else {
            String::new()
        };
        let location = frame
            .source_location
            .as_ref()
            .map(|location| format!("  [{}:{}]", location.file, location.line))
            .unwrap_or_default();
        outln!(
            "{}{:02} {}  {}{}{}",
            marker,
            global_index,
            ui::addr(frame.sp),
            ui::addr(frame.ip),
            if symbol.is_empty() {
                "".to_string()
            } else {
                format!("  {symbol}")
            },
            format!("{provenance}{location}")
        );
    }
    let hidden = trace.frames.len().saturating_sub(display_limit) + trace.truncated;
    if hidden > 0 {
        outln!("{}", format!("... {} more frames", hidden).bright_black());
    }
}

/// Render a Unix-millis timestamp as a `HH:MM:SS.mmm` UTC time-of-day prefix.
/// A bare wall-clock prefix is enough to correlate prints; no date needed.
fn fmt_timestamp(ms: u64) -> String {
    let secs = ms / 1000;
    let millis = ms % 1000;
    let tod = secs % 86_400;
    let (h, m, s) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    format!("{h:02}:{m:02}:{s:02}.{millis:03}")
}
