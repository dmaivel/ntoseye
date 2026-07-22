use tabled::builder::Builder;
use tabled::settings::object::Rows;
use tabled::settings::{Alignment, Modify, Panel};

use owo_colors::OwoColorize;

use crate::bugchecks::bugcheck_from_dump_info;
use crate::error::{Error, Result};
use crate::expr::Expr;
use crate::target::{irp_major_function_name, kthread_state_name, wait_reason_name};
use crate::trapframe::read_ktrap_frame_at_or_current;
use crate::types::VirtAddr;
use crate::ui;
use crate::unwind::{format_symbol, resolve_thread_trace_context};

use crate::repl::*;

repl_command! {
    cmd_pte;
    names: ["pte"],
    usage: "pte <address>",
    summary: "Display page table entries for an address.",
    completion: Expression,
}

repl_command! {
    cmd_pool;
    names: ["pool"],
    usage: "pool <address-expression>",
    summary: "Inspect the pool page containing an address.",
    completion: Expression,
}

repl_command! {
    cmd_registers();
    names: ["registers", "r"],
    usage: "registers",
    summary: "Display CPU registers.",
    run_state: Halted,
}

repl_command! {
    cmd_k;
    names: ["k"],
    usage: "k [count]",
    summary: "Display stack backtrace.",
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
    names: ["irp"],
    usage: "irp <address-expression>",
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
    names: ["drvobj"],
    usage: "drvobj <driver-object-expression-or-name>",
    summary: "Inspect a DRIVER_OBJECT, its device chain and dispatch table.",
    completion: Driver,
}

repl_command! {
    cmd_devobj;
    names: ["devobj"],
    usage: "devobj <device-object-expression>",
    summary: "Inspect a DEVICE_OBJECT and its attached stack.",
    completion: Expression,
}

repl_command! {
    cmd_object;
    names: ["object"],
    usage: "object <object-expression>",
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
    names: ["trap", ".trap"],
    usage: "trap [address-expression]",
    summary: "Decode and display a _KTRAP_FRAME (defaults to the current thread's saved frame).",
    completion: Expression,
}

repl_command! {
    cmd_analyze();
    names: ["analyze", "!analyze"],
    usage: "analyze",
    summary: "Analyze the current bugcheck (BSOD) from nt!KiBugCheckData.",
}

impl ReplState<'_> {
    fn cmd_pte(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let expr = require_arg!(invocation, 0, "pte");
        let address = match Expr::eval(expr, &self.ctx.target) {
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

                println!("{}\n", table);
            }
            Err(e) => {
                error!("{}\n", e);
            }
        }

        Ok(())
    }

    fn cmd_trap(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let address = match invocation.arg(0) {
            Some(expr) => match Expr::eval(expr, &self.ctx.target) {
                Ok(address) => Some(address),
                Err(e) => {
                    error!("{}", e);
                    return Ok(());
                }
            },
            None => None,
        };
        match read_ktrap_frame_at_or_current(&self.ctx.target, address) {
            Ok(frame) => {
                // Trap frames are kernel structures; resolve the interrupted
                // rip against the kernel address space like the bugcheck
                // analysis does.
                let trace =
                    resolve_thread_trace_context(&self.ctx.target, self.ctx.target.kernel_dtb());
                let symbol = format_symbol(&self.ctx.target, &trace, frame.rip);
                print_ktrap_frame(&frame, Some(&symbol));
                println!();
            }
            Err(e) => {
                error!("{}", e);
            }
        }

        Ok(())
    }

    fn cmd_analyze(&mut self) -> Result<()> {
        // Same decode path the stop banner and the SDK/MCP use; on demand so an
        // already-frozen guest (or a scrolled-away banner) can be re-analyzed.
        // Dumps whose KiBugCheckData memory is not captured fall back to the
        // dump header fields, mirroring the MCP/Python surfaces.
        match current_bugcheck(&self.ctx.target)
            .or_else(|| bugcheck_from_dump_info(&self.ctx.target))
        {
            Some(analysis) => {
                print_bugcheck_analysis(&analysis);
                println!();
            }
            None => println!(
                "no bugcheck: nt!KiBugCheckData has no plausible code (guest is not bugchecking)\n"
            ),
        }

        Ok(())
    }

    fn cmd_pool(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(expr) = invocation.arg(0) else {
            println!("{}\n", command_help("pool"));
            return Ok(());
        };

        let target = match Expr::eval(expr, &self.ctx.target) {
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
        println!("pool page {}", ui::addr(base.0));
        println!("  target        : {}", ui::addr(target.0));
        if let Some((name, start, end)) = region {
            println!(
                "  region        : {} [{} - {}]",
                name,
                ui::addr(start.0),
                ui::addr(end.0)
            );
        }
        if let Some(idx) = idx {
            println!(
                "  blocks in run : {} (target is #{})",
                blocks.len(),
                idx + 1
            );
        }
        println!();
        print_pool_page_listing(&blocks, idx, target);

        if idx.is_none() {
            if let Some(big) = find_big_pool(&self.ctx.target, &layout, target) {
                println!();
                print_big_pool(target, &big);
                return Ok(());
            }
            println!("  address does not lie inside a recognizable _POOL_HEADER block.");
            println!("  it may be segment heap, special pool, a mapped view, or image/stack.");
            if let Some(hint) = segment_heap_hint(&self.ctx.target) {
                println!("  hint          : {}", hint);
            }
            if let Some(near) = annotate_near_symbol(&self.ctx.target, target) {
                println!("  near symbol   : {}", near);
            }
        }

        Ok(())
    }

    fn cmd_registers(&mut self) -> Result<()> {
        if let Err(e) = self
            .ctx
            .backend
            .set_current_thread(&self.ctx.current_thread)
        {
            error!("failed to select execution context: {:?}", e);
            return Ok(());
        }

        let regs = match self.ctx.backend.read_registers() {
            Ok(r) => r,
            Err(e) => {
                error!("failed to read registers: {:?}", e);
                return Ok(());
            }
        };

        self.ctx.target.registers = Some(self.ctx.register_map.to_hashmap(&regs));
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

        println!();
        println!(
            "  cr0 {}   cr2 {}   cr3 {}",
            read_cr("cr0"),
            read_cr("cr2"),
            read_cr("cr3")
        );
        println!("  cr4 {}   cr8 {}", read_cr("cr4"), read_cr("cr8"));
        println!();

        println!(
            "  cs  {}   ds  {}   es  {}",
            read_seg("cs"),
            read_seg("ds"),
            read_seg("es")
        );
        println!(
            "  fs  {}   gs  {}   ss  {}",
            read_seg("fs"),
            read_seg("gs"),
            read_seg("ss")
        );
        println!();

        Ok(())
    }

    fn cmd_k(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let frame_limit: usize = invocation.arg(0).and_then(|s| s.parse().ok()).unwrap_or(64);

        if let Err(e) = self
            .ctx
            .backend
            .set_current_thread(&self.ctx.current_thread)
        {
            error!("failed to select execution context: {:?}", e);
            return Ok(());
        }

        let regs = match self.ctx.backend.read_registers() {
            Ok(r) => r,
            Err(e) => {
                error!("failed to read registers: {:?}", e);
                return Ok(());
            }
        };

        print_stacktrace(
            &self.ctx.target,
            &self.ctx.register_map,
            &regs,
            frame_limit,
            frame_limit,
            false,
        );
        println!();

        Ok(())
    }

    fn cmd_status(&mut self) -> Result<()> {
        if self.ctx.backend.is_running() {
            println!("VM is running\n");
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
            println!("{}\n", ui::muted("no debug output captured"));
            return Ok(());
        }

        let start = if count == 0 {
            0
        } else {
            page.lines.len().saturating_sub(count)
        };
        for line in &page.lines[start..] {
            println!(
                "{} {}",
                ui::muted(&fmt_timestamp(line.timestamp_ms)),
                line.text
            );
        }
        println!();

        Ok(())
    }
    fn cmd_irp(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(expr) = invocation.arg(0) else {
            println!("{}\n", command_help("irp"));
            return Ok(());
        };

        let addr = match Expr::eval(expr, &self.ctx.target) {
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

        println!("irp {}", ui::addr(irp.address.0));
        println!("  type          : {:#x}", irp.irp_type);
        println!("  size          : {:#x}", irp.size);
        println!("  stack count   : {}", irp.stack_count);
        println!("  current loc   : {}", irp.current_location);
        println!(
            "  pending       : {}",
            if irp.pending_returned { "yes" } else { "no" }
        );
        println!("  requestor mode: {} ({:#x})", mode, irp.requestor_mode);
        if let Some(status) = irp.io_status {
            println!("  io status     : {:#x}", status);
        }
        println!("  user event    : {}", ui::addr(irp.user_event.0));
        println!("  user buffer   : {}", ui::addr(irp.user_buffer.0));
        println!("  mdl           : {}", ui::addr(irp.mdl_address.0));
        println!("  thread        : {}", ui::addr(irp.thread.0));

        match irp.current_stack {
            Some(ios) => {
                println!("  current stack : {}", ui::addr(ios.address.0));
                println!(
                    "    major       : IRP_MJ_{} ({:#x})",
                    irp_major_function_name(ios.major_function),
                    ios.major_function
                );
                println!("    minor       : {:#x}", ios.minor_function);
                println!("    device      : {}", ui::addr(ios.device_object.0));
                println!("    file        : {}", ui::addr(ios.file_object.0));
                let completion = self
                    .ctx
                    .target
                    .closest_symbol_current_context(ios.completion_routine)
                    .unwrap_or_else(|| format!("{:#x}", ios.completion_routine.0));
                println!("    completion  : {}", completion);
                println!("    context     : {}", ui::addr(ios.context.0));
            }
            None => println!("  current stack : {}", "unavailable".bright_black()),
        }
        println!();

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
            println!("{}\n", command_help("drvobj"));
            return Ok(());
        };

        // An expression wins; otherwise treat the argument as a driver name.
        let input = match Expr::eval(expr, &self.ctx.target) {
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
        println!("driver object {} ({})", ui::addr(drv.object.0), mode);
        if let Some(name) = &drv.name {
            println!("  name          : {}", name);
        }
        println!("  driver start  : {}", ui::addr(drv.driver_start.0));
        println!("  driver size   : {:#x}", drv.driver_size);
        println!("  driver section: {}", ui::addr(drv.driver_section.0));
        println!(
            "  driver unload : {}",
            self.fmt_kernel_symbol(drv.driver_unload)
        );

        println!("  devices:");
        if drv.device_chain.is_empty() {
            println!("    {}", "(none)".bright_black());
        } else {
            for d in &drv.device_chain {
                println!(
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

        println!("  dispatch table:");
        for (i, fn_ptr) in drv.dispatch.iter().enumerate() {
            println!(
                "    IRP_MJ_{:<28} {}",
                irp_major_function_name(i as u8),
                self.fmt_kernel_symbol(*fn_ptr)
            );
        }
        println!();

        Ok(())
    }

    fn cmd_devobj(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(expr) = invocation.arg(0) else {
            println!("{}\n", command_help("devobj"));
            return Ok(());
        };

        let addr = match Expr::eval(expr, &self.ctx.target) {
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

        println!("device object {}", ui::addr(dev.object.0));
        println!("    type            : {:#x}", dev.device_type);
        println!("    flags           : {:#x}", dev.flags);
        println!("    characteristics : {:#x}", dev.characteristics);
        println!("    driver object   : {}", ui::addr(dev.driver_object.0));
        println!("    attached device : {}", ui::addr(dev.attached_device.0));
        println!("    next device     : {}", ui::addr(dev.next_device.0));
        println!("    current irp     : {}", ui::addr(dev.current_irp.0));
        println!("    device extension: {}", ui::addr(dev.device_extension.0));

        if !dev.attached_stack.is_empty() {
            println!("attached stack:");
            for (i, e) in dev.attached_stack.iter().enumerate() {
                println!(
                    "  #{} {} driver={} type={:#x} flags={:#x}",
                    i + 1,
                    ui::addr(e.device.0),
                    self.fmt_kernel_symbol(e.driver_object),
                    e.device_type,
                    e.flags
                );
            }
        }
        println!();

        Ok(())
    }

    fn cmd_object(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(expr) = invocation.arg(0) else {
            println!("{}\n", command_help("object"));
            return Ok(());
        };

        let addr = match Expr::eval(expr, &self.ctx.target) {
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

        println!("object {}", ui::addr(o.body.0));
        println!("  input         : {} ({})", ui::addr(o.input.0), o.mode);
        println!("  header        : {}", ui::addr(o.header.0));
        println!("  pointer count : {}", o.pointer_count);
        println!("  handle count  : {}", o.handle_count);
        if let Some(ti) = o.type_index {
            println!("  type index    : {:#x}", ti);
        }
        if let Some(to) = o.type_object {
            println!("  type object   : {}", ui::addr(to.0));
        }
        if let Some(tn) = &o.type_name {
            println!("  type name     : {}", tn);
        }
        if let Some(mask) = o.info_mask {
            println!("  info mask     : {:#x}", mask);
        }
        if let Some(ni) = o.name_info {
            println!("  name info     : {}", ui::addr(ni.0));
        }
        if let Some(name) = &o.name {
            println!("  name          : {}", name);
        }
        println!();

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
                println!("{} callbacks:", c.kind);
                last_kind = c.kind;
            }
            println!(
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
                Some(f) => println!("no callbacks matching '{}'", f),
                None => println!("no registered callbacks found"),
            }
        }
        println!();

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
                println!();
            }
            println!("{}: base={} limit={}", t.label, ui::addr(t.base.0), t.limit);
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
                println!("  [{:4}] {}{}", e.index, display, mark);
            }
            if hooks > 0 {
                println!("  {} hook(s) detected", hooks);
            }
        }
        println!();

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
                Some(f) => println!("  {}", format!("no IRPs found for '{}'", f).bright_black()),
                None => println!("  {}", "no IRPs found".bright_black()),
            }
            println!();
            return Ok(());
        }

        println!("  {:<16} {:<7} Details", "IRP", "Source");
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
            println!(
                "  {} {:<7} stack={:<2} current={:<2} {}",
                ui::addr(h.irp.0),
                h.source,
                h.stack_count,
                h.current_location,
                details
            );
        }
        println!();

        Ok(())
    }
    fn cmd_address(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(expr) = invocation.arg(0) else {
            println!("{}\n", command_help("address"));
            return Ok(());
        };

        let addr = match Expr::eval(expr, &self.ctx.target) {
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

        println!("address {}", ui::addr(d.address.0));
        println!("  kind    : {}", d.kind);
        if let Some(m) = &d.module {
            println!(
                "  module  : {}+{:#x}  (base {}, size {:#x})",
                m.name,
                m.offset,
                ui::addr(m.base.0),
                m.size
            );
        }
        if let Some(s) = &d.section {
            println!("  section : {}", s);
        }
        if let Some(va) = &d.va_type {
            println!("  region  : {}", va);
        }
        if let Some(r) = &d.region {
            println!(
                "  region  : {} - {}",
                ui::addr(r.start.0),
                ui::addr(r.end.0)
            );
            if let Some(p) = r.protection {
                println!("    protection : {:#x}", p);
            }
            if let Some(t) = r.vad_type {
                println!("    vad type   : {:#x}", t);
            }
            if let Some(pm) = r.private_memory {
                println!("    private    : {}", pm);
            }
            if let Some(det) = &r.details {
                println!("    details    : {}", det);
            }
        }
        if d.module.is_none() && d.region.is_none() && d.va_type.is_none() {
            println!(
                "  {}",
                "not inside any loaded module, kernel region, or VAD".bright_black()
            );
        }
        println!();

        Ok(())
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
