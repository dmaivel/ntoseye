//! Kernel object inspectors: driver and device objects, IRPs, object
//! headers, and the notify-callback and system-service tables.

use tabled::builder::Builder;

use owo_colors::OwoColorize;

use crate::error::Result;
use crate::expr::Expr;
use crate::target::{irp_major_function_name, kthread_state_name, wait_reason_name};
use crate::types::VirtAddr;
use crate::ui;

use crate::repl::*;

repl_command! {
    cmd_drivers;
    names: ["drivers"],
    usage: "drivers [filter]",
    summary: "List driver objects from the \\Driver object directory.",
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

impl ReplState<'_> {
    fn cmd_drivers(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let filter = invocation.arg(0).map(|s| s.to_lowercase());

        match self.ctx.target.enumerate_driver_objects() {
            Ok(drivers) => {
                let mut builder = Builder::default();
                builder.push_record(vec![
                    "DriverObject".to_string(),
                    "Name".to_string(),
                    "DriverStart".to_string(),
                    "Size".to_string(),
                    "Module".to_string(),
                    "DeviceObject".to_string(),
                    "DriverUnload".to_string(),
                ]);

                let mut count = 0;
                for driver in &drivers {
                    if let Some(ref f) = filter
                        && !driver.name.to_lowercase().contains(f)
                        && !format!("{:#x}", driver.object.0).starts_with(f)
                    {
                        continue;
                    }
                    count += 1;
                    let module = self
                        .ctx
                        .target
                        .symbols
                        .find_module_for_address(self.ctx.target.kernel_dtb(), driver.driver_start)
                        .map(|module| module.name)
                        .unwrap_or_else(|| "-".to_string());
                    builder.push_record(vec![
                        ui::addr(driver.object.0).to_string(),
                        driver.name.to_string(),
                        ui::addr(driver.driver_start.0).to_string(),
                        format!("0x{:x}", driver.driver_size),
                        module.to_string(),
                        ui::addr(driver.device_object.0).to_string(),
                        ui::addr(driver.driver_unload.0),
                    ]);
                }

                if count == 0 {
                    outln!("{}\n", "no matching drivers".bright_black());
                } else {
                    print_padded_table(builder);
                }
                *self.caches.drivers.write().unwrap() = drivers;
            }
            Err(e) => {
                error!("failed to list drivers: {}", e);
            }
        }

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

        let Some(addr) = self.eval_or_report(expr) else {
            return Ok(());
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

    fn cmd_irp(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(expr) = invocation.arg(0) else {
            outln!("{}\n", command_help("irp"));
            return Ok(());
        };

        let Some(addr) = self.eval_or_report(expr) else {
            return Ok(());
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

    fn cmd_object(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(expr) = invocation.arg(0) else {
            outln!("{}\n", command_help("object"));
            return Ok(());
        };

        let Some(addr) = self.eval_or_report(expr) else {
            return Ok(());
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
}
