//! Kernel object inspectors: driver and device objects, IRPs, object
//! headers, and the notify-callback and system-service tables.

use tabled::builder::Builder;

use owo_colors::OwoColorize;

use crate::error::Result;
use crate::expr::Expr;
use crate::target::irpfind::{IrpCriteria, IrpFindDetail, IrpPool};
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
    cmd_irpfind;
    names: ["!irpfind", "irpfind"],
    usage: "!irpfind [-v] [pool-type [restart-address [criteria data]]]",
    summary: "Find IRPs by scanning pool for IoAllocateIrp's allocations.",
    details: "Scans the pool region Windows 10 and later assign in MiState.Vs.SystemVaRegions, walking the page tables so only mapped pages are read, for 16-byte-aligned _POOL_HEADERs tagged Irp; big allocations come from PoolBigPageTable. A block counts when its body is a live _IRP: Type 6 (IoFreeIrp clears it), Size the header plus whole stack locations and at least IoSizeOfIrp(StackCount) (a lookaside IRP keeps its larger packet size), CurrentLocation at most StackCount + 1. Each IRP is listed with its thread (Tail.Overlay.Thread), the current stack location's major and minor function, device, and owning driver, and the process of its MDL; one whose CurrentLocation is past StackCount is listed as complete. -v adds the pool header, I/O status, PendingReturned, UserEvent, UserBuffer, the current location's file object and completion routine, and OriginalFileObject. pool-type is 0 (nonpaged, the default) or 1 (paged); 2 (special) and 4 (session) have no region of their own on these builds and are refused. restart-address resumes a scan from that page. Criteria follow WinDbg: arg (a stack location's Argument1-4), device (a stack location's DeviceObject), fileobject (Tail.Overlay.OriginalFileObject), mdlprocess (MdlAddress->Process), thread (Tail.Overlay.Thread), userevent (UserEvent); use 0 as the restart address to scan the whole pool. The scan stops after 4,096 IRPs or on Ctrl-C and prints where to restart. IRPs a driver builds in its own allocations (IoInitializeIrp) carry that driver's tag and are not found; irps lists IRPs from thread IrpLists instead.",
    completion: Expression,
}

repl_command! {
    cmd_object;
    names: ["!object", "object"],
    usage: "!object <path|object-expression>",
    summary: "Inspect an executive object header and body, and list a directory.",
    details: "A path starting with `\\` names an object in the object namespace (`!object \\`, `!object \\Driver\\ACPI`), looked up from the root directory without case; symbolic links along it are not followed. A directory lists its entries with their types.",
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

    fn cmd_irpfind(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let mut args: Vec<&str> = invocation.argv.iter().map(|arg| arg.as_ref()).collect();
        let verbose = args
            .first()
            .is_some_and(|arg| arg.eq_ignore_ascii_case("-v"));
        if verbose {
            args.remove(0);
        }
        if args.len() == 3 || args.len() > 4 {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        }
        let mut values = Vec::new();
        for (index, arg) in args.iter().enumerate() {
            // The criteria name is a word, not an expression.
            if index == 2 {
                continue;
            }
            let Some(VirtAddr(value)) = self.eval_or_report(arg) else {
                return Ok(());
            };
            values.push(value);
        }
        let pool = match IrpPool::from_windbg(values.first().copied().unwrap_or(0)) {
            Ok(pool) => pool,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let restart = values
            .get(1)
            .copied()
            .filter(|value| *value != 0)
            .map(VirtAddr);
        let criteria = match (args.get(2), values.get(2)) {
            (Some(name), Some(value)) => match IrpCriteria::parse(name, *value) {
                Ok(criteria) => Some(criteria),
                Err(error) => {
                    error!("{error}");
                    return Ok(());
                }
            },
            _ => None,
        };
        match self.ctx.target.irp_find(pool, restart, criteria) {
            Ok(detail) => self.print_irp_find(&detail, verbose),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn print_irp_find(&self, detail: &IrpFindDetail, verbose: bool) {
        outln!(
            "Searching {} pool ({} : {}) for Tag: Irp",
            detail.pool.name(),
            ui::addr(detail.scan_start.0),
            ui::addr(detail.region_end.0)
        );
        if let Some(criteria) = detail.criteria {
            outln!(
                "  only IRPs whose {} is {:#x}",
                criteria.name(),
                criteria.value()
            );
        }
        outln!();
        outln!(
            "{:<16} [ {:<16} ] irpStack: (Mj,Mn)  {:<16} [Driver]  MDL Process",
            "Irp",
            "Thread",
            "DevObj"
        );
        for entry in &detail.irps {
            let irp = &entry.irp;
            let head = format!("{} [{}]", ui::addr(irp.address.0), ui::addr(irp.thread.0));
            if entry.completed() {
                outln!(
                    "{head} Irp is complete (CurrentLocation {} > StackCount {})",
                    irp.current_location,
                    irp.stack_count
                );
            } else if let Some(stack) = &irp.current_stack {
                outln!(
                    "{head} irpStack: ({:>2x},{:>2x})  {} [{}]  {}  IRP_MJ_{}",
                    stack.major_function,
                    stack.minor_function,
                    ui::addr(stack.device_object.0),
                    entry.driver.as_deref().unwrap_or("?"),
                    entry
                        .mdl_process
                        .map(|process| ui::addr(process.0).to_string())
                        .unwrap_or_default(),
                    irp_major_function_name(stack.major_function)
                );
            } else {
                outln!(
                    "{head} current stack location {} of {} unreadable",
                    irp.current_location,
                    irp.stack_count
                );
            }
            if verbose {
                outln!(
                    "    pool header {}  tag '{}'  size {:#x}  stack {}/{}  mode {}",
                    entry
                        .pool_header
                        .map(|header| ui::addr(header.0).to_string())
                        .unwrap_or_else(|| "(big pool)".to_string()),
                    entry.tag,
                    irp.size,
                    irp.current_location,
                    irp.stack_count,
                    if irp.requestor_mode == 0 {
                        "KernelMode"
                    } else {
                        "UserMode"
                    }
                );
                outln!(
                    "    IoStatus {}  PendingReturned {}  UserEvent {}  UserBuffer {}  MdlAddress {}",
                    irp.io_status
                        .map(|status| format!("{status:#x}"))
                        .unwrap_or_else(|| "?".to_string()),
                    if irp.pending_returned { "yes" } else { "no" },
                    ui::addr(irp.user_event.0),
                    ui::addr(irp.user_buffer.0),
                    ui::addr(irp.mdl_address.0)
                );
                if let Some(stack) = irp.current_stack.as_ref().filter(|_| !entry.completed()) {
                    outln!(
                        "    stack location {}  FileObject {}  CompletionRoutine {}  Context {}",
                        ui::addr(stack.address.0),
                        ui::addr(stack.file_object.0),
                        self.fmt_kernel_symbol(stack.completion_routine),
                        ui::addr(stack.context.0)
                    );
                }
                outln!(
                    "    OriginalFileObject {}",
                    ui::addr(entry.original_file_object.0)
                );
            }
        }
        outln!();
        outln!(
            "{} IRP(s) in {} mapped page(s); big pool: {}",
            detail.irps.len(),
            detail.scanned_pages,
            detail.big_pool_status
        );
        if let Some(restart) = detail.restart {
            outln!(
                "{}; resume with !irpfind {} {}",
                if detail.interrupted {
                    "interrupted"
                } else {
                    "stopped after 4096 IRPs"
                },
                u8::from(detail.pool == IrpPool::Paged),
                ui::addr(restart.0)
            );
        }
        outln!();
    }

    fn cmd_object(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(expr) = invocation.arg(0) else {
            outln!("{}\n", command_help("object"));
            return Ok(());
        };

        let detail = match self
            .ctx
            .target
            .object_argument(expr, self.radix)
            .and_then(|addr| self.ctx.target.inspect_object(addr))
        {
            Ok(detail) => detail,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };
        let o = &detail.header;

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
        if let Some(entries) = &detail.entries {
            outln!("  entries       : {}", entries.len());
            let mut builder = Builder::default();
            builder.push_record(["Object", "Type", "Name"]);
            for entry in entries {
                builder.push_record([
                    ui::addr(entry.object.0).to_string(),
                    entry.type_name.clone().unwrap_or_else(|| "?".to_string()),
                    entry.name.clone(),
                ]);
            }
            outln!();
            print_padded_table(builder);
            return Ok(());
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
