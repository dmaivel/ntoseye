//! Kernel object inspectors: driver and device objects, IRPs, object
//! headers, and the notify-callback and system-service tables.

use std::collections::HashMap;

use tabled::builder::Builder;

use owo_colors::OwoColorize;

use ntoseye_macros::{command, grammar};

use crate::base::error::{Error, Result};
use crate::base::types::VirtAddr;
use crate::hosts::repl::args::{ArgCursor, ArgCx, ArgError, FromArg};
use crate::hosts::repl::*;
use crate::hosts::ui;
use crate::nt::target::irpfind::{IrpCriteria, IrpCriteriaKind, IrpFindDetail, IrpPool};
use crate::nt::target::object::{
    DeviceObjectDetail, DriverObjectDetail, DriverObjectInfo, IrpHit, IrpInfo, NotifyCallback,
    ObjectDetail, ObjectName, SL_INVOKE_ON_CANCEL, SL_INVOKE_ON_ERROR, SL_INVOKE_ON_SUCCESS,
    SL_PENDING_RETURNED, SsdtTable,
};
use crate::nt::target::{Target, irp_major_function_name, irp_minor_function_name};
use crate::session::Session;

/// A kernel address as its nearest symbol (styled), or the bare address
/// when nothing resolves.
fn kernel_symbol(target: &Target, address: VirtAddr) -> String {
    target
        .format_code_address(target.kernel_dtb(), address)
        .map(|symbol| ui::symbol(&symbol))
        .unwrap_or_else(|| ui::addr(address.0))
}

/// An address, or `-` for a null pointer.
fn addr_or_dash(address: VirtAddr) -> String {
    if address.is_zero() {
        "-".to_string()
    } else {
        ui::addr(address.0)
    }
}

/// A kernel address as its nearest symbol, or `-` for a null pointer.
fn kernel_symbol_or_dash(target: &Target, address: VirtAddr) -> String {
    if address.is_zero() {
        "-".to_string()
    } else {
        kernel_symbol(target, address)
    }
}

/// List the driver objects in the \Driver object directory.
#[command(
    names = ["drivers"],
    category = "processes and modules",
    kind = Query,
    target = Kernel,
    python = none,
)]
fn drivers(
    session: &Session,
    #[arg(render)] filter: Option<String>,
) -> Result<Vec<DriverObjectInfo>> {
    session
        .target
        .enumerate_driver_objects()
        .map_err(|error| Error::DebugInfo(format!("failed to list drivers: {error}")))
}

/// `drivers`: the drivers whose name contains `filter` or whose address
/// starts with it.
impl Render<Option<String>> for Vec<DriverObjectInfo> {
    fn render(&self, repl: &mut ReplState<'_>, filter: Option<String>) {
        let pattern = filter;
        let filter = pattern.as_ref().map(|filter| filter.to_lowercase());
        let target = &repl.ctx.target;
        let mut builder = Builder::default();
        builder.push_record([
            "Driver object",
            "Name",
            "Driver start",
            "Size",
            "Module",
            "Device object",
            "Driver unload",
        ]);

        // The loaded-module list, which names modules whose symbols did not
        // load too.
        let modules = target.kernel_modules().unwrap_or_default();
        let mut count = 0;
        for driver in self {
            if let Some(ref f) = filter
                && !driver.name.to_lowercase().contains(f)
                && !format!("{:#x}", driver.object.0).starts_with(f)
            {
                continue;
            }
            count += 1;
            let module = modules
                .iter()
                .find(|module| module.contains_address(driver.driver_start))
                .map_or("-", |module| module.name.as_str());
            builder.push_record(vec![
                ui::addr(driver.object.0).to_string(),
                driver.name.to_string(),
                ui::addr(driver.driver_start.0).to_string(),
                format!("0x{:x}", driver.driver_size),
                module.to_string(),
                addr_or_dash(driver.device_object),
                addr_or_dash(driver.driver_unload),
            ]);
        }

        if count == 0 {
            match pattern {
                Some(pattern) => {
                    outln!("{}", ui::muted(&format!("no drivers matching '{pattern}'")))
                }
                None => outln!("{}", ui::muted("no drivers")),
            }
        } else {
            print_padded_table(builder);
        }
        *repl.caches.drivers.write().unwrap() = self.clone();
    }
}

/// The driver object that `!drvobj` names: a driver name (`ACPI` or
/// `\Driver\ACPI`), or else an address expression. The name comes first:
/// nearly every driver's is also its module's, which evaluates to the
/// image base.
#[grammar(usage = "<driver-object|driver-name>", complete = [Driver])]
fn driver_argument(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<VirtAddr, ArgError> {
    let Some(text) = cursor.word() else {
        return Err(ArgError::Missing);
    };
    let full;
    let needle = if text
        .get(..8)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("\\Driver\\"))
    {
        &*text
    } else {
        full = format!("\\Driver\\{text}");
        full.as_str()
    };
    cx.state
        .ctx
        .target
        .enumerate_driver_objects()
        .ok()
        .and_then(|drivers| {
            drivers
                .into_iter()
                .find(|driver| driver.name.eq_ignore_ascii_case(needle))
        })
        .map(|driver| driver.object)
        .map_or_else(
            || {
                cx.eval(&text).map_err(|_| {
                    ArgError::Message(format!(
                        "driver '{text}' not found, and it is not an address expression"
                    ))
                })
            },
            Ok,
        )
}

/// The parts of a driver object `!drvobj` shows, by WinDbg's flags: 1 its
/// device objects, 2 its dispatch routines; 4, detail on the devices,
/// implies 1. Both without flags.
#[derive(Clone, Copy)]
pub struct DriverSections {
    devices: bool,
    dispatch: bool,
}

#[grammar(usage = "[flags]", complete = [Expression])]
fn drvobj_flags(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<DriverSections, ArgError> {
    let Some(word) = cursor.word() else {
        return Ok(DriverSections {
            devices: true,
            dispatch: true,
        });
    };
    let flags = cx.eval(&word)?.0;
    cursor.finish(cx.name)?;
    Ok(DriverSections {
        devices: flags & 0x5 != 0,
        dispatch: flags & 0x2 != 0,
    })
}

/// The device object a word names: an object path, where a bare name is
/// one in `\Device` (`Null` for `\Device\Null`), or else an address
/// expression. The name comes first, as for `!drvobj`: `Null` is also
/// null.sys's module. A long number is an address and nothing else, so it
/// skips the directory walk, which costs a read per entry over KD.
pub fn device_object_named(
    cx: &mut ArgCx<'_, '_>,
    text: &str,
) -> std::result::Result<VirtAddr, ArgError> {
    let digits: String = text
        .trim_start_matches("0x")
        .chars()
        .filter(|c| *c != '`')
        .collect();
    if digits.len() > 8 && digits.chars().all(|c| c.is_ascii_hexdigit()) {
        return cx.eval(text);
    }
    let path = if text.starts_with('\\') {
        text.to_string()
    } else {
        format!("\\Device\\{text}")
    };
    match cx.state.ctx.target.object_at_path(&path) {
        Ok(object) => Ok(object),
        Err(error) => cx.eval(text).map_err(|_| {
            ArgError::Message(format!(
                "device '{text}' not found ({error}), and it is not an address expression"
            ))
        }),
    }
}

/// The device object that `!devobj` names.
#[grammar(usage = "<device-object|device-name>", complete = [Expression])]
fn device_argument(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<VirtAddr, ArgError> {
    let Some(text) = cursor.word() else {
        return Err(ArgError::Missing);
    };
    device_object_named(cx, &text)
}

/// Show a DRIVER_OBJECT with its device chain and dispatch table.
///
/// The flags follow WinDbg: 1 shows the device objects, 2 the dispatch
/// routines; without flags, both.
#[command(
    names = ["!drvobj", "drvobj"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    python = Driver,
    python_name = "inspect",
)]
fn drvobj(
    session: &Session,
    #[arg(receiver, parse = driver_argument)] driver: VirtAddr,
    #[arg(render, parse = drvobj_flags)] sections: DriverSections,
) -> Result<DriverObjectDetail> {
    session.target.inspect_driver_object(driver)
}

impl Render<DriverSections> for DriverObjectDetail {
    fn render(&self, repl: &mut ReplState<'_>, sections: DriverSections) {
        let target = &repl.ctx.target;
        let mode = if self.via_pointer {
            "pointer"
        } else {
            "direct"
        };
        outln!("DRIVER_OBJECT {} ({})", ui::addr(self.object.0), mode);
        outln!("  DriverName    : {}", self.name.as_deref().unwrap_or("-"));
        outln!("  DriverStart   : {}", addr_or_dash(self.driver_start));
        outln!("  DriverSize    : {:#x}", self.driver_size);
        outln!("  DriverSection : {}", addr_or_dash(self.driver_section));
        outln!(
            "  DriverUnload  : {}",
            kernel_symbol_or_dash(target, self.driver_unload)
        );

        // A table ends with the blank line that separates sections.
        let mut after_table = false;
        if sections.devices {
            print_section("devices");
        }
        if !sections.devices {
        } else if self.devices.is_empty() {
            outln!("  {}", ui::muted("no device objects"));
        } else {
            let mut builder = Builder::default();
            builder.push_record([
                "Device",
                "Type",
                "Flags",
                "Characteristics",
                "Attached device",
                "Next device",
            ]);
            for d in &self.devices {
                builder.push_record([
                    ui::addr(d.device.0),
                    format!("{:#x}", d.device_type),
                    format!("{:#x}", d.flags),
                    format!("{:#x}", d.characteristics),
                    addr_or_dash(d.attached),
                    addr_or_dash(d.next),
                ]);
            }
            print_padded_table(builder);
            after_table = true;
        }
        if !sections.dispatch {
            return;
        }
        if after_table {
            outln!("{}", ui::label("dispatch table"));
        } else {
            print_section("dispatch table");
        }
        for routine in &self.dispatch {
            outln!(
                "  IRP_MJ_{:<28} {}",
                irp_major_function_name(routine.index as u8),
                routine
                    .symbol
                    .as_deref()
                    .map(ui::symbol)
                    .unwrap_or_else(|| ui::addr(routine.routine.0))
            );
        }
    }
}

/// Show a DEVICE_OBJECT and its attached stack.
#[command(
    names = ["!devobj", "devobj"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    python = Device,
    python_name = "inspect",
)]
fn devobj(
    session: &Session,
    #[arg(receiver, parse = device_argument)] device: VirtAddr,
) -> Result<DeviceObjectDetail> {
    session.target.inspect_device_object(device)
}

impl Render for DeviceObjectDetail {
    fn render(&self, repl: &mut ReplState<'_>, (): ()) {
        outln!("DEVICE_OBJECT {}", ui::addr(self.object.0));
        outln!("  DeviceType      : {:#x}", self.device_type);
        outln!("  Flags           : {:#x}", self.flags);
        outln!("  Characteristics : {:#x}", self.characteristics);
        outln!("  DriverObject    : {}", addr_or_dash(self.driver_object));
        outln!("  AttachedDevice  : {}", addr_or_dash(self.attached_device));
        outln!("  NextDevice      : {}", addr_or_dash(self.next_device));
        outln!("  CurrentIrp      : {}", addr_or_dash(self.current_irp));
        outln!(
            "  DeviceExtension : {}",
            addr_or_dash(self.device_extension)
        );

        if !self.attached_stack.is_empty() {
            print_section("attached stack");
            let mut builder = Builder::default();
            builder.push_record(["#", "Device", "Driver object", "Type", "Flags"]);
            for (i, e) in self.attached_stack.iter().enumerate() {
                builder.push_record([
                    format!("{:02}", i + 1),
                    ui::addr(e.device.0),
                    kernel_symbol_or_dash(&repl.ctx.target, e.driver_object),
                    format!("{:#x}", e.device_type),
                    format!("{:#x}", e.flags),
                ]);
            }
            print_padded_table(builder);
        }
    }
}

/// Show an IRP and its I/O stack locations.
///
/// Shows the IRP as WinDbg does: which stack location is current, the MDL,
/// system buffer and thread, then each location from the lowest driver's up,
/// the current one marked with > and a run of locations the IRP has not reached
/// as one unused line. A location shows its major and minor function, flags and
/// control, device and file, its completion routine and context with when the
/// routine runs (Success, Error, Cancel) and whether its driver returned
/// pending, the device's driver, and four arguments. The driver of the location
/// below it in the list set that completion routine. With a second argument,
/// such as 1, it first shows the IRP's status, requestor mode, user event and
/// user buffer.
#[command(
    names = ["!irp", "irp"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    python = Inspect,
)]
fn irp(
    session: &Session,
    address: VirtAddr,
    #[arg(render)] detail: Option<String>,
) -> Result<IrpInfo> {
    session.target.inspect_irp(address).map_err(|error| {
        Error::DebugInfo(format!(
            "{} is not a readable _IRP: {error}",
            ui::addr(address.0)
        ))
    })
}

impl Render<Option<String>> for IrpInfo {
    fn render(&self, repl: &mut ReplState<'_>, detail: Option<String>) {
        let irp = self;
        let (count, location) = (irp.stack_count, irp.current_location);
        if (1..=count).contains(&location) {
            let at = irp.current_stack().map_or_else(
                || "unreadable".to_string(),
                |current| format!("= {:#x}", current.address.0),
            );
            outln!("Irp is active with {count} stacks {location} is current ({at})");
        } else if usize::from(location) == usize::from(count) + 1 {
            outln!("Irp is completed with {count} stacks");
        } else {
            outln!("Irp has {count} stacks and an invalid current location {location}");
        }
        let mdl = if irp.mdl_address.is_zero() {
            "No Mdl".to_string()
        } else {
            format!("Mdl = {}", ui::addr(irp.mdl_address.0))
        };
        let system_buffer = if irp.system_buffer.is_zero() {
            "No System Buffer".to_string()
        } else {
            format!("System Buffer = {}", ui::addr(irp.system_buffer.0))
        };
        outln!(
            " {mdl}: {system_buffer}: Thread {}:  Irp stack trace.",
            ui::addr(irp.thread.0)
        );
        if detail.is_some() {
            print_irp_detail(irp);
        }
        outln!("     cmd  flg cl Device   File     Completion-Context");
        let target = &repl.ctx.target;
        let mut drivers = HashMap::new();
        let mut index = 0;
        while let Some(ios) = irp.stack.get(index) {
            // Locations below the current one that the IRP has not reached
            // are empty; a run of them is one line.
            let unused = irp.stack[index..]
                .iter()
                .take_while(|ios| ios.is_unused())
                .count();
            if unused > 0 {
                let (first, last) = (index + 1, index + unused);
                let marker = if (first..=last).contains(&usize::from(location)) {
                    '>'
                } else {
                    ' '
                };
                if first == last {
                    outln!("{marker}[{first}: unused]");
                } else {
                    outln!("{marker}[{first}-{last}: unused]");
                }
                index += unused;
                continue;
            }
            index += 1;
            let marker = if index == usize::from(location) {
                '>'
            } else {
                ' '
            };
            let minor = irp_minor_function_name(ios.major_function, ios.minor_function)
                .map_or_else(|| "N/A".to_string(), |name| format!("IRP_MN_{name}"));
            outln!(
                "{marker}[IRP_MJ_{}({:x}), {minor}({:x})]",
                irp_major_function_name(ios.major_function),
                ios.major_function,
                ios.minor_function
            );
            let control = ios.control;
            let mut when: Vec<&str> = [
                (SL_INVOKE_ON_SUCCESS, "Success"),
                (SL_INVOKE_ON_ERROR, "Error"),
                (SL_INVOKE_ON_CANCEL, "Cancel"),
            ]
            .into_iter()
            .filter(|(bit, _)| control & bit != 0)
            .map(|(_, name)| name)
            .collect();
            if control & SL_PENDING_RETURNED != 0 {
                when.push("pending");
            }
            outln!(
                "{:>13x} {:>2x} {:08x} {:08x} {:08x}-{:08x} {}",
                ios.flags,
                control,
                ios.device_object.0,
                ios.file_object.0,
                ios.completion_routine.0,
                ios.context.0,
                when.join(" ")
            );
            let driver = (!ios.device_object.is_zero())
                .then(|| {
                    drivers
                        .entry(ios.device_object)
                        .or_insert_with(|| target.device_driver_name(ios.device_object))
                        .clone()
                })
                .flatten()
                .unwrap_or_default();
            let routine = if ios.completion_routine.is_zero() {
                String::new()
            } else {
                kernel_symbol(target, ios.completion_routine)
            };
            if !driver.is_empty() || !routine.is_empty() {
                outln!(
                    "{}",
                    format!("               {driver}  {routine}").trim_end()
                );
            }
            let [a1, a2, a3, a4] = ios.arguments;
            outln!("                        Args: {a1:08x} {a2:08x} {a3:08x} {a4:08x}");
        }
        if irp.stack.len() < usize::from(count) {
            outln!(
                "{}",
                ui::muted(&format!(
                    "locations {} to {count} could not be read",
                    irp.stack.len() + 1
                ))
            );
        }
    }
}

/// The IRP's own fields that `!irp <address> 1` shows, as WinDbg's
/// detail form does.
fn print_irp_detail(irp: &IrpInfo) {
    outln!(
        "IoStatus.Status = {}",
        irp.io_status
            .map_or_else(|| "-".to_string(), |status| format!("{status:08x}"))
    );
    outln!(
        "RequestorMode = {}",
        if irp.requestor_mode == 0 {
            "KernelMode"
        } else {
            "UserMode"
        }
    );
    outln!("PendingReturned = {}", u8::from(irp.pending_returned));
    outln!("UserEvent = {}", ui::addr(irp.user_event.0));
    outln!("UserBuffer = {}", ui::addr(irp.user_buffer.0));
}

/// The next word, which a later argument also takes.
#[grammar(usage = "")]
fn peek_word(
    _: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<Option<String>, ArgError> {
    Ok(cursor.words().next().map(str::to_string))
}

/// Find the in-flight IRPs in thread IrpLists and device CurrentIrp fields.
#[command(
    names = ["irps"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    python = Inspect,
)]
fn irps(
    session: &Session,
    #[arg(render, parse = peek_word)] shown: Option<String>,
    #[arg(name = "process-filter|driver-filter", complete = Process)] filter: Option<String>,
) -> Result<Vec<IrpHit>> {
    session.target.discover_irps(filter.as_deref())
}

/// `irps`: the IRPs found, or that none matched `filter`.
impl Render<Option<String>> for Vec<IrpHit> {
    fn render(&self, _: &mut ReplState<'_>, filter: Option<String>) {
        if self.is_empty() {
            match filter {
                Some(f) => outln!("{}", ui::muted(&format!("no IRPs matching '{f}'"))),
                None => outln!("{}", ui::muted("no IRPs")),
            }
            return;
        }

        let dash = || "-".to_string();
        // Enum values read `Name (0xN)`, as every command shows them.
        let named = |name: Option<&str>, value: Option<u8>| match (name, value) {
            (Some(name), Some(value)) => format!("{name} ({value:#x})"),
            (None, Some(value)) => format!("{value:#x}"),
            (_, None) => "-".to_string(),
        };
        let mut builder = Builder::default();
        builder.push_record([
            "IRP",
            "Source",
            "Stack count",
            "Current",
            "PID",
            "TID",
            "ETHREAD",
            "State",
            "Wait reason",
            "Device",
            "Driver",
        ]);
        for h in self {
            builder.push_record([
                ui::addr(h.irp.0),
                h.source.to_string(),
                h.stack_count.to_string(),
                h.current_location.to_string(),
                h.pid.map(|p| p.to_string()).unwrap_or_else(dash),
                h.tid.map(|t| t.to_string()).unwrap_or_else(dash),
                h.ethread.map(|e| ui::addr(e.0)).unwrap_or_else(dash),
                named(h.state_name(), h.state),
                named(h.wait_reason_name(), h.wait_reason),
                h.device.map(|d| ui::addr(d.0)).unwrap_or_else(dash),
                h.driver.clone().unwrap_or_else(dash),
            ]);
        }
        print_padded_table(builder);
    }
}

/// A WinDbg pool type: 0 nonpaged, 1 paged.
impl FromArg for IrpPool {
    const COMPLETION: CompletionStrategy = CompletionStrategy::Expression;

    fn from_arg(cx: &mut ArgCx<'_, '_>, text: &str) -> std::result::Result<Self, ArgError> {
        IrpPool::from_windbg(cx.eval(text)?.0).map_err(|error| ArgError::Message(error.to_string()))
    }
}

/// A WinDbg `!irpfind` criteria name, in any case.
impl FromArg for IrpCriteriaKind {
    fn from_arg(_: &mut ArgCx<'_, '_>, text: &str) -> std::result::Result<Self, ArgError> {
        IrpCriteriaKind::parse(text).map_err(|error| ArgError::Message(error.to_string()))
    }
}

/// `!irpfind`'s pool type, once the line has a WinDbg shape: after `-v`,
/// up to a pool type and restart address, or both and a criteria pair.
#[grammar(usage = "[{}]", complete = [Expression])]
fn irpfind_pool(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<Option<IrpPool>, ArgError> {
    let words = cursor.remaining();
    if words == 3 {
        return Err(ArgError::usage(
            cx.name,
            format!("{}: a criteria needs its data", cx.name),
        ));
    }
    if words > 4 {
        return Err(ArgError::usage(
            cx.name,
            format!("{}: too many arguments", cx.name),
        ));
    }
    cursor
        .word()
        .map(|text| IrpPool::from_arg(cx, &text))
        .transpose()
}

/// Scan pool for the IRPs that IoAllocateIrp allocates.
///
/// Scans the pool region for 16-byte-aligned _POOL_HEADERs with the tag Irp. On
/// Windows 10 1803 and later, the region comes from MiState.Vs.SystemVaRegions,
/// and otherwise it is MmNonPagedPoolStart/End or MmPagedPoolStart/End. The
/// scan walks the page tables and reads only mapped pages, and big allocations
/// come from PoolBigPageTable. The command counts a block only if its body is a
/// live _IRP. In a live _IRP, Type is 6 (IoFreeIrp clears it), and Size is the
/// header plus whole stack locations and at least IoSizeOfIrp(StackCount). A
/// lookaside IRP keeps its larger packet size. CurrentLocation is at most
/// StackCount + 1. For each IRP, the command shows its thread
/// (Tail.Overlay.Thread), the process of its MDL, and the major function, minor
/// function, device, and owning driver of the current stack location. If
/// CurrentLocation is more than StackCount, the IRP shows as complete. -v also
/// shows the pool header, I/O status, PendingReturned, UserEvent, UserBuffer,
/// and OriginalFileObject, and also the file object and completion routine of
/// the current location. pool-type is 0 (nonpaged, the default) or 1 (paged).
/// The command does not accept 2 (special) or 4 (session), because these pool
/// types have no region of their own on these builds. restart-address continues
/// a scan from that page. The criteria are the same as in WinDbg: arg
/// (Argument1-4 of a stack location), device (DeviceObject of a stack
/// location), fileobject (Tail.Overlay.OriginalFileObject), mdlprocess
/// (MdlAddress->Process), thread (Tail.Overlay.Thread), and userevent
/// (UserEvent). Use 0 as the restart address to scan the whole pool. The scan
/// stops after 4,096 IRPs, or when you press Ctrl-C, and then shows the command
/// that continues the scan, with the criteria. The scan checks the big-pool
/// allocations last. If the scan gets to the limit in the big-pool allocations,
/// the command shows a message. A restart cannot get to the remaining big-pool
/// allocations. A driver can build IRPs in its own allocations
/// (IoInitializeIrp). These IRPs have the tag of that driver, so the scan does
/// not find them. Use irps to list the IRPs in thread IrpLists.
#[command(
    names = ["!irpfind", "irpfind"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    python = Inspect,
    python_name = "irp_find",
)]
fn irpfind(
    session: &Session,
    #[arg(render, switch = "-v")] verbose: bool,
    #[arg(parse = irpfind_pool)] pool_type: Option<IrpPool>,
    #[arg(name = "restart-address")] restart: Option<VirtAddr>,
    criteria: Option<IrpCriteriaKind>,
    #[arg(default = 0, name = "data")] value: u64,
) -> Result<IrpFindDetail> {
    let criteria = criteria.map(|kind| IrpCriteria::new(kind, value));
    session.target.irp_find(
        pool_type.unwrap_or(IrpPool::NonPaged),
        restart.filter(|address| !address.is_zero()),
        criteria,
    )
}

impl Render<bool> for IrpFindDetail {
    fn render(&self, repl: &mut ReplState<'_>, verbose: bool) {
        let detail = self;
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
        // The driver names vary in length; pad that column to the longest
        // so the MDL process and major function line up under their headers.
        let driver_width = detail
            .irps
            .iter()
            .map(|entry| entry.driver.as_deref().unwrap_or("-").len() + 2)
            .max()
            .unwrap_or(0)
            .max("[Driver]".len());
        outln!(
            "{:<16} [{:<16}] irpStack: (Mj,Mn)  {:<16} {:<driver_width$}  {:<16}  Major function",
            "Irp",
            "Thread",
            "DevObj",
            "[Driver]",
            "MDL Process"
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
            } else if let Some(stack) = irp.current_stack() {
                let driver = format!("[{}]", entry.driver.as_deref().unwrap_or("-"));
                outln!(
                    "{head} irpStack: ({:>2x},{:>2x})  {} {driver:<driver_width$}  {:<16}  IRP_MJ_{}",
                    stack.major_function,
                    stack.minor_function,
                    ui::addr(stack.device_object.0),
                    entry
                        .mdl_process
                        .map_or_else(|| "-".to_string(), addr_or_dash),
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
                        .map(|status| format!("{status:#010x}"))
                        .unwrap_or_else(|| "-".to_string()),
                    if irp.pending_returned { "yes" } else { "no" },
                    addr_or_dash(irp.user_event),
                    addr_or_dash(irp.user_buffer),
                    addr_or_dash(irp.mdl_address)
                );
                if let Some(stack) = irp.current_stack().filter(|_| !entry.completed()) {
                    outln!(
                        "    stack location {}  FileObject {}  CompletionRoutine {}  Context {}",
                        ui::addr(stack.address.0),
                        addr_or_dash(stack.file_object),
                        kernel_symbol_or_dash(&repl.ctx.target, stack.completion_routine),
                        addr_or_dash(stack.context)
                    );
                }
                outln!(
                    "    OriginalFileObject {}",
                    addr_or_dash(entry.original_file_object)
                );
            }
        }
        outln!();
        let irps = detail.irps.len();
        let pages = detail.scanned_pages;
        outln!(
            "{irps} IRP{} in {pages} mapped page{}; big pool: {}",
            if irps == 1 { "" } else { "s" },
            if pages == 1 { "" } else { "s" },
            detail.big_pool_status
        );
        if let Some(restart) = detail.restart {
            outln!(
                "{}; resume with !irpfind {}{} {}{}",
                if detail.interrupted {
                    "interrupted"
                } else {
                    "stopped after 4096 IRPs"
                },
                if verbose { "-v " } else { "" },
                detail.pool.windbg(),
                ui::addr(restart.0),
                detail
                    .criteria
                    .map(|criteria| format!(" {} {:#x}", criteria.name(), criteria.value()))
                    .unwrap_or_default()
            );
        } else if detail.truncated {
            outln!("stopped after 4096 IRPs; big-pool IRPs past the bound are not listed");
        }
    }
}

/// An object namespace path (`\`, `\Driver\ACPI`), else an address
/// expression.
impl FromArg for ObjectName {
    const COMPLETION: CompletionStrategy = CompletionStrategy::Expression;

    fn from_arg(cx: &mut ArgCx<'_, '_>, text: &str) -> std::result::Result<Self, ArgError> {
        if text.starts_with('\\') {
            Ok(ObjectName::Path(text.to_string()))
        } else {
            cx.eval(text).map(ObjectName::Address)
        }
    }
}

/// Show an executive object header and body, and list the entries of a directory.
///
/// A path that starts with `\` is the name of an object in the object namespace
/// (`!object \`, `!object \Driver\ACPI`). The command looks up the path from
/// the root directory and ignores case. It does not follow symbolic links in
/// the path. For a directory, the command lists the entries and their types.
#[command(
    names = ["!object", "object"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    python = Inspect,
)]
fn object(
    session: &Session,
    #[arg(name = "path|object-expression")] object: ObjectName,
) -> Result<ObjectDetail> {
    let target = &session.target;
    target.inspect_object(target.object_address(&object)?)
}

impl Render for ObjectDetail {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        let o = &self.header;
        outln!("object {}", ui::addr(o.body.0));
        outln!("  input          {} ({})", ui::addr(o.input.0), o.mode);
        outln!("  header         {}", ui::addr(o.header.0));
        outln!("  pointer count  {}", o.pointer_count);
        outln!("  handle count   {}", o.handle_count);
        if let Some(ti) = o.type_index {
            outln!("  type index     {:#x}", ti);
        }
        if let Some(to) = o.type_object {
            outln!("  type object    {}", ui::addr(to.0));
        }
        if let Some(tn) = &o.type_name {
            outln!("  type name      {}", tn);
        }
        if let Some(mask) = o.info_mask {
            outln!("  info mask      {:#x}", mask);
        }
        if let Some(ni) = o.name_info {
            outln!("  name info      {}", ui::addr(ni.0));
        }
        if let Some(name) = &o.name {
            outln!("  name           {}", name);
        }
        if let Some(entries) = &self.entries {
            outln!("  entries        {}", entries.len());
            let mut builder = Builder::default();
            builder.push_record(["Object", "Type", "Name"]);
            for entry in entries {
                builder.push_record([
                    ui::addr(entry.object.0).to_string(),
                    entry.type_name.clone().unwrap_or_else(|| "-".to_string()),
                    entry.name.clone(),
                ]);
            }
            outln!();
            print_padded_table(builder);
        }
    }
}

/// List the process, thread, and image notification callbacks.
#[command(
    names = ["callbacks"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    python = Inspect,
)]
fn callbacks(
    session: &Session,
    #[arg(render, name = "symbol-filter", complete = Symbol)] filter: Option<String>,
) -> Result<Vec<NotifyCallback>> {
    session.target.enumerate_notify_callbacks()
}

/// `callbacks`: those whose symbol contains `filter`, by kind.
impl Render<Option<String>> for Vec<NotifyCallback> {
    fn render(&self, _: &mut ReplState<'_>, filter: Option<String>) {
        let lowered = filter.as_ref().map(|filter| filter.to_lowercase());
        let mut printed = 0;
        let mut last_kind = None;
        let mut builder: Option<Builder> = None;
        for c in self {
            let target = c
                .symbol
                .clone()
                .unwrap_or_else(|| format!("0x{:x}", c.function.0));
            if let Some(f) = &lowered
                && !target.to_lowercase().contains(f)
            {
                continue;
            }
            if last_kind != Some(c.kind) {
                if let Some(table) = builder.take() {
                    print_padded_table(table);
                }
                outln!("{}", ui::label(&format!("{} callbacks", c.kind)));
                let mut table = Builder::default();
                table.push_record(["#", "Function", "Block", "Raw", "Context"]);
                builder = Some(table);
                last_kind = Some(c.kind);
            }
            if let Some(table) = builder.as_mut() {
                table.push_record([
                    format!("{:02}", c.index),
                    c.symbol
                        .as_deref()
                        .map(ui::symbol)
                        .unwrap_or_else(|| ui::addr(c.function.0)),
                    ui::addr(c.block.0),
                    ui::addr(c.raw.0),
                    // For these notify routines the block's context holds
                    // the registration's flags (Ex, Ex2), a small value
                    // rather than a pointer.
                    format!("{:#x}", c.context.0),
                ]);
            }
            printed += 1;
        }
        if let Some(table) = builder {
            print_padded_table(table);
        }

        if printed == 0 {
            match filter {
                Some(f) => outln!("{}", ui::muted(&format!("no callbacks matching '{f}'"))),
                None => outln!("{}", ui::muted("no callbacks")),
            }
        }
    }
}

/// Show the SSDT and the shadow SSDT.
#[command(
    names = ["ssdt"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    python = Inspect
)]
fn ssdt(session: &Session) -> Result<Vec<SsdtTable>> {
    session.target.dump_ssdt()
}

/// Whether `module` is where a service table's entries belong: the kernel's
/// image for the native table, a win32k image for the shadow table.
fn ssdt_owner(module: &str, shadow: bool) -> bool {
    let starts = |prefix: &str| {
        module
            .get(..prefix.len())
            .is_some_and(|start| start.eq_ignore_ascii_case(prefix))
    };
    if shadow {
        starts("win32k")
    } else {
        module.eq_ignore_ascii_case("nt") || starts("ntoskrnl") || starts("ntkrnl")
    }
}

impl Render for Vec<SsdtTable> {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        for (i, t) in self.iter().enumerate() {
            if i > 0 {
                outln!();
            }
            outln!(
                "{}  base {}  limit {}",
                t.label,
                ui::addr(t.base.0),
                t.limit
            );
            let shadow = t.label.contains("win32k");
            let mut hooks = 0;
            for e in &t.entries {
                let display = e
                    .symbol
                    .as_deref()
                    .map(ui::symbol)
                    .unwrap_or_else(|| ui::addr(e.target.0));
                // A target in no module (pool shellcode) is as suspect as
                // one in the wrong module.
                let hooked = !e
                    .module
                    .as_deref()
                    .is_some_and(|module| ssdt_owner(module, shadow));
                let mark = if hooked {
                    hooks += 1;
                    "  [HOOK]".red().to_string()
                } else {
                    String::new()
                };
                outln!("  [{:4}] {}{}", e.index, display, mark);
            }
            if hooks > 0 {
                outln!(
                    "  {hooks} hook{} detected",
                    if hooks == 1 { "" } else { "s" }
                );
            }
        }
    }
}
