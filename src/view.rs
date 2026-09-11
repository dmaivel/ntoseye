use crate::bugchecks::{BugcheckAnalysis, BugcheckTrapFrame};
use crate::dmp::{DmpException, DmpSystemInfo, TriageCrashInfo, UnloadedDriver};
use crate::gdb::breakpoints::Breakpoint;
use crate::guest::{ModuleInfo, ProcessInfo};
use crate::session::RunStatus;
use crate::symbols::{
    LocalVariableLocation, ProcedureLocal, SourceLocation, SymbolCandidate, SymbolVisibility,
    format_symbol_with_offset,
};
use crate::target::{
    AddressDescription, AddressModule, DeviceObjectDetail, DiagnosticMetric, DiagnosticValue,
    DriverObjectDetail, FileObjectDetail, HandleEntryDetail, HandleTableSummary,
    IoStackLocationInfo, IrpHit, IrpInfo, ListTermination, MemoryRegionInfo, MemorySearchMatch,
    NotifyCallback, ObjectHeaderDetail, PrivilegeInfo, ProcessMemoryUsage, PteLevel,
    ResourceDetail, ResourceListSummary, ResourceOwner, SidAndAttributes, SsdtTable,
    SymbolSearchMatch, SystemMemorySummary, Target, TokenDetail, irp_major_function_name,
    kthread_state_name, wait_reason_name,
};
use crate::trapframe::KtrapFrame;
use crate::triage::TriagePrcbInfo;
use crate::triage_report::{
    BlackboxFinding, BlackboxKind, BlackboxState, CulpritAttribution, CulpritConfidence,
    CulpritEvidenceKind, FailureCodeKind, FailureSignature, FailureSignatureSource, TriageReport,
    VerifierFinding, WheaFinding, WheaRecordState, WheaSectionKind, exception_code_name,
    filetime_to_iso,
};
use crate::types::VirtAddr;
use crate::unwind::StackFrame;

// Shared shape for SDK/MCP structure rendering; surfaces disagree only on how
// address-like values are encoded.
/// A node in a neutral value tree.
pub enum View {
    /// An address/pointer/status: hex string for MCP, int for Python.
    Hex(u64),
    OptHex(Option<u64>),
    /// A plain count: a number on both surfaces.
    Num(u64),
    OptNum(Option<u64>),
    /// A signed count.
    Int(i64),
    Bool(bool),
    OptBool(Option<bool>),
    Str(String),
    OptStr(Option<String>),
    Null,
    List(Vec<View>),
    /// An ordered key/value object (insertion order is preserved on render).
    Object(Vec<(&'static str, View)>),
}

/// Render a [`View`] to JSON (MCP): addresses become `0x` hex strings.
#[cfg(feature = "mcp")]
pub fn to_json(v: &View) -> serde_json::Value {
    use serde_json::Value;
    match v {
        View::Hex(n) => Value::from(format!("{n:#x}")),
        View::OptHex(o) => o.map_or(Value::Null, |n| Value::from(format!("{n:#x}"))),
        View::Num(n) => Value::from(*n),
        View::OptNum(o) => o.map_or(Value::Null, Value::from),
        View::Int(n) => Value::from(*n),
        View::Bool(b) => Value::from(*b),
        View::OptBool(o) => o.map_or(Value::Null, Value::from),
        View::Str(s) => Value::from(s.clone()),
        View::OptStr(o) => o.clone().map_or(Value::Null, Value::from),
        View::Null => Value::Null,
        View::List(items) => Value::Array(items.iter().map(to_json).collect()),
        View::Object(fields) => {
            let mut map = serde_json::Map::new();
            for (key, val) in fields {
                map.insert((*key).to_string(), to_json(val));
            }
            Value::Object(map)
        }
    }
}

/// Render a [`View`] to a Python object (the SDK): addresses become plain ints.
#[cfg(feature = "python")]
pub fn to_py<'py>(
    py: pyo3::Python<'py>,
    v: &View,
) -> pyo3::PyResult<pyo3::Bound<'py, pyo3::PyAny>> {
    use pyo3::IntoPyObjectExt;
    use pyo3::prelude::*;
    use pyo3::types::{PyDict, PyList};
    Ok(match v {
        View::Hex(n) | View::Num(n) => n.into_bound_py_any(py)?,
        View::OptHex(o) | View::OptNum(o) => match o {
            Some(n) => n.into_bound_py_any(py)?,
            None => py.None().into_bound(py),
        },
        View::Int(n) => n.into_bound_py_any(py)?,
        View::Bool(b) => b.into_bound_py_any(py)?,
        View::OptBool(o) => match o {
            Some(b) => b.into_bound_py_any(py)?,
            None => py.None().into_bound(py),
        },
        View::Str(s) => s.as_str().into_bound_py_any(py)?,
        View::OptStr(o) => match o {
            Some(s) => s.as_str().into_bound_py_any(py)?,
            None => py.None().into_bound(py),
        },
        View::Null => py.None().into_bound(py),
        View::List(items) => {
            let list = PyList::empty(py);
            for item in items {
                list.append(to_py(py, item)?)?;
            }
            list.into_any()
        }
        View::Object(fields) => {
            let dict = PyDict::new(py);
            for (key, val) in fields {
                dict.set_item(key, to_py(py, val)?)?;
            }
            dict.into_any()
        }
    })
}

// --- builders: one decoded struct → its neutral shape ---

fn io_stack(s: &IoStackLocationInfo) -> View {
    View::Object(vec![
        ("address", View::Hex(s.address.0)),
        ("major_function", View::Num(s.major_function as u64)),
        (
            "major_function_name",
            View::Str(format!(
                "IRP_MJ_{}",
                irp_major_function_name(s.major_function)
            )),
        ),
        ("minor_function", View::Num(s.minor_function as u64)),
        ("device_object", View::Hex(s.device_object.0)),
        ("file_object", View::Hex(s.file_object.0)),
        ("completion_routine", View::Hex(s.completion_routine.0)),
        ("context", View::Hex(s.context.0)),
    ])
}

/// `_IRP` plus its current `_IO_STACK_LOCATION` (`current_stack` is null when the
/// stack slot is out of range or unreadable).
pub fn irp(irp: &IrpInfo) -> View {
    View::Object(vec![
        ("address", View::Hex(irp.address.0)),
        ("type", View::Num(irp.irp_type as u64)),
        ("size", View::Num(irp.size as u64)),
        ("stack_count", View::Num(irp.stack_count as u64)),
        ("current_location", View::Num(irp.current_location as u64)),
        ("pending_returned", View::Bool(irp.pending_returned)),
        ("requestor_mode", View::Num(irp.requestor_mode as u64)),
        ("io_status", View::OptHex(irp.io_status.map(|s| s as u64))),
        ("user_event", View::Hex(irp.user_event.0)),
        ("user_buffer", View::Hex(irp.user_buffer.0)),
        ("mdl_address", View::Hex(irp.mdl_address.0)),
        ("thread", View::Hex(irp.thread.0)),
        (
            "current_stack",
            irp.current_stack.as_ref().map_or(View::Null, io_stack),
        ),
    ])
}

/// `_DRIVER_OBJECT`: header fields, device chain, and the 28-entry `IRP_MJ_*`
/// dispatch table (each routine resolved to its nearest symbol).
pub fn driver_object(target: &Target, d: &DriverObjectDetail) -> View {
    let dtb = target.kernel_dtb();
    let devices = d
        .device_chain
        .iter()
        .map(|x| {
            View::Object(vec![
                ("device", View::Hex(x.device.0)),
                ("device_type", View::Num(x.device_type as u64)),
                ("flags", View::Num(x.flags as u64)),
                ("characteristics", View::Num(x.characteristics as u64)),
                ("attached", View::Hex(x.attached.0)),
                ("next", View::Hex(x.next.0)),
            ])
        })
        .collect();
    let dispatch = d
        .dispatch
        .iter()
        .enumerate()
        .map(|(i, f)| {
            View::Object(vec![
                ("index", View::Num(i as u64)),
                (
                    "name",
                    View::Str(format!("IRP_MJ_{}", irp_major_function_name(i as u8))),
                ),
                ("routine", View::Hex(f.0)),
                (
                    "symbol",
                    View::OptStr(target.symbols.format_closest_symbol_for_address(dtb, *f)),
                ),
            ])
        })
        .collect();
    View::Object(vec![
        ("object", View::Hex(d.object.0)),
        ("via_pointer", View::Bool(d.via_pointer)),
        ("name", View::OptStr(d.name.clone())),
        ("driver_start", View::Hex(d.driver_start.0)),
        ("driver_size", View::Num(d.driver_size)),
        ("driver_section", View::Hex(d.driver_section.0)),
        ("driver_unload", View::Hex(d.driver_unload.0)),
        ("devices", View::List(devices)),
        ("dispatch", View::List(dispatch)),
    ])
}

/// `_DEVICE_OBJECT` plus its `AttachedDevice` stack.
pub fn device_object(d: &DeviceObjectDetail) -> View {
    let stack = d
        .attached_stack
        .iter()
        .map(|x| {
            View::Object(vec![
                ("device", View::Hex(x.device.0)),
                ("driver_object", View::Hex(x.driver_object.0)),
                ("device_type", View::Num(x.device_type as u64)),
                ("flags", View::Num(x.flags as u64)),
            ])
        })
        .collect();
    View::Object(vec![
        ("object", View::Hex(d.object.0)),
        ("via_pointer", View::Bool(d.via_pointer)),
        ("device_type", View::Num(d.device_type as u64)),
        ("flags", View::Num(d.flags as u64)),
        ("characteristics", View::Num(d.characteristics as u64)),
        ("driver_object", View::Hex(d.driver_object.0)),
        ("attached_device", View::Hex(d.attached_device.0)),
        ("next_device", View::Hex(d.next_device.0)),
        ("current_irp", View::Hex(d.current_irp.0)),
        ("device_extension", View::Hex(d.device_extension.0)),
        ("attached_stack", View::List(stack)),
    ])
}

/// Executive `_OBJECT_HEADER` and the body it precedes.
pub fn object_header(o: &ObjectHeaderDetail) -> View {
    View::Object(vec![
        ("input", View::Hex(o.input.0)),
        ("mode", View::Str(o.mode.to_string())),
        ("header", View::Hex(o.header.0)),
        ("body", View::Hex(o.body.0)),
        ("pointer_count", View::Int(o.pointer_count)),
        ("handle_count", View::Int(o.handle_count)),
        ("type_index", View::OptNum(o.type_index)),
        ("type_object", View::OptHex(o.type_object.map(|t| t.0))),
        ("type_name", View::OptStr(o.type_name.clone())),
        ("info_mask", View::OptNum(o.info_mask.map(u64::from))),
        ("name_info", View::OptHex(o.name_info.map(|n| n.0))),
        ("name", View::OptStr(o.name.clone())),
    ])
}

/// One notification-callback row; `symbol` is resolved by the surface (it also
/// drives MCP's symbol filter) and passed in.
pub fn notify_callback(c: &NotifyCallback, symbol: Option<String>) -> View {
    View::Object(vec![
        ("kind", View::Str(c.kind.to_string())),
        ("index", View::Num(c.index as u64)),
        ("function", View::Hex(c.function.0)),
        ("symbol", View::OptStr(symbol)),
        ("block", View::Hex(c.block.0)),
        ("raw", View::Hex(c.raw.0)),
        ("context", View::Hex(c.context.0)),
    ])
}

/// One system-service table (the kernel SSDT or the win32k shadow).
pub fn ssdt_table(t: &SsdtTable) -> View {
    let entries = t
        .entries
        .iter()
        .map(|e| {
            View::Object(vec![
                ("index", View::Num(e.index as u64)),
                ("target", View::Hex(e.target.0)),
                ("symbol", View::OptStr(e.symbol.clone())),
                ("module", View::OptStr(e.module.clone())),
            ])
        })
        .collect();
    View::Object(vec![
        ("label", View::Str(t.label.clone())),
        ("base", View::Hex(t.base.0)),
        ("limit", View::Num(t.limit as u64)),
        ("entries", View::List(entries)),
    ])
}

/// One discovered in-flight IRP plus the context it was found in.
pub fn irp_hit(h: &IrpHit) -> View {
    View::Object(vec![
        ("irp", View::Hex(h.irp.0)),
        ("source", View::Str(h.source.to_string())),
        ("stack_count", View::Num(h.stack_count as u64)),
        ("current_location", View::Num(h.current_location as u64)),
        ("pid", View::OptNum(h.pid)),
        ("tid", View::OptNum(h.tid)),
        ("ethread", View::OptHex(h.ethread.map(|e| e.0))),
        (
            "state",
            View::OptStr(h.state.map(|s| kthread_state_name(s).to_string())),
        ),
        (
            "wait_reason",
            View::OptStr(h.wait_reason.map(|r| wait_reason_name(r).to_string())),
        ),
        ("driver", View::OptStr(h.driver.clone())),
        ("device", View::OptHex(h.device.map(|d| d.0))),
    ])
}

/// What an address belongs to (the loaded module/section, the process VAD
/// region, or nothing recognized).
fn address_module(m: &AddressModule) -> View {
    View::Object(vec![
        ("name", View::Str(m.name.clone())),
        ("base", View::Hex(m.base.0)),
        ("size", View::Num(m.size as u64)),
        ("offset", View::Hex(m.offset)),
    ])
}

fn memory_region(r: &MemoryRegionInfo) -> View {
    View::Object(vec![
        ("start", View::Hex(r.start.0)),
        ("end", View::Hex(r.end.0)),
        ("protection", View::OptNum(r.protection)),
        ("vad_type", View::OptNum(r.vad_type)),
        ("private_memory", View::OptBool(r.private_memory)),
        ("commit_charge", View::OptNum(r.commit_charge)),
        ("details", View::OptStr(r.details.clone())),
    ])
}

pub fn address_description(d: &AddressDescription) -> View {
    let module = d.module.as_ref().map_or(View::Null, address_module);
    let region = d.region.as_ref().map_or(View::Null, memory_region);
    View::Object(vec![
        ("address", View::Hex(d.address.0)),
        ("dtb", View::Hex(d.dtb)),
        ("kind", View::Str(d.kind.to_string())),
        ("module", module),
        ("section", View::OptStr(d.section.clone())),
        ("va_type", View::OptStr(d.va_type.clone())),
        ("region", region),
    ])
}

/// One structured memory-search hit.
pub fn memory_search_match(m: &MemorySearchMatch) -> View {
    let d = &m.description;
    View::Object(vec![
        ("address", View::Hex(m.address.0)),
        ("offset", View::Hex(m.offset)),
        ("symbol", View::OptStr(m.symbol.clone())),
        ("kind", View::Str(d.kind.to_string())),
        (
            "module",
            d.module.as_ref().map_or(View::Null, address_module),
        ),
        ("section", View::OptStr(d.section.clone())),
        ("va_type", View::OptStr(d.va_type.clone())),
        (
            "region",
            d.region.as_ref().map_or(View::Null, memory_region),
        ),
    ])
}

/// One page-table level (WinDbg-style flags).
pub fn pte_level(pte: &PteLevel) -> View {
    View::Object(vec![
        ("level", View::Str(pte.name.clone())),
        ("address", View::Hex(pte.address.0)),
        ("value", View::Hex(pte.value.0)),
        ("pfn", View::Hex(pte.value.pfn())),
        ("present", View::Bool(pte.value.is_present())),
        ("large_page", View::Bool(pte.value.is_large_page())),
        ("writable", View::Bool(pte.value.is_writable())),
        ("user", View::Bool(pte.value.is_user())),
        ("nx", View::Bool(pte.value.is_nx())),
        ("flags", View::Str(pte.value.flags())),
    ])
}

/// A decoded bugcheck (BSOD): code/name/description, its four parameters, and the
/// faulting instruction when one was identified.
pub fn bugcheck(a: &BugcheckAnalysis) -> View {
    let args = a
        .args
        .iter()
        .enumerate()
        .map(|(i, arg)| {
            View::Object(vec![
                ("index", View::Num((i + 1) as u64)),
                ("value", View::Hex(arg.value)),
                ("description", View::Str(arg.description.clone())),
            ])
        })
        .collect();
    let fault = a.fault.as_ref().map_or(View::Null, |f| {
        View::Object(vec![
            ("ip", View::Hex(f.ip)),
            ("symbol", View::Str(f.symbol.clone())),
            ("driver", View::OptStr(f.driver.clone())),
        ])
    });
    let trap_frames = a.trap_frames.iter().map(bugcheck_trap_frame).collect();
    View::Object(vec![
        ("code", View::Num(a.code as u64)),
        ("code_hex", View::Str(format!("{:#010x}", a.code))),
        ("name", View::Str(a.name.clone())),
        ("description", View::OptStr(a.description.clone())),
        ("driver", View::OptStr(a.driver.clone())),
        ("source", View::OptStr(a.source.clone())),
        ("args", View::List(args)),
        ("fault", fault),
        ("trap_frames", View::List(trap_frames)),
    ])
}

fn ktrap_frame_registers(frame: &KtrapFrame) -> View {
    View::Object(vec![
        ("rax", View::Hex(frame.rax)),
        ("rbx", View::Hex(frame.rbx)),
        ("rcx", View::Hex(frame.rcx)),
        ("rdx", View::Hex(frame.rdx)),
        ("rsi", View::Hex(frame.rsi)),
        ("rdi", View::Hex(frame.rdi)),
        ("rbp", View::Hex(frame.rbp)),
        ("rsp", View::Hex(frame.rsp)),
        ("r8", View::Hex(frame.r8)),
        ("r9", View::Hex(frame.r9)),
        ("r10", View::Hex(frame.r10)),
        ("r11", View::Hex(frame.r11)),
        ("rip", View::Hex(frame.rip)),
        ("cs", View::Hex(frame.cs as u64)),
        ("ss", View::Hex(frame.ss as u64)),
        ("eflags", View::Hex(frame.eflags as u64)),
        ("error_code", View::Hex(frame.error_code)),
        ("previous_mode", View::Num(frame.previous_mode as u64)),
        ("previous_irql", View::Num(frame.previous_irql as u64)),
    ])
}

/// A decoded `_KTRAP_FRAME` shared by structured host APIs.
pub fn trap_frame(frame: &KtrapFrame, rip_symbol: Option<String>) -> View {
    View::Object(vec![
        ("address", View::Hex(frame.address)),
        ("rip_symbol", View::OptStr(rip_symbol)),
        ("frame", ktrap_frame_registers(frame)),
    ])
}

/// A trap frame carried by a bugcheck parameter: its address, the symbol at
/// the interrupted `rip`, and either the decoded `_KTRAP_FRAME` registers or
/// the reason decoding failed.
pub fn bugcheck_trap_frame(tf: &BugcheckTrapFrame) -> View {
    View::Object(vec![
        ("address", View::Hex(tf.address)),
        ("rip_symbol", View::OptStr(tf.rip_symbol.clone())),
        (
            "frame",
            tf.frame.as_ref().map_or(View::Null, ktrap_frame_registers),
        ),
        ("error", View::OptStr(tf.error.clone())),
    ])
}

/// One code-breakpoint/data-watchpoint row. `address` is null while a symbolic
/// or source breakpoint is deferred; `resolved` distinguishes that state from a
/// deliberately disabled breakpoint.
pub fn breakpoint(bp: &Breakpoint) -> View {
    View::Object(vec![
        ("id", View::Num(bp.id.into())),
        (
            "address",
            View::OptHex(bp.resolved_address().map(|address| address.0)),
        ),
        ("enabled", View::Bool(bp.enabled)),
        ("resolved", View::Bool(bp.resolved)),
        ("deferred", View::Bool(bp.deferred())),
        (
            "specification",
            View::OptStr(bp.specification().map(str::to_string)),
        ),
        ("symbol", View::OptStr(bp.symbol.clone())),
        ("scope", View::Str(bp.scope.label())),
        ("condition", View::OptStr(bp.condition.clone())),
        ("pass_count", View::Num(bp.pass_count)),
        ("hit_count", View::Num(bp.hit_count)),
        ("remaining_pass_count", View::Num(bp.remaining_pass_count)),
        ("one_shot", View::Bool(bp.one_shot)),
        ("action", View::OptStr(bp.action.clone())),
        ("temporary", View::Bool(bp.temporary)),
        (
            "watch_access",
            View::OptStr(bp.watch_access_name().map(str::to_string)),
        ),
        (
            "watch_length",
            View::OptNum(bp.watch_length().map(u64::from)),
        ),
    ])
}

pub fn run_status(status: &RunStatus) -> View {
    let process = status
        .process
        .as_ref()
        .map(|(pid, name, eprocess)| {
            View::Object(vec![
                ("pid", View::Num(*pid)),
                ("name", View::Str(name.clone())),
                ("eprocess", View::Hex(*eprocess)),
            ])
        })
        .unwrap_or(View::Null);
    View::Object(vec![
        ("running", View::Bool(status.running)),
        ("current_thread", View::Str(status.current_thread.clone())),
        ("rip", View::OptHex(status.rip)),
        ("symbol", View::OptStr(status.symbol.clone())),
        ("process", process),
        ("coherent", View::Bool(status.coherent)),
        ("kernel_base", View::Hex(status.kernel_base)),
    ])
}

pub fn stack_frame(frame: &StackFrame) -> View {
    View::Object(vec![
        ("ip", View::Hex(frame.ip)),
        ("sp", View::Hex(frame.sp)),
        ("symbol", View::Str(frame.symbol.clone())),
        ("source", View::Str(frame.source.as_str().to_string())),
    ])
}

pub fn module(module: &ModuleInfo) -> View {
    let mut fields = vec![
        ("name", View::Str(module.name.clone())),
        ("short_name", View::Str(module.short_name.clone())),
        ("base", View::Hex(module.base_address.0)),
        ("end", View::Hex(module.end_address().0)),
        ("size", View::Num(module.size.into())),
    ];
    if let Some(timestamp) = module.time_date_stamp {
        fields.push(("time_date_stamp", View::Hex(timestamp.into())));
    }
    if let Some(checksum) = module.checksum {
        fields.push(("checksum", View::Hex(checksum.into())));
    }
    if let Some(version) = &module.file_version {
        fields.push(("file_version", View::Str(version.clone())));
    }
    if let Some(version) = &module.product_version {
        fields.push(("product_version", View::Str(version.clone())));
    }
    View::Object(fields)
}

pub fn dump_exception(exception: &DmpException) -> View {
    View::Object(vec![
        ("code", View::Num(exception.code.into())),
        ("code_hex", View::Hex(exception.code.into())),
        (
            "code_name",
            View::Str(exception_code_name(exception.code).to_string()),
        ),
        ("flags", View::Num(exception.flags.into())),
        ("address", View::Hex(exception.address)),
        (
            "parameters",
            View::List(
                exception
                    .parameters
                    .iter()
                    .copied()
                    .map(View::Hex)
                    .collect(),
            ),
        ),
    ])
}

pub fn system_info(info: &DmpSystemInfo) -> View {
    let product = match info.product_type {
        1 => "Workstation",
        2 => "DomainController",
        3 => "Server",
        _ => "Unknown",
    };
    let machine = match info.machine_image_type {
        0x014c => "I386",
        0x8664 => "AMD64",
        0xAA64 => "ARM64",
        _ => "Unknown",
    };
    View::Object(vec![
        ("major_version", View::Num(info.major_version.into())),
        ("build", View::Num(info.minor_version.into())),
        (
            "service_pack_build",
            View::Num(info.service_pack_build.into()),
        ),
        (
            "machine_image_type",
            View::Hex(info.machine_image_type.into()),
        ),
        ("machine", View::Str(machine.to_string())),
        (
            "system_time",
            View::OptStr(
                (info.system_time != 0)
                    .then(|| filetime_to_iso(info.system_time as u64))
                    .flatten(),
            ),
        ),
        (
            "system_up_time_secs",
            View::OptNum(
                (info.system_up_time > 0)
                    .then(|| u64::try_from(info.system_up_time / 10_000_000).ok())
                    .flatten(),
            ),
        ),
        ("product_type", View::Str(product.to_string())),
        ("suite_mask", View::Hex(info.suite_mask.into())),
    ])
}

pub fn crash_context(context: &TriageCrashInfo) -> View {
    let mut fields = vec![
        ("process_name", View::OptStr(context.process_name.clone())),
        ("process_id", View::OptNum(context.process_id)),
        ("thread_id", View::OptNum(context.thread_id)),
    ];
    if let Some(parent_process_id) = context.parent_process_id {
        fields.push(("parent_process_id", View::Num(parent_process_id)));
    }
    if let Some(exit_status) = context.exit_status {
        fields.push(("exit_status", View::Hex(exit_status as u64)));
    }
    if let Some(create_time) = context.create_time {
        fields.push(("create_time", View::OptStr(filetime_to_iso(create_time))));
    }
    if let Some(exit_status) = context.thread_exit_status {
        fields.push(("thread_exit_status", View::Hex(exit_status as u64)));
    }
    View::Object(fields)
}

pub fn prcb(prcb: &TriagePrcbInfo) -> View {
    View::Object(vec![
        ("current_thread", View::Hex(prcb.current_thread)),
        ("processor_number", View::Num(prcb.processor_number.into())),
        ("mhz", View::Num(prcb.mhz.into())),
        ("cpu_type", View::Num(prcb.cpu_type.into())),
        ("vendor_string", View::Str(prcb.vendor_string.clone())),
    ])
}

fn failure_signature(signature: &FailureSignature) -> View {
    let code_kind = match signature.code_kind {
        FailureCodeKind::Bugcheck => "bugcheck",
        FailureCodeKind::Exception => "exception",
    };
    let source = match signature.source {
        FailureSignatureSource::BugcheckFault => "bugcheck_fault",
        FailureSignatureSource::ExceptionAddress => "exception_address",
        FailureSignatureSource::CurrentInstruction => "current_instruction",
        FailureSignatureSource::TopFrame => "top_frame",
        FailureSignatureSource::CodeOnly => "code_only",
    };
    View::Object(vec![
        ("code_kind", View::Str(code_kind.to_string())),
        ("code", View::Hex(signature.code.into())),
        ("source", View::Str(source.to_string())),
        ("module", View::OptStr(signature.module.clone())),
        ("symbol", View::OptStr(signature.symbol.clone())),
        (
            "components",
            View::List(
                signature
                    .components
                    .iter()
                    .cloned()
                    .map(View::Str)
                    .collect(),
            ),
        ),
        ("bucket", View::Str(signature.bucket.clone())),
    ])
}

fn culprit(culprit: &CulpritAttribution) -> View {
    let confidence = match culprit.confidence {
        CulpritConfidence::Low => "low",
        CulpritConfidence::Medium => "medium",
        CulpritConfidence::High => "high",
    };
    View::Object(vec![
        ("module", View::Str(culprit.module.clone())),
        ("confidence", View::Str(confidence.to_string())),
        (
            "evidence",
            View::List(
                culprit
                    .evidence
                    .iter()
                    .map(|evidence| {
                        let kind = match evidence.kind {
                            CulpritEvidenceKind::RecordedBrokenDriver => "recorded_broken_driver",
                            CulpritEvidenceKind::RecordedBugcheckDriver => {
                                "recorded_bugcheck_driver"
                            }
                            CulpritEvidenceKind::BugcheckFaultAddress => "bugcheck_fault_address",
                            CulpritEvidenceKind::ExceptionAddress => "exception_address",
                            CulpritEvidenceKind::CurrentInstruction => "current_instruction",
                            CulpritEvidenceKind::TopFrame => "top_frame",
                        };
                        View::Object(vec![
                            ("kind", View::Str(kind.to_string())),
                            ("detail", View::Str(evidence.detail.clone())),
                            ("address", View::OptHex(evidence.address)),
                        ])
                    })
                    .collect(),
            ),
        ),
    ])
}

fn verifier(verifier: &VerifierFinding) -> View {
    View::Object(vec![
        ("bugcheck_code", View::Hex(verifier.bugcheck_code.into())),
        ("bugcheck_name", View::Str(verifier.bugcheck_name.clone())),
        ("subcode", View::Hex(verifier.subcode)),
        ("known_subcode", View::Bool(verifier.known_subcode)),
        (
            "subcode_description",
            View::Str(verifier.subcode_description.clone()),
        ),
        (
            "associated_driver",
            View::OptStr(verifier.associated_driver.clone()),
        ),
        (
            "arguments",
            View::List(
                verifier
                    .arguments
                    .iter()
                    .map(|argument| {
                        View::Object(vec![
                            ("value", View::Hex(argument.value)),
                            ("description", View::Str(argument.description.clone())),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "addresses",
            View::List(
                verifier
                    .addresses
                    .iter()
                    .map(|address| {
                        View::Object(vec![
                            ("role", View::Str(address.role.clone())),
                            ("address", View::Hex(address.address)),
                        ])
                    })
                    .collect(),
            ),
        ),
    ])
}

fn whea(whea: &WheaFinding) -> View {
    const SECTION_LIMIT: usize = 64;
    match &whea.state {
        WheaRecordState::Unavailable { reason } => View::Object(vec![
            ("record_address", View::OptHex(whea.record_address)),
            ("available", View::Bool(false)),
            ("reason", View::Str(reason.clone())),
        ]),
        WheaRecordState::Decoded(record) => View::Object(vec![
            ("record_address", View::OptHex(whea.record_address)),
            ("available", View::Bool(true)),
            ("revision", View::Hex(record.revision.into())),
            ("severity", View::Num(record.severity.into())),
            ("length", View::Num(record.length.into())),
            ("sections_total", View::Num(record.sections.len() as u64)),
            (
                "sections",
                View::List(
                    record
                        .sections
                        .iter()
                        .take(SECTION_LIMIT)
                        .map(|section| {
                            let kind = match section.kind {
                                WheaSectionKind::ProcessorGeneric => "processor_generic",
                                WheaSectionKind::Memory => "memory",
                                WheaSectionKind::PciExpress => "pci_express",
                                WheaSectionKind::X64Processor => "x64_processor",
                                WheaSectionKind::Unknown => "unknown",
                            };
                            View::Object(vec![
                                ("offset", View::Num(section.offset.into())),
                                ("length", View::Num(section.length.into())),
                                ("severity", View::Num(section.severity.into())),
                                ("section_type", View::Str(section.section_type.clone())),
                                ("kind", View::Str(kind.to_string())),
                            ])
                        })
                        .collect(),
                ),
            ),
        ]),
    }
}

fn blackbox(blackbox: &BlackboxFinding) -> View {
    let kind = match blackbox.kind {
        BlackboxKind::Pnp => "pnp",
        BlackboxKind::Ntfs => "ntfs",
        BlackboxKind::Bsd => "bsd",
        BlackboxKind::Winlogon => "winlogon",
    };
    let (present, reason) = match &blackbox.state {
        BlackboxState::Unavailable { reason } => (None, reason.clone()),
        BlackboxState::PresentUnparsed => (
            Some(true),
            "stream payload is not exposed by the dump parser".to_string(),
        ),
    };
    View::Object(vec![
        ("kind", View::Str(kind.to_string())),
        ("name", View::Str(blackbox.name.clone())),
        ("size", View::OptNum(blackbox.size)),
        ("present", View::OptBool(present)),
        ("available", View::Bool(false)),
        ("parsed", View::Bool(false)),
        ("reason", View::Str(reason)),
    ])
}

fn unloaded_driver(driver: &UnloadedDriver) -> View {
    View::Object(vec![
        ("name", View::Str(driver.name.clone())),
        ("start_address", View::Hex(driver.start_address)),
        ("end_address", View::Hex(driver.end_address)),
    ])
}

/// Canonical structured crash-triage shape used by MCP and Python. The caller
/// chooses its module cap; all other collections are already bounded by the
/// presentation-free report builder.
pub fn triage_report(report: &TriageReport, module_limit: usize) -> View {
    View::Object(vec![
        ("status", run_status(&report.status)),
        (
            "bugcheck",
            report.bugcheck.as_ref().map(bugcheck).unwrap_or(View::Null),
        ),
        (
            "exception",
            report
                .exception
                .as_ref()
                .map(dump_exception)
                .unwrap_or(View::Null),
        ),
        (
            "system_info",
            report
                .system_info
                .as_ref()
                .map(system_info)
                .unwrap_or(View::Null),
        ),
        (
            "backtrace",
            report
                .backtrace
                .as_ref()
                .map(|trace| View::List(trace.frames.iter().map(stack_frame).collect()))
                .unwrap_or(View::Null),
        ),
        (
            "modules",
            View::List(
                report
                    .modules
                    .iter()
                    .take(module_limit)
                    .map(module)
                    .collect(),
            ),
        ),
        ("modules_total", View::Num(report.modules.len() as u64)),
        (
            "unloaded_drivers",
            View::List(
                report
                    .unloaded_drivers
                    .iter()
                    .map(unloaded_driver)
                    .collect(),
            ),
        ),
        (
            "crash_context",
            report
                .crash_context
                .as_ref()
                .map(crash_context)
                .unwrap_or(View::Null),
        ),
        ("prcb", report.prcb.as_ref().map(prcb).unwrap_or(View::Null)),
        ("broken_driver", View::OptStr(report.broken_driver.clone())),
        ("triage_overflowed", View::OptBool(report.triage_overflowed)),
        (
            "failure_signature",
            report
                .failure_signature
                .as_ref()
                .map(failure_signature)
                .unwrap_or(View::Null),
        ),
        (
            "culprit",
            report.culprit.as_ref().map(culprit).unwrap_or(View::Null),
        ),
        (
            "verifier",
            report.verifier.as_ref().map(verifier).unwrap_or(View::Null),
        ),
        ("whea", report.whea.as_ref().map(whea).unwrap_or(View::Null)),
        (
            "blackboxes",
            View::List(report.blackboxes.iter().map(blackbox).collect()),
        ),
        (
            "warnings",
            View::List(
                report
                    .warnings
                    .iter()
                    .map(|warning| View::Str(warning.clone()))
                    .collect(),
            ),
        ),
    ])
}

pub fn symbol_candidate(candidate: &SymbolCandidate) -> View {
    View::Object(vec![
        ("module", View::Str(candidate.module.clone())),
        ("address", View::Hex(candidate.address.0)),
        (
            "visibility",
            View::Str(
                match candidate.visibility {
                    SymbolVisibility::Public => "public",
                    SymbolVisibility::Private => "private",
                }
                .to_string(),
            ),
        ),
        ("compiland", View::OptStr(candidate.compiland.clone())),
    ])
}

pub fn symbol_search_match(symbol: &SymbolSearchMatch) -> View {
    View::Object(vec![
        ("name", View::Str(symbol.name.clone())),
        (
            "address",
            View::OptHex(symbol.address.map(|address| address.0)),
        ),
        ("module", View::OptStr(symbol.module.clone())),
    ])
}

pub fn nearest_symbol(address: VirtAddr, symbol: Option<(String, String, u32)>) -> View {
    let (formatted, module, name, offset) = match symbol {
        Some((module, name, offset)) => (
            View::Str(format_symbol_with_offset(&module, &name, offset)),
            View::Str(module),
            View::Str(name),
            View::Num(offset.into()),
        ),
        None => (View::Null, View::Null, View::Null, View::Null),
    };
    View::Object(vec![
        ("address", View::Hex(address.0)),
        ("symbol", formatted),
        ("module", module),
        ("name", name),
        ("offset", offset),
    ])
}

pub fn source_location(location: &SourceLocation) -> View {
    View::Object(vec![
        ("file", View::Str(location.file.clone())),
        ("line", View::Num(location.line.into())),
        ("column", View::OptNum(location.column.map(u64::from))),
        (
            "local_path",
            View::OptStr(
                location
                    .local_path
                    .as_ref()
                    .map(|path| path.display().to_string()),
            ),
        ),
        ("local_exists", View::Bool(location.local_exists)),
    ])
}

fn local_location(location: &LocalVariableLocation) -> View {
    let (kind, register, offset, reason) = match location {
        LocalVariableLocation::Register { register } => {
            ("register", Some(register.clone()), None, None)
        }
        LocalVariableLocation::RegisterRelative { register, offset } => (
            "register_relative",
            Some(register.clone()),
            Some(i64::from(*offset)),
            None,
        ),
        LocalVariableLocation::FrameRelative { offset } => {
            ("frame_relative", None, Some(i64::from(*offset)), None)
        }
        LocalVariableLocation::Unavailable { reason } => {
            ("unavailable", None, None, Some(reason.clone()))
        }
    };
    View::Object(vec![
        ("kind", View::Str(kind.to_string())),
        ("register", View::OptStr(register)),
        ("offset", offset.map(View::Int).unwrap_or(View::Null)),
        ("reason", View::OptStr(reason)),
    ])
}

pub fn procedure_local(target: &Target, address: VirtAddr, local: &ProcedureLocal) -> View {
    View::Object(vec![
        ("name", View::Str(local.name.clone())),
        ("type_name", View::Str(local.type_name.clone())),
        ("byte_size", View::OptNum(local.byte_size)),
        ("parameter", View::Bool(local.is_parameter)),
        ("location", local_location(&local.location)),
        (
            "value",
            View::OptHex(target.resolve_procedure_local_value(address, local)),
        ),
    ])
}

fn diagnostic<T>(value: &DiagnosticValue<T>, encode: impl FnOnce(&T) -> View) -> View {
    match value {
        DiagnosticValue::Available(value) => View::Object(vec![
            ("available", View::Bool(true)),
            ("value", encode(value)),
            ("error", View::Null),
        ]),
        DiagnosticValue::Unavailable(error) => View::Object(vec![
            ("available", View::Bool(false)),
            ("value", View::Null),
            ("error", View::Str(error.clone())),
        ]),
    }
}

fn diagnostic_metric<T>(metric: &DiagnosticMetric<T>, encode: impl FnOnce(&T) -> View) -> View {
    let mut fields = match diagnostic(&metric.value, encode) {
        View::Object(fields) => fields,
        _ => unreachable!(),
    };
    fields.push((
        "source",
        View::OptStr(metric.source.map(|source| source.to_string())),
    ));
    View::Object(fields)
}

fn process(process: &ProcessInfo) -> View {
    View::Object(vec![
        ("pid", View::Num(process.pid)),
        ("name", View::Str(process.name.clone())),
        ("dtb", View::Hex(process.dtb)),
        ("eprocess", View::Hex(process.eprocess_va.0)),
    ])
}

pub fn handle_entry(entry: &HandleEntryDetail) -> View {
    View::Object(vec![
        ("handle", View::Hex(entry.handle)),
        ("entry", View::Hex(entry.entry.0)),
        (
            "object",
            diagnostic(&entry.object, |address| View::Hex(address.0)),
        ),
        (
            "type_name",
            diagnostic(&entry.type_name, |name| View::OptStr(name.clone())),
        ),
        (
            "name",
            diagnostic(&entry.name, |name| View::OptStr(name.clone())),
        ),
        (
            "granted_access",
            diagnostic(&entry.granted_access, |access| View::Hex((*access).into())),
        ),
        (
            "attributes",
            diagnostic(&entry.attributes, |attributes| {
                View::Hex((*attributes).into())
            }),
        ),
    ])
}

pub fn handle_table(summary: &HandleTableSummary) -> View {
    View::Object(vec![
        ("process", process(&summary.process)),
        ("table", View::Hex(summary.table.0)),
        ("table_level", View::Num(summary.table_level.into())),
        (
            "advertised_handles",
            View::Num(summary.advertised_handles as u64),
        ),
        ("scanned_handles", View::Num(summary.scanned_handles as u64)),
        ("skipped_entries", View::Num(summary.skipped_entries as u64)),
        ("truncated", View::Bool(summary.truncated)),
        (
            "entries",
            View::List(summary.entries.iter().map(handle_entry).collect()),
        ),
    ])
}

fn sid_and_attributes(sid: &SidAndAttributes) -> View {
    View::Object(vec![
        ("sid", View::Str(sid.sid.clone())),
        ("attributes", View::Hex(sid.attributes.into())),
    ])
}

fn privilege(privilege: &PrivilegeInfo) -> View {
    View::Object(vec![
        ("luid", View::Hex(privilege.luid)),
        ("attributes", View::Hex(privilege.attributes.into())),
    ])
}

pub fn token(token: &TokenDetail) -> View {
    View::Object(vec![
        ("process", process(&token.process)),
        ("token", View::Hex(token.token.0)),
        (
            "token_id",
            diagnostic(&token.token_id, |value| View::Hex(*value)),
        ),
        (
            "authentication_id",
            diagnostic(&token.authentication_id, |value| View::Hex(*value)),
        ),
        (
            "token_type",
            diagnostic(&token.token_type, |value| View::Num((*value).into())),
        ),
        (
            "impersonation_level",
            diagnostic(&token.impersonation_level, |value| {
                View::Num((*value).into())
            }),
        ),
        (
            "flags",
            diagnostic(&token.flags, |value| View::Hex((*value).into())),
        ),
        (
            "user",
            diagnostic(&token.user, |user| {
                user.as_ref().map(sid_and_attributes).unwrap_or(View::Null)
            }),
        ),
        (
            "groups",
            diagnostic(&token.groups, |groups| {
                View::List(groups.iter().map(sid_and_attributes).collect())
            }),
        ),
        (
            "privileges",
            diagnostic(&token.privileges, |privileges| {
                View::List(privileges.iter().map(privilege).collect())
            }),
        ),
    ])
}

pub fn file_object(file: &FileObjectDetail) -> View {
    View::Object(vec![
        ("address", View::Hex(file.address.0)),
        (
            "file_type",
            diagnostic(&file.file_type, |value| View::Int((*value).into())),
        ),
        (
            "size",
            diagnostic(&file.size, |value| View::Int((*value).into())),
        ),
        (
            "device_object",
            diagnostic(&file.device_object, |value| View::Hex(value.0)),
        ),
        (
            "device_type",
            diagnostic(&file.device_type, |value| View::Hex((*value).into())),
        ),
        (
            "device_name",
            diagnostic(&file.device_name, |value| View::OptStr(value.clone())),
        ),
        (
            "file_name",
            diagnostic(&file.file_name, |value| View::Str(value.clone())),
        ),
        (
            "related_file_object",
            diagnostic(&file.related_file_object, |value| View::Hex(value.0)),
        ),
        (
            "flags",
            diagnostic(&file.flags, |value| View::Hex((*value).into())),
        ),
        (
            "current_byte_offset",
            diagnostic(&file.current_byte_offset, |value| View::Int(*value)),
        ),
        (
            "fs_context",
            diagnostic(&file.fs_context, |value| View::Hex(value.0)),
        ),
        (
            "fs_context2",
            diagnostic(&file.fs_context2, |value| View::Hex(value.0)),
        ),
        (
            "section_object_pointer",
            diagnostic(&file.section_object_pointer, |value| View::Hex(value.0)),
        ),
        (
            "private_cache_map",
            diagnostic(&file.private_cache_map, |value| View::Hex(value.0)),
        ),
        (
            "final_status",
            diagnostic(&file.final_status, |value| View::Hex(*value as u32 as u64)),
        ),
        (
            "lock_operation",
            diagnostic(&file.lock_operation, |value| View::Bool(*value)),
        ),
        (
            "delete_pending",
            diagnostic(&file.delete_pending, |value| View::Bool(*value)),
        ),
        (
            "read_access",
            diagnostic(&file.read_access, |value| View::Bool(*value)),
        ),
        (
            "write_access",
            diagnostic(&file.write_access, |value| View::Bool(*value)),
        ),
        (
            "delete_access",
            diagnostic(&file.delete_access, |value| View::Bool(*value)),
        ),
        (
            "shared_read",
            diagnostic(&file.shared_read, |value| View::Bool(*value)),
        ),
        (
            "shared_write",
            diagnostic(&file.shared_write, |value| View::Bool(*value)),
        ),
        (
            "shared_delete",
            diagnostic(&file.shared_delete, |value| View::Bool(*value)),
        ),
    ])
}

fn resource_owner(owner: &ResourceOwner) -> View {
    View::Object(vec![
        ("thread", View::Hex(owner.thread.0)),
        ("count", View::Int(owner.count.into())),
    ])
}

pub fn resource(resource: &ResourceDetail) -> View {
    View::Object(vec![
        ("address", View::Hex(resource.address.0)),
        (
            "active_count",
            diagnostic(&resource.active_count, |value| View::Int((*value).into())),
        ),
        (
            "flags",
            diagnostic(&resource.flags, |value| View::Hex((*value).into())),
        ),
        (
            "contention_count",
            diagnostic(&resource.contention_count, |value| {
                View::Num((*value).into())
            }),
        ),
        (
            "shared_waiters",
            diagnostic(&resource.shared_waiters, |value| View::Num((*value).into())),
        ),
        (
            "exclusive_waiters",
            diagnostic(&resource.exclusive_waiters, |value| {
                View::Num((*value).into())
            }),
        ),
        (
            "owners",
            diagnostic(&resource.owners, |owners| {
                View::List(owners.iter().map(resource_owner).collect())
            }),
        ),
    ])
}

fn list_termination(termination: &ListTermination) -> View {
    let (kind, address, error) = match termination {
        ListTermination::Head => ("head", None, None),
        ListTermination::Null => ("null", None, None),
        ListTermination::Cycle(address) => ("cycle", Some(address.0), None),
        ListTermination::Bound => ("bound", None, None),
        ListTermination::Corrupt(error) => ("corrupt", None, Some(error.clone())),
    };
    View::Object(vec![
        ("kind", View::Str(kind.to_string())),
        ("address", View::OptHex(address)),
        ("error", View::OptStr(error)),
    ])
}

pub fn resource_list(summary: &ResourceListSummary) -> View {
    View::Object(vec![
        ("head", View::Hex(summary.head.0)),
        (
            "resources",
            View::List(summary.resources.iter().map(resource).collect()),
        ),
        ("termination", list_termination(&summary.termination)),
    ])
}

fn process_memory_usage(usage: &ProcessMemoryUsage) -> View {
    View::Object(vec![
        ("process", process(&usage.process)),
        (
            "virtual_size",
            diagnostic(&usage.virtual_size, |value| View::Num(*value)),
        ),
        (
            "peak_virtual_size",
            diagnostic(&usage.peak_virtual_size, |value| View::Num(*value)),
        ),
        (
            "working_set_size",
            diagnostic(&usage.working_set_size, |value| View::Num(*value)),
        ),
        (
            "peak_working_set_size",
            diagnostic(&usage.peak_working_set_size, |value| View::Num(*value)),
        ),
        (
            "pagefile_usage",
            diagnostic(&usage.pagefile_usage, |value| View::Num(*value)),
        ),
        (
            "peak_pagefile_usage",
            diagnostic(&usage.peak_pagefile_usage, |value| View::Num(*value)),
        ),
        (
            "private_usage",
            diagnostic(&usage.private_usage, |value| View::Num(*value)),
        ),
    ])
}

pub fn memory_usage(summary: &SystemMemorySummary) -> View {
    View::Object(vec![
        (
            "physical_pages",
            diagnostic_metric(&summary.physical_pages, |value| View::Num(*value)),
        ),
        (
            "available_pages",
            diagnostic_metric(&summary.available_pages, |value| View::Num(*value)),
        ),
        (
            "committed_pages",
            diagnostic_metric(&summary.committed_pages, |value| View::Num(*value)),
        ),
        (
            "commit_limit_pages",
            diagnostic_metric(&summary.commit_limit_pages, |value| View::Num(*value)),
        ),
        (
            "paged_pool_pages",
            diagnostic_metric(&summary.paged_pool_pages, |value| View::Num(*value)),
        ),
        (
            "nonpaged_pool_bytes",
            diagnostic_metric(&summary.nonpaged_pool_bytes, |value| View::Num(*value)),
        ),
        (
            "processes",
            View::List(summary.processes.iter().map(process_memory_usage).collect()),
        ),
        ("process_count", View::Num(summary.process_count as u64)),
        ("truncated", View::Bool(summary.truncated)),
    ])
}

#[cfg(all(test, feature = "mcp"))]
mod tests {
    use super::{bugcheck_trap_frame, handle_table, memory_usage, to_json, trap_frame};
    use crate::bugchecks::BugcheckTrapFrame;
    use crate::debugger_data::MetadataSource;
    use crate::guest::ProcessInfo;
    use crate::target::{
        DiagnosticMetric, DiagnosticValue, HandleTableSummary, SystemMemorySummary,
    };
    use crate::trapframe::KtrapFrame;
    use crate::types::VirtAddr;

    #[test]
    fn bugcheck_trap_frame_exposes_decode_failure() {
        let view = bugcheck_trap_frame(&BugcheckTrapFrame {
            address: 0xffff_8000_1234_5000,
            frame: None,
            rip_symbol: None,
            error: Some("type `_KTRAP_FRAME` not found".to_string()),
        });
        let json = to_json(&view);
        assert!(json["frame"].is_null());
        assert_eq!(json["error"], "type `_KTRAP_FRAME` not found");
    }

    #[test]
    fn standalone_trap_frame_has_shared_structured_shape() {
        let frame = KtrapFrame {
            address: 0xffff_f800_1234_5000,
            rax: 1,
            rbx: 2,
            rcx: 3,
            rdx: 4,
            rsi: 5,
            rdi: 6,
            rbp: 7,
            rsp: 8,
            r8: 9,
            r9: 10,
            r10: 11,
            r11: 12,
            rip: 0xffff_f800_4321_1000,
            cs: 0x10,
            ss: 0x18,
            eflags: 0x202,
            error_code: 0,
            previous_mode: 0,
            previous_irql: 2,
        };
        let json = to_json(&trap_frame(&frame, Some("nt!KiDispatchException".into())));
        assert_eq!(json["address"], "0xfffff80012345000");
        assert_eq!(json["rip_symbol"], "nt!KiDispatchException");
        assert_eq!(json["frame"]["rip"], "0xfffff80043211000");
        assert_eq!(json["frame"]["previous_irql"], 2);
    }

    #[test]
    fn handle_table_view_exposes_skipped_entries() {
        let summary = HandleTableSummary {
            process: ProcessInfo {
                pid: 4,
                name: "System".into(),
                dtb: 0x1000,
                eprocess_va: VirtAddr(0xffff_8000_0000_1000),
            },
            table: VirtAddr(0xffff_8000_0000_2000),
            table_level: 1,
            advertised_handles: 64,
            scanned_handles: 32,
            skipped_entries: 3,
            truncated: true,
            entries: Vec::new(),
        };

        let json = to_json(&handle_table(&summary));
        assert_eq!(json["scanned_handles"], 32);
        assert_eq!(json["skipped_entries"], 3);
    }

    #[test]
    fn diagnostic_memory_view_retains_values_errors_and_provenance() {
        let available = DiagnosticMetric {
            value: DiagnosticValue::Available(0x1234),
            source: Some(MetadataSource::KernelSymbol),
        };
        let unavailable = DiagnosticMetric {
            value: DiagnosticValue::Unavailable("missing MmAvailablePages".into()),
            source: None,
        };
        let summary = SystemMemorySummary {
            physical_pages: available.clone(),
            available_pages: unavailable.clone(),
            committed_pages: available.clone(),
            commit_limit_pages: available.clone(),
            paged_pool_pages: available.clone(),
            nonpaged_pool_bytes: unavailable,
            processes: Vec::new(),
            process_count: 3,
            truncated: true,
        };

        let json = to_json(&memory_usage(&summary));
        assert_eq!(json["physical_pages"]["value"], 0x1234);
        assert_eq!(json["physical_pages"]["source"], "kernel symbol");
        assert_eq!(json["available_pages"]["available"], false);
        assert_eq!(json["available_pages"]["error"], "missing MmAvailablePages");
        assert_eq!(json["process_count"], 3);
        assert_eq!(json["truncated"], true);
    }
}
