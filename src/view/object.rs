//! Object- and I/O-manager [`View`](super::View) builders: IRPs, driver and
//! device objects, object headers, handles, file objects, executive
//! resources, notification callbacks, and service tables.

use super::process::process;
use super::{View, diagnostic, list_termination};
use crate::target::object::{
    DeviceObjectDetail, DriverObjectDetail, DriverObjectInfo, FileObjectDetail, HandleEntryDetail,
    HandleTableSummary, IoStackLocationInfo, IrpHit, IrpInfo, NotifyCallback, ObjectHeaderDetail,
    ResourceDetail, ResourceListSummary, ResourceOwner, SsdtTable,
};
use crate::target::{Target, irp_major_function_name, kthread_state_name, wait_reason_name};

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

/// A `_DRIVER_OBJECT` as enumerated from the object directory.
pub fn driver_object_info(driver: &DriverObjectInfo) -> View {
    View::Object(vec![
        ("name", View::Str(driver.name.clone())),
        ("object", View::Hex(driver.object.0)),
        ("driver_start", View::Hex(driver.driver_start.0)),
        ("driver_size", View::Num(driver.driver_size)),
        ("device_object", View::Hex(driver.device_object.0)),
        ("driver_unload", View::Hex(driver.driver_unload.0)),
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
