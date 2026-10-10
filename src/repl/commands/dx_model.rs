//! The objects of WinDbg's debugger data model that `dx` reads:
//! `Debugger`, `@$cursession`, `@$curprocess`, and `@$curthread`, their
//! sessions, processes, threads, modules, and handles, indexed as WinDbg
//! indexes them, `Debugger.Utility.Collections`, and the values a query
//! makes (numbers, strings, lists, and `new { ... }` objects). A
//! `KernelObject` property is the typed `_EPROCESS` or `_ETHREAD`, which
//! `dx` reads on as a typed expression. `dx_query` evaluates the language
//! over these objects.

use crate::error::{Error, Result};
use crate::guest::{ModuleInfo, ProcessInfo};
use crate::target::object::HandleEntryDetail;
use crate::target::{DiagnosticValue, Target, ThreadInfo};
use crate::types::VirtAddr;

/// A data model value.
#[derive(Clone)]
pub enum ModelValue {
    Debugger,
    Sessions,
    Session,
    Processes,
    Process(ProcessInfo),
    Threads(ProcessInfo),
    Thread(ThreadInfo),
    Modules(ProcessInfo),
    Module(ModuleInfo),
    /// A process's `Io`, which holds its `Handles`.
    Io(ProcessInfo),
    Handles(ProcessInfo),
    Handle(Box<HandleEntryDetail>),
    /// A handle's `Object`: its `_OBJECT_HEADER`, with the object type's
    /// name.
    ObjectHeader {
        header: VirtAddr,
        kind: Option<String>,
    },
    /// `Debugger.Utility`, and its `Collections`, which has `FromListEntry`.
    Utility,
    Collections,
    Int(Integer),
    Text(String),
    Bool(bool),
    /// A collection a query made, keyed as `dx` shows it.
    List(Vec<(u64, ModelValue)>),
    /// `new { Name = ..., ... }`.
    Object(Vec<(String, ModelValue)>),
    /// A typed value, as the expression `dx` evaluates for it.
    Typed(String),
}

impl ModelValue {
    pub fn unsigned(value: u64) -> Self {
        Self::Int(Integer::new(i128::from(value), true, true))
    }
}

/// An integer with its C type: 32 or 64 bits (`wide`), signed or not. An
/// unsigned one, such as an ID or a count, shows in hex, and a signed one,
/// such as a literal's arithmetic, in decimal, as in WinDbg.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Integer {
    pub value: i128,
    pub unsigned: bool,
    pub wide: bool,
}

impl Integer {
    /// `value` wrapped to the type's width and sign, as C wraps it.
    pub fn new(value: i128, unsigned: bool, wide: bool) -> Self {
        let value = match (wide, unsigned) {
            (true, true) => i128::from(value as u64),
            (true, false) => i128::from(value as i64),
            (false, true) => i128::from(value as u32),
            (false, false) => i128::from(value as i32),
        };
        Self {
            value,
            unsigned,
            wide,
        }
    }

    /// As `dx` writes it: decimal when signed or asked for (`, d`), else
    /// hex.
    pub fn text(self, decimal: bool) -> String {
        int_text(self.value, self.unsigned, decimal)
    }
}

/// The roots a data model expression starts at.
pub const ROOTS: [&str; 4] = ["Debugger", "@$cursession", "@$curprocess", "@$curthread"];

/// The kernel structure under the object header of each object type that
/// `UnderlyingObject` reads, as WinDbg types it.
const OBJECT_BODIES: [(&str, &str); 17] = [
    ("Process", "_EPROCESS"),
    ("Thread", "_ETHREAD"),
    ("File", "_FILE_OBJECT"),
    ("Event", "_KEVENT"),
    ("Mutant", "_KMUTANT"),
    ("Semaphore", "_KSEMAPHORE"),
    ("Timer", "_ETIMER"),
    ("Section", "_SECTION"),
    ("Key", "_CM_KEY_BODY"),
    ("Token", "_TOKEN"),
    ("Job", "_EJOB"),
    ("Directory", "_OBJECT_DIRECTORY"),
    ("SymbolicLink", "_OBJECT_SYMBOLIC_LINK"),
    ("Device", "_DEVICE_OBJECT"),
    ("Driver", "_DRIVER_OBJECT"),
    ("ALPC Port", "_ALPC_PORT"),
    ("IoCompletion", "_KQUEUE"),
];

/// An integer as `dx` writes it: decimal when signed or asked for (`, d`),
/// else hex.
pub fn int_text(value: i128, unsigned: bool, decimal: bool) -> String {
    if decimal || !unsigned || value < 0 {
        value.to_string()
    } else {
        format!("{value:#x}")
    }
}

/// The properties an object shows, in WinDbg's order.
pub fn properties(value: &ModelValue) -> Vec<String> {
    let names: &[&str] = match value {
        ModelValue::Debugger => &["Sessions", "Utility"],
        ModelValue::Session => &["Processes", "Id"],
        ModelValue::Process(_) => &["KernelObject", "Name", "Id", "Threads", "Modules", "Io"],
        ModelValue::Thread(_) => &["KernelObject", "Id"],
        ModelValue::Module(_) => &["BaseAddress", "Name", "Size"],
        ModelValue::Io(_) => &["Handles"],
        ModelValue::Handle(_) => &["Handle", "Type", "GrantedAccess", "Object"],
        ModelValue::ObjectHeader { .. } => &["ObjectName", "ObjectType", "UnderlyingObject"],
        ModelValue::Utility => &["Collections"],
        ModelValue::Text(_) => &["Length"],
        ModelValue::Object(fields) => {
            return fields.iter().map(|(name, _)| name.clone()).collect();
        }
        _ => &[],
    };
    names.iter().map(|name| name.to_string()).collect()
}

/// The value line of an object or collection: what WinDbg shows after its
/// name.
pub fn summary(target: &Target, value: &ModelValue, decimal: bool) -> Option<String> {
    match value {
        ModelValue::Process(process) => Some(process_name(target, process)),
        ModelValue::Thread(thread) => Some(format!(
            "{} TID {:#x} (ETHREAD {:#x})",
            thread.process_name.as_deref().unwrap_or("?"),
            thread.tid.unwrap_or_default(),
            thread.ethread.0
        )),
        ModelValue::Module(module) => Some(module.path.clone().unwrap_or(module.name.clone())),
        ModelValue::Int(integer) => Some(integer.text(decimal)),
        ModelValue::Text(text) => Some(text.clone()),
        ModelValue::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

/// A process's name as the data model gives it: the file name of its
/// image, from `SeAuditProcessCreationInfo`, which keeps the whole name
/// where `ImageFileName` keeps 15 characters; `ImageFileName` for a
/// process without an image file, such as System.
pub fn process_name(target: &Target, process: &ProcessInfo) -> String {
    let full = || -> Option<String> {
        let types = target.types_in(target.kernel_dtb());
        let audit = types
            .struct_at("_EPROCESS", process.eprocess_va)
            .ok()?
            .embedded("SeAuditProcessCreationInfo")
            .ok()?
            .read_pointer("ImageFileName")
            .ok()?;
        if audit.is_zero() {
            return None;
        }
        let path = types
            .struct_at("_OBJECT_NAME_INFORMATION", audit)
            .ok()?
            .unicode_string("Name")
            .ok()?;
        let file = path.rsplit('\\').next()?.to_string();
        (!file.is_empty()).then_some(file)
    };
    full().unwrap_or_else(|| process.name.clone())
}

/// The current process, as `@$curprocess` names it.
fn current_process(target: &Target) -> Result<ProcessInfo> {
    target
        .current_process()
        .ok_or_else(|| Error::InvalidExpression("no process owns the current context".into()))
}

/// A process's modules: its own user-mode modules, or the kernel's for a
/// process with no user-mode loader list (System, Idle, a minimal process
/// such as vmmem), as WinDbg lists the kernel's for every process.
fn process_modules(target: &Target, process: &ProcessInfo) -> Result<Vec<ModuleInfo>> {
    let no_peb = target
        .types_in(target.kernel_dtb())
        .struct_at("_EPROCESS", process.eprocess_va)
        .and_then(|eprocess| eprocess.read_pointer("Peb"))
        .is_ok_and(|peb| peb.is_zero());
    if process.pid <= 4 || no_peb {
        return target.kernel_modules();
    }
    target.guest()?.process_modules(process)
}

/// The elements of a collection, keyed as `dx` shows them: `[key]` and the
/// element.
pub fn elements(target: &Target, value: &ModelValue) -> Result<Vec<(u64, ModelValue)>> {
    Ok(match value {
        ModelValue::Sessions => vec![(0, ModelValue::Session)],
        ModelValue::Processes => {
            // WinDbg lists the Idle process first, which is on no process
            // list.
            let guest = target.guest()?;
            let idle = guest
                .ntoskrnl
                .symbol("PsIdleProcess")
                .and_then(|symbol| symbol.read::<VirtAddr>())
                .and_then(|eprocess| guest.process_at(eprocess))
                .ok();
            let listed = target.matching_processes(None)?;
            let idle = idle.filter(|idle| {
                !listed
                    .iter()
                    .any(|process| process.eprocess_va == idle.eprocess_va)
            });
            idle.into_iter()
                .chain(listed)
                .map(|process| (process.pid, ModelValue::Process(process)))
                .collect()
        }
        ModelValue::Threads(process) => target
            .enumerate_threads_for_process_info(process)?
            .into_iter()
            .map(|thread| (thread.tid.unwrap_or_default(), ModelValue::Thread(thread)))
            .collect(),
        ModelValue::Modules(process) => process_modules(target, process)?
            .into_iter()
            .enumerate()
            .map(|(index, module)| (index as u64, ModelValue::Module(module)))
            .collect(),
        ModelValue::Handles(process) => target
            .enumerate_process_handles(process.clone(), usize::MAX)?
            .entries
            .into_iter()
            .map(|entry| (entry.handle, ModelValue::Handle(Box::new(entry))))
            .collect(),
        ModelValue::List(elements) => elements.clone(),
        _ => Vec::new(),
    })
}

/// Whether `value` is a collection, which `[key]`, `.Count()`, and the
/// queries take.
pub fn is_collection(value: &ModelValue) -> bool {
    matches!(
        value,
        ModelValue::Sessions
            | ModelValue::Processes
            | ModelValue::Threads(_)
            | ModelValue::Modules(_)
            | ModelValue::Handles(_)
            | ModelValue::List(_)
    )
}

/// A kernel structure at `address`, as the typed expression `dx` reads.
pub fn kernel_object(type_name: &str, address: u64) -> ModelValue {
    ModelValue::Typed(format!("(*((nt!{type_name} *){address:#x}))"))
}

/// The value of a handle field, or why it is not known.
fn handle_field<T: Clone>(field: &DiagnosticValue<T>) -> Result<T> {
    match field {
        DiagnosticValue::Available(value) => Ok(value.clone()),
        DiagnosticValue::Unavailable(error) => Err(Error::InvalidExpression(error.clone())),
    }
}

/// The property `name` of the model object `value`. A typed value's fields
/// are `dx_query`'s, which reads them through the expression evaluator.
pub fn property(target: &Target, value: &ModelValue, name: &str) -> Result<ModelValue> {
    Ok(match (value, name) {
        (ModelValue::Debugger, "Sessions") => ModelValue::Sessions,
        (ModelValue::Debugger, "Utility") => ModelValue::Utility,
        (ModelValue::Utility, "Collections") => ModelValue::Collections,
        (ModelValue::Text(text), "Length") => ModelValue::unsigned(text.chars().count() as u64),
        (ModelValue::Session, "Processes") => ModelValue::Processes,
        (ModelValue::Session, "Id") => ModelValue::Int(Integer::new(0, false, false)),
        (ModelValue::Process(process), "KernelObject") => {
            kernel_object("_EPROCESS", process.eprocess_va.0)
        }
        (ModelValue::Process(process), "Name") => ModelValue::Text(process_name(target, process)),
        (ModelValue::Process(process), "Id") => ModelValue::unsigned(process.pid),
        (ModelValue::Process(process), "Threads") => ModelValue::Threads(process.clone()),
        (ModelValue::Process(process), "Modules") => ModelValue::Modules(process.clone()),
        (ModelValue::Process(process), "Io") => ModelValue::Io(process.clone()),
        (ModelValue::Io(process), "Handles") => ModelValue::Handles(process.clone()),
        (ModelValue::Thread(thread), "KernelObject") => kernel_object("_ETHREAD", thread.ethread.0),
        (ModelValue::Thread(thread), "Id") => ModelValue::unsigned(thread.tid.unwrap_or_default()),
        (ModelValue::Module(module), "Name") => {
            ModelValue::Text(module.path.clone().unwrap_or(module.name.clone()))
        }
        (ModelValue::Module(module), "BaseAddress") => ModelValue::unsigned(module.base_address.0),
        (ModelValue::Module(module), "Size") => ModelValue::unsigned(u64::from(module.size)),
        (ModelValue::Handle(handle), "Handle") => ModelValue::unsigned(handle.handle),
        (ModelValue::Handle(handle), "Type") => {
            ModelValue::Text(handle_field(&handle.type_name)?.unwrap_or_default())
        }
        (ModelValue::Handle(handle), "GrantedAccess") => {
            ModelValue::unsigned(u64::from(handle_field(&handle.granted_access)?))
        }
        (ModelValue::Handle(handle), "Object") => ModelValue::ObjectHeader {
            header: handle_field(&handle.object)?,
            kind: handle_field(&handle.type_name).ok().flatten(),
        },
        // As in WinDbg, only a named object has an `ObjectName`.
        (ModelValue::ObjectHeader { header, .. }, "ObjectName") => ModelValue::Text(
            target
                .inspect_object_header(*header + object_body_offset(target)?)?
                .name
                .filter(|name| !name.is_empty())
                .ok_or_else(|| Error::InvalidExpression("the object has no name".into()))?,
        ),
        (ModelValue::ObjectHeader { kind, .. }, "ObjectType") => {
            ModelValue::Text(kind.clone().unwrap_or_default())
        }
        (ModelValue::ObjectHeader { header, kind }, "UnderlyingObject") => {
            let kind = kind.as_deref().unwrap_or_default();
            let body = OBJECT_BODIES
                .iter()
                .find(|(name, _)| *name == kind)
                .map(|(_, body)| *body)
                .ok_or_else(|| {
                    Error::InvalidExpression(format!(
                        "no structure is known for a {kind} object; read its _OBJECT_HEADER's \
                         Body"
                    ))
                })?;
            kernel_object(body, header.0 + object_body_offset(target)?)
        }
        (ModelValue::Object(fields), _) => fields
            .iter()
            .find(|(field, _)| field == name)
            .map(|(_, value)| value.clone())
            .ok_or_else(|| no_property(value, name))?,
        _ => return Err(no_property(value, name)),
    })
}

/// `_OBJECT_HEADER.Body`'s offset: where an object starts after its header.
fn object_body_offset(target: &Target) -> Result<u64> {
    target
        .guest()?
        .ntoskrnl
        .types()
        .layout("_OBJECT_HEADER")?
        .field_offset("Body")
}

fn no_property(value: &ModelValue, name: &str) -> Error {
    let known = properties(value);
    Error::InvalidExpression(if known.is_empty() {
        format!("this value has no property {name}")
    } else {
        format!("no property {name}; this object has {}", known.join(", "))
    })
}

/// The root value `name`, one of [`ROOTS`].
pub fn root(target: &Target, name: &str) -> Result<ModelValue> {
    Ok(match name {
        "Debugger" => ModelValue::Debugger,
        "@$cursession" => ModelValue::Session,
        "@$curprocess" => ModelValue::Process(current_process(target)?),
        "@$curthread" => {
            let ethread = target.builtin_variable_value("thread").ok_or_else(|| {
                Error::InvalidExpression("no thread is current in this context".into())
            })?;
            ModelValue::Thread(target.thread_info_from_ethread(VirtAddr(ethread))?)
        }
        _ => {
            return Err(Error::InvalidExpression(format!(
                "{name} is not a data model root"
            )));
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// IDs, counts, and addresses are unsigned and show in hex; a literal's
    /// arithmetic is signed and shows in decimal; `, d` shows every integer
    /// in decimal.
    #[test]
    fn integers_show_as_windbg_types_them() {
        assert_eq!(int_text(0x2a4, true, false), "0x2a4");
        assert_eq!(int_text(26, false, false), "26");
        assert_eq!(int_text(-16, false, false), "-16");
        assert_eq!(int_text(0x2a4, true, true), "676");
    }
}
