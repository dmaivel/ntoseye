//! The part of WinDbg's debugger data model that `dx` reads: `Debugger`,
//! `@$cursession`, `@$curprocess`, and `@$curthread`, their sessions,
//! processes, threads, and modules, indexed as WinDbg indexes them, and
//! `.Count()` on a collection. A `KernelObject` property is the typed
//! `_EPROCESS` or `_ETHREAD`, which `dx` reads on from there as any typed
//! expression. Queries with lambdas (`.Where(p => ...)`) are not part of
//! this model.

use crate::error::{Error, Result};
use crate::guest::{ModuleInfo, ProcessInfo};
use crate::target::{Target, ThreadInfo};
use crate::types::VirtAddr;

/// The data model objects `dx` can show.
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
    /// A number or a string, shown as is.
    Scalar(String),
}

/// What a data model expression comes to: a model value, or a kernel
/// object as the typed expression `dx` evaluates, with the rest of the
/// expression after it.
pub enum ModelResult {
    Value(ModelValue),
    Typed { expression: String },
}

/// One accessor of a path: `.Name`, `[key]`, or `.Count()`; `Typed` marks
/// where text that is not a model accessor starts (`->`, an operator), and
/// `Invalid` an accessor that does not parse, which is an error unless a
/// typed kernel object before it reads it.
#[derive(Debug, PartialEq, Eq)]
enum Accessor<'a> {
    Property(&'a str),
    Index(u64),
    Count,
    Typed,
    Invalid(String),
}

/// The roots a data model expression starts at.
const ROOTS: [&str; 4] = ["Debugger", "@$cursession", "@$curprocess", "@$curthread"];

/// The queries over collections that take a lambda, which this model does
/// not evaluate.
const LAMBDA_QUERIES: [&str; 8] = [
    ".Where(",
    ".Select(",
    ".First(",
    ".OrderBy(",
    ".Take(",
    ".Any(",
    ".All(",
    ".Flatten(",
];

/// Whether `text` starts at a data model root.
pub fn is_model_expression(text: &str) -> bool {
    ROOTS.iter().any(|root| {
        text.strip_prefix(root)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(['.', '[', ' ']))
    })
}

/// Whether `text` asks for a query this model does not evaluate.
pub fn uses_lambda_query(text: &str) -> bool {
    text.contains("=>") || LAMBDA_QUERIES.iter().any(|query| text.contains(query))
}

/// An index as a C++ number: decimal unless written with `0x`.
fn parse_index(text: &str) -> Option<u64> {
    let text = text.trim();
    match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    }
}

/// The root of `text` and the accessors after it with where each starts,
/// up to the first that is not a model accessor.
fn split_path(text: &str) -> Result<(&str, Vec<(Accessor<'_>, usize)>)> {
    let text = text.trim();
    let root = ROOTS
        .iter()
        .copied()
        .find(|root| text.starts_with(root))
        .ok_or_else(|| Error::InvalidExpression(format!("{text} is not a data model path")))?;
    let mut accessors = Vec::new();
    let mut at = root.len();
    while at < text.len() {
        let rest = &text[at..];
        if let Some(after) = rest.strip_prefix(".Count()") {
            accessors.push((Accessor::Count, at));
            at = text.len() - after.len();
        } else if let Some(property) = rest.strip_prefix('.') {
            let end = property
                .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
                .unwrap_or(property.len());
            if end == 0 {
                accessors.push((
                    Accessor::Invalid(format!("expected a property name after '.' in {text}")),
                    at,
                ));
                break;
            }
            accessors.push((Accessor::Property(&property[..end]), at));
            at += 1 + end;
        } else if let Some(index) = rest.strip_prefix('[') {
            let parsed = index
                .find(']')
                .and_then(|end| parse_index(&index[..end]).map(|value| (value, end)));
            let Some((value, end)) = parsed else {
                accessors.push((
                    Accessor::Invalid(format!(
                        "{rest} is not an index; the data model indexes processes and threads \
                         by ID and modules from 0, with a number"
                    )),
                    at,
                ));
                break;
            };
            accessors.push((Accessor::Index(value), at));
            at += 2 + end;
        } else {
            // Anything else (`->`, an operator) is for a typed value.
            accessors.push((Accessor::Typed, at));
            break;
        }
    }
    Ok((root, accessors))
}

/// The properties an object shows, in WinDbg's order.
pub fn properties(value: &ModelValue) -> &'static [&'static str] {
    match value {
        ModelValue::Debugger => &["Sessions"],
        ModelValue::Session => &["Processes", "Id"],
        ModelValue::Process(_) => &["KernelObject", "Name", "Id", "Threads", "Modules"],
        ModelValue::Thread(_) => &["KernelObject", "Id"],
        ModelValue::Module(_) => &["Name", "BaseAddress", "Size"],
        _ => &[],
    }
}

/// The value line of an object or collection: what WinDbg shows after its
/// name.
pub fn summary(target: &Target, value: &ModelValue) -> Option<String> {
    match value {
        ModelValue::Process(process) => Some(process_name(target, process)),
        ModelValue::Thread(thread) => Some(format!(
            "{} TID {:#x} (ETHREAD {:#x})",
            thread.process_name.as_deref().unwrap_or("?"),
            thread.tid.unwrap_or_default(),
            thread.ethread.0
        )),
        ModelValue::Module(module) => Some(module.path.clone().unwrap_or(module.name.clone())),
        ModelValue::Scalar(text) => Some(text.clone()),
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

/// A process's modules: the kernel's for the System process, which has no
/// user-mode loader list, else its own.
fn process_modules(target: &Target, process: &ProcessInfo) -> Result<Vec<ModuleInfo>> {
    if process.pid == 4 {
        return target.kernel_modules();
    }
    target.guest()?.process_modules(process)
}

/// The elements of a collection, keyed as `dx` shows them: `[key]` and the
/// element.
pub fn elements(target: &Target, value: &ModelValue) -> Result<Vec<(u64, ModelValue)>> {
    Ok(match value {
        ModelValue::Sessions => vec![(0, ModelValue::Session)],
        ModelValue::Processes => target
            .matching_processes(None)?
            .into_iter()
            .map(|process| (process.pid, ModelValue::Process(process)))
            .collect(),
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
        _ => Vec::new(),
    })
}

/// Whether `value` is a collection, which `[key]` and `.Count()` take.
pub fn is_collection(value: &ModelValue) -> bool {
    matches!(
        value,
        ModelValue::Sessions
            | ModelValue::Processes
            | ModelValue::Threads(_)
            | ModelValue::Modules(_)
    )
}

/// The property `name` of `value`: a model value, or the typed kernel
/// object `KernelObject` names.
pub fn property(target: &Target, value: &ModelValue, name: &str) -> Result<ModelResult> {
    let model = |value| Ok(ModelResult::Value(value));
    let typed = |type_name: &str, address: u64| {
        Ok(ModelResult::Typed {
            expression: format!("(*((nt!{type_name} *){address:#x}))"),
        })
    };
    match (value, name) {
        (ModelValue::Debugger, "Sessions") => model(ModelValue::Sessions),
        (ModelValue::Session, "Processes") => model(ModelValue::Processes),
        (ModelValue::Session, "Id") => model(ModelValue::Scalar("0x0".into())),
        (ModelValue::Process(process), "KernelObject") => typed("_EPROCESS", process.eprocess_va.0),
        (ModelValue::Process(process), "Name") => {
            model(ModelValue::Scalar(process_name(target, process)))
        }
        (ModelValue::Process(process), "Id") => {
            model(ModelValue::Scalar(format!("{:#x}", process.pid)))
        }
        (ModelValue::Process(process), "Threads") => model(ModelValue::Threads(process.clone())),
        (ModelValue::Process(process), "Modules") => model(ModelValue::Modules(process.clone())),
        (ModelValue::Thread(thread), "KernelObject") => typed("_ETHREAD", thread.ethread.0),
        (ModelValue::Thread(thread), "Id") => model(ModelValue::Scalar(format!(
            "{:#x}",
            thread.tid.unwrap_or_default()
        ))),
        (ModelValue::Module(module), "Name") => model(ModelValue::Scalar(
            module.path.clone().unwrap_or(module.name.clone()),
        )),
        (ModelValue::Module(module), "BaseAddress") => {
            model(ModelValue::Scalar(format!("{:#x}", module.base_address.0)))
        }
        (ModelValue::Module(module), "Size") => {
            model(ModelValue::Scalar(format!("{:#x}", module.size)))
        }
        _ => {
            let known = properties(value);
            Err(Error::InvalidExpression(if known.is_empty() {
                format!("this value has no property {name}")
            } else {
                format!("no property {name}; this object has {}", known.join(", "))
            }))
        }
    }
}

/// The root value of a data model expression.
fn root(target: &Target, name: &str) -> Result<ModelValue> {
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
        _ => unreachable!("split_path returns one of ROOTS"),
    })
}

/// Evaluate the data model expression `text`.
pub fn evaluate(target: &Target, text: &str) -> Result<ModelResult> {
    let text = text.trim();
    let (root_name, accessors) = split_path(text)?;
    let mut value = root(target, root_name)?;
    for (accessor, at) in accessors {
        value = match accessor {
            Accessor::Typed => {
                return Err(Error::InvalidExpression(format!(
                    "'{}' does not apply to a data model object; use .KernelObject for the \
                     typed kernel object",
                    &text[at..]
                )));
            }
            Accessor::Invalid(message) => return Err(Error::InvalidExpression(message)),
            Accessor::Property(name) => match property(target, &value, name)? {
                ModelResult::Value(next) => next,
                ModelResult::Typed { expression } => {
                    // The rest of the expression reads the typed object.
                    let rest = &text[at + 1 + name.len()..];
                    return Ok(ModelResult::Typed {
                        expression: format!("{expression}{rest}"),
                    });
                }
            },
            Accessor::Index(key) => {
                if !is_collection(&value) {
                    return Err(Error::InvalidExpression(format!(
                        "'{}' indexes a value that is not a collection",
                        &text[at..]
                    )));
                }
                elements(target, &value)?
                    .into_iter()
                    .find(|(element_key, _)| *element_key == key)
                    .map(|(_, element)| element)
                    .ok_or_else(|| {
                        Error::InvalidExpression(format!(
                            "the collection has no element [{key:#x}]"
                        ))
                    })?
            }
            Accessor::Count => {
                if !is_collection(&value) {
                    return Err(Error::InvalidExpression(
                        ".Count() counts a collection; this value is not one".into(),
                    ));
                }
                ModelValue::Scalar(format!("{:#x}", elements(target, &value)?.len()))
            }
        };
    }
    Ok(ModelResult::Value(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_split_into_properties_indexes_and_counts() {
        let (root, accessors) =
            split_path("Debugger.Sessions[0].Processes[0x4].Threads.Count()").unwrap();
        assert_eq!(root, "Debugger");
        let accessors: Vec<_> = accessors
            .into_iter()
            .map(|(accessor, _)| accessor)
            .collect();
        assert_eq!(
            accessors,
            [
                Accessor::Property("Sessions"),
                Accessor::Index(0),
                Accessor::Property("Processes"),
                Accessor::Index(4),
                Accessor::Property("Threads"),
                Accessor::Count,
            ]
        );
        // A decimal index stays decimal, as in C++.
        let (_, accessors) = split_path("@$curprocess.Threads[10]").unwrap();
        assert_eq!(accessors[1].0, Accessor::Index(10));
    }

    #[test]
    fn a_typed_tail_stops_the_path_where_it_starts() {
        let text = "@$curprocess.KernelObject->Pcb";
        let (_, accessors) = split_path(text).unwrap();
        assert_eq!(accessors[0].0, Accessor::Property("KernelObject"));
        // `->` is not a model accessor; the path records where it begins.
        assert_eq!(accessors[1], (Accessor::Typed, 25));
        // A typed index after KernelObject need not be a number; elsewhere
        // it is an error once the evaluation reaches it.
        let (_, accessors) = split_path("@$curthread.KernelObject.Tcb.WaitBlock[i]").unwrap();
        assert!(matches!(accessors.last(), Some((Accessor::Invalid(_), _))));
        let (_, accessors) = split_path("@$curprocess.").unwrap();
        assert!(matches!(accessors.last(), Some((Accessor::Invalid(_), _))));
    }

    #[test]
    fn roots_need_a_boundary_after_them() {
        assert!(is_model_expression("@$curprocess"));
        assert!(is_model_expression("@$curprocess.Name"));
        assert!(is_model_expression("Debugger.Sessions"));
        assert!(!is_model_expression("DebuggerData"));
        assert!(!is_model_expression("@$proc->UniqueProcessId"));
        assert!(uses_lambda_query(
            "@$curprocess.Threads.Where(t => t.Id == 4)"
        ));
        assert!(!uses_lambda_query("@$curprocess.Threads.Count()"));
    }
}
