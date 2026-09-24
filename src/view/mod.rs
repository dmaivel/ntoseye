pub mod backend;
pub mod bugcheck;
pub mod cpu;
pub mod execution;
pub mod heap;
pub mod meta;
pub mod mm;
pub mod module;
pub mod object;
pub mod pnp;
pub mod process;
pub mod sched;
pub mod security;
pub mod symbols;
pub mod triage;
pub mod usermode;

use crate::target::{DiagnosticMetric, DiagnosticValue, ListTermination};

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
    /// A value that can fail to read on its own: `{available, value, error}`
    /// for MCP, an [`ntoseye.Diagnostic`](crate::python::record::Diagnostic)
    /// for Python.
    Diagnostic(Box<DiagnosticView>),
}

pub struct DiagnosticView {
    pub value: Option<View>,
    pub error: Option<String>,
    /// `Some` for a metric, whose provenance is part of the shape even when
    /// unknown (`source: null`).
    pub source: Option<Option<String>>,
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
        View::Diagnostic(diagnostic) => {
            let mut map = serde_json::Map::new();
            map.insert("available".into(), Value::from(diagnostic.error.is_none()));
            map.insert(
                "value".into(),
                diagnostic.value.as_ref().map_or(Value::Null, to_json),
            );
            map.insert(
                "error".into(),
                diagnostic.error.clone().map_or(Value::Null, Value::from),
            );
            if let Some(source) = &diagnostic.source {
                map.insert(
                    "source".into(),
                    source.clone().map_or(Value::Null, Value::from),
                );
            }
            Value::Object(map)
        }
    }
}

/// How [`to_py`] renders objects and diagnostics.
#[cfg(feature = "python")]
#[derive(Clone, Copy)]
pub enum PyShape {
    /// [`Record`](crate::python::record::Record)s and
    /// [`Diagnostic`](crate::python::record::Diagnostic)s with attribute access.
    Records,
    /// Plain `dict`s throughout, the shape `to_dict()` returns: a diagnostic
    /// becomes `{available, value, error[, source]}` as in [`to_json`].
    Plain,
}

/// Render a [`View`] to a Python object (the SDK): addresses become plain ints.
#[cfg(feature = "python")]
pub fn to_py<'py>(
    py: pyo3::Python<'py>,
    v: &View,
    shape: PyShape,
) -> pyo3::PyResult<pyo3::Bound<'py, pyo3::PyAny>> {
    use crate::python::record::{Diagnostic, Record};
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
                list.append(to_py(py, item, shape)?)?;
            }
            list.into_any()
        }
        View::Object(fields) => {
            let dict = PyDict::new(py);
            let mut hex = Vec::new();
            for (key, val) in fields {
                if matches!(val, View::Hex(_) | View::OptHex(Some(_))) {
                    hex.push(*key);
                }
                dict.set_item(key, to_py(py, val, shape)?)?;
            }
            match shape {
                PyShape::Records => Bound::new(py, Record::new(dict.unbind(), hex))?.into_any(),
                PyShape::Plain => dict.into_any(),
            }
        }
        View::Diagnostic(diagnostic) => {
            let value = match &diagnostic.value {
                Some(value) => to_py(py, value, shape)?,
                None => py.None().into_bound(py),
            };
            match shape {
                PyShape::Records => Bound::new(
                    py,
                    Diagnostic {
                        value: value.unbind(),
                        hex: matches!(diagnostic.value, Some(View::Hex(_) | View::OptHex(Some(_)))),
                        error: diagnostic.error.clone(),
                        source: diagnostic.source.clone(),
                    },
                )?
                .into_any(),
                PyShape::Plain => {
                    let dict = PyDict::new(py);
                    dict.set_item("available", diagnostic.error.is_none())?;
                    dict.set_item("value", value)?;
                    dict.set_item("error", diagnostic.error.as_deref())?;
                    if let Some(source) = &diagnostic.source {
                        dict.set_item("source", source.as_deref())?;
                    }
                    dict.into_any()
                }
            }
        }
    })
}

pub fn diagnostic<T>(value: &DiagnosticValue<T>, encode: impl FnOnce(&T) -> View) -> View {
    let (value, error) = match value {
        DiagnosticValue::Available(value) => (Some(encode(value)), None),
        DiagnosticValue::Unavailable(error) => (None, Some(error.clone())),
    };
    View::Diagnostic(Box::new(DiagnosticView {
        value,
        error,
        source: None,
    }))
}

pub fn diagnostic_metric<T>(metric: &DiagnosticMetric<T>, encode: impl FnOnce(&T) -> View) -> View {
    let View::Diagnostic(mut diagnostic) = diagnostic(&metric.value, encode) else {
        unreachable!()
    };
    diagnostic.source = Some(metric.source.map(|source| source.to_string()));
    View::Diagnostic(diagnostic)
}

/// How a guest linked-list walk ended.
pub fn list_termination(termination: &ListTermination) -> View {
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
