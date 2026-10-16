//! The SDK's result records that are not (yet) the target model's own
//! types, and the value tree ([`View`]) every record renders to (see
//! [`record`]).

pub mod backend;
pub mod bugcheck;
pub mod execution;
pub mod fs;
pub mod heap;
pub mod hypervisor;
pub mod meta;
pub mod mm;
pub mod module;
pub mod object;
pub mod pnp;
pub mod power;
pub mod process;
pub mod record;
pub mod registry;
pub mod security;
pub mod symbols;
pub mod triage;
pub mod userdump;
pub mod usermode;

/// A node in the value tree the SDK builds its results from.
pub enum View {
    /// An address, pointer or status: an int that records show in hex.
    Hex(u64),
    /// A plain count.
    Num(u64),
    /// A signed count.
    Int(i64),
    Bool(bool),
    Str(String),
    /// Raw bytes: `bytes` in the SDK.
    Bytes(Vec<u8>),
    Null,
    List(Vec<View>),
    /// An ordered key/value object (insertion order is preserved on render).
    Object(Vec<(&'static str, View)>),
    /// A `#[record]`: rendered as an [`Object`](Self::Object), and as its
    /// own class in the SDK.
    Shaped(record::Shaped),
    /// A value that can fail to read on its own: an `ntoseye.Diagnostic`, or
    /// `{available, value, error}` in plain form.
    Diagnostic(Box<DiagnosticView>),
}

pub struct DiagnosticView {
    pub value: Option<View>,
    pub error: Option<String>,
    /// `Some` for a metric, whose provenance is part of the shape even when
    /// unknown (`source: null`).
    pub source: Option<Option<String>>,
}

/// How [`to_py`] renders objects and diagnostics.
#[derive(Clone, Copy)]
pub enum PyShape {
    /// [`Record`](crate::python::record::Record)s and `ntoseye.Diagnostic`s
    /// with attribute access.
    Records,
    /// Plain `dict`s throughout, the shape `to_dict()` returns: a diagnostic
    /// becomes `{available, value, error[, source]}`.
    Plain,
}

/// Render a [`View`] to a Python object (the SDK): addresses become plain ints.
pub fn to_py<'py>(
    py: pyo3::Python<'py>,
    v: &View,
    shape: PyShape,
) -> pyo3::PyResult<pyo3::Bound<'py, pyo3::PyAny>> {
    use crate::python::record::{BaseRecord, Record, diagnostic_class};
    use pyo3::IntoPyObjectExt;
    use pyo3::prelude::*;
    use pyo3::types::{PyBytes, PyDict, PyList};
    Ok(match v {
        View::Hex(n) | View::Num(n) => n.into_bound_py_any(py)?,
        View::Int(n) => n.into_bound_py_any(py)?,
        View::Bool(b) => b.into_bound_py_any(py)?,
        View::Str(s) => s.as_str().into_bound_py_any(py)?,
        View::Bytes(bytes) => PyBytes::new(py, bytes).into_any(),
        View::Null => py.None().into_bound(py),
        View::List(items) => {
            let list = PyList::empty(py);
            for item in items {
                list.append(to_py(py, item, shape)?)?;
            }
            list.into_any()
        }
        View::Object(fields) | View::Shaped(record::Shaped { fields, .. }) => {
            let dict = PyDict::new(py);
            let mut hex = Vec::new();
            for (key, val) in fields {
                if matches!(val, View::Hex(_)) {
                    hex.push(*key);
                }
                dict.set_item(key, to_py(py, val, shape)?)?;
            }
            if let PyShape::Plain = shape {
                return Ok(dict.into_any());
            }
            match v {
                View::Shaped(shaped) => (shaped.class)(py, BaseRecord::new(dict.unbind(), hex))?,
                _ => Bound::new(py, Record::new(dict.unbind(), hex))?.into_any(),
            }
        }
        View::Diagnostic(diagnostic) => {
            let value = match &diagnostic.value {
                Some(value) => to_py(py, value, shape)?,
                None => py.None().into_bound(py),
            };
            match shape {
                PyShape::Records => diagnostic_class(py)?.call1((
                    value,
                    diagnostic.error.as_deref(),
                    diagnostic.source.as_ref().and_then(Option::as_deref),
                    diagnostic.source.is_some(),
                    matches!(diagnostic.value, Some(View::Hex(_))),
                ))?,
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
