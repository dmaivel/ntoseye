pub mod shape;

/// Declares the view modules, and `with_shape_classes!`, which adds every
/// class their shapes declare to the SDK's `#[pymodule]` as exports, so a
/// class is named only where its shape is (see [`shape`]). `$d` is a `$` for
/// the macros it defines.
macro_rules! view_modules {
    ([$d:tt] $($module:ident),* $(,)?) => {
        $(pub mod $module;)*

        /// `with_shape_classes! { #[pymodule] pub mod m { ... } }`: the module,
        /// exporting every shape class besides its own items.
        #[cfg(feature = "python")]
        macro_rules! with_shape_classes {
            ($d($d item:tt)*) => {
                $crate::view::collect_shape_classes!([$($module)*] [] { $d($d item)* });
            };
        }
        #[cfg(feature = "python")]
        pub(crate) use with_shape_classes;
    };
}

view_modules!([$] backend, bugcheck, cpu, etw, execution, fs, hardware, heap, list, meta, mm, module, object, pnp, process, sched, security, symbols, triage, usermode, wdf);

/// One step of [`with_shape_classes!`]: asks the next module for its classes
/// (its `shape_classes!`), then emits the module once none are left.
#[cfg(feature = "python")]
macro_rules! collect_shape_classes {
    ([$next:ident $($rest:ident)*] [$($done:tt)*] $module:tt) => {
        $crate::view::$next::shape_classes!(
            $crate::view::collected_shape_classes; $next [$($rest)*] [$($done)*] $module
        );
    };
    ([] [$(($from:ident $($class:ident)*))*] {
        $(#[$attr:meta])* $vis:vis mod $name:ident { $($body:tt)* }
    }) => {
        $(#[$attr])*
        $vis mod $name {
            $($body)*
            $(
                #[pymodule_export]
                use $crate::view::$from::py::{$($class),*};
            )*
        }
    };
}
#[cfg(feature = "python")]
pub(crate) use collect_shape_classes;

/// A module's classes, back from its `shape_classes!`.
#[cfg(feature = "python")]
macro_rules! collected_shape_classes {
    ($from:ident [$($rest:ident)*] [$($done:tt)*] $module:tt [$($class:ident)*]) => {
        $crate::view::collect_shape_classes!([$($rest)*] [$($done)* ($from $($class)*)] $module);
    };
}
#[cfg(feature = "python")]
pub(crate) use collected_shape_classes;

// Shared shape for SDK/MCP structure rendering; surfaces disagree only on how
// address-like values are encoded.
/// A node in a neutral value tree.
pub enum View {
    /// An address/pointer/status: hex string for MCP, int for Python.
    Hex(u64),
    /// A plain count: a number on both surfaces.
    Num(u64),
    /// A signed count.
    Int(i64),
    Bool(bool),
    Str(String),
    Null,
    List(Vec<View>),
    /// An ordered key/value object (insertion order is preserved on render).
    Object(Vec<(&'static str, View)>),
    /// An object declared with [`shape::shapes!`]: rendered as an
    /// [`Object`](Self::Object), and as its own class in the SDK.
    Shaped(shape::Shaped),
    /// A value that can fail to read on its own: `{available, value, error}`
    /// for MCP, an `ntoseye.Diagnostic` for Python.
    Diagnostic(Box<DiagnosticView>),
}

impl View {
    /// A list of rendered values: `View::list(stack_frames(&trace.frames))`.
    pub fn list<T: shape::ViewValue<Source = T>>(items: impl IntoIterator<Item = T>) -> View {
        View::List(items.into_iter().map(T::view).collect())
    }
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
        View::Num(n) => Value::from(*n),
        View::Int(n) => Value::from(*n),
        View::Bool(b) => Value::from(*b),
        View::Str(s) => Value::from(s.clone()),
        View::Null => Value::Null,
        View::List(items) => Value::Array(items.iter().map(to_json).collect()),
        View::Object(fields) | View::Shaped(shape::Shaped { fields, .. }) => {
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
    /// [`Record`](crate::python::record::Record)s and `ntoseye.Diagnostic`s
    /// with attribute access.
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
    use crate::python::record::{BaseRecord, Record, diagnostic_class};
    use pyo3::IntoPyObjectExt;
    use pyo3::prelude::*;
    use pyo3::types::{PyDict, PyList};
    Ok(match v {
        View::Hex(n) | View::Num(n) => n.into_bound_py_any(py)?,
        View::Int(n) => n.into_bound_py_any(py)?,
        View::Bool(b) => b.into_bound_py_any(py)?,
        View::Str(s) => s.as_str().into_bound_py_any(py)?,
        View::Null => py.None().into_bound(py),
        View::List(items) => {
            let list = PyList::empty(py);
            for item in items {
                list.append(to_py(py, item, shape)?)?;
            }
            list.into_any()
        }
        View::Object(fields) | View::Shaped(shape::Shaped { fields, .. }) => {
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
