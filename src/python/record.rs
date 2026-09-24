//! Attribute-shaped results: every [`View::Object`](crate::view::View) the SDK
//! returns is a [`Record`] (`frame.ip`, `thread.state_name`), and every field
//! that can fail to read on its own is a [`Diagnostic`] (`peb.ldr.value`,
//! `if peb.ldr:`). Both keep dict access (`record["ip"]`, `to_dict()`) so the
//! shape stays the one the MCP JSON surface documents.

use std::convert::Infallible;

use pyo3::exceptions::{PyAttributeError, PyKeyError};
#[cfg(feature = "python-stubs")]
use pyo3::inspect::PyStaticExpr;
use pyo3::prelude::*;
#[cfg(feature = "python-stubs")]
use pyo3::types::PyString;
use pyo3::types::{PyDict, PyList, PyTuple};
#[cfg(feature = "python-stubs")]
use pyo3::{PyTypeInfo, type_hint_identifier, type_hint_subscript};

use super::iter::NameIterator;

/// A `to_dict()` result: a plain `dict` of string keys and plain values,
/// typed as `dict[str, Any]` for type checkers.
pub struct PlainDict<'py>(pub Bound<'py, PyDict>);

impl<'py> IntoPyObject<'py> for PlainDict<'py> {
    type Target = PyDict;
    type Output = Bound<'py, PyDict>;
    type Error = Infallible;

    #[cfg(feature = "python-stubs")]
    const OUTPUT_TYPE: PyStaticExpr = type_hint_subscript!(
        PyDict::TYPE_HINT,
        PyString::TYPE_HINT,
        type_hint_identifier!("typing", "Any")
    );

    fn into_pyobject(self, _py: Python<'py>) -> Result<Self::Output, Self::Error> {
        Ok(self.0)
    }
}

/// An immutable, ordered set of named fields with attribute access.
#[pyclass(module = "ntoseye", frozen)]
pub struct Record {
    fields: Py<PyDict>,
    /// Fields that are addresses, rendered as hex by `__repr__`.
    hex: Vec<&'static str>,
}

impl Record {
    pub fn new(fields: Py<PyDict>, hex: Vec<&'static str>) -> Self {
        Self { fields, hex }
    }
}

#[pymethods]
impl Record {
    fn __getattr__<'py>(&self, py: Python<'py>, name: &str) -> PyResult<Bound<'py, PyAny>> {
        let fields = self.fields.bind(py);
        fields.get_item(name)?.ok_or_else(|| {
            let known: Vec<String> = fields.keys().iter().map(|k| k.to_string()).collect();
            PyAttributeError::new_err(format!("no field '{name}'; fields: {}", known.join(", ")))
        })
    }

    fn __getitem__<'py>(&self, py: Python<'py>, key: &str) -> PyResult<Bound<'py, PyAny>> {
        let fields = self.fields.bind(py);
        fields
            .get_item(key)?
            .ok_or_else(|| PyKeyError::new_err(key.to_string()))
    }

    fn __contains__(&self, py: Python<'_>, key: &str) -> PyResult<bool> {
        self.fields.bind(py).contains(key)
    }

    fn __len__(&self, py: Python<'_>) -> usize {
        self.fields.bind(py).len()
    }

    fn __iter__(&self, py: Python<'_>) -> PyResult<NameIterator> {
        Ok(NameIterator::new(self.keys(py)?))
    }

    fn __eq__(&self, py: Python<'_>, other: &Bound<'_, PyAny>) -> PyResult<bool> {
        let other = match other.cast::<Record>() {
            Ok(record) => record.get().fields.bind(py).clone().into_any(),
            Err(_) => other.clone(),
        };
        self.fields.bind(py).eq(other)
    }

    fn __dir__(&self, py: Python<'_>) -> PyResult<Vec<String>> {
        let mut names = self.keys(py)?;
        names.extend(
            ["keys", "values", "items", "get", "to_dict"]
                .into_iter()
                .map(str::to_string),
        );
        Ok(names)
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        let mut parts = Vec::new();
        for (key, value) in self.fields.bind(py).iter() {
            let key = key.extract::<String>()?;
            let shown = if self.hex.contains(&key.as_str()) && !value.is_none() {
                format!("{:#x}", value.extract::<u64>()?)
            } else {
                summarize(&value)?
            };
            parts.push(format!("{key}={shown}"));
        }
        Ok(format!("Record({})", parts.join(", ")))
    }

    /// The field names, in order.
    fn keys(&self, py: Python<'_>) -> PyResult<Vec<String>> {
        self.fields.bind(py).keys().extract()
    }

    /// The field values, in order.
    fn values<'py>(&self, py: Python<'py>) -> Vec<Bound<'py, PyAny>> {
        self.fields.bind(py).values().iter().collect()
    }

    /// `(name, value)` pairs, in order.
    fn items<'py>(&self, py: Python<'py>) -> PyResult<Vec<(String, Bound<'py, PyAny>)>> {
        self.fields
            .bind(py)
            .iter()
            .map(|(key, value)| Ok((key.extract()?, value)))
            .collect()
    }

    /// The field, or `default` when the record has no such field.
    #[pyo3(signature = (key, default=None))]
    fn get<'py>(
        &self,
        py: Python<'py>,
        key: &str,
        default: Option<Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        Ok(self
            .fields
            .bind(py)
            .get_item(key)?
            .or(default)
            .unwrap_or_else(|| py.None().into_bound(py)))
    }

    /// A plain nested `dict` (records and diagnostics converted throughout),
    /// the shape the MCP `format=json` surface returns.
    pub fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<PlainDict<'py>> {
        let dict = PyDict::new(py);
        for (key, value) in self.fields.bind(py).iter() {
            dict.set_item(key, plain(&value)?)?;
        }
        Ok(PlainDict(dict))
    }
}

/// One field that reads independently: `value` when it did, `error` when it
/// did not. Truthy exactly when available.
#[pyclass(module = "ntoseye", frozen)]
pub struct Diagnostic {
    pub value: Py<PyAny>,
    /// Whether `value` is an address, rendered as hex by `__repr__`.
    pub hex: bool,
    pub error: Option<String>,
    /// Provenance of a metric (`"dump header"`, `"KDBG"`, ...); `None` for a
    /// field that is not a metric.
    pub source: Option<Option<String>>,
}

#[pymethods]
impl Diagnostic {
    #[getter]
    fn available(&self) -> bool {
        self.error.is_none()
    }

    #[getter]
    fn value<'py>(&self, py: Python<'py>) -> Bound<'py, PyAny> {
        self.value.bind(py).clone()
    }

    #[getter]
    fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    #[getter]
    fn source(&self) -> Option<&str> {
        self.source.as_ref().and_then(|source| source.as_deref())
    }

    fn __bool__(&self) -> bool {
        self.error.is_none()
    }

    fn __eq__(&self, py: Python<'_>, other: &Bound<'_, PyAny>) -> PyResult<bool> {
        let Ok(other) = other.cast::<Diagnostic>() else {
            return Ok(false);
        };
        let other = other.get();
        Ok(self.error == other.error
            && self.source == other.source
            && self.value.bind(py).eq(other.value.bind(py))?)
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        Ok(match &self.error {
            Some(error) => format!("Diagnostic(error={error:?})"),
            None if self.hex => format!("Diagnostic({:#x})", self.value.extract::<u64>(py)?),
            None => format!("Diagnostic({})", summarize(self.value.bind(py))?),
        })
    }

    /// The `{available, value, error[, source]}` dict the MCP surface returns.
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<PlainDict<'py>> {
        let dict = PyDict::new(py);
        dict.set_item("available", self.error.is_none())?;
        dict.set_item("value", plain(self.value.bind(py))?)?;
        dict.set_item("error", self.error.as_deref())?;
        if let Some(source) = &self.source {
            dict.set_item("source", source.as_deref())?;
        }
        Ok(PlainDict(dict))
    }
}

/// A one-line rendering for `__repr__`: scalars in full, containers by size,
/// so a record with a 700-thread list stays readable.
fn summarize(value: &Bound<'_, PyAny>) -> PyResult<String> {
    if let Ok(record) = value.cast::<Record>() {
        return Ok(format!(
            "Record(<{} fields>)",
            record.get().fields.bind(value.py()).len()
        ));
    }
    if let Ok(diagnostic) = value.cast::<Diagnostic>() {
        return diagnostic.get().__repr__(value.py());
    }
    if let Ok(list) = value.cast::<PyList>() {
        return Ok(format!("[<{} items>]", list.len()));
    }
    Ok(value.repr()?.to_string())
}

/// Convert records and diagnostics to dicts throughout a value.
fn plain<'py>(value: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyAny>> {
    if let Ok(record) = value.cast::<Record>() {
        return Ok(record.get().to_dict(value.py())?.0.into_any());
    }
    if let Ok(diagnostic) = value.cast::<Diagnostic>() {
        return Ok(diagnostic.get().to_dict(value.py())?.0.into_any());
    }
    if let Ok(list) = value.cast::<PyList>() {
        let out = PyList::empty(value.py());
        for item in list.iter() {
            out.append(plain(&item)?)?;
        }
        return Ok(out.into_any());
    }
    if let Ok(tuple) = value.cast::<PyTuple>() {
        let items: Vec<Bound<'py, PyAny>> = tuple
            .iter()
            .map(|item| plain(&item))
            .collect::<PyResult<_>>()?;
        return Ok(PyTuple::new(value.py(), items)?.into_any());
    }
    Ok(value.clone())
}
