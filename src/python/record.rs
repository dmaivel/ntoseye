//! Attribute-shaped results: every [`View::Object`](crate::view::View) the SDK
//! returns is a [`Record`] (`frame.ip`, `thread.state_name`), every declared
//! shape ([`shapes!`](crate::view::shape::shapes)) its own [`BaseRecord`]
//! subclass with a property per field, and every field that can fail to read
//! on its own is the package's generic `Diagnostic` (`peb.ldr.value`,
//! `if peb.ldr:`). Records keep dict access (`record["ip"]`, `to_dict()`) so the
//! shape stays the one the MCP JSON surface documents.

use std::convert::Infallible;

use pyo3::exceptions::{PyAttributeError, PyKeyError};
#[cfg(feature = "python-stubs")]
use pyo3::inspect::PyStaticExpr;
use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::types::PyDict;
#[cfg(feature = "python-stubs")]
use pyo3::types::PyString;
#[cfg(feature = "python-stubs")]
use pyo3::{PyTypeInfo, type_hint_identifier, type_hint_subscript};

use super::iter::NameIterator;
use super::package_attr;

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

/// An immutable, ordered set of named fields with dict access: the base of
/// `Record` and of every typed result class (`PciFunction`, ...), whose
/// properties type each field.
#[pyclass(module = "ntoseye", frozen, subclass)]
pub struct BaseRecord {
    fields: Py<PyDict>,
    /// Fields that are addresses, rendered as hex by `__repr__`.
    hex: Vec<&'static str>,
}

/// An immutable, ordered set of named fields with attribute access.
#[pyclass(module = "ntoseye", frozen, extends = BaseRecord)]
pub struct Record;

impl Record {
    pub fn new(fields: Py<PyDict>, hex: Vec<&'static str>) -> PyClassInitializer<Self> {
        PyClassInitializer::from(BaseRecord::new(fields, hex)).add_subclass(Record)
    }
}

#[pymethods]
impl Record {
    fn __getattr__<'py>(slf: &Bound<'py, Self>, name: &str) -> PyResult<Bound<'py, PyAny>> {
        let fields = slf.as_super().get().fields.bind(slf.py());
        fields.get_item(name)?.ok_or_else(|| {
            let known: Vec<String> = fields.keys().iter().map(|k| k.to_string()).collect();
            PyAttributeError::new_err(format!("no field '{name}'; fields: {}", known.join(", ")))
        })
    }
}

impl BaseRecord {
    pub fn new(fields: Py<PyDict>, hex: Vec<&'static str>) -> Self {
        Self { fields, hex }
    }

    /// Field `name`, or `None` when the record leaves it out.
    pub fn field<'py>(&self, py: Python<'py>, name: &str) -> PyResult<Bound<'py, PyAny>> {
        Ok(self
            .fields
            .bind(py)
            .get_item(name)?
            .unwrap_or_else(|| py.None().into_bound(py)))
    }
}

#[pymethods]
impl BaseRecord {
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
        let other = match other.cast::<BaseRecord>() {
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

    fn __repr__(slf: &Bound<'_, Self>) -> PyResult<String> {
        let this = slf.get();
        let mut parts = Vec::new();
        for (key, value) in this.fields.bind(slf.py()).iter() {
            let key = key.extract::<String>()?;
            let shown = if this.hex.contains(&key.as_str()) && !value.is_none() {
                format!("{:#x}", value.extract::<u64>()?)
            } else {
                summarize(&value)?
            };
            parts.push(format!("{key}={shown}"));
        }
        Ok(format!("{}({})", slf.get_type().name()?, parts.join(", ")))
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

/// The package's generic `Diagnostic` class, which fields that can fail to
/// read on their own are built as.
pub(crate) fn diagnostic_class(py: Python<'_>) -> PyResult<&Bound<'_, PyAny>> {
    cached(py, &DIAGNOSTIC, "Diagnostic")
}

// Records and diagnostics share one rendering (`_summary`, `_plain`), which
// lives beside `Diagnostic` because that is Python.
static DIAGNOSTIC: PyOnceLock<Py<PyAny>> = PyOnceLock::new();
static SUMMARY: PyOnceLock<Py<PyAny>> = PyOnceLock::new();
static PLAIN: PyOnceLock<Py<PyAny>> = PyOnceLock::new();

fn cached<'py>(
    py: Python<'py>,
    cell: &'static PyOnceLock<Py<PyAny>>,
    name: &str,
) -> PyResult<&'py Bound<'py, PyAny>> {
    Ok(cell
        .get_or_try_init(py, || package_attr(py, name).map(Bound::unbind))?
        .bind(py))
}

/// A one-line rendering for `__repr__`: scalars in full, containers by size,
/// so a record with a 700-thread list stays readable.
fn summarize(value: &Bound<'_, PyAny>) -> PyResult<String> {
    cached(value.py(), &SUMMARY, "_summary")?
        .call1((value,))?
        .extract()
}

/// `value` with records and diagnostics converted to dicts throughout.
fn plain<'py>(value: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyAny>> {
    cached(value.py(), &PLAIN, "_plain")?.call1((value,))
}
