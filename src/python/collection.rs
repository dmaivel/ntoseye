//! The runtime of `#[collection]` (the `ntoseye-macros` crate): the typed
//! iterator its `__iter__` returns, the key that also takes a record, and
//! the errors for a missing key or index.

use std::convert::Infallible;
use std::marker::PhantomData;

use pyo3::IntoPyObjectExt;
#[cfg(feature = "python-stubs")]
use pyo3::inspect::{PyStaticExpr, PyStaticOperator};
use pyo3::prelude::*;
use pyo3::types::{PyIterator, PyList};
#[cfg(feature = "python-stubs")]
use pyo3::{PyTypeInfo, type_hint_identifier, type_hint_subscript};

use super::handle::Handle;
use super::record::RecordClass;

/// An iterator over a snapshot of `T`s, typed `Iterator[T]` in the stub:
/// what a collection's `__iter__` returns, and a record's (its keys).
pub struct Iter<'py, T>(Bound<'py, PyIterator>, PhantomData<fn() -> T>);

impl<'py, T: IntoPyObject<'py>> Iter<'py, T> {
    pub fn new(py: Python<'py>, items: impl IntoIterator<Item = T>) -> PyResult<Self> {
        Ok(Self(PyList::new(py, items)?.try_iter()?, PhantomData))
    }
}

impl<'py, T: IntoPyObject<'py>> IntoPyObject<'py> for Iter<'py, T> {
    type Target = PyIterator;
    type Output = Bound<'py, PyIterator>;
    type Error = Infallible;

    #[cfg(feature = "python-stubs")]
    const OUTPUT_TYPE: PyStaticExpr = type_hint_subscript!(
        type_hint_identifier!("collections.abc", "Iterator"),
        T::OUTPUT_TYPE
    );

    fn into_pyobject(self, _py: Python<'py>) -> Result<Self::Output, Self::Error> {
        Ok(self.0)
    }
}

/// A key of a collection of `H` handles: the collection's own key `K`
/// (a PID, a name), or a record of `H`'s kind (`stop.thread`), which names
/// the listed item it describes.
pub enum Key<'py, K, H: Handle> {
    Own(K),
    Record(Bound<'py, <H::Record as RecordClass>::Class>),
}

impl<'a, 'py, K, H> FromPyObject<'a, 'py> for Key<'py, K, H>
where
    K: FromPyObject<'a, 'py>,
    K::Error: Into<PyErr>,
    H: Handle,
{
    type Error = PyErr;

    #[cfg(feature = "python-stubs")]
    const INPUT_TYPE: PyStaticExpr = PyStaticExpr::BinOp {
        left: &K::INPUT_TYPE,
        op: PyStaticOperator::BitOr,
        right: &<<H::Record as RecordClass>::Class as PyTypeInfo>::TYPE_HINT,
    };

    fn extract(obj: Borrowed<'a, 'py, PyAny>) -> PyResult<Self> {
        if let Ok(record) = obj.cast::<<H::Record as RecordClass>::Class>() {
            return Ok(Key::Record(record.to_owned()));
        }
        obj.extract().map(Key::Own).map_err(Into::into)
    }
}

impl<'py, K: IntoPyObject<'py>, H: Handle> IntoPyObject<'py> for Key<'py, K, H> {
    type Target = PyAny;
    type Output = Bound<'py, PyAny>;
    type Error = PyErr;

    fn into_pyobject(self, py: Python<'py>) -> PyResult<Self::Output> {
        match self {
            Key::Own(key) => key.into_bound_py_any(py),
            Key::Record(record) => Ok(record.into_any()),
        }
    }
}

/// The handle in `items` that `record` describes.
pub fn described<H: Handle>(
    py: Python<'_>,
    items: Vec<H>,
    record: &Bound<'_, PyAny>,
) -> PyResult<Option<H>> {
    for item in items {
        if item.describes(py, record)? {
            return Ok(Some(item));
        }
    }
    Ok(None)
}

/// The `KeyError` for `key`, which no item has.
pub fn missing<'py>(py: Python<'py>, key: impl IntoPyObject<'py>) -> PyErr {
    match key.into_bound_py_any(py) {
        Ok(key) => pyo3::exceptions::PyKeyError::new_err(key.unbind()),
        Err(error) => error,
    }
}

/// A Python sequence index (negative counts from the end) into `len` items.
pub fn sequence_index(index: isize, len: usize) -> Option<usize> {
    let index = if index < 0 {
        len.checked_sub(index.unsigned_abs())?
    } else {
        index.unsigned_abs()
    };
    (index < len).then_some(index)
}

#[cfg(test)]
mod tests {
    use super::sequence_index;

    #[test]
    fn sequence_index_counts_negative_indexes_from_the_end() {
        assert_eq!(sequence_index(0, 4), Some(0));
        assert_eq!(sequence_index(3, 4), Some(3));
        assert_eq!(sequence_index(-1, 4), Some(3));
        assert_eq!(sequence_index(-4, 4), Some(0));
        assert_eq!(sequence_index(4, 4), None);
        assert_eq!(sequence_index(-5, 4), None);
        assert_eq!(sequence_index(0, 0), None);
    }
}
