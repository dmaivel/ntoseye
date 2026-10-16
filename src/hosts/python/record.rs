//! The SDK's results: how a `#[record]` (the `ntoseye-macros` crate)
//! renders for Python, the type each field has in the stub, and the classes
//! results are built as. Every record is its own [`BaseRecord`] subclass with
//! a property per field (`frame.ip`, `thread.state_name`), every keyed map a
//! `dict`, and every field that can fail to read on its own the package's
//! generic `Diagnostic` (`peb.ldr.value`, `if peb.ldr:`). Records are values,
//! like frozen dataclasses, not containers: `to_dict()` walks the fields by
//! name.
//!
//! ```text
//! /// A capability-list entry.            <- the class's docs
//! #[record]
//! pub struct PciCapability {
//!     /// Its offset in configuration space.   <- the property's docs
//!     #[record(hex)]
//!     pub offset: u16,
//!     pub name: Option<&'static str>,
//! }
//! ```
//!
//! **Fields.** A field's Rust type and its mode ([`Plain`], or [`Hex`] and
//! [`Bytes`] from `#[record(hex)]` and `#[record(bytes)]`) choose its
//! [`ToValue`] impl, which fixes how it renders ([`ToValue::to_value`], a
//! [`Value`] tree) and its SDK type ([`ToValue::HINT`], which the stub
//! prints). The scalars, `Option`, `Vec`, `Box`, [`DiagnosticValue`],
//! [`DiagnosticMetric`], [`Keyed`], records and record enums are the only
//! `ToValue`s, all implemented in this file (the last two by the macro).
//! Each impl's `HINT` must name the Python type [`to_py`] makes of its
//! value; the `hints` test below checks each one with no guest (a new form
//! needs a field there), and `python/tests/test_stub_types.py` checks real
//! results on a live one.
//!
//! **What `#[record]` generates.** For each record: its `ToValue` impl,
//! which renders every field, in order, as a [`Value::Record`]; the SDK
//! class `<Name>Py` (Python name `Name`), a [`BaseRecord`] subclass with one
//! typed property per field and `__match_args__`, which [`to_py`] wraps the
//! fields in. A `tagged` enum's class is a base, with a final subclass per
//! variant nested in it ([`Variants`]). SDK methods return `Typed<'py, T>`,
//! whose `T` types the method in the stub.
//!
//! **How classes reach the SDK.** `build.rs` walks the crate's module tree
//! from `src/lib.rs` and lists every class (a record struct or `tagged`
//! enum, a `#[handle]`, a `#[pyclass]`) in `with_sdk_classes!`, which
//! wraps the `#[pymodule]` in
//! `python/mod.rs` and adds one `#[pymodule_export] use` per class, under
//! the `cfg`s of the modules on its path. PyO3 exports only named `use`
//! items, and the stub lists only exported classes; so a new class needs
//! nothing else. A variant class is not exported: it is its base's.

use std::convert::Infallible;
use std::marker::PhantomData;

use pyo3::IntoPyObjectExt;
use pyo3::exceptions::PyKeyError;
#[cfg(feature = "python-stubs")]
use pyo3::inspect::{PyStaticExpr, PyStaticOperator};
use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
#[cfg(feature = "python-stubs")]
use pyo3::types::PyString;
use pyo3::types::{PyBytes, PyDict, PyList, PyTuple};
#[cfg(feature = "python-stubs")]
use pyo3::{PyTypeInfo, type_hint_identifier, type_hint_subscript};

use super::package_attr;
use crate::base::types::{Keyed, VirtAddr};
use crate::nt::target::{DiagnosticMetric, DiagnosticValue};

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

/// An immutable result, the base of every typed result class
/// (`PciFunction`, ...), whose properties are its fields. Like a frozen
/// dataclass, it compares and hashes by class and fields, matches by
/// `__match_args__` (its fields, in order) and is not a container; use
/// `to_dict()` to walk the fields by name.
#[pyclass(module = "ntoseye", frozen, subclass)]
pub struct BaseRecord {
    fields: Py<PyDict>,
    /// Fields that are addresses, rendered as hex by `__repr__`.
    hex: Vec<&'static str>,
}

impl BaseRecord {
    pub fn new(fields: Py<PyDict>, hex: Vec<&'static str>) -> Self {
        Self { fields, hex }
    }

    /// Field `name`; a `KeyError` when the record has no such field.
    pub fn field<'py>(&self, py: Python<'py>, name: &str) -> PyResult<Bound<'py, PyAny>> {
        self.fields
            .bind(py)
            .get_item(name)?
            .ok_or_else(|| PyKeyError::new_err(name.to_string()))
    }
}

/// Field `name` of `record`, an instance of a record class: what a
/// generated property returns.
pub fn field<'py>(record: &Bound<'py, PyAny>, name: &str) -> PyResult<Bound<'py, PyAny>> {
    record.cast::<BaseRecord>()?.get().field(record.py(), name)
}

#[pymethods]
impl BaseRecord {
    /// Equal to a record of the same class with equal fields.
    fn __eq__(slf: &Bound<'_, Self>, other: &Bound<'_, PyAny>) -> PyResult<bool> {
        if !slf.get_type().is(other.get_type()) {
            return Ok(false);
        }
        let other = other.cast::<BaseRecord>()?;
        slf.get()
            .fields
            .bind(slf.py())
            .eq(other.get().fields.bind(slf.py()))
    }

    /// The hash of the class and the fields; a `TypeError` when a field is
    /// unhashable (a `list`), as for a frozen dataclass.
    fn __hash__(slf: &Bound<'_, Self>) -> PyResult<isize> {
        let values = PyTuple::new(slf.py(), slf.get().fields.bind(slf.py()).values())?;
        (slf.get_type(), values).into_pyobject(slf.py())?.hash()
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
        Ok(format!(
            "{}({})",
            slf.get_type().qualname()?,
            parts.join(", ")
        ))
    }

    /// A plain nested `dict`, with all records and diagnostics converted, for
    /// serializing or comparing a result.
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

/// A node in the value tree the SDK builds its results from.
pub enum Value {
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
    List(Vec<Value>),
    /// An ordered key/value object (insertion order is preserved on render).
    Object(Vec<(&'static str, Value)>),
    /// A `#[record]`: rendered as an [`Object`](Self::Object), and as its
    /// own class in the SDK.
    Record(RecordFields),
    /// A value that can fail to read on its own: an `ntoseye.Diagnostic`, or
    /// `{available, value, error}` in plain form.
    Diagnostic(Box<Diagnosed>),
}

pub struct Diagnosed {
    pub value: Option<Value>,
    pub error: Option<String>,
    /// `Some` for a metric, whose provenance is part of the value even when
    /// unknown (`source: null`).
    pub source: Option<Option<String>>,
}

/// How [`to_py`] renders objects and diagnostics.
#[derive(Clone, Copy)]
pub enum PyStyle {
    /// Record classes and `ntoseye.Diagnostic`s, with attribute access.
    Records,
    /// Plain `dict`s throughout, the shape `to_dict()` returns: a diagnostic
    /// becomes `{available, value, error[, source]}`.
    Plain,
}

/// Render a [`Value`] to a Python object (the SDK): addresses become plain ints.
pub fn to_py<'py>(py: Python<'py>, v: &Value, style: PyStyle) -> PyResult<Bound<'py, PyAny>> {
    Ok(match v {
        Value::Hex(n) | Value::Num(n) => n.into_bound_py_any(py)?,
        Value::Int(n) => n.into_bound_py_any(py)?,
        Value::Bool(b) => b.into_bound_py_any(py)?,
        Value::Str(s) => s.as_str().into_bound_py_any(py)?,
        Value::Bytes(bytes) => PyBytes::new(py, bytes).into_any(),
        Value::Null => py.None().into_bound(py),
        Value::List(items) => {
            let list = PyList::empty(py);
            for item in items {
                list.append(to_py(py, item, style)?)?;
            }
            list.into_any()
        }
        Value::Object(fields) | Value::Record(RecordFields { fields, .. }) => {
            let dict = PyDict::new(py);
            let mut hex = Vec::new();
            for (key, val) in fields {
                if matches!(val, Value::Hex(_)) {
                    hex.push(*key);
                }
                dict.set_item(key, to_py(py, val, style)?)?;
            }
            match v {
                Value::Record(record) if matches!(style, PyStyle::Records) => {
                    (record.class)(py, BaseRecord::new(dict.unbind(), hex))?
                }
                _ => dict.into_any(),
            }
        }
        Value::Diagnostic(diagnostic) => {
            let value = match &diagnostic.value {
                Some(value) => to_py(py, value, style)?,
                None => py.None().into_bound(py),
            };
            match style {
                PyStyle::Records => diagnostic_class(py)?.call1((
                    value,
                    diagnostic.error.as_deref(),
                    diagnostic.source.as_ref().and_then(Option::as_deref),
                    diagnostic.source.is_some(),
                    matches!(diagnostic.value, Some(Value::Hex(_))),
                ))?,
                PyStyle::Plain => {
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

/// How a value of this type renders in mode `M`, and its SDK type there.
pub trait ToValue<M = Plain> {
    fn to_value(&self) -> Value;

    /// The type the field's SDK property returns, for the stub.
    #[cfg(feature = "python-stubs")]
    const HINT: PyStaticExpr;
}

/// A field as it is: numbers are ints, addresses ints the SDK's `repr`
/// shows in hex.
pub enum Plain {}

/// `#[record(hex)]`: integers (a register, ID, or flags value) the SDK's
/// `repr` shows in hex.
pub enum Hex {}

/// `#[record(bytes)]`: a `Vec<u8>` is Python `bytes`.
pub enum Bytes {}

/// The computed properties a `#[record] impl` block adds to its record.
pub trait RecordImpl {
    fn computed(&self, fields: &mut Vec<(&'static str, Value)>);
}

/// Wraps a record's fields' [`BaseRecord`] in the record's class.
pub type Wrap = for<'py> fn(Python<'py>, BaseRecord) -> PyResult<Bound<'py, PyAny>>;

/// A `tagged` record enum: which variant a value is, and that variant's
/// fields and class, a subclass of the enum's class or of the record
/// struct that holds it in a `#[record(flatten)]` field (its `base`).
pub trait Variants {
    /// A type whose hint is the `Literal` of the variants' kinds.
    type Kind: ToValue;
    fn kind(&self) -> &'static str;
    fn payload(&self, fields: &mut Vec<(&'static str, Value)>);
    fn class(&self) -> Wrap;
}

/// A record struct's SDK class (`<Name>Py`), which `#[record]` names.
pub trait RecordClass {
    type Class: pyo3::PyTypeInfo;
}

/// A class `build.rs` found and exported from the SDK module. `#[record]`
/// and `#[handle]` require it of their class (outside tests), so a class
/// the walk cannot see fails to compile rather than go missing from the
/// module.
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not exported from the SDK module: build.rs did not find it",
    note = "build.rs reads the source from src/lib.rs: write `#[record]` or `#[handle]` on the \
            item itself, not through `cfg_attr` or a `macro_rules!`, in a module it can reach"
)]
pub trait ExportedClass {}

/// `T`'s class is exported (see [`ExportedClass`]).
pub const fn exported<T: ExportedClass>() {}

/// Property `N` of a record struct: the Rust type of its value and its
/// mode. A `#[handle]` on the record names its properties' types through
/// this, since the types are written in the record's module.
pub trait Field<const N: usize> {
    type Type: ToValue<Self::Mode>;
    type Mode;
}

macro_rules! scalars {
    ($mode:ty: $($t:ty => |$v:ident| $value:expr, $hint:literal;)*) => {$(
        impl ToValue<$mode> for $t {
            fn to_value(&self) -> Value {
                let $v = *self;
                $value
            }
            #[cfg(feature = "python-stubs")]
            const HINT: PyStaticExpr = type_hint_identifier!("builtins", $hint);
        }
    )*};
}
scalars! { Plain:
    u8 => |v| Value::Num(v.into()), "int";
    u16 => |v| Value::Num(v.into()), "int";
    u32 => |v| Value::Num(v.into()), "int";
    u64 => |v| Value::Num(v), "int";
    usize => |v| Value::Num(v as u64), "int";
    i16 => |v| Value::Int(v.into()), "int";
    i32 => |v| Value::Int(v.into()), "int";
    i64 => |v| Value::Int(v), "int";
    // Holds both signed values and full-width `u64` ones (an operand that is
    // either an immediate or a branch target).
    i128 => |v| i64::try_from(v).map_or(Value::Num(v as u64), Value::Int), "int";
    VirtAddr => |v| Value::Hex(v.0), "int";
    bool => |v| Value::Bool(v), "bool";
    &'static str => |v| Value::Str(v.to_string()), "str";
}
scalars! { Hex:
    u8 => |v| Value::Hex(v.into()), "int";
    u16 => |v| Value::Hex(v.into()), "int";
    u32 => |v| Value::Hex(v.into()), "int";
    u64 => |v| Value::Hex(v), "int";
    usize => |v| Value::Hex(v as u64), "int";
    VirtAddr => |v| Value::Hex(v.0), "int";
}

impl ToValue for String {
    fn to_value(&self) -> Value {
        Value::Str(self.clone())
    }
    #[cfg(feature = "python-stubs")]
    const HINT: PyStaticExpr = type_hint_identifier!("builtins", "str");
}

impl ToValue<Bytes> for Vec<u8> {
    fn to_value(&self) -> Value {
        Value::Bytes(self.clone())
    }
    #[cfg(feature = "python-stubs")]
    const HINT: PyStaticExpr = type_hint_identifier!("builtins", "bytes");
}

/// An action that reports nothing (`Debugger.select_partition`): `None`.
impl ToValue for () {
    fn to_value(&self) -> Value {
        Value::Null
    }
    #[cfg(feature = "python-stubs")]
    const HINT: PyStaticExpr = type_hint_identifier!("builtins", "None");
}

impl<M, T: ToValue<M>> ToValue<M> for Keyed<T> {
    fn to_value(&self) -> Value {
        Value::Object(
            self.0
                .iter()
                .map(|(key, value)| (*key, value.to_value()))
                .collect(),
        )
    }
    /// `dict[str, T]`, in the order of the pairs.
    #[cfg(feature = "python-stubs")]
    const HINT: PyStaticExpr = type_hint_subscript!(
        PyDict::TYPE_HINT,
        type_hint_identifier!("builtins", "str"),
        T::HINT
    );
}

impl<M, T: ToValue<M>> ToValue<M> for Option<T> {
    fn to_value(&self) -> Value {
        self.as_ref().map_or(Value::Null, T::to_value)
    }
    /// `T | None`, or `T`'s own hint when that already ends in `| None`
    /// (`Option<Option<T>>`, a tagged enum's optional field).
    #[cfg(feature = "python-stubs")]
    const HINT: PyStaticExpr = if is_optional(&T::HINT) {
        T::HINT
    } else {
        PyStaticExpr::BinOp {
            left: &T::HINT,
            op: PyStaticOperator::BitOr,
            right: &type_hint_identifier!("builtins", "None"),
        }
    };
}

/// Whether `hint` is a union whose last member is `None`, as an `Option`'s.
#[cfg(feature = "python-stubs")]
const fn is_optional(hint: &PyStaticExpr) -> bool {
    let PyStaticExpr::BinOp {
        op: PyStaticOperator::BitOr,
        right: PyStaticExpr::Name { id },
        ..
    } = hint
    else {
        return false;
    };
    let (id, none) = (id.as_bytes(), b"None");
    if id.len() != none.len() {
        return false;
    }
    let mut index = 0;
    while index < id.len() {
        if id[index] != none[index] {
            return false;
        }
        index += 1;
    }
    true
}

impl<M, T: ToValue<M>> ToValue<M> for Vec<T> {
    fn to_value(&self) -> Value {
        Value::List(self.iter().map(T::to_value).collect())
    }
    #[cfg(feature = "python-stubs")]
    const HINT: PyStaticExpr =
        type_hint_subscript!(type_hint_identifier!("builtins", "list"), T::HINT);
}

impl<M, T: ToValue<M>> ToValue<M> for Box<T> {
    fn to_value(&self) -> Value {
        T::to_value(self)
    }
    #[cfg(feature = "python-stubs")]
    const HINT: PyStaticExpr = T::HINT;
}

/// A fixed-size array: a `list`, as a `Vec`.
impl<M, T: ToValue<M>, const N: usize> ToValue<M> for [T; N] {
    fn to_value(&self) -> Value {
        Value::List(self.iter().map(T::to_value).collect())
    }
    #[cfg(feature = "python-stubs")]
    const HINT: PyStaticExpr = <Vec<T> as ToValue<M>>::HINT;
}

fn diagnostic<M, T: ToValue<M>>(
    value: &DiagnosticValue<T>,
    source: Option<Option<String>>,
) -> Value {
    let (value, error) = match value {
        DiagnosticValue::Available(value) => (Some(value.to_value()), None),
        DiagnosticValue::Unavailable(error) => (None, Some(error.clone())),
    };
    Value::Diagnostic(Box::new(Diagnosed {
        value,
        error,
        source,
    }))
}

impl<M, T: ToValue<M>> ToValue<M> for DiagnosticValue<T> {
    fn to_value(&self) -> Value {
        diagnostic(self, None)
    }
    /// `ntoseye.Diagnostic[T]`: the package declares `Diagnostic` in Python,
    /// generic over its value.
    #[cfg(feature = "python-stubs")]
    const HINT: PyStaticExpr =
        type_hint_subscript!(type_hint_identifier!("ntoseye", "Diagnostic"), T::HINT);
}

/// A [`DiagnosticValue`] that also names where the value came from
/// (`source`, possibly unknown).
impl<M, T: ToValue<M>> ToValue<M> for DiagnosticMetric<T> {
    fn to_value(&self) -> Value {
        let source = self.source.map(|source| source.to_string());
        diagnostic(&self.value, Some(source))
    }
    #[cfg(feature = "python-stubs")]
    const HINT: PyStaticExpr = <DiagnosticValue<T> as ToValue<M>>::HINT;
}

/// A record's fields in order, and the SDK class it becomes.
pub struct RecordFields {
    pub fields: Vec<(&'static str, Value)>,
    /// Wraps the fields' [`BaseRecord`] in the record's class.
    pub class: Wrap,
}

/// A value as the SDK returns it (records for its objects), typed for the
/// stub as `T` declares in mode `M` ([`ToValue::HINT`]): what an SDK method
/// or a record's property returns.
pub struct Typed<'py, T, M = Plain>(Bound<'py, PyAny>, PhantomData<(fn() -> T, M)>);

impl<'py, T: ToValue<M>, M> Typed<'py, T, M> {
    pub fn new(py: Python<'py>, value: T) -> PyResult<Self> {
        Self::of(py, &value)
    }

    /// [`Self::new`] of a value the caller keeps.
    pub fn of(py: Python<'py>, value: &T) -> PyResult<Self> {
        let object = to_py(py, &value.to_value(), PyStyle::Records)?;
        Ok(Self(object, PhantomData))
    }

    /// A value already converted, such as a record's field.
    pub fn converted(object: Bound<'py, PyAny>) -> Self {
        Self(object, PhantomData)
    }

    pub fn into_bound(self) -> Bound<'py, PyAny> {
        self.0
    }
}

impl<'py, T: ToValue<M>, M> IntoPyObject<'py> for Typed<'py, T, M> {
    type Target = PyAny;
    type Output = Bound<'py, PyAny>;
    type Error = Infallible;

    #[cfg(feature = "python-stubs")]
    const OUTPUT_TYPE: PyStaticExpr = T::HINT;

    fn into_pyobject(self, _py: Python<'py>) -> Result<Self::Output, Self::Error> {
        Ok(self.0)
    }
}

#[cfg(test)]
mod tests {
    use ntoseye_macros::record;

    use super::*;

    #[record]
    pub struct Sample {
        pub r#type: &'static str,
        pub address: VirtAddr,
        #[record(hex)]
        pub id: u16,
        pub null: Option<String>,
        pub read: DiagnosticValue<VirtAddr>,
        pub failed: DiagnosticValue<VirtAddr>,
        #[record(rename = "items")]
        pub work_items: u8,
        #[record(skip)]
        #[allow(dead_code)] // Rust only: the test checks it is not rendered
        pub hidden: u8,
    }

    #[test]
    fn record_renders_as_the_object_it_declares() {
        let sample = Sample {
            r#type: "port",
            address: VirtAddr(0x1000),
            id: 0x1f,
            null: None,
            read: DiagnosticValue::Available(VirtAddr(0x20)),
            failed: DiagnosticValue::unavailable("paged out"),
            work_items: 1,
            hidden: 2,
        };
        let Value::Record(record) = ToValue::<Plain>::to_value(&sample) else {
            panic!("a record renders as Value::Record");
        };
        let keys: Vec<&str> = record.fields.iter().map(|(key, _)| *key).collect();
        assert_eq!(
            keys,
            ["type", "address", "id", "null", "read", "failed", "items"]
        );
        assert!(matches!(record.fields[2].1, Value::Hex(0x1f)));
    }
}

/// Every [`ToValue`] against its `HINT`, with no guest: one record holds a
/// field of each kind, and the SDK must hand back for each field a value of
/// the type its hint (which the stub prints) declares. Needs `python-stubs`,
/// which compiles the hints.
#[cfg(all(test, feature = "python-stubs", feature = "python-embed"))]
mod hints {
    use ntoseye_macros::record;
    use pyo3::types::PyDict;

    use super::*;
    use crate::backend::debugger_data::MetadataSource;

    #[record]
    pub struct Inner {
        pub id: u8,
    }

    #[record]
    pub enum Either {
        Number(u8),
        Nested(Inner),
        Flags(#[record(hex)] u32),
    }

    #[record]
    pub enum Color {
        Red,
        #[record(rename = "dark blue")]
        DarkBlue,
    }

    #[record(tagged)]
    pub enum End {
        Head,
        Cycle(#[record(rename = "address")] VirtAddr),
        Corrupt { error: String },
    }

    /// Declares `Every` with the fields given (and their attributes),
    /// `every()` building it from their values, and `hints()` naming each
    /// field's hint in its mode, then the computed property's, then a
    /// nested record's (a dotted path).
    macro_rules! every {
        ($($(#[$attr:meta])* $field:ident: $ty:ty [$mode:ty] = $value:expr),* $(,)?) => {
            #[record(impl)]
            pub struct Every {
                $($(#[$attr])* pub $field: $ty,)*
                #[record(skip)]
                #[allow(dead_code)]
                pub hidden: u8,
            }

            fn every() -> Every {
                Every { $($field: $value,)* hidden: 0 }
            }

            fn hints() -> Vec<(&'static str, String)> {
                let mut hints = vec![$((stringify!($field), <$ty as ToValue<$mode>>::HINT.to_string())),*];
                hints.push(("computed", <Option<u64> as ToValue<Hex>>::HINT.to_string()));
                hints.push(("end_cycle.kind", <__EndRecordKind as ToValue>::HINT.to_string()));
                hints
            }
        };
    }

    every! {
        unsigned: u64 [Plain] = 1,
        signed: i32 [Plain] = -1,
        address: VirtAddr [Plain] = VirtAddr(0x1000),
        #[record(hex)] hex: u16 [Hex] = 0x1f,
        flag: bool [Plain] = true,
        text: String [Plain] = "text".into(),
        name: &'static str [Plain] = "name",
        absent: Option<u8> [Plain] = None,
        present: Option<u8> [Plain] = Some(1),
        nested_option: Option<Option<u8>> [Plain] = Some(None),
        unit: () [Plain] = (),
        list: Vec<Inner> [Plain] = vec![Inner { id: 1 }],
        #[record(hex)] array: [u64; 2] [Hex] = [1, 2],
        boxed: Box<Inner> [Plain] = Box::new(Inner { id: 2 }),
        nested: Inner [Plain] = Inner { id: 3 },
        read: DiagnosticValue<VirtAddr> [Plain] = DiagnosticValue::Available(VirtAddr(0x20)),
        read_none: DiagnosticValue<Option<String>> [Plain] = DiagnosticValue::Available(None),
        failed: DiagnosticValue<Vec<Inner>> [Plain] = DiagnosticValue::unavailable("paged out"),
        sourced: DiagnosticMetric<u64> [Plain] = DiagnosticMetric {
            value: DiagnosticValue::Available(5),
            source: Some(MetadataSource::KernelSymbol),
        },
        unsourced: DiagnosticMetric<u64> [Plain] = DiagnosticMetric {
            value: DiagnosticValue::Available(6),
            source: None,
        },
        #[record(hex)] keyed: Keyed<DiagnosticValue<u64>> [Hex] =
            Keyed(vec![("a", DiagnosticValue::Available(7))]),
        #[record(bytes)] raw: DiagnosticValue<Vec<u8>> [Bytes] =
            DiagnosticValue::Available(vec![1, 2, 3]),
        number: Either [Plain] = Either::Number(8),
        either_nested: Either [Plain] = Either::Nested(Inner { id: 9 }),
        either_hex: Either [Plain] = Either::Flags(0x10),
        color: Color [Plain] = Color::Red,
        renamed_color: Color [Plain] = Color::DarkBlue,
        end_head: End [Plain] = End::Head,
        end_cycle: End [Plain] = End::Cycle(VirtAddr(0x30)),
        end_corrupt: End [Plain] = End::Corrupt { error: "bad link".into() },
        #[record(rename = "items")] work_items: u8 [Plain] = 2,
    }

    #[record]
    impl Every {
        /// A computed property.
        #[record(getter, hex)]
        pub fn computed(&self) -> Option<u64> {
            Some(self.unsigned + 1)
        }
    }

    #[test]
    fn every_field_holds_the_type_its_hint_declares() {
        Python::attach(|py| -> PyResult<()> {
            let globals = PyDict::new(py);
            globals.set_item("value", Typed::<Every>::new(py, every())?.into_bound())?;
            globals.set_item("again", Typed::<Every>::new(py, every())?.into_bound())?;
            globals.set_item("HINTS", hints())?;
            let source = format!(
                "{}\n{}",
                include_str!("../../../python/tests/stubcheck.py"),
                r#"
RENAMED = {"work_items": "items"}
checker = Checker({})
for name, hint in HINTS:
    field = value
    for part in name.split("."):
        field = getattr(field, RENAMED.get(part, part))
    checker.value(field, ast.parse(hint, mode="eval").body, name)
assert checker.errors == [], checker.errors
fields = value.to_dict()
assert len(fields) == len([name for name, _ in HINTS if "." not in name]), fields.keys()
assert "hidden" not in fields and "work_items" not in fields and "items" in fields, fields.keys()
assert value.items == 2 and not hasattr(value, "__getitem__") and not hasattr(value, "__len__"), value
assert value.color == "red" and value.renamed_color == "dark blue", value
assert value.computed == 2, value.computed
assert dict(HINTS)["nested_option"] == "int | None", dict(HINTS)["nested_option"]
assert dict(HINTS)["keyed"] == "builtins.dict[str, ntoseye.Diagnostic[int]]", dict(HINTS)["keyed"]
assert list(value.keyed) == ["a"] and value.keyed["a"].value == 7, value.keyed
End = type(value.end_head).__mro__[1]
assert End.__qualname__ == "End" and type(value.end_cycle).__qualname__ == "End.Cycle", type(value.end_cycle)
assert isinstance(value.end_head, End.Head) and value.end_head.kind == "head", value.end_head
assert not hasattr(value.end_head, "address"), value.end_head
assert value.end_cycle.kind == "cycle" and value.end_cycle.address == 0x30, value.end_cycle
assert End.Cycle.__match_args__ == ("address",), End.Cycle.__match_args__
match value.end_cycle:
    case End.Cycle(address):
        assert address == 0x30, address
    case _:
        raise AssertionError(value.end_cycle)
assert value.end_corrupt.error == "bad link", value.end_corrupt
assert value.list[0] != value.nested and value.nested.id == 3, (value.list, value.nested)
assert again.nested == value.nested and hash(again.nested) == hash(value.nested), value.nested
assert checker.forms >= {"class", "variant", "dict", "available", "unavailable", "source", "Literal"}, checker.forms
color = ast.parse(dict(HINTS)["color"], mode="eval").body
assert not checker.value("blue", color, "blue") and checker.errors, "a Literal admits only its texts"
"#
            );
            let code = std::ffi::CString::new(source).unwrap();
            py.run(&code, Some(&globals), None)
        })
        .unwrap();
    }
}
