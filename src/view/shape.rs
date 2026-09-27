//! Declared result shapes: one Rust struct per [`View`] object, declared with
//! [`shapes!`], renders the same JSON (MCP) and dict (`to_dict()`) as a
//! hand-built [`View::Object`], and is also a typed SDK class: a
//! [`BaseRecord`] subclass with one property per field, which the generated
//! stub types. Unlike `Record`, it has no catch-all `__getattr__`, so a type
//! checker flags a misspelt field.
//!
//! [`BaseRecord`]: crate::python::record::BaseRecord

use super::{DiagnosticView, View};
use crate::target::{DiagnosticMetric, DiagnosticValue};

/// A value a declared shape's field can hold, and how each surface shows it.
pub trait ViewValue: Sized {
    fn into_view(self) -> View;

    /// The field as its object holds it; `None` leaves the field out.
    fn into_field(self) -> Option<View> {
        Some(self.into_view())
    }

    /// The type the field's SDK property returns, for the stub.
    #[cfg(feature = "python-stubs")]
    const HINT: pyo3::inspect::PyStaticExpr;
}

/// An address, pointer, or register value: a `0x` hex string in JSON, an int
/// shown as hex by the SDK's `repr`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hex(pub u64);

/// A field left out of its object when `None`, rather than rendered `null`.
/// Its SDK property returns `None` then.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Omit<T>(pub Option<T>);

/// A field that reads on its own and can fail: `{available, value, error}`
/// in JSON (plus `source` for a metric), a `Diagnostic` in the SDK.
#[derive(Debug)]
pub struct Diag<T> {
    value: Option<T>,
    error: Option<String>,
    source: Option<Option<String>>,
}

impl<T> Diag<T> {
    /// A field read as `value`, encoded by `encode` when available.
    pub fn of<U>(value: &DiagnosticValue<U>, encode: impl FnOnce(&U) -> T) -> Self {
        let (value, error) = match value {
            DiagnosticValue::Available(value) => (Some(encode(value)), None),
            DiagnosticValue::Unavailable(error) => (None, Some(error.clone())),
        };
        Self {
            value,
            error,
            source: None,
        }
    }

    /// A metric, which also names where it came from (`source`, possibly
    /// unknown).
    pub fn metric<U>(metric: &DiagnosticMetric<U>, encode: impl FnOnce(&U) -> T) -> Self {
        Self {
            source: Some(metric.source.map(|source| source.to_string())),
            ..Self::of(&metric.value, encode)
        }
    }
}

macro_rules! scalars {
    ($($t:ty => |$v:ident| $view:expr, $hint:literal;)*) => {$(
        impl ViewValue for $t {
            fn into_view(self) -> View {
                let $v = self;
                $view
            }
            #[cfg(feature = "python-stubs")]
            const HINT: pyo3::inspect::PyStaticExpr = pyo3::type_hint_identifier!("builtins", $hint);
        }
    )*};
}
scalars! {
    u8 => |v| View::Num(v.into()), "int";
    u16 => |v| View::Num(v.into()), "int";
    u32 => |v| View::Num(v.into()), "int";
    u64 => |v| View::Num(v), "int";
    usize => |v| View::Num(v as u64), "int";
    i64 => |v| View::Int(v), "int";
    Hex => |v| View::Hex(v.0), "int";
    bool => |v| View::Bool(v), "bool";
    String => |v| View::Str(v), "str";
    &'static str => |v| View::Str(v.to_string()), "str";
}

/// An object not (yet) declared as a shape, or one whose keys are data
/// (register names, ...): passed through as is, typed `Any`.
impl ViewValue for View {
    fn into_view(self) -> View {
        self
    }
    #[cfg(feature = "python-stubs")]
    const HINT: pyo3::inspect::PyStaticExpr = pyo3::type_hint_identifier!("typing", "Any");
}

impl<T: ViewValue> ViewValue for Option<T> {
    fn into_view(self) -> View {
        self.map_or(View::Null, T::into_view)
    }
    #[cfg(feature = "python-stubs")]
    const HINT: pyo3::inspect::PyStaticExpr =
        hint_union!(T::HINT, pyo3::type_hint_identifier!("builtins", "None"));
}

impl<T: ViewValue> ViewValue for Omit<T> {
    fn into_view(self) -> View {
        self.0.into_view()
    }
    fn into_field(self) -> Option<View> {
        self.0.map(T::into_view)
    }
    #[cfg(feature = "python-stubs")]
    const HINT: pyo3::inspect::PyStaticExpr = <Option<T>>::HINT;
}

impl<T: ViewValue> ViewValue for Vec<T> {
    fn into_view(self) -> View {
        View::List(self.into_iter().map(T::into_view).collect())
    }
    #[cfg(feature = "python-stubs")]
    const HINT: pyo3::inspect::PyStaticExpr =
        pyo3::type_hint_subscript!(pyo3::type_hint_identifier!("builtins", "list"), T::HINT);
}

impl<T: ViewValue> ViewValue for Box<T> {
    fn into_view(self) -> View {
        (*self).into_view()
    }
    fn into_field(self) -> Option<View> {
        (*self).into_field()
    }
    #[cfg(feature = "python-stubs")]
    const HINT: pyo3::inspect::PyStaticExpr = T::HINT;
}

impl<T: ViewValue> ViewValue for Diag<T> {
    fn into_view(self) -> View {
        View::Diagnostic(Box::new(DiagnosticView {
            value: self.value.map(T::into_view),
            error: self.error,
            source: self.source,
        }))
    }
    #[cfg(feature = "python-stubs")]
    const HINT: pyo3::inspect::PyStaticExpr =
        <crate::python::record::Diagnostic as pyo3::PyTypeInfo>::TYPE_HINT;
}

/// A declared object: its fields in order, and the SDK class it becomes.
pub struct Shaped {
    pub fields: Vec<(&'static str, View)>,
    /// Wraps the fields' [`BaseRecord`](crate::python::record::BaseRecord)
    /// in the shape's class.
    #[cfg(feature = "python")]
    pub class: for<'py> fn(
        pyo3::Python<'py>,
        crate::python::record::BaseRecord,
    ) -> pyo3::PyResult<pyo3::Bound<'py, pyo3::PyAny>>,
}

/// A field's value as its SDK property returns it: the object the record
/// holds, typed for the stub as the field's [`ViewValue::HINT`].
#[cfg(feature = "python")]
pub struct Field<'py, T>(
    pub pyo3::Bound<'py, pyo3::PyAny>,
    pub std::marker::PhantomData<T>,
);

#[cfg(feature = "python")]
impl<'py, T: ViewValue> pyo3::IntoPyObject<'py> for Field<'py, T> {
    type Target = pyo3::PyAny;
    type Output = pyo3::Bound<'py, pyo3::PyAny>;
    type Error = std::convert::Infallible;

    #[cfg(feature = "python-stubs")]
    const OUTPUT_TYPE: pyo3::inspect::PyStaticExpr = T::HINT;

    fn into_pyobject(self, _py: pyo3::Python<'py>) -> Result<Self::Output, Self::Error> {
        Ok(self.0)
    }
}

/// The key of a field declared as `$field`: a raw identifier (`r#type`)
/// without its `r#`.
pub const fn field_key(name: &'static str) -> &'static str {
    match name.as_bytes() {
        [b'r', b'#', rest @ ..] => match std::str::from_utf8(rest) {
            Ok(key) => key,
            Err(_) => panic!("field name is not UTF-8"),
        },
        _ => name,
    }
}

/// Whether a property named `name` would hide a `BaseRecord` method or is a
/// Python keyword, which no attribute access can name.
pub const fn is_reserved_property(name: &str) -> bool {
    const RESERVED: [&str; 40] = [
        "keys", "values", "items", "get", "to_dict", "False", "None", "True", "and", "as",
        "assert", "async", "await", "break", "class", "continue", "def", "del", "elif", "else",
        "except", "finally", "for", "from", "global", "if", "import", "in", "is", "lambda",
        "nonlocal", "not", "or", "pass", "raise", "return", "try", "while", "with", "yield",
    ];
    let name = name.as_bytes();
    let mut index = 0;
    while index < RESERVED.len() {
        let reserved = RESERVED[index].as_bytes();
        if reserved.len() == name.len() {
            let mut at = 0;
            while at < name.len() && name[at] == reserved[at] {
                at += 1;
            }
            if at == name.len() {
                return true;
            }
        }
        index += 1;
    }
    false
}

/// Declare result shapes: each becomes a plain struct (build it, then
/// [`ViewValue::into_view`] it) and, in the SDK, a same-named `BaseRecord`
/// subclass in the invoking module's `py` submodule, with a property per
/// field. Doc comments on the struct and its fields document the class and
/// properties. A field named like a `BaseRecord` method (`keys`, `values`,
/// `items`, `get`, `to_dict`) or a Python keyword (`class`, `from`, ...) is a
/// compile error: give it another name and keep its key with `=> "items"`
/// after the type (`work_items: Vec<T> =>
/// "items"`). Write a keyword as a raw identifier (`r#type`), whose key
/// drops the `r#`. Methods after a `;` following the fields join the
/// class's `#[pymethods]` (`fn __str__(slf: &Bound<'_, Self>) -> ...`), for
/// behavior a record lacks; they resolve names beside the shapes.
macro_rules! shapes {
    ($(
        $(#[doc = $doc:literal])*
        $name:ident {
            $(
                $(#[doc = $field_doc:literal])*
                $field:ident: $ty:ty $(=> $key:literal)?
            ),* $(,)?
            $(; $($method:tt)*)?
        }
    )*) => {
        $(
            $(#[doc = $doc])*
            pub struct $name {
                $(
                    $(#[doc = $field_doc])*
                    pub $field: $ty,
                )*
            }

            $(
                const _: () = assert!(
                    !$crate::view::shape::is_reserved_property(
                        $crate::view::shape::field_key(stringify!($field))
                    ),
                    concat!(
                        "field `",
                        stringify!($field),
                        "` would hide a BaseRecord method or is a Python keyword"
                    ),
                );
            )*

            impl $name {
                /// Render this shape (see [`ViewValue`]); inherent so callers
                /// need no trait import.
                ///
                /// [`ViewValue`]: $crate::view::shape::ViewValue
                pub fn into_view(self) -> $crate::view::View {
                    $crate::view::shape::ViewValue::into_view(self)
                }
            }

            impl $crate::view::shape::ViewValue for $name {
                fn into_view(self) -> $crate::view::View {
                    let mut fields = Vec::new();
                    $(
                        if let Some(value) = $crate::view::shape::ViewValue::into_field(self.$field) {
                            fields.push(($crate::view::shape::key!($field $(, $key)?), value));
                        }
                    )*
                    $crate::view::View::Shaped($crate::view::shape::Shaped {
                        fields,
                        #[cfg(feature = "python")]
                        class: py::$name::wrap,
                    })
                }
                #[cfg(feature = "python-stubs")]
                const HINT: pyo3::inspect::PyStaticExpr =
                    <py::$name as pyo3::PyTypeInfo>::TYPE_HINT;
            }
        )*

        /// The SDK classes of this module's shapes. Only the classes live
        /// here; their methods are implemented beside the shapes, where the
        /// field types resolve.
        #[cfg(feature = "python")]
        pub mod py {
            $(
                $(#[doc = $doc])*
                #[pyo3::pyclass(module = "ntoseye", frozen, extends = $crate::python::record::BaseRecord)]
                pub struct $name;
            )*
        }

        $(
            #[cfg(feature = "python")]
            impl py::$name {
                pub fn wrap<'py>(
                    py: pyo3::Python<'py>,
                    record: $crate::python::record::BaseRecord,
                ) -> pyo3::PyResult<pyo3::Bound<'py, pyo3::PyAny>> {
                    let init = pyo3::PyClassInitializer::from(record).add_subclass(py::$name);
                    Ok(pyo3::Bound::new(py, init)?.into_any())
                }
            }

            #[cfg(feature = "python")]
            #[pyo3::pymethods]
            impl py::$name {
                $(
                    $(#[doc = $field_doc])*
                    #[getter]
                    fn $field<'py>(
                        slf: &pyo3::Bound<'py, Self>,
                    ) -> pyo3::PyResult<$crate::view::shape::Field<'py, $ty>> {
                        let key = $crate::view::shape::key!($field $(, $key)?);
                        Ok($crate::view::shape::Field(
                            slf.as_super().get().field(slf.py(), key)?,
                            std::marker::PhantomData,
                        ))
                    }
                )*
                $($($method)*)?
            }
        )*
    };
}
pub(crate) use shapes;

/// Declare fields that hold one of several kinds of value: each becomes an
/// enum whose variants wrap a [`ViewValue`] (usually a shape), rendered as
/// the variant's value and typed as the union of the variants' types.
macro_rules! unions {
    ($(
        $(#[doc = $doc:literal])*
        $name:ident {
            $(
                $(#[doc = $variant_doc:literal])*
                $variant:ident($ty:ty)
            ),+ $(,)?
        }
    )*) => {$(
        $(#[doc = $doc])*
        pub enum $name {
            $(
                $(#[doc = $variant_doc])*
                $variant($ty),
            )+
        }

        impl $crate::view::shape::ViewValue for $name {
            fn into_view(self) -> $crate::view::View {
                match self {
                    $(Self::$variant(value) => $crate::view::shape::ViewValue::into_view(value),)+
                }
            }
            #[cfg(feature = "python-stubs")]
            const HINT: pyo3::inspect::PyStaticExpr = $crate::view::shape::hint_union!(
                $(<$ty as $crate::view::shape::ViewValue>::HINT),+
            );
        }
    )*};
}
pub(crate) use unions;

/// `A | B | ...` of type hints (pyo3's `type_hint_union!` recurses by its
/// unqualified name, so it only works where imported).
#[cfg(feature = "python-stubs")]
macro_rules! hint_union {
    ($hint:expr) => { $hint };
    ($left:expr, $($rest:expr),+) => {
        pyo3::inspect::PyStaticExpr::BinOp {
            left: &$left,
            op: pyo3::inspect::PyStaticOperator::BitOr,
            right: &$crate::view::shape::hint_union!($($rest),+),
        }
    };
}
#[cfg(feature = "python-stubs")]
pub(crate) use hint_union;

/// A declared field's key: the one given with `=> "key"`, else its name.
macro_rules! key {
    ($field:ident) => {
        $crate::view::shape::field_key(stringify!($field))
    };
    ($field:ident, $key:literal) => {
        $key
    };
}
pub(crate) use key;

#[cfg(all(test, feature = "mcp"))]
mod tests {
    use super::*;
    use crate::target::DiagnosticValue;
    use crate::view::to_json;

    shapes! {
        Sample {
            r#type: &'static str,
            address: Hex,
            missing: Omit<u8>,
            present: Omit<u8>,
            null: Option<String>,
            read: Diag<Hex>,
            failed: Diag<Hex>,
            work_items: u8 => "items";
            fn __str__(slf: &pyo3::Bound<'_, Self>) -> pyo3::PyResult<String> {
                Ok(slf.as_super().get().field(slf.py(), "type")?.to_string())
            }
        }
    }

    #[test]
    fn shape_renders_as_the_object_it_declares() {
        let sample = Sample {
            r#type: "port",
            address: Hex(0x1000),
            missing: Omit(None),
            present: Omit(Some(3)),
            null: None,
            read: Diag::of(&DiagnosticValue::Available(0x20u64), |v| Hex(*v)),
            failed: Diag::of(
                &DiagnosticValue::<u64>::Unavailable("paged out".into()),
                |v| Hex(*v),
            ),
            work_items: 1,
        };
        let View::Shaped(shaped) = sample.into_view() else {
            panic!("a shape renders as View::Shaped");
        };
        let keys: Vec<&str> = shaped.fields.iter().map(|(key, _)| *key).collect();
        assert_eq!(
            keys,
            [
                "type", "address", "present", "null", "read", "failed", "items"
            ]
        );
        assert_eq!(
            to_json(&View::Shaped(shaped)),
            serde_json::json!({
                "type": "port",
                "address": "0x1000",
                "present": 3,
                "null": null,
                "read": {"available": true, "value": "0x20", "error": null},
                "failed": {"available": false, "value": null, "error": "paged out"},
                "items": 1,
            })
        );
    }
}
