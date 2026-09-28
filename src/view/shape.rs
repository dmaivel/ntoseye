//! Declared result shapes: one Rust struct per [`View`] object, declared with
//! [`shapes!`], renders the same JSON (MCP) and dict (`to_dict()`) as a
//! hand-built [`View::Object`], and is also a typed SDK class: a
//! [`BaseRecord`] subclass with one property per field, which the generated
//! stub types. Unlike `Record`, it has no catch-all `__getattr__`, so a type
//! checker flags a misspelt field.
//!
//! [`BaseRecord`]: crate::python::record::BaseRecord

use std::marker::PhantomData;

use super::{DiagnosticView, View};
use crate::target::{DiagnosticMetric, DiagnosticValue};
use crate::types::VirtAddr;

/// A type a shape's field is declared with: how the field renders, and the
/// value a builder supplies for it ([`Self::Source`]). The declaration is
/// the one place a field's presentation is stated: a field declared
/// `Hex<u16>` takes the `u16` itself, one declared `Diag<VirtAddr>` takes the
/// `DiagnosticValue<VirtAddr>` the target read.
pub trait ViewValue {
    /// What a builder supplies for a field of this type.
    type Source;

    fn view(source: Self::Source) -> View;

    /// The field as its object holds it; `None` leaves the field out.
    fn field(source: Self::Source) -> Option<View> {
        Some(Self::view(source))
    }

    /// The type the field's SDK property returns, for the stub.
    #[cfg(feature = "python-stubs")]
    const HINT: pyo3::inspect::PyStaticExpr;
}

/// A number shown in hex (a register, ID, or flags value): a `0x` string in
/// JSON, an int the SDK's `repr` shows in hex. Addresses are declared
/// [`VirtAddr`], which renders the same way.
pub struct Hex<T = u64>(PhantomData<T>);

/// A field left out of its object when `None`, rather than rendered `null`.
/// Its SDK property returns `None` then.
pub struct Omit<T>(PhantomData<T>);

/// A field that reads on its own and can fail: `{available, value, error}`
/// in JSON, a `Diagnostic` in the SDK. Takes the [`DiagnosticValue`] read.
pub struct Diag<T>(PhantomData<T>);

/// A [`Diag`] that also names where the value came from (`source`, possibly
/// unknown). Takes the [`DiagnosticMetric`] read.
pub struct Metric<T>(PhantomData<T>);

/// An object whose keys are data, not a schema (fields a Windows build may
/// or may not have): a JSON object, and in the SDK a `Record`, whose
/// attributes are its keys. Takes the `(key, value)` pairs.
pub struct Keyed<T>(PhantomData<T>);

macro_rules! scalars {
    ($($t:ty => |$v:ident| $view:expr, $hint:literal;)*) => {$(
        impl ViewValue for $t {
            type Source = Self;
            fn view($v: Self) -> View {
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
    i16 => |v| View::Int(v.into()), "int";
    i32 => |v| View::Int(v.into()), "int";
    i64 => |v| View::Int(v), "int";
    VirtAddr => |v| View::Hex(v.0), "int";
    bool => |v| View::Bool(v), "bool";
    String => |v| View::Str(v), "str";
    &'static str => |v| View::Str(v.to_string()), "str";
}

impl<T: Into<u64>> ViewValue for Hex<T> {
    type Source = T;
    fn view(value: T) -> View {
        View::Hex(value.into())
    }
    #[cfg(feature = "python-stubs")]
    const HINT: pyo3::inspect::PyStaticExpr = pyo3::type_hint_identifier!("builtins", "int");
}

impl<T: ViewValue> ViewValue for Keyed<T> {
    type Source = Vec<(&'static str, T::Source)>;
    fn view(fields: Self::Source) -> View {
        View::Object(
            fields
                .into_iter()
                .map(|(key, value)| (key, T::view(value)))
                .collect(),
        )
    }
    #[cfg(feature = "python-stubs")]
    const HINT: pyo3::inspect::PyStaticExpr =
        <crate::python::record::Record as pyo3::PyTypeInfo>::TYPE_HINT;
}

impl<T: ViewValue> ViewValue for Option<T> {
    type Source = Option<T::Source>;
    fn view(value: Self::Source) -> View {
        value.map_or(View::Null, T::view)
    }
    #[cfg(feature = "python-stubs")]
    const HINT: pyo3::inspect::PyStaticExpr =
        hint_union!(T::HINT, pyo3::type_hint_identifier!("builtins", "None"));
}

impl<T: ViewValue> ViewValue for Omit<T> {
    type Source = Option<T::Source>;
    fn view(value: Self::Source) -> View {
        <Option<T>>::view(value)
    }
    fn field(value: Self::Source) -> Option<View> {
        value.map(T::view)
    }
    #[cfg(feature = "python-stubs")]
    const HINT: pyo3::inspect::PyStaticExpr = <Option<T>>::HINT;
}

impl<T: ViewValue> ViewValue for Vec<T> {
    type Source = Vec<T::Source>;
    fn view(items: Self::Source) -> View {
        View::List(items.into_iter().map(T::view).collect())
    }
    #[cfg(feature = "python-stubs")]
    const HINT: pyo3::inspect::PyStaticExpr =
        pyo3::type_hint_subscript!(pyo3::type_hint_identifier!("builtins", "list"), T::HINT);
}

impl<T: ViewValue> ViewValue for Box<T> {
    type Source = Box<T::Source>;
    fn view(value: Self::Source) -> View {
        T::view(*value)
    }
    fn field(value: Self::Source) -> Option<View> {
        T::field(*value)
    }
    #[cfg(feature = "python-stubs")]
    const HINT: pyo3::inspect::PyStaticExpr = T::HINT;
}

fn diagnostic<T: ViewValue>(
    value: DiagnosticValue<T::Source>,
    source: Option<Option<String>>,
) -> View {
    let (value, error) = match value {
        DiagnosticValue::Available(value) => (Some(T::view(value)), None),
        DiagnosticValue::Unavailable(error) => (None, Some(error)),
    };
    View::Diagnostic(Box::new(DiagnosticView {
        value,
        error,
        source,
    }))
}

impl<T: ViewValue> ViewValue for Diag<T> {
    type Source = DiagnosticValue<T::Source>;
    fn view(value: Self::Source) -> View {
        diagnostic::<T>(value, None)
    }
    #[cfg(feature = "python-stubs")]
    const HINT: pyo3::inspect::PyStaticExpr =
        <crate::python::record::Diagnostic as pyo3::PyTypeInfo>::TYPE_HINT;
}

impl<T: ViewValue> ViewValue for Metric<T> {
    type Source = DiagnosticMetric<T::Source>;
    fn view(metric: Self::Source) -> View {
        let source = metric.source.map(|source| source.to_string());
        diagnostic::<T>(metric.value, Some(source))
    }
    #[cfg(feature = "python-stubs")]
    const HINT: pyo3::inspect::PyStaticExpr = <Diag<T>>::HINT;
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

/// A value as the SDK returns it (records for its objects), typed for the
/// stub as `T` declares ([`ViewValue::HINT`]): what an SDK method or a
/// shape's property returns.
#[cfg(feature = "python")]
pub struct Typed<'py, T>(pyo3::Bound<'py, pyo3::PyAny>, std::marker::PhantomData<T>);

#[cfg(feature = "python")]
impl<'py, T: ViewValue> Typed<'py, T> {
    pub fn new(py: pyo3::Python<'py>, value: T::Source) -> pyo3::PyResult<Self> {
        let object = super::to_py(py, &T::view(value), super::PyShape::Records)?;
        Ok(Self(object, std::marker::PhantomData))
    }

    /// A value already converted, such as a record's field.
    pub(crate) fn converted(object: pyo3::Bound<'py, pyo3::PyAny>) -> Self {
        Self(object, std::marker::PhantomData)
    }

    pub fn into_bound(self) -> pyo3::Bound<'py, pyo3::PyAny> {
        self.0
    }
}

#[cfg(feature = "python")]
impl<'py, T: ViewValue> pyo3::IntoPyObject<'py> for Typed<'py, T> {
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
/// [`into_view`](ViewValue::view) it) and, in the SDK, a same-named
/// `BaseRecord` subclass in the invoking module's `py` submodule, with a
/// property per field. A field's declared type says how it renders; the
/// struct holds what its builder supplies ([`ViewValue::Source`]). Doc comments on the struct and its fields document the class and
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
        $crate::view::shape::shapes!(@classes [$] $($name)*);

        $(
            $(#[doc = $doc])*
            pub struct $name {
                $(
                    $(#[doc = $field_doc])*
                    pub $field: <$ty as $crate::view::shape::ViewValue>::Source,
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
                    <Self as $crate::view::shape::ViewValue>::view(self)
                }

                /// This shape as its SDK class, for a handle Rust keeps.
                #[cfg(feature = "python")]
                #[allow(dead_code)] // most shapes only reach Python as `Typed`
                pub fn into_class<'py>(
                    self,
                    py: pyo3::Python<'py>,
                ) -> pyo3::PyResult<pyo3::Bound<'py, py::$name>> {
                    let typed = $crate::view::shape::Typed::<Self>::new(py, self)?;
                    Ok(typed.into_bound().cast_into::<py::$name>()?)
                }
            }

            impl $crate::view::shape::ViewValue for $name {
                type Source = Self;
                fn view(shape: Self) -> $crate::view::View {
                    let mut fields = Vec::new();
                    $(
                        if let Some(value) =
                            <$ty as $crate::view::shape::ViewValue>::field(shape.$field)
                        {
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
                    ) -> pyo3::PyResult<$crate::view::shape::Typed<'py, $ty>> {
                        let key = $crate::view::shape::key!($field $(, $key)?);
                        Ok($crate::view::shape::Typed::converted(
                            slf.as_super().get().field(slf.py(), key)?,
                        ))
                    }
                )*
                $($($method)*)?
            }
        )*
    };
    // Every module that declares shapes names its classes through
    // `shape_classes!`, which `view::with_shape_classes!` collects into the
    // SDK module's exports. `$d` is a `$` for the macro it defines.
    (@classes [$d:tt] $($name:ident)*) => {
        #[cfg(feature = "python")]
        #[allow(unused_macros)] // a test module's shapes join no SDK module
        macro_rules! shape_classes {
            ($d callback:path; $d($d args:tt)*) => { $d callback! { $d($d args)* [$($name)*] } };
        }
        #[cfg(feature = "python")]
        #[allow(unused_imports)]
        pub(crate) use shape_classes;
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
                $variant(<$ty as $crate::view::shape::ViewValue>::Source),
            )+
        }

        impl $crate::view::shape::ViewValue for $name {
            type Source = Self;
            fn view(value: Self) -> $crate::view::View {
                match value {
                    $(Self::$variant(value) => <$ty as $crate::view::shape::ViewValue>::view(value),)+
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
            address: VirtAddr,
            id: Hex<u16>,
            missing: Omit<u8>,
            present: Omit<u8>,
            null: Option<String>,
            read: Diag<VirtAddr>,
            failed: Diag<VirtAddr>,
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
            address: VirtAddr(0x1000),
            id: 0x1f,
            missing: None,
            present: Some(3),
            null: None,
            read: DiagnosticValue::Available(VirtAddr(0x20)),
            failed: DiagnosticValue::Unavailable("paged out".into()),
            work_items: 1,
        };
        let View::Shaped(shaped) = sample.into_view() else {
            panic!("a shape renders as View::Shaped");
        };
        let keys: Vec<&str> = shaped.fields.iter().map(|(key, _)| *key).collect();
        assert_eq!(
            keys,
            [
                "type", "address", "id", "present", "null", "read", "failed", "items"
            ]
        );
        assert_eq!(
            to_json(&View::Shaped(shaped)),
            serde_json::json!({
                "type": "port",
                "address": "0x1000",
                "id": "0x1f",
                "present": 3,
                "null": null,
                "read": {"available": true, "value": "0x20", "error": null},
                "failed": {"available": false, "value": null, "error": "paged out"},
                "items": 1,
            })
        );
    }
}
