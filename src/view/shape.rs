//! Declared result shapes: one Rust struct per [`View`] object, declared with
//! [`shapes!`], renders the same JSON (MCP) and dict (`to_dict()`) as a
//! hand-built [`View::Object`], and is also a typed SDK class: a
//! [`BaseRecord`] subclass with one property per field, which the generated
//! stub types. Unlike `Record`, it has no catch-all `__getattr__`, so a type
//! checker flags a misspelt field.
//!
//! [`BaseRecord`]: crate::python::record::BaseRecord

use super::View;
#[cfg(feature = "python-stubs")]
use pyo3::type_hint_union;

/// A value a declared shape's field can hold, and how each surface shows it.
pub trait ViewValue {
    fn view(&self) -> View;

    /// The field as its object holds it; `None` leaves the field out.
    fn field(&self) -> Option<View> {
        Some(self.view())
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

macro_rules! counts {
    ($($t:ty),*) => {$(
        impl ViewValue for $t {
            fn view(&self) -> View {
                View::Num((*self).into())
            }
            #[cfg(feature = "python-stubs")]
            const HINT: pyo3::inspect::PyStaticExpr = pyo3::type_hint_identifier!("builtins", "int");
        }
    )*};
}
counts!(u8, u16, u32, u64);

impl ViewValue for i64 {
    fn view(&self) -> View {
        View::Int(*self)
    }
    #[cfg(feature = "python-stubs")]
    const HINT: pyo3::inspect::PyStaticExpr = pyo3::type_hint_identifier!("builtins", "int");
}

impl ViewValue for Hex {
    fn view(&self) -> View {
        View::Hex(self.0)
    }
    #[cfg(feature = "python-stubs")]
    const HINT: pyo3::inspect::PyStaticExpr = pyo3::type_hint_identifier!("builtins", "int");
}

impl ViewValue for bool {
    fn view(&self) -> View {
        View::Bool(*self)
    }
    #[cfg(feature = "python-stubs")]
    const HINT: pyo3::inspect::PyStaticExpr = pyo3::type_hint_identifier!("builtins", "bool");
}

impl ViewValue for String {
    fn view(&self) -> View {
        View::Str(self.clone())
    }
    #[cfg(feature = "python-stubs")]
    const HINT: pyo3::inspect::PyStaticExpr = pyo3::type_hint_identifier!("builtins", "str");
}

impl ViewValue for &'static str {
    fn view(&self) -> View {
        View::Str((*self).to_string())
    }
    #[cfg(feature = "python-stubs")]
    const HINT: pyo3::inspect::PyStaticExpr = pyo3::type_hint_identifier!("builtins", "str");
}

impl<T: ViewValue> ViewValue for Option<T> {
    fn view(&self) -> View {
        self.as_ref().map_or(View::Null, T::view)
    }
    #[cfg(feature = "python-stubs")]
    const HINT: pyo3::inspect::PyStaticExpr =
        type_hint_union!(T::HINT, pyo3::type_hint_identifier!("builtins", "None"));
}

impl<T: ViewValue> ViewValue for Omit<T> {
    fn view(&self) -> View {
        self.0.view()
    }
    fn field(&self) -> Option<View> {
        self.0.as_ref().map(T::view)
    }
    #[cfg(feature = "python-stubs")]
    const HINT: pyo3::inspect::PyStaticExpr = <Option<T>>::HINT;
}

impl<T: ViewValue> ViewValue for Vec<T> {
    fn view(&self) -> View {
        View::List(self.iter().map(T::view).collect())
    }
    #[cfg(feature = "python-stubs")]
    const HINT: pyo3::inspect::PyStaticExpr =
        pyo3::type_hint_subscript!(pyo3::type_hint_identifier!("builtins", "list"), T::HINT);
}

/// A declared object: its fields in order, and the SDK class it becomes.
pub struct Shaped {
    pub fields: Vec<(&'static str, View)>,
    /// Wraps the fields' [`BaseRecord`](crate::python::record::BaseRecord) in the
    /// shape's class.
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

/// Declare result shapes: each becomes a plain struct (build it, then
/// [`ViewValue::view`] it) and, in the SDK, a same-named `BaseRecord` subclass in
/// the invoking module's `py` submodule, with a property per field. Doc
/// comments on the struct and its fields document the class and properties.
/// Field names must not be `BaseRecord` methods (`keys`, `values`, `items`,
/// `get`, `to_dict`).
macro_rules! shapes {
    ($(
        $(#[doc = $doc:literal])*
        $name:ident {
            $(
                $(#[doc = $field_doc:literal])*
                $field:ident: $ty:ty
            ),* $(,)?
        }
    )*) => {
        $(
            $(#[doc = $doc])*
            #[derive(Debug, Clone)]
            pub struct $name {
                $(
                    $(#[doc = $field_doc])*
                    pub $field: $ty,
                )*
            }

            impl $crate::view::shape::ViewValue for $name {
                fn view(&self) -> $crate::view::View {
                    let mut fields = Vec::new();
                    $(
                        if let Some(value) = $crate::view::shape::ViewValue::field(&self.$field) {
                            fields.push((stringify!($field), value));
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
                        Ok($crate::view::shape::Field(
                            slf.as_super().get().field(slf.py(), stringify!($field))?,
                            std::marker::PhantomData,
                        ))
                    }
                )*
            }
        )*
    };
}
pub(crate) use shapes;
