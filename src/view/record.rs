//! The runtime of `#[record]` (the `ntoseye-macros` crate): how a record's
//! fields render for the SDK, and the type each one has in the stub.
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
//! [`ToView`] impl, which fixes how it renders ([`ToView::to_view`]) and its
//! SDK type ([`ToView::HINT`], which the stub prints). The scalars, `Option`,
//! `Vec`, `Box`, [`DiagnosticValue`], [`DiagnosticMetric`], [`Keyed`],
//! records and record enums are the only `ToView`s, all implemented in this
//! file (the last two by the macro). Each impl's `HINT` must name the Python
//! type `view::to_py` makes of its view; the `hints` test below checks each
//! one with no guest (a new form needs a field there), and
//! `python/tests/test_stub_types.py` checks real results on a live one.
//!
//! **What `#[record]` generates.** For each record: its `ToView` impl, which
//! renders every field, in order, as a [`View::Shaped`]; the SDK class
//! `<Name>Py` (Python name `Name`), a [`BaseRecord`] subclass with one typed
//! property per field, which `view::to_py` wraps the fields in. SDK methods
//! return `Typed<'py, T>`, whose `T` types the method in the stub.
//!
//! **How classes reach the SDK.** `build.rs` walks the crate's module tree
//! from `src/lib.rs` and lists every record class (a struct, or a `tagged`
//! enum) in `with_record_classes!`, which wraps the `#[pymodule]` in
//! `python/mod.rs` and adds one `#[pymodule_export] use` per class, under
//! the `cfg`s of the modules on its path. PyO3 exports only named `use`
//! items, and the stub lists only exported classes; so a new record needs
//! nothing else.
//!
//! [`BaseRecord`]: crate::python::record::BaseRecord

use std::marker::PhantomData;

use pyo3::IntoPyObject;
#[cfg(feature = "python-stubs")]
use pyo3::inspect::{PyStaticExpr, PyStaticOperator};
use pyo3::{Bound, PyAny, PyResult, Python};
#[cfg(feature = "python-stubs")]
use pyo3::{type_hint_identifier, type_hint_subscript};

use super::{DiagnosticView, PyShape, View, to_py};
use crate::python::record::BaseRecord;
use crate::target::{DiagnosticMetric, DiagnosticValue};
use crate::types::{Keyed, VirtAddr};

/// How a value of this type renders in mode `M`, and its SDK type there.
pub trait ToView<M = Plain> {
    fn to_view(&self) -> View;

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
    fn computed(&self, fields: &mut Vec<(&'static str, View)>);
}

macro_rules! scalars {
    ($mode:ty: $($t:ty => |$v:ident| $view:expr, $hint:literal;)*) => {$(
        impl ToView<$mode> for $t {
            fn to_view(&self) -> View {
                let $v = *self;
                $view
            }
            #[cfg(feature = "python-stubs")]
            const HINT: PyStaticExpr = type_hint_identifier!("builtins", $hint);
        }
    )*};
}
scalars! { Plain:
    u8 => |v| View::Num(v.into()), "int";
    u16 => |v| View::Num(v.into()), "int";
    u32 => |v| View::Num(v.into()), "int";
    u64 => |v| View::Num(v), "int";
    usize => |v| View::Num(v as u64), "int";
    i16 => |v| View::Int(v.into()), "int";
    i32 => |v| View::Int(v.into()), "int";
    i64 => |v| View::Int(v), "int";
    // Holds both signed values and full-width `u64` ones (an operand that is
    // either an immediate or a branch target).
    i128 => |v| i64::try_from(v).map_or(View::Num(v as u64), View::Int), "int";
    VirtAddr => |v| View::Hex(v.0), "int";
    bool => |v| View::Bool(v), "bool";
    &'static str => |v| View::Str(v.to_string()), "str";
}
scalars! { Hex:
    u8 => |v| View::Hex(v.into()), "int";
    u16 => |v| View::Hex(v.into()), "int";
    u32 => |v| View::Hex(v.into()), "int";
    u64 => |v| View::Hex(v), "int";
    usize => |v| View::Hex(v as u64), "int";
    VirtAddr => |v| View::Hex(v.0), "int";
}

impl ToView for String {
    fn to_view(&self) -> View {
        View::Str(self.clone())
    }
    #[cfg(feature = "python-stubs")]
    const HINT: PyStaticExpr = type_hint_identifier!("builtins", "str");
}

impl ToView<Bytes> for Vec<u8> {
    fn to_view(&self) -> View {
        View::Bytes(self.clone())
    }
    #[cfg(feature = "python-stubs")]
    const HINT: PyStaticExpr = type_hint_identifier!("builtins", "bytes");
}

impl<M, T: ToView<M>> ToView<M> for Keyed<T> {
    fn to_view(&self) -> View {
        View::Object(
            self.0
                .iter()
                .map(|(key, value)| (*key, value.to_view()))
                .collect(),
        )
    }
    #[cfg(feature = "python-stubs")]
    const HINT: PyStaticExpr = <crate::python::record::Record as pyo3::PyTypeInfo>::TYPE_HINT;
}

impl<M, T: ToView<M>> ToView<M> for Option<T> {
    fn to_view(&self) -> View {
        self.as_ref().map_or(View::Null, T::to_view)
    }
    #[cfg(feature = "python-stubs")]
    const HINT: PyStaticExpr = PyStaticExpr::BinOp {
        left: &T::HINT,
        op: PyStaticOperator::BitOr,
        right: &type_hint_identifier!("builtins", "None"),
    };
}

impl<M, T: ToView<M>> ToView<M> for Vec<T> {
    fn to_view(&self) -> View {
        View::List(self.iter().map(T::to_view).collect())
    }
    #[cfg(feature = "python-stubs")]
    const HINT: PyStaticExpr =
        type_hint_subscript!(type_hint_identifier!("builtins", "list"), T::HINT);
}

impl<M, T: ToView<M>> ToView<M> for Box<T> {
    fn to_view(&self) -> View {
        T::to_view(self)
    }
    #[cfg(feature = "python-stubs")]
    const HINT: PyStaticExpr = T::HINT;
}

/// A fixed-size array: a `list`, as a `Vec`.
impl<M, T: ToView<M>, const N: usize> ToView<M> for [T; N] {
    fn to_view(&self) -> View {
        View::List(self.iter().map(T::to_view).collect())
    }
    #[cfg(feature = "python-stubs")]
    const HINT: PyStaticExpr = <Vec<T> as ToView<M>>::HINT;
}

fn diagnostic<M, T: ToView<M>>(value: &DiagnosticValue<T>, source: Option<Option<String>>) -> View {
    let (value, error) = match value {
        DiagnosticValue::Available(value) => (Some(value.to_view()), None),
        DiagnosticValue::Unavailable(error) => (None, Some(error.clone())),
    };
    View::Diagnostic(Box::new(DiagnosticView {
        value,
        error,
        source,
    }))
}

impl<M, T: ToView<M>> ToView<M> for DiagnosticValue<T> {
    fn to_view(&self) -> View {
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
impl<M, T: ToView<M>> ToView<M> for DiagnosticMetric<T> {
    fn to_view(&self) -> View {
        let source = self.source.map(|source| source.to_string());
        diagnostic(&self.value, Some(source))
    }
    #[cfg(feature = "python-stubs")]
    const HINT: PyStaticExpr = <DiagnosticValue<T> as ToView<M>>::HINT;
}

/// A record's fields in order, and the SDK class it becomes.
pub struct Shaped {
    pub fields: Vec<(&'static str, View)>,
    /// Wraps the fields' [`BaseRecord`] in the record's class.
    pub class: for<'py> fn(Python<'py>, BaseRecord) -> PyResult<Bound<'py, PyAny>>,
}

/// A value as the SDK returns it (records for its objects), typed for the
/// stub as `T` declares in mode `M` ([`ToView::HINT`]): what an SDK method
/// or a record's property returns.
pub struct Typed<'py, T, M = Plain>(Bound<'py, PyAny>, PhantomData<(fn() -> T, M)>);

impl<'py, T: ToView<M>, M> Typed<'py, T, M> {
    pub fn new(py: Python<'py>, value: T) -> PyResult<Self> {
        Self::of(py, &value)
    }

    /// [`Self::new`] of a value the caller keeps.
    pub fn of(py: Python<'py>, value: &T) -> PyResult<Self> {
        let object = to_py(py, &value.to_view(), PyShape::Records)?;
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

impl<'py, T: ToView<M>, M> IntoPyObject<'py> for Typed<'py, T, M> {
    type Target = PyAny;
    type Output = Bound<'py, PyAny>;
    type Error = std::convert::Infallible;

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
        let View::Shaped(shaped) = ToView::<Plain>::to_view(&sample) else {
            panic!("a record renders as View::Shaped");
        };
        let keys: Vec<&str> = shaped.fields.iter().map(|(key, _)| *key).collect();
        assert_eq!(
            keys,
            ["type", "address", "id", "null", "read", "failed", "items"]
        );
        assert!(matches!(shaped.fields[2].1, View::Hex(0x1f)));
    }
}

/// Every [`ToView`] against its `HINT`, with no guest: one record holds a
/// field of each kind, and the SDK must hand back for each field a value of
/// the type its hint (which the stub prints) declares. Needs `python-stubs`,
/// which compiles the hints.
#[cfg(all(test, feature = "python-stubs", feature = "python-embed"))]
mod hints {
    use std::fmt;

    use ntoseye_macros::record;
    use pyo3::prelude::*;
    use pyo3::types::PyDict;

    use super::*;
    use crate::debugger_data::MetadataSource;

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
    }

    impl fmt::Display for Color {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("red")
        }
    }

    #[record(tagged)]
    pub enum End {
        Head,
        Cycle(#[record(rename = "address")] VirtAddr),
        Corrupt { error: String },
    }

    /// Declares `Every` with the fields given (and their attributes),
    /// `every()` building it from their values, and `hints()` naming each
    /// field's hint in its mode, then the computed property's.
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
                let mut hints = vec![$((stringify!($field), <$ty as ToView<$mode>>::HINT.to_string())),*];
                hints.push(("computed", <Option<u64> as ToView<Hex>>::HINT.to_string()));
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
            globals.set_item("HINTS", hints())?;
            let source = format!(
                "{}\n{}",
                include_str!("../../python/tests/stubcheck.py"),
                r#"
checker = Checker({})
for name, hint in HINTS:
    checker.value(getattr(value, name), ast.parse(hint, mode="eval").body, name)
assert checker.errors == [], checker.errors
assert len(value) == len(HINTS), value.keys()
assert "hidden" not in value and "work_items" not in value and "items" in value, value.keys()
assert value.color == "red" and value.computed == 2, (value.color, value.computed)
assert value.end_head.kind == "head" and value.end_head.address is None, value.end_head
assert value.end_cycle.kind == "cycle" and value.end_cycle.address == 0x30, value.end_cycle
assert value.end_corrupt.error == "bad link", value.end_corrupt
assert checker.forms >= {"class", "Record", "available", "unavailable", "source"}, checker.forms
"#
            );
            let code = std::ffi::CString::new(source).unwrap();
            py.run(&code, Some(&globals), None)
        })
        .unwrap();
    }
}
