//! Procedural macros for ntoseye. They expand to paths inside the `ntoseye`
//! crate (`crate::view::record`, `crate::python::record`), so only that crate
//! can use them.

mod record;

use proc_macro::TokenStream;

/// One type for Rust, the REPL and the Python SDK.
///
/// On a struct with named fields, `#[record]` keeps the struct as written
/// (adding `Debug` and `Clone` derives if missing) and, under the `python`
/// feature, emits:
///
/// - `impl<M> ToView<M>` (`crate::view::record`), which renders the fields in
///   order as a `View::Shaped`;
/// - `<Name>Py`, a frozen `ntoseye.<Name>` class extending `BaseRecord`, with
///   a typed property per field (the struct's and fields' doc comments become
///   its docstrings), which `build.rs` exports from the SDK module;
/// - `Name::into_class`, the record as its class.
///
/// Field attributes, `#[record(...)]`:
///
/// - `hex`: integers in the field render as hex (`repr`), through any
///   `Option`, `Vec`, `Box`, `DiagnosticValue`, `DiagnosticMetric` or `Keyed`;
/// - `bytes`: a `Vec<u8>` (possibly wrapped) is Python `bytes`;
/// - `skip`: Rust only; Python does not see the field;
/// - `rename = "key"`: the record key. The property takes the key too,
///   unless the key would hide a `BaseRecord` method or is a Python keyword
///   (`keys`, `class`), in which case the property keeps the Rust name.
///
/// Item flags: `#[record(impl)]` says a `#[record] impl Name { ... }` block
/// follows in the same module, adding computed properties
/// (`#[record(getter)]` methods, which take the field attributes) and Python
/// methods (`#[record(python)]`, PyO3 methods of the class).
///
/// On an enum:
///
/// - fieldless: the value is the variant's `Display` text, typed `str`;
/// - every variant one unnamed field: the union of the variants' types
///   (the value is the variant's own);
/// - `#[record(tagged)]`: a class with `kind` (the snake_case variant name,
///   or the variant's `rename`) and each variant field as an optional
///   property, named by the field, its `rename`, or for a variant's single
///   unnamed field the variant's snake_case name.
#[proc_macro_attribute]
pub fn record(attr: TokenStream, item: TokenStream) -> TokenStream {
    record::expand(attr.into(), item.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}
