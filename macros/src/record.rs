//! `#[record]`: see the crate docs.

use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote};
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::{
    Attribute, Error, Fields, FnArg, Ident, ImplItem, Item, ItemEnum, ItemImpl, ItemStruct, LitStr,
    Path, Result, ReturnType, Token, Type,
};

pub fn expand(attr: TokenStream, item: TokenStream) -> Result<TokenStream> {
    let flags = Flags::parse(attr)?;
    match syn::parse2::<Item>(item)? {
        Item::Struct(item) => {
            if let Some(span) = flags.tagged.or(flags.base.as_ref().map(Ident::span)) {
                return Err(Error::new(span, "`tagged` and `base` apply to an enum"));
            }
            structure(flags, item)
        }
        Item::Enum(item) => enumeration(flags, item),
        Item::Impl(item) => {
            if let Some(span) = flags
                .has_impl
                .or(flags.tagged)
                .or(flags.base.as_ref().map(Ident::span))
            {
                return Err(Error::new(span, "a `#[record] impl` block takes no flags"));
            }
            implementation(item)
        }
        other => Err(Error::new_spanned(
            other,
            "#[record] applies to a struct, an enum, or an impl block",
        )),
    }
}

/// The item-level flags: `#[record(impl, tagged, base = Name)]`.
#[derive(Default)]
struct Flags {
    /// A `#[record] impl` block adds computed properties and methods.
    has_impl: Option<Span>,
    /// An enum becomes a base class with a `kind`, and a subclass per
    /// variant with its fields.
    tagged: Option<Span>,
    /// A tagged enum's variants subclass this record struct's class, which
    /// holds the enum in a `#[record(flatten)]` field, instead of a class
    /// of the enum's own.
    base: Option<Ident>,
}

impl Flags {
    fn parse(attr: TokenStream) -> Result<Self> {
        let mut flags = Self::default();
        let parser = |input: syn::parse::ParseStream<'_>| -> Result<()> {
            while !input.is_empty() {
                if input.peek(Token![impl]) {
                    let token: Token![impl] = input.parse()?;
                    flags.has_impl = Some(token.span);
                } else {
                    let ident: Ident = input.parse()?;
                    match ident.to_string().as_str() {
                        "tagged" => flags.tagged = Some(ident.span()),
                        "base" => {
                            input.parse::<Token![=]>()?;
                            flags.base = Some(input.parse()?);
                        }
                        _ => {
                            return Err(Error::new(
                                ident.span(),
                                "expected `impl`, `tagged` or `base = Name`",
                            ));
                        }
                    }
                }
                if !input.is_empty() {
                    input.parse::<Token![,]>()?;
                }
            }
            Ok(())
        };
        syn::parse::Parser::parse2(parser, attr)?;
        Ok(flags)
    }
}

/// How a field's integers and bytes render: the `M` of `ToValue<M>`.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Mode {
    #[default]
    Plain,
    Hex,
    Bytes,
}

impl Mode {
    fn tokens(self) -> TokenStream {
        match self {
            Self::Plain => quote!(crate::python::record::Plain),
            Self::Hex => quote!(crate::python::record::Hex),
            Self::Bytes => quote!(crate::python::record::Bytes),
        }
    }
}

/// A field's, variant's or method's `#[record(...)]` options.
#[derive(Default)]
struct Opts {
    mode: Mode,
    skip: bool,
    flatten: bool,
    rename: Option<LitStr>,
    /// A fieldless enum variant's REPL text (its `Display`), when it is not
    /// its SDK text.
    label: Option<LitStr>,
    getter: bool,
    python: bool,
    span: Option<Span>,
}

impl Opts {
    /// Remove the `#[record(...)]` attributes from `attrs` and parse them.
    fn take(attrs: &mut Vec<Attribute>) -> Result<Self> {
        let mut opts = Self::default();
        let mut kept = Vec::with_capacity(attrs.len());
        for attr in attrs.drain(..) {
            if !attr.path().is_ident("record") {
                kept.push(attr);
                continue;
            }
            opts.span = Some(attr.span());
            attr.parse_nested_meta(|meta| {
                let set_mode = |opts: &mut Self, mode| {
                    if opts.mode != Mode::Plain {
                        return Err(meta.error("a field takes one of `hex` and `bytes`"));
                    }
                    opts.mode = mode;
                    Ok(())
                };
                if meta.path.is_ident("hex") {
                    set_mode(&mut opts, Mode::Hex)
                } else if meta.path.is_ident("bytes") {
                    set_mode(&mut opts, Mode::Bytes)
                } else if meta.path.is_ident("skip") {
                    opts.skip = true;
                    Ok(())
                } else if meta.path.is_ident("flatten") {
                    opts.flatten = true;
                    Ok(())
                } else if meta.path.is_ident("rename") {
                    opts.rename = Some(meta.value()?.parse()?);
                    Ok(())
                } else if meta.path.is_ident("label") {
                    opts.label = Some(meta.value()?.parse()?);
                    Ok(())
                } else if meta.path.is_ident("getter") {
                    opts.getter = true;
                    Ok(())
                } else if meta.path.is_ident("python") {
                    opts.python = true;
                    Ok(())
                } else {
                    Err(meta.error(
                        "expected `hex`, `bytes`, `skip`, `flatten`, `rename = \"...\"`, `getter` or \
                         `python`",
                    ))
                }
            })?;
        }
        *attrs = kept;
        Ok(opts)
    }

    /// Reject the options a struct's field does not take.
    fn struct_field(&self) -> Result<()> {
        match self.span {
            Some(span) if self.getter || self.python => Err(Error::new(
                span,
                "`getter` and `python` apply to methods of a `#[record] impl` block",
            )),
            _ => Ok(()),
        }
    }

    /// Reject the options an enum's variant or variant field does not take.
    fn field_only(&self) -> Result<()> {
        self.struct_field()?;
        match self.span {
            Some(span) if self.flatten => Err(Error::new(
                span,
                "`flatten` applies to a record struct's field",
            )),
            _ => Ok(()),
        }
    }
}

/// Names that a property cannot take: `BaseRecord`'s method, which it would
/// hide, and Python keywords, which no attribute access can spell.
const RESERVED: [&str; 36] = [
    "to_dict", "False", "None", "True", "and", "as", "assert", "async", "await", "break", "class",
    "continue", "def", "del", "elif", "else", "except", "finally", "for", "from", "global", "if",
    "import", "in", "is", "lambda", "nonlocal", "not", "or", "pass", "raise", "return", "try",
    "while", "with", "yield",
];

fn unraw(ident: &Ident) -> String {
    let name = ident.to_string();
    name.strip_prefix("r#").map_or(name.clone(), str::to_string)
}

pub fn snake_case(ident: &Ident) -> String {
    let mut out = String::new();
    for (index, c) in unraw(ident).chars().enumerate() {
        if c.is_uppercase() {
            if index > 0 {
                out.push('_');
            }
            out.extend(c.to_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// A field's record key and Python property name: the key is `rename`, else
/// `default`; the property is the key, unless the key is reserved, in which
/// case it is the Rust name.
fn naming(
    rust: Option<&Ident>,
    rename: Option<&LitStr>,
    default: Option<String>,
    span: Span,
) -> Result<(String, String)> {
    let key = match (rename, default) {
        (Some(rename), _) => rename.value(),
        (None, Some(default)) => default,
        (None, None) => {
            return Err(Error::new(
                span,
                "a field without a name needs `#[record(rename = \"...\")]`",
            ));
        }
    };
    if !RESERVED.contains(&key.as_str()) {
        return Ok((key.clone(), key));
    }
    match rust.map(unraw) {
        Some(name) if !RESERVED.contains(&name.as_str()) => Ok((key, name)),
        _ => Err(Error::new(
            span,
            format!(
                "`{key}` would hide a BaseRecord method or is a Python keyword: give the field \
                 another Rust name and keep its key with `#[record(rename = \"{key}\")]`"
            ),
        )),
    }
}

fn docs(attrs: &[Attribute]) -> Vec<Attribute> {
    attrs
        .iter()
        .filter(|attr| attr.path().is_ident("doc"))
        .cloned()
        .collect()
}

/// A property of a record's class.
struct Getter {
    key: String,
    property: String,
    /// The Rust type of the value, whose `ToValue<mode>` types the property.
    ty: TokenStream,
    mode: Mode,
    docs: Vec<Attribute>,
    /// How a struct's value is read: its field, or its getter method. A
    /// tagged enum's properties have none.
    access: Option<Access>,
}

enum Access {
    Field(Ident),
    Method(Ident),
}

impl Getter {
    fn tokens(&self, index: usize) -> TokenStream {
        let Self {
            key,
            property,
            ty,
            mode,
            docs,
            access: _,
        } = self;
        let mode = mode.tokens();
        let ident = format_ident!("record_property_{index}");
        quote! {
            #(#docs)*
            #[getter]
            #[pyo3(name = #property)]
            fn #ident<'py>(
                slf: &pyo3::Bound<'py, Self>,
            ) -> pyo3::PyResult<crate::python::record::Typed<'py, #ty, #mode>> {
                ::std::result::Result::Ok(crate::python::record::Typed::converted(
                    crate::python::record::field(slf.as_any(), #key)?,
                ))
            }
        }
    }

    /// What a `#[handle]` on the record learns of this property (see
    /// [`handle_callback`]), and the `Field<index>` impl naming its type.
    fn handle_entry(&self, name: &Ident, index: usize) -> (TokenStream, TokenStream) {
        let Some(access) = &self.access else {
            return (TokenStream::new(), TokenStream::new());
        };
        let (kind, ident) = match access {
            Access::Field(ident) => (quote!(field), ident),
            Access::Method(ident) => (quote!(getter), ident),
        };
        let property = &self.property;
        let docs = &self.docs;
        let index = syn::Index::from(index);
        let ty = &self.ty;
        let mode = self.mode.tokens();
        (
            quote!(#kind #ident #property #index { #(#docs)* };),
            quote! {
                #[cfg(feature = "python")]
                impl crate::python::record::Field<#index> for #name {
                    type Type = #ty;
                    type Mode = #mode;
                }
            },
        )
    }
}

/// The macro a record struct defines under its own name, in the macro
/// namespace, so a module that imports the record imports it too: `Name!
/// { ... }` hands its input to `ntoseye_macros::handle_methods!` after the
/// record's properties (`entries`, then `extra`). `#[handle]` invokes it to
/// learn the record's properties. `d` is the `$` the definition is
/// written with (`$d` inside another `macro_rules!`).
fn handle_callback(
    name: &Ident,
    entries: &[TokenStream],
    extra: TokenStream,
    d: TokenStream,
) -> TokenStream {
    let hidden = format_ident!("__record_handle_{}", unraw(name));
    quote! {
        #[cfg(feature = "python")]
        #[doc(hidden)]
        #[allow(non_snake_case)]
        mod #hidden {
            #[allow(unused_macros)]
            macro_rules! #name {
                (#d (#d input:tt)*) => {
                    ::ntoseye_macros::handle_methods! { [#(#entries)* #extra] #d (#d input)* }
                };
            }
            #[allow(unused_imports)]
            pub(crate) use #name;
        }
        #[cfg(feature = "python")]
        #[allow(unused_imports)]
        pub(crate) use #hidden::#name;
    }
}

fn class_ident(name: &Ident) -> Ident {
    format_ident!("{}Py", unraw(name))
}

/// The macro a record with `#[record(impl)]` defines for its impl block,
/// which hands it the class's computed properties and methods.
fn methods_macro(name: &Ident) -> Ident {
    format_ident!("__record_methods_{}", unraw(name))
}

/// Check the property names are unique.
fn unique(getters: &[Getter], span: Span) -> Result<()> {
    for (index, getter) in getters.iter().enumerate() {
        if getters[..index]
            .iter()
            .any(|other| other.property == getter.property || other.key == getter.key)
        {
            return Err(Error::new(
                span,
                format!(
                    "two properties of the record are named `{}`",
                    getter.property
                ),
            ));
        }
    }
    Ok(())
}

/// `__match_args__` of `class`: `names`, typed as the tuple of their
/// `Literal`s so a type checker can match positional patterns.
fn match_args(class: &Ident, names: &[String]) -> TokenStream {
    let ty = format_ident!("__{}MatchArgs", class);
    let count = names.len();
    let hint = if names.is_empty() {
        // `tuple[()]`: the stub prints an empty `Tuple` as nothing.
        quote!(pyo3::inspect::PyStaticExpr::Name { id: "()" })
    } else {
        let literals = names
            .iter()
            .map(|name| literal_hint(std::slice::from_ref(name)));
        quote!(pyo3::inspect::PyStaticExpr::Tuple { elts: &[#(#literals),*] })
    };
    quote! {
        #[cfg(feature = "python")]
        #[doc(hidden)]
        #[allow(non_camel_case_types)]
        pub struct #ty;

        #[cfg(feature = "python")]
        impl<'py> pyo3::IntoPyObject<'py> for #ty {
            type Target = pyo3::types::PyTuple;
            type Output = pyo3::Bound<'py, pyo3::types::PyTuple>;
            type Error = pyo3::PyErr;

            #[cfg(feature = "python-stubs")]
            const OUTPUT_TYPE: pyo3::inspect::PyStaticExpr = pyo3::inspect::PyStaticExpr::Subscript {
                value: &pyo3::type_hint_identifier!("builtins", "tuple"),
                slice: &#hint,
            };

            fn into_pyobject(
                self,
                py: pyo3::Python<'py>,
            ) -> pyo3::PyResult<pyo3::Bound<'py, pyo3::types::PyTuple>> {
                let names: [&'static str; #count] = [#(#names),*];
                pyo3::types::PyTuple::new(py, names)
            }
        }

        #[cfg(feature = "python")]
        #[pyo3::pymethods]
        impl #class {
            #[classattr]
            #[pyo3(name = "__match_args__")]
            fn record_match_args() -> #ty {
                #ty
            }
        }
    }
}

/// The class of a record: `<Name>Py`, its `wrap`, `Name::into_class`, its
/// properties (through `methods_macro` when an impl block adds to them) and
/// `__match_args__` (`match_args`, when given). A struct's class also has the
/// `handle_callback` macro, with the impl block's computed properties when
/// it has one, and its `Field` impls. A `subclass` class is a base, which
/// a tagged enum's variant classes extend.
fn class(
    name: &Ident,
    docs: &[Attribute],
    getters: &[Getter],
    has_impl: bool,
    subclass: bool,
    match_names: Option<&[String]>,
) -> TokenStream {
    let class = class_ident(name);
    let python_name = unraw(name);
    let structure = getters.iter().any(|getter| getter.access.is_some());
    let (entries, fields): (Vec<_>, Vec<_>) = getters
        .iter()
        .enumerate()
        .map(|(index, getter)| getter.handle_entry(name, index))
        .unzip();
    let getters = getters
        .iter()
        .enumerate()
        .map(|(index, getter)| getter.tokens(index));
    let methods = if has_impl {
        let methods = methods_macro(name);
        // The impl block hands over `$` and its computed properties' entries.
        let callback =
            structure.then(|| handle_callback(name, &entries, quote!($($computed)*), quote!($d)));
        quote! {
            #[cfg(feature = "python")]
            #[allow(unused_macros)]
            macro_rules! #methods {
                ($d:tt [$($computed:tt)*] $($items:tt)*) => {
                    #[pyo3::pymethods]
                    impl #class {
                        #(#getters)*
                        $($items)*
                    }
                    #callback
                };
            }
        }
    } else {
        let callback =
            structure.then(|| handle_callback(name, &entries, TokenStream::new(), quote!($)));
        quote! {
            #[cfg(feature = "python")]
            #[pyo3::pymethods]
            impl #class {
                #(#getters)*
            }
            #callback
        }
    };
    let match_args = match_names.map(|names| match_args(&class, names));
    let subclass = subclass.then(|| quote!(subclass,));
    quote! {
        #[cfg(feature = "python")]
        #(#docs)*
        #[pyo3::pyclass(
            module = "ntoseye",
            name = #python_name,
            frozen,
            #subclass
            extends = crate::python::record::BaseRecord
        )]
        pub struct #class;

        #[cfg(feature = "python")]
        impl crate::python::record::RecordClass for #name {
            type Class = #class;
        }

        #(#fields)*

        #[cfg(feature = "python")]
        impl #class {
            /// The class around a record's fields.
            #[allow(dead_code)]
            pub fn wrap<'py>(
                py: pyo3::Python<'py>,
                record: crate::python::record::BaseRecord,
            ) -> pyo3::PyResult<pyo3::Bound<'py, pyo3::PyAny>> {
                let init = pyo3::PyClassInitializer::from(record).add_subclass(#class);
                ::std::result::Result::Ok(pyo3::Bound::new(py, init)?.into_any())
            }
        }

        #[cfg(feature = "python")]
        impl #name {
            /// This record as its SDK class, for a handle Rust keeps.
            #[allow(dead_code)]
            pub fn into_class<'py>(
                &self,
                py: pyo3::Python<'py>,
            ) -> pyo3::PyResult<pyo3::Bound<'py, #class>> {
                let typed = crate::python::record::Typed::<Self>::of(py, self)?;
                ::std::result::Result::Ok(typed.into_bound().cast_into::<#class>()?)
            }
        }

        #methods
        #match_args
    }
}

/// `Value::Record` of the fields `push` pushes onto `fields`, plus the
/// computed properties for a record with an impl block, as `class`.
fn shaped(push: TokenStream, class: TokenStream, has_impl: bool) -> TokenStream {
    let computed = has_impl.then(|| {
        quote! {
            <Self as crate::python::record::RecordImpl>::computed(self, &mut fields);
        }
    });
    quote! {
        #[allow(unused_mut)]
        let mut fields: ::std::vec::Vec<(&'static str, crate::python::record::Value)> =
            ::std::vec::Vec::new();
        #push
        #computed
        crate::python::record::Value::Record(crate::python::record::RecordFields {
            fields,
            class: #class,
        })
    }
}

/// `impl<M> ToValue<M> for Name`.
fn to_value(name: &Ident, body: TokenStream, hint: TokenStream) -> TokenStream {
    quote! {
        #[cfg(feature = "python")]
        impl<M> crate::python::record::ToValue<M> for #name {
            fn to_value(&self) -> crate::python::record::Value {
                #body
            }
            #[cfg(feature = "python-stubs")]
            const HINT: pyo3::inspect::PyStaticExpr = #hint;
        }
    }
}

fn class_hint(name: &Ident) -> TokenStream {
    let class = class_ident(name);
    quote!(<#class as pyo3::PyTypeInfo>::TYPE_HINT)
}

/// `typing.Literal[...]` of `texts`, the strings a value can be.
fn literal_hint(texts: &[String]) -> TokenStream {
    quote! {
        pyo3::type_hint_subscript!(
            pyo3::type_hint_identifier!("typing", "Literal"),
            #(pyo3::inspect::PyStaticExpr::Constant {
                value: pyo3::inspect::PyStaticConstant::Str(#texts),
            }),*
        )
    }
}

/// Refuse two variants that share a text: the value would not say which.
fn distinct(texts: &[(String, Span)], what: &str) -> Result<()> {
    for (index, (text, span)) in texts.iter().enumerate() {
        if texts[..index].iter().any(|(earlier, _)| earlier == text) {
            return Err(Error::new(
                *span,
                format!("two variants have the {what} `{text}`"),
            ));
        }
    }
    Ok(())
}

/// Add `Debug` and `Clone` to the item's derives, unless it has them.
fn derives(attrs: &mut Vec<Attribute>) -> Result<()> {
    let has = |want: &str| -> Result<bool> {
        for attr in attrs.iter().filter(|attr| attr.path().is_ident("derive")) {
            let paths = attr.parse_args_with(Punctuated::<Path, Token![,]>::parse_terminated)?;
            if paths
                .iter()
                .any(|path| path.segments.last().is_some_and(|last| last.ident == want))
            {
                return Ok(true);
            }
        }
        Ok(false)
    };
    let missing: Vec<Ident> = ["Debug", "Clone"]
        .into_iter()
        .filter_map(|want| match has(want) {
            Ok(true) => None,
            Ok(false) => Some(Ok(Ident::new(want, Span::call_site()))),
            Err(error) => Some(Err(error)),
        })
        .collect::<Result<_>>()?;
    if !missing.is_empty() {
        attrs.push(syn::parse_quote!(#[derive(#(#missing),*)]));
    }
    Ok(())
}

fn no_generics(generics: &syn::Generics) -> Result<()> {
    if generics.params.is_empty() {
        Ok(())
    } else {
        Err(Error::new_spanned(generics, "a record cannot be generic"))
    }
}

fn structure(flags: Flags, mut item: ItemStruct) -> Result<TokenStream> {
    no_generics(&item.generics)?;
    let Fields::Named(named) = &mut item.fields else {
        return Err(Error::new_spanned(
            &item,
            "a record struct needs named fields",
        ));
    };
    let mut getters = Vec::new();
    let mut values = Vec::new();
    let mut match_names = Vec::new();
    let mut flattened = None;
    for field in &mut named.named {
        let opts = Opts::take(&mut field.attrs)?;
        opts.struct_field()?;
        if opts.skip {
            if opts.flatten {
                return Err(Error::new_spanned(
                    &*field,
                    "a skipped field is not flattened",
                ));
            }
            continue;
        }
        let ident = field.ident.as_ref().expect("named field");
        let (key, property) = naming(
            Some(ident),
            opts.rename.as_ref(),
            Some(unraw(ident)),
            ident.span(),
        )?;
        let ty = &field.ty;
        match_names.push(property.clone());
        if opts.flatten {
            // The tagged enum's `kind`, then its variant's fields; the
            // variant's class is the record's.
            if key != "kind" || opts.mode != Mode::Plain || flattened.is_some() {
                return Err(Error::new_spanned(
                    &*field,
                    "one field is flattened, keyed `kind`, with no `hex` or `bytes`",
                ));
            }
            let variants = quote!(<#ty as crate::python::record::Variants>);
            values.push(quote! {
                fields.push((#key, crate::python::record::Value::Str(
                    ::std::string::String::from(#variants::kind(&self.#ident)),
                )));
                #variants::payload(&self.#ident, &mut fields);
            });
            getters.push(Getter {
                key,
                property,
                ty: quote!(#variants::Kind),
                mode: Mode::Plain,
                docs: docs(&field.attrs),
                access: None,
            });
            flattened = Some(quote!(#variants::class(&self.#ident)));
            continue;
        }
        let mode = opts.mode.tokens();
        values.push(quote! {
            fields.push((
                #key,
                <#ty as crate::python::record::ToValue<#mode>>::to_value(&self.#ident),
            ));
        });
        getters.push(Getter {
            key,
            property,
            ty: quote!(#ty),
            mode: opts.mode,
            docs: docs(&field.attrs),
            access: Some(Access::Field(ident.clone())),
        });
    }
    unique(&getters, item.ident.span())?;
    derives(&mut item.attrs)?;
    let name = &item.ident;
    let has_impl = flags.has_impl.is_some();
    let subclass = flattened.is_some();
    let wrap = flattened.unwrap_or_else(|| {
        let class = class_ident(name);
        quote!(#class::wrap)
    });
    let body = shaped(quote!(#(#values)*), wrap, has_impl);
    let to_value = to_value(name, body, class_hint(name));
    let class = class(
        name,
        &docs(&item.attrs),
        &getters,
        has_impl,
        subclass,
        Some(&match_names),
    );
    Ok(quote! {
        #item
        #to_value
        #class
    })
}

fn enumeration(flags: Flags, mut item: ItemEnum) -> Result<TokenStream> {
    no_generics(&item.generics)?;
    if item.variants.is_empty() {
        return Err(Error::new_spanned(&item, "a record enum needs variants"));
    }
    let fieldless = item
        .variants
        .iter()
        .all(|variant| matches!(variant.fields, Fields::Unit));
    let expanded = if flags.tagged.is_some() {
        tagged(&flags, &mut item)?
    } else if let Some(base) = &flags.base {
        return Err(Error::new(base.span(), "`base` applies to a `tagged` enum"));
    } else if let Some(span) = flags.has_impl {
        return Err(Error::new(
            span,
            "only a `tagged` record enum has a class to extend",
        ));
    } else if fieldless {
        fieldless_enum(&mut item)?
    } else {
        union(&mut item)?
    };
    derives(&mut item.attrs)?;
    Ok(quote! {
        #item
        #expanded
    })
}

/// A fieldless enum: each variant's text (its `rename`, else its snake_case
/// name), which is its `as_str()`, its `Display` and its SDK value, typed as
/// the `Literal` of every variant's text.
fn fieldless_enum(item: &mut ItemEnum) -> Result<TokenStream> {
    let mut texts = Vec::new();
    let mut arms = Vec::new();
    let mut labels = Vec::new();
    let mut parse = Vec::new();
    for variant in &mut item.variants {
        let opts = Opts::take(&mut variant.attrs)?;
        opts.field_only()?;
        if opts.skip || opts.mode != Mode::Plain {
            return Err(Error::new(
                opts.span.unwrap_or_else(|| variant.span()),
                "a fieldless record enum's variant takes only `rename`, for its text",
            ));
        }
        let text = opts
            .rename
            .map_or_else(|| snake_case(&variant.ident), |rename| rename.value());
        let ident = &variant.ident;
        let label = opts
            .label
            .map_or_else(|| text.clone(), |label| label.value());
        arms.push(quote!(Self::#ident => #text,));
        labels.push(quote!(Self::#ident => #label,));
        parse.push(quote!(#text => ::std::result::Result::Ok(Self::#ident),));
        texts.push((text, variant.ident.span()));
    }
    distinct(&texts, "text")?;
    let texts: Vec<String> = texts.into_iter().map(|(text, _)| text).collect();
    let expected = format!("expected one of '{}', got ", texts.join("', '"));
    let hint = literal_hint(&texts);
    let name = &item.ident;
    let to_value = to_value(
        name,
        quote!(crate::python::record::Value::Str(
            ::std::string::String::from(self.as_str())
        )),
        hint.clone(),
    );
    Ok(quote! {
        impl #name {
            /// The variant's text: its value in the SDK.
            pub const fn as_str(&self) -> &'static str {
                match self {
                    #(#arms)*
                }
            }
        }

        /// The variant's label, as the REPL shows it: its `label`, else its
        /// text.
        impl ::std::fmt::Display for #name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.write_str(match self {
                    #(#labels)*
                })
            }
        }

        #to_value

        /// An SDK argument takes the variant's text.
        #[cfg(feature = "python")]
        impl<'a, 'py> pyo3::FromPyObject<'a, 'py> for #name {
            type Error = pyo3::PyErr;

            #[cfg(feature = "python-stubs")]
            const INPUT_TYPE: pyo3::inspect::PyStaticExpr = #hint;

            fn extract(obj: pyo3::Borrowed<'a, 'py, pyo3::PyAny>) -> pyo3::PyResult<Self> {
                let text: ::std::borrow::Cow<'_, str> = obj.extract()?;
                match &*text {
                    #(#parse)*
                    other => ::std::result::Result::Err(
                        pyo3::exceptions::PyValueError::new_err(
                            ::std::format!("{}{other:?}", #expected),
                        ),
                    ),
                }
            }
        }

        #[cfg(feature = "python")]
        impl crate::python::command::PyArg for #name {
            type Py = Self;
            fn from_py(value: Self) -> Self {
                value
            }
        }
    })
}

/// An enum whose variants each hold one value: the value, typed as the union
/// of the variants' types.
fn union(item: &mut ItemEnum) -> Result<TokenStream> {
    let mut arms = Vec::new();
    let mut hints = Vec::new();
    for variant in &mut item.variants {
        let opts = Opts::take(&mut variant.attrs)?;
        if let Some(span) = opts.span {
            return Err(Error::new(span, "a union's variants take no options"));
        }
        let field = match &mut variant.fields {
            Fields::Unnamed(fields) if fields.unnamed.len() == 1 => &mut fields.unnamed[0],
            _ => {
                return Err(Error::new_spanned(
                    &*variant,
                    "each variant of a union record holds one unnamed value; mark the enum \
                     `#[record(tagged)]` for a class with a `kind`",
                ));
            }
        };
        let opts = Opts::take(&mut field.attrs)?;
        opts.field_only()?;
        if opts.skip || opts.rename.is_some() {
            return Err(Error::new_spanned(
                &*field,
                "a union's values take `hex` or `bytes` only",
            ));
        }
        let ty = &field.ty;
        let mode = opts.mode.tokens();
        let ident = &variant.ident;
        arms.push(quote! {
            Self::#ident(value) => <#ty as crate::python::record::ToValue<#mode>>::to_value(value),
        });
        hints.push(quote!(<#ty as crate::python::record::ToValue<#mode>>::HINT));
    }
    let hint = hints
        .into_iter()
        .rev()
        .reduce(|right, left| {
            quote! {
                pyo3::inspect::PyStaticExpr::BinOp {
                    left: &#left,
                    op: pyo3::inspect::PyStaticOperator::BitOr,
                    right: &#right,
                }
            }
        })
        .expect("variants");
    Ok(to_value(
        &item.ident,
        quote!(match self { #(#arms)* }),
        hint,
    ))
}

/// A tagged enum: a base class with `kind`, and a subclass per variant,
/// nested in it (`Base.Variant`), with that variant's fields. The base is
/// the enum's own class, or with `base = Name` the class of the record
/// struct `Name`, which holds the enum in its `#[record(flatten)]` field.
fn tagged(flags: &Flags, item: &mut ItemEnum) -> Result<TokenStream> {
    let name = item.ident.clone();
    if let (Some(base), Some(_)) = (&flags.base, flags.has_impl) {
        return Err(Error::new(
            base.span(),
            "the `base` record's impl block holds the computed properties",
        ));
    }
    let base = flags.base.clone().unwrap_or_else(|| name.clone());
    let base_class = class_ident(&base);
    let mut kinds = Vec::new();
    let mut kind_arms = Vec::new();
    let mut payload_arms = Vec::new();
    let mut class_arms = Vec::new();
    let mut classes = Vec::new();
    for variant in &mut item.variants {
        let opts = Opts::take(&mut variant.attrs)?;
        opts.field_only()?;
        if opts.skip || opts.mode != Mode::Plain {
            return Err(Error::new_spanned(
                &*variant,
                "a variant takes only `rename`, for its `kind`",
            ));
        }
        let kind = opts
            .rename
            .map_or_else(|| snake_case(&variant.ident), |rename| rename.value());
        kinds.push((kind.clone(), variant.ident.span()));
        let single =
            matches!(&variant.fields, Fields::Unnamed(fields) if fields.unnamed.len() == 1);
        let mut bindings = Vec::new();
        let mut getters = Vec::new();
        let mut pushes = Vec::new();
        for (index, field) in variant.fields.iter_mut().enumerate() {
            let opts = Opts::take(&mut field.attrs)?;
            opts.field_only()?;
            let binding = format_ident!("field_{index}");
            bindings.push(binding.clone());
            if opts.skip {
                continue;
            }
            let default = match &field.ident {
                Some(ident) => Some(unraw(ident)),
                None if single => Some(snake_case(&variant.ident)),
                None => None,
            };
            let (key, property) = naming(
                field.ident.as_ref(),
                opts.rename.as_ref(),
                default,
                field.span(),
            )?;
            if key == "kind" {
                return Err(Error::new_spanned(
                    &*field,
                    "`kind` names the variant; rename the field",
                ));
            }
            let ty = &field.ty;
            let mode = opts.mode.tokens();
            pushes.push(quote! {
                fields.push((
                    #key,
                    <#ty as crate::python::record::ToValue<#mode>>::to_value(#binding),
                ));
            });
            getters.push(Getter {
                key,
                property,
                ty: quote!(#ty),
                mode: opts.mode,
                docs: docs(&field.attrs),
                access: None,
            });
        }
        unique(&getters, variant.ident.span())?;
        let ident = &variant.ident;
        let (pattern, any) = match &variant.fields {
            Fields::Unit => (quote!(Self::#ident), quote!(Self::#ident)),
            Fields::Unnamed(_) => (
                quote!(Self::#ident(#(#bindings),*)),
                quote!(Self::#ident(..)),
            ),
            Fields::Named(fields) => {
                let names = fields.named.iter().map(|field| &field.ident);
                (
                    quote!(Self::#ident { #(#names: #bindings),* }),
                    quote!(Self::#ident { .. }),
                )
            }
        };
        let variant_class = format_ident!("{}{}Py", unraw(&name), unraw(ident));
        kind_arms.push(quote!(#any => #kind,));
        payload_arms.push(quote! {
            #[allow(unused_variables)]
            #pattern => { #(#pushes)* }
        });
        class_arms.push(quote!(#any => #variant_class::wrap,));
        classes.push(variant_subclass(
            &base_class,
            &unraw(&base),
            &variant_class,
            ident,
            &kind,
            &docs(&variant.attrs),
            &getters,
        ));
    }
    distinct(&kinds, "kind")?;
    let kinds: Vec<String> = kinds.into_iter().map(|(kind, _)| kind).collect();
    // `kind` is typed as the `Literal` of the kinds, through a type that
    // exists only for its hint.
    let kind_type = format_ident!("__{}RecordKind", unraw(&name));
    let kind_hint = literal_hint(&kinds);
    let variants = quote! {
        #[cfg(feature = "python")]
        impl crate::python::record::Variants for #name {
            type Kind = #kind_type;

            fn kind(&self) -> &'static str {
                match self {
                    #(#kind_arms)*
                }
            }

            fn payload(
                &self,
                fields: &mut ::std::vec::Vec<(&'static str, crate::python::record::Value)>,
            ) {
                match self {
                    #(#payload_arms)*
                }
            }

            fn class(&self) -> crate::python::record::Wrap {
                match self {
                    #(#class_arms)*
                }
            }
        }

        #[cfg(feature = "python")]
        #[doc(hidden)]
        #[allow(non_camel_case_types)]
        pub enum #kind_type {}

        #[cfg(feature = "python")]
        impl<M> crate::python::record::ToValue<M> for #kind_type {
            fn to_value(&self) -> crate::python::record::Value {
                match *self {}
            }
            #[cfg(feature = "python-stubs")]
            const HINT: pyo3::inspect::PyStaticExpr = #kind_hint;
        }

        #(#classes)*
    };
    if flags.base.is_some() {
        return Ok(variants);
    }
    // The enum's own base class: `kind`, and the impl block's computed
    // properties.
    let kind_docs = {
        let listed = kinds
            .iter()
            .map(|kind| format!("`{kind}`"))
            .collect::<Vec<_>>()
            .join(", ");
        let text = format!(" The variant: {listed}.");
        vec![syn::parse_quote!(#[doc = #text])]
    };
    let kind = Getter {
        key: "kind".to_string(),
        property: "kind".to_string(),
        ty: quote!(#kind_type),
        mode: Mode::Plain,
        docs: kind_docs,
        access: None,
    };
    let has_impl = flags.has_impl.is_some();
    let push = quote! {
        fields.push(("kind", crate::python::record::Value::Str(
            ::std::string::String::from(crate::python::record::Variants::kind(self)),
        )));
        crate::python::record::Variants::payload(self, &mut fields);
    };
    let body = shaped(
        push,
        quote!(crate::python::record::Variants::class(self)),
        has_impl,
    );
    let to_value = to_value(&name, body, class_hint(&name));
    let class = class(&name, &docs(&item.attrs), &[kind], has_impl, true, None);
    Ok(quote! {
        #to_value
        #class
        #variants
    })
}

/// A tagged enum's variant: `variant_class`, a final subclass of
/// `base_class` named after the variant, with `kind` (typed as the variant's
/// own `Literal`) and the variant's fields (`getters`), and `__match_args__`
/// of those fields. It is a class attribute of the base (`Stop.Breakpoint`)
/// with that `__qualname__`, as PyO3 nests a complex enum's variants: both
/// attributes go straight into the classes' items, so they add nothing to
/// the stub; there, an introspection fragment names the base as the
/// variant's parent, so maturin writes it as a nested class.
fn variant_subclass(
    base_class: &Ident,
    base_name: &str,
    variant_class: &Ident,
    variant: &Ident,
    kind: &str,
    docs: &[Attribute],
    getters: &[Getter],
) -> TokenStream {
    let python_name = unraw(variant);
    let kind_type = format_ident!("__{}Kind", variant_class);
    let kind_hint = literal_hint(&[kind.to_string()]);
    let kind_text = format!(" `{kind}`.");
    let kind_getter = Getter {
        key: "kind".to_string(),
        property: "kind".to_string(),
        ty: quote!(#kind_type),
        mode: Mode::Plain,
        docs: vec![syn::parse_quote!(#[doc = #kind_text])],
        access: None,
    };
    let properties = std::iter::once(&kind_getter)
        .chain(getters)
        .enumerate()
        .map(|(index, getter)| getter.tokens(index));
    let names: Vec<String> = getters
        .iter()
        .map(|getter| getter.property.clone())
        .collect();
    let match_args = match_args(variant_class, &names);
    let fragment = nested_fragment(base_class, variant_class, &python_name, docs);
    let attribute = syn::LitCStr::new(
        &std::ffi::CString::new(python_name.clone()).expect("an identifier"),
        Span::call_site(),
    );
    let qualname = format!("{base_name}.{python_name}");
    quote! {
        #[cfg(feature = "python")]
        #(#docs)*
        #[pyo3::pyclass(module = "ntoseye", name = #python_name, frozen, extends = #base_class)]
        pub struct #variant_class;

        #[cfg(feature = "python")]
        #[pyo3::pymethods]
        impl #variant_class {
            #(#properties)*
        }

        #[cfg(feature = "python")]
        impl #variant_class {
            /// The class around a record's fields.
            pub fn wrap<'py>(
                py: pyo3::Python<'py>,
                record: crate::python::record::BaseRecord,
            ) -> pyo3::PyResult<pyo3::Bound<'py, pyo3::PyAny>> {
                let init = pyo3::PyClassInitializer::from(record)
                    .add_subclass(#base_class)
                    .add_subclass(#variant_class);
                ::std::result::Result::Ok(pyo3::Bound::new(py, init)?.into_any())
            }

            /// The class, as its base's attribute.
            fn nested(py: pyo3::Python<'_>) -> pyo3::PyResult<pyo3::Py<pyo3::PyAny>> {
                ::std::result::Result::Ok(py.get_type::<#variant_class>().into_any().unbind())
            }

            /// Its `__qualname__`: `Base.Variant`.
            fn qualname(py: pyo3::Python<'_>) -> pyo3::PyResult<pyo3::Py<pyo3::PyAny>> {
                pyo3::IntoPyObjectExt::into_py_any(#qualname, py)
            }
        }

        #[cfg(feature = "python")]
        pyo3::inventory::submit! {
            type Inventory = <#base_class as pyo3::impl_::pyclass::PyClassImpl>::Inventory;
            Inventory::new(pyo3::impl_::pyclass::PyClassItems {
                methods: &[pyo3::impl_::pymethods::PyMethodDefType::ClassAttribute(
                    pyo3::impl_::pymethods::PyClassAttributeDef::new(
                        #attribute,
                        #variant_class::nested,
                    ),
                )],
                slots: &[],
            })
        }

        #[cfg(feature = "python")]
        pyo3::inventory::submit! {
            type Inventory = <#variant_class as pyo3::impl_::pyclass::PyClassImpl>::Inventory;
            Inventory::new(pyo3::impl_::pyclass::PyClassItems {
                methods: &[pyo3::impl_::pymethods::PyMethodDefType::ClassAttribute(
                    pyo3::impl_::pymethods::PyClassAttributeDef::new(
                        c"__qualname__",
                        #variant_class::qualname,
                    ),
                )],
                slots: &[],
            })
        }

        #[cfg(feature = "python")]
        #[doc(hidden)]
        #[allow(non_camel_case_types)]
        pub enum #kind_type {}

        #[cfg(feature = "python")]
        impl<M> crate::python::record::ToValue<M> for #kind_type {
            fn to_value(&self) -> crate::python::record::Value {
                match *self {}
            }
            #[cfg(feature = "python-stubs")]
            const HINT: pyo3::inspect::PyStaticExpr = #kind_hint;
        }

        #match_args
        #fragment
    }
}

/// `text` as a JSON string's contents.
fn json_escaped(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// The docstring PyO3 makes of `docs`: each line less one leading space.
fn docstring(docs: &[Attribute]) -> Option<String> {
    let lines: Vec<String> = docs
        .iter()
        .filter_map(|attr| match &attr.meta {
            syn::Meta::NameValue(syn::MetaNameValue {
                value:
                    syn::Expr::Lit(syn::ExprLit {
                        lit: syn::Lit::Str(text),
                        ..
                    }),
                ..
            }) => {
                let text = text.value();
                Some(text.strip_prefix(' ').unwrap_or(&text).to_string())
            }
            _ => None,
        })
        .collect();
    (!lines.is_empty()).then(|| lines.join("\n"))
}

/// The introspection fragment of a nested class (`python-stubs`): PyO3's
/// own for `class` names no parent, and PyO3 sets one only for a complex
/// enum's variants. This one names `parent`, so maturin writes `class` inside
/// it, and types it as `Parent.Name`. It is the same class (the same id), so
/// its properties, which name it as their parent, land in it.
fn nested_fragment(
    parent: &Ident,
    class: &Ident,
    python_name: &str,
    docs: &[Attribute],
) -> TokenStream {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    format!("{parent}::{class}").hash(&mut hasher);
    format!("{:?}", Span::call_site()).hash(&mut hasher);
    let symbol = format_ident!("PYO3_INTROSPECTION_1_ntoseye_nested_{}", hasher.finish());
    let head = format!(
        "{{\"type\":\"class\",\"name\":\"{}\",\"id\":\"",
        json_escaped(python_name)
    );
    let doc = docstring(docs)
        .map(|doc| format!(",\"doc\":\"{}\"", json_escaped(&doc)))
        .unwrap_or_default();
    let tail = format!("]{doc}}}");
    quote! {
        #[cfg(feature = "python-stubs")]
        const _: () = {
            use pyo3::inspect::{
                PyStaticExpr, serialize_for_introspection, serialized_len_for_introspection,
            };
            const BASE: PyStaticExpr = <#parent as pyo3::PyTypeInfo>::TYPE_HINT;
            const BASE_LEN: usize = serialized_len_for_introspection(&BASE);
            const BASE_SER: [u8; BASE_LEN] = {
                let mut out = [0; BASE_LEN];
                serialize_for_introspection(&BASE, &mut out);
                out
            };
            const FINAL: PyStaticExpr = pyo3::type_hint_identifier!("typing", "final");
            const FINAL_LEN: usize = serialized_len_for_introspection(&FINAL);
            const FINAL_SER: [u8; FINAL_LEN] = {
                let mut out = [0; FINAL_LEN];
                serialize_for_introspection(&FINAL, &mut out);
                out
            };
            const PIECES: &[&[u8]] = &[
                #head.as_bytes(),
                #class::_PYO3_INTROSPECTION_ID.as_bytes(),
                b"\",\"parent\":\"",
                #parent::_PYO3_INTROSPECTION_ID.as_bytes(),
                b"\",\"bases\":[",
                &BASE_SER,
                b"],\"decorators\":[",
                &FINAL_SER,
                #tail.as_bytes(),
            ];
            const LEN: usize = pyo3::impl_::concat::combined_len(PIECES);
            #[used]
            #[unsafe(no_mangle)]
            static #symbol: pyo3::impl_::introspection::SerializedIntrospectionFragment<LEN> =
                pyo3::impl_::introspection::SerializedIntrospectionFragment {
                    length: LEN as u32,
                    fragment: pyo3::impl_::concat::combine_to_array::<LEN>(PIECES),
                };
        };
    }
}

/// `#[record] impl Name { ... }`: the methods stay Rust methods, except that
/// `#[record(getter)]` ones also become computed properties and
/// `#[record(python)]` ones become methods of the class instead.
fn implementation(mut item: ItemImpl) -> Result<TokenStream> {
    if item.trait_.is_some() {
        return Err(Error::new_spanned(
            &item,
            "#[record] applies to an inherent impl block",
        ));
    }
    no_generics(&item.generics)?;
    let name = match &*item.self_ty {
        Type::Path(path) if path.qself.is_none() && path.path.segments.len() == 1 => {
            path.path.segments[0].ident.clone()
        }
        other => {
            return Err(Error::new_spanned(other, "expected the record's own name"));
        }
    };
    let mut getters = Vec::new();
    let mut values = Vec::new();
    let mut python = Vec::new();
    let mut kept = Vec::new();
    for mut impl_item in std::mem::take(&mut item.items) {
        let ImplItem::Fn(method) = &mut impl_item else {
            kept.push(impl_item);
            continue;
        };
        let opts = Opts::take(&mut method.attrs)?;
        if opts.flatten {
            return Err(Error::new_spanned(
                &method.sig,
                "`flatten` applies to a record struct's field",
            ));
        }
        if opts.python {
            if opts.getter || opts.skip || opts.rename.is_some() || opts.mode != Mode::Plain {
                return Err(Error::new_spanned(
                    &method.sig,
                    "a `python` method takes no other record options",
                ));
            }
            python.push(method.clone());
            continue;
        }
        if !opts.getter {
            if let Some(span) = opts.span {
                return Err(Error::new(span, "expected `getter` or `python`"));
            }
            kept.push(impl_item);
            continue;
        }
        if opts.skip {
            return Err(Error::new_spanned(
                &method.sig,
                "a getter cannot be skipped",
            ));
        }
        let sig = &method.sig;
        let receiver_only = sig.inputs.len() == 1
            && matches!(
                sig.inputs.first(),
                Some(FnArg::Receiver(receiver)) if receiver.reference.is_some() && receiver.mutability.is_none()
            );
        if !receiver_only || !sig.generics.params.is_empty() {
            return Err(Error::new_spanned(
                sig,
                "a getter takes `&self` and nothing else",
            ));
        }
        let ReturnType::Type(_, ty) = &sig.output else {
            return Err(Error::new_spanned(sig, "a getter returns its value"));
        };
        let ident = &sig.ident;
        let (key, property) = naming(
            Some(ident),
            opts.rename.as_ref(),
            Some(unraw(ident)),
            ident.span(),
        )?;
        let mode = opts.mode.tokens();
        values.push(quote! {
            fields.push((#key, <#ty as crate::python::record::ToValue<#mode>>::to_value(&self.#ident())));
        });
        getters.push(Getter {
            key,
            property,
            ty: quote!(#ty),
            mode: opts.mode,
            docs: docs(&method.attrs),
            access: Some(Access::Method(ident.clone())),
        });
        kept.push(impl_item);
    }
    unique(&getters, name.span())?;
    item.items = kept;
    let methods = methods_macro(&name);
    let offset = 1000;
    let (entries, fields): (Vec<_>, Vec<_>) = getters
        .iter()
        .enumerate()
        .map(|(index, getter)| getter.handle_entry(&name, offset + index))
        .unzip();
    let getters = getters
        .iter()
        .enumerate()
        .map(|(index, getter)| getter.tokens(offset + index));
    Ok(quote! {
        #item

        #[cfg(feature = "python")]
        impl crate::python::record::RecordImpl for #name {
            fn computed(
                &self,
                fields: &mut ::std::vec::Vec<(&'static str, crate::python::record::Value)>,
            ) {
                #(#values)*
            }
        }

        #(#fields)*

        #[cfg(feature = "python")]
        #methods! {
            $ [#(#entries)*]
            #(#getters)*
            #(#python)*
        }
    })
}
