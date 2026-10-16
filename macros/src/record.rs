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
            if let Some(span) = flags.tagged {
                return Err(Error::new(span, "`tagged` applies to an enum"));
            }
            structure(flags, item)
        }
        Item::Enum(item) => enumeration(flags, item),
        Item::Impl(item) => {
            if let Some(span) = flags.has_impl.or(flags.tagged) {
                return Err(Error::new(span, "a `#[record]` impl block takes no flags"));
            }
            implementation(item)
        }
        other => Err(Error::new_spanned(
            other,
            "#[record] applies to a struct, an enum, or an impl block",
        )),
    }
}

/// The item-level flags: `#[record(impl, tagged)]`.
#[derive(Default)]
struct Flags {
    /// A `#[record] impl` block adds computed properties and methods.
    has_impl: Option<Span>,
    /// An enum becomes a class with a `kind` and its variants' fields.
    tagged: Option<Span>,
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
                        _ => {
                            return Err(Error::new(ident.span(), "expected `impl` or `tagged`"));
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
    rename: Option<LitStr>,
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
                } else if meta.path.is_ident("rename") {
                    opts.rename = Some(meta.value()?.parse()?);
                    Ok(())
                } else if meta.path.is_ident("getter") {
                    opts.getter = true;
                    Ok(())
                } else if meta.path.is_ident("python") {
                    opts.python = true;
                    Ok(())
                } else {
                    Err(meta.error(
                        "expected `hex`, `bytes`, `skip`, `rename = \"...\"`, `getter` or `python`",
                    ))
                }
            })?;
        }
        *attrs = kept;
        Ok(opts)
    }

    /// Reject the options a field or variant does not take.
    fn field_only(&self) -> Result<()> {
        match self.span {
            Some(span) if self.getter || self.python => Err(Error::new(
                span,
                "`getter` and `python` apply to methods of a `#[record] impl` block",
            )),
            _ => Ok(()),
        }
    }
}

/// Names that a property cannot take: `BaseRecord`'s methods, which it would
/// hide, and Python keywords, which no attribute access can spell.
const RESERVED: [&str; 40] = [
    "keys", "values", "items", "get", "to_dict", "False", "None", "True", "and", "as", "assert",
    "async", "await", "break", "class", "continue", "def", "del", "elif", "else", "except",
    "finally", "for", "from", "global", "if", "import", "in", "is", "lambda", "nonlocal", "not",
    "or", "pass", "raise", "return", "try", "while", "with", "yield",
];

fn unraw(ident: &Ident) -> String {
    let name = ident.to_string();
    name.strip_prefix("r#").map_or(name.clone(), str::to_string)
}

fn snake_case(ident: &Ident) -> String {
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
}

impl Getter {
    fn tokens(&self, index: usize) -> TokenStream {
        let Self {
            key,
            property,
            ty,
            mode,
            docs,
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
                    slf.as_super().get().field(slf.py(), #key)?,
                ))
            }
        }
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

/// The class of a record: `<Name>Py`, its `wrap`, `Name::into_class`, and its
/// properties (through `methods_macro` when an impl block adds to them).
fn class(name: &Ident, docs: &[Attribute], getters: &[Getter], has_impl: bool) -> TokenStream {
    let class = class_ident(name);
    let python_name = unraw(name);
    let getters = getters
        .iter()
        .enumerate()
        .map(|(index, getter)| getter.tokens(index));
    let methods = if has_impl {
        let methods = methods_macro(name);
        quote! {
            #[cfg(feature = "python")]
            #[allow(unused_macros)]
            macro_rules! #methods {
                ($($items:tt)*) => {
                    #[pyo3::pymethods]
                    impl #class {
                        #(#getters)*
                        $($items)*
                    }
                };
            }
        }
    } else {
        quote! {
            #[cfg(feature = "python")]
            #[pyo3::pymethods]
            impl #class {
                #(#getters)*
            }
        }
    };
    quote! {
        #[cfg(feature = "python")]
        #(#docs)*
        #[pyo3::pyclass(
            module = "ntoseye",
            name = #python_name,
            frozen,
            extends = crate::python::record::BaseRecord
        )]
        pub struct #class;

        #[cfg(feature = "python")]
        impl #class {
            /// The class around a record's fields.
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
    }
}

/// `Value::Record` of `fields`, plus the computed properties for a record
/// with an impl block.
fn shaped(name: &Ident, fields: TokenStream, has_impl: bool) -> TokenStream {
    let class = class_ident(name);
    let computed = has_impl.then(|| {
        quote! {
            <Self as crate::python::record::RecordImpl>::computed(self, &mut fields);
        }
    });
    quote! {
        #[allow(unused_mut)]
        let mut fields: ::std::vec::Vec<(&'static str, crate::python::record::Value)> = #fields;
        #computed
        crate::python::record::Value::Record(crate::python::record::RecordFields {
            fields,
            class: #class::wrap,
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
    for field in &mut named.named {
        let opts = Opts::take(&mut field.attrs)?;
        opts.field_only()?;
        if opts.skip {
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
        let mode = opts.mode.tokens();
        values.push(quote! {
            (#key, <#ty as crate::python::record::ToValue<#mode>>::to_value(&self.#ident))
        });
        getters.push(Getter {
            key,
            property,
            ty: quote!(#ty),
            mode: opts.mode,
            docs: docs(&field.attrs),
        });
    }
    unique(&getters, item.ident.span())?;
    derives(&mut item.attrs)?;
    let name = &item.ident;
    let has_impl = flags.has_impl.is_some();
    let body = shaped(name, quote!(::std::vec![#(#values),*]), has_impl);
    let to_value = to_value(name, body, class_hint(name));
    let class = class(name, &docs(&item.attrs), &getters, has_impl);
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
        arms.push(quote!(Self::#ident => #text,));
        texts.push((text, variant.ident.span()));
    }
    distinct(&texts, "text")?;
    let texts: Vec<String> = texts.into_iter().map(|(text, _)| text).collect();
    let name = &item.ident;
    let to_value = to_value(
        name,
        quote!(crate::python::record::Value::Str(
            ::std::string::String::from(self.as_str())
        )),
        literal_hint(&texts),
    );
    Ok(quote! {
        impl #name {
            /// The variant's text: its `Display`, and its value in the SDK.
            pub const fn as_str(&self) -> &'static str {
                match self {
                    #(#arms)*
                }
            }
        }

        impl ::std::fmt::Display for #name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.write_str(self.as_str())
            }
        }

        #to_value
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

/// A tagged enum: a class with `kind` and every variant's fields, each
/// `None` outside its variant.
fn tagged(flags: &Flags, item: &mut ItemEnum) -> Result<TokenStream> {
    let name = item.ident.clone();
    let mut kinds = Vec::new();
    let mut getters: Vec<Getter> = Vec::new();
    // Per variant: its pattern, and the (getter index, value) it fills.
    let mut variants = Vec::new();
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
        let mut filled = Vec::new();
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
            let ty = &field.ty;
            let ty_tokens = quote!(#ty).to_string();
            let position = match getters.iter().position(|getter| getter.key == key) {
                Some(position) => {
                    let getter = &getters[position];
                    let existing = getter.ty.to_string();
                    let expected = quote!(::std::option::Option<#ty>).to_string();
                    if existing != expected || getter.mode != opts.mode {
                        return Err(Error::new_spanned(
                            &*field,
                            format!(
                                "`{key}` is `{ty_tokens}` here but has another type or \
                                 attribute in an earlier variant"
                            ),
                        ));
                    }
                    position
                }
                None => {
                    getters.push(Getter {
                        key,
                        property,
                        ty: quote!(::std::option::Option<#ty>),
                        mode: opts.mode,
                        docs: docs(&field.attrs),
                    });
                    getters.len() - 1
                }
            };
            let mode = opts.mode.tokens();
            filled.push((
                position,
                quote!(<#ty as crate::python::record::ToValue<#mode>>::to_value(#binding)),
            ));
        }
        let ident = &variant.ident;
        let pattern = match &variant.fields {
            Fields::Unit => quote!(Self::#ident),
            Fields::Unnamed(_) => quote!(Self::#ident(#(#bindings),*)),
            Fields::Named(fields) => {
                let names = fields.named.iter().map(|field| &field.ident);
                quote!(Self::#ident { #(#names: #bindings),* })
            }
        };
        variants.push((pattern, kind, filled));
    }
    distinct(&kinds, "kind")?;
    let kinds: Vec<String> = kinds.into_iter().map(|(kind, _)| kind).collect();
    let kind_docs = {
        let listed = kinds
            .iter()
            .map(|kind| format!("`{kind}`"))
            .collect::<Vec<_>>()
            .join(", ");
        let text = format!(" The variant: {listed}.");
        vec![syn::parse_quote!(#[doc = #text])]
    };
    // `kind` is typed as the `Literal` of the kinds, through a type that
    // exists only for its hint.
    let kind_type = format_ident!("__{}RecordKind", unraw(&name));
    let kind_hint = literal_hint(&kinds);
    let mut all = vec![Getter {
        key: "kind".to_string(),
        property: "kind".to_string(),
        ty: quote!(#kind_type),
        mode: Mode::Plain,
        docs: kind_docs,
    }];
    all.extend(getters);
    unique(&all, name.span())?;
    let count = all.len() - 1;
    let arms = variants.into_iter().map(|(pattern, kind, filled)| {
        let values = (0..count).map(|position| {
            let key = &all[position + 1].key;
            match filled.iter().find(|(at, _)| *at == position) {
                Some((_, value)) => quote!((#key, #value)),
                None => quote!((#key, crate::python::record::Value::Null)),
            }
        });
        quote! {
            #[allow(unused_variables)]
            #pattern => ::std::vec![
                ("kind", crate::python::record::Value::Str(::std::string::String::from(#kind))),
                #(#values),*
            ],
        }
    });
    let has_impl = flags.has_impl.is_some();
    let body = shaped(&name, quote!(match self { #(#arms)* }), has_impl);
    let to_value = to_value(&name, body, class_hint(&name));
    let class = class(&name, &docs(&item.attrs), &all, has_impl);
    Ok(quote! {
        #to_value
        #class

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
    })
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
        });
        kept.push(impl_item);
    }
    unique(&getters, name.span())?;
    item.items = kept;
    let methods = methods_macro(&name);
    let offset = 1000;
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

        #[cfg(feature = "python")]
        #methods! {
            #(#getters)*
            #(#python)*
        }
    })
}
