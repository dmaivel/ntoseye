//! `#[handle]` and `handle_methods!`: see the crate docs.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::parse::{Parse, ParseStream};
use syn::spanned::Spanned;
use syn::{
    Attribute, Error, Expr, Ident, ImplItem, Item, ItemImpl, ItemStruct, LitInt, LitStr, Meta,
    Path, Result, Token, Type, braced, bracketed,
};

use crate::record::snake_case;

pub fn expand(attr: TokenStream, item: TokenStream) -> Result<TokenStream> {
    match syn::parse2::<Item>(item)? {
        Item::Struct(item) => structure(Config::parse(attr.clone())?, attr, item),
        Item::Impl(item) => {
            if !attr.is_empty() {
                return Err(Error::new_spanned(
                    attr,
                    "a `#[handle]` impl block takes no options",
                ));
            }
            implementation(item)
        }
        other => Err(Error::new_spanned(
            other,
            "#[handle] applies to a struct or an impl block",
        )),
    }
}

/// `#[handle(record = R, key = field, ...)]`.
struct Config {
    record: Path,
    /// The record field (or getter) that names the object: a collection's
    /// record key matches it, and it is the handle's identity unless
    /// `identity` says otherwise.
    key: Ident,
    /// Where the record is: a field of the handle (`info`, the default),
    /// or a method `fn(&self, Python) -> PyResult<R>` that reads it now.
    source: Source,
    /// A method `fn(&self) -> impl Hash + Eq`: the identity, when it is
    /// not the key (a breakpoint's serial).
    identity: Option<Path>,
    /// `CommandHost`'s `context`, `refuse` and `prepare`, as expressions
    /// in the scope of those methods: `context` gives the `Context` (with
    /// `self` and `py`), `refuse` (with `self`, `operation` and `effects`)
    /// and `prepare` (with `self` and `session`) a `PyResult<()>`.
    context: Option<Expr>,
    refuse: Option<Expr>,
    prepare: Option<Expr>,
    /// A `#[handle] impl` block follows.
    has_impl: bool,
}

enum Source {
    Field(Ident),
    Fetch(Path),
}

impl Config {
    fn parse(attr: TokenStream) -> Result<Self> {
        let span = attr.span();
        let mut record = None;
        let mut key = None;
        let mut info = None;
        let mut fetch = None;
        let mut identity = None;
        let mut context = None;
        let mut refuse = None;
        let mut prepare = None;
        let mut has_impl = false;
        let parser = |input: ParseStream<'_>| -> Result<()> {
            while !input.is_empty() {
                if input.peek(Token![impl]) {
                    input.parse::<Token![impl]>()?;
                    has_impl = true;
                } else {
                    let name: Ident = input.parse()?;
                    input.parse::<Token![=]>()?;
                    match name.to_string().as_str() {
                        "record" => record = Some(input.parse()?),
                        "key" => key = Some(input.parse()?),
                        "info" => info = Some(input.parse()?),
                        "fetch" => fetch = Some(input.parse()?),
                        "identity" => identity = Some(input.parse()?),
                        "context" => context = Some(input.parse()?),
                        "refuse" => refuse = Some(input.parse()?),
                        "prepare" => prepare = Some(input.parse()?),
                        _ => {
                            return Err(Error::new(
                                name.span(),
                                "expected `record`, `key`, `info`, `fetch`, `identity`, \
                                 `context`, `refuse`, `prepare` or `impl`",
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
        let source = match (info, fetch) {
            (Some(_), Some(fetch)) => {
                return Err(Error::new_spanned(fetch, "give one of `info` and `fetch`"));
            }
            (_, Some(fetch)) => Source::Fetch(fetch),
            (info, None) => Source::Field(info.unwrap_or_else(|| Ident::new("info", span))),
        };
        if let (Source::Fetch(fetch), None) = (&source, &identity) {
            return Err(Error::new_spanned(
                fetch,
                "a handle that fetches its record needs an `identity`",
            ));
        }
        Ok(Self {
            record: record.ok_or_else(|| Error::new(span, "#[handle] needs `record = ...`"))?,
            key: key.ok_or_else(|| Error::new(span, "#[handle] needs `key = ...`"))?,
            source,
            identity,
            context,
            refuse,
            prepare,
            has_impl,
        })
    }
}

/// The macro a handle struct defines for its methods: it hands the
/// handle's options and its impl block's items to the record's own macro,
/// which adds the record's properties and calls `handle_methods!`.
fn methods_macro(name: &Ident) -> Ident {
    format_ident!("__handle_methods_{}", name)
}

fn structure(config: Config, attr: TokenStream, item: ItemStruct) -> Result<TokenStream> {
    if !item.generics.params.is_empty() {
        return Err(Error::new_spanned(
            &item.generics,
            "a handle cannot be generic",
        ));
    }
    let name = &item.ident;
    let record = &config.record;
    let command = quote!(crate::python::command);
    let context = config.context.as_ref().map(|context| {
        quote! {
            #[allow(unused_variables)]
            fn context(
                &self,
                py: pyo3::Python<'_>,
            ) -> pyo3::PyResult<crate::python::context::Context> {
                ::std::result::Result::Ok(#context)
            }
        }
    });
    let refuse = config.refuse.as_ref().map(|refuse| {
        quote! {
            #[allow(unused_variables)]
            fn refuse(
                &self,
                operation: &str,
                effects: &crate::session::effects::Effects,
            ) -> pyo3::PyResult<()> {
                #refuse
            }
        }
    });
    let prepare = config.prepare.as_ref().map(|prepare| {
        quote! {
            fn prepare(&self, session: &mut crate::session::Session) -> pyo3::PyResult<()> {
                #prepare
            }
        }
    });
    // A held record is what a `receiver` argument of the record's type
    // binds, and what a handle passed as an argument of that type gives;
    // a fetched one would need the session.
    let what = snake_case(name).replace('_', " ");
    let bind = match &config.source {
        Source::Field(info) => Some(quote! {
            impl #command::Bind<#record> for #name {
                fn bind(&self) -> #record {
                    ::std::clone::Clone::clone(&self.#info)
                }
            }

            /// The handle is the argument: its record, if it belongs to the
            /// debugger whose method takes it.
            impl #command::PyArg for #record {
                type Py = pyo3::Py<#name>;

                fn from_py(value: pyo3::Py<#name>) -> Self {
                    ::std::clone::Clone::clone(&value.get().#info)
                }

                fn from_py_in(
                    py: pyo3::Python<'_>,
                    owner: &crate::python::handle::Owner,
                    value: pyo3::Py<#name>,
                ) -> pyo3::PyResult<Self> {
                    let handle = value.get();
                    handle.owner.require_argument_of(py, owner, #what)?;
                    ::std::result::Result::Ok(::std::clone::Clone::clone(&handle.#info))
                }
            }
        }),
        Source::Fetch(_) => None,
    };
    let methods = methods_macro(name);
    let invoke = (!config.has_impl).then(|| quote!(#methods! {}));
    Ok(quote! {
        #[pyo3::pyclass(module = "ntoseye", frozen)]
        #item

        #[cfg(not(test))]
        const _: () = crate::python::record::exported::<#name>();

        impl #command::CommandHost for #name {
            fn session(&self) -> #command::HostSession<'_> {
                #command::HostSession::Owner(&self.owner)
            }
            #context
            #refuse
            #prepare
        }

        #bind

        #[allow(unused_macros)]
        macro_rules! #methods {
            ($($items:tt)*) => {
                #record! { { #name (#attr) } $($items)* }
            };
        }

        #invoke
    })
}

fn implementation(item: ItemImpl) -> Result<TokenStream> {
    if item.trait_.is_some() || !item.generics.params.is_empty() {
        return Err(Error::new_spanned(
            &item,
            "#[handle] applies to an inherent impl block",
        ));
    }
    let name = match &*item.self_ty {
        Type::Path(path) if path.qself.is_none() && path.path.segments.len() == 1 => {
            path.path.segments[0].ident.clone()
        }
        other => return Err(Error::new_spanned(other, "expected the handle's own name")),
    };
    let methods = methods_macro(&name);
    let items = &item.items;
    Ok(quote!(#methods! { #(#items)* }))
}

/// One property of the record, as its macro lists it:
/// `field|getter <ident> "<property>" <index> { <docs> };`.
struct Entry {
    method: bool,
    ident: Ident,
    property: LitStr,
    index: LitInt,
    docs: Vec<Attribute>,
}

impl Parse for Entry {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let kind: Ident = input.parse()?;
        let method = match kind.to_string().as_str() {
            "field" => false,
            "getter" => true,
            _ => return Err(Error::new(kind.span(), "expected `field` or `getter`")),
        };
        let ident = input.parse()?;
        let property = input.parse()?;
        let index = input.parse()?;
        let content;
        braced!(content in input);
        let docs = content.call(Attribute::parse_outer)?;
        input.parse::<Token![;]>()?;
        Ok(Self {
            method,
            ident,
            property,
            index,
            docs,
        })
    }
}

/// `handle_methods!`'s input: `[<entries>] { <Handle> (<options>) }
/// <impl items>`.
struct Methods {
    entries: Vec<Entry>,
    name: Ident,
    config: Config,
    items: Vec<ImplItem>,
}

impl Parse for Methods {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let content;
        bracketed!(content in input);
        let mut entries = Vec::new();
        while !content.is_empty() {
            entries.push(content.parse()?);
        }
        let content;
        braced!(content in input);
        let name = content.parse()?;
        let options;
        syn::parenthesized!(options in content);
        let config = Config::parse(options.parse()?)?;
        let mut items = Vec::new();
        while !input.is_empty() {
            items.push(input.parse()?);
        }
        Ok(Self {
            entries,
            name,
            config,
            items,
        })
    }
}

/// The Python name an impl item defines, unless it is a setter (which
/// adds to the property of its name rather than replacing it).
fn python_name(item: &ImplItem) -> Result<Option<String>> {
    let ImplItem::Fn(method) = item else {
        return Ok(None);
    };
    let mut name = None;
    let mut getter = false;
    for attr in &method.attrs {
        if attr.path().is_ident("setter") {
            return Ok(None);
        }
        if attr.path().is_ident("getter") {
            getter = true;
            if let Meta::List(list) = &attr.meta {
                name = Some(list.parse_args::<Ident>()?.to_string());
            }
        }
        if attr.path().is_ident("pyo3") {
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("name") {
                    name = Some(meta.value()?.parse::<LitStr>()?.value());
                } else if meta.input.peek(Token![=]) {
                    let value = meta.value()?;
                    // `signature = (address, *, physical = false)` is no
                    // expression.
                    if value.peek(syn::token::Paren) {
                        value.parse::<proc_macro2::Group>()?;
                    } else {
                        value.parse::<syn::Expr>()?;
                    }
                } else if meta.input.peek(syn::token::Paren) {
                    let _group: proc_macro2::Group = meta.input.parse()?;
                }
                Ok(())
            })?;
        }
    }
    let ident = method.sig.ident.to_string();
    Ok(Some(name.unwrap_or_else(
        || match ident.strip_prefix("get_") {
            Some(stripped) if getter => stripped.to_string(),
            _ => ident,
        },
    )))
}

pub fn methods(input: TokenStream) -> Result<TokenStream> {
    let Methods {
        entries,
        name,
        config,
        items,
    } = syn::parse2(input)?;
    let mut written = Vec::new();
    let mut eq_hash = [None, None];
    for item in &items {
        if let Some(name) = python_name(item)? {
            match name.as_str() {
                "__eq__" => eq_hash[0] = Some(item),
                "__hash__" => eq_hash[1] = Some(item),
                _ => {}
            }
            written.push(name);
        }
    }
    // Equal objects must hash equal: one written without the other would
    // pair it with the generated one, which compares something else.
    if let [Some(item), None] | [None, Some(item)] = eq_hash {
        return Err(Error::new_spanned(
            item,
            "a handle's `__eq__` and `__hash__` are written together: one beside the \
             generated other would let equal handles hash differently",
        ));
    }
    let own = |python: &str| written.iter().any(|name| name == python);
    let record = &config.record;
    let python = quote!(crate::python);
    let field = |entry: &Entry| {
        let index = &entry.index;
        (
            quote!(<#record as #python::record::Field<#index>>::Type),
            quote!(<#record as #python::record::Field<#index>>::Mode),
        )
    };
    let read = |entry: &Entry| {
        let ident = &entry.ident;
        if entry.method {
            quote!(&record.#ident())
        } else {
            quote!(&record.#ident)
        }
    };
    let getters = entries
        .iter()
        .filter(|entry| !own(&entry.property.value()))
        .map(|entry| {
            let docs = &entry.docs;
            let property = &entry.property;
            let ident = format_ident!("__handle_{}", entry.index.base10_digits());
            let (ty, mode) = field(entry);
            let value = read(entry);
            quote! {
                #(#docs)*
                #[getter]
                #[pyo3(name = #property)]
                fn #ident<'py>(
                    &self,
                    py: pyo3::Python<'py>,
                ) -> pyo3::PyResult<#python::record::Typed<'py, #ty, #mode>> {
                    let record = <Self as #python::handle::Handle>::record(self, py)?;
                    #python::record::Typed::of(py, #value)
                }
            }
        });
    let key = entries
        .iter()
        .find(|entry| entry.ident == config.key)
        .ok_or_else(|| {
            Error::new(
                config.key.span(),
                format!("the record has no property `{}`", config.key),
            )
        })?;
    let key_property = &key.property;
    let (key_ty, key_mode) = field(key);
    let key_value = read(key);
    let (source, record_body) = match &config.source {
        Source::Field(info) => (
            quote!(self.#info),
            quote! {
                self.owner.check(py)?;
                ::std::result::Result::Ok(::std::borrow::Cow::Borrowed(&self.#info))
            },
        ),
        Source::Fetch(fetch) => (
            TokenStream::new(),
            quote!(#fetch(self, py).map(::std::borrow::Cow::Owned)),
        ),
    };
    let (this, other) = match &config.identity {
        Some(identity) => (quote!(#identity(self)), quote!(#identity(other))),
        None => {
            let key = &config.key;
            let other_source = match &config.source {
                Source::Field(info) => quote!(other.#info),
                Source::Fetch(_) => unreachable!("validated"),
            };
            (quote!(&#source.#key), quote!(&#other_source.#key))
        }
    };
    let record_name = record
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
        .unwrap_or_default();
    let info_doc =
        format!(" The `{record_name}` record of this handle: its properties as one value.");
    let info = (!own("info")).then(|| {
        quote! {
            #[doc = #info_doc]
            #[getter]
            fn info<'py>(
                &self,
                py: pyo3::Python<'py>,
            ) -> pyo3::PyResult<#python::record::Typed<'py, #record>> {
                let record = <Self as #python::handle::Handle>::record(self, py)?;
                #python::record::Typed::of(py, &*record)
            }
        }
    });
    let to_dict = (!own("to_dict")).then(|| {
        quote! {
            /// The record (`info`) as a plain `dict`.
            fn to_dict<'py>(
                &self,
                py: pyo3::Python<'py>,
            ) -> pyo3::PyResult<#python::record::PlainDict<'py>> {
                let record = <Self as #python::handle::Handle>::record(self, py)?;
                #python::plain_dict(py, &*record)
            }
        }
    });
    let eq = (!own("__eq__")).then(|| {
        quote! {
            fn __eq__(&self, other: &pyo3::Bound<'_, pyo3::PyAny>) -> bool {
                use pyo3::types::PyAnyMethods;
                other.cast::<Self>().is_ok_and(|other| {
                    let other = other.get();
                    self.owner.same_target(&other.owner) && #this == #other
                })
            }
        }
    });
    let hash = (!own("__hash__")).then(|| {
        quote! {
            fn __hash__(&self) -> isize {
                self.owner.identity_hash(#this)
            }
        }
    });
    // PyO3 calls an `__eq__` from an `unsafe fn` through this path; spanned
    // at the handle's source it would be linted as the crate's own unsafe
    // call (`unsafe_op_in_unsafe_fn`), so it gets this macro's span.
    let class = Ident::new(&name.to_string(), proc_macro2::Span::mixed_site());
    Ok(quote! {
        impl #python::handle::Handle for #name {
            type Record = #record;

            fn record(
                &self,
                py: pyo3::Python<'_>,
            ) -> pyo3::PyResult<::std::borrow::Cow<'_, #record>> {
                #record_body
            }

            fn describes(
                &self,
                py: pyo3::Python<'_>,
                other: &pyo3::Bound<'_, pyo3::PyAny>,
            ) -> pyo3::PyResult<bool> {
                use pyo3::types::PyAnyMethods;
                let record = <Self as #python::handle::Handle>::record(self, py)?;
                let own = #python::record::Typed::<#key_ty, #key_mode>::of(py, #key_value)?;
                other.getattr(#key_property)?.eq(own.into_bound())
            }
        }

        #[pyo3::pymethods]
        impl #class {
            #(#getters)*
            #info
            #to_dict
            #eq
            #hash
            #(#items)*
        }
    })
}
