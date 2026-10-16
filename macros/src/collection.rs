//! `#[collection]`: see the crate docs.

use proc_macro2::TokenStream;
use quote::quote;
use syn::spanned::Spanned;
use syn::{
    Attribute, Error, FnArg, GenericArgument, Ident, ImplItem, ImplItemFn, ItemImpl, Pat,
    PathArguments, Result, ReturnType, Token, Type,
};

pub fn expand(attr: TokenStream, item: TokenStream) -> Result<TokenStream> {
    let flags = Flags::parse(attr)?;
    let mut item: ItemImpl = syn::parse2(item)?;
    if item.trait_.is_some() || !item.generics.params.is_empty() {
        return Err(Error::new_spanned(
            &item,
            "#[collection] applies to an inherent impl block",
        ));
    }
    let mut enumerate = None;
    let mut lookup = None;
    let mut matchers = Vec::new();
    let mut python = Vec::new();
    for impl_item in std::mem::take(&mut item.items) {
        let ImplItem::Fn(mut method) = impl_item else {
            python.push(impl_item);
            continue;
        };
        let matcher = Matcher::take(&mut method.attrs)?;
        match (matcher, method.sig.ident.to_string().as_str()) {
            (Some(kind), _) => matchers.push((kind, method)),
            (None, "enumerate") => enumerate = Some(method),
            (None, "lookup") => {
                // A key is taken by reference whatever its type, so a
                // `String` key arrives as `&String`.
                method
                    .attrs
                    .push(syn::parse_quote!(#[allow(clippy::ptr_arg)]));
                lookup = Some(method);
            }
            (None, _) => python.push(ImplItem::Fn(method)),
        }
    }
    let enumerate = enumerate
        .ok_or_else(|| Error::new_spanned(&item.self_ty, "a collection needs `fn enumerate`"))?;
    let element = element(&enumerate)?;
    let python_crate = quote!(crate::python);
    let mut generated = vec![quote! {
        fn __len__(&self, py: pyo3::Python<'_>) -> pyo3::PyResult<usize> {
            ::std::result::Result::Ok(Self::enumerate(self, py)?.len())
        }

        fn __iter__<'py>(
            &self,
            py: pyo3::Python<'py>,
        ) -> pyo3::PyResult<#python_crate::collection::Iter<'py, #element>> {
            #python_crate::collection::Iter::new(py, Self::enumerate(self, py)?)
        }
    }];
    let mut helpers = Vec::new();
    match (&lookup, flags.sequence) {
        (Some(lookup), true) => {
            return Err(Error::new_spanned(
                &lookup.sig,
                "a `sequence` is indexed by position; it takes no `lookup`",
            ));
        }
        (None, true) => generated.push(quote! {
            fn __getitem__<'py>(
                &self,
                py: pyo3::Python<'py>,
                index: isize,
            ) -> pyo3::PyResult<#element> {
                self.get(py, index)?
                    .ok_or_else(|| pyo3::exceptions::PyIndexError::new_err(index))
            }

            /// The item at position `index` (negative from the end), or
            /// `None` if there is none.
            fn get<'py>(
                &self,
                py: pyo3::Python<'py>,
                index: isize,
            ) -> pyo3::PyResult<::std::option::Option<#element>> {
                let mut items = Self::enumerate(self, py)?;
                ::std::result::Result::Ok(
                    #python_crate::collection::sequence_index(index, items.len())
                        .map(|index| items.swap_remove(index)),
                )
            }
        }),
        (Some(lookup), false) => {
            let key = lookup_key(lookup)?;
            let docs: Vec<&Attribute> = docs(&lookup.attrs).collect();
            let (key_type, find) = if flags.records {
                let key_type = quote!(#python_crate::collection::Key<'py, #key, #element>);
                helpers.push(quote! {
                    fn __collection_find<'py>(
                        &self,
                        py: pyo3::Python<'py>,
                        key: &#key_type,
                    ) -> pyo3::PyResult<::std::option::Option<#element>> {
                        match key {
                            #python_crate::collection::Key::Own(key) => Self::lookup(self, py, key),
                            #python_crate::collection::Key::Record(record) => {
                                #python_crate::collection::described(
                                    py,
                                    Self::enumerate(self, py)?,
                                    record.as_any(),
                                )
                            }
                        }
                    }
                });
                (key_type, quote!(__collection_find))
            } else {
                (quote!(#key), quote!(lookup))
            };
            generated.push(quote! {
                #(#docs)*
                fn __getitem__<'py>(
                    &self,
                    py: pyo3::Python<'py>,
                    key: #key_type,
                ) -> pyo3::PyResult<#element> {
                    match Self::#find(self, py, &key)? {
                        ::std::option::Option::Some(item) => ::std::result::Result::Ok(item),
                        ::std::option::Option::None => ::std::result::Result::Err(
                            #python_crate::collection::missing(py, key),
                        ),
                    }
                }

                #(#docs)*
                fn get<'py>(
                    &self,
                    py: pyo3::Python<'py>,
                    key: #key_type,
                ) -> pyo3::PyResult<::std::option::Option<#element>> {
                    Self::#find(self, py, &key)
                }

                fn __contains__<'py>(
                    &self,
                    py: pyo3::Python<'py>,
                    key: &pyo3::Bound<'py, pyo3::PyAny>,
                ) -> pyo3::PyResult<bool> {
                    use pyo3::types::PyAnyMethods;
                    match key.extract::<#key_type>() {
                        ::std::result::Result::Ok(key) => {
                            ::std::result::Result::Ok(Self::#find(self, py, &key)?.is_some())
                        }
                        ::std::result::Result::Err(_) => ::std::result::Result::Ok(false),
                    }
                }
            });
        }
        (None, false) if flags.records => {
            return Err(Error::new_spanned(
                &item.self_ty,
                "`records` keys a collection's `lookup`, which it lacks",
            ));
        }
        (None, false) => {}
    }
    for (kind, matcher) in &matchers {
        generated.push(kind.method(matcher, &element)?);
    }
    let self_ty = &item.self_ty;
    let attrs = &item.attrs;
    let lookup = lookup.iter();
    let matchers = matchers.iter().map(|(_, matcher)| matcher);
    Ok(quote! {
        #(#attrs)*
        impl #self_ty {
            #enumerate
            #(#lookup)*
            #(#matchers)*
            #(#helpers)*
        }

        #[pyo3::pymethods]
        impl #self_ty {
            #(#generated)*
            #(#python)*
        }
    })
}

/// `#[collection(sequence)]`: indexed by position, with no `lookup`;
/// `#[collection(records)]`: a record of the items' kind is a key too.
#[derive(Default)]
struct Flags {
    sequence: bool,
    records: bool,
}

impl Flags {
    fn parse(attr: TokenStream) -> Result<Self> {
        let mut flags = Self::default();
        let parser = |input: syn::parse::ParseStream<'_>| -> Result<()> {
            while !input.is_empty() {
                let ident: Ident = input.parse()?;
                match ident.to_string().as_str() {
                    "sequence" => flags.sequence = true,
                    "records" => flags.records = true,
                    _ => return Err(Error::new(ident.span(), "expected `sequence` or `records`")),
                }
                if !input.is_empty() {
                    input.parse::<Token![,]>()?;
                }
            }
            Ok(())
        };
        syn::parse::Parser::parse2(parser, attr)?;
        if flags.sequence && flags.records {
            return Err(Error::new(
                proc_macro2::Span::call_site(),
                "a `sequence` is indexed by position, not by record",
            ));
        }
        Ok(flags)
    }
}

/// A matcher function, `#[collection(find)]` or `#[collection(at)]`, from
/// which the collection's `find` or `at` is made.
enum Matcher {
    /// `fn(&Item, &str) -> bool`: `find(name)`, every item it holds for.
    Find,
    /// `fn(&Item, u64) -> bool`: `at(address)`, the first item it holds for.
    At,
}

impl Matcher {
    fn take(attrs: &mut Vec<Attribute>) -> Result<Option<Self>> {
        let mut found = None;
        let mut error = None;
        attrs.retain(|attr| {
            if !attr.path().is_ident("collection") {
                return true;
            }
            match attr.parse_args::<Ident>() {
                Ok(ident) if ident == "find" => found = Some(Matcher::Find),
                Ok(ident) if ident == "at" => found = Some(Matcher::At),
                Ok(ident) => error = Some(Error::new(ident.span(), "expected `find` or `at`")),
                Err(parse) => error = Some(parse),
            }
            false
        });
        match error {
            Some(error) => Err(error),
            None => Ok(found),
        }
    }

    /// The Python method made from `matcher`, named by the matcher's kind,
    /// with its second parameter and its docs.
    fn method(&self, matcher: &ImplItemFn, element: &Type) -> Result<TokenStream> {
        let function = &matcher.sig.ident;
        let docs = docs(&matcher.attrs);
        let (pattern, ty) = match matcher.sig.inputs.iter().nth(1) {
            Some(FnArg::Typed(arg)) if matcher.sig.inputs.len() == 2 => (&arg.pat, &arg.ty),
            _ => {
                return Err(Error::new_spanned(
                    &matcher.sig,
                    "a matcher takes the item and the value it matches",
                ));
            }
        };
        let Pat::Ident(param) = &**pattern else {
            return Err(Error::new_spanned(pattern, "expected a parameter name"));
        };
        let param = &param.ident;
        Ok(match self {
            Matcher::Find => quote! {
                #(#docs)*
                fn find(
                    &self,
                    py: pyo3::Python<'_>,
                    #param: #ty,
                ) -> pyo3::PyResult<::std::vec::Vec<#element>> {
                    ::std::result::Result::Ok(
                        Self::enumerate(self, py)?
                            .into_iter()
                            .filter(|item| Self::#function(item, #param))
                            .collect(),
                    )
                }
            },
            Matcher::At => quote! {
                #(#docs)*
                fn at(
                    &self,
                    py: pyo3::Python<'_>,
                    #param: #ty,
                ) -> pyo3::PyResult<::std::option::Option<#element>> {
                    ::std::result::Result::Ok(
                        Self::enumerate(self, py)?
                            .into_iter()
                            .find(|item| Self::#function(item, #param)),
                    )
                }
            },
        })
    }
}

fn docs(attrs: &[Attribute]) -> impl Iterator<Item = &Attribute> {
    attrs.iter().filter(|attr| attr.path().is_ident("doc"))
}

/// The `T` of `fn enumerate(...) -> PyResult<Vec<T>>`.
fn element(enumerate: &ImplItemFn) -> Result<Type> {
    let error = || Error::new_spanned(&enumerate.sig, "`enumerate` returns `PyResult<Vec<Item>>`");
    let ReturnType::Type(_, ty) = &enumerate.sig.output else {
        return Err(error());
    };
    let vec = first_argument(ty).ok_or_else(error)?;
    first_argument(vec).cloned().ok_or_else(error)
}

/// `A` of `Path<A, ...>`.
fn first_argument(ty: &Type) -> Option<&Type> {
    let Type::Path(path) = ty else {
        return None;
    };
    let PathArguments::AngleBracketed(arguments) = &path.path.segments.last()?.arguments else {
        return None;
    };
    arguments.args.iter().find_map(|argument| match argument {
        GenericArgument::Type(ty) => Some(ty),
        _ => None,
    })
}

/// The `K` of `fn lookup(&self, py, key: &K) -> PyResult<Option<Item>>`.
fn lookup_key(lookup: &ImplItemFn) -> Result<Type> {
    match lookup.sig.inputs.iter().nth(2) {
        Some(FnArg::Typed(arg)) if lookup.sig.inputs.len() == 3 => match &*arg.ty {
            Type::Reference(reference) => Ok((*reference.elem).clone()),
            other => Err(Error::new(
                other.span(),
                "`lookup` takes its key by reference",
            )),
        },
        _ => Err(Error::new_spanned(
            &lookup.sig,
            "`lookup` takes `&self`, the `Python` token and `&Key`",
        )),
    }
}
