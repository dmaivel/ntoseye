//! `#[grammar]`: see the crate docs.

use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::spanned::Spanned;
use syn::{Error, Ident, ItemFn, LitStr, Result};

use crate::command::Completion;

pub fn expand(attr: TokenStream, item: TokenStream) -> Result<TokenStream> {
    let function: ItemFn = syn::parse2(item)?;
    let span = attr.span();
    let mut usage: Option<LitStr> = None;
    let mut complete: Option<Completion> = None;
    let mut operation = false;
    let parser = syn::meta::parser(|meta| {
        if meta.path.is_ident("usage") {
            usage = Some(meta.value()?.parse()?);
        } else if meta.path.is_ident("complete") {
            complete = Some(Completion::parse(meta.value()?)?);
        } else if meta.path.is_ident("operation") {
            operation = true;
        } else {
            return Err(meta.error(
                "expected `usage = \"...\"`, `complete = Strategy | [Strategy, ...]` or \
                 `operation`",
            ));
        }
        Ok(())
    });
    syn::parse::Parser::parse2(parser, attr)?;
    let grammar = if operation {
        if usage.is_some() || complete.is_some() {
            return Err(Error::new(
                span,
                "an `operation` parser hands its words to the operation: each argument it \
                 parses describes them with `#[arg(usage = ..., complete = ...)]`",
            ));
        }
        quote!(::std::option::Option::None)
    } else {
        let usage = usage.ok_or_else(|| {
            Error::new(
                span,
                "#[grammar] needs `usage = \"...\"` (the words the parser reads, in the usage \
                 notation; `{}` is the argument's name) or `operation`",
            )
        })?;
        let grammar = literal(&usage, complete.as_ref())?;
        quote!(::std::option::Option::Some(#grammar))
    };
    let vis = &function.vis;
    let ident = &function.sig.ident;
    Ok(quote! {
        #function

        /// The usage fragment and completion of the parser of the same name.
        #[doc(hidden)]
        #vis mod #ident {
            pub const GRAMMAR: ::std::option::Option<crate::repl::usage::Grammar> = #grammar;
        }
    })
}

/// A `Grammar` from a usage fragment and its completion: a list completes
/// each word in turn, a bare strategy every word (the rest of the line).
pub fn literal(usage: &LitStr, complete: Option<&Completion>) -> Result<TokenStream> {
    check_notation(&usage.value(), usage.span())?;
    if usage.value().is_empty() && complete.is_some() {
        return Err(Error::new(
            usage.span(),
            "an argument the line has no word for completes nothing",
        ));
    }
    let strategy = |ident: &Ident| quote!(crate::repl::CompletionStrategy::#ident);
    let (words, rest) = match complete {
        None => (Vec::new(), quote!(::std::option::Option::None)),
        Some(Completion::PerArg(list)) => (
            list.iter().map(strategy).collect(),
            quote!(::std::option::Option::None),
        ),
        Some(Completion::All(ident)) => {
            let rest = strategy(ident);
            (Vec::new(), quote!(::std::option::Option::Some(#rest)))
        }
    };
    Ok(quote! {
        crate::repl::usage::Grammar {
            usage: #usage,
            words: &[#(#words),*],
            rest: #rest,
        }
    })
}

/// Refuse a fragment that breaks the notation (`crate::repl::usage`):
/// unbalanced `[]`/`<>`, or a `|` that is neither inline (`a|b`) nor a
/// form separator (` | `).
pub fn check_notation(usage: &str, span: Span) -> Result<()> {
    let mut stack = Vec::new();
    let bytes = usage.as_bytes();
    for (index, &byte) in bytes.iter().enumerate() {
        match byte {
            b'[' | b'<' => stack.push(byte),
            b']' | b'>' => {
                let open = if byte == b']' { b'[' } else { b'<' };
                if stack.pop() != Some(open) {
                    return Err(Error::new(
                        span,
                        format!("unbalanced `{}` in usage `{usage}`", byte as char),
                    ));
                }
            }
            b'|' => {
                let before = index > 0 && bytes[index - 1] == b' ';
                let after = bytes.get(index + 1) == Some(&b' ');
                if before != after {
                    return Err(Error::new(
                        span,
                        format!(
                            "in usage `{usage}`: write `a|b` for alternatives inside an \
                             argument and ` | ` between forms of the line"
                        ),
                    ));
                }
                if before && !stack.is_empty() {
                    return Err(Error::new(
                        span,
                        format!(
                            "in usage `{usage}`: ` | ` separates whole forms, not words in a group"
                        ),
                    ));
                }
            }
            _ => {}
        }
    }
    if let Some(open) = stack.pop() {
        return Err(Error::new(
            span,
            format!("unclosed `{}` in usage `{usage}`", open as char),
        ));
    }
    Ok(())
}
