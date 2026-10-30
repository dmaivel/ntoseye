//! The macros' refusals: each misuse fails with its own message, not a
//! panic or a silently wrong expansion.

use proc_macro2::TokenStream;
use quote::quote;

/// The message of the error `result` must be.
fn refused(result: syn::Result<TokenStream>) -> String {
    match result {
        Ok(tokens) => panic!("expanded instead of refusing: {tokens}"),
        Err(error) => error.to_string(),
    }
}

#[test]
fn a_label_belongs_to_a_fieldless_enums_variant() {
    let message = refused(crate::record::expand(
        TokenStream::new(),
        quote! {
            pub struct Job {
                #[record(label = "Job ID")]
                pub id: u64,
            }
        },
    ));
    assert!(
        message.contains("`label` applies to a fieldless"),
        "{message}"
    );
    crate::record::expand(
        TokenStream::new(),
        quote! {
            pub enum Pool {
                #[record(rename = "nonpaged", label = "NonPaged")]
                NonPaged,
            }
        },
    )
    .expect("a fieldless enum's variant takes a label");
}

#[test]
fn a_shown_field_or_variant_cannot_be_conditional() {
    let message = refused(crate::record::expand(
        TokenStream::new(),
        quote! {
            pub struct Job {
                #[cfg(feature = "x")]
                pub id: u64,
            }
        },
    ));
    assert!(message.contains("cannot be conditional"), "{message}");
    let message = refused(crate::record::expand(
        quote!(tagged),
        quote! {
            pub enum End {
                Head,
                #[cfg(feature = "x")]
                Cycle { address: u64 },
            }
        },
    ));
    assert!(message.contains("cannot be conditional"), "{message}");
    crate::record::expand(
        TokenStream::new(),
        quote! {
            pub struct Job {
                pub id: u64,
                #[cfg(feature = "x")]
                #[record(skip)]
                pub raw: u64,
            }
        },
    )
    .expect("a skipped field may be conditional");
}

#[test]
fn a_rename_is_a_python_identifier() {
    let message = refused(crate::record::expand(
        TokenStream::new(),
        quote! {
            pub struct Job {
                #[record(rename = "job-id")]
                pub id: u64,
            }
        },
    ));
    assert!(message.contains("not a Python identifier"), "{message}");
}

#[test]
fn a_record_has_no_generics_or_lifetimes() {
    for item in [
        quote!(
            pub struct Job<T> {
                pub id: T,
            }
        ),
        quote!(
            pub struct Job<'a> {
                pub name: &'a str,
            }
        ),
    ] {
        let message = refused(crate::record::expand(TokenStream::new(), item));
        assert!(message.contains("generics or lifetimes"), "{message}");
    }
}

/// A command with `attr`, around `function`.
fn command(attr: TokenStream, function: TokenStream) -> syn::Result<TokenStream> {
    crate::command::expand(
        attr,
        quote! {
            /// Do it.
            #function
        },
    )
}

#[test]
fn python_names_classes_or_none() {
    let function = quote!(
        fn job(session: &Session) -> Result<Job> {}
    );
    let message = refused(command(
        quote!(names = ["!job"], category = "c", kind = Query, python = []),
        function.clone(),
    ));
    assert!(
        message.contains("`python = []` names no class"),
        "{message}"
    );
    let message = refused(command(
        quote!(
            names = ["!job"],
            category = "c",
            kind = Query,
            python = [none, Inspect]
        ),
        function,
    ));
    assert!(message.contains("`none` stands alone"), "{message}");
}

#[test]
fn flow_is_refused_beside_a_returned_flow() {
    let message = refused(command(
        quote!(
            names = ["q"],
            category = "c",
            kind = Host,
            python = none,
            flow = Quit
        ),
        quote!(
            fn quit(state: &mut ReplState<'_>) -> Result<Flow> {}
        ),
    ));
    assert!(message.contains("drop `flow`"), "{message}");
}

#[test]
fn a_run_does_not_map_over_each() {
    let message = refused(command(
        quote!(names = ["g"], category = "c", kind = Run, python = none),
        quote! {
            fn go(session: &mut Session, #[arg(each = addresses)] address: u64) -> Result<Motion> {}
        },
    ));
    assert!(message.contains("cannot map over an `each`"), "{message}");
}

#[test]
fn sequence_and_records_conflict_at_the_second_flag() {
    let message = refused(crate::collection::expand(
        quote!(sequence, records),
        quote!(impl Heaps {}),
    ));
    assert!(message.contains("indexed by position"), "{message}");
}

#[test]
fn eq_and_hash_are_written_together() {
    let message = refused(crate::handle::methods(quote! {
        [] { Thread (record = ThreadInfo, key = tid) }
        fn __eq__(&self, other: &Self) -> bool { true }
    }));
    assert!(message.contains("written together"), "{message}");
}
