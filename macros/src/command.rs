//! `#[command]`: see the crate docs.

use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote};
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::{
    Attribute, Error, Expr, ExprLit, FnArg, GenericArgument, Ident, ItemFn, Lit, LitStr, Meta, Pat,
    Path, PathArguments, Result, ReturnType, Token, Type,
};

pub fn expand(attr: TokenStream, item: TokenStream) -> Result<TokenStream> {
    let options = Options::parse(attr)?;
    let mut function: ItemFn = syn::parse2(item)?;
    let help = Help::from_docs(&function.attrs, function.sig.ident.span())?;
    let receiver = Receiver::parse(&function)?;
    let args = take_args(&mut function)?;
    let output = result_type(&function.sig.output)?;
    let docs = function
        .attrs
        .iter()
        .filter(|attr| attr.path().is_ident("doc"))
        .cloned()
        .collect();
    let command = Command {
        options,
        help,
        docs,
        receiver,
        args,
        output,
        function: function.sig.ident.clone(),
    };
    command.validate()?;

    // The function as written, minus its render options (the REPL passes
    // them to `Render`, not to the operation) and the `#[arg]` attributes.
    function.sig.inputs = function
        .sig
        .inputs
        .iter()
        .enumerate()
        .filter(|(index, _)| *index == 0 || !command.args[index - 1].render)
        .map(|(_, input)| input.clone())
        .collect();
    let spec = command.spec();
    let repl = command.repl();
    let python = command.python()?;
    Ok(quote! {
        #function

        const _: () = {
            #repl
            #[linkme::distributed_slice(crate::repl::COMMANDS)]
            static SPEC: crate::repl::CommandSpec = #spec;
            #python
        };
    })
}

/// The `#[command(...)]` attribute.
struct Options {
    names: Vec<LitStr>,
    category: LitStr,
    kind: Ident,
    target: Option<Ident>,
    state: Option<Ident>,
    run: Option<Ident>,
    writes: Vec<Ident>,
    live_only: bool,
    capability: Option<Ident>,
    usage: Option<LitStr>,
    completion: Option<Vec<Ident>>,
    /// `None` is `python = none`: REPL only.
    python: Option<Ident>,
    python_name: Option<LitStr>,
    /// How the line splits: `StructuredArgs` (words), or `RawTail` /
    /// `ExpressionTail` (unsplit, for a `raw` argument).
    style: Option<Ident>,
    /// The flow a command that returns a value (not a `Flow`) ends with.
    flow: Option<Ident>,
}

impl Options {
    fn parse(attr: TokenStream) -> Result<Self> {
        let span = attr.span();
        let mut names = None;
        let mut category = None;
        let mut kind = None;
        let mut target = None;
        let mut state = None;
        let mut run = None;
        let mut writes = Vec::new();
        let mut live_only = false;
        let mut capability = None;
        let mut usage = None;
        let mut completion = None;
        let mut python = None;
        let mut python_name = None;
        let mut style = None;
        let mut flow = None;
        let parser = syn::meta::parser(|meta| {
            let key = meta
                .path
                .get_ident()
                .map(Ident::to_string)
                .unwrap_or_default();
            match key.as_str() {
                "names" => names = Some(lit_list(meta.value()?)?),
                "category" => category = Some(meta.value()?.parse()?),
                "kind" => kind = Some(meta.value()?.parse()?),
                "target" => target = Some(meta.value()?.parse()?),
                "state" => state = Some(meta.value()?.parse()?),
                "run" => run = Some(meta.value()?.parse()?),
                "writes" => writes = ident_list(meta.value()?)?,
                "live_only" => live_only = true,
                "capability" => capability = Some(meta.value()?.parse()?),
                "usage" => usage = Some(meta.value()?.parse()?),
                "completion" => completion = Some(ident_list(meta.value()?)?),
                "python" => python = Some(meta.value()?.parse::<Ident>()?),
                "python_name" => python_name = Some(meta.value()?.parse()?),
                "style" => style = Some(meta.value()?.parse()?),
                "flow" => flow = Some(meta.value()?.parse()?),
                _ => {
                    return Err(meta.error(
                        "expected `names`, `category`, `kind`, `target`, `state`, `run`, \
                         `writes`, `live_only`, `capability`, `usage`, `completion`, `python`, \
                         `python_name`, `style` or `flow`",
                    ));
                }
            }
            Ok(())
        });
        syn::parse::Parser::parse2(parser, attr)?;
        let missing = |what: &str| Error::new(span, format!("#[command] needs `{what} = ...`"));
        let names: Vec<LitStr> = names.ok_or_else(|| missing("names"))?;
        if names.is_empty() {
            return Err(Error::new(span, "`names` needs at least one name"));
        }
        let python = python.ok_or_else(|| missing("python"))?;
        Ok(Self {
            names,
            category: category.ok_or_else(|| missing("category"))?,
            kind: kind.ok_or_else(|| missing("kind"))?,
            target,
            state,
            run,
            writes,
            live_only,
            capability,
            usage,
            completion,
            python: (python != "none").then_some(python),
            python_name,
            style,
            flow,
        })
    }
}

/// `["a", "b"]`.
fn lit_list(input: syn::parse::ParseStream<'_>) -> Result<Vec<LitStr>> {
    let content;
    syn::bracketed!(content in input);
    Ok(Punctuated::<LitStr, Token![,]>::parse_terminated(&content)?
        .into_iter()
        .collect())
}

/// `[A, B]` or a single `A`.
fn ident_list(input: syn::parse::ParseStream<'_>) -> Result<Vec<Ident>> {
    if !input.peek(syn::token::Bracket) {
        return Ok(vec![input.parse()?]);
    }
    let content;
    syn::bracketed!(content in input);
    Ok(Punctuated::<Ident, Token![,]>::parse_terminated(&content)?
        .into_iter()
        .collect())
}

/// The doc comment: its first paragraph is the summary, the rest the
/// details. A paragraph's lines join with spaces, as the help text wraps
/// itself.
struct Help {
    summary: String,
    details: Option<String>,
}

impl Help {
    fn from_docs(attrs: &[Attribute], span: Span) -> Result<Self> {
        let mut paragraphs: Vec<String> = Vec::new();
        let mut current = String::new();
        for attr in attrs.iter().filter(|attr| attr.path().is_ident("doc")) {
            let Meta::NameValue(value) = &attr.meta else {
                continue;
            };
            let Expr::Lit(ExprLit {
                lit: Lit::Str(text),
                ..
            }) = &value.value
            else {
                continue;
            };
            for line in text.value().split('\n') {
                let line = line.strip_prefix(' ').unwrap_or(line).trim_end();
                if line.is_empty() {
                    if !current.is_empty() {
                        paragraphs.push(std::mem::take(&mut current));
                    }
                } else {
                    if !current.is_empty() {
                        current.push(' ');
                    }
                    current.push_str(line);
                }
            }
        }
        if !current.is_empty() {
            paragraphs.push(current);
        }
        let mut paragraphs = paragraphs.into_iter();
        let summary = paragraphs.next().ok_or_else(|| {
            Error::new(
                span,
                "a #[command] needs a doc comment: its first paragraph is the summary",
            )
        })?;
        let rest: Vec<String> = paragraphs.collect();
        Ok(Self {
            summary,
            details: (!rest.is_empty()).then(|| rest.join("\n\n")),
        })
    }
}

/// What the operation's first parameter receives.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Receiver {
    /// `&mut Session`.
    SessionMut,
    /// `&Session`.
    Session,
    /// `&mut ReplState`: a REPL-only command.
    Repl,
}

impl Receiver {
    fn parse(function: &ItemFn) -> Result<Self> {
        let error = || {
            Error::new(
                function.sig.span(),
                "a #[command]'s first parameter is `&Session`, `&mut Session` or \
                 `&mut ReplState`",
            )
        };
        let Some(FnArg::Typed(first)) = function.sig.inputs.first() else {
            return Err(error());
        };
        let Type::Reference(reference) = &*first.ty else {
            return Err(error());
        };
        let Type::Path(path) = &*reference.elem else {
            return Err(error());
        };
        let name = path.path.segments.last().map(|segment| &segment.ident);
        match (
            name.map(Ident::to_string).as_deref(),
            reference.mutability.is_some(),
        ) {
            (Some("Session"), true) => Ok(Self::SessionMut),
            (Some("Session"), false) => Ok(Self::Session),
            (Some("ReplState"), true) => Ok(Self::Repl),
            _ => Err(error()),
        }
    }
}

/// One argument after the receiver, with its `#[arg(...)]` options.
struct Arg {
    ident: Ident,
    ty: Type,
    /// `T` of an `Option<T>`: omitted is `None`.
    optional: Option<Type>,
    /// A REPL display option, passed to `Render` rather than the operation.
    render: bool,
    default: Option<Expr>,
    /// Omitted is the current one (`Current`).
    current: bool,
    switch: Option<LitStr>,
    /// The rest of the line's words, joined by spaces.
    rest: bool,
    /// The line after the command name, unsplit and unquoted (`style =
    /// RawTail` or `ExpressionTail`).
    raw: bool,
    /// The name the command was typed as (`echo` or `.echo`).
    invoked: bool,
    parse: Option<Path>,
    /// A custom parser that names several values: the REPL runs the
    /// operation on each and renders them together.
    each: Option<Path>,
    /// Bound from the SDK object the method is placed on.
    receiver: bool,
    name: Option<LitStr>,
    complete: Option<Ident>,
    span: Span,
}

impl Arg {
    fn usage_name(&self) -> String {
        match &self.name {
            Some(name) => name.value(),
            None => self
                .ident
                .to_string()
                .trim_start_matches('_')
                .replace('_', "-"),
        }
    }

    fn omittable(&self) -> bool {
        self.optional.is_some() || self.default.is_some() || self.current
    }

    fn positional(&self) -> bool {
        self.switch.is_none() && !self.raw && !self.invoked
    }

    /// The type whose `FromArg`/`PyArg` reads it: `T` of an `Option<T>`.
    fn value_type(&self) -> &Type {
        self.optional.as_ref().unwrap_or(&self.ty)
    }
}

fn take_args(function: &mut ItemFn) -> Result<Vec<Arg>> {
    let mut args = Vec::new();
    for input in function.sig.inputs.iter_mut().skip(1) {
        let FnArg::Typed(typed) = input else {
            return Err(Error::new(input.span(), "unexpected receiver"));
        };
        let Pat::Ident(pat) = &*typed.pat else {
            return Err(Error::new(
                typed.pat.span(),
                "a #[command] argument is a plain name",
            ));
        };
        let mut arg = Arg {
            ident: pat.ident.clone(),
            ty: (*typed.ty).clone(),
            optional: option_inner(&typed.ty),
            render: false,
            default: None,
            current: false,
            switch: None,
            rest: false,
            raw: false,
            invoked: false,
            parse: None,
            each: None,
            receiver: false,
            name: None,
            complete: None,
            span: typed.span(),
        };
        let mut kept = Vec::new();
        for attr in typed.attrs.drain(..) {
            if !attr.path().is_ident("arg") {
                kept.push(attr);
                continue;
            }
            attr.parse_nested_meta(|meta| {
                let key = meta
                    .path
                    .get_ident()
                    .map(Ident::to_string)
                    .unwrap_or_default();
                match key.as_str() {
                    "render" => arg.render = true,
                    "default" => arg.default = Some(meta.value()?.parse()?),
                    "current" => arg.current = true,
                    "switch" => arg.switch = Some(meta.value()?.parse()?),
                    "rest" => arg.rest = true,
                    "raw" => arg.raw = true,
                    "invoked" => arg.invoked = true,
                    "parse" => arg.parse = Some(meta.value()?.parse()?),
                    "each" => arg.each = Some(meta.value()?.parse()?),
                    "receiver" => arg.receiver = true,
                    "name" => arg.name = Some(meta.value()?.parse()?),
                    "complete" => arg.complete = Some(meta.value()?.parse()?),
                    _ => {
                        return Err(meta.error(
                            "expected `render`, `default = ...`, `current`, `switch = \"/x\"`, \
                             `rest`, `raw`, `invoked`, `parse = path`, `each = path`, `receiver`, \
                             `name = \"...\"` or `complete = Strategy`",
                        ));
                    }
                }
                Ok(())
            })?;
        }
        typed.attrs = kept;
        // A custom parser may return an `Option` of its own, and may name
        // the `default` the SDK's keyword takes (its parser supplies the
        // REPL's).
        let custom = arg.parse.is_some() || arg.each.is_some();
        let sources = [
            arg.default.is_some() && arg.parse.is_none(),
            arg.current,
            arg.switch.is_some(),
            arg.rest,
            arg.raw,
            arg.invoked,
            arg.parse.is_some(),
            arg.each.is_some(),
            arg.optional.is_some() && !custom,
        ];
        if sources.iter().filter(|set| **set).count() > 1 {
            return Err(Error::new(
                arg.span,
                "an argument takes one of `Option<T>`, `default`, `current`, `switch`, `rest`, \
                 `raw`, `invoked`, `parse` and `each`",
            ));
        }
        args.push(arg);
    }
    Ok(args)
}

/// `T` when `ty` is `Option<T>`.
fn option_inner(ty: &Type) -> Option<Type> {
    let Type::Path(path) = ty else {
        return None;
    };
    let segment = path.path.segments.last()?;
    if segment.ident != "Option" {
        return None;
    }
    let PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return None;
    };
    match arguments.args.first()? {
        GenericArgument::Type(inner) => Some(inner.clone()),
        _ => None,
    }
}

/// `R` of the operation's `-> Result<R>`.
fn result_type(output: &ReturnType) -> Result<Type> {
    let error = || Error::new(output.span(), "a #[command] returns `Result<R>`");
    let ReturnType::Type(_, ty) = output else {
        return Err(error());
    };
    let Type::Path(path) = &**ty else {
        return Err(error());
    };
    let segment = path.path.segments.last().ok_or_else(error)?;
    if segment.ident != "Result" {
        return Err(error());
    }
    let PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return Err(error());
    };
    match arguments.args.first() {
        Some(GenericArgument::Type(inner)) => Ok(inner.clone()),
        _ => Err(error()),
    }
}

struct Command {
    options: Options,
    help: Help,
    /// The doc comment as written: the Python docstring.
    docs: Vec<Attribute>,
    receiver: Receiver,
    args: Vec<Arg>,
    output: Type,
    function: Ident,
}

impl Command {
    /// Whether the function returns a [`Flow`] (a command that runs other
    /// commands, or a control token) rather than a value to render.
    fn returns_flow(&self) -> bool {
        matches!(&self.output, Type::Path(path)
            if path.path.segments.last().is_some_and(|segment| segment.ident == "Flow"))
    }

    fn validate(&self) -> Result<()> {
        if let Some(object) = &self.options.python
            && (self.options.kind == "Host" || self.returns_flow())
        {
            return Err(Error::new(
                object.span(),
                "a `kind = Host` command, or one returning `Flow`, is REPL-only: `python = none`",
            ));
        }
        if let Some(arg) = self.args.iter().find(|arg| arg.invoked && arg.render) {
            return Err(Error::new(
                arg.span,
                "an `invoked` argument is not a render option",
            ));
        }
        if self.args.iter().filter(|arg| arg.each.is_some()).count() > 1 {
            return Err(Error::new(
                self.function.span(),
                "a #[command] maps over one `each` argument",
            ));
        }
        if let Some(object) = &self.options.python {
            if self.receiver == Receiver::Repl {
                return Err(Error::new(
                    object.span(),
                    "a command on `&mut ReplState` is REPL-only: `python = none`",
                ));
            }
            for arg in &self.args {
                if arg.receiver || arg.render {
                    continue;
                }
                let why = if arg.each.is_some() {
                    Some("`each`")
                } else if arg.raw || arg.invoked {
                    Some("REPL-text")
                } else if arg.current {
                    Some("`current`")
                } else if arg.rest {
                    Some("`rest`")
                } else {
                    None
                };
                if let Some(why) = why {
                    return Err(Error::new(
                        arg.span,
                        format!(
                            "a {why} argument has no Python form: bind it with `receiver`, or \
                             make the command `python = none`"
                        ),
                    ));
                }
            }
        } else if let Some(arg) = self.args.iter().find(|arg| arg.receiver) {
            return Err(Error::new(
                arg.span,
                "`receiver` binds an argument from the `python = Object` the method is on",
            ));
        }
        Ok(())
    }

    fn usage(&self) -> String {
        if let Some(usage) = &self.options.usage {
            return usage.value();
        }
        let mut usage = self.options.names[0].value();
        for arg in &self.args {
            let part = if arg.invoked {
                continue;
            } else if let Some(switch) = &arg.switch {
                format!("[{}]", switch.value())
            } else if arg.rest || arg.raw {
                format!("[{}...]", arg.usage_name())
            } else if arg.omittable() {
                format!("[{}]", arg.usage_name())
            } else {
                format!("<{}>", arg.usage_name())
            };
            usage.push(' ');
            usage.push_str(&part);
        }
        usage
    }

    fn completion(&self) -> TokenStream {
        let strategy = |ident: &Ident| quote!(crate::repl::CompletionStrategy::#ident);
        if let Some(list) = &self.options.completion {
            let list = list.iter().map(strategy);
            return quote!(crate::repl::CompletionSpec::PerArg(&[#(#list),*]));
        }
        let list: Vec<TokenStream> = self
            .args
            .iter()
            .filter(|arg| arg.positional())
            .map(|arg| match (&arg.complete, &arg.parse, &arg.each) {
                (Some(ident), _, _) => strategy(ident),
                (None, None, None) => {
                    let ty = arg.value_type();
                    quote!(<#ty as crate::repl::args::FromArg>::COMPLETION)
                }
                _ => quote!(crate::repl::CompletionStrategy::None),
            })
            .collect();
        if list.is_empty() {
            quote!(crate::repl::CompletionSpec::None)
        } else {
            quote!(crate::repl::CompletionSpec::PerArg(&[#(#list),*]))
        }
    }

    fn spec(&self) -> TokenStream {
        let Options {
            names,
            category,
            kind,
            target,
            state,
            run,
            writes,
            live_only,
            capability,
            ..
        } = &self.options;
        let usage = self.usage();
        let summary = &self.help.summary;
        let details = match &self.help.details {
            Some(details) => quote!(Some(#details)),
            None => quote!(None),
        };
        let completion = self.completion();
        let style = self
            .options
            .style
            .as_ref()
            .map_or_else(|| quote!(StructuredArgs), |ident| quote!(#ident));
        let flow = self
            .options
            .flow
            .as_ref()
            .map_or_else(|| quote!(Continue), |ident| quote!(#ident));
        let handler = if self.returns_flow() {
            quote!(ArgsFlow)
        } else {
            quote!(Args)
        };
        let effects = quote!(crate::session::effects);
        let target = target
            .as_ref()
            .map_or_else(|| quote!(Any), |ident| quote!(#ident));
        let state = state
            .as_ref()
            .map_or_else(|| quote!(Any), |ident| quote!(#ident));
        let run = run
            .as_ref()
            .map_or_else(|| quote!(None), |ident| quote!(#ident));
        let capability = match capability {
            Some(ident) => quote!(Some(crate::dbg_backend::DebugCapability::#ident)),
            None => quote!(None),
        };
        quote! {
            crate::repl::CommandSpec {
                names: &[#(#names),*],
                category: #category,
                kind: Some(crate::repl::CommandKind::#kind),
                usage: #usage,
                summary: #summary,
                details: #details,
                completion: #completion,
                effects: #effects::Effects {
                    target: #effects::TargetScope::#target,
                    state: #effects::RunState::#state,
                    run: #effects::RunEffect::#run,
                    writes: &[#(#effects::Writes::#writes),*],
                    live_only: #live_only,
                    capability: #capability,
                },
                style: crate::repl::CommandStyle::#style,
                flow: crate::repl::Flow::#flow,
                handler: crate::repl::CommandHandler::#handler(repl),
            }
        }
    }

    /// The REPL handler: parse the arguments in the order the function
    /// declares them, run the operation (on each value of an `each`
    /// argument), and render the result with the render options.
    fn repl(&self) -> TokenStream {
        let args = quote!(crate::repl::args);
        let switches: Vec<&LitStr> = self
            .args
            .iter()
            .filter_map(|arg| arg.switch.as_ref())
            .collect();
        let mut steps = Vec::new();
        for arg in self.args.iter().filter(|arg| arg.switch.is_some()) {
            let ident = &arg.ident;
            let switch = arg.switch.as_ref().unwrap();
            steps.push(quote!(let #ident = cursor.switch(#switch);));
        }
        if !switches.is_empty() {
            steps.push(quote!(cursor.reject_switches(cx.name, &[#(#switches),*])?;));
        }
        for arg in self
            .args
            .iter()
            .filter(|arg| arg.switch.is_none() && !arg.invoked)
        {
            let ident = &arg.ident;
            let ty = &arg.ty;
            let value_ty = arg.value_type();
            let from = quote!(<#value_ty as #args::FromArg>::from_arg(cx, &text)?);
            let step = if let Some(path) = arg.parse.as_ref().or(arg.each.as_ref()) {
                quote!(let #ident = #path(cx, cursor)?;)
            } else if arg.rest {
                quote!(let #ident: #ty = cursor.rest();)
            } else if arg.raw {
                quote!(let #ident: #ty = cursor.raw();)
            } else if arg.optional.is_some() {
                quote! {
                    let #ident: #ty = match cursor.word() {
                        Some(text) => Some(#from),
                        None => None,
                    };
                }
            } else if let Some(default) = &arg.default {
                quote! {
                    let #ident: #ty = match cursor.word() {
                        Some(text) => #from,
                        None => #default,
                    };
                }
            } else if arg.current {
                quote! {
                    let #ident: #ty = match cursor.word() {
                        Some(text) => #from,
                        None => <#ty as #args::Current>::current(cx)?,
                    };
                }
            } else {
                quote! {
                    let #ident: #ty = match cursor.word() {
                        Some(text) => #from,
                        None => return Err(#args::ArgError::Missing),
                    };
                }
            };
            steps.push(step);
        }
        let parsed: Vec<&Ident> = self
            .args
            .iter()
            .filter(|arg| !arg.invoked)
            .map(|arg| &arg.ident)
            .collect();
        let invoked: Vec<&Ident> = self
            .args
            .iter()
            .filter(|arg| arg.invoked)
            .map(|arg| &arg.ident)
            .collect();
        let parsed_types: Vec<TokenStream> = self
            .args
            .iter()
            .filter(|arg| !arg.invoked)
            .map(|arg| {
                let ty = &arg.ty;
                if arg.each.is_some() {
                    quote!(::std::vec::Vec<#ty>)
                } else {
                    quote!(#ty)
                }
            })
            .collect();

        let receiver = match self.receiver {
            Receiver::SessionMut => quote!(&mut *state.ctx),
            Receiver::Session => quote!(&*state.ctx),
            Receiver::Repl => quote!(&mut *state),
        };
        let function = &self.function;
        let call_args: Vec<TokenStream> = self
            .args
            .iter()
            .filter(|arg| !arg.render)
            .map(|arg| {
                let ident = &arg.ident;
                if arg.each.is_some() {
                    quote!(item)
                } else if self.args.iter().any(|arg| arg.each.is_some()) {
                    quote!(::std::clone::Clone::clone(&#ident))
                } else {
                    quote!(#ident)
                }
            })
            .collect();
        let render: Vec<&Ident> = self
            .args
            .iter()
            .filter(|arg| arg.render)
            .map(|arg| &arg.ident)
            .collect();
        let options = match render.as_slice() {
            [] => quote!(()),
            [one] => quote!(#one),
            many => quote!((#(#many),*)),
        };
        let returns_flow = self.returns_flow();
        let run = match self.args.iter().find(|arg| arg.each.is_some()) {
            _ if returns_flow => quote!(self::#function(#receiver, #(#call_args),*)),
            Some(each) => {
                let ident = &each.ident;
                quote! {
                    let mut values = ::std::vec::Vec::with_capacity(#ident.len());
                    for item in #ident {
                        match self::#function(#receiver, #(#call_args),*) {
                            Ok(value) => values.push(value),
                            Err(error) => {
                                crate::repl::error(&error.to_string());
                                return Ok(());
                            }
                        }
                    }
                    crate::repl::Render::render(&values, state, #options);
                    Ok(())
                }
            }
            None => quote! {
                match self::#function(#receiver, #(#call_args),*) {
                    Ok(value) => crate::repl::Render::render(&value, state, #options),
                    Err(error) => crate::repl::error(&error.to_string()),
                }
                Ok(())
            },
        };
        let (returns, parse_failed) = if returns_flow {
            (
                quote!(crate::repl::Flow),
                quote!(crate::repl::Flow::Continue),
            )
        } else {
            (quote!(()), quote!(()))
        };
        quote! {
            #[allow(unused_variables, clippy::unnecessary_wraps)]
            fn parse(
                cx: &mut #args::ArgCx<'_, '_>,
                cursor: &mut #args::ArgCursor<'_>,
            ) -> ::std::result::Result<(#(#parsed_types,)*), #args::ArgError> {
                #(#steps)*
                cursor.finish(cx.name)?;
                Ok((#(#parsed,)*))
            }

            fn repl(
                state: &mut crate::repl::ReplState<'_>,
                invocation: crate::repl::CommandInvocation<'_>,
            ) -> crate::error::Result<#returns> {
                let name = invocation.name;
                let mut cursor = #args::ArgCursor::new(invocation);
                let parsed = parse(&mut #args::ArgCx { state: &mut *state, name }, &mut cursor);
                let (#(#parsed,)*) = match parsed {
                    Ok(parsed) => parsed,
                    Err(error) => {
                        error.report(name);
                        return Ok(#parse_failed);
                    }
                };
                #(let #invoked: &str = name;)*
                #run
            }
        }
    }

    /// The SDK method, `#[pymethods]` on the `python = Object` class: the
    /// arguments the receiver does not bind and the REPL does not render
    /// become keyword arguments, and the call runs on the session thread
    /// through `crate::python::command::run`, which admits the effects.
    fn python(&self) -> Result<TokenStream> {
        let Some(object) = &self.options.python else {
            return Ok(TokenStream::new());
        };
        let python_name = self
            .options
            .python_name
            .as_ref()
            .map_or_else(|| self.function.to_string(), LitStr::value);
        let method = format_ident!("command_{}", self.function);
        let operation = format!("{object}.{python_name}");
        let docs = &self.docs;
        let command = quote!(crate::python::command);
        let mut params = Vec::new();
        let mut signature = Vec::new();
        let mut bindings = Vec::new();
        for arg in &self.args {
            if arg.render {
                continue;
            }
            let ident = &arg.ident;
            let ty = &arg.ty;
            if arg.receiver {
                bindings.push(quote!(let #ident: #ty = <Self as #command::Bind<#ty>>::bind(self);));
                continue;
            }
            params.push(quote!(#ident: <#ty as #command::PyArg>::Py));
            bindings.push(quote!(let #ident = <#ty as #command::PyArg>::from_py(#ident);));
            signature.push(if arg.optional.is_some() {
                quote!(#ident = None)
            } else if arg.switch.is_some() {
                quote!(#ident = false)
            } else if let Some(default) = &arg.default {
                quote!(#ident = #default)
            } else {
                quote!(#ident)
            });
        }
        let receiver = match self.receiver {
            Receiver::SessionMut => quote!(session),
            Receiver::Session => quote!(&*session),
            Receiver::Repl => unreachable!("validated"),
        };
        let function = &self.function;
        let call: Vec<&Ident> = self
            .args
            .iter()
            .filter(|arg| !arg.render)
            .map(|arg| &arg.ident)
            .collect();
        let output = &self.output;
        Ok(quote! {
            #[cfg(feature = "python")]
            #[pyo3::pymethods]
            impl #command::#object {
                #(#docs)*
                #[pyo3(name = #python_name, signature = (#(#signature),*))]
                fn #method<'py>(
                    &self,
                    py: pyo3::Python<'py>,
                    #(#params),*
                ) -> pyo3::PyResult<crate::view::record::Typed<'py, #output>> {
                    #(#bindings)*
                    #command::run(py, self, #operation, &SPEC.effects, move |session| {
                        self::#function(#receiver, #(#call),*)
                    })
                }
            }
        })
    }
}
