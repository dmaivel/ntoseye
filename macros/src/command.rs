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
    let mut function: ItemFn = syn::parse2(item)?;
    let options = match Attr::parse(attr)? {
        Attr::Command(options) => *options,
        Attr::Form(form) => return expand_form(form, function),
    };
    let help = Help::from_docs(&function.attrs, function.sig.ident.span())?;
    let receiver = Receiver::parse(&function)?;
    let args = take_args(&mut function)?;
    let output = result_type(&function.sig.output)?;
    let docs = function
        .attrs
        .iter()
        .filter(|attr| attr.path().is_ident("doc"))
        .map(docstring_line)
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
    let forms = command.forms();
    Ok(quote! {
        #function
        #forms

        const _: () = {
            #repl
            #[linkme::distributed_slice(crate::repl::COMMANDS)]
            static SPEC: crate::repl::CommandSpec = #spec;
            #python
        };
    })
}

/// A form: one more SDK method of the command it names, from a function the
/// command's REPL operation calls. It has no REPL presence of its own (the
/// command's spec, usage and help cover it) and admits the command's
/// effects, which the command hands it as `__FORM_<command>_<form>`; that
/// constant exists only when the command lists the form in `forms`, so the
/// two must agree.
fn expand_form(form: FormOptions, mut function: ItemFn) -> Result<TokenStream> {
    let receiver = Receiver::parse(&function)?;
    if receiver == Receiver::Repl {
        return Err(Error::new(
            function.sig.span(),
            "a form is an SDK method: its first parameter is `&Session` or `&mut Session`",
        ));
    }
    if !function
        .attrs
        .iter()
        .any(|attr| attr.path().is_ident("doc"))
    {
        return Err(Error::new(
            function.sig.ident.span(),
            "a form needs a doc comment: its SDK method's docstring",
        ));
    }
    let args = take_args(&mut function)?;
    for arg in &args {
        let repl_only = arg.render
            || arg.switch.is_some()
            || arg.rest
            || arg.raw
            || arg.invoked
            || arg.parse.is_some()
            || arg.each.is_some()
            || arg.current;
        if repl_only {
            return Err(Error::new(
                arg.span,
                "a form's arguments are its SDK method's (`receiver`, `default`, `positional`, \
                 `Option<T>`, `sdk` for one the REPL line has no word for, and `name` and \
                 `complete` for its REPL usage); its command's REPL operation parses the line \
                 and calls it",
            ));
        }
    }
    let output = result_type(&function.sig.output)?;
    let docs: Vec<Attribute> = function
        .attrs
        .iter()
        .filter(|attr| attr.path().is_ident("doc"))
        .map(docstring_line)
        .collect();
    let effects = format_ident!("__FORM_{}_{}", form.command, function.sig.ident);
    let usage = format_ident!("__FORM_USAGE_{}_{}", form.command, function.sig.ident);
    let fragment = if form.sdk {
        quote!(None)
    } else {
        // The words after the command name: the selecting word, then each
        // argument the line gives (not a receiver, not an `sdk` one).
        let mut words = Vec::new();
        let mut completion = Vec::new();
        let strategy = quote!(crate::repl::CompletionStrategy);
        if let Some(word) = &form.word {
            words.push(word.value());
            completion.push(quote!(#strategy::None));
        }
        for arg in args.iter().filter(|arg| !arg.receiver && !arg.sdk) {
            words.push(if arg.omittable() {
                format!("[{}]", arg.usage_name())
            } else {
                format!("<{}>", arg.usage_name())
            });
            completion.push(match &arg.complete {
                Some(ident) => quote!(#strategy::#ident),
                None => quote!(#strategy::None),
            });
        }
        let words = words.join(" ");
        quote! {
            Some(crate::repl::FormUsage {
                usage: #words,
                completion: &[#(#completion),*],
            })
        }
    };
    let method = Method {
        function: &function.sig.ident,
        python_name: form.python_name.as_ref(),
        docs: &docs,
        receiver,
        args: &args,
        output: &output,
        effects: quote!(&#effects),
        run: None,
    };
    let python = form
        .python
        .iter()
        .map(|object| method.python(object))
        .collect::<Result<TokenStream>>()?;
    Ok(quote! {
        // A form is an SDK method first: the REPL may reach its operation
        // another way (`sdk` forms), so without Python it may go unused.
        #[cfg_attr(not(feature = "python"), allow(dead_code))]
        #function

        #[doc(hidden)]
        #[allow(non_upper_case_globals)]
        const #usage: ::std::option::Option<crate::repl::FormUsage> = #fragment;

        const _: () = {
            #python
        };
    })
}

/// A doc line as the Python docstring takes it: backslashes doubled, because
/// the stub writes the docstring verbatim into a `"""` literal, where `\R`
/// would be an invalid escape. (The help text keeps the doc comment as
/// written; a record field's doc comment escapes by hand instead.)
fn docstring_line(attr: &Attribute) -> Attribute {
    if let Meta::NameValue(value) = &attr.meta
        && let Expr::Lit(ExprLit {
            lit: Lit::Str(text),
            ..
        }) = &value.value
        && text.value().contains('\\')
    {
        let escaped = LitStr::new(&text.value().replace('\\', "\\\\"), text.span());
        return syn::parse_quote!(#[doc = #escaped]);
    }
    attr.clone()
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
    completion: Option<Completion>,
    /// The SDK classes the method goes on (`python = Process` or
    /// `python = [Process, UserProcess]`); empty is `python = none`: REPL
    /// only.
    python: Vec<Ident>,
    python_name: Option<LitStr>,
    /// How the line splits: `StructuredArgs` (words), or `RawTail` /
    /// `ExpressionTail` (unsplit, for a `raw` argument).
    style: Option<Ident>,
    /// The flow a command that returns a value (not a `Flow`) ends with.
    flow: Option<Ident>,
    /// The SDK methods of a command that is several SDK operations: the
    /// form functions (`#[command(form_of = ...)]`) its operation calls.
    forms: Vec<Ident>,
}

/// `#[command(form_of = command, python = Object, ...)]`.
struct FormOptions {
    /// The command (its function) whose REPL operation calls the form.
    command: Ident,
    python: Vec<Ident>,
    python_name: Option<LitStr>,
    /// The word that selects the form on the REPL line (a subcommand or a
    /// switch), before its arguments.
    word: Option<LitStr>,
    /// SDK-only: the REPL line has no form of it.
    sdk: bool,
}

/// What `#[command(...)]` declares: a command, or a form of one.
enum Attr {
    Command(Box<Options>),
    Form(FormOptions),
}

impl Attr {
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
        let mut forms = Vec::new();
        let mut form_of: Option<Ident> = None;
        let mut word: Option<LitStr> = None;
        let mut sdk = false;
        let mut command_keys = Vec::new();
        let mut form_keys = Vec::new();
        let parser = syn::meta::parser(|meta| {
            let key = meta
                .path
                .get_ident()
                .map(Ident::to_string)
                .unwrap_or_default();
            match key.as_str() {
                "form_of" | "python" | "python_name" => {}
                "word" | "sdk" => form_keys.push(meta.path.span()),
                _ => command_keys.push(meta.path.span()),
            }
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
                "completion" => completion = Some(Completion::parse(meta.value()?)?),
                "python" => python = Some(ident_list(meta.value()?)?),
                "python_name" => python_name = Some(meta.value()?.parse()?),
                "style" => style = Some(meta.value()?.parse()?),
                "flow" => flow = Some(meta.value()?.parse()?),
                "forms" => forms = ident_list(meta.value()?)?,
                "form_of" => form_of = Some(meta.value()?.parse()?),
                "word" => word = Some(meta.value()?.parse()?),
                "sdk" => sdk = true,
                _ => {
                    return Err(meta.error(
                        "expected `names`, `category`, `kind`, `target`, `state`, `run`, \
                         `writes`, `live_only`, `capability`, `usage`, `completion`, `python`, \
                         `python_name`, `style`, `flow`, `forms`, or a form's `form_of`, `word` \
                         and `sdk`",
                    ));
                }
            }
            Ok(())
        });
        syn::parse::Parser::parse2(parser, attr)?;
        let missing = |what: &str| Error::new(span, format!("#[command] needs `{what} = ...`"));
        let python: Option<Vec<Ident>> = python.map(|python| {
            python
                .into_iter()
                .filter(|object| object != "none")
                .collect()
        });
        if let Some(command) = form_of {
            if let Some(key) = command_keys.first() {
                return Err(Error::new(
                    *key,
                    "a form takes only `form_of`, `python`, `python_name`, `word` and `sdk`: \
                     its command declares the rest",
                ));
            }
            let python = python.ok_or_else(|| missing("python"))?;
            if python.is_empty() {
                return Err(Error::new(
                    span,
                    "a form is an SDK method: `python = Object`",
                ));
            }
            if sdk && word.is_some() {
                return Err(Error::new(span, "an `sdk` form has no REPL `word`"));
            }
            return Ok(Self::Form(FormOptions {
                command,
                python,
                python_name,
                word,
                sdk,
            }));
        }
        if let Some(key) = form_keys.first() {
            return Err(Error::new(
                *key,
                "`word` and `sdk` describe a form (`form_of = ...`)",
            ));
        }
        let names: Vec<LitStr> = names.ok_or_else(|| missing("names"))?;
        if names.is_empty() {
            return Err(Error::new(span, "`names` needs at least one name"));
        }
        // A command with forms has its SDK methods there.
        let python = match python {
            Some(python) if !forms.is_empty() && !python.is_empty() => {
                return Err(Error::new(
                    python[0].span(),
                    "a command with `forms` has its SDK methods there: drop `python`",
                ));
            }
            Some(python) => python,
            None if !forms.is_empty() => Vec::new(),
            None => return Err(missing("python")),
        };
        Ok(Self::Command(Box::new(Options {
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
            python,
            python_name,
            style,
            flow,
            forms,
        })))
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

/// `completion = ...`: a bare strategy completes every word with it, a list
/// one per word.
enum Completion {
    All(Ident),
    PerArg(Vec<Ident>),
}

impl Completion {
    fn parse(input: syn::parse::ParseStream<'_>) -> Result<Self> {
        if input.peek(syn::token::Bracket) {
            ident_list(input).map(Self::PerArg)
        } else {
            input.parse().map(Self::All)
        }
    }
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
    /// A `kind = Run` command's cancellation (`&Cancel`), which the host
    /// supplies: the REPL's stop budget, the SDK's `timeout`.
    cancel: bool,
    parse: Option<Path>,
    /// A custom parser that names several values: the REPL runs the
    /// operation on each and renders them together.
    each: Option<Path>,
    /// Bound from the SDK object the method is placed on.
    receiver: bool,
    /// SDK-only: the REPL never reads a word for it and passes `default`;
    /// Python takes it as a keyword with that default.
    sdk: bool,
    /// Positional in Python although it may be omitted: a subject (the
    /// address, name or object the method is about), not a mode.
    subject: bool,
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
        self.switch.is_none() && !self.raw && !self.invoked && !self.sdk && !self.cancel
    }

    /// Keyword-only in Python (after the `*`): an argument that may be
    /// omitted (a mode, flag or option), unless it is a `subject`.
    fn keyword(&self) -> bool {
        let omittable =
            self.optional.is_some() || self.default.is_some() || self.switch.is_some() || self.sdk;
        omittable && !self.subject
    }

    /// Supplied by the host, not parsed from the line.
    fn hosted(&self) -> bool {
        self.invoked || self.cancel
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
            cancel: false,
            parse: None,
            each: None,
            receiver: false,
            sdk: false,
            subject: false,
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
                    "cancel" => arg.cancel = true,
                    "parse" => arg.parse = Some(meta.value()?.parse()?),
                    "each" => arg.each = Some(meta.value()?.parse()?),
                    "receiver" => arg.receiver = true,
                    "sdk" => arg.sdk = true,
                    "positional" => arg.subject = true,
                    "name" => arg.name = Some(meta.value()?.parse()?),
                    "complete" => arg.complete = Some(meta.value()?.parse()?),
                    _ => {
                        return Err(meta.error(
                            "expected `render`, `default = ...`, `current`, `switch = \"/x\"`, \
                             `rest`, `raw`, `invoked`, `parse = path`, `each = path`, `receiver`, \
                             `sdk`, `positional`, `cancel`, `name = \"...\"` or `complete = \
                             Strategy`",
                        ));
                    }
                }
                Ok(())
            })?;
        }
        typed.attrs = kept;
        // A custom parser may return an `Option` of its own, and may name
        // the `default` the SDK's keyword takes (its parser supplies the
        // REPL's); an `sdk` argument's `default` is the REPL's value, and it
        // may be an `Option` too.
        let custom = arg.parse.is_some() || arg.each.is_some();
        let sources = [
            arg.default.is_some() && arg.parse.is_none() && !arg.sdk,
            arg.current,
            arg.switch.is_some(),
            arg.rest,
            arg.raw,
            arg.invoked,
            arg.cancel,
            arg.parse.is_some(),
            arg.each.is_some(),
            arg.optional.is_some() && !custom && !arg.sdk,
            arg.sdk,
        ];
        if sources.iter().filter(|set| **set).count() > 1 {
            return Err(Error::new(
                arg.span,
                "an argument takes one of `Option<T>`, `default`, `current`, `switch`, `rest`, \
                 `raw`, `invoked`, `cancel`, `parse`, `each` and `sdk`",
            ));
        }
        if arg.cancel && (arg.render || arg.receiver || arg.subject) {
            return Err(Error::new(
                arg.span,
                "a `cancel` argument is the host's, nothing else",
            ));
        }
        if arg.sdk && (arg.default.is_none() || arg.receiver) {
            return Err(Error::new(
                arg.span,
                "an `sdk` argument needs `default = ...` (the value the REPL passes), and is \
                 not a `receiver`",
            ));
        }
        if arg.sdk && arg.render {
            return Err(Error::new(
                arg.span,
                "an `sdk` argument is not a render option",
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

    /// Whether the REPL handler hands the dispatcher a [`Flow`]: the
    /// function's own, or the `flow = ...` it ends with.
    fn flow_handler(&self) -> bool {
        self.returns_flow() || self.options.flow.is_some()
    }

    fn is_run(&self) -> bool {
        self.options.kind == "Run"
    }

    /// Whether a `kind = Run` command returns the [`Motion`] its host drives
    /// (rather than driving the run itself through a `cancel` argument).
    fn returns_motion(&self) -> bool {
        matches!(&self.output, Type::Path(path)
            if path.path.segments.last().is_some_and(|segment| segment.ident == "Motion"))
    }

    fn validate(&self) -> Result<()> {
        let cancels = self.args.iter().filter(|arg| arg.cancel).count();
        if self.is_run() && (cancels > 1 || (cancels == 1) == self.returns_motion()) {
            return Err(Error::new(
                self.function.span(),
                "a `kind = Run` command returns the `Motion` its host drives, or takes one \
                 `#[arg(cancel)] cancel: &Cancel` and drives the run itself",
            ));
        }
        if !self.is_run()
            && let Some(arg) = self.args.iter().find(|arg| arg.cancel)
        {
            return Err(Error::new(
                arg.span,
                "a `cancel` argument belongs to a `kind = Run` command",
            ));
        }
        if self.is_run() && self.receiver != Receiver::SessionMut {
            return Err(Error::new(
                self.function.span(),
                "a `kind = Run` command takes `&mut Session`",
            ));
        }
        if let Some(object) = self.options.python.first()
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
        if let Some(object) = self.options.python.first() {
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
        } else if let Some(arg) = self.args.iter().find(|arg| arg.sdk || arg.subject) {
            return Err(Error::new(
                arg.span,
                "`sdk` and `positional` shape the method of a `python = Object` command",
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
            let part = if arg.hosted() || arg.sdk {
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
        match &self.options.completion {
            Some(Completion::All(ident)) => {
                let strategy = strategy(ident);
                return quote!(crate::repl::CompletionSpec::All(#strategy));
            }
            Some(Completion::PerArg(list)) => {
                let list = list.iter().map(strategy);
                return quote!(crate::repl::CompletionSpec::PerArg(&[#(#list),*]));
            }
            None => {}
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
        let handler = if self.flow_handler() {
            quote!(ArgsFlow)
        } else {
            quote!(Args)
        };
        let effects = self.effects();
        let forms = self
            .options
            .forms
            .iter()
            .map(|form| format_ident!("__FORM_USAGE_{}_{}", self.function, form));
        quote! {
            crate::repl::CommandSpec {
                names: &[#(#names),*],
                category: #category,
                kind: crate::repl::CommandKind::#kind,
                usage: #usage,
                summary: #summary,
                details: #details,
                completion: #completion,
                forms: &[#(#forms),*],
                effects: #effects,
                style: crate::repl::CommandStyle::#style,
                flow: crate::repl::Flow::#flow,
                handler: crate::repl::CommandHandler::#handler(repl),
            }
        }
    }

    /// The declared effects, as an `Effects` expression.
    fn effects(&self) -> TokenStream {
        let Options {
            target,
            state,
            run,
            writes,
            live_only,
            capability,
            ..
        } = &self.options;
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
            #effects::Effects {
                target: #effects::TargetScope::#target,
                state: #effects::RunState::#state,
                run: #effects::RunEffect::#run,
                writes: &[#(#effects::Writes::#writes),*],
                live_only: #live_only,
                capability: #capability,
            }
        }
    }

    /// What a command hands each of its forms: its effects, as the
    /// `__FORM_<command>_<form>` constant the form's SDK method admits (and
    /// names, so a form and its command must list each other).
    fn forms(&self) -> TokenStream {
        let effects = self.effects();
        self.options
            .forms
            .iter()
            .map(|form| {
                let name = format_ident!("__FORM_{}_{}", self.function, form);
                quote! {
                    #[cfg(feature = "python")]
                    #[doc(hidden)]
                    #[allow(non_upper_case_globals)]
                    const #name: crate::session::effects::Effects = #effects;
                }
            })
            .collect()
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
            .filter(|arg| arg.switch.is_none() && !arg.hosted())
        {
            let ident = &arg.ident;
            let ty = &arg.ty;
            let value_ty = arg.value_type();
            let from = quote!(<#value_ty as #args::FromArg>::from_arg(cx, &text)?);
            let step = if arg.sdk {
                let default = arg.default.as_ref().unwrap();
                quote!(let #ident: #ty = #default;)
            } else if let Some(path) = arg.parse.as_ref().or(arg.each.as_ref()) {
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
            .filter(|arg| !arg.hosted())
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
            .filter(|arg| !arg.hosted())
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
                if arg.cancel {
                    quote!(&__cancel)
                } else if arg.each.is_some() {
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
            // The REPL drives the motion and renders the stop.
            _ if self.is_run() && self.returns_motion() => quote! {
                match self::#function(#receiver, #(#call_args),*) {
                    Ok(motion) => state.run_motion(motion),
                    Err(error) => crate::repl::error(&error.to_string()),
                }
                Ok(())
            },
            // The operation drives the run within the REPL's stop budget.
            _ if self.is_run() => quote! {
                let __cancel = crate::repl::run_cancel(state.stop_wait.as_ref());
                let value = self::#function(#receiver, #(#call_args),*);
                match value {
                    Ok(value) => crate::repl::Render::render(&value, state, #options),
                    Err(error) => crate::repl::error(&error.to_string()),
                }
                Ok(())
            },
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
        // A command that ends with a flow of its own (`q` quits) ends with
        // it once it ran, but not when its line did not parse.
        let run = match &self.options.flow {
            Some(flow) if !returns_flow => quote! {
                #[allow(clippy::redundant_closure_call)]
                let () = (|| -> crate::error::Result<()> { #run })()?;
                Ok(crate::repl::Flow::#flow)
            },
            _ => run,
        };
        let (returns, parse_failed) = if self.flow_handler() {
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

    /// The SDK method, `#[pymethods]` on each `python = Object` class.
    fn python(&self) -> Result<TokenStream> {
        let method = Method {
            function: &self.function,
            python_name: self.options.python_name.as_ref(),
            docs: &self.docs,
            receiver: self.receiver,
            args: &self.args,
            output: &self.output,
            effects: quote!(&SPEC.effects),
            run: self.is_run().then(|| {
                if self.returns_motion() {
                    RunMode::Motion {
                        may_run_on: self
                            .options
                            .state
                            .as_ref()
                            .is_none_or(|state| state == "Any"),
                    }
                } else {
                    RunMode::Cancellable
                }
            }),
        };
        self.options
            .python
            .iter()
            .map(|object| method.python(object))
            .collect()
    }
}

/// An SDK method: a command's, or a form's.
struct Method<'a> {
    function: &'a Ident,
    python_name: Option<&'a LitStr>,
    /// The docstring.
    docs: &'a [Attribute],
    receiver: Receiver,
    args: &'a [Arg],
    output: &'a Type,
    /// The `&Effects` it admits.
    effects: TokenStream,
    /// How it drives a `kind = Run` command's run.
    run: Option<RunMode>,
}

/// How a `kind = Run` command's SDK method drives the run, through
/// `python::runcontrol`.
#[derive(Clone, Copy)]
enum RunMode {
    /// The command returns the `Motion`; `may_run_on` when it is admitted on
    /// a running target (`state = Any`), which a timeout can leave running.
    Motion { may_run_on: bool },
    /// The command drives the run itself through its `cancel` argument.
    Cancellable,
}

impl Method<'_> {
    /// The method on `object`, in a `#[pymethods]` block: the arguments the
    /// receiver does not bind and the REPL does not render become Python
    /// arguments, those that may be omitted keyword-only (`Arg::keyword`),
    /// and the call runs on the session thread through
    /// `crate::python::command::run`, which admits the effects.
    fn python(&self, object: &Ident) -> Result<TokenStream> {
        let python_name = self
            .python_name
            .map_or_else(|| self.function.to_string(), LitStr::value);
        let method = format_ident!("command_{}", self.function);
        let operation = format!("{object}.{python_name}");
        let docs = self.docs;
        let command = quote!(crate::python::command);
        let mut params = Vec::new();
        let mut signature = Vec::new();
        let mut bindings = Vec::new();
        // The arguments converted on the session thread ([`Pending`]).
        let mut pending = Vec::new();
        let mut keywords = false;
        // The `Debugger` has no `Owner` to check a handle argument against.
        let owner = quote!(#command::CommandHost::session(self).owner());
        for arg in self.args {
            if arg.render || arg.cancel {
                continue;
            }
            let ident = &arg.ident;
            let ty = &arg.ty;
            if arg.receiver {
                bindings.push(quote!(let #ident: #ty = <Self as #command::Bind<#ty>>::bind(self);));
                continue;
            }
            if arg.keyword() && !keywords {
                keywords = true;
                // A run's `timeout` goes before the keyword-only arguments.
                if self.run.is_some() {
                    params.push(quote!(timeout: ::std::option::Option<f64>));
                    signature.push(quote!(timeout = None));
                }
                signature.push(quote!(*));
            } else if keywords && !arg.keyword() {
                return Err(Error::new(
                    arg.span,
                    "a positional Python argument (a required one, or a `positional` one) \
                     comes before the keyword-only ones (those that may be omitted)",
                ));
            }
            params.push(quote!(#ident: <#ty as #command::SdkArg>::Py));
            bindings.push(quote! {
                let #ident = <#ty as #command::SdkArg>::from_sdk(py, #owner, #ident)?;
            });
            pending.push(ident);
            signature.push(if arg.sdk {
                let default = arg.default.as_ref().unwrap();
                quote!(#ident = #default)
            } else if arg.optional.is_some() {
                quote!(#ident = None)
            } else if arg.switch.is_some() {
                quote!(#ident = false)
            } else if let Some(default) = &arg.default {
                quote!(#ident = #default)
            } else {
                quote!(#ident)
            });
        }
        if self.run.is_some() && !keywords {
            params.push(quote!(timeout: ::std::option::Option<f64>));
            signature.push(quote!(timeout = None));
        }
        let receiver = match self.receiver {
            // Not `session`: a keyword argument may be named that (`!session`).
            Receiver::SessionMut => quote!(__session),
            Receiver::Session => quote!(&*__session),
            Receiver::Repl => unreachable!("validated"),
        };
        let function = self.function;
        let call: Vec<TokenStream> = self
            .args
            .iter()
            .filter(|arg| !arg.render)
            .map(|arg| {
                if arg.cancel {
                    quote!(__cancel)
                } else {
                    let ident = &arg.ident;
                    quote!(#ident)
                }
            })
            .collect();
        let output = self.output;
        let effects = &self.effects;
        // On the session thread, in the object's context and once the
        // effects are admitted: an address given as an expression evaluates
        // there, then the command runs.
        let body = quote! {
            #(let #pending = #pending.resolve(&*__session)?;)*
            self::#function(#receiver, #(#call),*)
        };
        if let Some(run) = self.run {
            let runcontrol = quote!(crate::python::runcontrol);
            let (driver, output, closure) = match run {
                RunMode::Cancellable => (
                    quote!(run_cancellable),
                    quote!(#output),
                    quote!(move |__session, __cancel| { #body }),
                ),
                // A run admitted on a running target (`g`) can still be
                // running when the timeout ends; any other ends on a stop.
                RunMode::Motion { may_run_on: true } => (
                    quote!(run_motion),
                    quote!(::std::option::Option<crate::session::Stop>),
                    quote!(move |__session| { #body }),
                ),
                RunMode::Motion { may_run_on: false } => (
                    quote!(run_motion_to_stop),
                    quote!(crate::session::Stop),
                    quote!(move |__session| { #body }),
                ),
            };
            return Ok(quote! {
                #[cfg(feature = "python")]
                #[pyo3::pymethods]
                impl #command::#object {
                    #(#docs)*
                    #[pyo3(name = #python_name, signature = (#(#signature),*))]
                    fn #method<'py>(
                        &self,
                        py: pyo3::Python<'py>,
                        #(#params),*
                    ) -> pyo3::PyResult<crate::python::record::Typed<'py, #output>> {
                        #(#bindings)*
                        #runcontrol::#driver(py, self, #operation, #effects, timeout, #closure)
                    }
                }
            });
        }
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
                ) -> pyo3::PyResult<crate::python::record::Typed<'py, #output>> {
                    #(#bindings)*
                    #command::run(py, self, #operation, #effects, move |__session| {
                        #body
                    })
                }
            }
        })
    }
}
