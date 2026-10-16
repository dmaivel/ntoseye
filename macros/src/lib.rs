//! Procedural macros for ntoseye. They expand to paths inside the `ntoseye`
//! crate (`crate::view::record`, `crate::python::record`, `crate::repl`,
//! `crate::python::command`), so only that crate can use them.

mod command;
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

/// One debugger operation: its REPL command, its Python SDK method and its
/// docs entry, from one function.
///
/// ```ignore
/// /// Show a job object and the processes in it.
/// ///
/// /// Details paragraph(s).
/// #[command(names = ["!job", "job"], category = "processes and threads",
///           kind = Query, target = Kernel, python = Inspect)]
/// fn job(session: &mut Session, address: Option<VirtAddr>,
///        #[arg(render, default = 1)] flags: u64) -> Result<Job> { ... }
/// ```
///
/// The doc comment's first paragraph is the summary, the rest the details
/// (the `help` text, the command reference, the Python docstring). The
/// attribute takes:
///
/// - `names = [...]` (the first is canonical), `category = "..."`,
///   `kind = Query | Action | Run | Host`, and `python = Object | [Object,
///   ...] | none` (one method on each class: a kernel and a user-dump
///   class can share a command);
/// - effects, which `Session::admit` enforces for every host: `target =
///   Any | Kernel`, `state = Any | Halted | HaltedOrParkedThread | Running`,
///   `run = None | Step | Run`, `writes = [Memory, Registers, Hardware,
///   Breakpoints, Symbols, Files]`, `live_only`, `capability =
///   <DebugCapability>`;
/// - overrides: `usage = "..."` (else generated from the arguments),
///   `completion = [Strategy, ...]` (one per word; else from the argument
///   types) or `completion = Strategy` (every word),
///   `python_name = "..."` (else the function's name), `style = RawTail |
///   ExpressionTail` (the line is not split into words, for a `raw`
///   argument), and `flow = Quit` (the flow the command ends with once it
///   ran; a line that does not parse ends with `Continue`).
///
/// The first parameter is `&Session`, `&mut Session`, or (REPL only)
/// `&mut ReplState`. Every other parameter is an argument, parsed in order
/// by `FromArg` from the REPL line; `#[arg(...)]` says how:
///
/// - `Option<T>`: may be omitted; `default = expr`: omitted is `expr`;
///   `current`: omitted is the current one (`Current`);
/// - `switch = "/x"`: a `bool` switch anywhere on the line;
/// - `rest`: the words left, joined, as one `String`; `raw`: the line after
///   the name, unsplit (with `style = RawTail`, quotes and `;` intact);
///   `invoked`: a `&str`, the name the command was typed as;
/// - `parse = path`: a custom parser `fn(&mut ArgCx, &mut ArgCursor) ->
///   Result<T, ArgError>`, which may take a `default` too: the SDK keyword's
///   default, as the parser gives the REPL's; `each = path`: one returning
///   `Vec<T>`, which the
///   REPL runs the operation on in turn, rendering the `Vec` of results;
/// - `render`: a display option (WinDbg's flags that only choose what the
///   text shows), not passed to the function: the REPL passes the render
///   options to `Render::render` (one value, or a tuple in order);
/// - `receiver`: the Python method's object binds it (`Bind<T>`);
/// - `sdk` (with `default = expr`): an SDK-only keyword; the REPL reads no
///   word for it and passes `expr`, Python's keyword defaults to `expr`;
/// - `keyword`: keyword-only in Python (after a `*`); every Python argument
///   after it must be `keyword` too;
/// - `cancel`: a `kind = Run` command's `&Cancel`, which the host supplies
///   (the REPL's stop budget, the SDK's `timeout`);
/// - `name = "..."`, `complete = Strategy`: its usage name and completion.
///
/// The function returns `Result<R>`. The REPL renders `R` with
/// `Render`, except a `Result<Flow>`, which a command that runs other
/// commands (`.foreach`, `.if`) returns to the dispatcher as it is; `python = Object` adds a method to that SDK class (through
/// PyO3's `multiple-pymethods`) whose keyword arguments are the arguments
/// that are neither bound nor rendered (`SdkArg`: every `PyArg`, and
/// addresses, which Python may give as a debugger expression that the
/// session evaluates in the method's context before the call), whose
/// docstring is the doc comment, and which returns `R`'s record class.
///
/// **Several SDK methods behind one REPL name.** When one REPL command is
/// several SDK operations (`!locks` decodes one resource or lists them all),
/// each operation is a *form*: a function of its own, with its own return
/// type and docstring, marked
/// `#[command(form_of = locks, python = Inspect, python_name = "...")]`.
/// The command lists them, `forms = [resource,
/// resources]` instead of `python`, and its REPL operation parses the line as
/// before and calls the form it names (usually; a form may also be an SDK
/// operation the REPL reaches its own way), returning a REPL-only enum of
/// their results. A form has no help or reference entry of its own; its SDK
/// method admits the command's effects. Its arguments are all the method's:
/// `Option<T>`, `default`, `keyword` and `receiver` apply (a REPL-only
/// option is refused), so a form can take what the REPL grammar has no word
/// for, such as an object handle (`PyArg for ProcessInfo` takes a `Process`).
///
/// Each form also describes its REPL form, for usage and completion generated
/// from forms (`CommandSpec::forms`, in the command's `forms` order): `word =
/// "/p"` is the subcommand or switch that selects it, then each argument the
/// line gives, `<name>` or `[name]` (`#[arg(name = ...)]`, completed by
/// `#[arg(complete = ...)]`); an `#[arg(sdk, default = e)]` argument and a
/// `receiver` have no word. A bare `sdk` key marks an SDK-only form, which
/// the line has no form of. A form and its command name each other (the
/// command hands the form its effects as `__FORM_<command>_<form>` and takes
/// its usage as `__FORM_USAGE_<command>_<form>`), and both live in one
/// module.
///
/// A `kind = Run` command takes `&mut Session` and either returns the
/// `Motion` its host drives through `Session::run`, or takes a `cancel`
/// argument and drives the run itself (`wt`). The REPL drives a motion with
/// its wait loop (`ReplState::run_motion`) and renders the `Stop`; the SDK
/// method takes a `timeout` (before any keyword-only arguments), settles the
/// motion with the `when=` callbacks (`python::runcontrol`) and returns the
/// `Stop`, or `Stop | None` for a command admitted on a running target
/// (`state = Any`), which can still be running when the timeout ends.
#[proc_macro_attribute]
pub fn command(attr: TokenStream, item: TokenStream) -> TokenStream {
    command::expand(attr.into(), item.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}
