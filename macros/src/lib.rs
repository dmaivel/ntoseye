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
///   `kind = Query | Action | Run | Host`, and `python = Object | none`;
/// - effects, which `Session::admit` enforces for every host: `target =
///   Any | Kernel`, `state = Any | Halted | HaltedOrParkedThread | Running`,
///   `run = None | Step | Run`, `writes = [Memory, Registers, Hardware,
///   Breakpoints, Symbols, Files]`, `live_only`, `capability =
///   <DebugCapability>`;
/// - overrides: `usage = "..."` (else generated from the arguments),
///   `completion = [Strategy, ...]` (one per word; else from the argument
///   types) or `completion = Strategy` (every word, as `repl_command!`'s
///   bare `completion: Expression`),
///   `python_name = "..."` (else the function's name), `style = RawTail |
///   ExpressionTail` (the line is not split into words, for a `raw`
///   argument), and `flow = Quit` (the flow the command ends with).
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
/// - `name = "..."`, `complete = Strategy`: its usage name and completion.
///
/// The function returns `Result<R>`. The REPL renders `R` with
/// `Render`, except a `Result<Flow>`, which a command that runs other
/// commands (`.foreach`, `.if`) returns to the dispatcher as it is; `python = Object` adds a method to that SDK class (through
/// PyO3's `multiple-pymethods`) whose keyword arguments are the arguments
/// that are neither bound nor rendered (`PyArg`), whose docstring is the doc
/// comment, and which returns `R`'s record class.
#[proc_macro_attribute]
pub fn command(attr: TokenStream, item: TokenStream) -> TokenStream {
    command::expand(attr.into(), item.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}
