//! Procedural macros for ntoseye. They expand to paths inside the `ntoseye`
//! crate (`crate::python::record`, `crate::repl`, `crate::python::command`),
//! so only that crate can use them.

mod collection;
mod command;
mod grammar;
mod handle;
mod record;
#[cfg(test)]
mod tests;

use proc_macro::TokenStream;

/// One type for Rust, the REPL and the Python SDK.
///
/// On a struct with named fields, `#[record]` keeps the struct as written
/// (adding `Debug` and `Clone` derives if missing) and, under the `python`
/// feature, emits:
///
/// - `impl<M> ToValue<M>` (`crate::python::record`), which renders the
///   fields in order as a `Value::Record`;
/// - `<Name>Py`, a frozen `ntoseye.<Name>` class extending `BaseRecord`, with
///   a typed property per field (the struct's and fields' doc comments become
///   its docstrings) and `__match_args__` (the properties, in order), which
///   `build.rs` exports from the SDK module;
/// - `Name::into_class`, the record as its class.
///
/// Field attributes, `#[record(...)]`:
///
/// - `hex`: integers in the field render as hex (`repr`), through any
///   `Option`, `Vec`, `Box`, `DiagnosticValue`, `DiagnosticMetric` or `Keyed`;
/// - `bytes`: a `Vec<u8>` (possibly wrapped) is Python `bytes`;
/// - `skip`: Rust only; Python does not see the field;
/// - `rename = "key"`: the record key. The property takes the key too,
/// unless the key would hide `BaseRecord.to_dict` or is a Python keyword
///   (`class`), in which case the property keeps the Rust name. The key
///   must be a Python identifier;
/// - `flatten`: the field (keyed `kind`) is a `tagged` enum declared with
/// `base = Name` for this struct: the struct's class is a base, and each
/// value is the subclass of its variant, with `kind` and the variant's
/// fields after the fields before it (`Stop.Breakpoint`).
///
/// A record cannot have generics or lifetimes: its class is one concrete
/// Python type. A field the record shows, a variant and a variant's field
/// cannot carry `#[cfg]` or `#[cfg_attr]`, since the class, its
/// `__match_args__` and `build.rs` list every one; a `skip`ped field may.
/// `build.rs` must see the `#[record]` in the source, so a record made by a
/// `macro_rules!` or a `cfg_attr` fails to compile at its name.
///
/// Item flags: `#[record(impl)]` says a `#[record] impl Name { ... }` block
/// follows in the same module, adding computed properties
/// (`#[record(getter)]` methods, which take the field attributes) and Python
/// methods (`#[record(python)]`, PyO3 methods of the class).
///
/// On an enum:
///
/// - fieldless: each variant has a text, its `rename` or else its snake_case
///   name. The macro generates `as_str()` from the texts, and the value is
///   the variant's text, typed as the `typing.Literal` of every variant's
///   text. An SDK argument of the enum's type takes the same texts
///   (`FromPyObject` and `PyArg`). `Display`, the REPL's text, is the
///   variant's `label = "..."` if it has one, else its text: a label
///   changes only what the REPL prints, while `rename` changes the SDK's
///   value (`#[record(rename = "nonpaged", label = "NonPagedPool")]`).
///   Only a fieldless enum's variant takes `label`;
/// - every variant one unnamed field: the union of the variants' types
///   (the value is the variant's own);
/// - `#[record(tagged)]`: a base class with `kind` (the snake_case variant
///   name, or the variant's `rename`; typed as the `Literal` of the kinds),
///   and a final subclass per variant, nested in it as `Name.Variant`, whose
///   `kind` is the variant's own `Literal` and whose properties are the
///   variant's fields (named by the field, its `rename`, or for a variant's
///   single unnamed field the variant's snake_case name), never `None`
///   outside it. `isinstance(x, Name.Variant)` and `case
///   Name.Variant(field=...)` narrow to the variant; its `__match_args__`
///   are its fields. `#[record(tagged, base = Struct)]` nests the variants
///   in a record struct's class instead, which holds the enum in a
///   `#[record(flatten)]` field. Each variant class is a class attribute of
///   its base, as PyO3 nests a complex enum's variants, and the stub nests it
///   through an introspection fragment naming the base as its parent.
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
/// `kind = Query | Action | Run | Host`, and `python = Object | [Object,
///   ...] | none` (one method on each class: a kernel and a user-dump
///   class can share a command; a list names at least one class, and
///   `none` stands alone);
/// - effects, which `Session::admit` enforces for every host: `target =
///   Any | Kernel | Machine | Nt` (`Kernel` and `Machine` need a kernel
///   target; `Kernel` and `Nt` read NT's structures, which a VTL1 address
///   space refuses), `state = Any | Halted | HaltedOrParkedThread | Running`,
///   `run = None | Step | Run`, `writes = [Memory, Registers, Hardware,
///   Breakpoints, Symbols, Files]`, `live_only`, `capability =
///   <DebugCapability>`;
/// - `python_name = "..."` (else the function's name), `style = RawTail |
/// ExpressionTail` (the line is not split into words, for a `raw`
/// argument), and `flow = Quit` (the flow the command ends with once it
///   ran; a line that does not parse ends with `Continue`; refused on a
///   function that returns its own `Flow`).
///
/// There is no `usage` or `completion` key: both are generated from the
/// arguments (`crate::repl::usage` has the notation), so they cannot drift
/// from what the line accepts. A typed argument is `<name>`, or `[name]`
/// when it may be omitted, completed as its `FromArg::COMPLETION`; a switch
/// is `[/x]`; `rest` is `[name]...`; a custom parser gives the fragment and
/// completion it declares with `#[grammar]`. A form of the line (` | ` in a
/// fragment) is a usage line of its own.
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
///   `Vec<T>`, which the REPL runs the operation on in turn, rendering the
///   `Vec` of results (not on a `kind = Run` command, which runs once).
///   The parser carries `#[grammar(...)]`;
/// - `render`: a display option (WinDbg's flags that only choose what the
///   text shows), not passed to the function: the REPL passes the render
///   options to `Render::render` (one value, or a tuple in order);
/// - `receiver`: the Python method's object binds it (`Bind<T>`);
/// - `sdk` (with `default = expr`): an SDK-only keyword; the REPL reads no
///   word for it and passes `expr`, Python's keyword defaults to `expr`;
/// - `positional`: positional in Python although it may be omitted. In the
///   SDK method, an argument that may be omitted (`Option<T>`, `default`,
///   `switch`, `sdk`) is a mode, flag or option, so it is keyword-only
///   (after the `*`); the arguments the method is about (an address, a
///   name, an object) stay positional: the required ones, and those marked
///   `positional` (`job(address=None)`, `pool_usage(tag=None, *,
///   sort=...)`). The positional ones come first;
/// - `cancel`: a `kind = Run` command's `&Cancel`, which the host supplies
///   (the REPL's stop budget, the SDK's `timeout`);
/// - `name = "..."`: its usage name (else the parameter's, kebab-case);
///   `complete = Strategy`: the completion of a typed argument whose type
///   does not say (a `String` that names a driver);
/// - `usage = "..."` (with `complete = [Strategy, ...]` per word, or
///   `complete = Strategy` for every word): the fragment of a `raw`
///   argument, or of one whose `#[grammar(operation)]` parser hands its
///   words to the operation, which reads them itself.
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
/// method admits the command's effects, except those the form declares in
/// their place (`target`, `state`, `run`, `writes`, `live_only`,
/// `capability`): `!gflag`'s set form declares `writes = [Memory]`. Its
/// arguments are all the method's:
/// `Option<T>`, `default`, `positional` and `receiver` apply (a REPL-only
/// option is refused), so a form can take what the REPL grammar has no word
/// for, such as an object handle (`PyArg for ProcessInfo` takes a `Process`).
/// The command's own arguments describe the line (its usage and completion),
/// not the forms'. A form and its command name each other (the command hands
/// the form its effects as `__FORM_<command>_<form>`), and both live in one
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

/// The usage fragment and completion of a custom argument parser
/// (`#[arg(parse = f)]` or `each = f`), declared beside it:
///
/// ```ignore
/// #[grammar(usage = "<address> [L<count>|length|end]", complete = [Expression, Expression])]
/// fn display_range(cx: &mut ArgCx, cursor: &mut ArgCursor) -> Result<AddressRange, ArgError> { ... }
/// ```
///
/// - `usage = "..."`: the words the parser reads, in the usage notation
///   (`crate::repl::usage`); `{}` stands for the argument's name, so a
///   shared parser can name each use (`<{}>`). Empty for a parser that
///   reads no word of its own;
/// - `complete = [Strategy, ...]`: the completion of each word, in order;
///   `complete = Strategy`: of every word (the parser takes the rest of the
///   line); omitted: none;
/// - `operation` (alone): the parser hands the words to the operation,
///   which reads them itself, so each argument it parses gives its own
///   `#[arg(usage = ..., complete = ...)]`.
///
/// The function stays as written; the grammar is `f::GRAMMAR`, in a hidden
/// module of the function's name and visibility (so a `use` of the parser
/// brings it along), which `#[command]` reads.
#[proc_macro_attribute]
pub fn grammar(attr: TokenStream, item: TokenStream) -> TokenStream {
    grammar::expand(attr.into(), item.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// An SDK handle class: a live object of a debugger, with a `#[record]`
/// that describes it.
///
/// ```ignore
/// #[handle(record = ThreadInfo, key = ethread, context = self.thread_context(py)?, impl)]
/// pub struct Thread {
///     pub owner: Owner,
///     pub info: ThreadInfo,
/// }
///
/// #[handle]
/// impl Thread {
///     /// The process that owns the thread.
///     #[getter]
///     fn process(&self, py: Python<'_>) -> PyResult<Option<Process>> { ... }
/// }
/// ```
///
/// The struct becomes a frozen `ntoseye.<Name>` class. It has an `owner`
/// (`python::handle::Owner`) and, by default, its record in `info`. The
/// class gets:
///
/// - a property for each of the record's properties (its fields and its
///   `#[record(getter)]`s), typed and documented as the record's, which
///   checks the handle is still valid and reads the record;
/// - `info` (the record), `to_dict()`, and `==`/`hash` by its identity;
/// - `python::handle::Handle`, through which a `#[collection(records)]`
///   finds the item a record describes (by its `key`);
/// - `CommandHost`, so `#[command(python = Name)]` methods run in its
///   `context`, and `Bind<Record>`, so a `receiver` argument of the
///   record's type is this object.
///
/// Options:
///
/// - `record = Path` (required): the `#[record]` struct;
/// - `key = field` (required): the record property that names the object;
///   also the identity, unless `identity` is given;
/// - `info = field`: where the record is held (default `info`); or
///   `fetch = path`, a `fn(&Self, Python) -> PyResult<Record>` that reads
///   it now (a breakpoint's state), for which `identity` is required;
/// - `identity = path`: a `fn(&Self) -> impl Hash + Eq`;
/// - `context = expr`: the `Context` its commands run in, an expression of
///   `self` and `py` (`?` may be used), else the kernel's; `refuse = expr`
///   (of `self`, `operation`, `effects`) and `prepare = expr` (of `self`,
///   `session`), `PyResult<()>`s: `CommandHost`'s other methods;
/// - `impl`: a `#[handle] impl Name { ... }` block follows in the same
///   module. Its items are the class's `#[pymethods]`, and a method or
///   getter there replaces the generated property of its Python name
///   (`Thread.process` is a `Process` handle, not the record's value).
#[proc_macro_attribute]
pub fn handle(attr: TokenStream, item: TokenStream) -> TokenStream {
    handle::expand(attr.into(), item.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// The `#[pymethods]` of a `#[handle]` class, with its record's
/// properties: the record's own macro (`#[record]` defines one, under the
/// record's name) calls this with them. Not for direct use.
#[doc(hidden)]
#[proc_macro]
pub fn handle_methods(input: TokenStream) -> TokenStream {
    handle::methods(input.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// An SDK collection class's container protocol, from one function that
/// lists its items and one that finds an item by key.
///
/// ```ignore
/// #[collection(records)]
/// impl Threads {
///     fn enumerate(&self, py: Python<'_>) -> PyResult<Vec<Thread>> { ... }
///     /// The thread with TID `key`, or the one a `ThreadInfo` describes.
///     fn lookup(&self, py: Python<'_>, key: &u64) -> PyResult<Option<Thread>> { ... }
///     /// The thread at an ETHREAD or KTHREAD address, or `None`.
///     #[collection(at)]
///     fn holds(thread: &Thread, address: u64) -> bool { ... }
/// }
/// ```
///
/// `enumerate` and `lookup` stay Rust methods; the class's `#[pymethods]`
/// get `__len__`, `__iter__` (a typed `Iterator[Item]` over a snapshot),
/// and, from `lookup` (whose docs they take), `__getitem__` (`KeyError`),
/// `get` (`None`) and `__contains__`, which takes a key, or else tests
/// whether the value is one of the items (`bp in dbg.breakpoints`). Flags:
///
/// - `records`: the items are `#[handle]`s, and a record of their kind is
///   a key too, naming the listed item it describes (`dbg.threads[stop.thread]`);
/// - `sequence`: no `lookup`; `__getitem__` and `get` take a position,
///   negative from the end (`IndexError`), and `__contains__` tests an
///   item (`heap in heaps`), as a Python sequence's does.
///
/// A method marked `#[collection(find)]`, `fn(&Item, &str) -> bool`, makes
/// `find(name)`, the items it holds for; `#[collection(at)]`, `fn(&Item,
/// u64) -> bool`, makes `at(address)`, the first. Other items of the block
/// are the class's own `#[pymethods]`.
#[proc_macro_attribute]
pub fn collection(attr: TokenStream, item: TokenStream) -> TokenStream {
    collection::expand(attr.into(), item.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}
