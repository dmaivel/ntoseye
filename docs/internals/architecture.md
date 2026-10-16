# How the code fits together

This page is for contributors. It describes how one definition serves the REPL, the Python SDK, the command reference and the other hosts (DAP, gdbserver, MCP), and what to write to add a command or an SDK method.

## Records: one type per concept

Each Windows-model concept has one Rust type, and that type is also its SDK class. A model struct or enum carries `#[record]` (the `ntoseye-macros` crate, `macros/src/record.rs`):

```rust
/// A job object (`!job`).
#[record(impl)]
pub struct Job {
    #[record(hex)]
    pub address: VirtAddr,
    pub job_id: Option<u64>,
    #[record(skip)]
    pub raw: Vec<JobField>,
}

#[record]
impl Job {
    /// The `JOB_OBJECT_LIMIT_*` names of the limit flags that are set.
    #[record(getter)]
    pub fn limit_flag_names(&self) -> Vec<String> { ... }
}
```

- The struct stays as written. The REPL renders it and the rest of the crate uses it.
- With the `python` feature, the macro also emits a frozen class `JobPy` (Python name `Job`) that extends `BaseRecord`, with one typed property for each field. The doc comments become docstrings.
- Field options: `hex` (`repr` shows the integer in hex), `bytes` (a `Vec<u8>` is Python `bytes`), `skip` (Rust and REPL only), and `rename = "key"`. A field's Rust type gives its stub type, through `Option`, `Vec`, `Box`, `DiagnosticValue` (`Diagnostic[T]`), `DiagnosticMetric` and `Keyed`.
- Values that are computed from the fields are `#[record(getter)]` methods in a `#[record] impl` block, and the struct then says `#[record(impl)]`. `#[record(python)]` methods in that block become ordinary Python methods.
- A fieldless enum is a string: each variant's text is its `rename`, or else its snake_case name, and the stub types the value as the `Literal` of every text. An SDK argument of the enum's type takes the same texts. `#[record(label = "...")]` on a variant gives the REPL a different text (`Display`) from the SDK's, so the SDK says `pde` where the REPL prints `PDE`.
- An enum whose variants each hold one value is the union of those values' types.
- `#[record(tagged)]` on an enum with struct variants makes a base class with `kind`, typed as the `Literal` of the variant kinds, and a final subclass per variant, nested in it (`ListTermination.Cycle`). A variant's class has its own `kind` and the variant's fields as properties that are never `None` for being in another variant, so `isinstance()` and `match` narrow. With `base = S`, the subclasses extend struct `S`'s class instead, and `S` holds the enum in a `#[record(flatten)]` field: that is how `Stop` has its shared context and `Stop.Breakpoint` its `breakpoint`.
- Context that depends on the session, not on the guest structure, stays outside the record. For example, the vCPU that runs a thread is a field of `ThreadDetail`, not of `ThreadInfo`.

In Python, a record is a value, like a frozen dataclass. `BaseRecord` gives it `==` (same class, equal fields), `hash` (a `TypeError` when a field is unhashable), `repr`, and `to_dict()`, and each class has `__match_args__`, its properties in order. It is not a container: it has no `len`, iteration or `record["field"]`, so a script reads fields as attributes. A `Keyed` field is a plain `dict[str, T]`.

The runtime that turns a record into Python objects is `src/python/record.rs` (`ToValue`, `Typed`, `to_py`). `build.rs` walks the module tree from `src/lib.rs` and exports every record class from the `_ntoseye` module, so a new record needs no list entry. For this reason, a record must be an item in a module that `crate::python` can see, not the output of a `macro_rules!`. Everything Python-specific is behind `cfg(feature = "python")`, so the core builds with `--no-default-features`.

## Commands: one function per operation

Each debugger operation is a function with `#[command]` (`macros/src/command.rs`; the full reference is the doc comment on `ntoseye_macros::command`). The function is the REPL command, its entry in `help` and in the command reference, and its SDK method:

```rust
/// Show a job object and the processes in it.
///
/// The address can be a job, or a process or thread, for which the command
/// shows its job.
#[command(names = ["!job", "job"], category = "processes and modules",
          kind = Query, target = Kernel, python = Inspect)]
fn job(session: &Session, address: Option<VirtAddr>) -> Result<Job> { ... }

impl Render for Job {
    fn render(&self, repl: &mut ReplState<'_>, (): ()) { ... }
}
```

- The first paragraph of the doc comment is the summary, and the rest is the details. Both appear in `help`, in the command reference and in the Python docstring.
- `kind` says what the command does:
  - `Query` reads state and returns a record.
  - `Action` changes guest, debugger or symbol state and returns a record of the change, or `()`.
  - `Run` resumes or steps the target. It returns the `Motion` to drive, and the host drives it to a `Stop`.
  - `Host` acts on the REPL itself (aliases, scripts, logging), and has no SDK form.
- Arguments after the receiver (`&Session`, `&mut Session`, or `&mut ReplState` for a REPL-only command) are parsed in order by `FromArg` (`src/repl/args.rs`). `#[arg(...)]` options cover defaults, the current process or thread, switches, the rest of the line, custom parsers (`parse = f`), and display flags (`render`), which go to `Render` and never to the function or to Python.
- `Render` prints the REPL text through `outln!`. The hosts capture that output. The renderer also gets the `ReplState`, for things that only the REPL keeps, such as completion caches and the selected thread.
- The macro registers a `CommandSpec` in the `COMMANDS` slice (`src/repl/command.rs`). `help`, completion, `--dump-command-reference` (and the generated command reference in these docs), MCP and the REPL dispatcher all read that one registry.

### Usage lines and completion

Nobody writes a command's usage line or its completion by hand. The macro generates both from the arguments (`src/repl/usage.rs`), so they cannot drift from what the parser accepts, and it refuses a `usage =` or `completion =` key on `#[command]`.

The notation follows WinDbg's documentation and POSIX:

| Notation | Meaning |
| --- | --- |
| `<name>` | a required word |
| `[name]` | an optional word |
| `<name>...`, `[name]...` | one or more, any number |
| `[/p]`, `[-v]` | a switch or option, as typed |
| `[/p <processor>]` | an option with a value |
| `a\|b` (no spaces) | alternatives within one argument: `<id\|id-id\|*>`, `[+\|-]value` |
| `[bus [device]]` | nested optional groups; optional words that the line gives in turn nest (`!job [address [flags]]`) |
| `a \| b` (spaced) | alternative forms of the whole line |

Names are kebab-case: the parameter's name, or `#[arg(name = "...")]`. Each form of the line is a usage line of its own, which starts with the command name: `help !alpc` shows `!alpc /p <port>`, `!alpc /m <message>` and `!alpc /lpp [process]` on three lines, and the command reference's `usage` holds them separated by newlines.

Each argument contributes a fragment and the completion of its words:

- A typed argument is `<name>`, or `[name]` when it may be omitted (`Option<T>`, `default`, `current`), and completes as its type's `FromArg::COMPLETION`: an expression (`VirtAddr`, the integers) as `Expression`, a `ThreadInfo` as `Thread`, a `BreakpointId` as `Breakpoint`, and so on. `#[arg(complete = Driver)]` covers a word that its type does not describe, such as a `String` that names a driver.
- `#[arg(switch = "/x")]` is `[/x]`, and `rest` is `[name]...`.
- A custom parser (`parse = f`, `each = f`) declares its words next to its code with `#[grammar(usage = "<address> [L<count>|length|end]", complete = [Expression, Expression])]`. In the fragment, `{}` stands for the argument's name, so a parser that several commands share can name each use. `usage = ""` declares a parser that reads no word of its own, and a bare `complete = Strategy` completes every word, for a parser that takes the rest of the line.
- A parser that only hands the words to the operation, which reads them itself, is `#[grammar(operation)]`. Each argument that uses it describes the words with `#[arg(usage = "...", complete = ...)]`, as may a `raw` or `rest` argument, whose operation reads its text.

The usage line is the command name and the fragments in parameter order. The completion of the `n`th word is the `n`th of the arguments' words in order; after an argument that takes the rest of the line, every word completes as it does. A test in `src/repl/command.rs` checks that every argument which names a value has a completion position.

### Forms: several SDK methods behind one REPL name

When one REPL command is several operations (`!alpc` decodes a port, a message, or a process's ports), each operation is a *form*: a function with its own return type and docstring, marked `#[command(form_of = alpc, python = Inspect)]`. The command lists its forms (`forms = [alpc_port, alpc_message, ...]`) instead of `python`, parses its line as before, and calls the form that the line selects. A form has no help entry of its own, and its SDK method admits the command's effects. A form can take arguments that the REPL grammar has no word for, such as a `Process` handle or a keyword-only option, and a form may exist only in the SDK, when the REPL reaches its operation another way (`Debugger.hypercalls()`, a form of `!hvcalls`). The command's own arguments describe the line, so its usage and completion come from them, not from its forms.

## Effects and `Session::admit`

A command declares what it needs and what it changes, instead of checking for itself:

- `target = Kernel | Machine | Nt`: `Kernel` and `Machine` are refused on a user-mode minidump; `Kernel` and `Nt` read NT's structures, which a VTL1 address space does not have, while `Machine` reads processors, MSRs, page tables, the hypervisor or the VTLs;
- `state = Halted | HaltedOrParkedThread | Running`;
- `run = Step | Run`;
- `writes = [Memory, Registers, Hardware, Breakpoints, Symbols, Files]`;
- `live_only` (refused on a dump);
- `capability = <DebugCapability>`.

`Session::admit(&Effects)` (`src/session/effects.rs`) makes the decision for every host and returns a `Refusal`. The REPL reports a refusal with the message that it has always printed (`report_refusal`). The SDK raises the matching exception (`python::command::admit`), for example `TargetRunningError`. Hand-written SDK methods go through the same function.

VTL1 is part of the same decision. In a VTL1 address space (the `.vtl 1` view, or the root of a live VTL1 stop), `admit` refuses what reads NT (`Kernel`, `Nt`) or writes guest state (`Memory`, `Registers`, `Hardware`). The `.vtl 1` view is memory alone, so it also refuses anything that needs the target halted, except breakpoint bookkeeping. Both hosts word the refusal with `Vtl1Refusal::message`.

## Running the target: the run driver and `Stop`

`Session::run(Motion, &Cancel) -> Result<RunOutcome>` (`src/session/driver.rs`) is the only way to resume, step or wait, for every host. A `Motion` is `Continue`, `Wait`, `Break`, `Step`, `StepOver`, `StepOut`, `RunTo` or `Walk`. A `Cancel` carries the cross-thread flag, a deadline, a behavior for when it fires, and a `tick` hook that the host calls between polls. The driver polls the backend, skips stops that do not count, applies the exception policy, surfaces parked stops, and runs breakpoint actions and filter commands through the session's `ActionRunner` (the REPL dispatcher, in every session built with the REPL). Every breakpoint stop runs its action, a `wt` that ends at one included. An action that resumes (`gc`) passes the hit as a declined one, unless a halt was asked for (`Motion::Break`, a cancellation that halts, Ctrl+C): halt wins, and the target stays at the hit.

The result is a `Stop` record: the context at the stop (vCPU, RIP, symbol, process, thread, inspection process, VTL, partition) and a `StopKind`, a `tagged` enum flattened into it, whose variants carry their own parts (`Breakpoint { breakpoint }`, `Exception { exception }`, `ModuleLoad { module }`, ...). In Python, each variant is a subclass, `Stop.Breakpoint` with a `breakpoint` that is never `None`. Each host only maps it. The REPL prints the stop card (`ReplState::run_motion`), the SDK returns the `Stop` itself (`python::runcontrol`), DAP sends a stopped event, gdbserver a stop reply, and MCP goes through the REPL.

## The Python SDK

A generated method runs through `python::command::run`. That function takes the object's context, admits the command's effects on the session thread, calls the function, and returns the result as its record class (`Typed<R>`). The class that a method is placed on implements `CommandHost` (`src/python/command.rs`):

- `session()` says how the object reaches its session: through its `Owner` for a handle or a namespace, or directly for the `Debugger`.
- `context()` gives the process or thread that its calls run in.
- `refuse()` and `prepare()` are optional. They refuse an operation that the object cannot run, and set up the session after admission (for example, a `Heap` loads its process's symbols).
- A `#[arg(receiver)]` argument comes from the object through `Bind<T>`. For example, a `Thread` binds the `ThreadInfo` that `!thread` takes.

A Python argument type implements `PyArg`, whose `Py` type is what the stub shows. A fieldless `#[record]` enum is one already, taking its variants' texts (`Literal[...]` in the stub), and a handle's record is one taking the handle (`ProcessInfo` takes a `Process`). A `VirtAddr` argument is an `AddressArg` (`src/python/args.rs`): an `int`, a debugger expression, which is evaluated on the session thread in the method's context, or a handle, which gives its object's address (a `Process` its `_EPROCESS`, a `Module` its base, ...; also `Thread`, `Driver`, `Device` and `Heap`) and must belong to the same debugger. Hand-written methods take `AddressArg` too, through `AddressArg::resolve` or `AddressArg::pending`. Run commands get a `timeout` and the `when=` handling of `python::runcontrol`.

The arguments a method is about (an address, a name, an object) are positional. An argument that may be omitted (`Option<T>`, `default`, `switch`, `sdk`) is a mode, flag or option, so the generated method makes it keyword-only, after the `*`; `#[arg(positional)]` keeps an omittable subject positional (`job(address=None)`, `pool_usage(tag=None, *, sort=...)`).

### Handles and collections

A live handle (`Process`, `Thread`, `Module`, `Breakpoint`) is a struct with `#[handle(record = R, key = field, ...)]` (`macros/src/handle.rs`). It holds its `Owner` and its record `R` (or, with `fetch = f`, reads the record now, as a `Cpu` or a `Breakpoint` does). The macro makes the frozen class, a typed property for each of `R`'s properties (with its doc comment), `info` (the record), `to_dict()`, `==` and `hash` by the key (or by `identity = f`), and the `CommandHost` (its `context`, `refuse` and `prepare` given as expressions), `Bind<R>` and `PyArg` for `R`. A `#[handle] impl` block adds hand-written methods; a property it defines replaces the record's.

A collection (`dbg.processes`) is an impl block with `#[collection]` (`macros/src/collection.rs`). It writes `fn enumerate`, which lists the items, and `fn lookup` for a key; the macro makes `__len__`, a typed `__iter__`, `__getitem__`, `get` and `__contains__`, and `find`/`at` from matcher functions marked `#[collection(find)]` or `#[collection(at)]`. `#[collection(records)]` also takes an item's record as a key (`dbg.threads[stop.thread]`), and `#[collection(sequence)]` indexes by position.

Every SDK class reaches the module without a list: `build.rs` finds each `#[record]`, `#[handle]` and `#[pyclass]` and writes their `#[pymodule_export]`s. A `tagged` variant class reaches it through its base, which nests it.

`build.rs` also fails the build on a name clash, which PyO3 would resolve silently by keeping one of the two: two SDK classes with one Python name, or two members of one class with one Python name. It collects a class's members from every source: a record's properties and `#[record(getter)]`s, a handle's generated members (`info`, `to_dict`, its record's properties), a `#[collection]`'s protocol, `#[command(python = ...)]` methods and forms, and hand-written `#[pymethods]`. A `#[handle] impl` item with the name of a generated property replaces it on purpose, and is not a clash.

Some SDK methods are written by hand. These are properties and setters (`Symbols.path`), mapping objects (`Cpu.msr`), cursor reads (`Debugger.debug_log`), and operations that no command performs. They return model records through `Typed` as well. A method that performs a command's operation but returns a live handle or takes a Python callback, such as `breakpoints.add()` (`bp`, `bu`, `ba`) with its `when=`, is a thin wrapper: it calls the session function that the command calls (`Session::set_code_breakpoint`, `set_symbolic_breakpoint`, `set_hardware_breakpoint`), which holds the operation's checks, so the two cannot drift.

## Adding a command

1. Make the result a model record: add `#[record]` to the model type (or write a new one next to the model), and use `#[record(skip)]` for fields that only the REPL needs.
2. Write the function with `#[command]` next to the other commands of its area in `src/repl/commands/`. Put the help text in the doc comment, and declare `kind`, `category`, the effects, and `python = Object` or `python = none`.
3. Implement `Render` for the result, reading the record.
4. For a new kind of argument, implement `FromArg` (and `Current` if it has a current value, and `PyArg` if Python takes it) next to the model, or write a `parse = f` parser, with its `#[grammar]`, for a grammar of the command's own.
5. Check `help <name>`, the REPL text, and `ntoseye --dump-command-reference`. A change in the reference is a change in the docs.

## Adding an SDK method

1. If a REPL command performs the operation, generate the method: use `python = Object` on the command, or add a form (`form_of`) when the command is several operations or the method needs arguments that the line has no word for. Use `python_name` to choose the Python name.
2. On a class that has no commands yet, implement `CommandHost`, and `Bind<T>` for each argument that the object supplies. A `#[handle]` has both. A generated method's Python name must not be one of the class's members; `build.rs` stops the build if it is.
3. Write a method by hand only for the cases listed above. Return records, and route halt and kernel checks through `python::command::admit`.
4. Regenerate the stub and check it, as `python/README.md` describes: `maturin develop --generate-stubs`, then `mypy --strict -p ntoseye` and the target-free tests in `python/tests`. A script-visible change is an SDK change, and belongs in the changelog.
