# Python SDK

The `ntoseye` package exposes debugger introspection and run control to standalone Python programs. The native wheel is self-contained: it needs no separately installed `ntoseye`, and installs the `ntoseye` command itself. The type stubs ship with the package, generated from the extension itself; editor completion, type checkers, and docstrings describe the API.

## Install

```sh
pip install ntoseye
```

To build and install the extension from a checkout:

```sh
cd python
python3 -m venv .venv
. .venv/bin/activate
pip install maturin
maturin develop --release
```

## Attach and inspect

`attach()` defaults to the `kd` backend. Choose `kdnet`, `gdb`, `memory`, or `dmp` as appropriate; `connect` supplies the transport endpoint (or dump path), and `key` is required for `kdnet`. `memory` is passive and cannot halt or resume the guest; use `kd` or `gdb` for run control. `dmp` reads an offline dump.

```python
import ntoseye

with ntoseye.attach(backend="kd") as dbg:
    proc = dbg.processes[1234]             # Process, keyed by PID
    print(proc.name, hex(proc.eprocess))
    print(proc.memory.read(proc.peb.addr, 16).hex() if proc.peb else "no PEB")
```

Leaving the `with` block (or calling `dbg.close()`) removes the debugger's breakpoints, resumes the guest, and ends the session: the connection and the target's single-instance lock are released, so the target can be attached again, and the debugger and its handles raise `NtoseyeError` afterwards.

A `Debugger` exposes namespaces rather than flat `inspect_*` methods:

| Namespace | Contents |
| --- | --- |
| `dbg.memory`, `dbg.physical` | Kernel virtual and guest-physical memory |
| `dbg.symbols`, `dbg.types`, `dbg.modules` | Kernel symbols, PDB types, and loaded modules |
| `dbg.processes`, `dbg.threads`, `dbg.cpus` | Keyed processes, threads, and processors |
| `dbg.breakpoints`, `dbg.exceptions` | Breakpoint handles and exception policies |
| `dbg.inspect`, `dbg.drivers` | System-wide reports/decoders and driver objects |
| `dbg.secure_kernel` | The VBS secure kernel and its trustlets (VTL1), read-only |

Processes are keyed by PID: `dbg.processes[pid]` raises `KeyError` if absent, while `.get(pid)` returns `None`. `dbg.processes.find(name)` returns exact, case-insensitive image-name matches as a list. A process owns address-space-bound views: `proc.memory`, `proc.symbols`, `proc.types`, `proc.modules`, `proc.threads`, `proc.regions`, and `proc.heaps`. Use these views directly instead of selecting or attaching a global process.

Handles such as `Process`, `Module`, `Thread`, `Frame`, and struct cursors are stamped with the target generation. After a reboot (`Stop.Reboot`), discard and re-query old handles; accessing one raises `ntoseye.StaleHandleError` (they stay hashable and printable, so a set or dict holding them keeps working). `dbg.generation` lets code that caches raw addresses detect a rebuild. `Breakpoint` handles are not stamped: breakpoints survive a reboot, and symbolic ones re-resolve in the new kernel.

## Memory, symbols, and types

Memory operations are explicit about address space: `dbg.memory` is kernel virtual memory, `proc.memory` is that process's virtual memory, and `dbg.physical` is untranslated physical memory.

```python
kernel_fn = dbg.symbols["nt!KeBugCheckEx"]
proc_module = proc.modules["ntdll"]
print(hex(kernel_fn), proc_module.name, hex(proc_module.base))
print(dbg.memory.read(kernel_fn, 16).hex())
```

Types are looked up with `dbg.types[name]` (or `proc.types[name]`). `Type.fields` maps names to `Field` layouts in offset order, and an enum's `Type.values` maps member names to values; `.at(address)` creates a live cursor, and `.read()` returns a snapshot dictionary. Cursor fields support attribute access, while pointer fields remain integer addresses and `follow("Field")` explicitly dereferences a typed pointer. `address_of("Field")` is a field's address (C's `&cursor->Field`), for a watchpoint or a raw read. `Type.walk(head, "Links")` (or `cursor.walk("HeadField", "_RECORD", "Links")`) follows an intrusive `_LIST_ENTRY` list to cursors of its records.

```python
entry = proc.object                         # live _EPROCESS cursor
print(entry.Pcb.DirectoryTableBase)          # nested typed field access
links = entry["ActiveProcessLinks"]          # works even if a field name collides
params = proc.peb.follow("ProcessParameters") if proc.peb else None
if params is not None:
    print(params.CommandLine)
```

PDB enum fields return cached `IntEnum` members when the value is defined; other values remain plain `int`. Use `cursor["Field"]` for collision-proof field access (and assignment); ordinary `cursor.Field` can resolve a cursor member first. `Struct` cursors are live reads tied to their original address space.

## Secure kernel (VTL1)

> [!IMPORTANT]
> VTL1 inspection is experimental; see [Secure kernel (VTL1)](usage.md#secure-kernel-vtl1) for how it works and where it has been tested.

With VBS running, `dbg.secure_kernel` is the secure kernel, discovered from host memory on first use (the `memory` and `gdb` backends, or `kd`/`kdnet` reading host memory). It raises `NtoseyeError` when VBS is not running or the backend cannot reach VTL1 memory. Its `memory`, `symbols`, `types`, and `modules` are bound to the secure kernel's system address space, as `proc.memory` is to a process's; `trustlets` lists the secure kernel's processes, each with the same views bound to its own address space and `process` naming its NT side.

```python
sk = dbg.secure_kernel
head = sk.symbols["securekernel!SkpsProcessList"]
print(sk.memory.read_u64(head), [m.name for m in sk.modules])
for trustlet in sk.trustlets:                # LsaIso.exe, trustlet_id 1, ...
    print(trustlet.pid, trustlet.name, trustlet.trustlet_id, hex(trustlet.dtb))
```

These views are read-only: writes, and operations that read NT's own state about an address (`describe`, `page_in`, `ptov`), raise `NtoseyeError`. Registers belong to VTL0, so `sk.eval("@rip")` raises too. Secure-kernel symbols resolve only in these views and NT's only outside them. The public `securekernel.pdb` has no types; name NT's explicitly (`sk.types["nt!_LIST_ENTRY"]`). A trustlet's own user-mode modules are not enumerated.

## Run control and breakpoints

`run(timeout=None)` resumes and waits; `wait(timeout=None)` waits without resuming. Both return a `Stop` when one is observed, or `None` when the timeout expires; timeouts are in seconds, and `None` waits indefinitely. `cont()` resumes without waiting; `interrupt()` breaks in and returns a `Stop`. `step()`, `step_over()`, `step_out()`, and `run_to()` provide synchronous run control; `step(until="call")` (and `"ret"`, `"branch"`) steps to the next such instruction, and `run_to(addr, step="over")` single-steps to an address instead of running there. `trace_calls()` records the call tree up to the current function's return (`wt`).

While the target is halted, the stop it is halted at stays current until it moves again: `dbg.stop`, `wait()`, and `interrupt()` all return it, and reading it consumes nothing.

Stop kinds are `ntoseye.Stop.Breakpoint`, `.Exception`, `.Interrupt`, `.Step`, `.Bugcheck`, and `.Reboot`. Inspect the specific stop with `isinstance` (available on Python 3.9+); shared fields include `rip`, `symbol`, `thread`, `process`, `cpu`, and `breakpoints`. `stop.breakpoints` is empty for other stop kinds, so `if bp in stop.breakpoints:` works without dispatching on the stop type. A crash dump opened with `backend="dmp"` is halted at its bugcheck, so its `dbg.stop` is a `Stop.Bugcheck`.

```python
bp = dbg.breakpoints.add("nt!NtCreateFile")
stop = dbg.run(timeout=10.0)
if stop is None:
    print("still running")
elif isinstance(stop, ntoseye.Stop.Breakpoint) and bp in stop.breakpoints:
    print("hit", stop.symbol, stop.thread)
```

`dbg.breakpoints` is a live iterable/ID-keyed collection. A breakpoint handle owns its state: set `bp.enabled`, `bp.condition`, or `bp.pass_count`; remove it with `bp.delete()`.

`add()` accepts debugger-expression conditions with `condition=` or a Python predicate with `when=`:

```python
bp = dbg.breakpoints.add(
    "nt!NtCreateFile",
    when=lambda stop: stop.process is not None and stop.process.pid == 1234,
)
```

A `when` callback runs on the thread waiting in `run()`, `wait()`, `run_to()`, `step()`, `step_over()`, or `step_out()` and receives the `Stop`; a false result resumes past the hit (or, for a step or `run_to(step=...)`, keeps going), and a callback that raises surfaces the hit with the error in `stop.condition_error`. It must not resume or step the target, or add/delete breakpoints; violating these restrictions raises an error. If the breakpoint hits when nobody is waiting, the target remains parked until a later wait. `command()` keeps the REPL's semantics and does not call `when` predicates: a hit during a resuming command stops there. The separate `condition=` argument is a debugger expression, not a Python callback; a breakpoint has one or the other, so assigning `bp.condition` while a `when` callback is attached raises `ValueError`.

The session lives on its own thread. A `Debugger` can be used from any Python thread; calls are serialized there, and waiting calls (`run()`, `wait()`, a resuming `command()`) release the GIL, so other threads keep running. Ctrl+C (`KeyboardInterrupt`) ends a wait, step, or trace early and is raised; an interrupted `run()` or `wait()` leaves the target running, so call `interrupt()` to halt it. During a resuming `command()` Ctrl+C breaks in, as in the REPL, then raises with the target halted. Between calls that thread keeps servicing the guest: wrong-process and false-`condition=` hits are resumed right away instead of leaving the guest frozen until your next call.

## Commands, errors, and build identity

`dbg.command(line, timeout=None)` runs a REPL command and returns text. REPL state (aliases, radix, and `$vars`) persists between calls. If a command resumes the target, `timeout` is its stop budget and the resulting stop is available as `dbg.stop`. Prefer typed SDK methods for structured results; for example, use `dbg.inspect.triage()` rather than parsing `dbg.command("!analyze -v")`.

All SDK exceptions derive from `ntoseye.NtoseyeError`. `MemoryAccessError` reports an unreadable/partially readable guest range; `TargetRunningError` means an operation requires a halted target; `SymbolNotFoundError` also derives from `LookupError`; `StaleHandleError` identifies a handle from before a reboot. An argument outside its fixed choices (`backend="windbg"`, `until="calls"`) or an invalid combination (`backend="kdnet"` without `key`) raises `ValueError` before anything touches the target.

`to_dict()` on a process, thread, module, CPU, driver, or breakpoint returns the same fields the MCP server reports for it; on a value object (a `Field`, `Symbol`, `MemoryRegion`, ...) it returns the object's attributes.

`ntoseye.build` is the commit stamp compiled into the extension (`<commit>`, `<commit>-dirty`, or `unknown`). Compare it after rebuilding if a long-lived Python interpreter may still have an older native module loaded.

## REPL custom commands

Custom commands run inside the CLI's REPL session rather than attaching a second debugger. Put a `*.py` file in `~/.ntoseye/commands/`; scripts are loaded at startup, and `reload-scripts` picks up edits. They run in the `ntoseye` command the Python package installs (`uv tool install ntoseye` or `pipx install ntoseye`) and in `cargo install` builds, which embed Python. The prebuilt release archives have no Python: they list the scripts they skipped and how to get a build that runs them. `ntoseye.repl` provides command decorators, completion markers, and the borrowed `Debugger` type.

```python
import ntoseye.repl as repl

@repl.command("pscount", "Count processes.")
def pscount(dbg: repl.Debugger):
    print(f"{len(dbg.processes)} processes")
    for proc in dbg.processes:
        print(f"  {proc.pid:>6}  {proc.name}")
```

See [`examples/commands/`](../examples/commands/) for custom command scripts. The Python package/build details are in [`python/README.md`](../python/README.md).

## 0.36 → 0.37 quick migration

| 0.36 | 0.37 |
| --- | --- |
| `processes()` / `process(pid)` | `dbg.processes`, `dbg.processes[pid]`, `.find(name)` |
| `attach_process(pid)` / `detach()` | Use `proc.memory`, `proc.modules`, and other process-bound views |
| `read(addr, n)` / `write(addr, data)` | `dbg.memory.read/write(...)`; use `proc.memory` or `dbg.physical` for other spaces |
| `type(name)`, `read_struct(...)`, `offset_of(...)` | `dbg.types[name]`, `.at(addr).read()`, and `.fields[name].offset` |
| `kernel_modules()` / `search_details(...)` | `dbg.modules` / `dbg.memory.search(pattern, start, length)` |
| `breakpoint(...)`, `clear_breakpoint(...)`, `disable_breakpoint(...)` | `dbg.breakpoints.add(...)`, `bp.delete()`, `bp.enabled = False` |
| `run(timeout_ms=...)` / `wait_for_stop(...)` | `run(timeout=seconds)` / `wait(timeout=seconds)`; both return `Stop \| None` |
| `StopOutcome` flags and reason strings | Test `isinstance(stop, ntoseye.Stop.Breakpoint)` (or another stop class); inspect that kind's fields |
| `run_command(line)` | `dbg.command(line, timeout=None)` |
| flat `inspect_*()` reports | `dbg.inspect.*()` or the owning process/thread/CPU/module method |
