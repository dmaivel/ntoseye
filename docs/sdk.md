# Python SDK

Drive the debugger from Python with the `ntoseye` module: the same introspection and run-control surface as the REPL (memory/struct reads, expression eval, symbol/type lookup, disassembly, backtraces, trap-frame decoding, code breakpoints, data watchpoints, execution control, process enumeration), with Python owning the loop. `dbg.watchpoint(target, access="write"|"read_write", length=1|2|4|8)` returns the same live handle type as `dbg.breakpoint(...)`; `dbg.inspect_trap_frame()` decodes the current thread's saved `_KTRAP_FRAME`, or accepts an explicit address. The wheel is self-contained, so this needs neither the `ntoseye` CLI nor a build with the embedded interpreter.

Data watchpoints currently require KD, apply globally across guest address spaces, and at most four can be active at a time.

## Install via pip

```sh
pip install ntoseye
```

## Usage

```python
import ntoseye

# defaults to backend="kd", connect="/tmp/ntoseye-kd.sock"
dbg = ntoseye.attach()

for proc in dbg.processes():  # _EPROCESS cursors
    print(proc.UniqueProcessId, proc.ImageFileName, hex(proc.addr))

fun = dbg.eval("nt!KeBugCheckEx")
print(hex(fun), dbg.read(fun, 16).hex())
```

The module is a native extension built with [maturin](https://www.maturin.rs/); see [`ntoseye-py/README.md`](../ntoseye-py/README.md) for build info and [`examples/standalone/`](../examples/standalone/) for standalone scripts.

# Custom commands

In addition to the standalone [Python SDK](#python-sdk), `ntoseye` can run Python commands inside the live REPL; the same SDK, but bound to the session you're already debugging rather than a separate attach. This requires a build with the embedded interpreter (which is enabled by default).

Drop any `*.py` file in `~/.ntoseye/commands/`; they're auto-loaded at REPL startup. Run `reload-scripts` in the REPL to pick up edits without restarting.

Custom commands need no `pip install ntoseye` as the module is served by the embedded interpreter. However, it may be worth installing to get LSP completions and type diagnostics while you write them.

```python
import ntoseye.repl as repl

# repl.Process is the completion type for processes, so the user can make use of `> hide ..<TAB>`
@repl.command("hide", "Unlink a process.\n(usage: hide <pid|name>)", target=repl.Process)
def hide(dbg: repl.Debugger, target=None):
    p = dbg.process(target)
    ...
```

See [`examples/commands/`](../examples/commands/) for more examples.
