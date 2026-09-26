# Custom REPL commands

A Python script can add commands to the REPL. They run inside the REPL's own session rather than attaching a second debugger, and they reach the target through the same API as the [Python SDK](sdk.md).

Put a `*.py` file in `~/.ntoseye/commands/`. Scripts load at startup, and {command}`reload-scripts` picks up edits without restarting. Custom commands need an `ntoseye` with Python in it: the command the Python package installs (`uv tool install ntoseye` or `pipx install ntoseye`) and `cargo install` builds both have it. The prebuilt release archives have no Python; they list the scripts they skipped and how to get a build that runs them.

## A first command

```python
import ntoseye.repl as repl


@repl.command("pscount", "Count running processes.\n(usage: pscount [-v])")
def pscount(dbg: repl.Debugger, *args: str):
    processes = dbg.processes
    print(f"{len(processes)} processes")
    if args and args[0] == "-v":
        for process in processes:
            print(f"  {process.eprocess:#x}  {process.pid:>6}  {process.name}")
```

This is [`examples/commands/pscount.py`](https://github.com/dmaivel/ntoseye/blob/master/examples/commands/pscount.py). After copying it into `~/.ntoseye/commands/`, `pscount -v` lists every process.

- **The help text** is the second argument. {command}`.hh` lists custom commands under "python commands" with the first line of their help, and `.hh pscount` prints all of it.
- **Arguments** arrive after `dbg` as strings, split and quoted the same way as a built-in command's.
- **`dbg`** is a borrowed {py:class}`ntoseye.Debugger` for the REPL's session. It is valid only until the command returns: keeping it (or an object read through it) in a global and using it later raises.

## Tab completion

Keyword arguments to `repl.command` bind a parameter, by name, to one of the completion markers in {py:mod}`ntoseye.repl`, so tab completes that argument the way the built-in commands do:

```python
@repl.command("pinfo", "Show a process.\n(usage: pinfo <process>)", target=repl.Process)
def pinfo(dbg: repl.Debugger, target: str):
    ...
```

The markers are `Process`, `Symbol`, `Expression`, `Type`, `Driver`, `Thread`, `Vcpu`, `Breakpoint`, and `Alias`. A parameter without a marker gets no completion.

## Registering without the decorator

`repl.register_command(name, help, fn, strategies)` is what the decorator calls: `strategies` lists one completion name per parameter after `dbg` (`"process"`, `"symbol"`, ..., or `"none"`). Outside the REPL, for example when a command script is run with plain `python`, it raises instead of registering.

More scripts are in [`examples/commands/`](https://github.com/dmaivel/ntoseye/tree/master/examples/commands/).
