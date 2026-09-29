# Custom REPL commands

A Python script can add commands to the REPL. These commands run in the REPL's own session, and do not attach a second debugger. They get access to the target through the same API as the [Python SDK](sdk.md).

To add a command, put a `*.py` file in `~/.ntoseye/commands/`. The REPL loads the scripts when it starts. To load changes to the scripts without a restart, use {command}`reload-scripts`.

Custom commands need an `ntoseye` that contains Python. These builds contain Python:

- the command that the Python package installs (`uv tool install ntoseye` or `pipx install ntoseye`)
- the build that `cargo install` makes

The prebuilt release archives do not contain Python. They show a list of the scripts that they did not load, and they tell you how to get a build that runs these scripts.

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

This example is [`examples/commands/pscount.py`](https://github.com/dmaivel/ntoseye/blob/master/examples/commands/pscount.py). Copy it into `~/.ntoseye/commands/`. Then `pscount -v` shows a list of all processes.

- **The help text** is the second argument. {command}`.hh` shows the custom commands under "python commands", with the first line of their help text. `.hh pscount` prints all the help text.
- **Arguments** come after `dbg` as strings. The REPL splits and quotes them in the same way as the arguments of a built-in command.
- **`dbg`** is a borrowed {py:class}`ntoseye.Debugger` for the REPL's session. It is valid only until the command returns. If you keep it in a global and use it later, the call raises an exception. This also applies to an object that you read through `dbg`.

## Tab completion

A keyword argument to `repl.command` binds a parameter, by its name, to one of the completion markers in {py:mod}`ntoseye.repl`. Then the Tab key completes that argument in the same way as for the built-in commands:

```python
@repl.command("pinfo", "Show a process.\n(usage: pinfo <process>)", target=repl.Process)
def pinfo(dbg: repl.Debugger, target: str):
    ...
```

The markers are:

- `Process`
- `Symbol`
- `Expression`
- `Type`
- `Driver`
- `Thread`
- `Vcpu`
- `Breakpoint`
- `Alias`

If a parameter does not have a marker, the REPL does not complete it.

## Registering without the decorator

The decorator calls `repl.register_command(name, help, fn, strategies)`. The `strategies` argument lists one completion name for each parameter after `dbg`. A completion name is `"process"`, `"symbol"`, ..., or `"none"`.

Outside the REPL, the function raises an exception and does not register the command. For example, this occurs when you run a command script with plain `python`.

For more scripts, see [`examples/commands/`](https://github.com/dmaivel/ntoseye/tree/master/examples/commands/).
