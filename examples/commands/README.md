# Custom commands

This directory contains example scripts for REPL commands. To load a command automatically at startup, copy its `*.py` file into `~/.ntoseye/commands/`.

The commands use the SDK namespaces, for example `dbg.processes` and `dbg.memory`. The commands use `ntoseye.repl.Debugger` for their type annotations.
