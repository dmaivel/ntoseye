# Examples

This directory contains example scripts for the [ntoseye Python SDK](../docs/scripting/sdk.md).
There are two types of scripts:

- [`commands/`](commands/): custom REPL commands. Put them in `~/.ntoseye/commands/`. Custom commands run inside the REPL session.
- [`standalone/`](standalone/): standalone scripts that attach to a guest directly. Standalone scripts use debugger namespaces and process-bound handles.

[`ghidra/ntoseye_regions.py`](ghidra/ntoseye_regions.py) is a gdb script for the gdb agent of Ghidra. Use it when Ghidra debugs through [`ntoseye gdbserver`](../docs/integrations/gdbserver.md#ghidra).
