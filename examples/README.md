# Examples

This directory contains example scripts for the [ntoseye Python SDK](../docs/scripting/sdk.md), in two types:

- [`commands/`](commands/): custom REPL commands that you put in `~/.ntoseye/commands/`. They run inside the REPL session.
- [`standalone/`](standalone/): standalone scripts that attach to a guest directly and use debugger namespaces and process-bound handles.

[`ghidra/ntoseye_regions.py`](ghidra/ntoseye_regions.py) is a gdb script for the gdb agent of Ghidra, for use when Ghidra debugs through [`ntoseye gdbserver`](../docs/integrations/gdbserver.md#ghidra).
