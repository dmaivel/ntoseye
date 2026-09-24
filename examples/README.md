# Examples

Example scripts for the 0.37 [ntoseye Python SDK](../docs/sdk.md):
standalone scripts use debugger namespaces and process-bound handles; custom
commands run inside the REPL's session.

- [`commands/`](commands/): custom REPL commands to drop into `~/.ntoseye/commands/`
- [`standalone/`](standalone/): standalone scripts that attach to a guest directly

[`ghidra/ntoseye_regions.py`](ghidra/ntoseye_regions.py) is a gdb script for Ghidra's gdb agent when it debugs through [`ntoseye gdbserver`](../docs/gdbserver.md#ghidra).
