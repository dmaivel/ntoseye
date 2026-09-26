# Install

## Shell script

```bash
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/dmaivel/ntoseye/releases/latest/download/ntoseye-installer.sh | sh
```

The prebuilt binaries have no Python, so they cannot run [custom commands](../scripting/commands.md).

## uv or pipx

```bash
uv tool install ntoseye    # or: pipx install ntoseye
```

Installs the `ntoseye` command with support for custom commands, in its own environment. Requires Python 3.9 or newer, on Linux (x86-64, ARM64) or Apple Silicon macOS.

## cargo

```bash
cargo install ntoseye
```

`cargo install` and default source builds embed Python and link against the local Python installation.

## Python SDK

To drive the debugger from your own Python code, install the same package into your project's environment:

```bash
pip install ntoseye
```

This also puts the `ntoseye` command in that environment. See the [Python SDK documentation](../scripting/sdk.md).

## Building from source

```bash
git clone https://github.com/dmaivel/ntoseye.git
cd ntoseye
cargo build --release
```

To build without embedded Python:

```bash
cargo build --release --no-default-features --features cli,mcp,dap,gdbserver
```

## Files and network access

`ntoseye` downloads symbols and images from Microsoft's official symbol server when required. Config, cache, and REPL state live under `~/.ntoseye`:

- `~/.ntoseye/commands/` for custom scripted commands
- `~/.ntoseye/symbols/` for PDBs and images, a symbol store in the `symstore` layout that WinDbg, IDA, Ghidra, and rizin read
- `~/.ntoseye/aliases` for command aliases
- `~/.ntoseye/history` for persistent REPL history
- `~/.ntoseye/sites/` for user-mode breakpoint bytes a session has written, restored by the next attach if that session dies
