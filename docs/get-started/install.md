# Install

`ntoseye` runs on Linux (x86-64, ARM64) and on macOS on Apple Silicon. Each method below installs the same debugger. The methods are different in two ways:

- Some methods embed Python. [Custom commands](../scripting/commands.md) need Python.
- Each method needs different software before you install.

| Method | Custom commands | Needs |
|---|---|---|
| [Shell script](#shell-script) | no | nothing |
| [uv or pipx](#uv-or-pipx) | yes | Python 3.9 or newer |
| [cargo](#cargo) | yes | Rust, and Python 3.9 or newer with its development files (`python3-dev` on Debian and Ubuntu) |
| [pip](#python-sdk), for the Python SDK | yes | Python 3.9 or newer |

## Shell script

```bash
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/dmaivel/ntoseye/releases/latest/download/ntoseye-installer.sh | sh
```

This command installs a prebuilt binary in `~/.local/bin`.

## uv or pipx

```bash
uv tool install ntoseye    # or: pipx install ntoseye
```

This command installs the `ntoseye` command in its own environment.

## cargo

```bash
cargo install ntoseye
```

This command builds the release from crates.io. It links the release against your Python.

## Python SDK

To control the debugger from your own Python code, install the same package in the environment of your project:

```bash
pip install ntoseye
```

This command also installs the `ntoseye` command in that environment. For more information, see the [Python SDK documentation](../scripting/sdk.md).

## Building from source

```bash
git clone https://github.com/dmaivel/ntoseye.git
cd ntoseye
cargo build --release
```

A default build embeds Python and needs the Python development files, as `cargo install` does. To build without Python:

```bash
cargo build --release --no-default-features --features cli,mcp,dap,gdbserver
```

## Files and network access

When `ntoseye` needs symbols or images, it downloads them from Microsoft's official symbol server. `ntoseye` keeps its configuration, cache, and REPL state in `~/.ntoseye`:

- `~/.ntoseye/commands/` for custom scripted commands.
- `~/.ntoseye/symbols/` for PDBs and images. This directory is a symbol store in the `symstore` layout. WinDbg, IDA, Ghidra, and rizin read this layout.
- `~/.ntoseye/aliases` for command aliases.
- `~/.ntoseye/history` for persistent REPL history.
- `~/.ntoseye/sites/` for breakpoint instructions that a session wrote and that the target does not remove itself. These are user-mode sites, and kernel sites over the `gdb` backend. If that session stops unexpectedly, the next attach restores these sites.
