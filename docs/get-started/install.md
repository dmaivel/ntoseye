# Install

`ntoseye` runs on Linux (x86-64, ARM64) and macOS on Apple Silicon. Every method below installs the same debugger; they differ in whether it embeds Python, which [custom commands](../scripting/commands.md) need, and in what they need installed first:

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

Installs a prebuilt binary to `~/.local/bin`.

## uv or pipx

```bash
uv tool install ntoseye    # or: pipx install ntoseye
```

Installs the `ntoseye` command in its own environment.

## cargo

```bash
cargo install ntoseye
```

Builds the release from crates.io, linked against your Python.

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

Like `cargo install`, a default build embeds Python and needs its development files. To build without it:

```bash
cargo build --release --no-default-features --features cli,mcp,dap,gdbserver
```

## Files and network access

`ntoseye` downloads symbols and images from Microsoft's official symbol server when required. Config, cache, and REPL state live under `~/.ntoseye`:

- `~/.ntoseye/commands/` for custom scripted commands
- `~/.ntoseye/symbols/` for PDBs and images, a symbol store in the `symstore` layout that WinDbg, IDA, Ghidra, and rizin read
- `~/.ntoseye/aliases` for command aliases
- `~/.ntoseye/history` for persistent REPL history
- `~/.ntoseye/sites/` for breakpoint instructions a session has planted that the target would not take out itself (user-mode sites, and kernel sites over the `gdb` backend), restored by the next attach if that session dies
