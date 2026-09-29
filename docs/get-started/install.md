# Install

`ntoseye` runs on Linux (x86-64, ARM64) and on macOS on Apple Silicon. Each method below installs the same debugger. The methods differ in whether they embed Python, which [custom commands](../scripting/commands.md) need, and in what software you need before you install:

| Method | Custom commands | Needs |
|---|---|---|
| [Shell script](#shell-script) | no | nothing |
| [uv or pipx](#uv-or-pipx) | yes | Python 3.9 or newer |
| [cargo](#cargo) | yes | Rust, and Python 3.9 or newer with its development files (`python3-dev` on Debian and Ubuntu) |
| [pip](#python-sdk), for the Python SDK | yes | Python 3.9 or newer |

## Shell script

The installer script puts a prebuilt binary in `~/.local/bin`:

```bash
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/dmaivel/ntoseye/releases/latest/download/ntoseye-installer.sh | sh
```

## uv or pipx

Either tool installs the `ntoseye` command in its own environment:

```bash
uv tool install ntoseye    # or: pipx install ntoseye
```

## cargo

cargo builds the release from crates.io and links it against your Python:

```bash
cargo install ntoseye
```

## Python SDK

To control the debugger from your own Python code, install the same package in the environment of your project:

```bash
pip install ntoseye
```

This also installs the `ntoseye` command in that environment. For more information, see the [Python SDK documentation](../scripting/sdk.md).

## Building from source

```bash
git clone https://github.com/dmaivel/ntoseye.git
cd ntoseye
cargo build --release
```

Like `cargo install`, a default build embeds Python and needs the Python development files. To build without Python:

```bash
cargo build --release --no-default-features --features cli,mcp,dap,gdbserver
```

## Files and network access

When `ntoseye` needs symbols or images, it downloads them from Microsoft's official symbol server. It keeps its configuration, cache, and REPL state in `~/.ntoseye`:

- `~/.ntoseye/commands/` for custom scripted commands.
- `~/.ntoseye/symbols/` for PDBs and images, as a symbol store in the `symstore` layout that WinDbg, IDA, Ghidra, and rizin read.
- `~/.ntoseye/aliases` for command aliases.
- `~/.ntoseye/history` for persistent REPL history.
- `~/.ntoseye/sites/` for breakpoint instructions that a session wrote and that the target does not remove itself, which are user-mode sites and kernel sites over the `gdb` backend. If that session stops unexpectedly, the next attach restores them.
