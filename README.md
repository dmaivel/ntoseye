<picture>
  <source media="(prefers-color-scheme: light)" srcset="media/logo_light.svg">
  <img align="right" width="24%" src="media/logo_dark.svg" alt="logo">
</picture>

# ntoseye ![license](https://img.shields.io/badge/license-MIT-blue) [![crates.io](https://img.shields.io/crates/v/ntoseye.svg)](https://crates.io/crates/ntoseye)

WinDbg-like kernel debugger for Windows VMs on Linux (KVM/QEMU, VMware) and macOS (UTM).

## Features

- WinDbg-compatible REPL commands and hexadecimal expression radix
- Kernel and usermode debugging
- Remote debugging over encrypted KDNET
- Public/private PDB symbols, source lines, and scoped local-variable metadata
- Deferred, conditional, pass-count, one-shot, and command-action breakpoints
- AMD64 hardware watchpoints
- Integrated bugcheck, exception, verifier, WHEA, and crash-dump analysis
- [Four backends](docs/backends.md): Windows KDCOM and KDNET, QEMU's GDB stub, and passive memory introspection
- [Python SDK and custom commands](docs/sdk.md)
- [MCP integration](docs/mcp.md)

### Supported Windows

`ntoseye` supports 64-bit AMD64 and ARM64 Windows 10 and 11 guests.

### Disclaimer

`ntoseye` downloads symbols and images from Microsoft's official symbol server when required. Config, cache, and REPL state live under `~/.ntoseye`:

- `~/.ntoseye/commands/` for custom scripted commands
- `~/.ntoseye/images/` for binaries downloaded from the VM
- `~/.ntoseye/symbols/` for PDBs
- `~/.ntoseye/aliases` for command aliases
- `~/.ntoseye/history` for persistent REPL history

### Preview

![ntos](media/preview.png)

# Installation

## Install via shell script

```bash
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/dmaivel/ntoseye/releases/latest/download/ntoseye-installer.sh | sh
```

Prebuilt release binaries include the CLI and MCP server but omit embedded Python for portability. Use a Cargo or source build for [in-REPL Python commands](docs/sdk.md); the standalone `pip install ntoseye` SDK needs neither.

## Install via cargo

```bash
cargo install ntoseye
```

`cargo install` and default source builds enable embedded Python and link against the local Python installation.

## Install the Python SDK

For standalone debugger automation from Python on Linux or Apple Silicon macOS:

```bash
pip install ntoseye
```

The Python package exposes the debugger through `import ntoseye`; it does not install the `ntoseye` CLI. See the [Python SDK documentation](docs/sdk.md).

## Building

```bash
git clone https://github.com/dmaivel/ntoseye.git
cd ntoseye
cargo build --release
```

To build without embedded Python:

```bash
cargo build --release --no-default-features --features cli,mcp
```

# Usage

## Quickstart

1. Power off the Windows VM.
2. Run `ntoseye configure` and select the hypervisor, virtual machine, and debugger backend. Note the `Run` command it prints.
3. Start the VM, run the printed guest setup commands in Administrator PowerShell, and reboot.
4. On Linux, allow `ntoseye` to inspect the hypervisor process. This resets on reboot:
   ```bash
   echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
   ```
   Alternatively, prefix the printed `Run` command with `sudo`.
5. Run the command saved in step 2.

Run `ntoseye status` at any time to inspect configured transports, assigned guest ports, endpoints, and launch commands without changing a VM.

### Hypervisor setup

`ntoseye configure` handles automatic setup for supported libvirt, VMware Workstation, and UTM guests. For plain QEMU or manual configuration, see the [KVM/QEMU](docs/kvm-qemu.md), [VMware](docs/vmware.md), and [UTM](docs/utm.md) setup guides.

### Not sure which backend to use?

See the [backend comparison table](docs/backends.md).

# Documentation

The debugger is self-documented: run `ntoseye --help` for command-line arguments, and press tab in the REPL for completions and descriptions of commands, symbols, and types.

- [REPL usage](docs/usage.md): expressions, radix, breakpoints, watchpoints, aliases
- [Symbols and source](docs/symbols.md): private PDBs, `.sympath`/`.srcpath`, source breakpoints
- [Choosing a backend](docs/backends.md): kd/kdnet/gdb/memory comparison, per-hypervisor setup for [KVM/QEMU](docs/kvm-qemu.md), [VMware](docs/vmware.md), and [UTM](docs/utm.md)
- [Crash dumps](docs/dumps.md): offline dump analysis, generating dumps, guest tweaks
- [Python SDK and custom commands](docs/sdk.md)
- [MCP integration](docs/mcp.md)

# Credits

Functionality regarding initialization of guest information was written with the help of the following sources:

- [vmread](https://github.com/h33p/vmread)
- [pcileech](https://github.com/ufrisk/pcileech)
- [MemProcFS](https://github.com/ufrisk/MemProcFS)
- [ReactOS](https://github.com/reactos/reactos)
