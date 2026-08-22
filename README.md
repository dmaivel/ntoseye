<picture>
  <source media="(prefers-color-scheme: light)" srcset="media/logo_light.svg">
  <img align="right" width="24%" src="media/logo_dark.svg" alt="logo">
</picture>

# ntoseye ![license](https://img.shields.io/badge/license-MIT-blue) [![crates.io](https://img.shields.io/crates/v/ntoseye.svg)](https://crates.io/crates/ntoseye)

WinDbg-like kernel debugger for Windows VMs on Linux (KVM/QEMU, VMware) and macOS (UTM).

## Features

- WinDbg-compatible REPL commands and hexadecimal expression radix
- Kernel and usermode debugging
- Public/private PDB symbols, source lines, and scoped local-variable metadata
- Deferred, conditional, pass-count, one-shot, and command-action breakpoints
- AMD64 hardware watchpoints
- Integrated bugcheck, exception, verifier, WHEA, and crash-dump analysis
- Three backends: Windows KD, QEMU's GDB stub, and passive memory introspection
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

## Install via cargo

```bash
cargo install ntoseye
```

## Building

```bash
git clone https://github.com/dmaivel/ntoseye.git
cd ntoseye
cargo build --release
```

The default build embeds Python for [in-REPL custom commands](docs/sdk.md), so it links libpython and needs the Python dev lib (`python3-dev` / `python3-devel`). To build without it:

```bash
cargo build --release --no-default-features --features cli,mcp
```

# Usage

## Quickstart

The default and recommended backend is `kd` (KDCOM), which runs Windows KD over a QEMU serial socket. For a libvirt/virt-manager guest, the fastest path is:

1. Configure the VM transport with `ntoseye virsh`: pick the domain, choose _configure debug transports_, then `kd`. (Prefer editing the XML yourself? See [KVM/QEMU setup](docs/kvm-qemu.md).)
2. In the guest, enable kernel debugging and reboot (Administrator PowerShell):
   ```
   bcdedit /debug on
   bcdedit /dbgsettings serial debugport:1 baudrate:115200
   Restart-Computer
   ```
3. On the host, relax ptrace scope so `ntoseye` can attach to QEMU (resets on reboot):
   ```bash
   echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
   ```
4. Start the VM, then run `ntoseye`.

For guests that aren't configured for KD, see [Choosing a backend](docs/backends.md) for the `gdb` and `memory` alternatives. macOS/UTM setup and the `memory` backend are documented there too.

The debugger is self-documented: run `ntoseye --help` for command-line arguments, and press tab in the REPL for completions and descriptions of commands, symbols, and types.

# Documentation

- [REPL usage](docs/usage.md): expressions, radix, breakpoints, watchpoints, aliases
- [Symbols and source](docs/symbols.md): private PDBs, `.sympath`/`.srcpath`, source breakpoints
- [Choosing a backend](docs/backends.md): kd/gdb/memory comparison, per-hypervisor setup for [KVM/QEMU](docs/kvm-qemu.md), [VMware](docs/vmware.md), and [UTM](docs/utm.md)
- [Crash dumps](docs/dumps.md): offline dump analysis, generating dumps, guest tweaks
- [Python SDK and custom commands](docs/sdk.md)
- [MCP integration](docs/mcp.md)

# Credits

Functionality regarding initialization of guest information was written with the help of the following sources:

- [vmread](https://github.com/h33p/vmread)
- [pcileech](https://github.com/ufrisk/pcileech)
- [MemProcFS](https://github.com/ufrisk/MemProcFS)
- [ReactOS](https://github.com/reactos/reactos)
