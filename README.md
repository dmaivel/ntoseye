# ntoseye

<img align="right" width="32%" src="media/ntoseye.svg" alt="logo">

[![license](https://img.shields.io/badge/license-MIT-blue?style=flat-square&labelColor=1c1c1c)](LICENSE)
[![release](https://img.shields.io/github/v/release/dmaivel/ntoseye?style=flat-square&labelColor=1c1c1c&logo=github&logoColor=white)](https://github.com/dmaivel/ntoseye/releases/latest)
[![crates.io](https://img.shields.io/crates/v/ntoseye?style=flat-square&labelColor=1c1c1c&logo=rust&logoColor=white)](https://crates.io/crates/ntoseye)
[![docs.rs](https://img.shields.io/docsrs/ntoseye?style=flat-square&labelColor=1c1c1c&logo=docsdotrs&logoColor=white)](https://docs.rs/ntoseye)

A WinDbg-like Windows debugger for Linux and macOS, with support for kernel-mode and user-mode debugging of virtual and physical machines, and offline crash-dump analysis.

## Showcase

| Debugging via REPL | Debugging via VSCode + DAP |
| - | - |
| ![repl](media/repl.webp) | ![vscode](media/vscode.webp) |

## Features

- WinDbg-style commands and expressions
- Public and private PDB symbols, source lines, and local variables
- Conditional and deferred breakpoints, hardware watchpoints, and breakpoint commands
- [KD/KDNET, QEMU GDB, and passive memory backends](https://ntoseye.com/setup/backends/)
- [VBS secure-kernel (VTL1) and trustlet memory inspection](https://ntoseye.com/platforms/vbs/)
- [Host-served driver images for driver development](https://ntoseye.com/using/kdfiles/)
- [Python SDK](https://ntoseye.com/scripting/sdk/) and [custom commands](https://ntoseye.com/scripting/commands/)
- [Editor integration over DAP](https://ntoseye.com/integrations/dap/)
- [IDA, Binja, Ghidra over the GDB remote protocol](https://ntoseye.com/integrations/gdbserver/)
- [Agent integration over MCP](https://ntoseye.com/integrations/mcp/)

### Supported Windows

`ntoseye` supports 64-bit AMD64 and ARM64 Windows 10 and 11 targets.

### Supported hypervisors

`ntoseye` supports any target that Windows can debug over [KDNET](https://ntoseye.com/setup/kdnet/). KVM/QEMU, VMware Workstation, and UTM guests additionally get [KDCOM, GDB, and memory-only backends](https://ntoseye.com/setup/backends/).

### Files and network access

`ntoseye` downloads symbols and images from Microsoft's official symbol server when required. Config, cache, and REPL state live under `~/.ntoseye`:

- `~/.ntoseye/commands/` for custom scripted commands
- `~/.ntoseye/symbols/` for PDBs and images, a symbol store in the `symstore` layout that WinDbg, IDA, Ghidra, and rizin read
- `~/.ntoseye/aliases` for command aliases
- `~/.ntoseye/history` for persistent REPL history
- `~/.ntoseye/sites/` for user-mode breakpoint bytes a session has written, restored by the next attach if that session dies

# Getting started

## Install

### Shell script

```bash
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/dmaivel/ntoseye/releases/latest/download/ntoseye-installer.sh | sh
```

The prebuilt binaries have no Python, so they cannot run [custom commands](https://ntoseye.com/scripting/commands/).

### uv or pipx

```bash
uv tool install ntoseye    # or: pipx install ntoseye
```

Installs the `ntoseye` command with support for custom commands, in its own environment. Requires Python 3.9 or newer, on Linux (x86-64, ARM64) or Apple Silicon macOS.

### cargo

```bash
cargo install ntoseye
```

`cargo install` and default source builds embed Python and link against the local Python installation.

### Python SDK

To drive the debugger from your own Python code, install the same package into your project's environment:

```bash
pip install ntoseye
```

This also puts the `ntoseye` command in that environment. See the [Python SDK documentation](https://ntoseye.com/scripting/sdk/).

## Building

```bash
git clone https://github.com/dmaivel/ntoseye.git
cd ntoseye
cargo build --release
```

To build without embedded Python:

```bash
cargo build --release --no-default-features --features cli,mcp,dap,gdbserver
```

To build the documentation site, whose command and SDK references are generated from the source (this runs `cargo`):

```bash
pip install -r docs/requirements.txt
sphinx-build -b dirhtml -n -W docs docs/_build/html
```

For a live preview that rebuilds as you edit, `pip install sphinx-autobuild` and run `sphinx-autobuild -b dirhtml docs docs/_build/html` (served at `http://127.0.0.1:8000`).

# Usage

## Quickstart

If you are using QEMU/KVM, VMware, or UTM, you can use `ntoseye configure` for easy setup. Otherwise, look at [KDNET](https://ntoseye.com/setup/kdnet/) instructions.

1. Power off the Windows VM.
2. Run `ntoseye configure` and select the hypervisor, virtual machine, and debugger backend. Note the `Run` command it prints.
3. Start the VM, run the printed guest setup commands in Administrator PowerShell, and reboot.
4. Run the command saved in step 2.

Run `ntoseye status` at any time to inspect configured transports, assigned guest ports, endpoints, and launch commands without changing a VM.

### Hypervisor setup

`ntoseye configure` handles automatic setup for supported libvirt, VMware Workstation, and UTM guests. For plain QEMU or manual configuration, see the [KVM/QEMU](https://ntoseye.com/setup/kvm-qemu/), [VMware](https://ntoseye.com/setup/vmware/), and [UTM](https://ntoseye.com/setup/utm/) setup guides.

For any other target, follow the [KDNET guide](https://ntoseye.com/setup/kdnet/) instead; `configure` is not needed.

### Not sure which backend to use?

See the [backend comparison table](https://ntoseye.com/setup/backends/).

# Documentation

The full documentation is at [ntoseye.com](https://ntoseye.com). The debugger also documents itself: run `ntoseye --help` for command-line arguments, press tab in the REPL for completions and descriptions of commands, symbols, and types, and run `.hh <command>` for a command's full help. The site's command reference is built from that same help.

- [Tutorial](https://ntoseye.com/get-started/tutorial/): a first session, from attaching to stepping
- [Coming from WinDbg](https://ntoseye.com/get-started/windbg/): what carries over and what differs
- [Troubleshooting](https://ntoseye.com/get-started/troubleshooting/)
- [Using the REPL](https://ntoseye.com/using/repl/): command names, aliases
- [Expressions](https://ntoseye.com/reference/expressions/): numbers and radix, operators, registers and pseudo-registers, symbols, types, locals
- [Breakpoints and watchpoints](https://ntoseye.com/using/breakpoints/): the breakpoint grammar, conditions, scoping
- [VBS and the Windows hypervisor](https://ntoseye.com/platforms/vbs/): VTL1 and trustlet inspection, stops in the hypervisor
- [WOW64 processes](https://ntoseye.com/platforms/wow64/)
- [Memory and paging](https://ntoseye.com/using/memory/): memory sources, writes, paged-out memory
- [Symbols and source](https://ntoseye.com/using/symbols/): private PDBs, `.sympath`/`.srcpath`, source breakpoints
- [Choosing a backend](https://ntoseye.com/setup/backends/): kd/kdnet/gdb/memory comparison, per-hypervisor setup for [KVM/QEMU](https://ntoseye.com/setup/kvm-qemu/), [VMware](https://ntoseye.com/setup/vmware/), and [UTM](https://ntoseye.com/setup/utm/)
- [KDNET](https://ntoseye.com/setup/kdnet/): `kdnet.exe` guest setup, host launch, reboot behavior
- [Crash dumps](https://ntoseye.com/using/dumps/): offline dump analysis, generating dumps, guest tweaks
- [Driver replacement map](https://ntoseye.com/using/kdfiles/): `.kdfiles`, loading a driver from the host instead of the guest
- [Python SDK](https://ntoseye.com/scripting/sdk/) and [custom REPL commands](https://ntoseye.com/scripting/commands/)
- [MCP integration](https://ntoseye.com/integrations/mcp/)
- [Editor integration (DAP)](https://ntoseye.com/integrations/dap/): source-level debugging from VS Code, Emacs (dape), or nvim-dap
- [Disassembler integration (GDB remote protocol)](https://ntoseye.com/integrations/gdbserver/): debugging from IDA, Binary Ninja, Ghidra, gdb, or lldb

# Credits

Functionality regarding initialization of guest information was written with the help of the following sources:

- [vmread](https://github.com/h33p/vmread)
- [pcileech](https://github.com/ufrisk/pcileech)
- [MemProcFS](https://github.com/ufrisk/MemProcFS)
- [ReactOS](https://github.com/reactos/reactos)
