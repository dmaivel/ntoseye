# ntoseye

`ntoseye` is a Windows debugger for Linux and macOS. It debugs the Windows kernel and user-mode processes of virtual and physical machines, and analyzes crash dumps offline, with the command language of WinDbg.

| Debugging via REPL | Debugging via VS Code + DAP |
| - | - |
| ![The ntoseye REPL](../media/repl.webp) | ![ntoseye in VS Code](../media/vscode.webp) |

`ntoseye` is available under the MIT license.

## Using ntoseye

New to `ntoseye`? [Install](get-started/install.md) it, attach to a VM with the [Quickstart](get-started/quickstart.md), then follow the [Tutorial](get-started/tutorial.md) through a first session. If you already know WinDbg, [Coming from WinDbg](get-started/windbg.md) lists what carries over and what differs.

Every REPL command is documented in the [command reference](reference/commands/index.md), which is the same text `.hh <command>` prints. To drive the debugger from code, start with the [Python SDK](scripting/sdk.md).

## Debugging from the host

`ntoseye` runs outside the machine it debugs and reaches it through one of four backends:

| Backend | Connects over | Needs in Windows | Stops and steps |
| --- | --- | --- | --- |
| `kd` | KDCOM, on a VM serial port | Kernel debugging | Yes |
| `kdnet` | KDNET, on the network | Kernel network debugging | Yes |
| `gdb` | The hypervisor's GDB stub | Nothing | Yes |
| `memory` | The VM's memory | Nothing | No |

KDNET reaches any machine Windows can debug, physical or virtual. With `gdb` and `memory`, Windows runs without its debugger enabled and does not know it is being debugged. With a VM on the same host, `ntoseye` reads guest memory straight from the VM process whenever it can, instead of through the debugger transport. [Choosing a backend](setup/backends.md) compares the backends in full.

Because it reads memory itself, `ntoseye` also sees what Windows' own debugger cannot: the [secure kernel and trustlets](platforms/vbs.md) that virtualization-based security isolates in VTL1, and where each processor left off when it stopped inside the Windows hypervisor.

## Symbols and source

Symbols come from Microsoft's symbol server, into a cache in the `symstore` layout that WinDbg, IDA, and Ghidra also read. [Private PDBs and local source](using/symbols.md) add source lines, local variables, and source breakpoints for your own drivers, and [driver replacement](using/kdfiles.md) loads a rebuilt driver from the host without copying it into the guest.

## Platform support

`ntoseye` debugs 64-bit Windows 10 and 11 on AMD64 and ARM64, live or from a crash dump, and runs on Linux (x86-64, ARM64) and macOS on Apple Silicon. It sets up and works directly with [KVM/QEMU](setup/kvm-qemu.md) and [VMware Workstation](setup/vmware.md) on Linux and [UTM](setup/utm.md) on macOS; any other machine, physical or virtual, is reached over [KDNET](setup/kdnet.md).

## Get involved

The source is on [GitHub](https://github.com/dmaivel/ntoseye). It builds with Cargo:

```bash
git clone https://github.com/dmaivel/ntoseye.git
cd ntoseye
cargo build --release
```

Report bugs on the [issue tracker](https://github.com/dmaivel/ntoseye/issues), and ask questions or share what you have built in [Discussions](https://github.com/dmaivel/ntoseye/discussions).

```{toctree}
:hidden:
:caption: Getting started

get-started/install
get-started/quickstart
get-started/tutorial
get-started/windbg
get-started/troubleshooting
reference/command-line/index
```

```{toctree}
:hidden:
:caption: Setting up a target

setup/backends
setup/kvm-qemu
setup/vmware
setup/utm
setup/kdnet
```

```{toctree}
:hidden:
:caption: Using ntoseye

using/repl
using/breakpoints
using/memory
using/symbols
using/dumps
using/kdfiles
```

```{toctree}
:hidden:
:caption: Platform topics

platforms/vbs
platforms/wow64
```

```{toctree}
:hidden:
:caption: Integrations

integrations/dap
integrations/gdbserver
integrations/mcp
```

```{toctree}
:hidden:
:caption: Scripting

scripting/sdk
scripting/commands
reference/sdk/index
```

```{toctree}
:hidden:
:caption: Reference

reference/commands/index
reference/expressions
```

```{toctree}
:hidden:
:caption: Internals

internals/vbs
internals/kd-reads
Rust crate API (docs.rs) <https://docs.rs/ntoseye/latest/ntoseye/>
```

```{toctree}
:hidden:
:caption: Resources

Source code <https://github.com/dmaivel/ntoseye>
Releases <https://github.com/dmaivel/ntoseye/releases>
Bug reports <https://github.com/dmaivel/ntoseye/issues>
Discussions <https://github.com/dmaivel/ntoseye/discussions>
PyPI package <https://pypi.org/project/ntoseye/>
crates.io <https://crates.io/crates/ntoseye>
```
