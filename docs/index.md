# ntoseye

`ntoseye` is a Windows debugger for Linux and macOS. It debugs the Windows kernel and user-mode processes of virtual and physical machines. It also analyzes crash dumps offline. It uses the command language of WinDbg.

| Debugging via REPL | Debugging via VS Code + DAP |
| - | - |
| ![The ntoseye REPL](../media/repl.webp) | ![ntoseye in VS Code](../media/vscode.webp) |

`ntoseye` is available under the MIT license.

## Using ntoseye

If you are new to `ntoseye`, do these steps:

1. [Install](get-started/install.md) `ntoseye`.
2. Attach to a VM with the [Quickstart](get-started/quickstart.md).
3. Follow [Your first session](get-started/tutorial.md). It shows how to attach and how to step through code.

If you already know WinDbg, read [Coming from WinDbg](get-started/windbg.md). It shows what is the same in `ntoseye` and what is different.

The [command reference](reference/commands/index.md) documents each REPL command. `.hh <command>` shows the same text. To control the debugger from code, start with the [Python SDK](scripting/sdk.md).

## Debugging from the host

`ntoseye` runs outside the machine that it debugs. It connects to that machine through one of four backends:

| Backend | Connects over | Needs in Windows | Stops and steps |
| --- | --- | --- | --- |
| `kd` | KDCOM, on a VM serial port | Kernel debugging | Yes |
| `kdnet` | KDNET, on the network | Kernel network debugging | Yes |
| `gdb` | The hypervisor's GDB stub | Nothing | Yes |
| `memory` | The VM's memory | Nothing | No |

KDNET can connect to any physical or virtual machine that Windows can debug. With `gdb` and `memory`, the Windows debugger is not enabled, and Windows does not detect the debugger. If the VM is on the same host, `ntoseye` reads guest memory directly from the VM process when it can. It does not use the debugger transport for these reads. [Choosing a backend](setup/backends.md) gives a full comparison of the backends.

`ntoseye` reads memory itself. So it can show data that the Windows debugger cannot show:

- The [secure kernel and trustlets](platforms/vbs.md) that virtualization-based security isolates in VTL1.
- Where each processor was when it stopped inside the Windows hypervisor.

## Symbols and source

`ntoseye` downloads symbols from Microsoft's symbol server into a cache. The cache uses the `symstore` layout, which WinDbg, IDA, and Ghidra also read.

For your own drivers, [private PDBs and local source](using/symbols.md) add source lines, local variables, and source breakpoints. [Driver replacement](using/kdfiles.md) loads a rebuilt driver from the host. You do not need to copy the driver into the guest.

## Platform support

`ntoseye` debugs 64-bit Windows 10 and 11 on AMD64 and ARM64, live or from a crash dump. It runs on Linux (x86-64 and ARM64) and on macOS on Apple Silicon.

`ntoseye` can set up and work directly with these hypervisors:

- [KVM/QEMU](setup/kvm-qemu.md) on Linux.
- [VMware Workstation](setup/vmware.md) on Linux.
- [UTM](setup/utm.md) on macOS.

`ntoseye` connects to all other physical or virtual machines over [KDNET](setup/kdnet.md).

## Get involved

The source code is on [GitHub](https://github.com/dmaivel/ntoseye). To build it, use Cargo:

```bash
git clone https://github.com/dmaivel/ntoseye.git
cd ntoseye
cargo build --release
```

Report bugs on the [issue tracker](https://github.com/dmaivel/ntoseye/issues). Ask questions or show what you built in [Discussions](https://github.com/dmaivel/ntoseye/discussions).

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
using/bugchecks
using/dumps
using/kdfiles
using/kmdf
using/drivers
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
