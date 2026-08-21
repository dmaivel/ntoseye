<picture>
  <source media="(prefers-color-scheme: light)" srcset="media/logo_light.svg">
  <img align="right" width="24%" src="media/logo_dark.svg" alt="logo">
</picture>

# ntoseye ![license](https://img.shields.io/badge/license-MIT-blue) [![crates.io](https://img.shields.io/crates/v/ntoseye.svg)](https://crates.io/crates/ntoseye)

Windows kernel debugger for Linux hosts running Windows under KVM/QEMU or VMware. Essentially, WinDbg for Linux.

## Features

- Command line interface
- WinDbg-compatible REPL commands and hexadecimal expression radix
- Kernel debugging
- Public/private PDB symbols, source lines, and scoped local-variable metadata
- Deferred, conditional, pass-count, one-shot, and command-action breakpoints
- Hardware watchpoints (kernel and user mode)
- Integrated bugcheck, exception, verifier, WHEA, and crash-dump analysis
- Three backends: Windows KD over a serial pipe (KDCOM, default), a hypervisor `gdbstub`, and passive memory introspection (see [Choosing a backend](#choosing-a-backend))
- [Python SDK](#python-sdk)
- [Custom commands](#custom-commands)
- [MCP integration](#mcp-integration)

### Supported Windows

`ntoseye` supports 64-bit AMD64 Windows 10 and 11 guests.

### Disclaimer

`ntoseye` needs to download symbols and images to initialize required offsets, it will only download symbols from Microsoft's official symbol server. Config, cache, and REPL state live under `~/.ntoseye`. If a legacy `~/.config/ntoseye` directory exists and `~/.ntoseye` does not, ntoseye moves it to `~/.ntoseye` automatically and prints a note. Notable paths:

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

The default build embeds Python for [in-REPL custom commands](#custom-commands), so it links libpython and needs the Python dev lib (`python3-dev` / `python3-devel`). To build without it:

```bash
cargo build --release --no-default-features --features cli,mcp
```

# Usage

## Quickstart

The default and recommended backend is `kd` (KDCOM), which runs Windows KD over a QEMU serial socket. For a libvirt/virt-manager guest, the fastest path is:

1. Configure the VM transport with `ntoseye virsh`: pick the domain, choose _configure debug transports_, then `kd`. (Prefer editing the XML yourself? See [VM configuration](#vm-configuration).)
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

For guests that aren't configured for KD, see [Choosing a backend](#choosing-a-backend) for the `gdb` and `memory` alternatives.

The debugger is self-documented: run `ntoseye --help` for command-line arguments, and press tab in the REPL for completions and descriptions of commands, symbols, and types.

## REPL syntax

Expressions accept symbols, numeric literals, registers, casts, arithmetic, indexing, and pointer reads:

```text
ev @rip
ev poi(nt!PsInitialSystemProcess)
ev (_EPROCESS)poi(nt!PsInitialSystemProcess)->UniqueProcessId
```

The REPL follows WinDbg's hexadecimal default radix: a bare `1000` is `0x1000`. Use the `0n` prefix for an explicit decimal value (`0n10`), or `n 10` to switch the session default to decimal. `n 8` and `n 16` select octal and hexadecimal. Bare hexadecimal tokens containing `a`-`f` are resolved as symbols first and fall back to hexadecimal only when no symbol matches. Use `0x...` when an address must be unambiguously numeric.

Field access in `ev` needs an explicit cast so ntoseye knows the layout. The `dt` command gets the type from its first argument, so the address expression does not need a cast:

```text
dt _EPROCESS poi(nt!PsInitialSystemProcess) UniqueProcessId
```

Breakpoints and data watchpoints accept conditions written directly after the address expression. Conditions use the normal expression grammar: comparisons, bitwise operations, and short-circuiting `!`, `&&`, and `||` can be combined with parentheses. Write ranges explicitly (`0 < @rax && @rax < 0n10`) rather than as chained comparisons.

```text
bp nt!KeBugCheckEx @rcx == 0x50 && (@rdx & 0xff) != 0
```

Data watchpoints use `ba <access><size> <address>` (`w` = write, `r` = read/write, `e` = execute; sizes 1, 2, 4, or 8 with natural alignment; KD backend only). For a quick live test, watch a global the kernel writes to frequently:

```text
ba w8 nt!KiBalanceSetManagerLastCheckTick
```

Deferred breakpoints preserve their symbolic or `file.c:line` specification across module unload/reload. `/1` makes a one-shot breakpoint, `/p <pid>` sets an explicit process scope, a pass count delays surfacing, and `do` attaches a bounded REPL action:

```text
bu /1 /p 1234 mydriver!DriverEntry
bu mydriver.c:42 10 if @rcx != 0 do r; gc
bm mydriver!Dispatch*
```

### Private PDBs and local source

Symbol and source paths are configured independently. The Linux host needs the private PDB and, for source display, a copy of the source tree. Use the full linker PDB (`/DEBUG:FULL`, not a stripped/public PDB) when procedure locals are needed. ntoseye validates the selected PDB's GUID and age against the CodeView identity in the loaded guest image and rejects a mismatch.

Append the directory containing the PDB with `.sympath+`. The `+` preserves the managed cache and Microsoft's public symbol server; bare `.sympath` replaces the entire active list:

```text
.sympath+ <directory-containing-the-pdb>
```

`.srcpath` maps a source-path prefix recorded in the PDB to the corresponding source directory on the Linux host:

```text
.srcpath <source-prefix-recorded-in-pdb>=<local-source-root>
```

For example:

```text
.sympath+ /home/me/symbols/mydriver
.srcpath C:\Users\me\source\repos\MyDriver=/home/me/src/MyDriver
```

The left side of `.srcpath` is a build-time source path such as the prefix shown in an unmapped source location; it is not the PDB path embedded in the image. The right side is the local directory containing the same source files.

If the driver is already loaded, force source selection and indexing once after changing the path, inspect the accepted identity, and set the source breakpoint:

```text
ld mydriver
lmv mydriver
bu MyDriver.c:42
bl
g
```

`lmv` reports the loaded image range, symbol status, where the image was read from (for example, guest memory), and the accepted PDB GUID and age. `.reload mydriver` is equivalent to `ld mydriver`; `.reload` without a module reloads every module in the current inspection scope.

The paths and breakpoint can also be configured before loading the driver. In that case, omit `ld`: `bu MyDriver.c:42` creates a deferred breakpoint, and `bl` shows `deferred` with no address. Load and trigger the driver in Windows after `g`. At the next debugger stop, ntoseye refreshes the module list, loads the matching PDB, and enables the same breakpoint ID with its existing settings.

At the source hit, these commands verify the complete private-symbol workflow:

```text
lmv mydriver
ln @rip
uf mydriver!Transform
k
dv
```

The stack and disassembly include mapped source locations. `dv` displays the current procedure's private parameters and locals, including register- or stack-relative locations and live values when the current register context matches the procedure.

Keep a `bu` breakpoint installed if the driver will be cycled. Once ntoseye observes the unload, `bl` changes it from `enabled` to `deferred` without losing its ID, source specification, conditions, pass count, hit count, or action. After the module reload is observed at a later stop, the same breakpoint becomes `enabled` at the new address.

`.reload` is reserved for Rust-owned symbol reload behavior; `reload-scripts` reloads custom commands and aliases.

Aliases use `alias <name> <expansion>`. `${1}` is the first argument passed to the alias, `${2}` is the second, and `${*}` expands to all alias arguments separated by spaces. Alias expansions can contain command lists separated by semicolons.

```text
alias ubp bp ${1}; g
alias pe dt _EPROCESS poi(nt!PsInitialSystemProcess) ${1}
unalias ubp
```

Aliases are saved in `~/.ntoseye/aliases`; `reload-scripts` reloads aliases and custom Python commands.

## Choosing a backend

`ntoseye` can talk to the guest three ways. Pick with `--backend kd` (default), `--backend gdb`, or `--backend memory`.

|                                 | `kd` (default)                                                                                         | `gdb`                                     | `memory`                                      |
| ------------------------------- | ------------------------------------------------------------------------------------------------------ | ----------------------------------------- | --------------------------------------------- |
| Transport                       | Windows KD over a serial pipe (KDCOM)                                                                  | Hypervisor `gdbstub`                      | None; hypervisor-process memory introspection |
| Requires in-guest configuration | Yes (`bcdedit /debug on`; anti-debug code, PatchGuard, and some Windows behaviour change once enabled) | No (guest is unaware it's being debugged) | No                                            |
| Requires host VM configuration  | Yes (serial socket)                                                                                    | Yes (a listening `gdbstub`)               | No                                            |
| Execution control               | Yes                                                                                                    | Yes                                       | No                                         |
| Kernel breakpoints              | Yes                                                                                                    | Yes                                       | No                                         |
| Usermode breakpoints            | Yes                                                                                                    | No                                        | No                                         |
| Kernel breakpoint mechanism     | `DbgKdWriteBreakPointApi`                                                                              | gdb `Z0` packets                          | No                                         |

See [VM configuration](#vm-configuration) for the host-side setup of each backend.

## VM configuration

Manual host-side setup for each backend. libvirt/virt-manager users can do most of this automatically with `ntoseye virsh` (see [Quickstart](#quickstart)); `ntoseye virsh` can also remove ntoseye-managed debug transports later.

For VMware Workstation, power the VM off before editing its `.vmx` file. `ntoseye virsh` only configures libvirt/QEMU guests. VMware VM discovery currently selects the first running `vmware-vmx` process, so only the target VMware VM should be powered on while using `ntoseye`.

### GDBSTUB

Fallback backend for guests that are not configured for Windows KD. Expose QEMU's gdbstub on `127.0.0.1:1234` by passing `-s -S`, then run with `--backend gdb`.

> [!NOTE]
> Do not enable kernel debug mode (`bcdedit /debug on`) in the guest when using the `gdb` backend. That setting is only for the `kd` backend, and the `gdb` backend's whole advantage is that the guest is unaware it's being debugged. With debug mode on, the kernel changes behaviour (anti-debug code, PatchGuard) and expects a KD debugger to service breaks, while nothing on the `gdb` side answers the KD transport, so the guest can hang on `DbgBreakPoint`/exceptions. Leave debug mode off.

#### QEMU

Append `-s -S` to the qemu command.

#### virt-manager

Add the following to the XML configuration:

```xml
<domain xmlns:qemu="http://libvirt.org/schemas/domain/qemu/1.0" type="kvm">
  ...
  <qemu:commandline>
    <qemu:arg value="-s"/>
    <qemu:arg value="-S"/>
  </qemu:commandline>
</domain>
```

#### VMware

VMware Workstation provides its own GDB remote stub. Add the following to the VM's `.vmx` file:

```ini
debugStub.listen.guest64 = "TRUE"
debugStub.port.guest64 = "1234"
```

Legacy VMware stubs that do not expose an AMD64 XML target description are unsupported; use KDCOM or the `memory` backend instead.

### KDCOM

Default backend. In the guest, enable kernel debugging (run as Administrator, then reboot):

```
bcdedit /debug on
bcdedit /dbgsettings serial debugport:1 baudrate:115200
```

Use `debugport:2` instead of `:1` if the KD chardev ends up as COM2 (see the virt-manager subsection below).

#### QEMU

Add a Unix-socket chardev and route a serial port to it:

```
-chardev socket,id=kd,path=/tmp/ntoseye-kd.sock,server=on,wait=off -serial chardev:kd
```

Then connect: `ntoseye`.

The initial KD handshake timeout is 8 seconds by default. For unusually slow guests, override it with `NTOSEYE_KD_TIMEOUT=<seconds>`.

#### virt-manager

> [!WARNING]
> virt-manager auto-adds a `<serial>` console device on every VM, which
> claims COM1. Either replace that device with one pointing at the KD socket
> (KD becomes COM1, use `debugport:1`), or leave it and add the KD chardev
> via `qemu:commandline` (KD becomes COM2, use `debugport:2`).

**Option A (recommended):** replace the auto-added serial. KD is COM1, `debugport:1` is correct.

```xml
<serial type="unix">
  <source mode="bind" path="/tmp/ntoseye-kd.sock"/>
  <target type="isa-serial" port="0"/>
</serial>
```

**Option B:** keep the auto-added serial and append the KD chardev via `qemu:commandline`. If KD is COM2, use `debugport:2`.

```xml
<domain xmlns:qemu="http://libvirt.org/schemas/domain/qemu/1.0" type="kvm">
  ...
  <qemu:commandline>
    <qemu:arg value="-chardev"/>
    <qemu:arg value="socket,id=kd,path=/tmp/ntoseye-kd.sock,server=on,wait=off"/>
    <qemu:arg value="-serial"/>
    <qemu:arg value="chardev:kd"/>
  </qemu:commandline>
</domain>
```

#### VMware

Configure the first virtual serial port (guest COM1) as a server-side pipe:

```ini
serial0.present = "TRUE"
serial0.fileType = "pipe"
serial0.fileName = "/tmp/ntoseye-kd.sock"
serial0.pipe.endPoint = "server"
serial0.startConnected = "TRUE"
serial0.yieldOnMsrRead = "TRUE"
```

If another virtual serial device already occupies COM1, configure the next `serialN` entry and use the corresponding `debugport:N+1`.

### Memory

Passive backend for KVM/QEMU and VMware guests where you only want memory introspection. It reads the VM process directly and requires no guest or VM debug transport configuration:

```bash
ntoseye --backend memory
```

Execution control, registers, execution-context selection, breakpoints, debug output, bugcheck stops, and reload detection are unavailable in this mode. Run `capabilities` in the REPL for the exact backend feature matrix.

### Crash dump

Analyse a Windows kernel crash dump (`.dmp`) offline, without a running VM:

```bash
ntoseye --dump /path/to/MEMORY.DMP
```

Full and kernel memory dumps are supported. The dump's `DirectoryTableBase` and `CONTEXT` record are used automatically: for BSOD dumps the crash registers, stack trace, and bugcheck analysis are available, while live system dumps (bugcheck 0x161) have memory but no exception context.

Available commands include `ps`, `lm`, `dt`, `dq`/`db`/`dd`, `dqs`, `da`/`du`, `analyze`, `trap`, `x`, `ev`, `drivers`, and `s`. Execution control, breakpoints, and register/memory writes are not available (the dump is read-only).

The Python SDK supports dump analysis as well:

```python
import ntoseye
dbg = ntoseye.attach("dmp", connect="/path/to/MEMORY.DMP")
```

So does the MCP server: pass `--dump` at startup (`ntoseye --dump /path/to/MEMORY.DMP mcp`), or start it with `ntoseye mcp` (no flags) and let the client load a dump later via the `open_dump` tool.

#### Generating dumps

From the host, without crashing the guest (produces a live system dump, bugcheck 0x161):

```bash
virsh dump <domain> /tmp/win.dmp --memory-only --format=win-dmp
```

This needs the domain's `vmcoreinfo` feature (`ntoseye virsh` can enable it) and the virtio-win `fwcfg` driver installed in the guest; without them QEMU fails with `invalid vmcoreinfo note size`.

From a real BSOD, Windows writes `C:\Windows\MEMORY.DMP` on the boot after the crash (System Properties > Startup and Recovery > "Kernel memory dump"). The dump is staged through the page file, so pick one:

- keep a page file on `C:` at least as large as the dump (in the Virtual Memory dialog, click **Set** before OK, or it silently discards the change), or
- keep paging disabled (see [Recommended guest tweaks](#recommended-guest-tweaks)) and configure a dedicated dump file instead, under `HKLM\SYSTEM\CurrentControlSet\Control\CrashControl`: `DedicatedDumpFile` (REG_SZ, e.g. `C:\dedicated.sys`) and `DumpFileSize` (DWORD, MB).

Force the crash with Sysinternals NotMyFault or the `CrashOnCtrlScroll` registry switch. If the guest is booted in debug mode with a debugger attached, continue past the bugcheck (`g`), otherwise Windows waits in the debugger instead of writing the dump.

Copy the dump out to the host with [guestfs-tools](https://libguestfs.org/) while the guest is shut off:

```bash
virt-copy-out -d <domain> /Windows/MEMORY.DMP /tmp/
```

(or use any guest-to-host channel: an SMB/virtiofs share, scp, etc.)

### Recommended guest tweaks

Although not required, disabling memory paging and compression in the guest avoids memory-related issues. This only needs to be done once per Windows installation (Administrator PowerShell):

```
Get-CimInstance Win32_ComputerSystem | Set-CimInstance -Property @{ AutomaticManagedPagefile = $false }
Get-CimInstance Win32_PageFileSetting | Remove-CimInstance
Disable-MMAgent -MemoryCompression
Restart-Computer
```

Note: BSOD crash dumps are staged through the page file, so with paging disabled Windows won't write `MEMORY.DMP` unless you set a dedicated dump file (see [Generating dumps](#generating-dumps)).

## Python SDK

Drive the debugger from Python with the `ntoseye` module: the same introspection and run-control surface as the REPL (memory/struct reads, expression eval, symbol/type lookup, disassembly, backtraces, trap-frame decoding, code breakpoints, data watchpoints, execution control, process enumeration), with Python owning the loop. `dbg.watchpoint(target, access="write"|"read_write", length=1|2|4|8)` returns the same live handle type as `dbg.breakpoint(...)`; `dbg.inspect_trap_frame()` decodes the current thread's saved `_KTRAP_FRAME`, or accepts an explicit address. The wheel is self-contained, so this needs neither the `ntoseye` CLI nor a build with the embedded interpreter.

Data watchpoints currently require KD, apply globally across guest address spaces, and consume one of the four x86 debug-register slots.

### Install via pip

```sh
pip install ntoseye
```

### Usage

```python
import ntoseye

# defaults to backend="kd", connect="/tmp/ntoseye-kd.sock"
dbg = ntoseye.attach()

for proc in dbg.processes():  # _EPROCESS cursors
    print(proc.UniqueProcessId, proc.ImageFileName, hex(proc.addr))

fun = dbg.eval("nt!KeBugCheckEx")
print(hex(fun), dbg.read(fun, 16).hex())
```

The module is a native extension built with [maturin](https://www.maturin.rs/); see [`ntoseye-py/README.md`](ntoseye-py/README.md) for build info and [`examples/`](examples/) for standalone scripts.

## Custom commands

In addition to the standalone [Python SDK](#python-sdk), `ntoseye` can run Python commands inside the live REPL; the same SDK, but bound to the session you're already debugging rather than a separate attach. This requires a build with the embedded interpreter (which is enabled by default).

Drop any `*.py` file in `~/.ntoseye/commands/`; they're auto-loaded at REPL startup. Run `reload-scripts` in the REPL to pick up edits without restarting.

Custom commands need no `pip install ntoseye` as the module is served by the embedded interpreter. However, it may be worth installing to get LSP completions and type diagnostics while you write them.

```python
import ntoseye.repl as repl

# repl.Process is the completion type for processes, so the user can make use of `> hide ..<TAB>`
@repl.command("hide", "Unlink a process.\n(usage: hide <pid|name>)", target=repl.Process)
def hide(dbg: repl.Debugger, target=None):
    p = dbg.process(target)
    ...
```

See [`commands/`](commands/) for more examples.

## MCP integration

`ntoseye` can run as an [MCP](https://modelcontextprotocol.io) server, exposing the debugger as tools to MCP clients. It reads the top-level `--backend`/`--connect` flags to choose how to attach, so the VM and its debug transport must be set up exactly as for the REPL (see [Choosing a backend](#choosing-a-backend)). Only one consumer of the VM can run at a time.

The structured tool surface includes `inspect_trap_frame` and `set_watchpoint`; watchpoints report `stop: "watchpoint"` with access/length metadata and use the existing breakpoint lifecycle tools for list, disable, enable, and clear operations.

> [!IMPORTANT]
> The server attaches on launch, so bring up the guest and its debug transport before starting the client.

### stdio (default)

The MCP client launches `ntoseye mcp` as a subprocess and talks to it over stdin/stdout. Most desktop MCP clients are configured with a JSON file listing the command to spawn:

```json
{
  "mcpServers": {
    "ntoseye": {
      "command": "ntoseye",
      "args": ["mcp"]
    }
  }
}
```

Top-level flags go before the `mcp` subcommand, e.g. to pin the backend and socket:

```json
{
  "mcpServers": {
    "ntoseye": {
      "command": "ntoseye",
      "args": ["--backend", "kd", "--connect", "/tmp/ntoseye-kd.sock", "mcp"]
    }
  }
}
```

Use an absolute path for `command` (e.g. `../target/release/ntoseye`) if `ntoseye` isn't within `PATH`.

### Streamable HTTP

For web MCP clients that connect over the network instead of spawning a subprocess, use `--http`:

```bash
ntoseye mcp --http 127.0.0.1:8080
```

The service is mounted at `http://127.0.0.1:8080/mcp`. HTTP binds are loopback-only by default, since the tool surface includes execution control and guest writes; pass `--unsafe-http` to bind a non-loopback address and expose those tools to the network (only on trusted hosts).

# Credits

Functionality regarding initialization of guest information was written with the help of the following sources:

- [vmread](https://github.com/h33p/vmread)
- [pcileech](https://github.com/ufrisk/pcileech)
- [MemProcFS](https://github.com/ufrisk/MemProcFS)
- [ReactOS](https://github.com/reactos/reactos)
