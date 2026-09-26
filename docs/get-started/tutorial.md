# Tutorial: a first session

This walks through one session against a Windows 11 VM: attach, look around, stop on a kernel function, read its arguments, step, and leave. Every command and output below was captured from a real session and trimmed only where marked `...`. It assumes a target you can attach to; the [Quickstart](quickstart.md) gets you there.

The session uses the `gdb` backend, which needs nothing set up inside Windows. The commands are the same over `kd` and `kdnet`; what differs is where the first stop lands.

## Attach

```text
$ ntoseye --backend gdb
target
  kernel Windows 26200
  base   fffff80797200000
  psmods ffffe70faa662830

 BREAK  p01.01 hypervisor at hvix64+0x3a6bde
 ├─ thread Idle  state Running  ethread fffff807981d25c0  pid 0  tid 0
 ╰─ saved VTL0 nt!HalProcessorIdle+0xf
...
gdb:p01.01>
```

Attaching halts the VM. `ntoseye` finds the kernel in guest memory, loads its symbols from Microsoft's symbol server (cached under `~/.ntoseye/symbols` after the first time), and prints a *stop header*: the vCPU (`p01.01`), what it was running, and where. Below the header come the registers, a few instructions of disassembly, and the top of the stack.

This VM runs virtualization-based security, so its idle vCPU stopped inside the Windows hypervisor (`hvix64`), and the header's last line says where Windows itself left off. On a VM without VBS the first stop is in Windows directly. [VBS and the Windows hypervisor](../platforms/vbs.md) covers what these stops mean.

The prompt names the backend and the selected vCPU.

## Look around

{command}`vertarget` describes the target:

```text
gdb:p01.01> vertarget
target version
  target Windows 10.0 build 26200 (26100.ge_release.240331-1435)
  arch AMD64
  kernel fffff80797200000 size 0x1450000
  processors 4
  uptime 0d 05:27:42
  backend gdb
  ...
```

{command}`lm` lists loaded kernel modules and whether their symbols loaded:

```text
gdb:p01.01> lm
Start             End               Module     Version          Symbols  Source  Image
fffff80797200000  fffff80798650000  nt         -                loaded   cached  ntoskrnl.exe
fffff80798660000  fffff80798666000  hal        -                loaded   cached  hal.dll
fffff80728e30000  fffff8072933d000  dxgkrnl    10.0.26100.9444  loaded   cached  dxgkrnl.sys
...
```

{command}`ps` lists processes with the address of each `_EPROCESS` and its page-table root:

```text
gdb:p01.01> ps
Name            PID   EPROCESS          DTB               Wow64
System          4     ffffe70faa6df040  00000000001ae000  -
Secure System   132   ffffe70faa7a1040  0000000118d7e000  -
smss.exe        544   ffffe70fb19a4280  0000000268526000  -
lsass.exe       960   ffffe70fb2d51080  0000000114917000  -
...
```

Symbols are searched with {command}`x`; `*` and `?` are wildcards:

```text
gdb:p01.01> x nt!NtCreateFi*
fffff80797ac7930  nt!NtCreateFile
```

## Stop on a kernel function

Set a breakpoint with {command}`bp` and resume with {command}`g`. `NtCreateFile` runs whenever any process opens a file, so it hits almost at once:

```text
gdb:p01.01> bp nt!NtCreateFile
breakpoint #0 set at fffff80797ac7930 (nt!NtCreateFile) (global)

gdb:p01.01> g
VM running, waiting for stop (Ctrl+C to pause)...

 BREAK  p01.02 LogonUI.exe (1204) at nt!NtCreateFile
 ├─ breakpoint #0
 ╰─ thread LogonUI.exe  state Running  ethread ffffe70fb4c8b080  pid 1204  tid 3804
...
```

The header now names the process and thread that called into the kernel. Ctrl+C breaks in at any time while the VM runs.

{command}`kn` shows the stack. It crosses from the kernel into the calling process's user-mode code, and resolves that too:

```text
gdb:p01.02> k 6
 00 fffffd86b64aeda8  fffff80797ac7930  nt!NtCreateFile
 01 fffffd86b64aedb0  fffff807978c1d55  nt!KiSystemServiceCopyEnd+0x25
 02 0000009112efd5a8  00007ff855661864  ntdll!NtCreateFile+0x14
 03 0000009112efd5b0  00007ff852e36217  kernelbase!CreateFileInternal+0x373
 04 0000009112efd730  00007ff852e37887  kernelbase!CreateFileW+0x97
 05 0000009112efd790  00007ff852e395f6  kernelbase!BasepLoadLibraryAsDataFileInternal+0x206
```

A module seen for the first time shows `module+offset` for a moment while its symbols download in the background; {command}`lm` shows it as `fetching` meanwhile.

## Read the arguments

`NtCreateFile`'s third argument, in `r8` on x64, is an `OBJECT_ATTRIBUTES` whose `ObjectName` is the path being opened. Expressions understand types from the PDB, so a cast reads it directly, and {command}`dS` prints a `UNICODE_STRING`:

```text
gdb:p01.02> dS ((nt!_OBJECT_ATTRIBUTES*)@r8)->ObjectName
0000009112efd668  Length=66 MaximumLength=68 Buffer=000002702036ac90  "\\??\\C:\\WINDOWS\\SYSTEM32\\tzres.dll"
```

{command}`dt` displays a structure, optionally only the named fields. `$proc` is the current process's `_EPROCESS`:

```text
gdb:p01.01> dt nt!_EPROCESS @$proc UniqueProcessId ImageFileName
_EPROCESS (2112 bytes) @ ffffe70fb6199080
  +0x1d0 UniqueProcessId : void* = 0x1710
  +0x338 ImageFileName : UCHAR[15] = "svchost.exe"
```

[Expressions](../reference/expressions.md) covers registers, pseudo-registers, casts, and members.

## Step

{command}`p` steps over one instruction, and {command}`gu` runs until the current function returns. Each stop prints a header again:

```text
gdb:p01.01> p
 BREAK  p01.01 svchost.exe (5904) at nt!NtCreateFile+0x7
...
gdb:p01.01> gu
VM running, waiting for stop (Ctrl+C to pause)...

 BREAK  p01.01 svchost.exe (5904) at nt!KiSystemServiceCopyEnd+0x25
...
```

## Clean up and leave

```text
gdb:p01.01> bc *
breakpoint #0 cleared

gdb:p01.01> q
```

{command}`bc` clears breakpoints; {command}`q` detaches and lets the VM run on.

## Where to go next

- {command}`.hh` lists every command, and `.hh <command>` explains one; the same text is the [command reference](../reference/commands/index.md). Tab completes commands, symbols, and types.
- [Coming from WinDbg](windbg.md) lists what carries over and what differs.
- [Breakpoints](../using/breakpoints.md) covers conditions, scoping to one process or thread, and commands that run on a hit.
- [Python SDK](../scripting/sdk.md) does all of the above from a script.
