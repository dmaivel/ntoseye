# Your first session

This walks through one session against a Windows 11 VM: attach, look around, stop on a kernel function, read its arguments, step, and leave.

The session uses the `kdnet` backend, Windows' own kernel debugging over the network, as WinDbg uses it; the [KDNET guide](../setup/kdnet.md) sets it up. The commands are the same over `kd` and `gdb`; what differs is where the first stop lands.

## Attach

```text
$ ntoseye --backend kdnet --kdnet-key 1.2.3.4
kdnet: listening on 0.0.0.0:50000
kdnet: listener ready; waiting for Windows KDNET target (timeout 8s)
kdnet: memory source host (validated VM-process memory)
...
target
  kernel Windows 26200
  base   fffff80797200000
  psmods ffffe70faa662830

 BREAK  p1.2 kernel at nt!DbgBreakPointWithStatus
 ╰─ thread System  state Running  ethread ffffe70fb1986040  pid 4  tid 588
...
kdnet:p1.2>
```

Attaching halts the VM. `ntoseye` finds the kernel, loads its symbols from Microsoft's symbol server (cached under `~/.ntoseye/symbols` after the first time), and prints a *stop header*: the processor (`p1.2`), what it was running, and where. Below the header come the registers, a few instructions of disassembly, and the top of the stack; the breakpoint [below](#stop-on-a-kernel-function) shows a whole stop.

The first stop is Windows answering the break-in: its debugger code stops in `nt!DbgBreakPointWithStatus`, here on a `System` thread that was receiving KDNET's packets. With the `gdb` backend, which halts the vCPUs from outside, the first stop is wherever each one happened to be.

The prompt names the backend and the selected processor.

## Look around

{command}`vertarget` describes the target:

```text
kdnet:p1.2> vertarget
target version
  target Windows 10.0 build 26200 (26100.ge_release.240331-1435)
  arch AMD64
  kernel fffff80797200000 size 0x1450000
  pdb ntoskrnl.pdb GUID C29EBFB06B78B3C020DCA66D99713F9E age 6
  processors 4
  product Workstation
  uptime 0d 08:51:37
  backend kdnet
  ...
```

{command}`lm` lists loaded kernel modules and whether their symbols loaded. `kdcom` and `kdstub` are the KDNET transport this session talks to:

```text
kdnet:p1.2> lm
Start             End               Module                 Version          Symbols  Source  Image
fffff80797200000  fffff80798650000  nt                     -                loaded   cached  ntoskrnl.exe
fffff80798660000  fffff80798666000  hal                    -                loaded   cached  hal.dll
fffff80728730000  fffff80728779000  kdcom                  -                loaded   cached  kdcom.dll
fffff807286c0000  fffff80728726000  kdstub                 -                loaded   cached  kdstub.dll
...
```

{command}`ps` lists processes with the address of each `_EPROCESS` and its page-table root:

```text
kdnet:p1.2> ps
Name            PID   EPROCESS          DTB               Wow64
System          4     ffffe70faa6df040  00000000001ae000  -
...
smss.exe        544   ffffe70fb19a4280  0000000268526000  -
csrss.exe       704   ffffe70fb2b5c140  0000000271bd6000  -
wininit.exe     780   ffffe70fb2d46080  000000026c398000  -
csrss.exe       788   ffffe70fb2d4e140  0000000119154000  -
winlogon.exe    840   ffffe70fb2d8b080  000000026188b000  -
services.exe    932   ffffe70fb2e1b1c0  000000010ec46000  -
...
```

Symbols are searched with {command}`x`; `*` and `?` are wildcards:

```text
kdnet:p1.2> x nt!NtCreateFi*
fffff80797ac7930  nt!NtCreateFile

1 symbol (in $0..$0)
```

## Stop on a kernel function

Set a breakpoint with {command}`bp` and resume with {command}`g`. `NtCreateFile` runs whenever any process opens a file, so it hits almost at once:

```text
kdnet:p1.2> bp nt!NtCreateFile
breakpoint #0 set at fffff80797ac7930 (nt!NtCreateFile) (global)

kdnet:p1.2> g
VM running, waiting for stop (Ctrl+C to pause)...

 BREAK  p1.1 svchost.exe (468) at nt!NtCreateFile
 ├─ breakpoint #0
 ╰─ thread svchost.exe  state Running  ethread ffffe70fb280f080  pid 468  tid 4076

registers
  rax fffff80797ac7930   rbx ffffe70fb280f080   rcx 000000ef8a37ee60
  rdx 0000000000100080   rsi 000000ef8a37ee08   rdi fffffd86b6413a88
  rsp fffffd86b6413a68   rbp fffffd86b6413b60   rip fffff80797ac7930
  r8  000000ef8a37eee8   r9  000000ef8a37ee90   r10 fffff80797ac7930
  r11 fffff807978c1cf8   r12 00007ff8555c7600   r13 0000000000000000
  r14 0000000000000000   r15 0000000000000003   rfl 0000000000040246 [PF ZF IF AC]

disasm
 > fffff80797ac7930  48 81 ec 88 00 00 00     sub  rsp, 0x88
   fffff80797ac7937  33 c0                    xor  eax, eax
   fffff80797ac7939  48 89 44 24 78           mov  qword [rsp+0x78], rax
   fffff80797ac793e  c7 44 24 70 20 00 00 00  mov  dword [rsp+0x70], 0x20
   fffff80797ac7946  89 44 24 68              mov  dword [rsp+0x68], eax
   fffff80797ac794a  48 89 44 24 60           mov  qword [rsp+0x60], rax
   fffff80797ac794f  89 44 24 58              mov  dword [rsp+0x58], eax

stack
  #0  fffff80797ac7930  nt!NtCreateFile
  #1  fffff807978c1d55  nt!KiSystemServiceCopyEnd+0x25
  #2  00007ff855661864  ntdll!NtCreateFile+0x14
  #3  00007ff852e36217  kernelbase!CreateFileInternal+0x373
  #4  00007ff852e37887  kernelbase!CreateFileW+0x97
  #5  00007ff84fbf0c85  psmserviceexthost!CrmStateMonitorSystemDiskUsageTimerCallback+0xa5
  ... 4 more frames
```

{command}`k` walks the whole stack and adds each frame's stack pointer. It crosses from the kernel into the calling process's user-mode code, and resolves that too:

```text
kdnet:p1.1> k
 00 fffffd86b6413a68  fffff80797ac7930  nt!NtCreateFile
 01 fffffd86b6413a70  fffff807978c1d55  nt!KiSystemServiceCopyEnd+0x25
 02 000000ef8a37ede8  00007ff855661864  ntdll!NtCreateFile+0x14
 03 000000ef8a37edf0  00007ff852e36217  kernelbase!CreateFileInternal+0x373
 04 000000ef8a37ef70  00007ff852e37887  kernelbase!CreateFileW+0x97
 05 000000ef8a37efd0  00007ff84fbf0c85  psmserviceexthost!CrmStateMonitorSystemDiskUsageTimerCallback+0xa5
 06 000000ef8a37f310  00007ff8555808ea  ntdll!TppTimerpExecuteCallback+0x2ba
 07 000000ef8a37f410  00007ff85551aaed  ntdll!TppWorkerThread+0x80d
 08 000000ef8a37f770  00007ff853afcd87  kernel32!BaseThreadInitThunk+0x17
 09 000000ef8a37f7a0  00007ff8555acaec  ntdll!RtlUserThreadStart+0x2c
```

A module seen for the first time shows `module+offset` for a moment while its symbols download in the background; {command}`lm` shows it as `fetching` meanwhile.

## Read the arguments

`NtCreateFile`'s third argument, in `r8` on x64, is an `OBJECT_ATTRIBUTES` whose `ObjectName` is the path being opened. Expressions understand types from the PDB, so a cast reads it directly, and {command}`dS` prints a `UNICODE_STRING`:

```text
kdnet:p1.1> dS ((nt!_OBJECT_ATTRIBUTES*)@r8)->ObjectName
000000ef8a37eea8  Length=36 MaximumLength=38 Buffer=000002276cb50ac0  "\\??\\PhysicalDrive0"
```

{command}`dt` displays a structure, optionally only the named fields. `$proc` is the current process's `_EPROCESS`:

```text
kdnet:p1.1> dt nt!_EPROCESS @$proc UniqueProcessId ImageFileName
_EPROCESS (2112 bytes) @ ffffe70fb2ed3080
  +0x1d0 UniqueProcessId : void* = 0x1d4
  +0x338 ImageFileName : UCHAR[15] = "svchost.exe"
```

[Expressions](../reference/expressions.md) covers registers, pseudo-registers, casts, and members.

## Step

{command}`p` steps over one instruction, and {command}`gu` runs until the current function returns. Each stop prints a header again:

```text
kdnet:p1.1> p

 BREAK  p1.1 svchost.exe (468) at nt!NtCreateFile+0x7
...
kdnet:p1.1> gu
VM running, waiting for stop (Ctrl+C to pause)...

 BREAK  p1.1 svchost.exe (468) at nt!KiSystemServiceCopyEnd+0x25
...
```

## Clean up and leave

```text
kdnet:p1.1> bc *
breakpoint #0 cleared

kdnet:p1.1> q
```

{command}`bc` clears breakpoints; {command}`q` detaches and lets the VM run on.

## Where to go next

- {command}`.hh` lists every command, and `.hh <command>` explains one; the same text is the [command reference](../reference/commands/index.md). Tab completes commands, symbols, and types.
- [Coming from WinDbg](windbg.md) lists what carries over and what differs.
- [Breakpoints](../using/breakpoints.md) covers conditions, scoping to one process or thread, and commands that run on a hit.
- [Python SDK](../scripting/sdk.md) does all of the above from a script.
