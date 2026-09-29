# Your first session

This tutorial walks through one full session with a Windows 11 VM, in which you:

1. Attach to the VM.
2. Look at the target.
3. Stop on a kernel function.
4. Read the arguments of the function.
5. Step through the code.
6. Leave the session.

The session uses the `kdnet` backend, which is the Windows kernel debugger over the network, as WinDbg uses it. To set it up, see the [KDNET guide](../setup/kdnet.md). The commands are the same with the `kd` and `gdb` backends, and only the location of the first stop is different.

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

When `ntoseye` attaches, it halts the VM, finds the kernel, and loads the kernel symbols from the Microsoft symbol server. After the first time, it keeps the symbols in a cache under `~/.ntoseye/symbols`.

It then shows a *stop header* with the processor (`p1.2`), what the processor was running, and where. Below the header come the registers, a few instructions of disassembly, and the top of the stack. The breakpoint [below](#stop-on-a-kernel-function) shows a full stop.

The first stop is the Windows response to the break-in. The Windows debugger code stops in `nt!DbgBreakPointWithStatus`, here on a `System` thread that received KDNET packets. The `gdb` backend halts the vCPUs from outside the VM instead, so each vCPU stops wherever it was at that time.

The prompt shows the backend and the selected processor.

## Look around

{command}`vertarget` shows information about the target:

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

{command}`lm` lists the loaded kernel modules and shows whether the symbols of each one loaded. `kdcom` and `kdstub` are the KDNET transport that this session communicates with:

```text
kdnet:p1.2> lm
Start             End               Module                 Version          Symbols  Source  Image
fffff80797200000  fffff80798650000  nt                     -                loaded   cached  ntoskrnl.exe
fffff80798660000  fffff80798666000  hal                    -                loaded   cached  hal.dll
fffff80728730000  fffff80728779000  kdcom                  -                loaded   cached  kdcom.dll
fffff807286c0000  fffff80728726000  kdstub                 -                loaded   cached  kdstub.dll
...
```

{command}`ps` lists the processes with the address of each `_EPROCESS` and its page-table root:

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

To find symbols, use {command}`x`, with `*` and `?` as wildcards:

```text
kdnet:p1.2> x nt!NtCreateFi*
fffff80797ac7930  nt!NtCreateFile

1 symbol (in $0..$0)
```

## Stop on a kernel function

To set a breakpoint, use {command}`bp`, and to resume the VM, use {command}`g`. Because `NtCreateFile` runs each time a process opens a file, the breakpoint hits almost immediately:

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

{command}`k` shows the full stack with the stack pointer of each frame. The stack goes from the kernel into the user-mode code of the calling process, and {command}`k` resolves the user-mode frames too:

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

When `ntoseye` sees a module for the first time, it downloads the module symbols in the background. Until the download completes, frames in that module show as `module+offset` for a short time, and {command}`lm` shows the module as `fetching`.

## Read the arguments

On x64, the third argument of `NtCreateFile` is in `r8`. It is an `OBJECT_ATTRIBUTES` structure whose `ObjectName` field is the path of the file that the process opens. Because expressions use types from the PDB, a cast reads the path directly, and {command}`dS` shows the `UNICODE_STRING`:

```text
kdnet:p1.1> dS ((nt!_OBJECT_ATTRIBUTES*)@r8)->ObjectName
000000ef8a37eea8  Length=36 MaximumLength=38 Buffer=000002276cb50ac0  "\\??\\PhysicalDrive0"
```

{command}`dt` shows a structure, or only the fields that you name. `$proc` is the `_EPROCESS` of the current process:

```text
kdnet:p1.1> dt nt!_EPROCESS @$proc UniqueProcessId ImageFileName
_EPROCESS (2112 bytes) @ ffffe70fb2ed3080
  +0x1d0 UniqueProcessId : void* = 0x1d4
  +0x338 ImageFileName : UCHAR[15] = "svchost.exe"
```

For more information about registers, pseudo-registers, casts, and members, see [Expressions](../reference/expressions.md).

## Step

{command}`p` steps over one instruction, and {command}`gu` runs until the current function returns. At each stop, `ntoseye` shows a stop header again:

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

{command}`bc` clears breakpoints, and {command}`q` detaches from the VM and lets it continue to run.

## Where to go next

- {command}`.hh` lists all commands, and `.hh <command>` explains one. The [command reference](../reference/commands/index.md) has the same text. Press Tab to complete commands, symbols, and types.
- [Coming from WinDbg](windbg.md) lists what matches WinDbg and what is different.
- [Breakpoints](../using/breakpoints.md) explains conditions, breakpoints limited to one process or thread, and commands that run when a breakpoint hits.
- [Python SDK](../scripting/sdk.md) shows how to do all of these tasks from a script.
