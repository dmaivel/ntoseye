# Bugchecks

When Windows crashes, it stops with a *bugcheck*. This is the blue screen. A bugcheck has a code and four arguments that tell what went wrong. If a debugger is attached, the crash stops in the debugger first. At that time, all the data is still in memory.

This page shows one crash as an example. The crash is the high-IRQL fault of Sysinternals NotMyFault. The command for this crash is `notmyfaultc64 -accepteula crash 0x01`. The target is a Windows 11 VM, and the backend is `kdnet`.

## How the crash is caught

| Backend | Bugcheck stop |
|---|---|
| `kd`, `kdnet` | Windows reports it after it fills in the bugcheck data |
| `gdb` | A breakpoint on `nt!KeBugCheckEx`, which `ntoseye` sets at attach |
| `memory` | Not detected |
| crash dump | The dump is stopped at its bugcheck |

With KD, the crash comes to `ntoseye` as a separate stop.

The `gdb` backend cannot get a notification of the crash. So it sets a breakpoint at the first instruction of `nt!KeBugCheckEx`. When it attaches, it shows the message `armed a bugcheck trap at nt!KeBugCheckEx`. It reads the bugcheck code and arguments from the call to `nt!KeBugCheckEx`.

If a session ends without cleanup, this breakpoint can stay in the guest. At the next bugcheck, the breakpoint would crash Windows a second time. The next attach, over any backend, puts back the original instruction and reports it.

[Choosing a backend](../setup/backends.md) compares the backends.

## The bugcheck stop

Resume the target, then crash it:

```text
kdnet:p1.2> g
VM running, waiting for stop (Ctrl+C to pause)...
KDTARGET: Refreshing KD connection

*** Fatal System Error: 0x000000d1
                       (0xFFFFCE06DC2DD010,0x0000000000000002,0x0000000000000000,0xFFFFF808BB461730)


 BUGCHECK  DRIVER_IRQL_NOT_LESS_OR_EQUAL (0x000000d1)
 ├─ module myfault.sys
 ├─ fault  fffff808bb461730  myfault+0x1730
 ├─ reason An attempt was made to access a pageable (or completely invalid) address at an interrupt request level (IRQL) that is too high. This is usually caused by drivers using improper addresses. If kernel debugger is available get stack backtrace.
 ╰─ args
    ├─ #1 ffffce06dc2dd010  memory referenced
    ├─ #2 0000000000000002  IRQL
    ├─ #3 0000000000000000  value 0 = read operation, 1 = write operation, 2 or 8 = execute operation
    ╰─ #4 fffff808bb461730  address which referenced memory

 BREAK  p1.4 notmyfaultc64. (2012) at myfault+0x1730
 ├─ stopped at nt!DbgBreakPointWithStatus
 ╰─ thread notmyfaultc64.  state Running  ethread ffffbe0ab9e42080  pid 2012  tid 2644
...
disasm
 > fffff808bb461730  8b 03                 mov  eax, dword [rbx]
   fffff808bb461732  48 8d 9b 00 10 00 00  lea  rbx, [rbx+0x1000]
   fffff808bb461739  89 44 24 30           mov  dword [rsp+0x30], eax
   fffff808bb46173d  eb f1                 jmp  0xFFFFF808BB461730
   fffff808bb46173f  cc                    int3
   fffff808bb461740  40 53                 push rbx
   fffff808bb461742  56                    push rsi
...
kdnet:p1.4>
```

Windows writes the first lines, and the debugger prints them. The `BUGCHECK` block is the `ntoseye` interpretation of these lines. It shows:

- the name and the code of the bugcheck
- the module and the address where the fault occurred
- the meaning of the code
- each argument, with a label

In this example, a driver, `myfault.sys`, read memory that it must not access at IRQL 2.

The `BREAK` header shows the processor and the thread. It shows the stop at the fault, `myfault+0x1730`. But Windows is actually stopped in `nt!DbgBreakPointWithStatus`. In this function, Windows gives control to the debugger.

The disassembly starts at the fault. The code is a loop that reads a dword and then moves forward by one page. The registers and the stack are those of the processor at the time it stopped.

## Analyze it

{command}`!analyze` gives the result of the analysis. It shows:

- the bugcheck
- a failure signature, which you can use to compare crashes
- the culprit module, with a confidence level


```text
kdnet:p1.4> !analyze
crash analysis

bugcheck 0x000000d1 DRIVER_IRQL_NOT_LESS_OR_EQUAL  driver myfault.sys

failure signature
  bugcheck:000000d1|module:myfault
  source: bugcheck fault

culprit attribution
  myfault.sys  medium confidence
  BugcheckFaultAddress fffff808bb461730  bugcheck fault address resolves to myfault.sys

loaded modules
  ntoskrnl.exe             fffff803e9a00000-fffff803eae50000  0x1450000 bytes
  myfault.sys              fffff808bb460000-fffff808bb46b000  0xb000 bytes
  174 loaded modules total
```

`!analyze -v` adds more data:

- the bugcheck block
- the full stack
- all loaded modules
- the trap frame that Windows made when the driver faulted

In this example, `nt!KiPageFault` made the trap frame. `!analyze -v` prints the registers that the fault saved. The frame of a page fault does not hold `rbx`, `rsi`, or `rdi`, so these registers show `-`. The faulting context in the output shows `myfault+0x1730` and the address of the trap frame.

To select the trap frame, give its address to {command}`.trap`. Then {command}`k` and the register commands start at the fault. Otherwise they start at `nt!DbgBreakPointWithStatus`.

{command}`k` shows how the driver got to the fault. Read the stack from the bottom up:

1. NotMyFault asked its driver for the crash with `DeviceIoControl`.
2. The driver faulted at `myfault+0x1730`.
3. The page fault handler raised the bugcheck.


```text
kdnet:p1.4> k
 00 fffffb84648d08b8  fffff803e9efdfb0  nt!DbgBreakPointWithStatus
 01 fffffb84648d08c0  fffff803e9fb3622  nt!KiBugCheckDebugBreak+0x12
 02 fffffb84648d0920  fffff803e9fb2b4e  nt!KeBugCheck2+0xb2e
 03 fffffb84648d10b0  fffff803e9efd237  nt!KeBugCheckEx+0x107
 04 fffffb84648d10f0  fffff803ea0c26e9  nt!KiBugCheckDispatch+0x69
 05 fffffb84648d1230  fffff803ea0bd9a8  nt!KiPageFault+0x468
 06 fffffb84648d13c0  fffff808bb461730  myfault+0x1730
 07 fffffb84648d13f0  fffff808bb461bd2  myfault+0x1bd2
 08 fffffb84648d1560  fffff808bb461d54  myfault+0x1d54
 09 fffffb84648d15c0  fffff803e9cb3221  nt!IopfCallDriver+0x6d
 10 fffffb84648d1600  fffff803ea5b5d84  nt!IovCallDriver+0x44
 11 fffffb84648d1640  fffff803e9cb227d  nt!IofCallDriver+0xad
 12 fffffb84648d1680  fffff803e9cb1fc6  nt!IopCallDriverReference+0xe6
 13 fffffb84648d1700  fffff803ea2eb3eb  nt!IopSynchronousServiceTail+0x30b
 14 fffffb84648d1790  fffff803ea2ea0ec  nt!IopXxxControlFile+0x99c
 15 fffffb84648d1a00  fffff803ea2e973e  nt!NtDeviceIoControlFile+0x5e
 16 fffffb84648d1a70  fffff803ea0c1d55  nt!KiSystemServiceCopyEnd+0x25
 17 000000cd0b18f4b8  00007ff9a7f00ea4  ntdll!NtDeviceIoControlFile+0x14
 18 000000cd0b18f4c0  00007ff9a51d36d3  kernelbase!DeviceIoControl+0x73
 19 000000cd0b18f530  00007ff9a7431ac5  kernel32!DeviceIoControlImplementation+0x75
 20 000000cd0b18f580  00007ff6cf95c0a7  notmyfaultc64+0x1c0a7
 21 000000cd0b18f5c8  00007ff6cf95e5fe  notmyfaultc64+0x1e5fe
 22 000000cd0b18f788  00007ff6cf95ef24  notmyfaultc64+0x1ef24
 23 000000cd0b18f798  00007ff6cf95f0b9  notmyfaultc64+0x1f0b9
 24 000000cd0b18f7c8  00007ff9a743cd87  kernel32!BaseThreadInitThunk+0x17
 25 000000cd0b18f7f8  00007ff9a7e4caec  ntdll!RtlUserThreadStart+0x2c
```

The `myfault` frames show `module+offset`. The reason is that the Microsoft symbol server has no PDB for `myfault`. {command}`lm` shows this:

```text
kdnet:p1.4> lm m myfault
Start             End               Module   Version  Symbols  Source  Image
fffff808bb460000  fffff808bb46b000  myfault  -        failed   -       myfault.sys
```

For your own driver, give `ntoseye` its PDB. Then these frames show names and source lines. [Symbols](symbols.md) tells how to do this.

You can examine the rest of the target as at all other stops:

- Use {command}`!thread` to examine the thread that crashed.
- Use {command}`dt` and the `d*` commands to examine memory.

## Decode a code without a crash

`!analyze -show` decodes a bugcheck code and arguments that you got from a different source. Examples are a photo of a blue screen or an event log entry.


```text
kdnet:p1.1> !analyze -show 0x50
 BUGCHECK  PAGE_FAULT_IN_NONPAGED_AREA (0x00000050)
 ├─ reason Invalid system memory was referenced. This cannot be protected by try-except. Typically the address is just plain bad or it is pointing at freed memory.
 ╰─ args
    ├─ #1 0000000000000000  memory address referenced
    ├─ #2 0000000000000000  access type (0 = read; 1 = write; 2 = execute; some builds report 0x10 for execute)
    ├─ #3 0000000000000000  address that referenced memory, if known
    ╰─ #4 0000000000000000  page-fault subtype on newer Windows; reserved on older versions
```

## After the bugcheck

The crashed system cannot continue to run. But it has not written its crash dump yet. When you enter {command}`g`, these events occur:

1. Windows writes the dump.
2. Windows reboots.
3. `ntoseye` follows the reboot. It stops at the first boot notification of the new kernel.


```text
kdnet:p1.4> g
VM running, waiting for stop (Ctrl+C to pause)...

 BREAK  p1.1 kernel at nt!DebugService2+0x5
 ╰─ guest rebooted; kernel reloaded, module list not available yet (continue to finish)
```

Enter {command}`g` again to let the boot finish.

If the crash settings of the guest allow a dump, the dump is at `C:\Windows\MEMORY.DMP` in the guest. [Crash dumps](dumps.md) tells how to configure the dump, copy it out of the guest, and analyze it offline.

To keep the memory as it was at the stop, write a dump with {command}`.dump` before you continue.

## Forcing a crash

{command}`.crash` crashes the target on purpose with `MANUALLY_INITIATED_CRASH` (0xE2). Use it to test the dump configuration. You can also use it to capture a system that is hung but did not crash.

For a crash inside a driver, as in the example on this page, use [NotMyFault](https://learn.microsoft.com/sysinternals/downloads/notmyfault). Its command-line form is `notmyfaultc64 -accepteula crash 0x01`.

## From scripts

In the [Python SDK](../scripting/sdk.md), a bugcheck comes as a `Stop.Bugcheck`. Its `info` holds the code, the arguments, and the culprit. `dbg.inspect.bugcheck()` returns the same data for the current stop. `dbg.inspect.triage()` returns the full `!analyze` report.

With [MCP](../integrations/mcp.md), `!analyze` with `format: "json"` returns the report as structured data.
