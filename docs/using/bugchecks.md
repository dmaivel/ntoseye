# Bugchecks

When Windows crashes, it stops with a *bugcheck*, the blue screen, and names what went wrong with a code and four arguments. With a debugger attached, the crash stops in the debugger first, while everything is still in memory. This page follows one: Sysinternals NotMyFault's high-IRQL fault (`notmyfaultc64 -accepteula crash 0x01`) in a Windows 11 VM, over the `kdnet` backend. Every output below comes from that session, trimmed only where marked `...`.

## How the crash is caught

| Backend | Bugcheck stop |
|---|---|
| `kd`, `kdnet` | Windows reports it, after filling in the bugcheck data |
| `gdb` | A breakpoint on `nt!KeBugCheckEx`, armed at attach |
| `memory` | Not detected |
| crash dump | The dump is halted at its bugcheck |

Over KD, the crash arrives as a stop of its own. The `gdb` backend has no way to hear about it, so it plants a breakpoint at the first instruction of `nt!KeBugCheckEx` and says so when it attaches (`armed a bugcheck trap at nt!KeBugCheckEx`); it reads the code and arguments from that call. A session that ends without cleaning up can leave that breakpoint in the guest, where it would crash Windows a second time at its next bugcheck; the next attach, over any backend, puts the original instruction back and reports it. [Choosing a backend](../setup/backends.md) compares the backends.

## The bugcheck stop

Resume the target, and crash it:

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

The first lines are Windows' own, printed through the debugger. The `BUGCHECK` block is `ntoseye`'s reading of them: the bugcheck's name and code, the module and address where the fault happened, what the code means, and each argument labeled. Here a driver, `myfault.sys`, read memory it may not touch at IRQL 2.

The `BREAK` header names the processor and thread, and places the stop at the fault, `myfault+0x1730`, though Windows is actually halted in `nt!DbgBreakPointWithStatus`, where it hands control to the debugger. The disassembly is at the fault: a loop that reads a dword and steps a page at a time. The registers and stack are those of the processor as it stopped.

## Analyze it

{command}`!analyze` gives the verdict: the bugcheck, a failure signature to compare crashes by, and the module to blame, with how sure that is:

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

`!analyze -v` adds the bugcheck block, the whole stack, and every loaded module, and finds the trap frame Windows built when the driver faulted, here by `nt!KiPageFault`: it prints the registers the fault saved (a page fault's frame holds no `rbx`, `rsi`, or `rdi`, which read `-`), and its faulting context names `myfault+0x1730` and the trap frame's address. {command}`.trap` with that address selects it, so {command}`k` and the register commands start at the fault instead of at `nt!DbgBreakPointWithStatus`.

{command}`k` shows how the driver got there. Reading up from the bottom: NotMyFault asked its driver for the crash with `DeviceIoControl`, the driver faulted at `myfault+0x1730`, and the page fault handler raised the bugcheck:

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

`myfault` frames read `module+offset` because Microsoft's symbol server has no PDB for it, which {command}`lm` shows:

```text
kdnet:p1.4> lm m myfault
Start             End               Module   Version  Symbols  Source  Image
fffff808bb460000  fffff808bb46b000  myfault  -        failed   -       myfault.sys
```

For your own driver, point `ntoseye` at its PDB ([Symbols](symbols.md)) and these frames get names and source lines. The rest of the target is there to inspect as at any stop: {command}`!thread` for the crashing thread, {command}`dt` and the `d*` commands for memory.

## Decode a code without a crash

`!analyze -show` decodes a bugcheck code and arguments you have from elsewhere, such as a blue screen photo or an event log entry:

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

The crashed system cannot run on, but it has not written its crash dump yet. {command}`g` lets it: Windows writes the dump and reboots, and `ntoseye` follows the reboot, stopping at the new kernel's first boot notification:

```text
kdnet:p1.4> g
VM running, waiting for stop (Ctrl+C to pause)...

 BREAK  p1.1 kernel at nt!DebugService2+0x5
 ╰─ guest rebooted; kernel reloaded, module list not available yet (continue to finish)
```

{command}`g` again lets the boot finish. The dump is at `C:\Windows\MEMORY.DMP` in the guest if its crash settings allow one; [Crash dumps](dumps.md) covers configuring that, copying it out, and analyzing it offline. To keep memory exactly as it was at the stop instead, write a dump yourself before continuing with {command}`.dump`.

## Forcing a crash

{command}`.crash` crashes the target on purpose with `MANUALLY_INITIATED_CRASH` (0xE2), for testing the dump setup or capturing a system that is hung but not crashed. For a crash inside a driver, as above, use [NotMyFault](https://learn.microsoft.com/sysinternals/downloads/notmyfault); `notmyfaultc64 -accepteula crash 0x01` is its command-line form.

## From scripts

In the [Python SDK](../scripting/sdk.md), a bugcheck arrives as a `Stop.Bugcheck`, whose `info` holds the code, arguments, and culprit; `dbg.inspect.bugcheck()` returns the same for the current stop, and `dbg.inspect.triage()` the whole `!analyze` report. Over [MCP](../integrations/mcp.md), `!analyze` with `format: "json"` returns the report as structured data.
