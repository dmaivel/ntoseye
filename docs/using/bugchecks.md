# Bugchecks

When Windows crashes, it stops with a *bugcheck*, the blue screen. A bugcheck has a code and four arguments that tell what went wrong. If a debugger is attached, the crash stops in the debugger first, while all the data is still in memory.

This page follows one example crash, the high-IRQL fault of Sysinternals NotMyFault (`notmyfaultc64 -accepteula crash 0x01`), on a Windows 11 VM with the `kdnet` backend.

## How the crash is caught

| Backend | Bugcheck stop |
|---|---|
| `kd`, `kdnet` | Windows reports it after it fills in the bugcheck data |
| `gdb` | A breakpoint on `nt!KeBugCheckEx`, which `ntoseye` sets at attach |
| `memory` | Not detected |
| crash dump | The dump is stopped at its bugcheck |

With KD, the crash comes to `ntoseye` as a separate stop.

The `gdb` backend cannot get a notification of the crash, so when it attaches, it sets a breakpoint at the first instruction of `nt!KeBugCheckEx` and shows the message `armed a bugcheck trap at nt!KeBugCheckEx`. At a bugcheck, it reads the bugcheck code and arguments from the call to `nt!KeBugCheckEx`.

If a session ends without cleanup, this breakpoint can stay in the guest, where it would crash Windows a second time at the next bugcheck. The next attach, over any backend, puts back the original instruction and reports it.

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
 └─ args
    ├─ #1 ffffce06dc2dd010  memory referenced
    ├─ #2 0000000000000002  IRQL
    ├─ #3 0000000000000000  value 0 = read operation, 1 = write operation, 2 or 8 = execute operation
    └─ #4 fffff808bb461730  address which referenced memory

 BREAK  p1.4 notmyfaultc64. (2012) at myfault+0x1730
 ├─ stopped at nt!DbgBreakPointWithStatus
 └─ thread notmyfaultc64.  state Running  ethread ffffbe0ab9e42080  pid 2012  tid 2644
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

Windows writes the first lines, and the debugger prints them. The `BUGCHECK` block is the `ntoseye` interpretation of these lines, and shows:

- the name and the code of the bugcheck
- the module and the address where the fault occurred
- the meaning of the code
- each argument, with a label

In this example, a driver, `myfault.sys`, read memory that it must not access at IRQL 2.

The `BREAK` header shows the processor and the thread, and puts the stop at the fault, `myfault+0x1730`. Windows is actually stopped in `nt!DbgBreakPointWithStatus`, where it gives control to the debugger.

The disassembly starts at the fault, in a loop that reads a dword and then moves forward by one page. The registers and the stack are those of the processor at the time it stopped.

## Analyze it

{command}`!analyze` shows the bugcheck, a failure signature that you can use to compare crashes, and the culprit module with a confidence level.

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

In this example, `nt!KiPageFault` made the trap frame, and `!analyze -v` prints the registers that the fault saved. The frame of a page fault does not hold `rbx`, `rsi`, or `rdi`, so these registers show `-`. The faulting context in the output shows `myfault+0x1730` and the address of the trap frame.

To select the trap frame, give its address to {command}`.trap`. {command}`k` and the register commands then start at the fault instead of at `nt!DbgBreakPointWithStatus`.

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

The `myfault` frames show `module+offset` because the Microsoft symbol server has no PDB for `myfault`, as {command}`lm` shows:

```text
kdnet:p1.4> lm m myfault
Start             End               Module   Version  Symbols  Source  Image
fffff808bb460000  fffff808bb46b000  myfault  -        failed   -       myfault.sys
```

For your own driver, give `ntoseye` its PDB so that these frames show names and source lines. [Symbols](symbols.md) tells how to do this.

You can examine the rest of the target as at any other stop, for example the thread that crashed with {command}`!thread`, and memory with {command}`dt` and the `d*` commands.

## Power hangs

When a driver does not finish a power request, Windows bugchecks with DRIVER_POWER_STATE_FAILURE (0x9F). Parameter 1 says what went wrong. In the most common case, subtype 0x3, the power manager armed a watchdog when it sent a power IRP to a device, and the watchdog expired before the IRP completed. Parameter 2 is then the PDO of the device's stack, parameter 3 a `TRIAGE_9F_POWER` block that names the kernel's power IRP and worker thread lists, and parameter 4 the IRP.

For a 0x9F, {command}`!analyze` adds a `power failure` section that names what is stuck:

- For 0x3: the blocked IRP, the request in its current stack location, the driver whose stack location it is pending in, how long ago the watchdog was armed, the device stack of the PDO with that driver's device marked, every power IRP the power manager has allocated, and the power IRP worker threads with their stacks. The IRP and thread lists are the ones that `TRIAGE_9F_POWER` names, `nt!PopIrpList` and `nt!PopIrpThreadList`. The driver that holds the IRP becomes the culprit with high confidence, and the failure signature is `bugcheck:0000009f|subtype:3|module:<driver>`.
- For 0x4, a power transition that timed out waiting for PnP: the thread that holds the PnP lock, and its stack. The first driver on that stack becomes the culprit, with medium confidence.
- For 0x1, 0x2, and 0x500: the driver of the device object or driver object in the parameters, which becomes the culprit, and the device's stack.

The IRP's current stack location belongs to the lowest driver the IRP has reached. If that driver returned `STATUS_PENDING`, as `(returned STATUS_PENDING)` shows, it took the request and has not completed it. Look at what it waits for: {command}`!irp` shows the whole IRP, {command}`!devstack` the stack, and {command}`!stacks` or {command}`!thread` the driver's threads.

`!analyze -show 9f` reads what the parameters point to in the target, so you can try it on any power IRP that {command}`!poaction` lists. This guest has no bugcheck; the IRP is a wait/wake request that USBHUB3 holds, as a bus driver does until its device signals a wake. Parameter 3 is not a `TRIAGE_9F_POWER` block here, so `ntoseye` walks the kernel's lists, and says so:

```text
mem:1> !analyze -show 9f 3 ffffb28a86bae780 0 ffffb28a8c5cd010
...
power failure
  subtype 0x3: a device blocked a power IRP for too long
  driver      \Driver\USBHUB3 (UsbHub3.sys) holds the blocked power IRP 0xffffb28a8c5cd010 in stack location 11 of 14
  blocked IRP ffffb28a8c5cd010  (!irp)
  request     IRP_MJ_POWER IRP_MN_WAIT_WAKE Working
  pending in  \Driver\USBHUB3 (UsbHub3.sys)  device ffffb28a86bae780  stack location 11 of 14  (returned STATUS_PENDING)
  pending for watchdog Disabled  POP_IRP_DATA ffffb28a8a2ae010
  device      ffffb28a86bae780  (!devstack, !podev)
     ffffb28a86e51060  \Driver\HidUsb       _HID00000000
   > ffffb28a86bae780  \Driver\USBHUB3      USBPDO-1
  > holds the blocked IRP
  Allocated power IRPs (nt!PopIrpList fffff802bd60bcb0)
  ...
  IRP worker threads (nt!PopIrpThreadList fffff802bd6087b0)
    THREAD ffffb28a7f721040 (static)  waiting for work
    THREAD ffffb28a7f6f9040 (static)  waiting for work
  thread ffffb28a7f721040  IRP worker, waiting for work
#0  fffffc01d5414800  fffff802bcdb64d6  nt!KiSwapContext+0x76
...
  parameter 3 (0x0) is not a readable TRIAGE_9F_POWER: Bad virtual address: 0; walked nt!PopIrpList and nt!PopIrpThreadList
```

A wait/wake IRP stays pending by design, and its watchdog does not run. A set-power or query-power IRP that has been pending in a driver for many seconds is the hang.

### Power state without a crash

To look at a power transition that is slow or stuck before the watchdog fires, use these commands at any stop, or with the `memory` backend while the guest runs:

- {command}`!poaction` shows the system power action in progress (`nt!PopAction`): the action, its state and flags, the system state being entered, and the device notification pass when one runs. Then it lists every power IRP the power manager has allocated, from `nt!PopIrpList`: the PDO, the device it was sent to, the minor function and the requested state, the driver it is pending in, and how long ago its watchdog was armed. Last, it lists the power IRP worker threads from `nt!PopIrpThreadList`, with the IRP and device each one is passing on.
- {command}`!podev` shows the power state of one device object: the system and device states that its driver last set with `PoSetPowerState`, the idle detection it registered, the device state that PnP records for the stack, whether the driver registered with the power framework, and the power IRPs sent to the device's stack.
- {command}`!popolicy` shows the system power policy in effect (`SYSTEM_POWER_POLICY` at `nt!PopPolicy`): the actions for the buttons, the lid, idling, and overheating, the sleep states, and the timeouts.

```text
mem:1> !podev ffffb28a86bae780
Device object ffffb28a86bae780 is for:
  \Driver\USBHUB3 (UsbHub3.sys)
  Flags 00003044 DO_POWER_PAGABLE
DevObjExtension: ffffb28a86bae8f8
PowerFlags: 00000030 => SystemState=Unspecified DeviceState=D2
Idle detection: not registered
DevNode ffffb28a86e31bb0 "USB\VID_0627&PID_0001\28754-0000:00:02.1:00.0-1"
  CurrentPowerState: D2
  Power framework: ffffb28a86e54560
Power IRPs for the stack (nt!PopIrpList):
  IRP ffffb28a8c5cd010  IRP_MN_WAIT_WAKE Working  PDO ffffb28a86bae780
    sent to    ffffb28a86e51060
    pending in \Driver\USBHUB3 (UsbHub3.sys)  device ffffb28a86bae780  stack location 11 of 14  (returned STATUS_PENDING)
    watchdog   Disabled  POP_IRP_DATA ffffb28a8a2ae010
```

This USB tablet is selectively suspended in D2, as Device Manager's power data for it also shows.

## Decode a code without a crash

`!analyze -show` decodes a bugcheck code and arguments that you got from a different source, such as a photo of a blue screen or an event log entry.

```text
kdnet:p1.1> !analyze -show 0x50
 BUGCHECK  PAGE_FAULT_IN_NONPAGED_AREA (0x00000050)
 ├─ reason Invalid system memory was referenced. This cannot be protected by try-except. Typically the address is just plain bad or it is pointing at freed memory.
 └─ args
    ├─ #1 0000000000000000  memory address referenced
    ├─ #2 0000000000000000  access type (0 = read; 1 = write; 2 = execute; some builds report 0x10 for execute)
    ├─ #3 0000000000000000  address that referenced memory, if known
    └─ #4 0000000000000000  page-fault subtype on newer Windows; reserved on older versions
```

## After the bugcheck

The crashed system cannot continue to run, but it has not written its crash dump yet. When you enter {command}`g`, Windows writes the dump and reboots, and `ntoseye` follows the reboot and stops at the first boot notification of the new kernel.

```text
kdnet:p1.4> g
VM running, waiting for stop (Ctrl+C to pause)...

 BREAK  p1.1 kernel at nt!DebugService2+0x5
 └─ guest rebooted; kernel reloaded, module list not available yet (continue to finish)
```

Enter {command}`g` again to let the boot finish.

If the crash settings of the guest allow a dump, the dump is at `C:\Windows\MEMORY.DMP` in the guest. [Crash dumps](dumps.md) tells how to configure the dump, copy it out of the guest, and analyze it offline.

To keep the memory as it was at the stop, write a dump with {command}`.dump` before you continue.

## Forcing a crash

{command}`.crash` crashes the target on purpose with `MANUALLY_INITIATED_CRASH` (0xE2). Use it to test the dump configuration, or to capture a system that is hung but did not crash.

For a crash inside a driver, as in the example on this page, use [NotMyFault](https://learn.microsoft.com/sysinternals/downloads/notmyfault) with the command line `notmyfaultc64 -accepteula crash 0x01`.

## From scripts

In the [Python SDK](../scripting/sdk.md), a bugcheck comes as a `Stop.Bugcheck`, whose `bugcheck` holds the code, the parameters, and the driver when the transport decoded them. `dbg.inspect.bugcheck()` returns the analysis of the current bugcheck, with its name, description, arguments, and fault site, and `dbg.inspect.triage()` returns the full `!analyze` report, with a 0x9F's findings in `power`. `dbg.inspect.power_action()` and `dbg.inspect.device_power(address)`, which takes a device object's address or its `Device` handle, return what {command}`!poaction` and {command}`!podev` show.
