# Debugging a Windows Sandbox

This walkthrough debugs a Windows Sandbox that runs inside the Windows VM you debug. The Sandbox is a guest partition of the Windows hypervisor, with its own kernel and processes, and `ntoseye` reads it from the host, read-only. You will:

1. Find the Sandbox's partition.
2. Look around inside the Sandbox.
3. Read one of its processes.
4. Stop on a hypercall that the Sandbox makes, and see the Sandbox code that made it.
5. Go back to the target.
6. Do the same from Python.

## Before you start

- The VM must run the Windows hypervisor, so it needs nested virtualization, and the `hv-evmcs` enlightenment, with which `ntoseye` finds the hypervisor's partitions. [KVM/QEMU](../setup/kvm-qemu.md#virtualization-based-security-vbs) shows both settings.
- `ntoseye` attaches with the `gdb` backend ([GDB stub](../setup/kvm-qemu.md#gdb-stub)), because the hypercall breakpoint in step 4 is a hardware breakpoint in the hypervisor.
- In the guest, which must be Windows 11 Pro or Enterprise, turn on Windows Sandbox from an elevated PowerShell prompt and reboot:

  ```text
  Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All
  ```

- Start Windows Sandbox from the Start menu, and in the Sandbox, open a Command Prompt.

The output below is from a Windows 11 26200 guest on an Intel host, in which WSL2 and a Hyper-V VM also run.

## Find the Sandbox

```text
$ ntoseye --backend gdb
...
target
  kernel Windows 26200
  base   fffff805d00c0000
  psmods ffffe602fa470810
...
 BREAK  p01.01 partition 0x5 VP 0 at 0x7fcafb11b256
 └─ thread vmmemWSL  state Running  ethread ffffe602fad19080  pid 8480  tid 2456
...
gdb:p01.01>
```

The `gdb` backend halts the vCPUs wherever they are. Here, `p01.01` was running a VP of partition 0x5 for the `vmmemWSL` process, which is how the root partition runs WSL2, so the vCPU shows WSL2's registers. Under the hypervisor, a vCPU also often halts in the hypervisor itself ([how it shows](hypervisor-stops.md)).

{command}`!hvpartitions` lists the partitions. The privilege lines are left out here:

```text
gdb:p01.01> !hvpartitions
partition 0x1  root  ffffe80000001000
├─ VP 0  VTL0 (+VTL1)  hvcall!Hypercall  last exit VMCALL
├─ VP 1  CPU 1  VTL0 (+VTL1)  nt!HvlpGetRegister64+0x3e  last exit RDMSR
├─ VP 2  CPU 2  VTL0 (+VTL1)  nt!HalProcessorIdle+0xf  last exit HLT
├─ VP 3  CPU 3  VTL0 (+VTL1)  nt!HalProcessorIdle+0xf  last exit HLT
├─ partition 0x5  ffffe80400001000
│  ├─ VP 0  CPU 0  VTL0  00007fcafb11afac  last exit external interrupt
│  ├─ VP 1  VTL0  ffffffffbd1df02f  last exit HLT
│  ├─ VP 2  VTL0  ffffffffbd1df02f  last exit HLT
│  └─ VP 3  VTL0  ffffffffbd1df02f  last exit HLT
├─ partition 0x6  ffffe80300001000
│  ├─ VP 0  VTL0  fffff80272905d67  last exit RDMSR
│  └─ VP 1  VTL0  fffff80272905d67  last exit RDMSR
└─ partition 0x7  ffffe80200001000
   ├─ VP 0  VTL0 (+VTL1)  fffff8058670f8bd  last exit RDMSR
   ├─ VP 1  VTL0 (+VTL1)  fffff8058670f8bd  last exit RDMSR
   ├─ VP 2  VTL0 (+VTL1)  fffff8058670f8bd  last exit RDMSR
   └─ VP 3  VTL0 (+VTL1)  fffff8058670f8bd  last exit RDMSR
```

Partition 0x1 is the target's own Windows. The hypervisor does not name the others, and their IDs change each time a guest starts, so [tell them apart](guest-partitions.md#which-partition-is-which) by what they run: partition 0x5 runs a Linux kernel (`ffffffffbd1df02f`, WSL2), and partitions 0x6 and 0x7 run NT at `fffff80...` addresses. Partition 0x7 is the Sandbox: it has VTL1, because the Sandbox runs with VBS, and after {command}`.partition` `7`, {command}`lmv` `m nt` shows the target's own kernel PDB, because a Sandbox runs the host's Windows image.

## Look around inside the Sandbox

{command}`.partition` shows the Sandbox in place of the target:

```text
gdb:p01.01> .partition 7
inspecting partition 0x7: nt at 0xfffff80586250000, VPs p7.1 p7.2 p7.3 p7.4

partition:p7.1> lm
Start             End               Module                 Version  Symbols  Source  Image
fffff80586250000  fffff805876a0000  nt                     -        loaded   cached  ntoskrnl.exe
fffff805876b0000  fffff805876b6000  hal                    -        loaded   cached  hal.dll
fffff805176d0000  fffff805176db000  kdcom                  -        loaded   cached  kdcom.dll
...
```

The prompt names the partition, and the Sandbox's four VPs are now the processors, `p7.1` to `p7.4`. Memory reads go through the Sandbox's EPT, and {command}`lm`, {command}`!process`, {command}`dt`, {command}`u` and {command}`k` read the Sandbox's kernel with its symbols.

```text
partition:p7.1> !process 0 0
PROCESS           SessionId  Cid            Peb               Wow64  ParentCid  ...  Image
ffff810cbf6a0040  0          4 (0x4)        -                 -      0          ...  System
ffff810cbf743080  0          92 (0x5c)      -                 -      4          ...  Secure System
...
ffff810cc3408080  0          2780 (0xadc)   0000005d24b77000  -      696        ...  CExecSvc.exe
ffff810cc33e90c0  0          3044 (0xbe4)   000000c1b47f8000  -      696        ...  VmComputeAgent
...
ffff810cc406f080  1          4856 (0x12f8)  0000000000cec000  -      4696       ...  explorer.exe
...
ffff810cc3f2b080  1          6820 (0x1aa4)  000000b17f3bb000  -      4856       ...  cmd.exe
ffff810cc2f52080  1          6948 (0x1b24)  0000008cf335e000  -      6820       ...  conhost.exe
```

These are the Sandbox's 86 processes, not the target's. Among them are `CExecSvc.exe` and `VmComputeAgent`, the Sandbox's container services, and `cmd.exe`, the Command Prompt that you opened, under the Sandbox's own `explorer.exe`.

{command}`~` lists the VPs, and {command}`k` walks the stack of the selected one. All four are idle:

```text
partition:p7.1> ~
vCPU  RIP               Context  Symbol
p7.1  fffff8058670f8bd  kernel   nt!PpmIdleGuestExecute+0x1d
p7.2  fffff8058670f8bd  kernel   nt!PpmIdleGuestExecute+0x1d
p7.3  fffff8058670f8bd  kernel   nt!PpmIdleGuestExecute+0x1d
p7.4  fffff8058670f8bd  kernel   nt!PpmIdleGuestExecute+0x1d

partition:p7.1> k
 00 fffff805187199a0  fffff8058670f8bd  nt!PpmIdleGuestExecute+0x1d
 01 fffff805187199e0  fffff8058658bc54  nt!PpmIdleExecuteTransition+0x518
 02 fffff80518719b70  fffff8058658a9f0  nt!PoIdle+0x190
 03 fffff80518719c40  fffff805868ff684  nt!KiIdleLoop+0x54
```

## Read a process in the Sandbox

:::{important}
The host trims the memory of an idle Sandbox, and a trimmed page is not mapped in the Sandbox's EPT until the Sandbox uses it again, so it reads as not mapped. Before you read a process, use it: run `.partition 1` and {command}`g`, type `set` in the Sandbox's Command Prompt, press Ctrl+C, and run `.partition 7` again. While the VM is halted, the host trims nothing, so the pages that the process just used stay readable.
:::

{command}`.process` selects the process, as it does in the target, and loads the symbols of its modules:

```text
partition:p7.1> .process /p 6820
process context: cmd.exe (PID 6820, EPROCESS ffff810cc3f2b080)
symbols: loaded 11/11

partition:p7.1> !peb
PEB 000000b17f3bb000
  ImageBaseAddress : 00007ff752030000
  ...
  OSBuildNumber    : 26100
  SessionId        : 1
  NumberOfProcessors: 4
  Process parameters 0000022e869679b0
    CommandLine       : "C:\Windows\system32\cmd.exe"
    ImagePathName     : C:\Windows\system32\cmd.exe
    CurrentDirectory  : C:\Users\WDAGUtilityAccount\
...

partition:p7.1> !dlls
11 loader modules
Base              Size      Entry             Timestamp   Name
00007ff752030000  0x70000   00007ff752057b80  0x789f4656  cmd.exe
00007ff8a8cc0000  0x267000  -                 0x6bdf03ca  ntdll.dll
00007ff8a6d70000  0xcb000   00007ff8a6d9c5d0  0x3ecccf12  KERNEL32.DLL
...
```

`WDAGUtilityAccount` is the account that the Sandbox's desktop runs as. {command}`!process` with flags 7 shows the threads of the process with their stacks:

```text
partition:p7.1> !process 0 7 cmd.exe
...
thread: ffff810cc38da080  TID 5412  PID 6820  process cmd.exe
  state=Waiting (0x5) wait=Executive (0x0) kthread=ffff810cc38da080 eprocess=ffff810cc3f2b080
...
stack
  #0  fffff805869064d6  nt!KiSwapContext+0x76 [seed]
  #1  fffff8058651c438  nt!KiSwapThread+0x248 [unwind]
...
  #7  fffff80586b3973e  nt!NtDeviceIoControlFile+0x5e [unwind]
  #8  fffff80586911d55  nt!KiSystemServiceCopyEnd+0x25 [unwind]
  #9  00007ff8a8e20ea4  ntdll!NtDeviceIoControlFile+0x14 [unwind]
  #10 00007ff8a5f9f290  kernelbase!ConsoleCallServerGeneric+0x110 [unwind]
  #11 00007ff8a5f9f0e9  kernelbase!ReadConsoleInternal+0x1a1 [unwind]
  #12 00007ff8a5f9ef0e  kernelbase!ReadConsoleW+0x1e [unwind]
  #13 00007ff75204d65d  cmd!?ReadBufFromConsole@@YAHPEAXPEAGHPEAH@Z+0x149 [unwind]
...
  #20 00007ff752063fa1  cmd!main+0x2c9 [unwind]
  #21 00007ff752057afb  cmd!__scrt_common_main_seh+0x10b [unwind]
  #22 00007ff8a6d9cd87  kernel32!BaseThreadInitThunk+0x17 [unwind]
  #23 00007ff8a8d6caec  ntdll!RtlUserThreadStart+0x2c [unwind]
```

The Command Prompt waits for you to type the next line, in `ReadConsoleW`, and the stack goes from `cmd!main` through `kernelbase` and `ntdll` into the Sandbox's kernel. If the stack ends at the first user-mode frame, the process's stack page was trimmed: use the process again and break in.

## Stop on a hypercall from the Sandbox

The Sandbox's VPs run only when the target's Windows runs them, so breakpoints go back in the target. `.partition 1` returns to it, and {command}`!hvbp` stops on a hypercall from one partition:

```text
partition:p7.1> .partition 1
inspecting the target (the root partition)

gdb:p01.01> !hvbp HvCallSendSyntheticClusterIpi 7
hypercall breakpoint #0 set at fffff81d51c927c0 (hv!HvCallSendSyntheticClusterIpi) (global, hypercall 0x000b HvCallSendSyntheticClusterIpi from partition 0x7)

gdb:p01.01> g
VM running, waiting for stop (Ctrl+C to pause)...
```

An idle Sandbox makes few hypercalls, so move the mouse over the Sandbox's window. A processor in the Sandbox sends an interrupt to another one with `HvCallSendSyntheticClusterIpi`, and the target stops in the hypervisor's handler:

```text
 BREAK  p01.02 hypervisor at hv!HvCallSendSyntheticClusterIpi
 ├─ hypercall breakpoint #0  hv!HvCallSendSyntheticClusterIpi
 ├─ thread vmmemSandbox  state Running  ethread ffffe6031b5b4080  pid 10212  tid 4860
 ├─ saved VTL0 hvcall!Hypercall
 ├─ serving partition 0x7 VP 2  VTL0 fffff805171e0000, last exit VMCALL (hypercall 0x000b HvCallSendSyntheticClusterIpi fast)
 └─ inspecting saved VTL0 (.cxr shows the hypervisor's registers)
...
stack
  #0  fffff80561040000  hvcall!Hypercall
  #1  fffff805d0778bb1  nt!HvcallpExtendedFastHypercall+0x51
  #2  fffff805d0778bd2  nt!HvcallpExtendedFastHypercallWithOutput+0x12
  #3  fffff805d02ef314  nt!HvcallFastExtended+0x164
  #4  fffff8063437b6ed  winhvr!WinHvpVpDispatchLoop+0x38d
  #5  fffff8063437b297  winhvr!WinHvRunVpDispatchLoop+0x157
  ... 3 more frames
```

The stop shows two sides of the same call. The `serving` line names the Sandbox's VP 2, whose hypercall the hypervisor handles. The thread and the stack are the target's: a `vmmemSandbox` thread, whose `winhvr!WinHvRunVpDispatchLoop` asked the hypervisor, with a hypercall of its own, to run the Sandbox's VP on this processor ([how stops in the hypervisor show](hypervisor-stops.md)). {command}`!hvcall` decodes the Sandbox's call:

```text
gdb:p01.02> !hvcall
partition 0x7 VP 2 VTL0  hypercall 0x000b HvCallSendSyntheticClusterIpi fast
├─ input value 0x000000000001000b  fast
├─ input in RDX and R8
├─ Vector         0x000000d2
├─ TargetVtl      0x00  UseTargetVtl clear
└─ ProcessorMask  0x0000000000000001  VPs 0
```

The Sandbox's VP 2 sends interrupt vector 0xd2 to its VP 0. To see why, go back into the Sandbox and walk the stack of VP 2, which is `p7.3`:

```text
gdb:p01.02> bc *
breakpoint #0 cleared

gdb:p01.02> .partition 7
inspecting partition 0x7: nt at 0xfffff80586250000, VPs p7.1 p7.2 p7.3 p7.4

partition:p7.1> ~
vCPU  RIP               Context  Symbol
p7.1  fffff8058670f8bd  kernel   nt!PpmIdleGuestExecute+0x1d
p7.2  fffff8058670f8bd  kernel   nt!PpmIdleGuestExecute+0x1d
p7.3  fffff805171e0000  kernel   hvcall!Hypercall
p7.4  fffff8058670f8bd  kernel   nt!PpmIdleGuestExecute+0x1d

partition:p7.1> ~2s
switched to processor p7.3

partition:p7.3> k
 00 fffff986d44613c8  fffff805171e0000  hvcall!Hypercall
 01 fffff986d44613d0  fffff8058664f758  nt!HvlSendSyntheticClusterIpi+0x88
 02 fffff986d4461430  fffff8058655b491  nt!HalpInterruptSendIpi+0x571
 03 fffff986d4461750  fffff8058653d82c  nt!KiSendClockInterruptToTargetProcessor+0xcc
 04 fffff986d44618d0  fffff8058680a678  nt!KeResumeClockTimerFromIdle+0x294
 05 fffff986d44619e0  fffff8058692e892  nt!PpmIdleExecuteTransition+0x3a3156
 06 fffff986d4461b70  fffff8058658a9f0  nt!PoIdle+0x190
 07 fffff986d4461c40  fffff805868ff684  nt!KiIdleLoop+0x54
```

As VP 2 left its idle loop, the Sandbox's kernel resumed the clock timer and sent the clock interrupt to VP 0, through the hypervisor. Frame 05 is in a block that the compiler moved away from the rest of `nt!PpmIdleExecuteTransition` ([how it is named](../using/symbols.md#code-split-off-from-its-function)).

## Go back to the target

```text
partition:p7.3> .partition 1
inspecting the target (the root partition)

gdb:p01.02> q
```

While the Sandbox is shown, {command}`g`, steps, breakpoints, and writes are refused, because the Sandbox runs only when the target runs. `.partition 1` brings back the target with its breakpoints, and {command}`q` detaches and lets the VM continue to run.

## From Python

The [Python SDK](../scripting/sdk.md) does the same with `select_partition()`. A handle that a call returns before a switch goes stale after it, so the script reads the VP index of the caller before it switches:

```python
import ntoseye

with ntoseye.attach("gdb", "127.0.0.1:1234") as dbg:
    dbg.interrupt()
    dbg.select_partition(7)                      # the Sandbox's ID from !hvpartitions
    cmd = dbg.processes.find("cmd.exe")[0]
    for thread in cmd.threads:
        print([frame.symbol for frame in thread.backtrace(limit=24)][-4:])
    dbg.select_partition(1)                      # back to the target

    bp = dbg.breakpoints.add_hypercall("HvCallSendSyntheticClusterIpi", 7)
    stop = dbg.run(timeout=60.0)
    bp.delete()
    caller = stop.cpu.hypercall_caller()
    vp_index = caller.vp_index                   # read before the switch
    print(caller.partition_id, vp_index, caller.hypercall.summary)

    dbg.select_partition(7)
    print([frame.symbol for frame in dbg.cpus[vp_index].backtrace(limit=5)])
    dbg.select_partition(1)
```

```text
['cmd!main+0x2c9', 'cmd!__scrt_common_main_seh+0x10b', 'kernel32!BaseThreadInitThunk+0x17', 'ntdll!RtlUserThreadStart+0x2c']
['nt!IoRemoveIoCompletion+0x92', 'nt!NtWaitForWorkViaWorkerFactory+0x6bf', 'nt!KiSystemServiceCopyEnd+0x25', 'ntdll!NtWaitForWorkViaWorkerFactory+0x14']
7 2 hypercall 0x000b HvCallSendSyntheticClusterIpi fast
['hvcall!Hypercall', 'nt!HvlSendSyntheticClusterIpi+0x88', 'nt!HalpInterruptSendIpi+0x571', 'nt!KiSendClockInterruptToTargetProcessor+0xcc', 'nt!KeResumeClockTimerFromIdle+0x294']
```

The second thread of `cmd.exe` is a thread-pool worker that has not run since the host trimmed its user-mode stack, so its walk ends at its first user-mode frame.

## Where to go next

- [Guest partitions](guest-partitions.md) explains the partition view and its limits, and reads the memory of any guest, such as WSL2.
- [Hypercalls and VM exits](hypercalls.md) explains hypercall breakpoints, conditions on the caller's registers and memory, and breakpoints on VM exits.
- [Partitions and virtual processors](partitions.md) shows the registers of any VP, the page permissions of each VTL's EPT, and what each VTL intercepts.
- [Stops in the Windows hypervisor](hypervisor-stops.md) explains what a vCPU that halted in the hypervisor shows.
