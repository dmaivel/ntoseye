# Debugging a Windows Sandbox

This walkthrough debugs a Windows Sandbox that runs inside the Windows VM you debug. The Sandbox is a guest partition of the Windows hypervisor, with its own kernel and processes, and `ntoseye` reads it from the host, stops it at breakpoints in its kernel, and steps it. You will:

1. Find the Sandbox's partition.
2. Look around inside the Sandbox.
3. Read one of its processes.
4. Break in the Sandbox's kernel and step through it.
5. Stop on a hypercall that the Sandbox makes, and see the Sandbox code that made it.
6. Go back to the target.
7. Do the same from Python.

## Before you start

- The VM must run the Windows hypervisor, so it needs nested virtualization, and the `hv-evmcs` enlightenment, with which `ntoseye` finds the hypervisor's partitions. [KVM/QEMU](../setup/kvm-qemu.md#virtualization-based-security-vbs) shows both settings.
- `ntoseye` attaches with the `gdb` backend ([GDB stub](../setup/kvm-qemu.md#gdb-stub)), because the breakpoints in steps 4 and 5 are hardware breakpoints that the host programs: one in the Sandbox's kernel, and one in the hypervisor.
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
  base   fffff804a1a70000
  psmods ffff8082614709d0
...
 BREAK  processor 0  hypervisor at hv+0x3a6bde
 ├─ thread fffff804a2a425c0  TID 0  PID 0  process Idle  state Running
 ├─ saved VTL0 nt!HalProcessorIdle+0xf
 └─ inspecting saved VTL0 (.cxr shows the hypervisor's registers)
...
0: gdb>
```

The `gdb` backend halts the vCPUs wherever they are. Here, processor 0 halted in the hypervisor, and the stop shows where the target's Windows left off, its idle thread in `nt!HalProcessorIdle`, from the state the hypervisor saved ([how stops in the hypervisor show](hypervisor-stops.md)). A vCPU can also halt while it runs a guest's VP, and then shows that guest's registers.

{command}`!hvpartitions` lists the partitions. The privilege lines are left out here:

```text
0: gdb> !hvpartitions
partition 0x1  root  ffffe80000001000
├─ VP 0  CPU 0  VTL0 (+VTL1)  nt!HalProcessorIdle+0xf  last exit HLT
├─ VP 1  CPU 1  VTL0 (+VTL1)  nt!HalProcessorIdle+0xf  last exit HLT
├─ VP 2  VTL0 (+VTL1)  hvcall!Hypercall  last exit VMCALL
├─ VP 3  CPU 3  VTL0 (+VTL1)  nt!HalProcessorIdle+0xf  last exit HLT
├─ partition 0x3  ffffe80200001000
│  ├─ VP 0  VTL0  fffff805adca5d67  last exit RDMSR
│  └─ VP 1  VTL0  fffff805adca5d67  last exit RDMSR
├─ partition 0x4  ffffe80300001000
│  ├─ VP 0  VTL0 (+VTL1)  fffff8058670f8bd  last exit RDMSR
│  ├─ VP 1  VTL0 (+VTL1)  fffff8058670f8bd  last exit RDMSR
│  ├─ VP 2  VTL0 (+VTL1)  fffff8058670f8bd  last exit RDMSR
│  └─ VP 3  VTL0 (+VTL1)  fffff8058670f8bd  last exit RDMSR
└─ partition 0x5  ffffe80400001000
   ├─ VP 0  VTL0  ffffffffa61df02f  last exit HLT
   ├─ VP 1  CPU 2  VTL0  0000769622673b90  last exit external interrupt
   ├─ VP 2  VTL0  ffffffffa61df02f  last exit HLT
   └─ VP 3  VTL0  ffffffffa61df02f  last exit HLT
```

Partition 0x1 is the target's own Windows. The hypervisor does not name the others, and their IDs change each time a guest starts, so [tell them apart](guest-partitions.md#which-partition-is-which) by what they run: partition 0x5 runs a Linux kernel (`ffffffffa61df02f`, WSL2), and partitions 0x3 and 0x4 run NT at `fffff80...` addresses. Partition 0x4 is the Sandbox: it has VTL1, because the Sandbox runs with VBS, and after {command}`.partition` `4`, {command}`lmv` `m nt` shows the target's own kernel PDB, because a Sandbox runs the host's Windows image.

## Look around inside the Sandbox

{command}`.partition` shows the Sandbox in place of the target:

```text
0: gdb> .partition 4
inspecting partition 0x4: nt at 0xfffff80586250000, VPs 0 1 2 3
0: partition 0x4> lm
Start             End               Module                 Version  Symbols  Source  Image
fffff80586250000  fffff805876a0000  nt                     -        loaded   cached  ntoskrnl.exe
fffff805876b0000  fffff805876b6000  hal                    -        loaded   cached  hal.dll
fffff805176d0000  fffff805176db000  kdcom                  -        loaded   cached  kdcom.dll
...
```

The prompt names the partition, and the Sandbox's four VPs are now the processors, 0 to 3, each numbered by its VP index. Memory reads go through the Sandbox's EPT, and {command}`lm`, {command}`!process`, {command}`dt`, {command}`u` and {command}`k` read the Sandbox's kernel with its symbols.

```text
0: partition 0x4> !process 0 0
PROCESS           SessionId  Cid            Peb               Wow64  ParentCid  ...  Image
ffff810cbf6a0040  0          4 (0x4)        -                 -      0          ...  System
ffff810cbf743080  0          92 (0x5c)      -                 -      4          ...  Secure System
...
ffff810cc3408080  0          2780 (0xadc)   0000005d24b77000  -      696        ...  CExecSvc.exe
ffff810cc33e90c0  0          3044 (0xbe4)   000000c1b47f8000  -      696        ...  VmComputeAgent
...
ffff810cc51ac080  1          4752 (0x1290)  0000000000652000  -      4732       ...  explorer.exe
...
ffff810cc2a80080  1          6996 (0x1b54)  0000003f10fdb000  -      4752       ...  cmd.exe
ffff810cc38de080  1          7044 (0x1b84)  000000b77c602000  -      6996       ...  conhost.exe
```

These are the Sandbox's 75 processes, not the target's. Among them are `CExecSvc.exe` and `VmComputeAgent`, the Sandbox's container services, and `cmd.exe`, the Command Prompt that you opened, under the Sandbox's own `explorer.exe`.

{command}`~` lists the VPs, and {command}`k` walks the stack of the selected one. All four are idle:

```text
0: partition 0x4> ~
   Processor  RIP               Context  Symbol
.  0          fffff8058670f8bd  kernel   nt!PpmIdleGuestExecute+0x1d
   1          fffff8058670f8bd  kernel   nt!PpmIdleGuestExecute+0x1d
   2          fffff8058670f8bd  kernel   nt!PpmIdleGuestExecute+0x1d
   3          fffff8058670f8bd  kernel   nt!PpmIdleGuestExecute+0x1d

0: partition 0x4> k
  # Child-SP          IP                Call Site
 00 fffff805187199a0  fffff8058670f8bd  nt!PpmIdleGuestExecute+0x1d
 01 fffff805187199e0  fffff8058658bc54  nt!PpmIdleExecuteTransition+0x518
 02 fffff80518719b70  fffff8058658a9f0  nt!PoIdle+0x190
 03 fffff80518719c40  fffff805868ff684  nt!KiIdleLoop+0x54
```

## Read a process in the Sandbox

:::{important}
The host trims the memory of an idle Sandbox, and a trimmed page is not mapped in the Sandbox's EPT until the Sandbox uses it again, so it reads as not mapped. Before you read a process, use it: run {command}`g`, type `set` in the Sandbox's Command Prompt, press Ctrl+C, and run `.partition 4` again. While the VM is halted, the host trims nothing, so the pages that the process just used stay readable.
:::

{command}`.process` selects the process, as it does in the target, and loads the symbols of its modules:

```text
0: partition 0x4> .process /p 6996
process context: cmd.exe (PID 6996, EPROCESS ffff810cc2a80080, DTB …)
symbols: loaded 11/11

0: partition 0x4> !peb
PEB 0000003f10fdb000
  ImageBaseAddress                    : 00007ff61ed70000
  ...
  OSBuildNumber                       : 26100
  SessionId                           : 1
  NumberOfProcessors                  : 4
  ...
  ProcessParameters 000001e28cc979b0
    CommandLine      : "C:\Windows\system32\cmd.exe"
    ImagePathName    : C:\Windows\system32\cmd.exe
    CurrentDirectory : C:\Users\WDAGUtilityAccount\
...

0: partition 0x4> !dlls
11 loader modules
Base              Size      Entry             Timestamp   Name
00007ff61ed70000  0x70000   00007ff61ed97b80  0x789f4656  cmd.exe
00007ff8a8cc0000  0x267000  -                 0x6bdf03ca  ntdll.dll
00007ff8a6d70000  0xcb000   00007ff8a6d9c5d0  0x3ecccf12  KERNEL32.DLL
...
```

`WDAGUtilityAccount` is the account that the Sandbox's desktop runs as. {command}`!process` with flags 7 shows the threads of the process with their stacks:

```text
0: partition 0x4> !process 0 7 cmd.exe
...
THREAD ffff810cc3744080  TID 7000  PID 6996  process cmd.exe
  state                Waiting (0x5)
  wait reason          Executive (0x0)
  KTHREAD              ffff810cc3744080
  EPROCESS             ffff810cc2a80080
...
stack (kernel-stack)
...
```

Each stack is listed as {command}`k` lists it. The Command Prompt waits for you to type the next line, in `ReadConsoleW`: its stack goes from `cmd!main` through `cmd!?ReadBufFromConsole@@YAHPEAXPEAGHPEAH@Z`, `kernelbase!ReadConsoleW` and `ntdll!NtDeviceIoControlFile` into the Sandbox's kernel, where `nt!NtDeviceIoControlFile` waits in `nt!KiSwapContext`. If the stack ends at the first user-mode frame, the process's stack page was trimmed: use the process again and break in.

## Break in the Sandbox's kernel

A hardware breakpoint set while the Sandbox is shown is the Sandbox's. {command}`g` runs the target, and when one of the Sandbox's VPs reaches the address, ntoseye shows the Sandbox again, with that VP selected. Run {command}`g` and move the mouse over the Sandbox's window:

```text
0: partition 0x4> ba e1 nt!NtClose
hardware breakpoint #0 (execute 1b) set at fffff80586ac0f10 (nt!NtClose)

0: partition 0x4> g
VM running, waiting for stop (Ctrl+C to pause)...
 BREAK  processor 2  dwm.exe (3832) at nt!NtClose
 ├─ hardware breakpoint #0 e1  nt!NtClose
 └─ thread ffff810cc3a5d080  TID 3956  PID 3832  process dwm.exe  state Running
...
stack
  00  fffff80586ac0f10  nt!NtClose
  01  fffff80586911d55  nt!KiSystemServiceCopyEnd+0x25
  02  fffff80586900180  nt!KiServiceLinkage
  03  fffff8051d93c799  win32kbase!rimSignalReadComplete+0x209
  04  fffff8051d94010f  win32kbase!rimProcessDeviceBufferAndStartRead+0x187
  05  fffff8051d93fa7f  win32kbase!rimInputApc+0x1af
  ... 14 more frames
```

The Sandbox's `dwm.exe` closed a handle on its VP 2, processor 2 in its view, as `win32kbase` handled the mouse's input. The target's own Windows runs `NtClose` too, at its own address, and the debug register traps any code there, so ntoseye resumes the hits that are not the Sandbox's. {command}`k`, {command}`r` and {command}`dt` read the Sandbox at the stop, and {command}`t`, {command}`p` and {command}`gu` step the thread:

```text
2: partition 0x4> t
 BREAK  processor 2  dwm.exe (3832) at nt!NtClose+0x5
 └─ thread ffff810cc3a5d080  TID 3956  PID 3832  process dwm.exe  state Running
...
2: partition 0x4> gu
VM running, waiting for stop (Ctrl+C to pause)...
 BREAK  processor 2  dwm.exe (3832) at nt!KiSystemServiceCopyEnd+0x25
 └─ thread ffff810cc3a5d080  TID 3956  PID 3832  process dwm.exe  state Running
...
2: partition 0x4> bc *
breakpoint #0 cleared
```

A VP of the Sandbox runs on whichever of the target's processors the hypervisor gives it, so each step runs the target to the thread's next instruction, in a fraction of a second. Only {command}`ba` sets breakpoints in the Sandbox; [Breakpoints in a guest partition](guest-partitions.md#breakpoints-in-a-guest-partition) and [Stepping in a guest partition](guest-partitions.md#stepping-in-a-guest-partition) explain how, and the limits.

## Stop on a hypercall from the Sandbox

A hypercall breakpoint is in the hypervisor, which is the target's, so set it from the target. `.partition 1` returns to it, and {command}`!hvbp` stops on a hypercall from one partition:

```text
2: partition 0x4> .partition 1
inspecting the target (the root partition)
1: gdb> !hvbp HvCallSendSyntheticClusterIpi 4
hypercall breakpoint #0 set at fffff850200927c0 (hv!HvCallSendSyntheticClusterIpi) (global, hypercall 0x000b HvCallSendSyntheticClusterIpi from partition 0x4)

1: gdb> g
VM running, waiting for stop (Ctrl+C to pause)...
```

An idle Sandbox makes few hypercalls, so move the mouse over the Sandbox's window again. A processor in the Sandbox sends an interrupt to another one with `HvCallSendSyntheticClusterIpi`, and the target stops in the hypervisor's handler:

```text
 BREAK  processor 2  hypervisor at hv!HvCallSendSyntheticClusterIpi
 ├─ hypercall breakpoint #0  hv!HvCallSendSyntheticClusterIpi
 ├─ thread ffff808268aa2080  TID 7536  PID 11116  process vmmemSandbox  state Running
 ├─ saved VTL0 hvcall!Hypercall
 ├─ serving partition 0x4 VP 2  VTL0 fffff805171e0000, last exit VMCALL (hypercall 0x000b HvCallSendSyntheticClusterIpi fast)
 └─ inspecting saved VTL0 (.cxr shows the hypervisor's registers)
...
stack
  00  fffff80432ab0000  hvcall!Hypercall
  01  fffff804a2128bb1  nt!HvcallpExtendedFastHypercall+0x51
  02  fffff804a2128bd2  nt!HvcallpExtendedFastHypercallWithOutput+0x12
  03  fffff804a1c9f314  nt!HvcallFastExtended+0x164
  04  fffff806c1bfb6ed  winhvr!WinHvpVpDispatchLoop+0x38d
  05  fffff806c1bfb297  winhvr!WinHvRunVpDispatchLoop+0x157
  ... 3 more frames
```

The stop shows two sides of the same call. The `serving` line names the Sandbox's VP 2, whose hypercall the hypervisor handles. The thread and the stack are the target's: a `vmmemSandbox` thread, whose `winhvr!WinHvRunVpDispatchLoop` asked the hypervisor, with a hypercall of its own, to run the Sandbox's VP on this processor ([how stops in the hypervisor show](hypervisor-stops.md)). {command}`!hvcall` decodes the Sandbox's call:

```text
2: gdb> !hvcall
partition 0x4 VP 2 VTL0  hypercall 0x000b HvCallSendSyntheticClusterIpi fast
├─ input value 0x000000000001000b  fast
├─ input in RDX and R8
├─ Vector         0x000000e1
├─ TargetVtl      0x00  UseTargetVtl clear
└─ ProcessorMask  0x0000000000000001  VPs 0
```

The Sandbox's VP 2 sends interrupt vector 0xe1 to its VP 0. To see why, go back into the Sandbox and walk the stack of VP 2, which is processor 2 there:

```text
2: gdb> bc *
breakpoint #0 cleared

2: gdb> .partition 4
inspecting partition 0x4: nt at 0xfffff80586250000, VPs 0 1 2 3
0: partition 0x4> ~
   Processor  RIP               Context  Symbol
.  0          fffff8058670f8bd  kernel   nt!PpmIdleGuestExecute+0x1d
   1          fffff8058670f8bd  kernel   nt!PpmIdleGuestExecute+0x1d
   2          fffff805171e0000  kernel   hvcall!Hypercall
   3          fffff8058670f8bd  kernel   nt!PpmIdleGuestExecute+0x1d

0: partition 0x4> ~2s
switched to processor 2

2: partition 0x4> k
  # Child-SP          IP                Call Site
 00 fffff986d4461638  fffff805171e0000  hvcall!Hypercall
 01 fffff986d4461640  fffff8058664f758  nt!HvlSendSyntheticClusterIpi+0x88
 02 fffff986d44616a0  fffff8058655b491  nt!HalpInterruptSendIpi+0x571
 03 fffff986d44619c0  fffff8058658c4b3  nt!HalRequestIpi+0x73
 04 fffff986d4461a20  fffff8058658b709  nt!PpmWakeClockOwnerIfNeeded+0xc5
 05 fffff986d4461b70  fffff8058658a9aa  nt!PoIdle+0x14a
 06 fffff986d4461c40  fffff805868ff684  nt!KiIdleLoop+0x54
```

VP 2 was idle: in its idle loop, the Sandbox's kernel woke VP 0 with an interrupt that `nt!PpmWakeClockOwnerIfNeeded` requested, which it sent through the hypervisor.

## Go back to the target

```text
2: partition 0x4> .partition 1
inspecting the target (the root partition)
2: gdb> q
```

While the Sandbox is shown, the target stays halted, and {command}`g` runs the target and leaves the Sandbox's view. `.partition 1` brings back the target, and {command}`q` detaches and lets the VM continue to run.

## From Python

The [Python SDK](../scripting/sdk.md) does the same with `select_partition()`. A handle that a call returns before a switch goes stale after it, so the script reads the VP index of the caller before it switches:

```python
import ntoseye

with ntoseye.attach("gdb", "127.0.0.1:1234") as dbg:
    dbg.interrupt()
    dbg.select_partition(4)                      # the Sandbox's ID from !hvpartitions
    cmd = dbg.processes.find("cmd.exe")[0]
    for thread in cmd.threads:
        print([frame.symbol for frame in thread.backtrace(limit=24)][-4:])

    bp = dbg.breakpoints.add("nt!NtClose", hardware=True)
    stop = dbg.run(timeout=60.0)                 # the hit shows the Sandbox again
    bp.delete()
    assert stop is not None and stop.thread is not None
    print(dbg.partition, stop.cpu, stop.thread.process_name)
    stop = dbg.step_out()                        # gu, on the same thread
    print(stop.symbol)
    dbg.select_partition(1)                      # back to the target

    bp = dbg.breakpoints.add_hypercall("HvCallSendSyntheticClusterIpi", 4)
    stop = dbg.run(timeout=60.0)
    bp.delete()
    assert stop is not None and stop.cpu is not None
    caller = dbg.cpus[stop.cpu].hypercall_caller()
    assert caller is not None and caller.hypercall is not None
    vp_index = caller.vp_index                   # read before the switch
    print(caller.partition_id, vp_index, caller.hypercall.summary)

    dbg.select_partition(4)
    print([frame.symbol for frame in dbg.cpus[vp_index].backtrace(limit=5)])
    dbg.select_partition(1)
```

```text
['cmd!main+0x2c9', 'cmd!__scrt_common_main_seh+0x10b', 'kernel32!BaseThreadInitThunk+0x17', 'ntdll!RtlUserThreadStart+0x2c']
4 2 dwm.exe
nt!KiSystemServiceCopyEnd+0x25
4 2 hypercall 0x000b HvCallSendSyntheticClusterIpi fast
['hvcall!Hypercall', 'nt!HvlSendSyntheticClusterIpi+0x88', 'nt!HalpInterruptSendIpi+0x571', 'nt!HalRequestIpi+0x73', 'nt!PpmWakeClockOwnerIfNeeded+0xc5']
```

## Where to go next

- [`guest_partition.py`](https://github.com/dmaivel/ntoseye/blob/master/examples/standalone/guest_partition.py), [`guest_break.py`](https://github.com/dmaivel/ntoseye/blob/master/examples/standalone/guest_break.py) and [`hypercall_watch.py`](https://github.com/dmaivel/ntoseye/blob/master/examples/standalone/hypercall_watch.py) do these steps as scripts that find the guests and handle their refusals.
- [Guest partitions](guest-partitions.md) explains the partition view and its limits, breakpoints and steps in a guest, and reads the memory of any guest, such as WSL2.
- [Hypercalls and VM exits](hypercalls.md) explains hypercall breakpoints, conditions on the caller's registers and memory, and breakpoints on VM exits.
- [Partitions and virtual processors](partitions.md) shows the registers of any VP, the page permissions of each VTL's EPT, and what each VTL intercepts.
- [Stops in the Windows hypervisor](hypervisor-stops.md) explains what a vCPU that halted in the hypervisor shows.
