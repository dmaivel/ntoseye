# Guest partitions

A guest partition runs an operating system of its own: a Hyper-V VM, a WSL2 Linux kernel, or a Windows Sandbox. `ntoseye` reads a guest through its partition's EPT, read-only: a Windows guest as a debug target with its own kernel's symbols, and any guest as raw memory and code.

## Which partition is which

The hypervisor does not name its partitions. Their IDs follow the order in which they were created, so they change when a VM, WSL2, or a Sandbox starts again. {command}`!hvpartitions` lists them, and these tell them apart:

- {command}`.partition` `<id>` loads a Windows guest's kernel, and says that a Linux guest, such as WSL2's, runs none. It refuses a VM that is still in its firmware.
- A Linux kernel runs in the top 2 GiB of the address space (`ffffffff8...` and above), and NT runs at `fffff8...`, so the guest RIPs that {command}`!hvvps` `<id>` shows give the kernel away.
- A Windows Sandbox runs the host's own Windows image, so {command}`lmv` `m nt` in it shows the target's kernel PDB, while a Hyper-V VM runs whatever it installed.

```text
gdb:p01.01> .partition 5
error: Windows hypervisor: partition 0x5 runs no Windows kernel: no NT image is mapped where its VPs run, as in a Linux guest such as WSL2's; !hvd and !hvu read any guest's memory and code
gdb:p01.01> !hvvps 5
VP  Address           CPU  VTL  Context           eVMCS      EPT pointer  Guest RIP         Last exit
0   ffffe804c5038050       0*   ffffe804c5039000  22754d000  227c3105e    ffffffffbd1df02f  HLT
...
gdb:p01.01> .partition 4
inspecting partition 0x4: nt at 0xfffff80586250000, VPs p4.1 p4.2 p4.3 p4.4
```

## Inspecting a Windows guest partition

{command}`.partition` `<partition-id>` inspects the Windows guest that a partition runs, such as a Windows Sandbox or a Hyper-V VM, in place of the target:

- Its memory is read through the partition's EPT.
- Its NT kernel is found from the page-table root of a VP in kernel mode, and its symbols are loaded.
- Its VPs are the threads. {command}`~` lists them as `p<partition>.<VP index + 1>`, `~Ns` selects VP N, and each has its VTL0 registers, as `!hvr <partition> <vp> 0` shows them. A VP that runs in VTL1 when the target halts has VTL0's RIP, RSP, flags, control and segment registers, without its general-purpose registers, and `.partition` says so. Frames in the partition's hypercall page read `hvcall!Hypercall`, as in the target's.

{command}`lm`, {command}`!process`, {command}`.process`, {command}`!peb`, {command}`!thread`, {command}`dt`, {command}`db`, {command}`u` and {command}`k` then read that guest. The target stays halted while the view is shown, and the guest is read-only:

- Register writes and memory writes are refused.
- {command}`g` leaves the view and runs the target. A hit of one of the partition's breakpoints shows the view again (see [Breakpoints in a guest partition](#breakpoints-in-a-guest-partition)); any other stop shows the target.
- {command}`t`, {command}`p`, {command}`gu` and {command}`g` `<address>` run the target too (see [Stepping in a guest partition](#stepping-in-a-guest-partition)).
- {command}`bl` lists every breakpoint, the target's too.
- `.partition 1`, the root partition's ID, returns to the target.

In the SDK, `dbg.select_partition(id)` switches and `dbg.partition` says which partition is inspected. Handles minted on one side of a switch raise `StaleHandleError` on the other.

```text
gdb:p01.01> .partition 4
inspecting partition 0x4: nt at 0xfffff80586250000, VPs p4.1 p4.2 p4.3 p4.4

partition:p4.1> k
 00 fffff805187199a0  fffff8058670f8bd  nt!PpmIdleGuestExecute+0x1d
 01 fffff805187199e0  fffff8058658bc54  nt!PpmIdleExecuteTransition+0x518
 02 fffff80518719b70  fffff8058658a9f0  nt!PoIdle+0x190
 03 fffff80518719c40  fffff805868ff684  nt!KiIdleLoop+0x54
```

The guest must be 64-bit Windows: a partition with no VP in 4-level long-mode paging, such as a VM still in its firmware, is refused. A Linux guest, such as WSL2's, has no NT kernel to find. Use {command}`!hvd` and {command}`!hvu` for those.

The host can trim a guest's memory, as it does a Windows Sandbox's while it idles, and a trimmed page is not mapped in the partition's EPT until the guest touches it again, so it reads as not mapped. {command}`lm` and {command}`!process` list the modules and processes past a loader entry or process on such a page, by walking their lists back from the end, and leave out only that one. The view reads only the memory that VTL0's EPT maps, so {command}`.vtl` `1` is refused: the partition's secure kernel is not in it.

## Breakpoints in a guest partition

In a partition's view, {command}`ba` sets a breakpoint of the partition's, and {command}`g` runs the target until the partition hits it. The hit shows the partition's view, with the VP that ran the code selected:

```text
partition:p4.1> ba e1 nt!NtClose
hardware breakpoint #0 (execute 1b) set at fffff80586ac0f10 (nt!NtClose)

partition:p4.1> bl
ID  Status  Address           Pass Count   Process/Thread         Symbol               Condition  Action
#0  e       fffff80586ac0f10  0001 (0001)  partition 0x4, global  watch e1 nt!NtClose  -          -

partition:p4.1> g
VM running, waiting for stop (Ctrl+C to pause)...
 BREAK  p4.3 dwm.exe (3832) at nt!NtClose
 ├─ hardware breakpoint #0 e1  nt!NtClose
 └─ thread dwm.exe  state Running  ethread ffff810cc3a5d080  pid 3832  tid 3956
...
stack
  #0  fffff80586ac0f10  nt!NtClose
  #1  fffff80586911d55  nt!KiSystemServiceCopyEnd+0x25
  #2  fffff80586900180  nt!KiServiceLinkage
  #3  fffff8051d93c799  win32kbase!rimSignalReadComplete+0x209
```

The partition's VPs run on the target's processors, and only a debug register traps the partition's code there:

- The breakpoint is a debug register of the target's processors, one of the four that {command}`ba` and the target's breakpoints share. It needs the gdb backend.
- {command}`bp`, {command}`bu` and {command}`bm` are refused in the view: the gdb stub writes an `int3` through the target's page tables, and an `int3` it did not plant stops the guest, not the debugger.
- The register traps any code at its address, so ntoseye resumes hits by the target's own VPs or another partition's, and stops only on the partition's. In the view, `/c <n>` limits the breakpoint to VP n, as the view numbers its processors.
- A data watch, `ba w8` or `ba r8`, works the same way and stops after the access, as in the target. Each Windows maps `KUSER_SHARED_DATA` at `fffff78000000000` read-only and writes it through its own alias (`nt!MmWriteableSharedUserData`), so watch the alias for writes. A read of the shared address by the target's own Windows is resumed too, in a few milliseconds, but there are hundreds a second, and they slow the target.
- `/p` and `/t` name the partition's processes and threads, and a condition reads its registers, memory and symbols, as a breakpoint in the target reads the target's. ntoseye checks a hit against them before it shows the view, in about 0.1 s, so a busy function with a false condition slows the guest.
- The target's {command}`!hvbp` and {command}`!hvexit` are refused in the view.

In the SDK, `dbg.breakpoints.add(target, hardware=True)` and `dbg.breakpoints.watch(...)` set the partition's breakpoints while `dbg.select_partition(id)` shows it, and `bp.partition` names the partition. `dbg.run()` returns the hit with `dbg.partition` set to that partition.

## Stepping in a guest partition

In a partition's view, {command}`t`, {command}`p` and {command}`gu` step the thread on the selected VP, and {command}`g` `<address>` runs until any of the partition's VPs reaches the address. Each stop shows the view again:

```text
partition:p4.1> g nt!NtClose+0xa3
VM running, waiting for stop (Ctrl+C to pause)...
 BREAK  p4.1 dwm.exe (3832) at nt!NtClose+0xa3
 └─ thread dwm.exe  state Running  ethread ffff810cc3a60080  pid 3832  tid 3944
...
 > fffff80586ac0fb3  e8 98 14 00 00     call 0xFFFFF80586AC2450 ; nt!ExpLookupHandleTableEntry

partition:p4.1> p
VM running, waiting for stop (Ctrl+C to pause)...
 BREAK  p4.1 dwm.exe (3832) at nt!NtClose+0xa8
 └─ thread dwm.exe  state Running  ethread ffff810cc3a60080  pid 3832  tid 3944
...
partition:p4.1> gu
VM running, waiting for stop (Ctrl+C to pause)...
 BREAK  p4.1 dwm.exe (3832) at nt!KiSystemServiceCopyEnd+0x25
 └─ thread dwm.exe  state Running  ethread ffff810cc3a60080  pid 3832  tid 3944
```

The partition's VPs run on the target's processors, where the hypervisor moves them, so ntoseye cannot single-step one. A step runs the target instead, to debug registers of the partition's on every instruction that the current one can continue at, as for a breakpoint in the view:

- The step follows the thread, not the VP, so it ends on whichever VP the thread runs on next. A hit by another thread, or by the same thread deeper on the stack than the step can take it (an interrupt handler that runs the same code), is resumed.
- Each step takes about 0.25 s, so {command}`tc`, {command}`pc`, {command}`ta`, {command}`pa` and {command}`wt`, which step instruction by instruction, are refused in the view.
- A conditional branch takes two of the four debug registers, so a step there fails while three breakpoints hold theirs.

In the SDK, `dbg.step()`, `dbg.step_over()`, `dbg.step_out()` and `dbg.run_to(address)` do the same while the view is shown.

## Raw memory and code

{command}`!hvd` `[-p] [-b|-d|-q] [<partition-id> <vp-index>] <address> [range]` shows the memory of the guest that a child partition runs, such as a Hyper-V VM, WSL2, or Windows Sandbox inside the target. Without a partition and VP, it reads the guest VP that the current vCPU's processor runs. It reads guest virtual memory through the page tables of the VTL that the VP runs in (the CR3 in its eVMCS), or guest physical memory with `-p`, and it translates both through that VTL's EPT. Virtual addresses need a guest in 4-level long-mode paging; for a guest in 32-bit, PAE, or 5-level paging, read guest physical memory with `-p`. `-d` and `-q` show dwords and qwords, and the range works as for {command}`db`. Pages that are not mapped show as `??`. Here, a VM that sits in its firmware halted in the idle loop of its UEFI:

```text
mem:1> !hvvps 3
VP  Address           CPU  VTL  Context           eVMCS      EPT pointer  Guest RIP         Last exit
0   ffffe80200231050       0*   ffffe80200232000  2052dc000  20523105e    000000001ff26114  HLT
...
mem:1> !hvd 3 0 0x1ff26110 L10
000000001ff26110  fb c3 fb f4 c3 cc cc cc cc cc cc cc cc cc cc cc  ................
```

`sti; hlt` is at `0x1ff26112`, and the guest RIP is after the `hlt`. The memory is read-only, and {command}`!hvd` shows it without the guest's symbols; for a Windows guest, [`.partition`](#inspecting-a-windows-guest-partition) shows it with its kernel's symbols, processes, and modules. A VP that has not started, such as a second VP that the firmware has not woken, has no state to read through.

{command}`!hvu` `[-p] [<partition-id> <vp-index>] <address> [range]` disassembles the same memory, read as {command}`!hvd` reads it and with the same defaults. It decodes the code in the mode that the VTL left off in, by its eVMCS: 64-bit when the "IA-32e mode guest" entry control is set and the code segment is a 64-bit one (or its access rights are unusable), else 32-bit, in protected mode or compatibility mode. Real mode and 16-bit code give an error instead of a wrong listing. The range works as for {command}`u`: `L<count>` instructions (8 by default), or an end address or a length, which lists each instruction that starts before the range ends. The listing stops at the first page that it cannot read and says where. It uses no symbols of the guest, so branch targets and RIP-relative operands show as addresses. The same VM, where its VP left off:

```text
mem:1> !hvu 3 0 0x1ff26110 L4
000000001ff26110  fb  sti
000000001ff26111  c3  ret
000000001ff26112  fb  sti
000000001ff26113  f4  hlt
```

A vCPU that is running a guest partition's VP when the target halts shows that guest's registers. {command}`~` and the stop line name the VP that it runs, so a WSL2 busy loop reads as follows:

```text
vCPU    RIP               Context             Symbol
p01.03  00007c27330c4321  partition 0x5 VP 2  0x7c27330c4321
```

With that vCPU selected, {command}`!hvd` `<address>` reads that guest's memory and {command}`!hvu` `<address>` disassembles it, at that RIP for example; from another vCPU, pass the partition ID and VP index.
