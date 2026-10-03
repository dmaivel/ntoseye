# Guest partitions

A guest partition runs an operating system of its own: a Hyper-V VM, a WSL2 Linux kernel, or a Windows Sandbox. `ntoseye` reads a guest through its partition's EPT, read-only: a Windows guest as a debug target with its own kernel's symbols, and any guest as raw memory and code.

## Inspecting a Windows guest partition

{command}`.partition` `<partition-id>` inspects the Windows guest that a partition runs, such as a Windows Sandbox or a Hyper-V VM, in place of the target:

- Its memory is read through the partition's EPT.
- Its NT kernel is found from the page-table root of a VP in kernel mode, and its symbols are loaded.
- Its VPs are the threads. {command}`~` lists them as `p<partition>.<VP index + 1>`, `~Ns` selects VP N, and each has the registers that {command}`!hvr` shows.

{command}`lm`, {command}`!process`, {command}`.process`, {command}`!peb`, {command}`!thread`, {command}`dt`, {command}`db`, {command}`u` and {command}`k` then read that guest. The view is read-only, and the target stays halted while it is shown:

- {command}`g`, steps, breakpoints, register writes and memory writes are refused.
- The target's breakpoints are not listed, and they are kept as they were.
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
p01.03  00007c27330c4321  partition 0x4 VP 2  0x7c27330c4321
```

With that vCPU selected, {command}`!hvd` `<address>` reads that guest's memory and {command}`!hvu` `<address>` disassembles it, at that RIP for example; from another vCPU, pass the partition ID and VP index.
