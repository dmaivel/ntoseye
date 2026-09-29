# VBS internals

This page describes how [VBS inspection](../platforms/vbs.md) works: what `ntoseye` reads, how it recognizes that data, and which data it does not accept.

## Finding the secure kernel

The first `.vtl 1` command finds the secure kernel by scanning guest RAM for its page tables, and it accepts an image only if the image's CodeView record names `securekernel.pdb`. `ntoseye` keeps the result for the session. If NT reports that VSM did not start (`nt!VslVsmEnabled` is 0), the command fails immediately without scanning.

## Trustlet enumeration

Trustlet enumeration reads fields of secure-kernel processes that public symbols do not describe, so `ntoseye` gets their offsets from the secure kernel's own code:

- The list link: from the location where `SkpsInitializeProcess` adds a new process to `SkpsProcessList`.
- The NT PID and the trustlet ID: from the `IumProcessStartFailed` event, which reports these two values.
- The address-space root: from `SkeSelectProcessAddressSpace`.

The trustlet ID must also be a field that `SkpsReadPolicyMetadata` checks against the image's policy.

`ntoseye` then validates each record: its root must map the secure kernel, and its PID must match an NT process. This method recognizes every build that we examined from 10.0.19041 (Windows 10 20H1) through 10.0.28000, whose offsets differ between releases.

## Breakpoints while vCPUs are outside NT

QEMU writes kernel breakpoints through the page tables of the selected vCPU, which do not map NT while that vCPU is outside NT. Because QEMU software breakpoints apply to all vCPUs, `ntoseye` tries such a breakpoint again through a different vCPU that is halted in NT.

Only if all vCPUs are outside NT does `ntoseye` use the NT kernel's page tables on the selected vCPU for that one packet, and it then immediately restores the vCPU's CR3. With both methods, {command}`bp` and the bugcheck trap work in every address space where the vCPU can stop.

:::{warning}
If `ntoseye` is killed during the packet with the borrowed CR3, the vCPU resumes with the wrong CR3 and the guest crashes.
:::

## Stepping without the trap flag

When Windows runs its own hypervisor (VBS, Hyper-V, or WSL2), the GDB backend never uses the trap flag. Windows runs nested under that hypervisor, and a KVM single step of the Windows vCPU can complete inside the hypervisor while the trap flag is still set in Windows, which then takes the trap itself. With a kernel debugger configured, this froze the tested guest.

`ntoseye` reads `nt!HvlHyperVRootPartition` to find out whether Windows runs its own hypervisor.

### One instruction without the trap flag

In this case, `ntoseye` executes one instruction differently, both for a step ({command}`t`, {command}`p`, {command}`wt`, and the SDK's stepping calls) and to resume from a breakpoint:

1. It holds the other vCPUs.
2. It sets a temporary breakpoint on each successor of the instruction, that is, on each location where the instruction can continue.
3. It runs that vCPU alone to one of these temporary breakpoints.

The successors depend on the instruction:

| Instruction | Successor |
| --- | --- |
| A branch | Both arms of the branch |
| `ret` or `iretq` | The return address |
| An indirect `call` or `jmp` | The target |
| `sysret` | The address in RCX |
| `syscall` | The system-call entry of the kernel |
| `int` | The handler in the IDT of the processor |
| A hypercall | The next instruction |

The GDB stub does not read MSRs, so for `syscall`, `ntoseye` uses the entry that NT programs:

- `KiSystemCall64Shadow` while KVA shadowing runs (`nt!KiKvaShadow`).
- `KiSystemCall64` in other cases.
- From compatibility mode, the `32` variants of these entries.

Some instructions, for example `sysenter`, `xabort`, and `rsm`, have no successor that `ntoseye` can determine from the stop. `ntoseye` gives an error instead of stepping them. To step through these instructions, use the `kd` or `kdnet` backend.

### Steps in VTL1

In secure-kernel code, the temporary breakpoints are debug-register breakpoints in free slots, so `ntoseye` does not write VTL1 code. A VTL1 step needs one free slot for each successor, and if one more slot is free, the step also uses it to mark the instruction while the held vCPUs run.

`ntoseye` does not step a `syscall`, `int`, `ud2`, or hypercall in VTL1 and gives an error, because the secure kernel enters these instructions through its own entry and IDT, which NT's entry and IDT do not describe.

### When the vCPU waits on a held vCPU

If the vCPU does not get past the instruction in 100 ms, it is waiting on a held vCPU. It is then in the hypervisor, still on the instruction, or in the handler of an interrupt that it took first (from VTL1, this is NT's handler, in VTL0).

`ntoseye` then breaks in on the vCPU and lets all vCPUs run 20 ms at a time, with the instruction also marked. The runs continue until one of these conditions occurs:

- The vCPU is past the instruction.
- The vCPU is back on the instruction, on the same thread. `ntoseye` then runs the vCPU alone again.
- One second has passed.

If a different vCPU gets to a marked site, the run ends early, which in hot code happens immediately. That vCPU then waits at the site until the next run. `ntoseye` does not hold that vCPU, because it can be the vCPU that the hypervisor waits for, and this is why a time limit ends the runs instead of a count.

After these runs, the step stops and reports its location if it is still in an interrupt handler, if the handler switched out the step's thread, or if the handler hit a breakpoint during the runs. The report includes a notice that gives the reason. Stepping loops ({command}`wt`, `step(until=...)`, `run_to(step=...)`) also stop there, because the handler can wait on a vCPU that the loop holds. {command}`wt` ends as `diverted`.

If the vCPU is still on the instruction or in the hypervisor after these runs, the step fails, and {command}`g` resumes the vCPU from there.

In a stress test on a 4-vCPU guest, none of 6,000 kernel steps from `nt!NtClose` and none of 3,000 breakpoint resumes on `nt!KiSwapContext` failed, and 13 of the steps ended in a handler.

### Breakpoint resumes that end in a handler

When the vCPU of a breakpoint resume ends in a handler, the resume continues with the breakpoint armed again, so the interrupted execution traps on the breakpoint again when the handler returns. `ntoseye` recognizes this hit and absorbs it, so it does not report the hit twice.

To recognize the hit, `ntoseye` finds the processor's interrupt frame below the stack pointer of the site, which shows that the interrupt occurred on the site itself. Because the thread cannot get past the armed site without a hit on it, the next hit of that thread at the site, with that stack pointer, is the return.

In a test on `nt!KiSwapContext` with the handler runs disabled, `ntoseye` absorbed 49 of 49 such returns.

## Reading the saved VTL state

`ntoseye` makes these checks on the saved VTL state:

- A page is an eVMCS only if it has the TLFS version, paging on, and an upper-half hypervisor entry point.
- The page belongs to a vCPU if its hypervisor root is the CR3 of that vCPU.
- The state is VTL0 only if it is in an NT address space. In kernel mode, the GS base must also be the KPCR of that processor.
- The state is VTL1 only if it is in a secure-kernel address space.

If a state fails these checks, `ntoseye` does not show it.
