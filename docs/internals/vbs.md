# VBS internals

This page tells how [VBS inspection](../platforms/vbs.md) works. It tells what `ntoseye` reads, how `ntoseye` recognizes it, and which data `ntoseye` does not accept.

## Finding the secure kernel

The first `.vtl 1` command finds the secure kernel. It scans guest RAM for the page tables of the secure kernel. It accepts an image only if the CodeView record of the image names `securekernel.pdb`. `ntoseye` keeps the result for the session. If NT reports that VSM did not start (`nt!VslVsmEnabled` is 0), the command fails immediately and does not scan.

## Trustlet enumeration

Trustlet enumeration reads fields of secure-kernel processes. Public symbols do not describe these fields. So `ntoseye` gets their offsets from the code of the secure kernel:

- The list link: from the location where `SkpsInitializeProcess` adds a new process to `SkpsProcessList`.
- The NT PID and the trustlet ID: from the `IumProcessStartFailed` event, which reports these two values.
- The address-space root: from `SkeSelectProcessAddressSpace`.

The trustlet ID must also be a field that `SkpsReadPolicyMetadata` checks against the policy of the image.

Then `ntoseye` validates each record:

- The root of the record must map the secure kernel.
- The PID of the record must match an NT process.

This method recognizes all builds that we examined, from 10.0.19041 (Windows 10 20H1) through 10.0.28000. The offsets are different between these releases.

## Breakpoints while vCPUs are outside NT

QEMU writes kernel breakpoints through the page tables of the selected vCPU. When that vCPU is outside NT, these page tables do not map NT. The QEMU software breakpoints apply to all vCPUs. So `ntoseye` tries such a breakpoint again through a different vCPU that is halted in NT.

If all vCPUs are outside NT, `ntoseye` uses the page tables of the NT kernel on the selected vCPU for that one packet. It then immediately restores the CR3 of the vCPU. With both methods, {command}`bp` and the bugcheck trap work in all address spaces where the vCPU can stop.

:::{warning}
If `ntoseye` is killed during the packet with the borrowed CR3, the vCPU resumes with the wrong CR3. The guest then crashes.
:::

## Stepping without the trap flag

When Windows runs its own hypervisor (VBS, Hyper-V, or WSL2), the GDB backend never uses the trap flag. The reason is as follows. Windows runs nested under that hypervisor. A KVM single step of the Windows vCPU can complete inside the hypervisor while the trap flag is still set in Windows. Windows then takes the trap itself. With a kernel debugger configured, this froze the tested guest.

`ntoseye` reads `nt!HvlHyperVRootPartition` to find out if Windows runs its own hypervisor.

### One instruction without the trap flag

In this case, `ntoseye` executes one instruction in a different way. It does this for a step ({command}`t`, {command}`p`, {command}`wt`, and the stepping calls of the SDK) and to resume from a breakpoint:

1. `ntoseye` holds the other vCPUs.
2. It sets a temporary breakpoint on each location where the instruction can continue. Each of these locations is a successor of the instruction.
3. It runs that vCPU alone to one of these temporary breakpoints.

The table shows the successors:

| Instruction | Successor |
| --- | --- |
| A branch | Both arms of the branch |
| `ret` or `iretq` | The return address |
| An indirect `call` or `jmp` | The target |
| `sysret` | The address in RCX |
| `syscall` | The system-call entry of the kernel |
| `int` | The handler in the IDT of the processor |
| A hypercall | The next instruction |

The GDB stub does not read MSRs. So for `syscall`, `ntoseye` uses the entry that NT programs:

- `KiSystemCall64Shadow` while KVA shadowing runs (`nt!KiKvaShadow`).
- `KiSystemCall64` in other cases.
- From compatibility mode, the `32` variants of these entries.

Some instructions do not have a successor that `ntoseye` can know from the stop, for example `sysenter`, `xabort`, and `rsm`. `ntoseye` does not step these instructions and gives an error. To step through these instructions, use the `kd` or `kdnet` backend.

### Steps in VTL1

In secure-kernel code, the temporary breakpoints are debug-register breakpoints in free slots. So `ntoseye` does not write VTL1 code. A VTL1 step needs one free slot for each successor. If one more slot is free, the step also uses it to mark the instruction while the held vCPUs run.

`ntoseye` does not step a `syscall`, `int`, `ud2`, or hypercall in VTL1, and gives an error. The secure kernel enters these instructions through its own entry and IDT. The entry and IDT of NT do not describe them.

### When the vCPU waits on a held vCPU

If the vCPU does not get past the instruction in 100 ms, it waits on a held vCPU. The vCPU is then in one of these locations:

- In the hypervisor.
- Still on the instruction.
- In the handler of an interrupt that it took first. From VTL1, this is the handler of NT, in VTL0.

`ntoseye` then breaks in on the vCPU and lets all vCPUs run, 20 ms at a time. During these runs, the instruction is also marked. The runs continue until one of these conditions occurs:

- The vCPU is past the instruction.
- The vCPU is back on the instruction, on the same thread. `ntoseye` then runs the vCPU alone again.
- One second has passed.

If a different vCPU gets to a marked site, the run ends early. In hot code, this occurs immediately. That vCPU then waits at the site until the next run. `ntoseye` does not hold that vCPU, because it can be the vCPU that the hypervisor waits for. For this reason, a time limit stops the runs, and `ntoseye` does not count them.

After these runs, the step stops and reports its location in these cases:

- The step is still in an interrupt handler.
- The handler switched out the thread of the step.
- The handler hit a breakpoint during the runs.

The report includes a notice that gives the reason. Stepping loops ({command}`wt`, `step(until=...)`, `run_to(step=...)`) also stop there. The reason is that the handler can wait on a vCPU that the loop holds. {command}`wt` ends as `diverted`.

If the vCPU is still on the instruction or in the hypervisor after these runs, the step fails. {command}`g` resumes the vCPU.

We did a stress test on a 4-vCPU guest. None of 6,000 kernel steps from `nt!NtClose` failed. None of 3,000 breakpoint resumes on `nt!KiSwapContext` failed. Of the steps, 13 ended in a handler.

### Breakpoint resumes that end in a handler

The vCPU of a breakpoint resume can end in a handler. In this case, the resume continues with the breakpoint armed again. When the handler returns, the interrupted execution traps on the breakpoint again. `ntoseye` recognizes this hit and absorbs it, so it does not report the hit twice. It recognizes the hit as follows:

- The interrupt frame of the processor is below the stack pointer of the site. This frame shows that the interrupt occurred on the site itself.
- The thread cannot get past the armed site without a hit on it.
- So the next hit of that thread at the site, with that stack pointer, is the return.

In a test on `nt!KiSwapContext` with the handler runs disabled, `ntoseye` absorbed 49 of 49 such returns.

## Reading the saved VTL state

`ntoseye` makes these checks on the saved VTL state:

- A page is an eVMCS only if it has the TLFS version, paging on, and an upper-half hypervisor entry point.
- The page belongs to a vCPU if its hypervisor root is the CR3 of that vCPU.
- The state is VTL0 only if it is in an NT address space. In kernel mode, the GS base must also be the KPCR of that processor.
- The state is VTL1 only if it is in a secure-kernel address space.

If a state fails these checks, `ntoseye` does not show it.
