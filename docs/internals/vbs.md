# VBS internals

This page describes how [VBS inspection](../platforms/vbs.md) works: what `ntoseye` reads, how it recognizes that data, and which data it does not accept.

## Finding the secure kernel

The first `.vtl 1` command, or the first stop in the Windows hypervisor that finds a saved state outside NT, finds the secure kernel by scanning guest RAM for its page tables, and it accepts an image only if the image's CodeView record names `securekernel.pdb`. `ntoseye` keeps the result for the session. If NT reports that VSM did not start (`nt!VslVsmEnabled` is 0), the command fails immediately without scanning.

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

If the vCPU does not get past the instruction in 30 ms, it is waiting on a held vCPU: in the measurements, every run alone that finished did so within 24 ms. It is then in the hypervisor, still on the instruction, or in the handler of an interrupt that it took first (from VTL1, this is NT's handler, in VTL0).

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

A state that passes can still be one exit behind. KVM copies the guest state of a VM exit into the eVMCS on its way into the hypervisor, not when the exit happens, so a stop that falls between the two finds the vCPU on the hypervisor's `host_rip` and the page still holding the previous exit. `ntoseye` treats every state as possibly stale while the vCPU's RIP is the page's `host_rip`, unless the vCPU stopped there on one of the session's instruction breakpoints: those fire only once the vCPU executes in the hypervisor, after the write. On sampled stops under load, most hypervisor stops were on `host_rip`, and for an `rdmsr` exit 106 of 144 such pages already had RIP past the instruction, which a freshly written page cannot have.

## The general-purpose registers of an exit

A VMCS holds RIP and RSP but no other general-purpose register. On a VM exit the rest stay in the CPU, and the hypervisor's entry point (the eVMCS `host_rip`, which runs on `host_rsp`) saves them. Where it saves them is a detail of the hypervisor build, so `ntoseye` reads it off the entry code instead of keeping offsets:

1. It follows the code from `host_rip` until the first branch, call, or return. It tracks every register as either the guest's value or an address computed from `host_rsp` (add an offset, load a qword, and so on), and it tracks the memory that the code stores guest registers to. A later write that overlaps a stored register forgets it, and a write through a register that holds neither (or with an index) forgets all of them. Memory reached through different loads, and fixed addresses such as `gs:0x85`, count as different memory.
2. It accepts the result only when all fifteen registers other than RSP end up in one block, each once, behind one chain of loads from `host_rsp`. A register that the code overwrites before it saves it, or an entry that branches first, gives no registers.
3. It remembers the result for the boot, by entry point, and reads the block through the hypervisor's address space at each stop.

The block holds the last exit, from whichever VTL made it. General-purpose registers are shared between VTLs (TLFS, Virtual Secure Mode), so they belong to the virtual processor, and `ntoseye` attaches them only to the current VTL's saved state. They are also not there while the vCPU is on `host_rip` or still in the stores, where the guest's registers are still the vCPU's own. A VM exit loads only RSP and RIP, so at a breakpoint on `host_rip`, where the state is current, `ntoseye` takes them from the vCPU. After the stores, the hypervisor works on the block in place: for an `rdmsr` it handled, RDX:EAX already holds the value it returns.

Every `hvix64` checked saves the registers in encoding order, at offsets 0 to 0x78 of the block: 10.0.16299.15, 10.0.17134.1, 10.0.17763.1, 10.0.18362.1, 10.0.19041.1, 10.0.22000.1, 10.0.22621.1, 10.0.26100.1, 10.0.26100.9444, and 10.0.28000.1. From 10.0.17763 the block is at `[[host_rsp+0x20]]`; 10.0.16299 and 10.0.17134 keep it one load closer, at `[host_rsp+0x20]`. The Windows 11 builds also have a fast-path entry that reads the exit reason before it saves only the volatile registers elsewhere, which `ntoseye` refuses. `tools/fetch_hvix64.py` downloads these images for the test that checks them. On the 10.0.26100.9444 guest, hardware breakpoints on `host_rip` and on the entry code's first call matched the registers `ntoseye` read on 400 of 400 exits, 200 with HVCI off and 200 with it on. The live test `test_saved_general_registers_are_the_exits` repeats that check.

## Partitions and virtual processors

`hvix64` has no public symbols, so {command}`!hvpartitions` and {command}`!hvvps` read the offsets of the hypervisor's partition and VP objects from its own code. The anchor is the hypercall table, an array of 24-byte entries, each with a handler and the call code that the Hyper-V TLFS assigns to it. `ntoseye` finds it as the run of entries whose call code is their index, and then follows the handlers of these hypercalls through every branch, inlining their direct calls:

- `HvCallGetNextChildPartition` calls a walker that reads a child's parent and its link in the parent's child list, compares the link with the parent's list head, and loads the next child's ID at a fixed distance from its link. This gives the parent, the list head, the link, and the partition ID.
- `HvCallGetPartitionId` stores the calling partition's ID after it tests the partition's AccessPartitionId privilege (bit 33). This gives where the processor block (the GS base) holds the current partition, and the privilege mask. Its ID offset must be the one that the child walker uses.
- The VP lookup that `HvCallGetVpRegisters`, `HvCallSetVpRegisters`, and `HvCallEnableVpVtl` use bounds a VP index with the partition's capacity and loads the VP from the partition's array. All lookups found must agree.
- `HvCallVtlReturn` reads its VP's current VTL context, reads that context's VTL level, and indexes the VP's array of VTL contexts with the level.
- `HvCallVtlCall` ANDs the VTLs above the current one with the VP's mask of enabled VTLs. The VTL array also holds contexts that the hypervisor allocated for VTLs that the partition did not enable, so only the VTLs in this mask are listed.

The current partition is reached differently between builds: directly from the processor block (`gs:82E8h` in 10.0.16299, `gs:360h` in 10.0.26100), or through the current VP (10.0.28000). `ntoseye` evaluates each way that the code takes on each processor block and keeps the partition that validates:

- A partition's child list must be a ring in which each link's back pointer is the link before it, and each child must name the partition as its parent.
- A VP's current VTL must be enabled, its context must be the entry of its VTL array at that context's level, and each enabled VTL's context must hold its own level.

From any valid partition, `ntoseye` follows the parents to the root partition and then lists every child list from there.

A VTL context keeps its VMCS in a VMCS object, and the hypervisor loads that VMCS with `vmptrld [object + address]`, or, with the enlightenment, stores the same address to `current_nested_vmcs` in the VP assist page. For each `vmptrld` in the image, `ntoseye` takes the load that produced the object register, `[base + object]`, following up to three register-to-register copies back to it, and adds a `lea base, [context + offset]` before it when there is one. This gives a few candidates for each build, for example `0x13e8` and `0x188` in 10.0.26100 and `0x13a8` and `0x190` in 10.0.28000, where the object is the context itself at another offset. `ntoseye` then uses the candidate under which the most VTL contexts point at pages that the eVMCS scan found, and names no VMCS if no candidate does or if two candidates match equally often. When the scan found eVMCS pages but no VTL context leads to one, which a build that loads its VMCS another way would cause, {command}`!hvvps` says so below its table rather than leaving the eVMCS columns empty without a reason. The EPT pointer and the other state come from the eVMCS page itself, whose layout the TLFS defines.

Each hypercall table entry holds, after the handler and the call code, a word of flags and the sizes of the fixed input, each rep input element, the fixed output, and each rep output element. Bit 0 of the flags marks a rep call, and bit 1 a variable-size input header, which the TLFS `...Ex` calls have. In every build that `ntoseye` checks, each call that the TLFS documents and the build implements has the rep bit that the TLFS gives it.

This method recognizes 10.0.16299.15, 10.0.17134.1, 10.0.17763.1, 10.0.18362.1, 10.0.19041.1, 10.0.22000.1, 10.0.22621.1, 10.0.26100.1, 10.0.26100.9444, and 10.0.28000.1, whose offsets differ between releases: the partition ID moves from `0xc70` to `0x4630`, and a partition holds up to 0x140, 0x400, or 0x800 VPs. The same test as for the exit registers checks these images (`cargo test --lib hv_layout -- --ignored`).

