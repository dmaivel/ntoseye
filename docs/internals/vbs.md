# VBS internals

How [VBS inspection](../platforms/vbs.md) works: what `ntoseye` reads, how it recognizes it, and what it refuses. None of it is needed to use the feature.

## Finding the secure kernel

The first `.vtl 1` discovers the secure kernel by scanning guest RAM for its page tables and accepting an image only when its CodeView record names `securekernel.pdb`; the result is kept for the session. When NT reports that VSM never started (`nt!VslVsmEnabled` is 0), it fails at once instead of scanning.

## Trustlet enumeration

Trustlet enumeration reads secure-kernel process fields that public symbols do not describe. `ntoseye` recovers their offsets from the secure kernel's own code: the list link from where `SkpsInitializeProcess` links a new process onto `SkpsProcessList`, the NT PID and trustlet ID from the `IumProcessStartFailed` event it reports them with, and the address-space root from `SkeSelectProcessAddressSpace`. The trustlet ID must also be a field `SkpsReadPolicyMetadata` checks against the image's policy. Every record is then validated: its root must map the secure kernel and its PID must match an NT process. This recognizes every build examined from 10.0.19041 (Windows 10 20H1) through 10.0.28000, whose offsets differ between releases.

## Breakpoints while vCPUs are outside NT

QEMU plants kernel breakpoints through the selected vCPU's page tables, which do not map NT there. Its software breakpoints apply to every vCPU, so `ntoseye` retries such a breakpoint through another vCPU halted in NT. Only when every vCPU is outside NT does it borrow the NT kernel's page tables on the selected vCPU for that one packet, restoring the vCPU's CR3 immediately. Either way {command}`bp` and the bugcheck trap work whichever address space the vCPU stopped in. If `ntoseye` were killed during that borrowed-CR3 packet, the vCPU would resume with the wrong CR3 and the guest would crash.

## Stepping without the trap flag

While Windows runs its own hypervisor (VBS, Hyper-V, WSL2), the GDB backend never uses the trap flag. Windows runs nested under that hypervisor, and a KVM single step of its vCPU can complete inside the hypervisor with the trap flag still set in Windows, which then takes the trap itself; with a kernel debugger configured, that froze the tested guest. `ntoseye` reads `nt!HvlHyperVRootPartition` to tell. It then executes one instruction, for a step ({command}`t`, {command}`p`, {command}`wt`, the SDK's stepping calls) or to resume from a breakpoint, by running that vCPU alone, with the others held, to a temporary breakpoint on each place the instruction can continue at (both arms of a branch, a `ret`'s return address, an indirect `call`/`jmp`'s target). In secure-kernel code those temporary sites are debug-register breakpoints in free slots, so no VTL1 code is written; a VTL1 step needs one free slot per successor. A vCPU that has not got past the instruction after 100 ms is usually waiting on a held one; it is then broken in on. If it moved (most often into an interrupt handler), the step reports where it stopped and a breakpoint resume continues with the breakpoint armed again, so that execution can report a second hit (1-2% of hits on hot kernel functions when stress-tested under VBS). Only a vCPU still on the instruction after the break-in fails. Instructions whose next address cannot be computed from the stop (`syscall`, `sysret`, `int`, far transfers) are refused; use the `kd` or `kdnet` backend to step through those.

## Reading the saved VTL state

A page counts as an eVMCS only with the TLFS version, paging on, and an upper-half hypervisor entry point; it belongs to a vCPU when its hypervisor root is that vCPU's CR3; its state counts as VTL0 only in an NT address space and, in kernel mode, with that processor's KPCR as its GS base, and as VTL1 only in a secure-kernel address space. A state that fails these checks is refused rather than shown.
