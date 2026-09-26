# VBS and the Windows hypervisor

With virtualization-based security (VBS) running, Windows runs a second kernel, `securekernel.exe`, in Virtual Trust Level 1 alongside isolated user-mode processes (trustlets such as `LsaIso.exe`). `ntoseye` can inspect that memory on an AMD64 guest whose memory it reads directly from the host.
The Python SDK exposes the same views as [`dbg.secure_kernel`](../scripting/sdk.md#secure-kernel-vtl1).

:::{important}
VTL1 inspection is experimental. It relies on undocumented secure-kernel structures, finds them heuristically, and has been tested live on a single guest: Windows 11 10.0.26100 under QEMU/KVM, with memory integrity (HVCI) both off and on. It may fail on other builds or hosts, and it refuses rather than guesses when a structure is not recognized.
:::

## Requirements

VTL1 requires direct host memory. Inspection works with the `memory` and `gdb` backends; `kd` and `kdnet` can inspect VTL1 only while reads come from host memory (`--memory-source host`, or `auto` once the host mapping matched), and cannot control VTL1 execution. Crash dumps, `--memory-source kd`, and ARM64 targets are unsupported. Memory integrity (HVCI) is not required.

VBS itself needs nested virtualization exposed to the VM; the [KVM/QEMU setup](../setup/kvm-qemu.md#virtualization-based-security-vbs) covers the tested CPU model.

## Inspecting VTL1 memory

- {command}`.vtl` `[0|1 [pid]]`: Display or select the inspection scope. A bare {command}`.vtl` prints the current scope, `0` returns to the NT kernel, `1` selects the secure kernel's system address space, and `1 <pid>` selects a trustlet's address space by its NT PID (always decimal).
- {command}`!trustlets`: List secure-kernel processes: the secure-kernel process object, NT PID and image name, trustlet ID, and address-space root.

```text
.vtl 1
lm
x securekernel!Skps*
!trustlets
.vtl 1 936
.vtl 0
```

:::{warning}
{command}`.vtl` changes what the debugger inspects, not the virtual trust level the CPU is executing. Cached registers are cleared on selection. The explicit VTL1 memory view rejects writes, register/stack commands, and NT-specific or custom extensions. Hardware execution breakpoints and plain {command}`g` are allowed; {command}`g` leaves the memory view before resuming. Any stop restores the actual halted vCPU's context. At a real VTL1 stop, {command}`r`, {command}`k`, {command}`.frame`, {command}`u`, and memory reads inspect VTL1 state, not the suspended NT thread. `lm k` explicitly lists NT modules; plain {command}`lm` lists the selected secure kernel's modules.
:::

The first `.vtl 1` finds the secure kernel in guest RAM and keeps it for the session ([how](../internals/vbs.md#finding-the-secure-kernel)); when NT reports that VSM never started (`nt!VslVsmEnabled` is 0), it fails at once. In VTL1 scope, {command}`lm`, {command}`x`, {command}`ln`, {command}`u`, {command}`db`/{command}`dq`, {command}`dt`, {command}`!vtop`, and {command}`.reload` operate on the secure kernel's modules (`securekernel.exe`, `skci.dll`, and the other modules it loaded). `nt!` types remain available (`dt nt!_KLDR_DATA_TABLE_ENTRY <address>`), but NT's address symbols are not resolved in VTL1 scope, and secure-kernel symbols are not resolved in VTL0, because each kernel's modules are mapped only in its own address spaces. Microsoft's public `securekernel.pdb` carries no types.

## Breakpoints and stepping in VTL1

The AMD64 QEMU/KVM `gdb` backend supports hardware execution breakpoints in loaded secure-kernel modules, followed by inspection and continue:

```text
.vtl 1
ba e1 securekernel!SkeSelectProcessAddressSpace
g
r
k
.vtl
g
bc *
```

`ba e1` uses QEMU's host debug-register breakpoint (`Z1`), without patching secure code. Breakpoints apply to all vCPUs and share the four hardware slots with other hardware breakpoints. `/c` and register conditions can filter hits; NT `/p` and `/t` filters cannot describe secure-kernel execution and are refused. Secure-system and trustlet roots are recognized by their mapping of the secure kernel. Stops show `VTL1`, real CPU registers, and secure-kernel stack frames; no NT thread is attributed to that CPU. `.vtl 0` leaves an explicit memory view; it does not move a CPU stopped in VTL1 back into NT.

At a VTL1 stop, {command}`t`, {command}`p`, {command}`gu`, {command}`pa`/{command}`ta`, {command}`wt`, and `g <address>` run through secure-kernel code using free debug-register slots: a step takes one per place the instruction can continue at, a run-to one for its target (see [stepping under the Windows hypervisor](../internals/vbs.md#stepping-without-the-trap-flag)). The `.vtl 1` memory view accepts only plain {command}`g`. Software breakpoints in known secure modules, secure memory/register writes, data watches, and trustlet user-code breakpoints are not supported. Hardware sites resolve once and must be recreated after a reboot. Avoid stopping for long periods: the whole VM is halted. This path was exercised on the same Windows 11 QEMU/KVM guest with HVCI on and off; that is not a guarantee against integrity checks or different nested-virtualization behavior on other hosts.

Hardware execution breakpoints were also exercised at the running `hvix64` idle address, with repeated hits and continue. Use {command}`~` and {command}`vcpu` to select its register/address-space context, then `ba e1 <address>`; no software code patch is needed. These are linear-address breakpoints, not VTL-tagged breakpoints, and use the same four hardware slots across vCPUs.

Hardware breakpoints avoid integrity-sensitive code writes, but they are not invisible or side-effect-free. KVM owns the debug-register breakpoint state while host debugging is active. Upstream [nested VMX handling](https://github.com/torvalds/linux/blob/master/arch/x86/kvm/vmx/nested.c) documents an interaction that can lose L1's own DR7 state with `KVM_GUESTDBG_USE_HW_BP`; do not assume simultaneous guest/hypervisor hardware debugging preserves both debuggers' state. The tested guest remained responsive, including with HVCI enabled; other kernel/QEMU versions and hosts remain unverified.

## Trustlet enumeration

{command}`!trustlets` reads secure-kernel structures that public symbols do not describe ([how](../internals/vbs.md#trustlet-enumeration)). It recognizes every build examined from 10.0.19041 (Windows 10 20H1) through 10.0.28000. Older secure kernels lack these routines under these names, so enumeration is refused there while secure-kernel/module inspection remains available. Modules loaded inside a trustlet are not enumerated. Live lists are not atomic snapshots; concurrent process exit or module unload can invalidate a walk.

## Stops in the Windows hypervisor

With VBS running, the GDB stub reports what each vCPU was executing when it halted, and an idle vCPU is usually inside the Windows hypervisor itself, with its own CR3. `ntoseye` names such a stop by the image it is in: the context reads `hypervisor` (or `VTL1` for the secure kernel), and code and stack frames read `hvix64+0x…`. Microsoft publishes no symbols for this hypervisor build and its address space does not map its unwind data, so hypervisor frames past the first are stack-scan guesses (`[scan]`). {command}`bp` and the bugcheck trap work whichever address space the vCPU stopped in ([how](../internals/vbs.md#breakpoints-while-vcpus-are-outside-nt)).

Hyper-V's NT-side drivers use ordinary NT module/symbol inspection. The hypervisor itself has raw memory/register inspection, image-plus-offset stack labels, and the [VTL state it saved](#where-nt-left-off-under-the-hypervisor) for each vCPU halted in it, not structured partition or virtual-processor enumeration. Public symbols/unwind data are unavailable for the tested hypervisor build, so this does not provide full Hyper-V internals or reliable unwinding there.

:::{important}
While Windows runs its own hypervisor (VBS, Hyper-V, WSL2), the `gdb` backend steps without the trap flag, which can freeze such a guest ([how](../internals/vbs.md#stepping-without-the-trap-flag)). Stepping and resuming from breakpoints work as usual, with two differences: a step through `syscall`, `sysret`, `int`, or a far transfer is refused (use the `kd` or `kdnet` backend for those), and a breakpoint on a hot kernel function can occasionally report the same execution twice (1-2% of hits under stress).
:::

### Where NT left off under the hypervisor

A vCPU halted in the Windows hypervisor has put aside what its VTLs were doing, and the hypervisor keeps that in its own memory. `ntoseye` reads it from Enlightened VMCS pages, whose layout the Hyper-V TLFS defines, so it depends on no hypervisor build. The hypervisor uses them only when the VM exposes the `hv-evmcs` enlightenment ([KVM/QEMU setup](../setup/kvm-qemu.md#virtualization-based-security-vbs)); a plain nested VMCS is in a CPU-private format that KVM keeps out of guest memory.

The stop header then names where VTL0 left off (`saved VTL0 nt!HalProcessorIdle+0xf`), as does {command}`~`, and {command}`.vtlcxr` lists each VTL's saved state with why it last entered the hypervisor (`HLT`, `VMCALL`, ...) and selects VTL0's, so {command}`r`, {command}`k`, and {command}`u` follow NT's code and stack on that processor. {command}`.cxr` returns to the live registers. The saved context has RIP, RSP, flags, control and segment registers, and no other general-purpose registers: the hypervisor keeps those in undocumented state. VTL1's saved state is listed but not selectable, and its RIP resolves once the secure kernel is discovered (`.vtl 1`).

The pages are found by scanning host RAM once per boot, the first time a stop, {command}`~`, or {command}`.vtlcxr` meets a vCPU in the hypervisor (about 0.6 s for an 8 GiB guest), and once more for a vCPU the scan found no pages for, which a stop early in boot can make. A saved state that fails validation is refused rather than shown ([how](../internals/vbs.md#reading-the-saved-vtl-state)). Tested on a Core i9-14900F host with a 4-vCPU Windows 11 guest; AMD hosts, whose nested state uses a different structure, are not supported.
