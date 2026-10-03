# The secure kernel (VTL1)

When virtualization-based security (VBS) runs, Windows runs a second kernel, `securekernel.exe`, in Virtual Trust Level 1 (VTL1), together with isolated user-mode processes (trustlets) such as `LsaIso.exe`. `ntoseye` can inspect this memory on an AMD64 guest when it reads the guest memory directly from the host.
The Python SDK shows the same data through [`dbg.secure_kernel`](../scripting/sdk.md#secure-kernel-vtl1).

## Requirements

VTL1 inspection needs direct host memory. The `memory` and `gdb` backends can inspect VTL1, and `kd` and `kdnet` can too while they read from host memory, which is the case with `--memory-source host`, or with `auto` after the host mapping matched. `kd` and `kdnet` cannot control VTL1 execution.

ntoseye does not support VTL1 inspection for crash dumps, with `--memory-source kd`, or on ARM64 targets. Memory integrity (HVCI) is not necessary.

VBS needs a VM that gives nested virtualization to the guest, and the [KVM/QEMU setup](../setup/kvm-qemu.md#virtualization-based-security-vbs) gives a CPU model that works.

When VBS runs, Windows does not allow KD writes to user-mode code pages, physical or virtual, although KD writes to data pages and to kernel code succeed. Because of this, `kd` and `kdnet` cannot set user-mode breakpoints, and `bp` shows the error that the target gives.

## Inspecting VTL1 memory

- {command}`.vtl` `[0|1 [pid]]`: Show or select the inspection scope.
  - A bare {command}`.vtl` shows the current scope.
  - `0` goes back to the NT kernel. After `1`, it returns to the view that the stop selected, which at a stop in the Windows hypervisor is where NT left off. Otherwise, at a stop in VTL1 or in the Windows hypervisor, `0` selects the vCPU's own address space, and you use {command}`.vtlcxr` or {command}`.thread` to select NT.
  - `1` selects the system address space of the secure kernel.
  - `1 <pid>` selects the address space of a trustlet by its NT PID, which is always decimal.
- {command}`!trustlets`: Show a list of secure-kernel processes with the process object, the NT PID and image name, the trustlet ID, and the address-space root of each.

```text
.vtl 1
lm
x securekernel!Skps*
!trustlets
.vtl 1 936
.vtl 0
```

:::{warning}
{command}`.vtl` changes only the scope that the debugger inspects and does not change the virtual trust level in which the CPU executes. When you select a scope, ntoseye clears the cached registers.

In the explicit VTL1 memory view, ntoseye does not accept writes, register and stack commands, or NT-specific and custom extensions. You can use hardware execution breakpoints and plain {command}`g`, which leaves the memory view before it resumes the target. At each stop, ntoseye restores the context of the vCPU that actually halted.

At a real VTL1 stop, {command}`r`, {command}`k`, {command}`.frame`, {command}`u`, and memory reads show the VTL1 state instead of the suspended NT thread. `lm k` shows the NT modules, and a plain {command}`lm` shows the modules of the selected secure kernel.
:::

The first `.vtl 1` finds the secure kernel in guest RAM, and ntoseye keeps the result for the session ([how](internals.md#finding-the-secure-kernel)). If NT reports that VSM did not start (`nt!VslVsmEnabled` is 0), `.vtl 1` fails immediately.

In VTL1 scope, {command}`lm`, {command}`x`, {command}`ln`, {command}`u`, {command}`db`/{command}`dq`, {command}`dt`, {command}`!vtop`, and {command}`.reload` operate on the modules of the secure kernel, which are `securekernel.exe`, `skci.dll`, and the other modules that the secure kernel loaded.

You can still use `nt!` types, for example `dt nt!_KLDR_DATA_TABLE_ENTRY <address>`. However, ntoseye does not resolve NT address symbols in VTL1 scope or secure-kernel symbols in VTL0, because the modules of each kernel are mapped only in the address spaces of that kernel. Microsoft's public `securekernel.pdb` does not contain types.

## Breakpoints and stepping in VTL1

The `gdb` backend on AMD64 QEMU/KVM supports hardware execution breakpoints in loaded secure-kernel modules. When a breakpoint stops the target, you can inspect the target and continue, for example:

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

`ba e1` uses QEMU's host debug-register breakpoint (`Z1`) and does not patch secure code. The breakpoints apply to all vCPUs and use the same four hardware slots as other hardware breakpoints. You can filter hits with `/c` and with register conditions, but ntoseye does not accept the NT filters `/p` and `/t`, because they cannot describe secure-kernel execution.

ntoseye identifies secure-system and trustlet roots by their mapping of the secure kernel. A stop shows `VTL1`, the real CPU registers, and the secure-kernel stack frames, and ntoseye does not attribute an NT thread to that CPU. `.vtl 0` leaves an explicit memory view, but it does not move a CPU that stopped in VTL1 back into NT.

At a VTL1 stop, {command}`t`, {command}`p`, {command}`gu`, {command}`pa`/{command}`ta`, {command}`wt`, and `g <address>` run through secure-kernel code. They use free debug-register slots: a step uses one slot for each place where the instruction can continue, and a run-to command uses one slot for its target. For more information, see [stepping under the Windows hypervisor](internals.md#stepping-without-the-trap-flag). In the `.vtl 1` memory view, you can use only plain {command}`g`.

ntoseye does not support these operations:

- Software breakpoints in known secure modules.
- Writes to secure memory or to secure registers.
- Data watches.
- Breakpoints in trustlet user code.

ntoseye resolves the address of a hardware breakpoint once, so you must set the breakpoint again after a reboot. Do not keep the target stopped for a long time, because the full VM stays halted.

Hardware execution breakpoints also work in the Windows hypervisor itself (`hvix64`), without a software code patch. To set one, use {command}`~` and {command}`vcpu` to select the register and address-space context of the hypervisor, and then use `ba e1 <address>` or `ba e1 hv+<offset>`. These breakpoints use linear addresses and are not VTL-tagged breakpoints. They use the same four hardware slots, which all vCPUs share.

Hardware breakpoints do not write to integrity-sensitive code, but they can be visible and can have side effects. While host debugging is active, KVM controls the debug-register breakpoint state, and the upstream [nested VMX handling](https://github.com/torvalds/linux/blob/master/arch/x86/kvm/vmx/nested.c) documents an interaction with `KVM_GUESTDBG_USE_HW_BP` that can cause the loss of L1's own DR7 state. Do not assume that simultaneous guest and hypervisor hardware debugging keeps the state of both debuggers.

## Trustlet enumeration

{command}`!trustlets` reads secure-kernel structures that the public symbols do not describe ([how](internals.md#trustlet-enumeration)). It recognizes every build that we examined, from 10.0.19041 (Windows 10 20H1) to 10.0.28000. Older secure kernels do not have these routines with these names, so {command}`!trustlets` gives an error on them, but you can still inspect the secure kernel and its modules.

ntoseye does not list the modules that are loaded in a trustlet. The lists that {command}`!trustlets` walks are live and are not atomic snapshots, so the walk can become incorrect if a process exits or a module unloads during it.
