# VBS and the Windows hypervisor

When virtualization-based security (VBS) runs, Windows runs a second kernel, `securekernel.exe`, in Virtual Trust Level 1 (VTL1), together with isolated user-mode processes (trustlets) such as `LsaIso.exe`. `ntoseye` can inspect this memory on an AMD64 guest when it reads the guest memory directly from the host.
The Python SDK shows the same data through [`dbg.secure_kernel`](../scripting/sdk.md#secure-kernel-vtl1).

## Should VBS be on?

VBS can run only if the VM gives nested virtualization to the guest, which is the "Virtualize Intel VT-x/EPT" option in VMware and a CPU with `vmx` in KVM/QEMU. UTM under Apple's hypervisor does not have nested virtualization. Windows 11 turns on VBS by default when the hardware allows it, and Hyper-V or WSL2 in the guest also start the hypervisor. To see if VBS runs, use `msinfo32` in the guest.

If you debug drivers or the kernel, turn off VBS unless your work needs it, because it brings these limits:

- Windows does not allow KD to write to user-mode code, so a user-mode breakpoint over KD uses one of the four hardware slots ({command}`ba` `e1`).
- The `gdb` backend cannot single-step with the trap flag, so it runs the vCPU alone to the next instruction. Sometimes a step ends early, in an interrupt handler or in another thread ([how](../internals/vbs.md#stepping-without-the-trap-flag)).
- A vCPU can stop inside the Windows hypervisor, where you cannot step until the guest resumes.

Keep VBS on when you:

- Research VBS and the secure kernel, which is what the rest of this page is about.
- Test a driver under Memory integrity (HVCI) before release, because a production driver must load when Memory integrity is on.
- Debug a problem that occurs only when VBS is on.

To turn off VBS:

1. In the guest, run this command from an elevated prompt:

   ```text
   bcdedit /set hypervisorlaunchtype off
   ```

2. Reboot the guest.

This stops the Windows hypervisor, so Hyper-V, WSL2, and Windows Sandbox in the guest also stop. To turn the hypervisor on again, run `bcdedit /set hypervisorlaunchtype auto` and reboot the guest.

:::{important}
The VTL1 features on this page need an **AMD64 guest** and are not available on ARM64 guests. Support also depends on the host CPU:

| Feature | Backends | Intel host | AMD host |
| --- | --- | --- | --- |
| VTL1 memory, symbols, and {command}`!trustlets` | `memory`, `gdb`; `kd`/`kdnet` reading host memory | Supported | Untested |
| VTL1 breakpoints and stepping | `gdb` on QEMU/KVM | Supported | Untested |
| Stepping NT while the Windows hypervisor runs | `gdb` | Supported | Untested |
| [Where NT left off](#where-nt-left-off-under-the-hypervisor) under the hypervisor | `gdb` | Supported (needs `hv-evmcs`) | Not supported |

We tested all of these features on one host, a Core i9-14900F with QEMU/KVM, with Windows 11 guests (10.0.26100 and 10.0.26200) and memory integrity (HVCI) both off and on.

VTL1 inspection is experimental. It finds undocumented secure-kernel structures by heuristics, so it can fail on other Windows builds. If ntoseye does not recognize a structure, it shows an error instead of the data.
:::

## Requirements

VTL1 inspection needs direct host memory. The `memory` and `gdb` backends can inspect VTL1, and `kd` and `kdnet` can too while they read from host memory, which is the case with `--memory-source host`, or with `auto` after the host mapping matched. `kd` and `kdnet` cannot control VTL1 execution.

ntoseye does not support VTL1 inspection for crash dumps, with `--memory-source kd`, or on ARM64 targets. Memory integrity (HVCI) is not necessary.

VBS needs a VM that gives nested virtualization to the guest, and the [KVM/QEMU setup](../setup/kvm-qemu.md#virtualization-based-security-vbs) gives a CPU model that works.

When VBS runs, Windows does not allow KD writes to user-mode code pages, physical or virtual, although KD writes to data pages and to kernel code succeed. Because of this, `kd` and `kdnet` cannot set user-mode breakpoints, and `bp` shows the error that the target gives.

## Inspecting VTL1 memory

- {command}`.vtl` `[0|1 [pid]]`: Show or select the inspection scope.
  - A bare {command}`.vtl` shows the current scope.
  - `0` goes back to the NT kernel. At a stop in VTL1 or in the Windows hypervisor, `0` selects the vCPU's own address space, and you use {command}`.vtlcxr` or {command}`.thread` to select NT.
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

The first `.vtl 1` finds the secure kernel in guest RAM, and ntoseye keeps the result for the session ([how](../internals/vbs.md#finding-the-secure-kernel)). If NT reports that VSM did not start (`nt!VslVsmEnabled` is 0), `.vtl 1` fails immediately.

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

At a VTL1 stop, {command}`t`, {command}`p`, {command}`gu`, {command}`pa`/{command}`ta`, {command}`wt`, and `g <address>` run through secure-kernel code. They use free debug-register slots: a step uses one slot for each place where the instruction can continue, and a run-to command uses one slot for its target. For more information, see [stepping under the Windows hypervisor](../internals/vbs.md#stepping-without-the-trap-flag). In the `.vtl 1` memory view, you can use only plain {command}`g`.

ntoseye does not support these operations:

- Software breakpoints in known secure modules.
- Writes to secure memory or to secure registers.
- Data watches.
- Breakpoints in trustlet user code.

ntoseye resolves the address of a hardware breakpoint once, so you must set the breakpoint again after a reboot. Do not keep the target stopped for a long time, because the full VM stays halted.

Hardware execution breakpoints also work in the Windows hypervisor itself (`hvix64`), without a software code patch. To set one, use {command}`~` and {command}`vcpu` to select the register and address-space context of the hypervisor, and then use `ba e1 <address>`. These breakpoints use linear addresses and are not VTL-tagged breakpoints. They use the same four hardware slots, which all vCPUs share.

Hardware breakpoints do not write to integrity-sensitive code, but they can be visible and can have side effects. While host debugging is active, KVM controls the debug-register breakpoint state, and the upstream [nested VMX handling](https://github.com/torvalds/linux/blob/master/arch/x86/kvm/vmx/nested.c) documents an interaction with `KVM_GUESTDBG_USE_HW_BP` that can cause the loss of L1's own DR7 state. Do not assume that simultaneous guest and hypervisor hardware debugging keeps the state of both debuggers.

## Trustlet enumeration

{command}`!trustlets` reads secure-kernel structures that the public symbols do not describe ([how](../internals/vbs.md#trustlet-enumeration)). It recognizes every build that we examined, from 10.0.19041 (Windows 10 20H1) to 10.0.28000. Older secure kernels do not have these routines with these names, so {command}`!trustlets` gives an error on them, but you can still inspect the secure kernel and its modules.

ntoseye does not list the modules that are loaded in a trustlet. The lists that {command}`!trustlets` walks are live and are not atomic snapshots, so the walk can become incorrect if a process exits or a module unloads during it.

## Stops in the Windows hypervisor

When VBS runs, the GDB stub reports what each vCPU executed when it halted. An idle vCPU is usually inside the Windows hypervisor, with the hypervisor's own CR3. `ntoseye` names such a stop by the image in which the vCPU stopped. The context shows `hypervisor`, or `VTL1` for the secure kernel, and code and stack frames show `hvix64+0x…`.

Microsoft does not publish symbols for this hypervisor build, and the address space of the hypervisor does not map its unwind data, so all hypervisor frames after the first frame are guesses from a stack scan (`[scan]`).

Because the CR3 of the hypervisor does not map NT memory, ntoseye inspects such a stop at the point where NT left off ([below](#where-nt-left-off-under-the-hypervisor)). {command}`bp` and the bugcheck trap work in all address spaces in which the vCPU can stop ([how](../internals/vbs.md#breakpoints-while-vcpus-are-outside-nt)).

For the NT-side drivers of Hyper-V, you use the usual NT module and symbol inspection. For the hypervisor itself, ntoseye gives raw memory and register inspection, stack labels as image plus offset, and the [VTL state that the hypervisor saved](#where-nt-left-off-under-the-hypervisor) for each vCPU halted in it.

ntoseye does not give a structured list of partitions or virtual processors. In the SDK, `cpu.memory` reads the address space of the hypervisor and `cpu.saved_vtl` reads the saved VTL state ([Python SDK](../scripting/sdk.md#secure-kernel-vtl1)). Because Microsoft does not publish symbols or unwind data for the hypervisor, ntoseye does not show all Hyper-V internals, and stack unwinding in the hypervisor is not reliable.

:::{important}
When Windows runs its own hypervisor (VBS, Hyper-V, WSL2), the `gdb` backend steps without the trap flag, because the trap flag can freeze such a guest ([how](../internals/vbs.md#stepping-without-the-trap-flag)). Steps and resumes from breakpoints work as usual, including through `syscall`, `sysret`, `iretq`, `int`, hypercalls, and far transfers.

The one difference is that a step sometimes ends early, in an interrupt handler or in another thread that the handler switched to. This happens in about 2 of 1,000 steps in kernel code, and ntoseye then shows a notice. Use {command}`g` to resume.

Step-until walks ({command}`pa`, {command}`ta`, {command}`pc`, {command}`tc`, and the SDK's `until=` and `run_to(step=)`) and call traces ({command}`wt` and `trace_calls()`) do not end early at such a point. They run until their thread has executed the instruction, and then continue.
:::

### Where NT left off under the hypervisor

When a vCPU halts in the Windows hypervisor, the hypervisor keeps the state of that vCPU's VTLs in its own memory. `ntoseye` reads this state from Enlightened VMCS pages, whose layout the Hyper-V TLFS defines, so this method does not depend on a hypervisor build. The hypervisor uses these pages only if the VM gives the `hv-evmcs` enlightenment ([KVM/QEMU setup](../setup/kvm-qemu.md#virtualization-based-security-vbs)). A plain nested VMCS has a CPU-private format, and KVM keeps it out of guest memory.

ntoseye then inspects a stop in the hypervisor at the point where VTL0 left off. The stop header shows this point (`saved VTL0 nt!HalProcessorIdle+0xf`) with its registers, code, and stack, and {command}`r`, {command}`k`, {command}`u`, memory reads, and expressions use the NT state on that processor. The same applies when you switch to such a vCPU with `~Ns` ({command}`~`) or with a bare {command}`.thread`, and when a DAP client gets the stack of each vCPU that is halted in the hypervisor.

{command}`.cxr` goes back to the registers, stack, and address space of the hypervisor, and {command}`.vtlcxr` selects the NT context again. {command}`.vtlcxr` also shows the saved state of each VTL and the reason why that VTL last entered the hypervisor (`HLT`, `VMCALL`, ...).

The saved context has RIP, RSP, flags, control registers, and segment registers from the eVMCS. The eVMCS does not hold the other general-purpose registers: the hypervisor's VM-exit entry code saves them itself. ntoseye reads that code to find where ([how](../internals/vbs.md#the-general-purpose-registers-of-an-exit)) and adds RAX to R15 to the context of the current VTL, so {command}`r`, expressions, and stack walks that need a frame pointer have them. This is experimental. The registers are missing, and {command}`.vtlcxr` says why, for a VTL that is not the current one, while the vCPU is on the entry point or still saving them, and when the entry code does not save them in one place before it first branches. {command}`.vtlcxr` shows the saved state of VTL1, but you cannot select it. ntoseye resolves the RIP of VTL1 after it finds the secure kernel (`.vtl 1`).

Because such a vCPU runs hypervisor code, ntoseye does not step it, and {command}`t`, {command}`p`, {command}`gu`, {command}`wt`, and the other step commands give an error. {command}`g` resumes the vCPU. The registers of the vCPU are read-only in all selected contexts. If there is no saved state, which happens when the VM does not have `hv-evmcs` or on an AMD host, the stop stays in the context of the hypervisor.

A vCPU can also stop on the first instruction of the hypervisor's VM-exit handler (the eVMCS `host_rip`). KVM writes the saved state when it enters the hypervisor, and such a stop can fall between a VM exit and that entry, so the saved state may still describe the previous exit. Under load this is common. ntoseye marks such a state `(may be one exit behind)` in the stop header, {command}`~`, and {command}`.vtlcxr`, and does not select it or start stacks from it on its own. {command}`.vtlcxr` still selects it when you ask. The guest's general-purpose registers at that point are the vCPU's own registers.

The NT thread that runs on that processor also starts from the same saved state everywhere that ntoseye shows this thread:

- {command}`!thread` shows the stack of the thread from this point (`k-stack (saved VTL0 context)`).
- {command}`.thread` selects this state as the register context of the thread.
- The SDK's `Thread.backtrace()` also starts from this state.
- For running threads, the stacks that {command}`!running` `-t`, {command}`!stacks`, {command}`!process`, and {command}`!analyze` `-hang` show also start from this state.

ntoseye finds the Enlightened VMCS pages with a scan of host RAM, once per boot, the first time that a stop, {command}`~`, or {command}`.vtlcxr` finds a vCPU in the hypervisor. For an 8 GiB guest, the scan takes about 0.6 s. If the scan found no pages for a vCPU, which a stop early in the boot can cause, ntoseye scans once more for that vCPU. If a saved state fails validation, ntoseye does not show it ([how](../internals/vbs.md#reading-the-saved-vtl-state)).

ntoseye does not support AMD hosts for this feature, because the Windows hypervisor uses eVMCS only on Intel (VMX). On AMD, its nested state is a VMCB.
