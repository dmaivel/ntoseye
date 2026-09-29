# VBS and the Windows hypervisor

When virtualization-based security (VBS) runs, Windows runs a second kernel, `securekernel.exe`, in Virtual Trust Level 1 (VTL1). Windows also runs isolated user-mode processes (trustlets) there, for example `LsaIso.exe`. `ntoseye` can inspect this memory on an AMD64 guest if it reads the guest memory directly from the host.
The Python SDK shows the same data through [`dbg.secure_kernel`](../scripting/sdk.md#secure-kernel-vtl1).

## Should VBS be on?

VBS can run only if the VM gives nested virtualization to the guest. These VM settings give nested virtualization:

- In VMware, the "Virtualize Intel VT-x/EPT" option.
- In KVM/QEMU, a CPU with `vmx`.

UTM under Apple's hypervisor does not have nested virtualization. If the hardware allows it, Windows 11 turns on VBS by default. Hyper-V or WSL2 in the guest also start the hypervisor. To see if VBS runs, use `msinfo32` in the guest.

If you debug drivers or the kernel, turn off VBS, unless your work needs it. When VBS is on, these limits apply:

- Windows does not allow KD to write to user-mode code. So a user-mode breakpoint over KD uses one of the four hardware slots ({command}`ba` `e1`).
- The `gdb` backend cannot single-step with the trap flag. It runs the vCPU alone to the next instruction. Sometimes a step ends early, in an interrupt handler or in another thread ([how](../internals/vbs.md#stepping-without-the-trap-flag)).
- A vCPU can stop inside the Windows hypervisor. There, you cannot step until the guest resumes.

Keep VBS on for these tasks:

- To research VBS and the secure kernel. The rest of this page is about this task.
- To test a driver under Memory integrity (HVCI) before release. A production driver must load when Memory integrity is on.
- To debug a problem that occurs only when VBS is on.

To turn off VBS:

1. In the guest, open an elevated prompt.
2. Run this command:

   ```text
   bcdedit /set hypervisorlaunchtype off
   ```

3. Reboot the guest.

This command stops the Windows hypervisor. So Hyper-V, WSL2, and Windows Sandbox in the guest also stop. To turn the hypervisor on again, run `bcdedit /set hypervisorlaunchtype auto` and reboot the guest.

:::{important}
Everything on this page needs an **AMD64 guest**. ntoseye does not support ARM64 guests. The host CPU is also important:

| Feature | Backends | Intel host | AMD host |
| --- | --- | --- | --- |
| VTL1 memory, symbols, and {command}`!trustlets` | `memory`, `gdb`; `kd`/`kdnet` reading host memory | Supported | Untested |
| VTL1 breakpoints and stepping | `gdb` on QEMU/KVM | Supported | Untested |
| Stepping NT while the Windows hypervisor runs | `gdb` | Supported | Untested |
| [Where NT left off](#where-nt-left-off-under-the-hypervisor) under the hypervisor | `gdb` | Supported (needs `hv-evmcs`) | Not supported |

We tested all of these features on one host, a Core i9-14900F with QEMU/KVM. The guests were Windows 11 (10.0.26100 and 10.0.26200), with memory integrity (HVCI) off and on.

VTL1 inspection is experimental. It uses undocumented secure-kernel structures and finds them by heuristics. So it can fail on other Windows builds. If ntoseye does not recognize a structure, it shows an error and does not show the data.
:::

## Requirements

VTL1 inspection needs direct host memory. The `memory` and `gdb` backends can inspect VTL1. The `kd` and `kdnet` backends can inspect VTL1 only while they read from host memory. This is the case with `--memory-source host`, or with `auto` after the host mapping matched. `kd` and `kdnet` cannot control VTL1 execution.

ntoseye does not support VTL1 inspection for these targets:

- Crash dumps.
- `--memory-source kd`.
- ARM64 targets.

Memory integrity (HVCI) is not necessary.

VBS needs a VM that gives nested virtualization to the guest. The [KVM/QEMU setup](../setup/kvm-qemu.md#virtualization-based-security-vbs) gives a CPU model that works.

When VBS runs, Windows does not allow KD writes to user-mode code pages. This applies to physical and to virtual writes. KD writes to data pages and to kernel code succeed. So `kd` and `kdnet` cannot set user-mode breakpoints. `bp` shows the error that the target gives.

## Inspecting VTL1 memory

- {command}`.vtl` `[0|1 [pid]]`: Show or select the inspection scope.
  - A bare {command}`.vtl` shows the current scope.
  - `0` goes back to the NT kernel. At a stop in VTL1 or in the Windows hypervisor, `0` selects the vCPU's own address space. There, use {command}`.vtlcxr` or {command}`.thread` to select NT.
  - `1` selects the system address space of the secure kernel.
  - `1 <pid>` selects the address space of a trustlet by its NT PID. The PID is always decimal.
- {command}`!trustlets`: Show a list of secure-kernel processes. For each process, the list shows:
  - The secure-kernel process object.
  - The NT PID and the image name.
  - The trustlet ID.
  - The address-space root.

```text
.vtl 1
lm
x securekernel!Skps*
!trustlets
.vtl 1 936
.vtl 0
```

:::{warning}
{command}`.vtl` changes only the scope that the debugger inspects. It does not change the virtual trust level in which the CPU executes. When you select a scope, ntoseye clears the cached registers.

In the explicit VTL1 memory view, ntoseye does not accept these commands:

- Writes.
- Register and stack commands.
- NT-specific or custom extensions.

You can use hardware execution breakpoints and plain {command}`g`. {command}`g` leaves the memory view before it resumes the target. At each stop, ntoseye restores the context of the vCPU that actually halted.

At a real VTL1 stop, {command}`r`, {command}`k`, {command}`.frame`, {command}`u`, and memory reads show the VTL1 state. They do not show the suspended NT thread. `lm k` shows the NT modules. A plain {command}`lm` shows the modules of the selected secure kernel.
:::

The first `.vtl 1` finds the secure kernel in guest RAM. ntoseye keeps the result for the session ([how](../internals/vbs.md#finding-the-secure-kernel)). If NT reports that VSM did not start (`nt!VslVsmEnabled` is 0), `.vtl 1` fails immediately.

In VTL1 scope, {command}`lm`, {command}`x`, {command}`ln`, {command}`u`, {command}`db`/{command}`dq`, {command}`dt`, {command}`!vtop`, and {command}`.reload` operate on the modules of the secure kernel. These modules are `securekernel.exe`, `skci.dll`, and the other modules that the secure kernel loaded.

You can still use `nt!` types, for example `dt nt!_KLDR_DATA_TABLE_ENTRY <address>`. But ntoseye does not resolve NT address symbols in VTL1 scope. It also does not resolve secure-kernel symbols in VTL0. This is because the modules of each kernel are mapped only in the address spaces of that kernel. Microsoft's public `securekernel.pdb` does not contain types.

## Breakpoints and stepping in VTL1

The `gdb` backend on AMD64 QEMU/KVM supports hardware execution breakpoints in loaded secure-kernel modules. After a breakpoint stops the target, you can inspect the target and continue. For example:

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

`ba e1` uses the host debug-register breakpoint of QEMU (`Z1`). It does not patch secure code. The breakpoints apply to all vCPUs. They use the same four hardware slots as other hardware breakpoints. You can filter hits with `/c` and with register conditions. The NT filters `/p` and `/t` cannot describe secure-kernel execution. So ntoseye does not accept them.

ntoseye identifies secure-system and trustlet roots by their mapping of the secure kernel. A stop shows `VTL1`, the real CPU registers, and the secure-kernel stack frames. ntoseye does not attribute an NT thread to that CPU. `.vtl 0` leaves an explicit memory view. It does not move a CPU that stopped in VTL1 back into NT.

At a VTL1 stop, {command}`t`, {command}`p`, {command}`gu`, {command}`pa`/{command}`ta`, {command}`wt`, and `g <address>` run through secure-kernel code. They use free debug-register slots:

- A step uses one slot for each place where the instruction can continue.
- A run-to command uses one slot for its target.

For more information, see [stepping under the Windows hypervisor](../internals/vbs.md#stepping-without-the-trap-flag). In the `.vtl 1` memory view, you can use only plain {command}`g`.

ntoseye does not support these operations:

- Software breakpoints in known secure modules.
- Writes to secure memory or to secure registers.
- Data watches.
- Breakpoints in trustlet user code.

ntoseye resolves the address of a hardware breakpoint one time. After a reboot, you must set the breakpoint again. Do not keep the target stopped for a long time, because the full VM stays halted.

Hardware execution breakpoints also work in the Windows hypervisor itself (`hvix64`). To set one:

1. Use {command}`~` and {command}`vcpu` to select the register and address-space context of the hypervisor.
2. Use `ba e1 <address>`.

This does not need a software code patch. These breakpoints use linear addresses. They are not VTL-tagged breakpoints. They use the same four hardware slots, and all vCPUs share these slots.

Hardware breakpoints do not write to integrity-sensitive code. But they can be visible, and they can have side effects. While host debugging is active, KVM controls the debug-register breakpoint state. The upstream [nested VMX handling](https://github.com/torvalds/linux/blob/master/arch/x86/kvm/vmx/nested.c) documents an interaction with `KVM_GUESTDBG_USE_HW_BP`. This interaction can cause the loss of L1's own DR7 state. Do not assume that simultaneous guest and hypervisor hardware debugging keeps the state of both debuggers.

## Trustlet enumeration

{command}`!trustlets` reads secure-kernel structures that the public symbols do not describe ([how](../internals/vbs.md#trustlet-enumeration)). It recognizes every build that we examined, from 10.0.19041 (Windows 10 20H1) to 10.0.28000. Older secure kernels do not have these routines with these names. On these kernels, {command}`!trustlets` gives an error. You can still inspect the secure kernel and its modules.

{command}`!trustlets` does not list the modules that are loaded in a trustlet. The lists are live and are not atomic snapshots. If a process exits or a module unloads during the walk, the walk can become incorrect.

## Stops in the Windows hypervisor

When VBS runs, the GDB stub reports what each vCPU executed when it halted. An idle vCPU is usually inside the Windows hypervisor, with the hypervisor's own CR3. `ntoseye` names such a stop by the image in which the vCPU stopped:

- The context shows `hypervisor`, or `VTL1` for the secure kernel.
- Code and stack frames show `hvix64+0x…`.

Microsoft does not publish symbols for this hypervisor build. Also, the address space of the hypervisor does not map its unwind data. So all hypervisor frames after the first frame are guesses from a stack scan (`[scan]`).

The CR3 of the hypervisor does not map NT memory. So ntoseye inspects such a stop at the point where NT left off ([below](#where-nt-left-off-under-the-hypervisor)). {command}`bp` and the bugcheck trap work in all address spaces in which the vCPU can stop ([how](../internals/vbs.md#breakpoints-while-vcpus-are-outside-nt)).

For the NT-side drivers of Hyper-V, you use the usual NT module and symbol inspection. For the hypervisor itself, ntoseye gives:

- Raw memory and register inspection.
- Stack labels as image plus offset.
- The [VTL state that the hypervisor saved](#where-nt-left-off-under-the-hypervisor) for each vCPU halted in it.

ntoseye does not give a structured list of partitions or virtual processors. In the SDK, `cpu.memory` reads the address space of the hypervisor. `cpu.saved_vtl` reads the saved VTL state ([Python SDK](../scripting/sdk.md#secure-kernel-vtl1)). Microsoft does not publish symbols or unwind data for the hypervisor. So ntoseye does not show all Hyper-V internals, and stack unwinding in the hypervisor is not reliable.

:::{important}
When Windows runs its own hypervisor (VBS, Hyper-V, WSL2), the `gdb` backend steps without the trap flag. The reason is that the trap flag can freeze such a guest ([how](../internals/vbs.md#stepping-without-the-trap-flag)). Steps and resumes from breakpoints work as usual. They also work through `syscall`, `sysret`, `iretq`, `int`, hypercalls, and far transfers.

There is one difference. Sometimes a step ends early, in an interrupt handler or in another thread that the handler switched to. This occurs in approximately 2 of 1,000 steps in kernel code. ntoseye then shows a notice. Use {command}`g` to resume.

Step-until walks and call traces do not end early at such a point. They run until their thread has executed the instruction, and then they continue. These commands are:

- Step-until walks: {command}`pa`, {command}`ta`, {command}`pc`, {command}`tc`, the SDK's `until=` and `run_to(step=)`.
- Call traces: {command}`wt`, `trace_calls()`.
:::

### Where NT left off under the hypervisor

When a vCPU halts in the Windows hypervisor, the hypervisor keeps in its own memory the state of the VTLs of that vCPU. `ntoseye` reads this state from Enlightened VMCS pages. The Hyper-V TLFS defines the layout of these pages. So this method does not depend on a hypervisor build. The hypervisor uses these pages only if the VM gives the `hv-evmcs` enlightenment ([KVM/QEMU setup](../setup/kvm-qemu.md#virtualization-based-security-vbs)). A plain nested VMCS has a CPU-private format, and KVM keeps it out of guest memory.

ntoseye then inspects a stop in the hypervisor at the point where VTL0 left off. The stop header shows this point (`saved VTL0 nt!HalProcessorIdle+0xf`), with its registers, code, and stack. {command}`r`, {command}`k`, {command}`u`, memory reads, and expressions use the NT state on that processor. The same applies in these cases:

- You switch to such a vCPU with `~Ns` ({command}`~`) or with a bare {command}`.thread`.
- A DAP client gets the stack of each vCPU that is halted in the hypervisor.

{command}`.cxr` goes back to the registers, stack, and address space of the hypervisor. {command}`.vtlcxr` selects the NT context again. {command}`.vtlcxr` also shows the saved state of each VTL, and the reason why that VTL last entered the hypervisor (`HLT`, `VMCALL`, ...).

The saved context has RIP, RSP, flags, control registers, and segment registers. It does not have the other general-purpose registers, because the hypervisor keeps them in undocumented state. {command}`.vtlcxr` shows the saved state of VTL1, but you cannot select it. ntoseye resolves the RIP of VTL1 after it finds the secure kernel (`.vtl 1`).

Such a vCPU runs hypervisor code. So ntoseye does not step it. {command}`t`, {command}`p`, {command}`gu`, {command}`wt`, and the other step commands give an error. {command}`g` resumes the vCPU. The registers of the vCPU are read-only, in all selected contexts. If there is no saved state, the stop stays in the context of the hypervisor. This occurs if the VM does not have `hv-evmcs`, or on an AMD host.

The NT thread that runs on that processor also starts from the same saved state, in all places that show this thread:

- {command}`!thread` shows the stack of the thread from this point (`k-stack (saved VTL0 context)`).
- {command}`.thread` selects this state as the register context of the thread.
- The SDK's `Thread.backtrace()` also starts from this state.
- For running threads, the stacks that {command}`!running` `-t`, {command}`!stacks`, {command}`!process`, and {command}`!analyze` `-hang` show also start from this state.

ntoseye finds the Enlightened VMCS pages with a scan of host RAM. The scan occurs one time per boot, the first time that a stop, {command}`~`, or {command}`.vtlcxr` finds a vCPU in the hypervisor. For an 8 GiB guest, the scan takes approximately 0.6 s. If the scan found no pages for a vCPU, ntoseye scans one more time for that vCPU. A stop early in the boot can cause this. If a saved state fails validation, ntoseye does not show it ([how](../internals/vbs.md#reading-the-saved-vtl-state)).

ntoseye does not support AMD hosts for this feature. The Windows hypervisor uses eVMCS only on Intel (VMX). On AMD, its nested state is a VMCB.
