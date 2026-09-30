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
| [Hypervisor partitions, virtual processors, and VTL page permissions](#hypervisor-partitions-and-virtual-processors) | `memory`, `gdb`; `kd`/`kdnet` reading host memory | Supported (needs `hv-evmcs`, or a `gdb` vCPU stopped in the hypervisor) | Not supported |

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

Hardware execution breakpoints also work in the Windows hypervisor itself (`hvix64`), without a software code patch. To set one, use {command}`~` and {command}`vcpu` to select the register and address-space context of the hypervisor, and then use `ba e1 <address>` or `ba e1 hv+<offset>`. These breakpoints use linear addresses and are not VTL-tagged breakpoints. They use the same four hardware slots, which all vCPUs share.

Hardware breakpoints do not write to integrity-sensitive code, but they can be visible and can have side effects. While host debugging is active, KVM controls the debug-register breakpoint state, and the upstream [nested VMX handling](https://github.com/torvalds/linux/blob/master/arch/x86/kvm/vmx/nested.c) documents an interaction with `KVM_GUESTDBG_USE_HW_BP` that can cause the loss of L1's own DR7 state. Do not assume that simultaneous guest and hypervisor hardware debugging keeps the state of both debuggers.

## Trustlet enumeration

{command}`!trustlets` reads secure-kernel structures that the public symbols do not describe ([how](../internals/vbs.md#trustlet-enumeration)). It recognizes every build that we examined, from 10.0.19041 (Windows 10 20H1) to 10.0.28000. Older secure kernels do not have these routines with these names, so {command}`!trustlets` gives an error on them, but you can still inspect the secure kernel and its modules.

ntoseye does not list the modules that are loaded in a trustlet. The lists that {command}`!trustlets` walks are live and are not atomic snapshots, so the walk can become incorrect if a process exits or a module unloads during it.

## Hypervisor partitions and virtual processors

The Windows hypervisor keeps a partition object for NT (the root partition) and one for each Hyper-V VM, WSL2 instance, or Windows Sandbox that runs in the guest, and a virtual processor (VP) object for each of their processors. `ntoseye` walks these objects:

- {command}`!hvpartitions`: Show each partition, root first, with its partition object, partition ID, the parent's ID, the number of VPs, and its privilege mask (the TLFS `HV_PARTITION_PRIVILEGE_MASK`). Below the table, it shows the TLFS names of each partition's privileges, and the set bits that the TLFS lists as reserved as a hexadecimal value.
- {command}`!hvvps` `[partition-id]`: Show the VPs of a partition, the root partition by default, with one row for each VTL that is enabled on a VP. `*` marks the VTL that the VP runs or last ran in. `CPU` is the processor whose current VP it is, the one that runs it or ran it last, by number; builds before 10.0.19041 keep no number where ntoseye finds the current VP, so it shows the processor block instead. Each row shows the hypervisor's context object for the VTL, the physical address of the VTL's eVMCS, its EPT pointer, the guest RIP where the VTL left off, and why it last left for the hypervisor. The hypervisor also allocates contexts for VTLs that a partition does not enable, for example VTL1 in a VM without VBS, and the command does not show those.

With a Hyper-V VM that runs in the guest:

```text
mem:1> !hvpartitions
Partition         ID   Parent  VPs  Privileges
ffffe80000001000  0x1  root    4    002bb9ff00003fff
ffffe80200001000  0x2  0x1     2    003b803000002e7f
0x1: AccessVpRunTimeReg ... CreatePartitions AccessPartitionId ... StartVirtualProcessor (+0x8a00800001000)
0x2: AccessVpRunTimeReg ... PostMessages SignalEvents AccessVSM AccessVpRegisters EnableExtendedHypercalls StartVirtualProcessor (+0x8800000000000)

mem:1> !hvvps
VP  Address           CPU  VTL  Context           eVMCS      EPT pointer  Guest RIP         Last exit
0   ffffe8000026c050  0    0*   ffffe8000026d000  1160e4000  10155901e    fffff805932e950f  HLT
                           1    ffffe8000026f000  1160e7000  10155c01e    fffff80523b40035  VMCALL
1   ffffe80000389050  1    0*   ffffe80000390000  12ec0d000  10155901e    fffff805932e950f  HLT
                           1    ffffe80000392000  12ec10000  10155c01e    fffff80523b40035  VMCALL
...

mem:1> !hvvps 2
VP  Address           CPU  VTL  Context           eVMCS      EPT pointer  Guest RIP         Last exit
0   ffffe80200231050       0*   ffffe80200232000  2052dc000  20523105e    000000001ff26114  HLT
1   ffffe8020024b050       0*   ffffe8020024c000  2053e7000
```

The root partition's VPs are pinned to the processors with their numbers, and the child's VPs show no processor while every processor runs a root VP.

The EPT pointer is the root of the VTL's second-level address translation (SLAT), which maps the guest's physical addresses to host physical addresses with read, write, and execute permissions. The VPs of a partition share one EPT for each VTL, and VTL0 and VTL1 have different ones: this is how the secure kernel and memory integrity (HVCI) set page permissions that NT cannot change. The root partition's EPT maps each address to itself, except the pages that the hypervisor keeps for itself. The eVMCS columns stay empty without the `hv-evmcs` enlightenment, and the state columns stay empty for a VP that has not started, such as the second VP of a VM still in its firmware.

### Page permissions of each VTL

{command}`!hvept` `[-v] <address> [partition-id [vp-index]]` translates a guest physical address through the EPT of each VTL of a VP, the root partition's VP 0 by default. Each row shows the host physical address, the access that every level of the walk allows, the page size, and the memory type. With memory integrity (HVCI) on, VTL0 can execute NT's code but not write it, and can write its data but not execute it, while VTL1 has full access. VTL0 has no access at all to the pages of the secure kernel:

With `-v`, the address is virtual, in the current address space ({command}`.process`, or the {command}`.vtl` `1` scope), and the command translates it through the guest's page tables first:

```text
mem:1> !hvept -v nt!KeBugCheckEx
virtual fffff8059313d130 -> guest physical 5efd130
VTL  EPT pointer  Host physical  Access  User exec  Page  Type
0    10155901e    5efd130        r-x                2M    WB
1    10155c01e    5efd130        rwx                2M    WB

mem:1> !hvept -v nt!KiProcessorBlock
virtual fffff80593c08c80 -> guest physical 1185c8c80
VTL  EPT pointer  Host physical  Access  User exec  Page  Type
0    10155901e    1185c8c80      rw-                2M    WB
1    10155c01e    1185c8c80      rwx                2M    WB

mem:1> .vtl 1
mem:1> !hvept -v securekernel
virtual fffff805290d3000 -> guest physical 18ba000
VTL  EPT pointer  Host physical                  Access  User exec  Page  Type
0    10155901e    not mapped (no level-1 entry)
1    10155c01e    18ba000                        rwx                2M    WB
```

In the SDK, translate a virtual address with `memory.translate()` first.

{command}`!hveptdiff` `[partition-id [vp-index]]` walks the whole EPT of VTL0 and of VTL1 of a VP and lists every range of guest physical memory that the two map differently. A summary of how they differ comes first, largest first. With memory integrity on:

```text
mem:1> !hveptdiff
VTL0 EPT 10155901e: 9184 mappings, 10.1G
VTL1 EPT 10155c01e: 6378 mappings, 8.9G

VTL0  VTL1  Ranges  Size
rw-   rwx   93      7.8G
rw-   none  17      1.3G
r-x   rwx   35      70.0M
none  rwx   32      35.7M
r--   rwx   14      24.8M
...

Start      End        Size    VTL0  VTL1
...
216 ranges differ, 9.2G in all
```

Most of memory is `rw-` in VTL0 because memory integrity does not let NT execute its data. The `r-x` ranges hold the code that NT can execute but not change, the `none` ranges the memory of the secure kernel and trustlets, and the `r--` ranges pages that NT can read but not write. When a VTL uses mode-based execute control, `x` is execute in kernel mode and the `User exec` column shows execute in user mode. The walk follows Intel's EPT format and needs the `hv-evmcs` enlightenment.

### Memory of a guest partition

{command}`!hvd` `[-p] [-b|-d|-q] <partition-id> <vp-index> <address> [range]` shows the memory of the guest that a child partition runs, such as a Hyper-V VM, WSL2, or Windows Sandbox inside the target. It reads guest virtual memory through the page tables of the VTL that the VP runs in (the CR3 in its eVMCS), or guest physical memory with `-p`, and it translates both through that VTL's EPT. `-d` and `-q` show dwords and qwords, and the range works as for {command}`db`. Pages that are not mapped show as `??`. Here, a VM that sits in its firmware halted in the idle loop of its UEFI:

```text
mem:1> !hvvps 3
VP  Address           VTL  Context           eVMCS      EPT pointer  Guest RIP         Last exit
0   ffffe80200231050  0*   ffffe80200232000  2052dc000  20523105e    000000001ff26114  HLT
...
mem:1> !hvd 3 0 0x1ff26110 L10
000000001ff26110  fb c3 fb f4 c3 cc cc cc cc cc cc cc cc cc cc cc  ................
```

`sti; hlt` is at `0x1ff26112`, and the guest RIP is after the `hlt`. The memory is read-only, and ntoseye has no symbols or process list for the guest, so to inspect a guest in depth, attach ntoseye to it directly. A VP that has not started, such as a second VP that the firmware has not woken, has no state to read through.

### VMCS and intercepts

{command}`!hvvmcs` `[-msr|-io] [partition-id [vp-index [vtl]]]` shows the eVMCS of a VTL, the root partition's VP 0 and the VTL that it runs in by default: each field with its name, offset, and value. With `-msr`, it shows the MSRs whose reads and writes the VTL's MSR bitmap intercepts, and with `-io`, the I/O ports that its I/O bitmaps intercept. When the VM-execution controls do not use the bitmaps, it says that every access exits, or none. The eVMCS layout is the Hyper-V TLFS's, so this works on every hypervisor build.

```text
mem:1> !hvvmcs -io
VP 0 of partition 0x1, VTL0: eVMCS 1160e4000

First port  Last port
0x20        0x21
0x64        0x64
0xa0        0xa1
0x605       0x605
0xcf8       0xcf8
...
```

### Hypercalls

{command}`!hvcalls` lists the hypercalls that the hypervisor implements, from its own hypercall table: the call code, the name that the Hyper-V TLFS gives it, whether it is a simple or a rep call (`+var` marks a variable-size input header), the sizes of its fixed input and output and of each rep element, and its handler. Codes that share the handler of the reserved code 0 are not implemented, and `-a` lists them too.

```text
mem:1> !hvcalls
Code    Name                                  Kind        Input   Rep in  Output  Rep out  Handler
0x0000                                        simple                                       hv+0x2868a0
0x0001  HvCallSwitchVirtualAddressSpace       simple      0x8                              hv+0x28fc70
0x0003  HvCallFlushVirtualAddressList         rep         0x18    0x8                      hv+0x28dce0
...
0x0040  HvCallCreatePartition                 simple      0x38            0x8              hv+0x2831e0
...
221 of 306 codes implemented; code 0's handler serves the rest
```

The TLFS documents only some of the call codes, and the others have no name. Each handler is also a symbol in the hypervisor's context (see below), so with a vCPU stopped in the hypervisor and its context selected with {command}`.cxr`, {command}`u` `hv!HvCallCreatePartition` disassembles a handler, and {command}`ba` `e1 hv!HvCallCreatePartition` stops in it (with the `gdb` backend). ntoseye refuses a software breakpoint ({command}`bp`) in the hypervisor's image or address space, because it does not write the hypervisor's memory.

The addresses are in the address space of the hypervisor. To read them with {command}`dq` and the other memory commands, first select the context of a vCPU that is stopped in the hypervisor with {command}`.cxr`.

`ntoseye` reaches the objects from the hypervisor's per-processor blocks, whose addresses it takes from the eVMCS pages (their host GS base) and from the selected vCPU when that vCPU is stopped in the hypervisor. So the commands need the `hv-evmcs` enlightenment, as [where NT left off](#where-nt-left-off-under-the-hypervisor) does, or a `gdb` stop in the hypervisor, and they do not work on AMD hosts. `hvix64` has no public symbols, so `ntoseye` reads the offsets of these objects from the hypervisor's own code and checks every object before it shows it ([how](../internals/vbs.md#partitions-and-virtual-processors)). It recognizes every build that we examined, from 10.0.16299 to 10.0.28000. If it does not recognize a build, the commands give an error and do not guess.

The walk reads live memory and is not an atomic snapshot, so a partition that is created or deleted during the walk can make it fail.

## Stops in the Windows hypervisor

When VBS runs, the GDB stub reports what each vCPU executed when it halted. An idle vCPU is usually inside the Windows hypervisor, with the hypervisor's own CR3. `ntoseye` names such a stop by the image in which the vCPU stopped. The context shows `hypervisor`, or `VTL1` for the secure kernel. As in WinDbg, the module name of the hypervisor image (`hvix64.exe`) is `hv`, so code and stack frames show `hv+0x…`. While the context of the hypervisor is selected, expressions accept `hv` and `hv+<offset>` like any other module name.

`hvix64` has no public symbols, but `ntoseye` names some of its code: each hypercall handler by the TLFS name of the lowest call code it serves (`hv!HvCallGetVpRegisters`), or `HvCall` and the code when the TLFS does not name it (`hv!HvCall0004`), the handler of every unimplemented code `hv!HvCallUnimplemented`, and the VM-exit entry point from the eVMCS pages `hv!VmExitEntry`. {command}`k`, {command}`u`, {command}`ln`, {command}`x` `hv!*`, and expressions use these names. A name covers only its own function, as the image's `.pdata` bounds it, so code in the other functions still shows `hv+0x…`.

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

A vCPU can also stop on the first instruction of the hypervisor's VM-exit handler (the eVMCS `host_rip`). KVM writes the saved state when it enters the hypervisor, and a stop from outside, such as a break-in, can fall between a VM exit and that entry, so the saved state may still describe the previous exit. Under load this is common. ntoseye marks such a state `(may be one exit behind)` in the stop header, {command}`~`, and {command}`.vtlcxr`, and does not select it or start stacks from it on its own. {command}`.vtlcxr` still selects it when you ask. The guest's general-purpose registers at that point are the vCPU's own registers. A breakpoint on `host_rip` fires only after KVM has written the state, so at a stop on such a breakpoint the state is current, and ntoseye selects it with the vCPU's own general-purpose registers.

The NT thread that runs on that processor also starts from the same saved state everywhere that ntoseye shows this thread:

- {command}`!thread` shows the stack of the thread from this point (`k-stack (saved VTL0 context)`).
- {command}`.thread` selects this state as the register context of the thread.
- The SDK's `Thread.backtrace()` also starts from this state.
- For running threads, the stacks that {command}`!running` `-t`, {command}`!stacks`, {command}`!process`, and {command}`!analyze` `-hang` show also start from this state.

ntoseye finds the Enlightened VMCS pages with a scan of host RAM, once per boot, the first time that a stop, {command}`~`, or {command}`.vtlcxr` finds a vCPU in the hypervisor. For an 8 GiB guest, the scan takes about 0.6 s. The saved state of VTL1 is recognized by the secure kernel's image, so the first of these stops also finds the secure kernel, as the first {command}`.vtl` `1` does. If ntoseye does not find it then, it does not look again during that boot, and it does not show VTL1's saved state. If the scan found no pages for a vCPU, which a stop early in the boot can cause, ntoseye scans once more for that vCPU. If a saved state fails validation, ntoseye does not show it ([how](../internals/vbs.md#reading-the-saved-vtl-state)).

ntoseye does not support AMD hosts for this feature, because the Windows hypervisor uses eVMCS only on Intel (VMX). On AMD, its nested state is a VMCB.
