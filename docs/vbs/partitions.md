# Partitions and virtual processors

The Windows hypervisor keeps a partition object for NT (the root partition) and one for each Hyper-V VM, WSL2 instance, or Windows Sandbox that runs in the guest, and a virtual processor (VP) object for each of their processors. `ntoseye` walks these objects:

- {command}`!hvpartitions`: Show the partitions as a tree, each child partition below its parent, with its partition ID and partition object. Below each partition are its privilege mask (the TLFS `HV_PARTITION_PRIVILEGE_MASK`) with the TLFS names of its privileges, and the set bits that the TLFS lists as reserved as a hexadecimal value, then each of its VPs: the processor whose current VP it is, the VTL that it runs or last ran in with the other enabled VTLs after it, the guest RIP where that VTL left off, and why it last left for the hypervisor. A root partition VP's RIP is named from NT's and the secure kernel's symbols.
- {command}`!hvvps` `[partition-id]`: Show the VPs of a partition, the root partition by default, with one row for each VTL that is enabled on a VP. `*` marks the VTL that the VP runs or last ran in. `CPU` is the processor whose current VP it is, the one that runs it or ran it last, by number; builds before 10.0.19041 keep no number where ntoseye finds the current VP, so it shows the processor block instead. Each row shows the hypervisor's context object for the VTL, the physical address of the VTL's eVMCS, its EPT pointer, the guest RIP where the VTL left off, and why it last left for the hypervisor. The hypervisor also allocates contexts for VTLs that a partition does not enable, for example VTL1 in a VM without VBS, and the command does not show those.

With a Hyper-V VM that runs in the guest:

```text
mem:1> !hvpartitions
partition 0x1  root  ffffe80000001000
├─ privileges 002bb9ff00003fff  AccessVpRunTimeReg AccessPartitionReferenceCounter
│                               AccessSynicRegs AccessSyntheticTimerRegs AccessIntrCtrlRegs
│                               ...
│                               StartVirtualProcessor (+0x8a00800001000)
├─ VP 0  CPU 0  VTL0 (+VTL1)  nt!HalProcessorIdle+0xf  last exit HLT
├─ VP 1  CPU 1  VTL0 (+VTL1)  nt!HalProcessorIdle+0xf  last exit HLT
├─ VP 2  CPU 2  VTL0 (+VTL1)  nt!HalProcessorIdle+0xf  last exit HLT
├─ VP 3  CPU 3  VTL0 (+VTL1)  nt!HalProcessorIdle+0xf  last exit HLT
└─ partition 0x2  ffffe80200001000
   ├─ privileges 003b803000002e7f  AccessVpRunTimeReg AccessPartitionReferenceCounter
   │                               ...
   │                               AccessVpRegisters EnableExtendedHypercalls StartVirtualProcessor
   │                               (+0x8800000000000)
   ├─ VP 0  VTL0  000000001ff26114  last exit HLT
   └─ VP 1  VTL0

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

## Page permissions of each VTL

{command}`!hvept` `[-v] <address> [partition-id [vp-index]]` translates a guest physical address through the EPT of each VTL of a VP: by default the VP that the current vCPU's processor runs, or the root partition's VP 0, and with `-v` always a root partition's VP. It names the VP first. Each row shows the host physical address, the access that every level of the walk allows, the page size, and the memory type. With memory integrity (HVCI) on, VTL0 can execute NT's code but not write it, and can write its data but not execute it, while VTL1 has full access. VTL0 has no access at all to the pages of the secure kernel:

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

With `-v`, the address is virtual in the current address space (the `.process` or VTL1 scope), which belongs to the root partition, so `-v` works only for the root partition's VPs; {command}`!hvd` reads a guest partition's virtual memory. In the SDK, translate a virtual address with `memory.translate()` first.

{command}`!hveptdiff` `[partition-id [vp-index]]` walks the whole EPT of VTL0 and of VTL1 of a VP, by default the one that the current vCPU's processor runs, and lists every range of guest physical memory that the two map differently. A summary of how they differ comes first, largest first. With memory integrity on:

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

Most of memory is `rw-` in VTL0 because memory integrity does not let NT execute its data. The `r-x` ranges hold the code that NT can execute but not change, the `none` ranges the memory of the secure kernel and trustlets, and the `r--` ranges pages that NT can read but not write. When a VTL uses mode-based execute control, `x` is execute in kernel mode and a fourth character, `u` or `-`, shows execute in user mode. The walk follows Intel's EPT format and needs the `hv-evmcs` enlightenment.

## VMCS and intercepts

{command}`!hvvmcs` `[-msr|-io] [partition-id [vp-index [vtl]]]` shows the eVMCS of a VTL, by default of the VP that the current vCPU's processor runs (a guest partition's first, else the root partition's) and the VTL that it runs in: each field with its name, offset, and value. With `-msr`, it shows the MSRs whose reads and writes the VTL's MSR bitmap intercepts, with the names of the architectural MSRs in each range, and then the architectural MSRs that the VTL reads and writes without an exit (`read without an exit: IA32_SPEC_CTRL ... IA32_KERNEL_GS_BASE`). The bitmap covers 0x0-0x1fff and 0xc0000000-0xc0001fff, and every other MSR, such as Hyper-V's synthetic ones, always exits. With `-io`, it shows the I/O ports that its I/O bitmaps intercept. When the VM-execution controls do not use the bitmaps, it says that every access exits, or none. The eVMCS layout is the Hyper-V TLFS's, so this works on every hypervisor build.

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

## Registers of a VP

{command}`!hvr` `[partition-id vp-index [vtl]]` shows the registers of a VTL of a VP, by default of the VP that the current vCPU's processor runs and the VTL that it runs in, whether or not a processor runs it:

- A VP that a vCPU runs now has its registers in that vCPU, and `!hvr` shows them.
- For a VP whose exit a vCPU in the hypervisor handles, it shows the registers of that exit, as {command}`!hvcall` finds them.
- Any other VP waits for the hypervisor to run it again, such as a WSL2 VP blocked in `HLT`, and `!hvr` shows the registers it saved at its last exit. The hypervisor resumes the VP with them, except for what it writes as the exit's result, such as a hypercall's status in RAX.

RIP, RSP, the flags, the control registers and the segment registers come from the VTL's eVMCS. The general-purpose registers are shared by a VP's VTLs and belong to the VTL that it runs in, so another VTL shows its eVMCS state alone. The SDK has `VirtualProcessor.registers(vtl=None)`, whose `source` says where they are from.

```text
mem:1> !hvr 6 1
partition 0x6 VP 1 VTL0  from its last exit
  rax     ffff8c3020a14000   rbx     0000000000000000   rcx     0000000000000001
  rdx     0000000000000001   rsi     0000000000000083   rdi     0000000002125454
  rsp     ffffcd5cc00cbe90   rbp     ffffcd5cc00cbe98   rip     ffffffffa11df02f
```

The hypervisor's VM-exit entry saves a VP's general-purpose registers in a register block that the VP object points at, in a 2 MiB region of the VP's own. A processor's root maps only the region of the VP that the processor runs, so a waiting VP's block is mapped nowhere, and `ntoseye` reads it through the region's page directory entry, which a descriptor that the VP object points at keeps for the hypervisor to map it again. `hvix64` has no public symbols, so `ntoseye` finds where the pointers and fields are on the VPs whose regions are mapped when the target halts, and uses them only when they agree for all of those VPs. Builds before 10.0.17763 save the registers on the processor's stack instead, so `!hvr` has no general-purpose registers for a waiting VP there.

## How ntoseye finds them

`ntoseye` reaches the objects from the hypervisor's per-processor blocks, whose addresses it takes from the eVMCS pages (their host GS base) and from the selected vCPU when that vCPU is stopped in the hypervisor. So the commands need the `hv-evmcs` enlightenment, as [where NT left off](hypervisor-stops.md#where-nt-left-off-under-the-hypervisor) does, or a `gdb` stop in the hypervisor, and they do not work on AMD hosts. `hvix64` has no public symbols, so `ntoseye` reads the offsets of these objects from the hypervisor's own code and checks every object before it shows it ([how](internals.md#partitions-and-virtual-processors)). It recognizes every build that we examined, from 10.0.16299 to 10.0.28000. If it does not recognize a build, the commands give an error and do not guess.

The walk reads live memory and is not an atomic snapshot, so a partition that is created or deleted during the walk can make it fail.
