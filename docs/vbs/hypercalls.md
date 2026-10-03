# Hypercalls and VM exits

A virtual processor leaves its guest for the hypervisor with a VM exit: to make a hypercall (a `VMCALL`), or because it did something that the hypervisor intercepts, such as reading an MSR. `ntoseye` lists the hypercalls that the hypervisor implements, stops on a hypercall or an exit from a given caller, and decodes the hypercall that a processor handles.

## The hypercall table

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

The TLFS documents only some of the call codes, and the others have no name. Each handler is also a symbol in the hypervisor's context ([names](hypervisor-stops.md)), so with a vCPU stopped in the hypervisor and its context selected with {command}`.cxr`, {command}`u` `hv!HvCallCreatePartition` disassembles a handler, and {command}`ba` `e1 hv!HvCallCreatePartition` stops in it (with the `gdb` backend). ntoseye refuses a software breakpoint ({command}`bp`) in the hypervisor's image or address space, because it does not write the hypervisor's memory.

The addresses are in the address space of the hypervisor. To read them with {command}`dq` and the other memory commands, first select the context of a vCPU that is stopped in the hypervisor with {command}`.cxr`.

## Hypercall breakpoints and decoding

{command}`!hvbp` `<code|name> [partition-id [vp-index]]` stops on a hypercall, optionally only from one partition or one of its VPs, with the `gdb` backend: `!hvbp HvCallSendSyntheticClusterIpi 3` stops when a VP of partition 0x3 sends a synthetic IPI. It sets a hardware execute breakpoint on the call's handler from this table, and at each hit reads the caller (the guest partition's VP that the processor serves, or the root partition's VP) and its call code from RCX, and resumes the target past the hits of other callers and of the other codes that share the handler, such as every unimplemented code. A hit whose caller ntoseye cannot tell stops. A condition (`if`) sees the caller's registers and reads the caller's memory, as {command}`!hvcall` does: `$pqwo(rdx)` is the first qword of a slow call's input. The stop header then shows the caller and its call, as `serving partition 0x3 VP 1` or as the root partition's saved VTL state, with the decoded hypercall. [Hypercall breakpoints](../using/breakpoints.md#hypercall-breakpoints) has the details.

{command}`!hvcall` shows the hypercall that the current vCPU's processor handles, at a stop in the hypervisor such as a hit of {command}`!hvbp` or of {command}`ba` `e1 hv!HvCallFlushVirtualAddressList`. It finds the caller as {command}`!hvbp` does, and decodes the call from the caller's registers at its `VMCALL`: the call code and TLFS name, the flags (fast, the size of a variable header, nested), a rep call's start and count, the GPAs of the input and output, and each field of the input as the Hyper-V TLFS lays it out, then each element of a rep call's input list, with the elements before the rep start marked `done`. Fields that have names for their values show them: `HV_PARTITION_ID_SELF`, flags, the VPs of a processor mask or of a sparse processor set (`HV_VP_SET`), a VTL, the TLFS names of the common registers in `HvCallGetVpRegisters` and `HvCallSetVpRegisters`, and the pages of a GVA or GPA range. ntoseye decodes the flushes of virtual and guest physical address spaces and lists and their `Ex` forms, the synthetic IPIs, `HvCallNotifyLongSpinWait`, `HvCallPostMessage`, `HvCallSignalEvent`, the VP register calls, `HvCallModifyVtlProtectionMask`, `HvCallEnablePartitionVtl`, `HvCallEnableVpVtl`, `HvCallStartVirtualProcessor`, `HvCallGetVpIndexFromApicId`, and `HvCallRetargetDeviceInterrupt`. For another call, it shows the first eight qwords of the input, or RDX and R8 for a fast call. For example, a flush of two ranges of an address space on VPs 0 and 1, whose first range is done, shows as follows:

```text
mem:1> !hvbp HvCallFlushVirtualAddressList
mem:1> g
...
mem:1> !hvcall
root partition VP 0 VTL0  hypercall 0x0003 HvCallFlushVirtualAddressList fast rep 0/4
├─ input value 0x0000000400010003  fast
├─ input in RDX and R8
├─ AddressSpace   0x0000000000000000  ignored: HV_FLUSH_ALL_VIRTUAL_ADDRESS_SPACES
├─ Flags          0x000000000000000f  HV_FLUSH_ALL_PROCESSORS | HV_FLUSH_ALL_VIRTUAL_ADDRESS_SPACES | HV_FLUSH_NON_GLOBAL_MAPPINGS_ONLY | HV_FLUSH_USE_EXTENDED_RANGE_FORMAT
├─ ProcessorMask  0x0000000000000000  ignored: HV_FLUSH_ALL_PROCESSORS
└─ rep list 4 elements
   ├─ [0] GvaRange  0xffffa789d4012000  0xffffa789d4012000, 1 page
   ├─ [1] GvaRange  0xffffa789d401b000  0xffffa789d401b000, 1 page
   ├─ [2] GvaRange  0xffffa789d41a7000  0xffffa789d41a7000, 1 page
   └─ [3] GvaRange  0xffffa789d41bd000  0xffffa789d41bd000, 1 page
```

NT made this call as an XMM fast hypercall: the ProcessorMask and the four ranges past RDX and R8 are in XMM0 to XMM2. A slow call shows the GPAs of its input and output instead of `input in RDX and R8`.

The flags select the extended GVA range format, which the TLFS does not describe. Bits 10:0 of a range count the pages after the first, and bit 11 selects large pages. A range of 4 KiB pages has its GVA in bits 63:12; a range of large pages has its GVA in bits 63:21, and bit 12 selects 2 MiB or 1 GiB pages, shown as `<GVA>, <count> of 2 MiB`. Microsoft's OpenVMM defines the format ([`HvGvaRangeExtended`](https://github.com/microsoft/openvmm/blob/b018341376ca9a34afc3502b1b605f8f8da2ecaa/vm/hv1/hvdef/src/lib.rs#L2413-L2444)), and the flush handlers of `hvix64.exe` read it the same way. Without the flag, bits 11:0 count the pages after the first.

ntoseye reads a slow call's input at its GPA through the EPT of the calling VTL, which is the root partition's for its own calls, and the guest's for a guest partition's VP. A fast call passes its input in RDX and R8, and an XMM fast call passes the rest of it in XMM0 to XMM5, which the hypervisor's VM-exit entry code saves beside the general-purpose registers before it clears them (every build from 10.0.16299 to 10.0.28000 does). The registers come from where that code saved them ([where NT left off](hypervisor-stops.md#where-nt-left-off-under-the-hypervisor)), so when they are not known, for example while the vCPU is still on the entry, or when the caller's last exit was not a `VMCALL`, {command}`!hvcall` says so.

## VM exits

{command}`!hvexit` `<reason> [partition-id [vp-index]]` stops on a VM exit by its basic exit reason, optionally only from one partition or one of its VPs ([how](../using/breakpoints.md#vm-exit-breakpoints)): `!hvexit rdmsr 1 2` stops when VP 2 of the root partition reads an MSR. Every exit of every VP enters the hypervisor at one entry point, `hv!VmExitEntry`, the host RIP of the eVMCSes of the VTLs that the partition walk finds; the command breaks there and reads the reason from the eVMCS that the processor has loaded, which the CPU filled in at the exit. On the test guest, about 250 exits a second reached the debugger while it was set, a small part of the thousands that the guest takes when it runs freely: each takes about 4 ms, almost all of it QEMU stopping and resuming every vCPU.

A guest partition's VPs run only when the root partition's NT runs them, and NT barely runs while the breakpoint is set, so with a guest partition's ID it rarely stops: on the test guest, a Windows Sandbox or WSL2 VP exited about once in 30 seconds. To stop on a guest partition's hypercalls, use {command}`!hvbp` with its ID, which breaks only at the call's handler and leaves the rest of the guest at full speed.
