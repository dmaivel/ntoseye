# WOW64 processes

A 32-bit process on an x64 kernel has `_EPROCESS.WoW64Process` set. ntoseye marks such a process `WOW64` in {command}`.process` and in the `Wow64` column of {command}`!process`/{command}`ps`, and the process detail shows its `Wow64Peb`.

When you attach to a WOW64 process, ntoseye loads both loader lists: the native `ntdll` and `wow64*.dll`, and the 32-bit modules, whose symbols come from their x86 PDBs.

Use the name `ntdll32` for the 32-bit ntdll, for example `x ntdll32!Rtl*` or `bu ntdll32!RtlAllocateHeap`. All other 32-bit modules keep their names. ntoseye shows x86 public symbols without decoration, for example `RtlAllocateHeap` instead of `_RtlAllocateHeap@12`.

Types follow the same rule. A name without a module gives the kernel layout, and `ntdll32!_PEB` gives the 32-bit layout, whose nested types are also 32-bit. For example, `dt ntdll32!_LDR_DATA_TABLE_ENTRY <address>` reads 4-byte pointers and `_UNICODE_STRING`s.

For a WOW64 process, these commands also show 32-bit data:

- {command}`!peb` shows the `PEB32` block and its process parameters.
- {command}`!teb` shows the `TEB32` at `WowTebOffset`.
- {command}`!gle` shows the last error of the 32-bit TEB.
- {command}`!heap` walks the 32-bit heaps.

## Disassembly

ntoseye disassembles code in a 32-bit module as x86 in {command}`u`, {command}`ub`, {command}`uf`, and the DAP disassembly.

On an ARM64 target, where Windows runs x86 and x64 code by emulation, the machine type of the image also controls the disassembly:

- ntoseye disassembles an x86 image as x86.
- ntoseye disassembles an x64 image as AMD64.
- ntoseye disassembles a hybrid image by its code-range map:
  - An ARM64X or ARM64EC image has x64 ranges, and the rest of its code is ARM64. The native system DLLs of ARM64 Windows 11 are images of this type.
  - A CHPE x86 image has ranges compiled to ARM64, and the rest of its code is x86. The x86 system DLLs of ARM64 Windows 11 are images of this type.

`.effmach x86|amd64|arm64|.` overrides this choice, and its `arm64` value is for an ARM64 target.

`.effmach x86` also makes {command}`ds`/{command}`dS` decode 32-bit string descriptors with the `ntdll32` layout. In the SDK, `read_unicode_string`/`read_ansi_string` take `bits=32` for the same result.

## Stacks

The stack of a WOW64 thread continues into its x86 frames at the point where the thread left x86 code, and shows the frames in this order:

1. The frames of the WOW64 CPU layer, which is `wow64cpu` on AMD64 and the `xtajit` emulator on ARM64.
2. The frames of the 32-bit program, which ntoseye walks by frame pointer, starting from the x86 registers that WOW64 saved at the transition.
3. The native frames that started the thread.

The x86 frames appear in {command}`k`, the stop display, {command}`!thread`, {command}`!stacks`, and SDK and DAP stacks.

The x86 walk has two limits:

- If a thread is running x86 code at the stop, it has not saved its registers at the transition, so its stack shows no x86 frames.
- The walk follows `ebp`, so it ends at a function that was built without a frame pointer.

## x64 programs on an ARM64 target

An x64 program on an ARM64 target is not a WOW64 process. It runs as a 64-bit process in which the x64 code of the program and the ARM64EC code of the system DLLs call each other on one stack.

The stack walk reads each frame with the unwind data for the instruction set of that frame, so the x64 frames of the program appear between the thunks that enter and leave ARM64EC code (`$ientry_thunk$…`, `$iexit_thunk$…`):

```text
  #9  00007ffaae048534  kernelbase!#WaitForSingleObjectEx+0x84 [unwind]
  #10 00007ffaae19f4dc  kernelbase!$ientry_thunk$cdecl$i8$i8+0x24 [unwind]
  #11 00007ff773c7c1e5  qemu-ga+0x6c1e5 [unwind]
  #12 00007ff773c7b3f5  qemu-ga+0x6b3f5 [unwind]
  #13 00007ffab157c8bc  msvcrt!$iexit_thunk$cdecl$i8$i8+0x1c [unwind]
  #14 00007ffab153ef00  msvcrt!_callthreadstartex+0x38 [unwind]
```
