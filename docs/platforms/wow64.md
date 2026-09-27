# WOW64 processes

A 32-bit process on an x64 kernel (`_EPROCESS.WoW64Process` set) is marked `WOW64` by {command}`.process`, in the `Wow64` column of {command}`!process`/{command}`ps`, and by its `Wow64Peb` in process detail. Attaching to one loads both loader lists: the native `ntdll` and `wow64*.dll`, and the 32-bit modules, whose symbols come from their x86 PDBs. The 32-bit ntdll is addressed as `ntdll32` (`x ntdll32!Rtl*`, `bu ntdll32!RtlAllocateHeap`); every other 32-bit module keeps its name. x86 public symbols are shown undecorated (`RtlAllocateHeap`, not `_RtlAllocateHeap@12`).

Types follow the same rule: a bare name resolves the kernel's layout, `ntdll32!_PEB` the 32-bit one, and the nested types of a 32-bit layout stay 32-bit (`dt ntdll32!_LDR_DATA_TABLE_ENTRY <address>` reads 4-byte pointers and `_UNICODE_STRING`s). {command}`!peb` adds the `PEB32` block and its process parameters, {command}`!teb` the `TEB32` behind `WowTebOffset`, {command}`!gle` the 32-bit TEB's last error, and {command}`!heap` walks the 32-bit heaps.

Code in a 32-bit module disassembles as x86 ({command}`u`, {command}`ub`, {command}`uf`, DAP disassembly). On an ARM64 target, where Windows runs x86 and x64 code by emulation, the image's own machine decides as well: an x86 image disassembles as x86, an x64 image as AMD64, and a hybrid image by its code-range map: an ARM64X or ARM64EC image (the native system DLLs of ARM64 Windows 11) has x64 ranges, the rest ARM64, and a CHPE x86 image (its x86 system DLLs) has ranges compiled to ARM64, the rest x86. `.effmach x86|amd64|arm64|.` overrides the choice (`arm64` on an ARM64 target). `.effmach x86` also makes {command}`ds`/{command}`dS` decode 32-bit string descriptors with the `ntdll32` layout; the SDK's `read_unicode_string`/`read_ansi_string` take `bits=32` for the same. A WOW64 thread's stack goes on into its x86 frames where it left x86 code: after the WOW64 CPU layer's frames (`wow64cpu` on AMD64, the `xtajit` emulator on ARM64) come the 32-bit program's, walked by frame pointer from the x86 registers WOW64 saved at the transition, and then the native frames that started the thread. {command}`k`, the stop display, {command}`!thread`, {command}`!stacks`, and SDK and DAP stacks show them. A thread running x86 code at the stop has not saved its registers there, so its stack shows no x86 frames, and the walk follows `ebp`, so it ends at a function built without a frame pointer.

An x64 program on an ARM64 target is not a WOW64 process: it runs as a 64-bit process in which its own x64 code and the ARM64EC code of the system DLLs call each other on one stack. A walk takes each frame by the unwind data of that frame's instruction set, so the program's x64 frames sit between the thunks that enter and leave ARM64EC code (`$ientry_thunk$…`, `$iexit_thunk$…`):

```text
  #9  00007ffaae048534  kernelbase!#WaitForSingleObjectEx+0x84 [unwind]
  #10 00007ffaae19f4dc  kernelbase!$ientry_thunk$cdecl$i8$i8+0x24 [unwind]
  #11 00007ff773c7c1e5  qemu-ga+0x6c1e5 [unwind]
  #12 00007ff773c7b3f5  qemu-ga+0x6b3f5 [unwind]
  #13 00007ffab157c8bc  msvcrt!$iexit_thunk$cdecl$i8$i8+0x1c [unwind]
  #14 00007ffab153ef00  msvcrt!_callthreadstartex+0x38 [unwind]
```
