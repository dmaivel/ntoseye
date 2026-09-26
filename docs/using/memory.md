# Memory and paging

How `ntoseye` reads and writes guest memory, and what happens to memory the guest has paged out. Which backends can read memory at all is in [Choosing a backend](../setup/backends.md).

## Where reads come from

KD and KDNET accept `--memory-source auto|host|kd`:

- `auto` (default) reads direct VM-process memory only after its kernel PE header and live module-list links match the KD target; otherwise it falls back to KD.
- `host` requires matching direct VM-process memory and fails on mismatch.
- `kd` forces target-mediated reads: kernel-space addresses under any process context, and user-space addresses of the process the current processor is running (AMD64), go through `DbgKdReadVirtualMemory`; user space of any other process goes through `DbgKdReadPhysicalMemory` behind a host page walk whose translations are cached until the target next runs. Session space resolves in the halted processor's session, as in WinDbg.

The source controls reads. Where the target can service virtual writes, all sources use `DbgKdWriteVirtualMemory`; other addresses use a page walk and `DbgKdWritePhysicalMemory`. A virtual write resolves through the target's own page tables and refuses a page it will not write; a physical or host-memory write reaches whatever frame is mapped, reports nothing, and follows that frame if the guest remaps it.

Neither preserves write protection or copy-on-write. The kernel services a debugger write with `MMDBG_COPY_UNSAFE`, which makes the PTE writable for the duration instead of taking the fault that would copy a shared page; the copy-on-write path beside it requires IRQL <= APC_LEVEL, which a debugger holding every other processor frozen can never reach. A breakpoint written into a shared image page is therefore visible to every process mapping that page, however it was written. See [breakpoints in shared pages](breakpoints.md#user-mode-breakpoints-in-shared-pages).

The host mapping's identity is re-checked after a guest reboot rebuilds debugger state, not just at attach.

The `kd` source needs no hypervisor or VM-process access, so AMD64 and ARM64 Windows VMs or physical machines can be debugged across any routable network. Memory-backed commands require the target to be halted; remote latency also makes large scans slower than direct host memory. Prefer `--memory-source host` (the `auto` default) whenever the VM is local; [reading memory over KD](../internals/kd-reads.md) explains what each read costs.

## Paged-out memory

A page the guest has trimmed out of a working set is usually still in RAM on the standby or modified list, with its PTE left in the *transition* state. Both the host page walk and the target read those, so trimmed memory keeps reading normally. Writes to such a page are refused: the kernel is free to repurpose the frame or re-read it from disk, so the edit would be lost or land somewhere unrelated.

A page that has genuinely gone to disk reads as unavailable, and {command}`.pagein` asks the guest to fetch it:

```
.pagein /p 5280 0x1048000
```

The guest's own debugger worker thread does the work, so the target is resumed and comes back halted at `nt!DbgBreakPointWithStatus` rather than wherever it was. Nothing can fault a page in while every processor is frozen, so that resume is inherent rather than an implementation choice. `/p` attaches the worker to a process first, which user-space addresses need.
