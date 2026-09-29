# Memory and paging

This page tells how `ntoseye` reads and writes guest memory. It also tells what happens to memory that the guest has paged out. To find which backends can read memory, see [Choosing a backend](../setup/backends.md).

## Where reads come from

The KD and KDNET backends accept `--memory-source auto|host|kd`. The option has three values:

- `auto` is the default. `ntoseye` reads memory directly from the VM process, but only after the kernel PE header and the live module-list links in that memory match the KD target. If they do not match, `ntoseye` reads through KD.
- `host` reads memory directly from the VM process. This memory must match the KD target. If it does not match, the attach fails with an error.
- `kd` makes the target do all reads.

With the `kd` source, `ntoseye` sends each read through the target as follows:

- Kernel-space addresses, in all process contexts, go through `DbgKdReadVirtualMemory`.
- User-space addresses of the process that the current processor runs (AMD64) also go through `DbgKdReadVirtualMemory`.
- User space of all other processes goes through `DbgKdReadPhysicalMemory`. Before the read, `ntoseye` does a page walk on the host. `ntoseye` keeps the translations in a cache until the target runs again.
- Session space resolves in the session of the halted processor, as in WinDbg.

The memory source controls only reads. All sources write memory in the same way:

- If the target can do a virtual write to the address, `ntoseye` uses `DbgKdWriteVirtualMemory`.
- For other addresses, `ntoseye` does a page walk and uses `DbgKdWritePhysicalMemory`.

The two types of write have different results:

- A virtual write resolves through the page tables of the target. If the target does not write to a page, the write to that page fails.
- A physical write or a host-memory write goes to the frame that is mapped at that time. It does not report a problem. If the guest remaps the frame, the change stays with that frame.

Neither type of write keeps write protection or copy-on-write. The kernel does a debugger write with `MMDBG_COPY_UNSAFE`. This flag makes the PTE writable while the write occurs. So no fault occurs, and the kernel does not copy a shared page. The kernel also has a copy-on-write path, but that path needs IRQL <= APC_LEVEL. A debugger that holds all other processors frozen can never get that IRQL.

So if you write a breakpoint into a shared image page, every process that maps that page sees the breakpoint. This is true for all types of write. See [breakpoints in shared pages](breakpoints.md#user-mode-breakpoints-in-shared-pages).

`ntoseye` checks the identity of the host mapping when it attaches. It checks the identity again after a guest reboot, when it builds the debugger state again. If the host memory no longer matches, `ntoseye` shows a warning. Reads through the host mapping are then not reliable. Attach again with `--memory-source kd`.

The `kd` source does not need access to the hypervisor or to the VM process. So you can debug AMD64 and ARM64 Windows VMs or physical machines across any routable network. This has two costs:

- Commands that use memory need a halted target.
- Network latency makes large scans slower than scans of direct host memory.

If the VM is local, use `--memory-source host` or the default `auto`. For the cost of each read, see [reading memory over KD](../internals/kd-reads.md).

The memory source also controls when `ntoseye` [rebuilds a driver's PDB from guest memory](symbols.md):

- If reads come from the host, `ntoseye` rebuilds the PDB automatically.
- If reads go through KD, `ntoseye` rebuilds the PDB only when you enter `.reload <module>`.

## Paged-out memory

When the guest trims a page from a working set, the page usually stays in RAM on the standby list or the modified list. The PTE of the page stays in the *transition* state. The host page walk and target reads can both read these pages. So reads of trimmed memory work normally.

A write to a trimmed page fails. The kernel can use the frame for a different purpose, or it can read the page from disk again. Then the change is lost, or it goes to an unrelated location.

If a process has never touched a page of a DLL or a mapped file, the process has no PTE for that page. But a different process that maps the same file often has that page in memory. The host page walk finds the page through the VAD of the process. Then it reads the frame that the shared prototype PTE of the section records. So `ntoseye` can read the code and unwind tables of a DLL in every process that maps the DLL. {command}`!vtop` shows such a page as `mapping : section`. These pages are also read-only.

If a page is on disk, a read of that page shows it as unavailable. To get the page, use {command}`.pagein`. This command tells the guest to read the page into memory:

```
.pagein /p 5280 0x1048000
```

The debugger worker thread of the guest reads the page. So the target runs again. It then halts at `nt!DbgBreakPointWithStatus`, not at its previous location. The target must run, because no code can fault a page in while all processors are frozen.

For user-space addresses, use `/p`. This option first attaches the worker thread to the process.
