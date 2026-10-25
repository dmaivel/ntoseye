# Memory and paging

This page describes how `ntoseye` reads and writes guest memory, and what happens to memory that the guest has paged out. To find which backends can read memory, see [Choosing a backend](../setup/backends.md).

## Where reads come from

The KD and KDNET backends accept `--memory-source auto|host|kd`:

- `auto` is the default. `ntoseye` reads memory directly from the VM process, but only after the kernel PE header and the live module-list links in that memory match the KD target. If they do not match, it reads through KD.
- `host` reads memory directly from the VM process. This memory must match the KD target, or the attach fails with an error.
- `kd` makes the target do all reads.

With the `kd` source, `ntoseye` sends each read through the target like this:

- Kernel-space addresses, in all process contexts, go through `DbgKdReadVirtualMemory`.
- User-space addresses of the process that the current processor runs (AMD64) also go through `DbgKdReadVirtualMemory`.
- User space of all other processes goes through `DbgKdReadPhysicalMemory`, after a page walk on the host. `ntoseye` keeps the translations in a cache until the target runs again.
- Session space resolves in the session of the halted processor, as in WinDbg.

The memory source controls only reads. All sources write memory in the same way: `ntoseye` uses `DbgKdWriteVirtualMemory` where the target can service virtual writes, and for other addresses it does a page walk and uses `DbgKdWritePhysicalMemory`.

The two types of write have different results:

- A virtual write resolves through the page tables of the target, and fails on a page that the target does not allow the debugger to write.
- A physical write or a host-memory write goes to the frame that is mapped at that time, and it does not report a problem. If the guest remaps the frame, the change stays with that frame.

Neither type of write keeps write protection or copy-on-write. The kernel does a debugger write with `MMDBG_COPY_UNSAFE`, which makes the PTE writable while the write occurs, so no fault occurs and the kernel does not copy a shared page. The kernel also has a copy-on-write path, but that path needs IRQL <= APC_LEVEL, which a debugger that holds all other processors frozen can never get.

As a result, if you write a breakpoint into a shared image page, every process that maps that page sees the breakpoint, whatever the type of write. See [breakpoints in shared pages](breakpoints.md#user-mode-breakpoints-in-shared-pages).

`ntoseye` checks the identity of the host mapping when it attaches, and again when it builds the debugger state after a guest reboot. If the host memory no longer matches, it shows a warning, and reads through the host mapping are then not reliable. Attach again with `--memory-source kd`.

Because the `kd` source does not need access to the hypervisor or to the VM process, you can debug AMD64 and ARM64 Windows VMs or physical machines across any routable network. This has two costs: commands that use memory need a halted target, and network latency makes large scans slower than scans of direct host memory.

If the VM is local, use `--memory-source host` or the default `auto`. For the cost of each read, see [reading memory over KD](../internals/kd-reads.md).

The memory source also controls when `ntoseye` [rebuilds a driver's PDB from guest memory](symbols.md). If reads come from the host, it rebuilds the PDB automatically. If reads go through KD, it rebuilds the PDB only when you enter `.reload <module>`.

## Paged-out memory

When the guest trims a page from a working set, the page usually stays in RAM on the standby list or the modified list, and its PTE stays in the *transition* state. Both the host page walk and target reads can read these pages, so reads of trimmed memory work normally. The same holds for a page table that the guest trimmed: the host page walk reads it from its frame and goes on to the pages under it.

A write to a trimmed page fails. The kernel can use the frame for a different purpose or read the page from disk again, and the change would then be lost or go to an unrelated location.

If a process has never touched a page of a DLL or a mapped file, the process has no PTE for that page, but a different process that maps the same file often has that page in memory. The host page walk finds the page through the VAD of the process and reads the frame that the shared prototype PTE of the section records. This lets `ntoseye` read the code and unwind tables of a DLL in every process that maps the DLL. {command}`!vtop` shows such a page as `mapping : section`. These pages are also read-only.

### Compressed memory

With memory compression on, which is Windows' default on client editions, the guest compresses most trimmed pages of processes into its compression store in RAM instead of writing them to the page file. Their PTEs then point into a virtual page file, the store's. The host page walk reads such a page from the store and decompresses it, so the read works like a read of a page in memory. Windows also compresses the page tables of a trimmed process into the store, and the walk reads such a table from the store and goes on to the page. The page is read-only, as the trimmed pages above are, and `.dump /u` captures it.

This works on the `memory` backend, and on `kd` and `kdnet` with either memory source: with the `kd` source, a page that the target refuses to read is walked on the host. It also works in a dump that holds the memory of the store's process, `MemCompression`: a complete or active memory dump, a dump that {command}`.dump` writes, and a `virsh dump`. A kernel memory dump holds no process memory, so neither the page nor the store is in it. A page whose compressed data the guest moved to the page file reads as unavailable.

`ntoseye` reads the store's layout from the kernel's own code the first time it needs it, because the PDB does not describe the store's structures and they change between Windows releases. It reads the code from the kernel's file in the symbol cache when the cache has the file. With the `kd` memory source, it downloads the file if the cache does not have it, because reading the kernel's 12 MiB of code through KD takes more than half a minute. It reads the code from guest memory only when it cannot get the file. This works for 64-bit Windows 10 1703 and later, for builds whose PDB types the partition's store fields (`_MI_PARTITION_STORES.VirtualPageFileNumber` and `StoreProcess`). Where the layout is not recognized, or memory compression is off, a page in the store reads as unavailable, as a page on disk does. Windows creates the store some time after boot, or when memory compression is turned on with `Enable-MMAgent -MemoryCompression`, which takes effect without a restart. Until the store exists, `ntoseye` looks for it again each time the target halts, or about once a second while the target runs.

A page that `ntoseye` cannot read says where it is. {command}`!pte` adds a line after its table, such as `in page file 0 at page 0x3fe02f`, or, for a page in the memory-compression store that does not decode, why not; a command whose read failed adds the same as a note after its error.

A read of a page that is on disk shows the page as unavailable. To get it, use {command}`.pagein`, which tells the guest to read the page into memory:

```
.pagein /p 5280 0x1048000
```

The guest's debugger worker thread reads the page, so the target runs again and then halts at `nt!DbgBreakPointWithStatus` instead of at its previous location. The target must run because no code can fault a page in while all processors are frozen.

For user-space addresses, use `/p`, which first attaches the worker thread to the process.
