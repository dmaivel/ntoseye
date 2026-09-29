# Reading memory over KD

With `--memory-source kd`, or when the target memory is not on this host, ntoseye reads all guest memory through the Windows kernel debugger transport, and each read is a round trip of one request and one reply.

Over KDCOM on an emulated UART, the request alone takes about 2 ms to reach the target. QEMU's 16550 gives the guest one byte per main-loop iteration, at the FIFO trigger level that KDCOM sets, and a KD request and its ACK are about 90 bytes from host to guest. The reply then takes about 5 µs per byte, so a 2 KiB read takes about 12 ms. KDNET does not have these two minimum costs.

If host memory is not available, ntoseye keeps reads few and short in these ways:

- While the target stays halted, ntoseye serves virtual reads through the target from a cache of 512-byte lines. A cache miss fetches from the start of the line to the end of the request, so all the fields of one structure need only one request, while a large read still needs the same 2 KiB requests as without the cache. A KDNET datagram carries 1 KiB of data, and ntoseye adapts the fills to this size after the first short reply. ntoseye discards the cache when the target runs, and each time the debugger writes memory or sets or removes a breakpoint.
- The host page walk, which ntoseye uses for the user space of a process other than the one on the halted processor, reads page-table entries in the same 512-byte lines, so adjacent pages share their upper-level entries and their run of PTEs. Other physical reads do not get read-ahead, because they can touch a device. ntoseye walks the loader list of a process once per halt, however many of its threads it unwinds.
- ntoseye never copies a full module image. At attach, it reads the headers of each module with one probe. The unwinder fetches 2 KiB blocks of `.pdata`/`.rdata` when its lookups touch them and keeps them for the session, and a stack walk reads the stack one page at a time.
- ntoseye records the PDB of each module by the image identity that the symbol server uses, and keeps these records in `~/.ntoseye/symbols/identities` with the file name, `TimeDateStamp`, and `SizeOfImage` as the key. Because the loader's module list already contains all three values, ntoseye identifies a module from an earlier session without reads from the target, and {command}`lm` shows its symbol source as `cached`. If a recorded PDB does not load, ntoseye deletes the record and finds the module from the target again.

ntoseye walks the process list, the kernel-module list, and the driver-object list only when a listing command, a tab completion, or a break context in a user-mode process needs them. The first walk after a halt serves all later uses until the target runs again.

The process walk reads one span for each `_EPROCESS`, and reads the PEB only for names that the kernel's 15-byte `ImageFileName` may have truncated, so the prompt after attach and after each stop does not wait for a full process walk.
