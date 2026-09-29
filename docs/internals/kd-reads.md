# Reading memory over KD

With `--memory-source kd`, or if the target memory is not on this host, ntoseye reads all guest memory through the Windows kernel debugger transport. Each read is a round trip: one request and one reply.

Over KDCOM on an emulated UART, the request alone takes about 2 ms before the target gets it. These are the causes:

- QEMU's 16550 gives the guest one byte per main-loop iteration, at the FIFO trigger level that KDCOM sets.
- A KD request and its ACK are approximately 90 bytes from host to guest.

The reply then takes about 5 µs per byte. For example, a 2 KiB read takes approximately 12 ms. KDNET does not have these two minimum costs.

If host memory is not available, ntoseye uses these methods to make the session need few, short reads:

- While the target stays halted, ntoseye serves virtual reads through the target from a cache of 512-byte lines. On a cache miss, ntoseye fetches from the start of the line to the end of the request. So all the fields of one structure need only one request. A large read still needs the same 2 KiB requests as without the cache. A KDNET datagram carries 1 KiB of data, and after the first short reply, ntoseye adapts the fills to this size. ntoseye discards the cache when the target runs, and each time the debugger writes memory or sets or removes a breakpoint.
- The host page walk reads page-table entries in the same 512-byte lines. ntoseye uses the host page walk for the user space of a process other than the process of the halted processor. So adjacent pages share their upper-level entries and their run of PTEs. Other physical reads do not get read-ahead, because they can touch a device. ntoseye walks the loader list of a process one time per halt, independent of the number of its threads that it unwinds.
- ntoseye never copies a full module image. At attach, ntoseye reads the headers of each module with one probe. The unwinder fetches 2 KiB blocks of `.pdata`/`.rdata` when its lookups touch them, and keeps them for the session. A stack walk reads the stack one page at a time.
- ntoseye records the PDB of each module by the image identity that the symbol server uses. It keeps these records in `~/.ntoseye/symbols/identities`, with the file name, `TimeDateStamp`, and `SizeOfImage` as the key. The module list of the loader already contains all three values. ntoseye identifies a module from an earlier session without reads from the target. For such modules, {command}`lm` shows the symbol source as `cached`. If a recorded PDB does not load, ntoseye deletes the record and finds the module from the target again.

ntoseye walks the process list, the kernel-module list, and the driver-object list only when an operation needs them. These operations need a list:

- A listing command.
- A tab completion.
- A break context in a user-mode process.

The first walk after a halt serves all later uses until the target runs again.

The process walk reads one span for each `_EPROCESS`. It reads the PEB only for names that the kernel's 15-byte `ImageFileName` possibly truncated. So the prompt after attach and after each stop does not wait for a full process walk.
