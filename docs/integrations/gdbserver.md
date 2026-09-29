# Disassembler integration (GDB remote protocol)

`ntoseye gdbserver` serves a debugger session over the [GDB Remote Serial Protocol](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Remote-Protocol.html), so IDA, Binary Ninja, Ghidra, gdb, and lldb can control the target with their own debugger UI.

## Client support

| Client | Support | Limits |
| --- | --- | --- |
| IDA | Supported | IDA keeps the name of each thread from the first time it sees that thread |
| gdb, lldb | Supported | |
| Ghidra | Best effort | Runs through gdb and needs [`ntoseye_regions.py`](https://github.com/dmaivel/ntoseye/blob/master/examples/ghidra/ntoseye_regions.py), which depends on the internals of Ghidra's gdb agent |
| Binja | Best effort | No stack view, and can exit on disconnect |

Best-effort clients work as this page describes, but their other limits are in the client, and we do not plan more client-specific support than this page describes.

## Quickstart

Configure the VM as [Choosing a backend](../setup/backends.md) describes. Because the protocol has no attach request, you give the target on the command line:

```bash
ntoseye gdbserver --connect /tmp/ntoseye-kd.sock
ntoseye gdbserver --backend kdnet --kdnet-key 1.2.3.4 --listen 127.0.0.1:2345
ntoseye gdbserver --dump crash.dmp
```

By default, the server listens on `127.0.0.1:2345`. QEMU's own stub usually uses `:1234`, and the `gdb` backend can connect to that stub.

### IDA

The fastest way to start is to let IDA load the running kernel through the server:

```bash
ida -rgdb@127.0.0.1:2345 ntoskrnl.exe
```

IDA opens `ntoskrnl.exe` through the server's [remote file access](#remote-file-access), which gives the same build that runs on the target, analyzes it as a normal database, and then attaches. To open a driver, give its name the same way, for example `mydriver.sys`.

To attach from a database that you already have:

1. Open `ntoskrnl.exe` or a driver, and let IDA analyze it. The file must be the build that is running.

   To get that build, run `.fetchimage nt` in the REPL, which downloads it and prints its path. While a server runs, you can also use `gdb -batch -ex 'target remote 127.0.0.1:2345' -ex 'monitor .fetchimage nt'`.
2. Select **Debugger > Select debugger > Remote GDB debugger**.
3. In **Debugger > Process options**, set the host to `127.0.0.1` and the port to `2345`.
4. Select **Debugger > Attach to process**.

IDA reads the memory map from the server, so you do not need to add memory regions manually. The server reports `ntoskrnl.exe` as the program and each loaded driver as a library, and IDA uses this to rebase the database.

Text that you type at IDA's `GDB` command line runs as an ntoseye command, for example `!process 0 0` or {command}`lm`.

### gdb and lldb

```bash
gdb -ex 'target remote 127.0.0.1:2345'
lldb -o 'gdb-remote 127.0.0.1:2345'
```

gdb does not need local files. Through the server's [remote file access](#remote-file-access), it loads `ntoskrnl.exe` as the program and each loaded module as a library. Because gdb relocates each file to the address where it runs, disassembly and backtraces show the exports of each module, for example `ntoskrnl!HalProcessorIdle`.

If an image is not in the cache yet, the server downloads it in the background, and gdb reports it as missing until it arrives. After that, `sharedlibrary` loads it. If you give a kernel file with `file ntoskrnl.exe`, gdb also relocates that file onto the live kernel.

To run ntoseye commands in gdb, use `monitor`, for example `monitor k` or `monitor dt nt!_EPROCESS @$proc`. In lldb, use `process plugin packet monitor k`. `remote get /ntoskrnl.exe ./ntoskrnl.exe` copies the running kernel's file through the connection.

### Ghidra

Ghidra's debugger controls a local gdb, which connects to the server. To connect:

1. Import and analyze `ntoskrnl.exe` or a driver, and open it in the **Debugger** tool. To get the running build, use {command}`.fetchimage`.
2. Select **Debugger > Configure and Launch ... using > gdb remote**. Set **Host** to `127.0.0.1`, **Port** to `2345`, and **gdb cmd args** to `-x /path/to/ntoseye/examples/ghidra/ntoseye_regions.py`, and then launch.

Ghidra maps the program onto the module that has the same name, so listings, decompilation, and breakpoints follow the live kernel.

Ghidra's gdb agent gets memory regions only from `info proc mappings`, which gdb does not supply for a PE target. [`ntoseye_regions.py`](https://github.com/dmaivel/ntoseye/blob/master/examples/ghidra/ntoseye_regions.py) reads the `/proc/<pid>/maps` file that the server generates instead. Without this script, each module has its base at its first section, and the program maps one page away from its correct address.

To run ntoseye commands, use `monitor` in the gdb terminal pane.

### Binary Ninja

To connect:

1. Open `ntoskrnl.exe` or a driver. To get the running build, use {command}`.fetchimage`.
2. Select the **GDB RSP** debug adapter.
3. Select **Connect to Remote Process**. The adapter does not support **Connect to Debug Server**.

The adapter reads its module list and memory map from a Linux `/proc/<pid>/maps` file, which the server generates from the loaded modules. This lets the database rebase onto the live module and addresses resolve to module names.

These functions work:

- registers
- memory
- breakpoints
- stepping
- `monitor` commands in the debugger console

The adapter does not have its own stack walk, so the stack view stays empty. To see the stack, use `monitor k`.

:::{warning}
Do not use **Restart**. It stops the connection and then tries to start a process again, which a kernel target cannot do. When the connection stops, the server detaches and the guest continues to run. To connect again, disconnect and then connect.
:::

Binary Ninja can exit if it disconnects while it reads memory. By then, the server has already detached correctly, and the guest continues to run.

## Feature mapping

| Protocol surface | ntoseye |
| --- | --- |
| Threads | Backend execution contexts (vCPUs), as {command}`~` lists them. At each stop, the server names each thread with the process and symbol that it runs. Because IDA keeps the name from the first time it sees the thread, only the vCPU part of the name stays current in IDA |
| Registers | The AMD64 or AArch64 register file, with GDB's standard names. A register that gdb requires but the transport does not have reads as unavailable, for example x87 over KD. The server does not describe optional registers that the transport does not have, such as segment bases over KD and debug registers over QEMU's stub |
| Memory | Virtual reads and writes in the current inspection context |
| Software breakpoints (`Z0`) | `bp <address>` |
| Hardware breakpoints (`Z1`) | `ba e1 <address>` |
| Watchpoints (`Z2`-`Z4`) | `ba w` and `ba r`. A read watch also traps writes because x86 has no read-only watch |
| Step and continue | Step single-steps the selected vCPU, and continue resumes all vCPUs |
| Interrupt | Break-in, reported as `SIGINT` |
| `monitor` | Any ntoseye command that does not resume, step, reboot, or crash the target. `q` and `.shell` are not available |
| Library list | Kernel modules, plus the modules of the current process after {command}`.process`. Each library is named `/` followed by its file name |
| Program | `/ntoskrnl.exe`, with the relocation of the kernel from the preferred base of its file (`qOffsets`) |
| Memory map | The user and kernel halves of the address space, with each library image as a separate region |
| Console output | Guest `DbgPrint` output and stop details, while the target runs |
| Remote files (`vFile`) | Read-only. The PE file of the loaded module that has the requested file name, and a generated `/proc/<pid>/maps` |

Each stop halts the full target. If the target stops on a breakpoint that the client set, the server reports that breakpoint. It reports all other stops as a signal and prints the details to the client's console:

| Stop | Signal |
| --- | --- |
| Step, `STATUS_BREAKPOINT`, `monitor bp` hit, reboot, `sxe ld` module load | `SIGTRAP` |
| Access violation, in-page error | `SIGSEGV` |
| Illegal or privileged instruction | `SIGILL` |
| Integer or floating-point fault | `SIGFPE` |
| Bugcheck | `SIGABRT` |

Hardware breakpoints and watchpoints need KD or KDNET, and they use the same four debug-register slots as {command}`ba`.

## Remote file access

When a client opens a file through the server, it gets the PE file of the loaded module with that file name, whatever directory the path gives. The server matches the file name without regard to case, and looks first in the current scope and then in the kernel modules. For example, these paths all resolve by file name:

- `ntoskrnl.exe`
- `C:\Windows\System32\ntdll.dll`
- `/anything/mydriver.sys`

The file comes from the symbol cache, under the same key that [`.fetchimage`](../reference/commands/symbols-types-and-expressions.md) uses, so it is the build that is running. If a client tries to open a file for writing, the open fails.

An open never waits for the network, because clients time out quickly (IDA after one second) and a late reply puts the rest of the session out of sync.

If an image is not in the cache yet, the server downloads it in the background, one image at a time, and opens of that image fail until it arrives. To wait for the image, run `.fetchimage <module>`.

When the server attaches, it starts to download the kernel image, because IDA opens that image on each attach. gdb opens the image of each module when it connects, so the first gdb connection puts all the module images in the download queue.

The server generates `/proc/<pid>/maps` when a client opens it, for any pid or `self`. The file covers the same address space as the memory map and contains:

- An `r-xp` line for each published module, whose path is `/` followed by the file name of the module.
- Unnamed `rw-p` lines for the RAM between the modules.

## Process context

Memory reads and new breakpoints use ntoseye's inspection context instead of the thread that the client selects.

To read the user space of a process, change the context with `monitor .process <eprocess>`. New breakpoints then apply only to that process, as with {command}`bp` in the REPL.

The client caches memory and gets no notice of the context change, so refresh its views after you change the context. In IDA, select **Debugger > Refresh memory**.

If the client reads the registers of a different thread, ntoseye's current vCPU does not change, and `monitor` commands continue to operate on the stopped vCPU or on the vCPU that you select with `monitor ~<n>s`.

## Resume and step from the client

If a `monitor` command resumes, steps, reboots, or crashes the target, ntoseye gives an error and does not run the command, because the client caches registers and memory for the last stop that it saw. Such commands include {command}`g`, {command}`p`, {command}`t`, {command}`gu`, {command}`.reboot`, and {command}`.crash`.

Breakpoints that you set with `monitor bp ... do "..."` still run their actions. If the action ends with `gc`, the target continues, and the server does not report a stop.

## Sessions

The server keeps the session when one client disconnects and another connects, and it serves one client at a time. When a client connects, the target is halted.

When a client detaches or disconnects, the server removes that client's breakpoints and resumes the guest, but breakpoints that you set through `monitor` stay for the next client.

`SIGINT`, `SIGTERM`, and `SIGHUP` stop the server, which removes all breakpoints and resumes the guest before it exits.

## Limitations

- If a driver loads while the target runs, the driver appears in the library list the next time that the client reads the list.

## Troubleshooting

`NTOSEYE_GDB_TRACE=1` prints each packet to stderr, and each line shows the seconds since the first line. There are two types of lines, both on the same clock:

- `client` lines show the conversation between the server and its client.
- `stub` lines show the conversation between the `gdb` backend and the hypervisor's stub.

With these lines, you can compare a client's timeouts and retries with the time that each reply took, and see what the backend did for each reply. ntoseye cuts long packets at 200 bytes.

To see IDA's side of the conversation, start IDA with `-z10000`, and it prints `GDB: ...` lines in the Output window.
