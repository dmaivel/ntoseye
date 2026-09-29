# Disassembler integration (GDB remote protocol)

`ntoseye gdbserver` serves a debugger session over the [GDB Remote Serial Protocol](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Remote-Protocol.html). So IDA, Binary Ninja, Ghidra, gdb, and lldb can control the target with their own debugger UI.

## Client support

| Client | Support | Limits |
| --- | --- | --- |
| IDA | Supported | IDA keeps the name of each thread from the first time it sees that thread |
| gdb, lldb | Supported | |
| Ghidra | Best effort | Runs through gdb. Needs [`ntoseye_regions.py`](https://github.com/dmaivel/ntoseye/blob/master/examples/ghidra/ntoseye_regions.py), which depends on the internals of Ghidra's gdb agent |
| Binja | Best effort | No stack view. Can exit on disconnect |

Best-effort clients work as this page describes. Their other limits are in the client. We do not plan more client-specific support than this page describes.

## Quickstart

Configure the VM as [Choosing a backend](../setup/backends.md) describes. The protocol has no attach request. So you give the target on the command line:

```bash
ntoseye gdbserver --connect /tmp/ntoseye-kd.sock
ntoseye gdbserver --backend kdnet --kdnet-key 1.2.3.4 --listen 127.0.0.1:2345
ntoseye gdbserver --dump crash.dmp
```

By default, the server listens on `127.0.0.1:2345`. QEMU's own stub usually uses `:1234`, and the `gdb` backend can be connected to that stub.

### IDA

The fastest way to start is to let IDA load the running kernel through the server:

```bash
ida -rgdb@127.0.0.1:2345 ntoskrnl.exe
```

IDA opens `ntoskrnl.exe` through the server's [remote file access](#remote-file-access). The server gives the same build that runs on the target. IDA analyzes the file as a normal database, and then it attaches. To open a driver, give its name in the same way, for example `mydriver.sys`.

To attach from a database that you already have:

1. Open `ntoskrnl.exe` or a driver, and let IDA analyze it. The file must be the build that is running.

   `.fetchimage nt` downloads that build and prints its path. Run it in the REPL. If a server runs, you can also use `gdb -batch -ex 'target remote 127.0.0.1:2345' -ex 'monitor .fetchimage nt'`.
2. Select **Debugger > Select debugger > Remote GDB debugger**.
3. In **Debugger > Process options**, set the host to `127.0.0.1` and the port to `2345`.
4. Select **Debugger > Attach to process**.

IDA reads the memory map from the server. So you do not need to add memory regions manually. The server reports `ntoskrnl.exe` as the program and each loaded driver as a library. IDA uses this data to rebase the database.

If you type text at IDA's `GDB` command line, ntoseye runs it as an ntoseye command. Examples are `!process 0 0` and {command}`lm`.

### gdb and lldb

```bash
gdb -ex 'target remote 127.0.0.1:2345'
lldb -o 'gdb-remote 127.0.0.1:2345'
```

gdb does not need local files. It uses the server's [remote file access](#remote-file-access) to load these files:

- `ntoskrnl.exe`, as the program
- each loaded module, as a library

gdb relocates each file to the address where it runs. So disassembly and backtraces show the exports of each module, for example `ntoskrnl!HalProcessorIdle`.

If an image is not in the cache yet, the server downloads it in the background. While the image downloads, gdb reports it as missing. After the image arrives, `sharedlibrary` loads it. If you give a kernel file with `file ntoskrnl.exe`, gdb also relocates that file onto the live kernel.

To run ntoseye commands in gdb, use `monitor`, for example `monitor k` or `monitor dt nt!_EPROCESS @$proc`. In lldb, use `process plugin packet monitor k`. The command `remote get /ntoskrnl.exe ./ntoskrnl.exe` copies the file of the running kernel through the connection.

### Ghidra

Ghidra's debugger controls a local gdb, and that gdb connects to the server. To connect:

1. Import and analyze `ntoskrnl.exe` or a driver, and open it in the **Debugger** tool. To get the running build, use {command}`.fetchimage`.
2. Select **Debugger > Configure and Launch ... using > gdb remote**. Set **Host** to `127.0.0.1`, **Port** to `2345`, and **gdb cmd args** to `-x /path/to/ntoseye/examples/ghidra/ntoseye_regions.py`.
3. Launch.

Ghidra maps the program onto the module that has the same name. So listings, decompilation, and breakpoints follow the live kernel.

Ghidra's gdb agent gets memory regions only from `info proc mappings`. gdb does not supply this command for a PE target. [`ntoseye_regions.py`](https://github.com/dmaivel/ntoseye/blob/master/examples/ghidra/ntoseye_regions.py) reads the `/proc/<pid>/maps` file that the server generates. Without this script, each module has its base at its first section, and the program maps one page away from its correct address.

To run ntoseye commands, use `monitor` in the gdb terminal pane.

### Binary Ninja

To connect:

1. Open `ntoskrnl.exe` or a driver. To get the running build, use {command}`.fetchimage`.
2. Select the **GDB RSP** debug adapter.
3. Select **Connect to Remote Process**. The adapter does not support **Connect to Debug Server**.

The adapter reads its module list and memory map from a Linux `/proc/<pid>/maps` file. The server generates this file from the loaded modules. So the database rebases onto the live module, and addresses resolve to module names.

These functions work:

- registers
- memory
- breakpoints
- stepping
- `monitor` commands in the debugger console

The adapter does not have its own stack walk. So the stack view stays empty. To see the stack, use `monitor k`.

:::{warning}
Do not use **Restart**. Restart stops the connection, and then it tries to start a process again. A kernel target cannot do this. When the connection stops, the server detaches and the guest continues to run. To connect again, disconnect and then connect.
:::

Binary Ninja can exit if it disconnects while it reads memory. At that time, the server has already detached correctly, and the guest continues to run.

## Feature mapping

| Protocol surface | ntoseye |
| --- | --- |
| Threads | Backend execution contexts (vCPUs), as {command}`~` lists them. At each stop, the server names each thread with the process and symbol that it runs. IDA keeps the name from the first time it sees the thread. So in IDA, only the vCPU part of the name stays current |
| Registers | The AMD64 or AArch64 register file, with GDB's standard names. If gdb requires a register that the transport does not have, that register reads as unavailable, for example x87 over KD. If the transport does not have an optional register, the server does not describe it. Examples are segment bases over KD and debug registers over QEMU's stub |
| Memory | Virtual reads and writes in the current inspection context |
| Software breakpoints (`Z0`) | `bp <address>` |
| Hardware breakpoints (`Z1`) | `ba e1 <address>` |
| Watchpoints (`Z2`-`Z4`) | `ba w` and `ba r`. A read watch also traps writes, because x86 has no read-only watch |
| Step and continue | Step does a single-step of the selected vCPU. Continue resumes all vCPUs |
| Interrupt | Break-in. The server reports it as `SIGINT` |
| `monitor` | Any ntoseye command that does not resume, step, reboot, or crash the target. `q` and `.shell` are not available |
| Library list | Kernel modules. After {command}`.process`, also the modules of the current process. The name of each library is `/` followed by its file name |
| Program | `/ntoskrnl.exe`, with the relocation of the kernel from the preferred base of its file (`qOffsets`) |
| Memory map | The user half and the kernel half of the address space. Each library image is a separate region |
| Console output | Guest `DbgPrint` output and stop details, while the target runs |
| Remote files (`vFile`) | Read-only. The PE file of the loaded module that has the requested file name, and a generated `/proc/<pid>/maps` |

Each stop halts the full target. If the target stops on a breakpoint that the client set, the server reports that breakpoint. The server reports all other stops as a signal, and it prints the details to the client's console:

| Stop | Signal |
| --- | --- |
| Step, `STATUS_BREAKPOINT`, `monitor bp` hit, reboot, `sxe ld` module load | `SIGTRAP` |
| Access violation, in-page error | `SIGSEGV` |
| Illegal or privileged instruction | `SIGILL` |
| Integer or floating-point fault | `SIGFPE` |
| Bugcheck | `SIGABRT` |

Hardware breakpoints and watchpoints need KD or KDNET. They use the same four debug-register slots that {command}`ba` uses.

## Remote file access

When a client opens a file through the server, it gets the PE file of the loaded module with that file name. The directory in the path has no effect. The server finds the module by the file name, and the comparison is not case-sensitive. The server looks first in the current scope, and then in the kernel modules. For example, these paths all resolve by file name:

- `ntoskrnl.exe`
- `C:\Windows\System32\ntdll.dll`
- `/anything/mydriver.sys`

The file comes from the symbol cache. The cache key is the same key that [`.fetchimage`](../reference/commands/symbols-types-and-expressions.md) uses. So the file is the build that is running. If a client tries to open a file for writing, the open fails.

An open never waits for the network. Clients time out quickly. For example, IDA times out after one second. A late reply puts the rest of the session out of sync.

If an image is not in the cache yet, the server downloads it in the background. The server downloads one image at a time. Until the image arrives, opens of that image fail. To wait for the image, run `.fetchimage <module>`.

When the server attaches, it starts to download the kernel image, because IDA opens that image on each attach. When gdb connects, it opens the image of each module. So the first gdb connection puts all the module images in the download queue.

The server generates `/proc/<pid>/maps` when a client opens it. You can use any pid, or `self`. The file contains these lines:

- An `r-xp` line for each published module. The path on the line is `/` followed by the file name of the module.
- Unnamed `rw-p` lines for the RAM between the modules.

The file covers the same address space as the memory map.

## Process context

Memory reads and new breakpoints use ntoseye's inspection context. They do not use the thread that the client selects.

To read the user space of a process, change the context with `monitor .process <eprocess>`. After this change, new breakpoints apply only to that process, as with {command}`bp` in the REPL.

The client caches memory, and it does not know that the context changed. So after you change the context, refresh the views of the client. In IDA, select **Debugger > Refresh memory**.

If the client reads the registers of a different thread, ntoseye's current vCPU does not change. `monitor` commands continue to operate on the stopped vCPU, or on the vCPU that you select with `monitor ~<n>s`.

## Resume and step from the client

If a `monitor` command resumes, steps, reboots, or crashes the target, ntoseye gives an error and does not run the command. Examples are {command}`g`, {command}`p`, {command}`t`, {command}`gu`, {command}`.reboot`, and {command}`.crash`. The reason is that the client caches registers and memory for the last stop that it saw.

Breakpoints that you set with `monitor bp ... do "..."` still run their actions. If the action ends with `gc`, the target continues, and the server does not report a stop.

## Sessions

The server keeps the session when one client disconnects and a different client connects. It serves one client at a time. When a client connects, the target is halted.

When a client detaches or disconnects, the server removes the breakpoints of that client and resumes the guest. Breakpoints that you set through `monitor` stay for the next client.

`SIGINT`, `SIGTERM`, and `SIGHUP` stop the server. Before the server exits, it removes all breakpoints and resumes the guest.

## Limitations

- If a driver loads while the target runs, the driver appears in the library list the next time that the client reads the list.

## Troubleshooting

`NTOSEYE_GDB_TRACE=1` prints each packet to stderr. Each line shows the seconds since the first line. There are two types of lines, and both use the same clock:

- `client` lines show the conversation between the server and its client.
- `stub` lines show the conversation between the `gdb` backend and the hypervisor's stub.

With these lines, you can compare the timeouts and retries of a client with the time that each reply took. You can also see what the backend did for each reply. ntoseye cuts long packets at 200 bytes.

To see IDA's side of the conversation, start IDA with `-z10000`. IDA then prints `GDB: ...` lines in the Output window.
