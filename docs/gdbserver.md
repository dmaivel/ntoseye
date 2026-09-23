# Disassembler integration (GDB remote protocol)

`ntoseye gdbserver` serves a debugger session over the [GDB Remote Serial Protocol](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Remote-Protocol.html), so IDA, Binary Ninja, Ghidra, gdb, and lldb can drive the target with their own debugger UI.

## Client support

| Client | Support | Limits |
| --- | --- | --- |
| IDA | Supported | Thread names stay as they were when IDA first saw each thread |
| gdb, lldb | Supported | |
| Ghidra | Best effort | Runs through gdb and needs [`ntoseye_regions.py`](../examples/ghidra/ntoseye_regions.py), which depends on the internals of Ghidra's gdb agent |
| Binja | Best effort | No stack view; may exit on disconnect |

Best-effort clients work as described below, but their remaining limits are in the client, and no client-specific support beyond what is here is planned.

## Quickstart

Configure the VM as described in [Choosing a backend](backends.md). The protocol has no attach request, so the top-level flags name the target:

```bash
ntoseye --connect /tmp/ntoseye-kd.sock gdbserver
ntoseye --backend kdnet --kdnet-key 1.2.3.4 gdbserver --listen 127.0.0.1:2345
ntoseye --dump crash.dmp gdbserver
```

The server listens on `127.0.0.1:2345` by default. QEMU's own stub usually holds `:1234`, and the `gdb` backend may be connected to it.

### IDA

The quickest start lets IDA load the running kernel through the server:

```bash
ida -rgdb@127.0.0.1:2345 ntoskrnl.exe
```

IDA opens `ntoskrnl.exe` through the server's [remote file access](#remote-file-access), which serves the exact build that is running, analyzes it as a normal database, and attaches. Name a driver (`mydriver.sys`) the same way.

To attach from a database you already have:

1. Open `ntoskrnl.exe` (or a driver) and let it analyze. It must be the build that is running. `.fetchimage nt` downloads that build and prints its path: run it in the REPL, or against a running server with `gdb -batch -ex 'target remote 127.0.0.1:2345' -ex 'monitor .fetchimage nt'`.
2. Select **Debugger > Select debugger > Remote GDB debugger**.
3. In **Debugger > Process options**, set the host to `127.0.0.1` and the port to `2345`.
4. Use **Debugger > Attach to process**.

IDA reads the memory map from the server, so no manual memory regions are needed. The server reports `ntoskrnl.exe` as the program and every loaded driver as a library, which IDA uses to rebase the database. Text typed at IDA's `GDB` command line runs as an ntoseye command, for example `!process 0 0` or `lm`.

### gdb and lldb

```bash
gdb -ex 'target remote 127.0.0.1:2345'
lldb -o 'gdb-remote 127.0.0.1:2345'
```

gdb needs no local files: it loads `ntoskrnl.exe` as the program and every loaded module as a library through the server's [remote file access](#remote-file-access), relocated to where they run, so disassembly and backtraces name each module's exports (`ntoskrnl!HalProcessorIdle`). Images that are not cached yet are downloaded in the background while gdb reports them missing; `sharedlibrary` loads them once they arrive. A kernel file given with `file ntoskrnl.exe` is relocated onto the live kernel too.

In gdb, run ntoseye commands with `monitor`, for example `monitor k` or `monitor dt nt!_EPROCESS @$proc`; in lldb, with `process plugin packet monitor k`. `remote get /ntoskrnl.exe ./ntoskrnl.exe` copies the running kernel's file over the connection.

### Ghidra

Ghidra's debugger drives a local gdb, which connects to the server:

1. Import and analyze `ntoskrnl.exe` (or a driver; `.fetchimage` gets the running build), and open it in the **Debugger** tool.
2. Choose **Debugger > Configure and Launch ... using > gdb remote**. Set **Host** to `127.0.0.1`, **Port** to `2345`, and **gdb cmd args** to `-x /path/to/ntoseye/examples/ghidra/ntoseye_regions.py`.
3. Launch.

Ghidra maps the program onto the module with the same name, so listings, decompilation, and breakpoints follow the live kernel. Its gdb agent learns memory regions only from `info proc mappings`, which gdb does not offer for a PE target; without [`ntoseye_regions.py`](../examples/ghidra/ntoseye_regions.py), which reads the server's generated `/proc/<pid>/maps` instead, every module is based at its first section and the program maps a page off. Run ntoseye commands in the gdb terminal pane with `monitor`.

### Binary Ninja

Open `ntoskrnl.exe` (or a driver; `.fetchimage` gets the running build), choose the **GDB RSP** debug adapter, and use **Connect to Remote Process** (the adapter does not support **Connect to Debug Server**). The adapter reads its module list and memory map from a Linux `/proc/<pid>/maps` file, which the server generates from the loaded modules, so the database rebases onto the live module and addresses resolve to module names. Registers, memory, breakpoints, stepping, and `monitor` commands in the debugger console work. The adapter has no stack walk of its own, so the stack view stays empty; use `monitor k`.

Do not use **Restart**: it kills the connection (the server detaches and the guest keeps running) and then tries to relaunch a process, which a kernel target cannot do. Disconnect and connect again instead. Binary Ninja may exit when it disconnects while it is still reading memory; the server has detached cleanly by then and the guest keeps running.

## Feature mapping

| Protocol surface | ntoseye |
| --- | --- |
| Threads | backend execution contexts (vCPUs), as listed by `~`, each named by the process and symbol it is running at every stop (IDA keeps the name from when it first saw the thread, so there only the vCPU part stays current) |
| Registers | the AMD64 or AArch64 register file under GDB's standard names; registers gdb requires that the transport lacks (x87 over KD) read as unavailable, and optional ones it lacks (segment bases over KD, debug registers over QEMU's stub) are not described |
| Memory | virtual reads and writes in the current inspection context |
| Software breakpoints (`Z0`) | `bp <address>` |
| Hardware breakpoints (`Z1`) | `ba e1 <address>` |
| Watchpoints (`Z2`-`Z4`) | `ba w` and `ba r`; a read watch also traps writes, since x86 has no read-only watch |
| Step and continue | single-step of the selected vCPU; continue resumes every vCPU |
| Interrupt | break-in, reported as `SIGINT` |
| `monitor` | any ntoseye command that does not move the target |
| Library list | kernel modules, plus the current process's modules after `.process`, each named `/` and its file name |
| Program | `/ntoskrnl.exe`, with the kernel's relocation from its file's preferred base (`qOffsets`) |
| Memory map | the user and kernel halves of the address space, each library image a region of its own |
| Console output | guest `DbgPrint` output and stop details, while the target runs |
| Remote files (`vFile`) | read-only: the PE file of the loaded module with the requested file name, and a generated `/proc/<pid>/maps` |

Every stop halts the whole target. A stop on a breakpoint the client planted is reported as that breakpoint. Any other stop is a signal, with the detail printed to the client's console:

| Stop | Signal |
| --- | --- |
| Step, `STATUS_BREAKPOINT`, `monitor bp` hit, reboot | `SIGTRAP` |
| Access violation, in-page error | `SIGSEGV` |
| Illegal or privileged instruction | `SIGILL` |
| Integer or floating-point fault | `SIGFPE` |
| Bugcheck | `SIGABRT` |

Hardware breakpoints and watchpoints need KD or KDNET, and take the same four debug-register slots `ba` uses.

## Remote file access

A client that opens a file through the server gets the PE file of the loaded module with that file name, whatever directory the path names: `ntoskrnl.exe`, `C:\Windows\System32\ntdll.dll`, and `/anything/mydriver.sys` all resolve by file name, case-insensitively, first in the current scope and then among kernel modules. The file comes from the symbol cache, keyed exactly as [`.fetchimage`](usage.md#symbols) keys it, so it is the build that is running. Opening for writing is refused.

An open never waits on the network, because clients time out quickly (IDA after one second) and a late reply desynchronizes the rest of the session. An image that is not cached yet is downloaded in the background, one at a time, and opens fail until it arrives; run `.fetchimage <module>` to wait for it instead. The server starts fetching the kernel's image when it attaches, since IDA opens it on every attach. A gdb connecting opens every module's image, so its first connection queues all of them.

`/proc/<pid>/maps` (any pid, or `self`) is generated at open: each published module as an `r-xp` line whose path is `/` and its file name, and the RAM between them as unnamed `rw-p` lines, covering the same address space as the memory map.

## Process context

Memory reads and new breakpoints follow ntoseye's inspection context, not the client's selected thread. Switch it with `monitor .process <eprocess>` to read a process's user space, and new breakpoints are scoped to that process, as with `bp` in the REPL. The client caches memory and does not know the context changed, so refresh its views afterwards (in IDA, **Debugger > Refresh memory**).

Reading another thread's registers does not change ntoseye's current vCPU; `monitor` commands keep acting on the stopped vCPU, or on the one selected with `monitor ~<n>s`.

## Run control belongs to the client

`monitor` commands that resume or step the target (`g`, `p`, `t`, `gu`, ...) are refused, because the client caches registers and memory for the stop it last saw. Breakpoints set with `monitor bp ... do "..."` still run their actions, and a trailing `gc` continues without reporting a stop.

## Sessions

The server keeps the session across clients and serves one client at a time. A connecting client finds the target halted. When a client detaches or disconnects, the server removes that client's breakpoints and resumes the guest. Breakpoints set through `monitor` stay for the next client.

`SIGINT`, `SIGTERM`, and `SIGHUP` stop the server: it removes every breakpoint and resumes the guest before exiting.

## Limitations

- A driver that loads while the target runs appears in the library list the next time the client reads it.

## Troubleshooting

`NTOSEYE_GDB_TRACE=1` prints every packet to stderr, with seconds since the first line: `client` lines are the server's conversation with its client, and `stub` lines are the `gdb` backend's with the hypervisor's stub, on the same clock. A client's timeouts and retries can then be matched against how long each reply took and what the backend did for it. Long packets are cut at 200 bytes. IDA prints its side of the conversation (`GDB: ...` lines in the Output window) when started with `-z10000`.
