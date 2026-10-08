# MCP integration

`ntoseye` can run as an [MCP](https://modelcontextprotocol.io) server, which gives an agent WinDbg syntax and run control with a time limit on each call.

:::{tip}
If the agent's harness keeps a Python kernel alive between calls, such as oh-my-pi's `eval` tool or a Jupyter kernel, tell the agent to use the [Python SDK](../scripting/sdk.md) instead. The SDK runs the same WinDbg-style commands (`dbg.command("!process 0 0")`) and also returns structured values (`dbg.processes`, `dbg.types`, `dbg.memory`), so a script can filter or walk them and give the agent only the result. The SDK and this server each attach to the target themselves, so use only one of them at a time.
:::

| Tool | Purpose |
| --- | --- |
| `command` | Runs one REPL line and returns its text with a `[target ...]` trailer. A `;` separates commands, and {command}`help` lists them. The arguments are `line` and `timeout_ms` (default 10 s, maximum 5 min). |
| `output` | Reads more of a long `command` result: the lines from `offset`, or only the lines that contain `filter`. The arguments are `id`, `offset`, `limit`, and `filter`. |
| `open` / `close` | `open` attaches to a target using `backend`, `connect`, and, for `kdnet`, `key`. For a crash dump, use `backend: dump` with the dump path as `connect`. `close` releases the target. The server holds one session at a time. |

## Run control

The `command` tool works like a WinDbg prompt, with one difference: a call never blocks for longer than `timeout_ms`.

### Commands and the target state

- A resuming command ({command}`g`, {command}`gh`, {command}`gn`, {command}`p`, {command}`t`, {command}`gu`, {command}`pa`, {command}`wt`, {command}`.reboot`, ...) resumes the target and waits up to `timeout_ms` for the next stop. The result shows the stop the same way the REPL does, with the breakpoint banner, the registers, and the stack. If the target does not stop in time, the result ends with `[target running]`, and the target keeps running without losing any data.
- A command that needs a halted target ({command}`k`, {command}`r`, {command}`bp`, {command}`t`, ...) and arrives while the target runs waits up to `timeout_ms` for the stop, shows it, and then runs, the same way WinDbg queues input that you type at a running debuggee. If the target is still running when the time limit ends, the result reports this and ntoseye does not run the command. To wait longer, send the command again.
- Memory, process, module, and struct commands do not wait. They work on a running target when the memory comes from the host, as with the default `--memory-source auto` on a local VM and with the memory and gdb backends. When the session reads memory over KD, these commands fail with a message that gives the reason.
- A resuming command sent while the target runs also waits for the stop, but ntoseye then shows the stop and does not run the command in this call, so the agent sees the stop before the target continues past it.
- ntoseye checks each command on a `;` line against the target state at the moment that command starts, instead of the state when the line arrived. This is why `break; bp nt!NtCreateFile; g` works as one call: {command}`break` stops the guest, {command}`bp` runs on the halted target, and {command}`g` resumes it.
- If no breakpoint is set, nothing that ntoseye set up can stop the guest, so a command that needs a halted target fails at once instead of waiting for `timeout_ms`, and the result says to send {command}`break` first. The guest can still stop by itself, for example at a bugcheck, and an empty `line` waits for such a stop.
- {command}`break` interrupts a running target. On a halted target it does nothing and says so, so `break; bp ...; g` works in either state.
- A command that reports an error ends its line: the rest does not run, and the result names it. This keeps `bp ...; g` from resuming the guest when the breakpoint failed. A result that contains an error, or a command that ntoseye did not run, is marked as an error (`isError`).
- A stop can occur between calls, for example when the guest hits a breakpoint while the agent thinks, and the next result shows that stop at the top. If that next call is a resuming command, ntoseye does not run it in this call, so the agent sees the stop before the target continues past it.
- A multi-step command ({command}`pa`, {command}`pt`, {command}`gu`, {command}`wt`) can take longer than the time limit. The target then keeps running to its next stop, and the next command that needs a halted target collects that stop.
- An empty `line` runs no command and only waits.

### The trailer

The trailer takes one of two forms:

- `[target running]`
- `[target halted @ <vcpu> <rip> <symbol> | process <name> (<pid>) | scope <name> (<pid>)]`

In the halted form, `process` is the process whose page tables the stopped vCPU has loaded, and `scope` is the {command}`.process` inspection scope that memory commands read through. The scope stays after the target resumes, so `process` and `scope` can differ.

A vCPU that runs a guest partition's VP shows that guest's code, and the trailer names the VP: `[target halted @ p01.02 0x56383cc2d7df | runs partition 0x5 VP 2]`. While {command}`.partition` shows a guest partition in place of the target, the trailer ends with `| inspecting partition 0x4`, and everything before it is that guest's: its VPs are the vCPUs (`p4.1`), and the process is its own.

If a vCPU halted in the Windows hypervisor, the trailer shows `hv+<offset>` and adds the location where Windows stopped, for example `| saved VTL0 nt!HalProcessorIdle+0xf`, with the hypercall that VTL made when its last exit was a `VMCALL` (`| saved VTL0 hvcall!Hypercall (hypercall 0x0003 HvCallFlushVirtualAddressList fast rep 0/1)`). When the processor serves a guest partition's VP, the trailer adds it too: `| serving partition 0x3 VP 2 VTL0 ffffffffc0000000, last exit VMCALL (hypercall 0x000b HvCallSendSyntheticClusterIpi fast)`. For more information, refer to [VBS](../vbs/hypervisor-stops.md#where-nt-left-off-under-the-hypervisor).

After a reboot, the target stops, and over KD it stops at the first boot notification of the new kernel. Until the kernel's module list exists, the trailer adds `boot in progress`. Kernel symbols and `bp nt!...` already work at this point, which makes it the place to set early-boot breakpoints, but the process and module lists do not work yet. {command}`g` lets the boot continue. While the target runs, wait for the next stop instead of enumerating the state, because that state is stale.

### Debug output

ntoseye appends the guest debug output (`DbgPrint`) captured since the previous call to the result, as lines that start with `[dbgprint] ...`.

### Long results

A listing such as `x nt!*`, `!vad` or `!process 0 7` can run to megabytes, which would fill an agent's context in one call. A result longer than about 24,000 characters (roughly 12,000 tokens of debugger output) shows only its first page, followed by a footer and the trailer:

```text
[output 3: 35123 lines, offsets 0-611 shown; the output tool reads on from offset 612, or with a filter finds lines in it]
```

The `output` tool reads the rest without running the command again: `{"id": 3, "offset": 612}` returns the next page, and `{"id": 3, "filter": "explorer"}` returns only the lines that contain `explorer`, each after its offset, so that a later call can read around a match. The server keeps the latest long results in memory, up to 64 MB, for as long as it runs, and reading them needs no session. ntoseye writes no files for them, so they also work for a client that has no access to the host's file system.

ntoseye also removes the spaces that pad table rows at their ends from every result.

### Breakpoint example

A typical breakpoint flow is:

1. Send `break; bp nt!NtCreateFile; g`.
2. Send {command}`k`. If {command}`g` returned while the target still ran, {command}`k` waits for the breakpoint.

For a user-mode breakpoint, give the process, and ntoseye resolves the symbol in that process: `break; bu /p <pid> user32!PeekMessageW; g`. You do not need a `.process /p` first, because the debugger loads the symbols of that module itself. For more information, refer to [symbols](../using/symbols.md).

When a backtrace goes through a module whose PDB is not in the cache yet, ntoseye shows those frames as `module+offset` and gets the PDB in the background without making the call wait. A later {command}`k` shows the names.

## Target at server start

The server reads `--backend`, `--connect`, `--kdnet-key`, and `--dump` to attach at launch, so you must set up the VM and its debug transport the same way as for the REPL. For more information, refer to [Choosing a backend](../setup/backends.md). Without these options, the server starts with no target, and the client attaches with `open`.

The guest runs freely between calls. When a breakpoint on a shared page stops the wrong process, ntoseye absorbs the hit in the background and lets the guest continue, so the guest does not stay frozen.

## stdio (default)

The MCP client starts `ntoseye mcp` as a subprocess and communicates with it over stdin and stdout. Most desktop MCP clients use a JSON file that gives the command to start:

```json
{
  "mcpServers": {
    "ntoseye": {
      "command": "ntoseye",
      "args": ["mcp"]
    }
  }
}
```

Put the target options after the subcommand, for example to set the backend and the socket:

```json
{
  "mcpServers": {
    "ntoseye": {
      "command": "ntoseye",
      "args": ["mcp", "--backend", "kd", "--connect", "/tmp/ntoseye-kd.sock"]
    }
  }
}
```

For KDNET, use `["mcp", "--backend", "kdnet", "--kdnet-key", "1.2.3.4"]`. To force target-mediated memory, add `["--memory-source", "kd"]`, and add `--connect` only to change the default `0.0.0.0:50000` listener.

The `open` tool accepts the same backend, connect, and key values. If the server starts without a target, it tells the agent to ask the user how the VM is exposed instead of guessing.

If `ntoseye` is not in `PATH`, use an absolute path for `command` (for example, `../target/release/ntoseye`).

Closing the server's stdin, or sending it `SIGINT`, `SIGTERM`, or `SIGHUP`, detaches the target the same way as `close`: ntoseye removes the installed breakpoints and resumes the guest before the server exits. `SIGKILL` prevents this cleanup and leaves the breakpoint entries installed. For more information, refer to [breakpoint recovery](../using/breakpoints.md).

## Streamable HTTP

Some web MCP clients connect over the network instead of starting a subprocess. For these clients, use `--http`:

```bash
ntoseye mcp --http 127.0.0.1:8080
```

The service is at `http://127.0.0.1:8080/mcp`, and by default HTTP binds only to loopback addresses.

:::{warning}
The `command` tool gives access to the full REPL, including:

- execution control
- guest memory writes ({command}`eb`, {command}`!eb`)
- host filesystem writes ({command}`.dump`, {command}`.logopen`)
- host files that the guest can get ({command}`.kdfiles`)

Use `--unsafe-http` to bind to a non-loopback address only on trusted networks.
:::
