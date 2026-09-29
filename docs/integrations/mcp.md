# MCP integration

`ntoseye` can run as an [MCP](https://modelcontextprotocol.io) server. In this mode, an agent uses WinDbg syntax, and each call has a time limit for run control.

:::{tip}
If the harness of the agent keeps a Python kernel alive between calls, tell the agent to use the [Python SDK](../scripting/sdk.md). Examples of such kernels are the `eval` tool of oh-my-pi and a Jupyter kernel. The SDK runs the same WinDbg-style commands (`dbg.command("!process 0 0")`). It also returns structured values (`dbg.processes`, `dbg.types`, `dbg.memory`). So a script can filter or walk these values and give only the result to the agent. The SDK and this server each attach to the target themselves, so use only one of them at a time.
:::

| Tool | Purpose |
| --- | --- |
| `command` | Runs one REPL line and returns its text and a `[target ...]` trailer. A `;` separates commands, and {command}`help` lists the commands. The arguments are `line`, `timeout_ms` (default 10 s, maximum 5 min), and `format` (`text` or [`json`](#structured-results)). |
| `open` / `close` | `open` attaches to a target. Its arguments are `backend`, `connect`, and, for `kdnet`, `key`. For a crash dump, use `backend: dump` and give the dump path as `connect`. `close` releases the target. The server has one session at a time. |

## Run control

The `command` tool works like a WinDbg prompt. There is one difference: a call never blocks for longer than `timeout_ms`.

### Commands and the target state

- A resuming command ({command}`g`, {command}`gh`, {command}`gn`, {command}`p`, {command}`t`, {command}`gu`, {command}`pa`, {command}`wt`, {command}`.reboot`, ...) resumes the target. Then it waits up to `timeout_ms` for the next stop. The result shows the stop in the same way as the REPL: the breakpoint banner, the registers, and the stack. If the target does not stop in time, the result ends with `[target running]`. The target continues to run, and no data is lost.
- Some commands need a halted target ({command}`k`, {command}`r`, {command}`bp`, {command}`t`, ...). If you send such a command while the target runs, the command waits up to `timeout_ms` for the stop. Then ntoseye shows the stop and runs the command. WinDbg queues input that you type at a running debuggee in the same way. If the target still runs at the end of the time limit, the result tells you this, and ntoseye does not run the command. To wait longer, send the command again.
- Memory, process, module, and struct commands do not wait. They work on a running target if the memory comes from the host. This is the case for the default `--memory-source auto` with a local VM, and for the memory and gdb backends. If the session reads memory over KD, these commands fail with a message that gives the reason.
- If you send a resuming command while the target runs, the command also waits for the stop. Then ntoseye shows the stop and does not run the command for this call. So the agent sees the stop before the target continues past it.
- ntoseye checks each command on a `;` line against the target state at the time that command starts. It does not use the state at the time the line arrives. So `break; bp nt!NtCreateFile; g` works as one call. {command}`break` stops the guest, {command}`bp` runs on the halted target, and {command}`g` resumes the target.
- If you send only {command}`bp` and nothing stops the guest, the command waits for the full `timeout_ms`. Then the result tells you that ntoseye did not run the command.
- {command}`break` interrupts a running target.
- A stop can occur between calls. For example, the guest can hit a breakpoint while the agent thinks. The next result shows that stop at the top. If that next call is a resuming command, ntoseye does not run it for this call. So the agent sees the stop before the target continues past it.
- A multi-step command ({command}`pa`, {command}`pt`, {command}`gu`, {command}`wt`) can take longer than the time limit. In this case, the target continues to run to its next stop. The next command that needs a halted target collects that stop.
- An empty `line` runs no command and only waits.

### The trailer

The trailer has one of these two forms:

- `[target running]`
- `[target halted @ <vcpu> <rip> <symbol> | process <name> (<pid>) | scope <name> (<pid>)]`

In the halted form, `process` is the process whose page tables the stopped vCPU has loaded. `scope` is the {command}`.process` inspection scope, which memory commands read through. The scope stays after the target resumes, so `process` and `scope` can be different.

If a vCPU halted in the Windows hypervisor, the trailer shows `hvix64+<offset>`. It also adds the location where Windows stopped, for example `| saved VTL0 nt!HalProcessorIdle+0xf`. For more information, refer to [VBS](../platforms/vbs.md#where-nt-left-off-under-the-hypervisor).

After a reboot, the target stops. Over KD, it stops at the first boot notification of the new kernel. Until the module list of the kernel exists, the trailer adds `boot in progress`. At this point, kernel symbols and `bp nt!...` work, but the process and module lists do not work yet. So this is the place to set early-boot breakpoints. {command}`g` lets the boot continue. While the target runs, wait for the next stop, and do not enumerate the state, because it is stale.

### Debug output

ntoseye adds the guest debug output (`DbgPrint`) that it captured since the previous call to the result. Each line starts with `[dbgprint] ...`.

### Breakpoint example

A typical breakpoint flow is:

1. Send `break; bp nt!NtCreateFile; g`.
2. Send {command}`k`. If {command}`g` returned while the target still ran, {command}`k` waits for the breakpoint.

For a user-mode breakpoint, give the process. ntoseye then resolves the symbol in that process: `break; bu /p <pid> user32!PeekMessageW; g`. You do not need a `.process /p` before this command, because the debugger loads the symbols of that module itself. For more information, refer to [symbols](../using/symbols.md).

A backtrace can go through a module whose PDB is not in the cache yet. In this case, ntoseye shows those frames as `module+offset` and gets the PDB in the background. The call does not wait for the PDB. A later {command}`k` shows the names.

## Structured results

`format: "json"` returns `{ok, output, result, target, debug_output}` as structured content. The fields are:

- `output`: the text that the command printed.
- `target`: the run-state snapshot (`{running, current_thread, rip, symbol, saved_vtl, attached_process, stopped_process, stopped_thread, coherent, kernel_base}`).
- `debug_output`: the captured `DbgPrint` lines.
- `result`: the typed decoding, for commands that have one. For other commands, `result` is `null`.

The decodings are the same as the methods of the [Python SDK](../scripting/sdk.md). Examples are the `!` inspectors, {command}`lm`, {command}`!process`, {command}`k`, {command}`bl`, {command}`dt`, {command}`?`, {command}`r`, and {command}`!analyze`. For the full set, refer to the SDK surface table.

## Target at server start

The server reads `--backend`, `--connect`, `--kdnet-key`, and `--dump` to attach at launch. So you must set up the VM and its debug transport in the same way as for the REPL. For more information, refer to [Choosing a backend](../setup/backends.md). Without these options, the server starts with no target, and the client attaches with `open`.

The guest runs freely between calls. A breakpoint on a shared page can stop the wrong process. ntoseye absorbs these hits in the background and lets the guest continue. So the guest does not stay frozen.

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

Put the target options after the subcommand. For example, this configuration sets the backend and the socket:

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

For KDNET, use `["mcp", "--backend", "kdnet", "--kdnet-key", "1.2.3.4"]`. To force target-mediated memory, add `["--memory-source", "kd"]`. Add `--connect` only to change the default `0.0.0.0:50000` listener.

The `open` tool accepts the same backend, connect, and key values. If the server starts without a target, it tells the agent to ask the user how the VM is exposed, and not to guess.

If `ntoseye` is not in `PATH`, use an absolute path for `command` (for example, `../target/release/ntoseye`).

These events detach the target in the same way as `close`:

- The stdin of the server closes.
- The server gets `SIGINT`, `SIGTERM`, or `SIGHUP`.

ntoseye then removes the installed breakpoints and resumes the guest before the server exits. `SIGKILL` stops this cleanup, and the breakpoint entries stay installed. For more information, refer to [breakpoint recovery](../using/breakpoints.md).

## Streamable HTTP

Some web MCP clients connect over the network and do not start a subprocess. For these clients, use `--http`:

```bash
ntoseye mcp --http 127.0.0.1:8080
```

The service is at `http://127.0.0.1:8080/mcp`. By default, HTTP binds only to loopback addresses.

:::{warning}
The `command` tool gives access to the full REPL. This includes:

- execution control
- guest memory writes ({command}`eb`, {command}`!eb`)
- host filesystem writes ({command}`.dump`, {command}`.logopen`)
- host files that the guest can get ({command}`.kdfiles`)

So use `--unsafe-http` to bind to a non-loopback address only on trusted networks.
:::
