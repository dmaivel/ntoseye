# MCP integration

`ntoseye` can run as an [MCP](https://modelcontextprotocol.io) server. Agents may use either this, for WinDbg syntax with bounded run-control, or the [Python SDK](sdk.md), for structured values and scripted loops (conditional stops, bulk enumeration); both drive the same debugger.

| Tool | Purpose |
| --- | --- |
| `command` | Run one REPL line in ntoseye's WinDbg-style syntax (`!process 0 0`, `dt nt!_EPROCESS <addr>`, `k`, `bp nt!NtCreateFile`, `dq rsp l8`, `u rip`, `lm`, `g`, `p`, `break`, ...) with REPL semantics (`;` separates commands on one line) and return its text, styling stripped, followed by a one-line `[target ...]` trailer. `help` lists every command. Arguments: `line`, `timeout_ms` (default 10 s, max 5 min), `format` (`text` or `json`). |
| `open` / `close` | Attach to a target (`backend: kd \| kdnet \| gdb \| memory \| dump`, plus `connect` and, for kdnet, `key`) or release it. One session at a time. The KD memory source is an operator setting (`--memory-source` on the command line), not a tool argument. |

## Run control

The `command` tool behaves like a WinDbg prompt, with one difference: it never blocks longer than `timeout_ms`.

- A resuming command (`g`, `gh`, `gn`, `p`, `t`, `gu`, `pa`, `wt`, `.reboot`, ...) resumes and waits up to `timeout_ms` for the next stop. A stop is rendered the way the REPL renders it (breakpoint banner, registers, stack). If nothing stops in time the result ends with `[target running]`; the target keeps running and nothing is lost.
- A command that needs a halted target (`k`, `r`, `bp`, `t`, ...) sent while the target runs waits up to `timeout_ms` for the stop, renders it, then runs, the way WinDbg queues input typed at a running debuggee. If the target is still running when the budget ends, the result says so and the command was not run; re-issue it to keep waiting. Memory, process, module, and struct commands do not wait: they work live when memory comes from the host (the default `--memory-source auto` with a local VM, and the memory/gdb backends), and fail with a message saying why on a session that reads memory over KD.
- A resuming command sent while the target runs also waits, but is then refused once so the stop is seen before it is continued past.
- Each command on a `;` line is admitted against the target's state at that point, not the state when the line arrived. `break; bp nt!NtCreateFile; g` therefore works as one call: `break` halts the guest, `bp` runs on the halted target, `g` resumes. A bare `bp` on a guest that nothing will stop only waits out `timeout_ms` and reports that it was not run.
- `break` interrupts a running target.
- A stop that arrived between calls (the guest hit a breakpoint while the agent was thinking) is rendered at the top of the next result. If that next call was itself a resuming command it is refused once, so the agent sees the stop before continuing past it.
- A multi-step command (`pa`, `pt`, `gu`, `wt`) that overruns the budget leaves the target running toward its next stop; the next halted-only command collects it. An empty `line` runs nothing and only waits.

The trailer reads `[target running]` or `[target halted @ <vcpu> <rip> <symbol> | process <name> (<pid>) | scope <name> (<pid>)]`, where `process` is the process whose page tables the stopped vCPU has loaded and `scope` is the `.process` inspection scope memory commands read through (it survives resumes, so the two can differ). After a reboot it adds `rediscovery pending` until the kernel is rediscovered; wait rather than enumerating stale state.

Guest debug output (`DbgPrint`) captured since the previous call is appended as `[dbgprint] ...` lines.

A typical breakpoint flow: `break; bp nt!NtCreateFile; g`, then `k` (which waits for the breakpoint if `g` returned with the target still running). For a user-mode breakpoint name the process and the symbol resolves in it: `break; bu /p <pid> user32!PeekMessageW; g`. No prior `.process /p` is needed, because the debugger loads that module's symbols itself (see [symbols](symbols.md)).

A backtrace through a module whose PDB is not cached yet renders those frames as `module+offset` and fetches the PDB in the background rather than holding the call open; a later `k` shows the names.

## Structured results

`format: "json"` returns `{ok, output, result, target, debug_output}` as structured content: `output` is the text the command printed, `target` is the run-state snapshot (`{running, current_thread, rip, symbol, attached_process, stopped_process, stopped_thread, coherent, kernel_base}`), `debug_output` the captured `DbgPrint` lines, and `result` the typed decoding for commands that have one, else `null`. The decodings are the same ones the [Python SDK](sdk.md) exposes as methods (the `!` inspectors, `lm`, `!process`, `k`, `bl`, `dt`, `?`, `r`, `!analyze`, ...); see the SDK surface table for the set.

The server reads the top-level `--backend`/`--connect`/`--kdnet-key`/`--dump` flags to attach at launch, so the VM and its debug transport must be set up exactly as for the REPL (see [Choosing a backend](backends.md)). Without those flags it starts empty and the client attaches with `open`. The guest runs freely between calls; wrong-process hits on shared-page breakpoints are absorbed in the background so it is never left frozen.

## stdio (default)

The MCP client launches `ntoseye mcp` as a subprocess and talks to it over stdin/stdout. Most desktop MCP clients are configured with a JSON file listing the command to spawn:

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

Top-level flags go before the `mcp` subcommand, e.g. to pin the backend and socket:

```json
{
  "mcpServers": {
    "ntoseye": {
      "command": "ntoseye",
      "args": ["--backend", "kd", "--connect", "/tmp/ntoseye-kd.sock", "mcp"]
    }
  }
}
```

For KDNET, use `["--backend", "kdnet", "--kdnet-key", "1.2.3.4", "mcp"]`; add `["--memory-source", "kd"]` to force target-mediated memory and add `--connect` before `mcp` only when changing the default `0.0.0.0:50000` listener. The `open` tool takes the same backend/connect/key choices; when the server starts without a target the agent is instructed to ask the user how the VM is exposed rather than guess.

Use an absolute path for `command` (e.g. `../target/release/ntoseye`) if `ntoseye` isn't within `PATH`.

## Streamable HTTP

For web MCP clients that connect over the network instead of spawning a subprocess, use `--http`:

```bash
ntoseye mcp --http 127.0.0.1:8080
```

The service is mounted at `http://127.0.0.1:8080/mcp`. HTTP binds are loopback-only by default. The `command` tool exposes the full REPL, including execution control, guest memory writes (`eb`, `!eb`), host filesystem writes (`.dump`, `.logopen`), and host files served to the guest (`.kdfiles`). Use `--unsafe-http` to bind a non-loopback address only on trusted networks.
