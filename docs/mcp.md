# MCP integration

`ntoseye` can run as an [MCP](https://modelcontextprotocol.io) server. Agents may use either this, for WinDbg syntax with bounded run-control, or the [Python SDK](sdk.md), for structured values and scripted loops (conditional stops, bulk enumeration); both drive the same debugger.

The surface is deliberately thin: the debugger's REPL command language is the API.

| Tool | Purpose |
| --- | --- |
| `command` | Run one REPL line in ntoseye's WinDbg-style syntax (`!process 0 0`, `dt nt!_EPROCESS <addr>`, `k`, `bp nt!NtCreateFile`, `dq rsp l8`, `u rip`, `lm`, ...) and return its text, styling stripped. `help` lists every command. Commands that resume until the next stop (`g`, `gh`, `gn`, `p`, `pa`, `ta`, `pc`, `tc`, `pt`, `tt`, `ph`, `th`, `gu`, `wt`, `.reboot`, `.crash`) are refused because they would block the session; use the run-control tools below. `t`/`si` (one instruction) is allowed. |
| `status` | Where the target is now: `{running, current_thread, rip, symbol, process, coherent, kernel_base}`. |
| `interrupt` | Pause a running VM (needed before `k`, `r`, `bp`, `t`, ...). |
| `resume` | Resume, non-blocking; optional `disposition: handled \| not_handled` (KD only). |
| `wait_for_stop` | Wait up to `timeout_ms` (default 10 s, max 20 s) for the next stop without resuming; returns `{stop: "breakpoint" \| "watchpoint" \| "exception" \| "bugcheck" \| "step" \| "target_reloaded" \| "running" \| "halted", ...}`. Poll by calling again while it returns `running`. |
| `open` / `close` | Attach to a target (`backend: kd \| kdnet \| gdb \| memory \| dump`, plus `connect` and, for kdnet, `key`) or release it. One session at a time. The KD memory source is an operator setting (`--memory-source` on the command line), not a tool argument. |

Run-control is split so no request blocks: a typical breakpoint flow is `interrupt`, `command("bp nt!NtCreateFile")`, `resume`, `wait_for_stop` (until `stop:"breakpoint"`), then `command("k")`.

The server reads the top-level `--backend`/`--connect`/`--kdnet-key`/`--dump` flags to attach at launch, so the VM and its debug transport must be set up exactly as for the REPL (see [Choosing a backend](backends.md)). Without those flags it starts empty and the client attaches with `open`.

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

The service is mounted at `http://127.0.0.1:8080/mcp`. HTTP binds are loopback-only by default, since `command` grants execution control and guest writes; pass `--unsafe-http` to bind a non-loopback address and expose those tools to the network (only on trusted hosts).
