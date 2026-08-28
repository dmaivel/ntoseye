# MCP integration

`ntoseye` can run as an [MCP](https://modelcontextprotocol.io) server, exposing the debugger as tools to MCP clients. It reads the top-level `--backend`/`--connect`/`--kdnet-key` flags to choose how to attach, so the VM and its debug transport must be set up exactly as for the REPL (see [Choosing a backend](backends.md)). Only one consumer of the VM can run at a time.

The structured tool surface includes `inspect_trap_frame` and `set_watchpoint`; watchpoints report `stop: "watchpoint"` with access/length metadata and use the existing breakpoint lifecycle tools for list, disable, enable, and clear operations.

> [!IMPORTANT]
> The server attaches on launch, so bring up the guest and its debug transport before starting the client.

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

For KDNET, use `["--backend", "kdnet", "--kdnet-key", "1.2.3.4", "mcp"]`; add `["--memory-source", "kd"]` to force target-mediated memory and add `--connect` before `mcp` only when changing the default `0.0.0.0:50000` listener. The dynamic `open` tool exposes the same choice as `memory_source`.

Use an absolute path for `command` (e.g. `../target/release/ntoseye`) if `ntoseye` isn't within `PATH`.

## Streamable HTTP

For web MCP clients that connect over the network instead of spawning a subprocess, use `--http`:

```bash
ntoseye mcp --http 127.0.0.1:8080
```

The service is mounted at `http://127.0.0.1:8080/mcp`. HTTP binds are loopback-only by default, since the tool surface includes execution control and guest writes; pass `--unsafe-http` to bind a non-loopback address and expose those tools to the network (only on trusted hosts).
