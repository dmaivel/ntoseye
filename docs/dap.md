# Editor integration (DAP)

`ntoseye dap` exposes a debugger session over the [Debug Adapter Protocol](https://microsoft.github.io/debug-adapter-protocol/). Editors provide source and disassembly views, breakpoints, stacks, registers, and watches. The Debug Console accepts inspection commands; use the editor’s controls to step and continue.

## Quickstart

Configure the VM as described in [Choosing a backend](backends.md). Use one client per target.

The target can be named on the command line, or in the client's own launch configuration.

```bash
ntoseye dap # stdio, spawned by the client
ntoseye dap --port 4711
```

### VS Code

VS Code requires an extension to register the debug type. Create `~/.vscode/extensions/ntoseye-dap/package.json` and set `program` to your ntoseye binary:

```json
{
  "name": "ntoseye-dap",
  "publisher": "local",
  "version": "0.0.1",
  "engines": { "vscode": "^1.75.0" },
  "categories": ["Debuggers"],
  "contributes": {
    "breakpoints": [{ "language": "c" }, { "language": "cpp" }, { "language": "rust" }],
    "debuggers": [
      {
        "type": "ntoseye",
        "label": "ntoseye (Windows kernel)",
        "program": "/usr/local/bin/ntoseye",
        "args": ["dap"]
      }
    ]
  }
}
```

Reload VS Code, then add a configuration to `launch.json`.

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Windows kernel (ntoseye)",
      "type": "ntoseye",
      "request": "attach",
      "backend": "kd",
      "connect": "/tmp/ntoseye-kd.sock",
      "symbolPath": "/path/to/your/driver/symbols",
      "sourcePath": "C:\\Users\\you\\source\\repos\\MyDriver\\MyDriver=/home/you/src/MyDriver"
    }
  ]
}
```

To debug the adapter itself, run `ntoseye dap --port 4711` in a terminal and add `"debugServer": 4711` to the configuration. VS Code then connects to that process instead of spawning one, and the adapter's stderr stays visible.

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Windows kernel (ntoseye)",
      "type": "ntoseye",
      "request": "attach",
      "debugServer": 4711,
      "backend": "kd",
      "connect": "/tmp/ntoseye-kd.sock"
    }
  ]
}
```

### Emacs ([dape](https://github.com/svaante/dape))

Install `dape` with `M-x package-install`, then add this to your Emacs configuration:

```emacs-lisp
(with-eval-after-load 'dape
  (add-to-list 'dape-configs
               '(ntoseye
                 modes (c-mode c-ts-mode c++-mode c++-ts-mode rust-mode rust-ts-mode)
                 ensure dape-ensure-command
                 command "ntoseye"
                 command-args ("dap")
                 :type "ntoseye"
                 :request "attach"
                 :backend "kd"
                 :connect "/tmp/ntoseye-kd.sock")))
```

Ensure `ntoseye` is on Emacs's `exec-path`, or set `command` to its absolute path. Run `M-x dape` and select `ntoseye`; dape launches the adapter over stdio.

Add `:symbolPath` and `:sourcePath` entries as needed, using the formats in [Attach arguments](#attach-arguments).

### [nvim-dap](https://github.com/mfussenegger/nvim-dap)

```lua
local dap = require("dap")
dap.adapters.ntoseye = {
  type = "executable",
  command = "ntoseye",
  args = { "dap" },
}
dap.configurations.c = {
  {
    name = "Windows kernel (ntoseye)",
    type = "ntoseye",
    request = "attach",
    backend = "kd",
    connect = "/tmp/ntoseye-kd.sock",
    symbolPath = "/path/to/your/driver/symbols",
    sourcePath = [[C:\Users\you\source\repos\MyDriver\MyDriver=/home/you/src/MyDriver]],
  },
}
```

## Attach arguments

Kernel debugging has no process to start, so `launch` and `attach` behave identically. Both accept the same target choices as the command line.

| Argument | Meaning |
| --- | --- |
| `backend` | `kd` (default), `kdnet`, `gdb`, or `memory`. |
| `connect` | KD socket path, KDNET listen address, or GDB address. |
| `kdnetKey` | KDNET encryption key (four base-36 components). |
| `memorySource` | `auto` (default), `host`, or `kd`; KD and KDNET only. |
| `dump` | Open a crash dump instead of attaching to a live VM. Takes precedence over the live options. |
| `symbolPath` | Directories or symbol servers appended to the symbol path, in `.sympath` syntax. |
| `sourcePath` | Source-path mappings appended to the source path, in `.srcpath` syntax. |

`symbolPath` accepts a local directory, a symbol server (`https://...`, `srv*a*b`), a `;`-separated list, or a JSON array. Entries are appended to the managed cache and Microsoft server. Symbols are reloaded at attach.

`sourcePath` takes `<prefix-recorded-in-the-pdb>=<local-root>` or a bare local root, in the same `;`-separated or JSON array forms. A source view needs it whenever the driver was not built on this host.

When the top-level flags already pinned a target (`ntoseye --dump crash.dmp dap`), the attach request adopts that session and ignores its own target arguments. `symbolPath` and `sourcePath` still apply.

## Feature mapping

| DAP surface | ntoseye |
| --- | --- |
| Threads | backend execution contexts, as listed by `~` |
| Call stack | `k` |
| Locals scope | `dv` |
| Variable expansion | `dt` |
| Registers scope | `r` |
| Watch and hover | the shared core expression grammar |
| Debug Console | any command that inspects state |
| Breakpoints | `bu file:line` |
| Function breakpoints | `bu <symbol>` |
| Instruction breakpoints | `bp <address>` |
| Data breakpoints | `ba` hardware watchpoints |
| Exception breakpoints | none, use the console's `sx` |
| Condition and hit count | breakpoint condition and WinDbg pass count |
| Log points | a `.printf "..."; gc` breakpoint action |
| Step over and into | one source line, or one instruction |
| Step out | `gu` |
| Disassembly view | `u` and `ub` |
| Variable writes | in-place scalar writes |
| Memory view | virtual reads and writes |
| Modules view | `lm` |
| Exception info | the stop's NTSTATUS, or the bugcheck code and its four parameters |
| Output console | guest `DbgPrint` output over KD and KDNET, streamed as it arrives |

### Threads and stacks

DAP threads are backend execution contexts (vCPUs), as listed by `~`. Stops halt the whole target and set `allThreadsStopped`. Inspect Windows threads with `!process`, `!stacks`, and `!thread`; parked `_ETHREAD`s cannot be stepped or resumed.

The call stack uses `k`, with source lines from private PDBs. `.thread <ethread>` selects a parked Windows thread’s saved context. Clients supporting `supportsInvalidatedEvent` refresh their panes automatically; others need a manual refresh.

### Locals, registers, and watches

Locals and parameters use PDB locations, as in `dv`. Caller frames contain only registers recovered by unwinding; other values are unavailable.

Structs, unions, arrays, and pointers expand through `dt` decoding. Null pointers and unresolved or zero-sized types cannot expand. Use console `dt` to inspect the raw layout.

The Registers scope is `r`. Frame 0 is the live register file and is writable, while caller frames show the sparse recovered context. Under a parked Windows thread every frame is recovered, so none is writable.

Watch and hover use [core expressions](usage.md#expressions), including locals (`index`, `Irp->IoStatus.Status`), addresses (`poi(nt!PsInitialSystemProcess)`), registers (`@rip`), and casts (`(_IRP*)@rcx`). The console radix (`n 10`) applies. Locals require private PDBs and a recoverable location in the selected frame. Use `$!name` to require a local and `&` for its storage address. Typed structs, arrays, and pointers expand into children.

Scalar registers, locals, struct fields, and array elements can be written in place. Bitfields and values wider than 8 bytes require console commands such as `eb` or `ed`.

### Breakpoints

Source breakpoints use `bu file:line`. Unresolved lines remain unverified until their module loads, when a `breakpoint` event updates the client. Breakpoints can be edited while running; the adapter pauses and resumes the target.

Function breakpoints use `bu <symbol>` but skip the prologue so parameters are available. Console `bu` stops at the symbol itself.

Instruction breakpoints, set from the disassembly view, are `bp <address>`.

Data breakpoints use `ba` on variable storage, including fields and array elements. Register-held locals and bitfields have no separately watchable address. Only KD and KDNET support them.

Exception breakpoints are unsupported. Configure exception policy with console `sx` commands.

All breakpoint kinds accept conditions and hit counts. `hitCondition` must be a decimal pass count, not `>5` or `0x10`. Editor breakpoint conditions also use decimal literals; console conditions use the session radix.

### Log points

A log point is a breakpoint whose action prints and continues, `.printf "..."; gc`. `{...}` placeholders hold core expressions, including locals such as `{index}`, and render their values in hexadecimal. The surrounding text is literal.

Log placeholders cannot contain quotes or semicolons. Whitespace is removed because `.printf` separates arguments on whitespace. Successful log actions continue without stopping the client; conditions and hit counts still apply.

### Stepping

Step over and step into advance one source line when line records exist, or one instruction otherwise. `instruction` granularity always steps one instruction. Straight-line instruction ranges are covered in one run.

Step out uses `gu` and stops at the return address for every granularity.

The disassembly view uses `u` and `ub` to scroll forward and backward.

### Memory

The memory view reads and writes virtual memory in the current process context. Reads mask this debugger's own breakpoint bytes back to the original opcodes, so the view never shows an injected `int3`. A write that crosses into an untranslatable page commits the bytes before it; with `allowPartial` the response reports that count, otherwise the write fails with it.

### Paging

Stack and variable requests support paging (`startFrame`/`levels`, `start`/`count`). Arrays are decoded per window, up to 1024 elements per request. Stack pages slice a single bounded walk per stop. Console `dt` displays 16 elements by default; use `dt -a` or `dq` for more.

## Run control belongs to the client

The Debug Console uses the same remote dispatch context as MCP. Commands that resume the target (`g`, `p`, `gu`, `wt`, `.reboot`, ...) are refused. Use the editor’s step and continue controls.

Breakpoint actions still run. A breakpoint created with `bp nt!NtCreateFile do "k; gc"` executes its action on each hit, prints into the console, and continues if the action ends in `gc`.

Pause also interrupts a step over a long-running call.

Disconnect, terminate, `SIGTERM`, `SIGHUP`, and `SIGINT` detach like `qd`: remove installed breakpoints and resume the guest. Cleanup precedes the disconnect response because clients may immediately kill the adapter. If the target cannot halt for cleanup, the adapter reports the failure and does not issue a resume.

`SIGKILL` prevents cleanup and leaves breakpoint entries installed. See [breakpoint recovery](usage.md#breakpoints-and-watchpoints).
