# Editor integration (DAP)

`ntoseye dap` makes a debugger session available over the [Debug Adapter Protocol](https://github.com/microsoft/debug-adapter-protocol). The editor gives source and disassembly views, breakpoints, stacks, registers, and watches. The Debug Console accepts inspection commands. To step and continue, use the controls of the editor.

## Quickstart

Configure the VM as [Choosing a backend](../setup/backends.md) describes. Use one client for each target.

You can name the target on the command line or in the launch configuration of the client.

```bash
ntoseye dap # stdio, spawned by the client
ntoseye dap --port 4711
```

### VS Code

VS Code needs an extension to register the debug type. To set up VS Code:

1. Create `~/.vscode/extensions/ntoseye-dap/package.json`. Set `program` to the path of your ntoseye binary:

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

2. Reload VS Code.
3. Add a configuration to `launch.json`:

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
         "sourcePath": "/home/you/src/MyDriver"
       }
     ]
   }
   ```

To debug the adapter:

1. In a terminal, run `ntoseye dap --port 4711`.
2. Add `"debugServer": 4711` to the configuration:

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

VS Code then connects to that adapter process and does not start a new one. The stderr output of the adapter stays visible.

### Emacs ([dape](https://github.com/svaante/dape))

1. Install `dape` with `M-x package-install`.
2. Add this to your Emacs configuration:

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

   If necessary, add `:symbolPath` and `:sourcePath` entries. Use the formats in [Attach arguments](#attach-arguments).

3. If `ntoseye` is not on the `exec-path` of Emacs, set `command` to the absolute path of `ntoseye`.
4. Run `M-x dape`.
5. Select `ntoseye`. dape starts the adapter over stdio.

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
    sourcePath = "/home/you/src/MyDriver",
  },
}
```

## Attach arguments

Kernel debugging does not start a process. So `launch` and `attach` do the same thing. Both requests accept the same target options as the command line.

| Argument | Meaning |
| --- | --- |
| `backend` | `kd` (default), `kdnet`, `gdb`, or `memory`. |
| `connect` | KD socket path, KDNET listen address, or GDB address. |
| `kdnetKey` | KDNET encryption key (four base-36 components). |
| `memorySource` | `auto` (default), `host`, or `kd`. Only for KD and KDNET. |
| `dump` | Opens a crash dump and does not attach to a live VM. This argument has priority over the live options. |
| `symbolPath` | Directories or symbol servers that ntoseye adds to the end of the symbol path, in {command}`.sympath` syntax. |
| `sourcePath` | Source-path mappings that ntoseye adds to the end of the source path, in {command}`.srcpath` syntax. |

`symbolPath` accepts these values:

- a local directory
- a symbol server (`https://...`, `srv*a*b`)
- a `;`-separated list
- a JSON array

ntoseye adds the entries after the managed cache and the Microsoft server. ntoseye loads the symbols again when it attaches.

`sourcePath` accepts these values:

- The local directory that contains the source tree. ntoseye matches it as {command}`.srcpath` describes.
- A mapping `<prefix-recorded-in-the-pdb>=<local-root>`.

`sourcePath` also accepts the same `;`-separated list and JSON array forms as `symbolPath`. If the driver was not built on this host, a source view needs `sourcePath`.

If the command line already sets a target (`ntoseye dap --dump crash.dmp`), the attach request uses that session. The attach request then ignores its own target arguments. `symbolPath` and `sourcePath` still apply.

## Feature mapping

| DAP surface | ntoseye |
| --- | --- |
| Threads | backend execution contexts, as listed by {command}`~` |
| Call stack | {command}`k` |
| Locals scope | {command}`dv` |
| Variable expansion | {command}`dt` |
| Registers scope | {command}`r` |
| Watch and hover | the shared core expression grammar |
| Debug Console | any command that inspects state |
| Breakpoints | `bu file:line` |
| Function breakpoints | `bu <symbol>` |
| Instruction breakpoints | `bp <address>` |
| Data breakpoints | {command}`ba` hardware watchpoints |
| Exception breakpoints | none. Use {command}`sx` in the console. |
| Condition and hit count | breakpoint condition and WinDbg pass count |
| Log points | a `.printf "..."; gc` breakpoint action |
| Step over and into | one source line, or one instruction |
| Step out | {command}`gu` |
| Disassembly view | {command}`u` and {command}`ub` |
| Variable writes | in-place scalar writes |
| Memory view | virtual reads and writes |
| Modules view | {command}`lm` |
| Exception info | the NTSTATUS of the stop, or the bugcheck code and its four parameters |
| Output console | guest `DbgPrint` output over KD and KDNET, shown when it arrives |

### Threads and stacks

DAP threads are backend execution contexts (vCPUs), as {command}`~` lists them. A stop halts the whole target and sets `allThreadsStopped`. To examine Windows threads, use {command}`!process`, {command}`!stacks`, and {command}`!thread`. You cannot step or resume a parked `_ETHREAD`.

The call stack uses {command}`k`, with source lines from private PDBs. For each frame, the frame name and the source lines use the address space that ntoseye used to recover that frame. This includes the process address space of a parked thread.

The stack of the current vCPU starts from the console context. These commands select the console context:

- `.thread <ethread>` selects the saved context of a parked Windows thread. If the vCPU of the thread is halted in the Windows hypervisor, `.thread` selects the VTL0 state that the hypervisor saved.
- {command}`.cxr` selects a context record.
- {command}`.trap` selects a trap frame.

The stacks of other vCPUs start from the registers of those vCPUs. When the editor shows these stacks, the console context does not change. If you select a frame from one of these stacks, the console switches to that vCPU.

Clients that support `supportsInvalidatedEvent` refresh their panes automatically. With other clients, refresh the panes manually.

### Locals, registers, and watches

The compiler can inline a call. ntoseye shows an inlined call as a frame named `[Inline Frame] module!function`, as Visual Studio does. This frame is at the source line of the inlined function. The frame that contains the inlined call is at the line of the call.

Locals and parameters use PDB locations, as in {command}`dv`. An inline frame shows the locals and parameters of the inlined function. The frame that contains the inlined call shows the locals and parameters of its own procedure.

Caller frames contain only the registers that ntoseye recovers when it unwinds the stack. Other values are not available.

ntoseye gets the locals of a frame, their values, and their children from the address space in which it recovered the stack. So the frames of a parked thread show the locals of the process of that thread. The {command}`.process` selection does not change this.

ntoseye uses {command}`dt` decoding to expand structs, unions, arrays, and pointers. Null pointers, unresolved types, and zero-sized types do not expand. To see the raw layout, use {command}`dt` in the console.

The Registers scope uses {command}`r`. Frame 0 shows the live register file, and you can write to it. The inline frames at the address of frame 0 share its registers, so you can also write to them. Caller frames show the sparse recovered context.

In a stack that ntoseye walks from a saved context, every frame is recovered. So you cannot write to the registers of any frame in that stack. These are saved contexts:

- a parked thread
- a {command}`.cxr` context record
- the VTL0 state that the hypervisor saved

Watch and hover use [core expressions](../reference/expressions.md). These expressions can contain:

- locals (`index`, `Irp->IoStatus.Status`)
- addresses (`poi(nt!PsInitialSystemProcess)`)
- registers (`@rip`)
- casts (`(_IRP*)@rcx`)

The console radix (`n 10`) applies to these expressions. An expression uses the registers of the selected frame. Like the locals, it reads the address space in which ntoseye recovered the stack of that frame. The Debug Console uses the inspection context of the console. So a {command}`.process` scope applies in the Debug Console.

Locals need private PDBs and a location that ntoseye can recover in the selected frame. To make sure that a name resolves to a local, use `$!name`. To get the storage address of a local, use `&`. Typed structs, arrays, and pointers expand into children.

You can write in place to scalar registers, locals, struct fields, and array elements. For bitfields and for values wider than 8 bytes, use console commands such as {command}`eb` or {command}`ed`.

### Breakpoints

Source breakpoints use `bu file:line`. A breakpoint on an unresolved line stays unverified until its module loads. When the module loads, a `breakpoint` event updates the client. You can edit breakpoints while the target runs. The adapter then pauses and resumes the target.

Function breakpoints use `bu <symbol>`, but they skip the prologue. So the parameters are available when the breakpoint stops. {command}`bu` in the console stops at the symbol.

You set instruction breakpoints from the disassembly view. They use `bp <address>`.

Data breakpoints use {command}`ba` on variable storage, which includes fields and array elements. Locals in registers and bitfields do not have a separate address that ntoseye can watch. Only KD and KDNET support data breakpoints.

ntoseye does not support exception breakpoints. To configure the exception policy, use {command}`sx` commands in the console. If `sxe ld` causes a stop at a module load, the adapter reports the stop with the reason `module load`. The console shows the `ModLoad:` line of that stop.

All breakpoint types accept conditions and hit counts. `hitCondition` must be a decimal pass count. Values such as `>5` or `0x10` are not valid. Breakpoint conditions in the editor also use decimal literals. Breakpoint conditions in the console use the session radix.

### Log points

A log point is a breakpoint with the action `.printf "..."; gc`. This action prints a message and continues. A `{...}` placeholder contains a core expression, for example a local such as `{index}`. The placeholder shows the value of the expression in hexadecimal. The text around the placeholders is literal.

Log placeholders cannot contain quotes or semicolons. ntoseye removes whitespace from the placeholders, because {command}`.printf` uses whitespace to separate arguments. If a log action succeeds, the target continues and the client does not stop. Conditions and hit counts still apply.

### Stepping

If line records exist, step over and step into go forward one source line. If no line records exist, they go forward one instruction. With `instruction` granularity, a step is always one instruction. A step covers a range of straight-line instructions in one run.

Step out uses {command}`gu`. It stops at the return address for all granularities.

The disassembly view uses {command}`u` to scroll forward and {command}`ub` to scroll backward.

### Memory

The memory view reads and writes virtual memory in the current process context. When ntoseye reads memory, it replaces the bytes of its own breakpoints with the original opcodes. So the view does not show an `int3` that ntoseye put in memory.

A write can cross into a page that ntoseye cannot translate. In this case, ntoseye writes the bytes before that page. If the request sets `allowPartial`, the response gives the number of bytes written. If not, the write fails and gives that number.

### Paging

Stack and variable requests support paging:

- Stack requests use `startFrame` and `levels`.
- Variable requests use `start` and `count`.

ntoseye decodes arrays one window at a time, with a maximum of 1024 elements for each request. For each stop, ntoseye does one stack walk with a limit, and each stack page is a part of this walk. By default, {command}`dt` in the console shows 16 elements. To see more elements, use `dt -a` or {command}`dq`.

## Resume and step from the editor

The Debug Console uses the same remote dispatch context as MCP. The Debug Console does not accept commands that resume the target, for example {command}`g`, {command}`p`, {command}`gu`, {command}`wt`, and {command}`.reboot`. To step and continue, use the controls of the editor.

Breakpoint actions still run. For example, you can create a breakpoint with `bp nt!NtCreateFile do "k; gc"`. At each hit, this breakpoint runs its action and prints the output in the console. If the action ends in `gc`, the target continues.

Pause also interrupts a step over a call that runs for a long time.

These events detach the adapter as `qd` does:

- disconnect
- terminate
- `SIGTERM`, `SIGHUP`, and `SIGINT`

When the adapter detaches, it removes the installed breakpoints and resumes the guest. The adapter does this cleanup before it sends the disconnect response, because a client can kill the adapter immediately. If the target cannot halt for the cleanup, the adapter reports the failure and does not resume the target.

:::{warning}
`SIGKILL` stops the adapter before it can do the cleanup. The breakpoint entries then stay installed. For more information, see [breakpoint recovery](../using/breakpoints.md).
:::
