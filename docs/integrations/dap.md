# Editor integration (DAP)

`ntoseye dap` makes a debugger session available over the [Debug Adapter Protocol](https://github.com/microsoft/debug-adapter-protocol). The editor gives source and disassembly views, breakpoints, stacks, registers, and watches, and its Debug Console accepts inspection commands. To step and continue, use the editor's controls.

## Quickstart

Configure the VM as [Choosing a backend](../setup/backends.md) describes, and use one client for each target.

You can name the target on the command line or in the client's launch configuration.

```bash
ntoseye dap # stdio, spawned by the client
ntoseye dap --port 4711
```

### VS Code

VS Code needs an extension to register the debug type. To set it up:

1. Create `~/.vscode/extensions/ntoseye-dap/package.json` and set `program` to the path of your ntoseye binary:

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

2. Reload VS Code, then add a configuration to `launch.json`:

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
         "symbolPath": ["${workspaceFolder}/x64/Debug", "${workspaceFolder}/x64/Release"],
         "sourcePath": "${workspaceFolder}"
       }
     ]
   }
   ```

   This configuration assumes the driver's source tree is the workspace; [Paths from the workspace](#paths-from-the-workspace) explains the two paths.

To debug the adapter itself, run `ntoseye dap --port 4711` in a terminal and add `"debugServer": 4711` to the configuration:

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

VS Code then connects to that adapter process instead of starting a new one, and the adapter's stderr output stays visible.

### Emacs ([dape](https://github.com/svaante/dape))

1. Install `dape` with `M-x package-install`, then add this to your Emacs configuration:

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

   Add `:symbolPath` and `:sourcePath` entries as needed, using the formats in [Attach arguments](#attach-arguments).

2. If `ntoseye` is not on Emacs's `exec-path`, set `command` to its absolute path.
3. Run `M-x dape` and select `ntoseye`. dape starts the adapter over stdio.

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

Kernel debugging does not start a process, so `launch` and `attach` do the same thing, and both accept the same target options as the command line.

| Argument | Meaning |
| --- | --- |
| `backend` | `kd` (default), `kdnet`, `gdb`, or `memory`. |
| `connect` | KD socket path, KDNET listen address, or GDB address. |
| `kdnetKey` | KDNET encryption key (four base-36 components). |
| `memorySource` | `auto` (default), `host`, or `kd`, for KD and KDNET only. |
| `dump` | Opens a crash dump instead of attaching to a live VM, and has priority over the live options. |
| `symbolPath` | Directories or symbol servers to add to the end of the symbol path, in {command}`.sympath` syntax. |
| `sourcePath` | Source-path mappings to add to the end of the source path, in {command}`.srcpath` syntax. |

`symbolPath` accepts a local directory, a symbol server (`https://...`, `srv*a*b`), a `;`-separated list, or a JSON array. ntoseye adds the entries after the managed cache and the Microsoft server, and loads the symbols again when it attaches.

`sourcePath` accepts the local directory that contains the source tree, which ntoseye matches as {command}`.srcpath` describes, or a mapping `<prefix-recorded-in-the-pdb>=<local-root>`. It also accepts the same `;`-separated list and JSON array forms as `symbolPath`. If the driver was not built on this host, a source view needs `sourcePath`.

If the command line already sets a target (`ntoseye dap --dump crash.dmp`), the attach request uses that session and ignores its own target arguments, but `symbolPath` and `sourcePath` still apply.

### Paths from the workspace

VS Code and nvim-dap replace `${workspaceFolder}` with the workspace directory before they send the configuration, so one configuration serves every checkout of a driver.

- `sourcePath` can be the workspace itself. ntoseye matches the end of each recorded source path under it, so sources compiled as `C:\Users\you\src\MyDriver\queue.c` inside the guest are found at `${workspaceFolder}/queue.c`.
- `symbolPath` must name the folders that contain the PDB. ntoseye looks for `<folder>/<name>.pdb` and for the symbol-store layout under each folder, and does not search subfolders.
- You can list every output folder of the project, for example Debug and Release, or x64 and ARM64. ntoseye loads a PDB only when its GUID and age match the loaded driver, so a PDB from another build in a listed folder is passed over, and a stale PDB is never loaded.

If the PDB exists only inside the guest, ntoseye can read it from guest memory instead, shortly after the build; see [Symbols](../using/drivers.md#symbols) in the driver guide.

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
| Exception breakpoints | none (use {command}`sx` in the console) |
| Condition and hit count | breakpoint condition and WinDbg pass count |
| Log points | a `.printf "..."; gc` breakpoint action |
| Step over and into | one source line, or one instruction |
| Step out | {command}`gu` |
| Disassembly view | {command}`u` and {command}`ub` |
| Variable writes | in-place scalar writes |
| Memory view | virtual reads and writes |
| Modules view | {command}`lm` |
| Exception info | the stop's NTSTATUS, or the bugcheck code and its four parameters |
| Output console | guest `DbgPrint` output over KD and KDNET, shown when it arrives |

### Threads and stacks

DAP threads are backend execution contexts (vCPUs), as {command}`~` lists them. A stop halts the whole target and sets `allThreadsStopped`. To examine Windows threads, use {command}`!process`, {command}`!stacks`, and {command}`!thread`. You cannot step or resume a parked `_ETHREAD`.

A thread's name is the vCPU, what it runs, and its symbol (`p01.01 [kernel] nt!KiIdleLoop+0x2d`). For a vCPU halted in the Windows hypervisor, the name adds where each VTL left off, with the hypercall of a `VMCALL` exit, and the guest partition's VP that the processor serves: `p01.02 [hypervisor] hv!HvCallSendSyntheticClusterIpi (VTL0 hvcall!Hypercall) (serving partition 0x3 VP 2 VTL0 ffffffffc0000000, last exit VMCALL (hypercall 0x000b HvCallSendSyntheticClusterIpi fast))`. {command}`!hvcall` in the Debug Console decodes that call's input ([VBS](../platforms/vbs.md#hypercalls)). `ntoseye gdbserver` names its threads the same way.

The call stack uses {command}`k`, with source lines from private PDBs. Each frame's name and source lines use the address space that ntoseye recovered that frame from, including the process address space of a parked thread.

The stack of the current vCPU starts from the console context, which these commands select:

- `.thread <ethread>` selects the saved context of a parked Windows thread. If the vCPU of the thread is halted in the Windows hypervisor, `.thread` selects the VTL0 state that the hypervisor saved.
- {command}`.cxr` selects a context record.
- {command}`.trap` selects a trap frame.

The stacks of other vCPUs start from their own registers, and showing them in the editor does not change the console context. If you select a frame from one of these stacks, the console switches to that vCPU.

Clients that support `supportsInvalidatedEvent` refresh their panes automatically. With other clients, you refresh the panes manually.

### Locals, registers, and watches

When the compiler inlines a call, ntoseye shows it as a frame named `[Inline Frame] module!function`, as Visual Studio does. That frame is at the source line of the inlined function, and the frame that contains the inlined call is at the line of the call.

Locals and parameters use PDB locations, as in {command}`dv`. An inline frame shows the locals and parameters of the inlined function, and the frame that contains the inlined call shows those of its own procedure.

Caller frames contain only the registers that ntoseye recovers when it unwinds the stack, and other values are not available.

ntoseye reads a frame's locals, their values, and their children from the address space in which it recovered the stack. As a result, the frames of a parked thread show the locals of that thread's process, whatever {command}`.process` selects.

ntoseye expands structs, unions, arrays, and pointers with {command}`dt` decoding. Null pointers, unresolved types, and zero-sized types do not expand. To see the raw layout, use {command}`dt` in the console.

The Registers scope uses {command}`r`. Frame 0 shows the live register file and is writable, as are the inline frames at its address, which share its registers. Caller frames show the sparse recovered context.

When ntoseye walks a stack from a saved context (a parked thread, a {command}`.cxr` context record, or the VTL0 state that the hypervisor saved), every frame is recovered, so you cannot write to the registers of any frame in that stack.

Watch and hover use [core expressions](../reference/expressions.md), which can contain:

- locals (`index`, `Irp->IoStatus.Status`)
- addresses (`poi(nt!PsInitialSystemProcess)`)
- registers (`@rip`)
- casts (`(_IRP*)@rcx`)

The console radix (`n 10`) applies to these expressions. An expression uses the registers of the selected frame and, like the locals, reads the address space in which ntoseye recovered that frame's stack. The Debug Console uses the console's inspection context instead, so a {command}`.process` scope applies there.

Locals need private PDBs and a location that ntoseye can recover in the selected frame. Use `$!name` to make sure that a name resolves to a local, and `&` to get the storage address of a local. Typed structs, arrays, and pointers expand into children.

You can write in place to scalar registers, locals, struct fields, and array elements. Bitfields and values wider than 8 bytes need console commands such as {command}`eb` or {command}`ed`.

### Breakpoints

Source breakpoints use `bu file:line`. A breakpoint on an unresolved line stays unverified until its module loads, and then a `breakpoint` event updates the client. You can edit breakpoints while the target runs, in which case the adapter pauses and resumes the target.

Function breakpoints use `bu <symbol>` but skip the prologue, so the parameters are available when the breakpoint stops. {command}`bu` in the console stops at the symbol itself.

Instruction breakpoints, which you set from the disassembly view, use `bp <address>`.

Data breakpoints use {command}`ba` on variable storage, including fields and array elements. Locals held in registers and bitfields have no separate address that ntoseye can watch. Only KD and KDNET support data breakpoints.

No DAP breakpoint type names a hypercall's caller, so set a [hypercall breakpoint](../using/breakpoints.md#hypercall-breakpoints) with {command}`!hvbp` in the Debug Console. The client's continue honors its filter, and its hit is reported as a breakpoint stop.

ntoseye does not support exception breakpoints, so configure the exception policy with {command}`sx` commands in the console. When `sxe ld` causes a stop at a module load, the adapter reports it with the reason `module load`, and the console shows the stop's `ModLoad:` line. A stop from `sxe ud` has the reason `module unload`, with its `Unload module` line.

All breakpoint types accept conditions and hit counts. `hitCondition` must be a decimal pass count, so values such as `>5` or `0x10` are not valid. Breakpoint conditions in the editor also use decimal literals, while conditions in the console use the session radix.

### Log points

A log point is a breakpoint with the action `.printf "..."; gc`, which prints a message and continues. Each `{...}` placeholder contains a core expression, for example a local such as `{index}`, and shows its value in hexadecimal. The text around the placeholders is literal.

Log placeholders cannot contain quotes or semicolons, and ntoseye removes whitespace from them because {command}`.printf` uses whitespace to separate arguments. When a log action succeeds, the target continues without stopping the client. Conditions and hit counts still apply.

### Stepping

Step over and step into go forward one source line when line records exist, or one instruction when they do not. With `instruction` granularity, a step is always one instruction. A step covers a range of straight-line instructions in one run.

Step out uses {command}`gu` and stops at the return address for all granularities.

The disassembly view uses {command}`u` to scroll forward and {command}`ub` to scroll backward.

### Memory

The memory view reads and writes virtual memory in the current process context. When ntoseye reads memory, it replaces the bytes of its own breakpoints with the original opcodes, so the view does not show an `int3` that ntoseye put in memory.

If a write crosses into a page that ntoseye cannot translate, ntoseye writes the bytes before that page. When the request sets `allowPartial`, the response gives the number of bytes written. Otherwise, the write fails and gives that number.

### Paging

Stack requests support paging with `startFrame` and `levels`, and variable requests with `start` and `count`.

ntoseye decodes arrays one window at a time, up to 1024 elements for each request. It does one bounded stack walk for each stop, and each stack page is a slice of that walk. {command}`dt` in the console shows 16 elements by default; to see more, use `dt -a` or {command}`dq`.

## Resume and step from the editor

The Debug Console uses the same remote dispatch context as MCP and does not accept commands that resume the target, such as {command}`g`, {command}`p`, {command}`gu`, {command}`wt`, and {command}`.reboot`. To step and continue, use the editor's controls.

Breakpoint actions still run. For example, a breakpoint created with `bp nt!NtCreateFile do "k; gc"` runs its action at each hit and prints the output in the console, and because the action ends in `gc`, the target continues.

Pause also interrupts a step over a long-running call.

Disconnect, terminate, `SIGTERM`, `SIGHUP`, and `SIGINT` detach the adapter as `qd` does, which removes the installed breakpoints and resumes the guest. The adapter does this cleanup before it sends the disconnect response, because a client can kill the adapter immediately. If the target cannot halt for the cleanup, the adapter reports the failure and does not resume the target.

:::{warning}
`SIGKILL` stops the adapter before it can do the cleanup, so the breakpoint entries stay installed. For more information, see [breakpoint recovery](../using/breakpoints.md).
:::
