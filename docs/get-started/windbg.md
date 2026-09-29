# Coming from WinDbg

`ntoseye` uses the WinDbg command language. So most commands that you type in WinDbg work in `ntoseye` without changes. This page lists:

- the items that work the same as in WinDbg,
- the items that have a different syntax or are not available,
- the items that only `ntoseye` has.

## What carries over

- **Command names and syntax.** {command}`bp`, {command}`kn`, {command}`dt`, {command}`!process`, {command}`lm`, {command}`u`, the `d*` and `e*` families, {command}`.reload`, {command}`.sympath`, {command}`!analyze`, and many more commands have the same names and syntax. The [command reference](../reference/commands/index.md) lists all of the commands.
- **MASM expressions.** `ntoseye` uses MASM expressions, with the WinDbg default radix (hexadecimal). This includes `poi()`, `by`/`wo`/`dwo`/`qwo`, `@rax`, `$ip`/`$proc`/`$thread` and the other pseudo-registers, and `@$name`. It also includes separated addresses such as ``fffff803`1a2b3c4d``. See [Expressions](../reference/expressions.md).
- **The breakpoint grammar.** Breakpoints accept pass counts and `if <expr>` conditions. They also accept `do "<commands>"` actions that resume with `g` or `gc`, and `/1`, `/p`, and `/t`. See [Breakpoints](../using/breakpoints.md).
- **Command programs and scripts.** `ntoseye` has `.if`/`.elsif`/`.else`, `.while`, `.for`, `.do`, `.break`, `.continue`, `.block`, `j`, `.foreach`, the `!for_each_*` commands, and `$t0`-`$t19`. You can run script files with `$<`, `$$<`, `$><`, `$$><`, and `$$>a<`. Scripts can use `${$arg1}` and `${/d:$arg1}`.
- **Address ranges.** `L<count>`, `L?<count>`, `L-<count>`, and an end address work the same. The range includes the end address: `db nt nt+7` shows 8 bytes.
- **Symbols.** The default symbol server is the Microsoft symbol server. The cache under `~/.ntoseye/symbols` uses the `symstore` layout. WinDbg also reads this layout.
- **{command}`.kdfiles`.** {command}`.kdfiles` reads WinDbg driver replacement map files. See [Driver replacement](../using/kdfiles.md).

## Spelled differently, or missing

| In WinDbg | In ntoseye |
| --- | --- |
| `dx`, `??`, `@@c++( )` | Use typed MASM expressions, for example `ev ((nt!_EPROCESS*)@$proc)->UniqueProcessId`. You can also use {command}`dt`. Member access gives the value of the field. It does not give the address of the field. There is no C++ evaluator. So `ntoseye` does not scale pointer arithmetic. |
| `!name` for a symbol in any module | Use `module!name`. In `ntoseye`, a leading `!` negates the value. `!name` alone shows a message that the name is ambiguous. |
| `x` exact wildcard match | {command}`x` does a fuzzy search. `*` and `?` are still wildcards. `^`, `$`, `'`, `!`, and spaces make the search narrower. |
| `as Name Text` with `${Name}` substituted in later commands | {command}`as` defines a command alias. For example, type `as ubp bp ${1}; g`, then type `ubp nt!NtCreateFile`. `${1}`, `${2}`, ... and `${*}` are the arguments of the alias. |
| `.process /i` (invasive switch, then `g`) | {command}`.process` switches to the process immediately, with or without `/i`. `ntoseye` reads the memory of any process through the page tables of that process. `attach <pid>` does the same. |
| `!wmitrace.searchpath`, `!wmitrace.tmffile` (WPP message formatting) | You do not need these commands. `ntoseye` does not read `.tmf` files. {command}`!wmitrace.logdump` formats a WPP message from the trace message format (TMF) annotations in a loaded PDB that declares the message. If no loaded PDB declares the message, {command}`!wmitrace.logdump` shows the raw message. The public Microsoft `Wdf01000.pdb` contains the TMF for KMDF. For other drivers, the TMF is only in the private PDB of the driver. Use {command}`.sympath+` to add that PDB (see [Symbols and source](../using/symbols.md)). |
| `.detach` | Not available. {command}`q` (also `qd`) removes the breakpoints of the session and exits. The guest continues to run. |
| `a` (assemble), `.fnret`, `!for_each_local` | Not available. `ntoseye` does not assemble code. Public symbols do not contain return types or local types. To write bytes, use {command}`eb`. |
| `!wdfkd.*` (KMDF) | `ntoseye` has {command}`!wdfkd.wdfldr`, {command}`!wdfkd.wdfdriverinfo`, {command}`!wdfkd.wdfhandle`, {command}`!wdfkd.wdfdevice`, {command}`!wdfkd.wdfqueue`, and {command}`!wdfkd.wdflogdump`. These commands use `Wdf01000.pdb`. The other `!wdfkd` commands and UMDF are not available. See [KMDF drivers](../using/kmdf.md). |
| `!rcdrkd.*`, `!ndiskd.*`, `!apic`, `!ioapic`, `!sysinfo` | Not available. |
| `~` lists threads of a user-mode process | {command}`~` lists the processors (vCPUs). `~Ns` selects a processor. For Windows threads, use {command}`threads` and {command}`!thread`. |

## Behaves differently

- **Breakpoint scoping is a filter.** `ntoseye` checks `bp /p <pid>` and `/t` when a breakpoint hits. The breakpoint itself is global. So a breakpoint in a shared DLL stops every process that runs that code. `ntoseye` resumes the hits outside the scope and shows no message. [Breakpoints in shared pages](../using/breakpoints.md#user-mode-breakpoints-in-shared-pages) explains the cost. `/c <processor>` limits a breakpoint to one processor. WinDbg has no equivalent option.
- **{command}`!uniqstack` groups kernel threads.** In WinDbg, the user-mode {command}`!uniqstack` groups the threads of one process. In `ntoseye`, it groups the threads of the `.process` process, or all threads in the system. A stack includes the user frames below a system call.
- **{command}`.shell` runs only at the interactive prompt.** `ntoseye` does not accept {command}`.shell` in these locations:
  - breakpoint actions
  - exception commands
  - MCP, DAP, and the SDK

  So a client cannot start programs on the host.
- **Some hardware access depends on the backend.** Port I/O needs the `kd` or `kdnet` backend. The port I/O commands are {command}`ib`, {command}`ob`, and their word and dword forms. {command}`!pci` reads configuration space over `kd`, `kdnet`, or `gdb`. It cannot read configuration space from memory alone. {command}`!pcitree` works on all backends.
- **Some backends need no debugger in Windows.** With the `gdb` and `memory` backends, Windows starts normally, without `bcdedit /debug`. So Windows does not detect the debugger, and it operates as it does in production. See [Choosing a backend](../setup/backends.md).

## Only in ntoseye

- Listings: {command}`ps`, {command}`threads`, {command}`drivers`, {command}`ssdt`, {command}`callbacks`, {command}`irps`.
- Ranges: if the second value of a range is less than its start, the second value is a length in bytes. For example: `db nt 20`.
- Target and session: {command}`status`, {command}`capabilities`, {command}`vcpu`, and convenience variables with {command}`set`, {command}`unset`, and {command}`vars`.
- Symbols: {command}`.fetchimage` downloads the image of a module. {command}`ld` forces the symbol load for one module.
- VBS: {command}`.vtl`, {command}`!trustlets`, and {command}`.vtlcxr` inspect the secure kernel and the Windows hypervisor. See [VBS and the Windows hypervisor](../platforms/vbs.md).
- Scripting: [custom REPL commands](../scripting/commands.md) in Python. {command}`reload-scripts` reloads them.
