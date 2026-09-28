# Coming from WinDbg

`ntoseye` speaks WinDbg's command language, so most of what you type in WinDbg works unchanged. This page lists what carries over, what is spelled differently or missing, and what `ntoseye` adds.

## What carries over

- **Command names and syntax.** {command}`bp`, {command}`kn`, {command}`dt`, {command}`!process`, {command}`lm`, {command}`u`, the `d*` and `e*` families, {command}`.reload`, {command}`.sympath`, {command}`!analyze`, and so on. The [command reference](../reference/commands/index.md) lists every one.
- **MASM expressions** with WinDbg's hexadecimal default radix: `poi()`, `by`/`wo`/`dwo`/`qwo`, `@rax`, `$ip`/`$proc`/`$thread` and the other pseudo-registers, `@$name`, separated addresses like ``fffff803`1a2b3c4d``. See [Expressions](../reference/expressions.md).
- **The breakpoint grammar:** pass counts, `if <expr>` conditions, `do "<commands>"` actions that resume with `g` or `gc`, `/1`, `/p`, `/t`. See [Breakpoints](../using/breakpoints.md).
- **Command programs and scripts:** `.if`/`.elsif`/`.else`, `.while`, `.for`, `.do`, `.break`, `.continue`, `.block`, `j`, `.foreach`, the `!for_each_*` commands, `$t0`-`$t19`, and script files run with `$<`, `$$<`, `$><`, `$$><`, and `$$>a<` (with `${$arg1}` and `${/d:$arg1}`).
- **Address ranges:** `L<count>`, `L?<count>`, `L-<count>`, and an end address, which is included (`db nt nt+7` shows 8 bytes).
- **Symbols.** Microsoft's symbol server is the default, and the cache under `~/.ntoseye/symbols` uses the `symstore` layout that WinDbg reads too.
- **{command}`.kdfiles`** reads WinDbg's driver replacement map files. See [Driver replacement](../using/kdfiles.md).

## Spelled differently, or missing

| In WinDbg | In ntoseye |
| --- | --- |
| `dx`, `??`, `@@c++( )` | Typed MASM expressions: `ev ((nt!_EPROCESS*)@$proc)->UniqueProcessId`, or {command}`dt`. Member access yields the field's value, not its address. There is no C++ evaluator, so pointer arithmetic is never scaled. |
| `!name` for a symbol in any module | `module!name`. A leading `!` negates here, and `!name` alone reports the ambiguity. |
| `x` exact wildcard match | {command}`x` is a fuzzy search: `*` and `?` still glob, and `^`, `$`, `'`, `!`, and spaces refine it. |
| `as Name Text` with `${Name}` substituted in later commands | {command}`as` defines a command alias: `as ubp bp ${1}; g`, then `ubp nt!NtCreateFile`. `${1}`, `${2}`, ... and `${*}` are the alias's arguments. |
| `.process /i` (invasive switch, then `g`) | {command}`.process` switches immediately, with or without `/i`: `ntoseye` reads any process's memory through its page tables. `attach <pid>` is the same. |
| `!wmitrace.searchpath`, `!wmitrace.tmffile` (WPP message formatting) | Not needed, and `.tmf` files are not read: {command}`!wmitrace.logdump` formats a WPP message from the trace message format (TMF) annotations in any loaded PDB that declares it, and shows it raw otherwise. Microsoft's public `Wdf01000.pdb` carries KMDF's own TMF; any other driver's is only in its private PDB, which {command}`.sympath+` adds (see [Symbols and source](../using/symbols.md)). |
| `.detach` | Not available. {command}`q` (also spelled `qd`) removes the session's breakpoints and exits with the guest running. |
| `a` (assemble), `.fnret`, `!for_each_local` | Not available: `ntoseye` does not assemble code, and public symbols carry no return or local types. Write bytes with {command}`eb`. |
| `!wdfkd.*` (KMDF) | {command}`!wdfkd.wdfldr`, {command}`!wdfkd.wdfdriverinfo`, {command}`!wdfkd.wdfhandle`, {command}`!wdfkd.wdfdevice`, {command}`!wdfkd.wdfqueue`, and {command}`!wdfkd.wdflogdump`, from `Wdf01000.pdb`; the rest of `!wdfkd`, and UMDF, are not available. See [KMDF drivers](../using/kmdf.md). |
| `!rcdrkd.*`, `!ndiskd.*`, `!apic`, `!ioapic`, `!sysinfo` | Not available. |
| `~` lists threads of a user-mode process | {command}`~` lists processors (vCPUs), `~Ns` selects one. Windows threads are {command}`threads` and {command}`!thread`. |

## Behaves differently

- **Breakpoint scoping is a filter.** `bp /p <pid>` and `/t` are checked by `ntoseye` when a breakpoint hits; the breakpoint itself is global, so a breakpoint in a shared DLL traps every process that runs it, and hits outside the scope are resumed silently. [Breakpoints in shared pages](../using/breakpoints.md#user-mode-breakpoints-in-shared-pages) explains the cost. `/c <processor>` scopes to one processor and has no WinDbg equivalent.
- **{command}`!uniqstack` groups kernel threads.** WinDbg's user-mode {command}`!uniqstack` groups one process's threads; here it groups the `.process` process's threads or every thread in the system, and a stack includes the user frames below a system call.
- **{command}`.shell` runs only at the interactive prompt.** It is refused in breakpoint actions and exception commands, and from MCP, DAP, and the SDK, so a client cannot start host programs.
- **Some hardware access depends on the backend.** Port I/O ({command}`ib`, {command}`ob`, and their word and dword forms) needs the `kd` or `kdnet` backend; {command}`!pci` reads configuration space over `kd`, `kdnet`, or `gdb`, not from memory alone. {command}`!pcitree` works everywhere.
- **Some backends need no debugger in Windows.** Over the `gdb` and `memory` backends Windows boots normally, without `bcdedit /debug`, so it does not know it is being debugged and behaves as it does in production. See [Choosing a backend](../setup/backends.md).

## Only in ntoseye

- Listings: {command}`ps`, {command}`threads`, {command}`drivers`, {command}`ssdt`, {command}`callbacks`, {command}`irps`.
- A range's second value below its start is a length in bytes: `db nt 20`.
- Target and session: {command}`status`, {command}`capabilities`, {command}`vcpu`, convenience variables with {command}`set`, {command}`unset`, and {command}`vars`.
- Symbols: {command}`.fetchimage` downloads a module's image, {command}`ld` forces one module's symbol loading.
- VBS: {command}`.vtl`, {command}`!trustlets`, and {command}`.vtlcxr` inspect the secure kernel and the Windows hypervisor. See [VBS and the Windows hypervisor](../platforms/vbs.md).
- Scripting: [custom REPL commands](../scripting/commands.md) in Python, reloaded with {command}`reload-scripts`.
