# Coming from WinDbg

`ntoseye` speaks WinDbg's command language, so most of what you type in WinDbg works unchanged. This page lists what carries over, what is spelled differently or missing, and what `ntoseye` adds.

## What carries over

- **Command names and syntax.** {command}`bp`, {command}`kn`, {command}`dt`, {command}`!process`, {command}`lm`, {command}`u`, the `d*` and `e*` families, {command}`.reload`, {command}`.sympath`, {command}`!analyze`, and so on. The [command reference](../reference/commands/index.md) lists every one.
- **MASM expressions** with WinDbg's hexadecimal default radix: `poi()`, `by`/`wo`/`dwo`/`qwo`, `@rax`, `$ip`/`$proc`/`$thread` and the other pseudo-registers, `@$name`, separated addresses like ``fffff803`1a2b3c4d``. See [Expressions](../reference/expressions.md).
- **The breakpoint grammar:** pass counts, `if <expr>` conditions, `do "<commands>"` actions with a trailing `gc`, `/1`, `/p`, `/t`. See [Breakpoints](../using/breakpoints.md).
- **Symbols.** Microsoft's symbol server is the default, and the cache under `~/.ntoseye/symbols` uses the `symstore` layout that WinDbg reads too.
- **{command}`.kdfiles`** reads WinDbg's driver replacement map files. See [Driver replacement](../using/kdfiles.md).

## Spelled differently, or missing

| In WinDbg | In ntoseye |
| --- | --- |
| `dx`, `??`, `@@c++( )` | Typed MASM expressions: `ev ((nt!_EPROCESS*)@$proc)->UniqueProcessId`, or {command}`dt`. Member access yields the field's value, not its address. There is no C++ evaluator, so pointer arithmetic is never scaled. |
| `!name` for a symbol in any module | `module!name`. A leading `!` negates here, and `!name` alone reports the ambiguity. |
| `.foreach`, `!for_each_process` | The [Python SDK](../scripting/sdk.md) or a [custom command](../scripting/commands.md). |
| `x` exact wildcard match | {command}`x` is a fuzzy search: `*` and `?` still glob, and `^`, `$`, `'`, `!`, and spaces refine it. |
| `as Name Text` with `${Name}` substituted in later commands | {command}`as` defines a command alias: `as ubp bp ${1}; g`, then `ubp nt!NtCreateFile`. `${1}`, `${2}`, ... and `${*}` are the alias's arguments. |
| `.process /i` (invasive switch, then `g`) | {command}`.process` switches immediately, with or without `/i`: `ntoseye` reads any process's memory through its page tables. `attach <pid>` is the same. |
| `bsc`, `c`, `m`, `.detach`, `qd` | Not available. Change a condition with {command}`bpc`; {command}`q` exits. |
| `~` lists threads of a user-mode process | {command}`~` lists processors (vCPUs), `~Ns` selects one. Windows threads are {command}`threads` and {command}`!thread`. |

## Behaves differently

- **Breakpoint scoping is a filter.** `bp /p <pid>` and `/t` are checked by `ntoseye` when a breakpoint hits; the breakpoint itself is global, so a breakpoint in a shared DLL traps every process that runs it, and hits outside the scope are resumed silently. [Breakpoints in shared pages](../using/breakpoints.md#user-mode-breakpoints-in-shared-pages) explains the cost. `/c <processor>` scopes to one processor and has no WinDbg equivalent.
- **Some backends need no debugger in Windows.** Over the `gdb` and `memory` backends Windows boots normally, without `bcdedit /debug`, so it does not know it is being debugged and behaves as it does in production. See [Choosing a backend](../setup/backends.md).

## Only in ntoseye

- Listings: {command}`ps`, {command}`threads`, {command}`drivers`, {command}`ssdt`, {command}`callbacks`, {command}`irps`.
- Target and session: {command}`status`, {command}`capabilities`, {command}`vcpu`, convenience variables with {command}`set`, {command}`unset`, and {command}`vars`.
- Symbols: {command}`.fetchimage` downloads a module's image, {command}`ld` forces one module's symbol loading.
- VBS: {command}`.vtl`, {command}`!trustlets`, and {command}`.vtlcxr` inspect the secure kernel and the Windows hypervisor. See [VBS and the Windows hypervisor](../platforms/vbs.md).
- Scripting: [custom REPL commands](../scripting/commands.md) in Python, reloaded with {command}`reload-scripts`.
