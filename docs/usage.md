# REPL usage

Expressions accept symbols, numeric literals, registers, casts, arithmetic, indexing, and pointer reads:

```text
ev @rip
ev poi(nt!PsInitialSystemProcess)
ev (_EPROCESS)poi(nt!PsInitialSystemProcess)->UniqueProcessId
```

The REPL follows WinDbg's hexadecimal default radix: a bare `1000` is `0x1000`. Use the `0n` prefix for an explicit decimal value (`0n10`), or `n 10` to switch the session default to decimal. `n 8` and `n 16` select octal and hexadecimal. Bare hexadecimal tokens containing `a`-`f` are resolved as symbols first and fall back to hexadecimal only when no symbol matches. Use `0x...` when an address must be unambiguously numeric.

Field access in `ev` needs an explicit cast so ntoseye knows the layout. The `dt` command gets the type from its first argument, so the address expression does not need a cast:

```text
dt _EPROCESS poi(nt!PsInitialSystemProcess) UniqueProcessId
```

## Breakpoints and watchpoints

Breakpoints and data watchpoints accept conditions written directly after the address expression. Conditions use the normal expression grammar: comparisons, bitwise operations, and short-circuiting `!`, `&&`, and `||` can be combined with parentheses. Write ranges explicitly (`0 < @rax && @rax < 0n10`) rather than as chained comparisons.

```text
bp nt!KeBugCheckEx @rcx == 0x50 && (@rdx & 0xff) != 0
```

Data watchpoints use `ba <access><size> <address>` (`w` = write, `r` = read/write, `e` = execute; sizes 1, 2, 4, or 8 with natural alignment; KD backend only). For a quick live test, watch a global the kernel writes to frequently:

```text
ba w8 nt!KiBalanceSetManagerLastCheckTick
```

Deferred breakpoints preserve their symbolic or `file.c:line` specification across module unload/reload. `/1` makes a one-shot breakpoint, `/p <pid>` sets an explicit process scope, a pass count delays surfacing, and `do` attaches a bounded REPL action:

```text
bu /1 /p 1234 mydriver!DriverEntry
bu mydriver.c:42 10 if @rcx != 0 do r; gc
bm mydriver!Dispatch*
```

## Aliases

Aliases use `alias <name> <expansion>`. `${1}` is the first argument passed to the alias, `${2}` is the second, and `${*}` expands to all alias arguments separated by spaces. Alias expansions can contain command lists separated by semicolons.

```text
alias ubp bp ${1}; g
alias pe dt _EPROCESS poi(nt!PsInitialSystemProcess) ${1}
unalias ubp
```

Aliases are saved in `~/.ntoseye/aliases`; `reload-scripts` reloads aliases and custom Python commands.
