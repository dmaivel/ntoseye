# Using the REPL

Command names follow WinDbg. The first name is canonical, and friendly aliases ({command}`ps`, {command}`threads`, {command}`vcpu`, {command}`vmmap`, {command}`attach`, {command}`si`, {command}`ni`, and {command}`finish`) still work.

Every command is listed in the [command reference](../reference/commands/index.md), and `.hh <command>` prints the same help in the REPL; expressions, registers, and symbol syntax are in the [expression reference](../reference/expressions.md). Several commands can go on one line, separated by semicolons.

## Aliases

Aliases use `alias <name> <expansion>`. `${1}` is the first argument passed to the alias, `${2}` is the second, and `${*}` expands to all alias arguments separated by spaces. Alias expansions can contain command lists separated by semicolons.

```text
alias ubp bp ${1}; g
alias pe dt _EPROCESS poi(nt!PsInitialSystemProcess) ${1}
unalias ubp
```

Aliases are saved in `~/.ntoseye/aliases`; {command}`reload-scripts` reloads aliases and custom Python commands.
