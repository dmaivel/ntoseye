# Using the REPL

Command names follow WinDbg. The first name is the canonical name, and these friendly aliases also work:

- {command}`ps`
- {command}`threads`
- {command}`vcpu`
- {command}`vmmap`
- {command}`attach`
- {command}`si`
- {command}`ni`
- {command}`finish`

The [command reference](../reference/commands/index.md) lists every command, and `.hh <command>` shows the same help in the REPL. The [expression reference](../reference/expressions.md) describes expressions, registers, and symbol syntax. You can put several commands on one line if you separate them with semicolons.

With `--plain-repl`, ntoseye reads commands line by line without completion or history, so you can pipe a command file into it.

ntoseye shows color only when the output goes to a terminal. If you redirect the output, or if `NO_COLOR` is set, the output is plain text.

## Aliases

To make an alias, use `alias <name> <expansion>`. In the expansion, you can use these variables:

- `${1}` is the first argument to the alias.
- `${2}` is the second argument.
- `${*}` is all the alias arguments, separated by spaces.

ntoseye leaves other `${...}` forms, for example a `.foreach` variable or `${@#ModuleName}` in `!for_each_module`, in place for the command that uses them to replace. An alias expansion can contain a list of commands separated by semicolons.

```text
alias ubp bp ${1}; g
alias pe dt _EPROCESS poi(nt!PsInitialSystemProcess) ${1}
unalias ubp
```

ntoseye saves aliases in `~/.ntoseye/aliases`, and the {command}`reload-scripts` command loads the aliases and the custom Python commands again.
