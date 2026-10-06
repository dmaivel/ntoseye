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

## In Tern

In [Tern](https://stencil.so/tern), Stencil's terminal, the REPL draws its results natively instead of as text:

- A stop is a card. A chip in its head says why the target stopped, such as `breakpoint #0`, `exception 0xC0000005` or `bugcheck`, in the color of the card's ring: the accent for a breakpoint, amber for an exception, red for a bugcheck. Beside it is how long the target ran. The card holds the thread, the registers (folded), the code at the stop with the current instruction marked, and the stack.
- A bugcheck is a red card with the bugcheck's name and code, its parameters and what they mean, the faulting module and the trap frames. {command}`!analyze` shows its report as one card, with a section for each part of the report.
- {command}`k`, {command}`lm`, {command}`!process`, {command}`ps`, {command}`bl`, {command}`~`, {command}`!pte` and {command}`vars` are tables. In a narrow pane, their less important columns hide first, and a column that no row fills is left out.
- Memory dumps such as {command}`db`, {command}`dd` and {command}`dq` dim the zero values and show a byte that isn't printable as `·`, and {command}`dqs` lists the symbol of each value.
- {command}`dt`, {command}`wt` and {command}`!hvpartitions` are trees that you can fold, and {command}`.help` folds by category.
- {command}`r` is a register grid, and {command}`u`, {command}`ub` and {command}`uf` color instructions with Tern's syntax colors.
- {command}`ls` and {command}`lsa` show source in Tern's highlighting for the file's language, with line numbers and the current line marked, under a header that opens the file in Tern. A stop at a line of a file that {command}`.srcpath` finds shows that source in the card, and the disassembly folds under it.
- While {command}`g` waits for a stop, a timer shows how long the target has run.
- Long tasks, such as indexing symbols and writing a dump with {command}`.dump`, show a Tern progress bar.

Other commands print text. ntoseye asks the terminal when the REPL starts, so this also works over ssh, but not inside tmux, screen or zellij. Output that a host captures (MCP, the Python SDK, the DAP console, `.foreach`) and `.logopen` transcripts are always text. For text in Tern, set `TERN_TSP=0` or use `--plain-repl`.

A Tern too old to draw these views, such as a session daemon still running the version from before an update, gets text, and ntoseye says so when it starts. To run the updated version, use **Restart Tern** in Tern's command palette.

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
