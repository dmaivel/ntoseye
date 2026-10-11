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

The [command reference](../reference/commands/index.md) lists every command, and `.hh <command>` shows the same help in the REPL. The [expression reference](../reference/expressions.md) describes expressions, registers, and symbol syntax. You can put several commands on one line if you separate them with semicolons. As in WinDbg, a command that reports an error ends the line, and ntoseye names the commands it did not run, so `bp nt!NoSuchName; g` does not resume the target.

With `--plain-repl`, ntoseye reads commands line by line without completion or history, so you can pipe a command file into it.

ntoseye shows color only when the output goes to a terminal. If you redirect the output, or if `NO_COLOR` is set, the output is plain text.

## In Tern

[Tern](https://stencil.so/tern) is Stencil's terminal. When you run ntoseye in it, the REPL uses Tern's own interface: you type in a real input field, and stops, stacks, memory dumps and other results appear as cards, tables and trees instead of plain text. Other terminals aren't affected.

Tern support is experimental. It's built on a protocol that is still changing, so a Tern update can change how things look, or turn some views back into text until ntoseye catches up.

### The prompt

You type commands in Tern's input field at the bottom of the pane. The status bar above it shows the backend, the current thread, whether the target is running, and the main keys.

- **Tab** shows completions in a popup at the cursor, and the list narrows as you keep typing. The popup lists up to 100. When there are more, such as every command on an empty line, its last row says how many. Keep typing to narrow the list, or choose that row (or press **Alt+P**) to search them all in the [palette](#the-palette).
- The line is colored as you type, and a command name that doesn't exist turns red.
- If an earlier line starts with what you've typed, the rest of the most recent one appears dimmed after the cursor. Press **→** or **End** to accept it.
- **↑** and **↓** step through your history, and **Ctrl+Z** undoes.
- When you paste several lines, they become one line, with `;` between the commands.
- **Alt+P** opens the [palette](#the-palette), and **Ctrl+R** opens it on your history.

If Tern doesn't answer when the prompt opens, ntoseye switches to its regular line editor for the rest of the session. Restart ntoseye to get Tern's input field back.

### What results look like

**Stops** are cards. A chip at the top says why the target stopped, such as `breakpoint #0`, `exception 0xC0000005` or `bugcheck`, and the card's border matches it: your theme's accent color for a breakpoint, amber for an exception, red for a bugcheck. Hover over an exception chip to see the name of its status code. Next to the chip is how long the target ran.

The card shows the thread, the registers (folded), the code at the stop with the current instruction marked, and the stack. When the stop is on the same thread as the one before, the registers' heading names the ones that changed, such as `registers rsp rip changed`, and their values are amber when you open it. Your {command}`display` expressions are in a table at the end, with changed values in amber. If the stop is at a line of a source file that {command}`.srcpath` can find, the card shows that source and folds the disassembly under it. The first stop after the guest reboots has a `reboot` chip and says whether the module list is available yet.

Other results:

- A **bugcheck** is a red card with the bugcheck's name and code, what its parameters mean, the faulting module and the trap frames. {command}`!analyze` shows its report as one card, with a section for each part.
- {command}`.trap` shows a card whose chip says what kind of entry built the frame, such as `system call` or `exception`. A register that kind of entry doesn't save shows `-`, and the chip's tooltip lists them. Trap frames in a bugcheck card look the same.
- {command}`k`, {command}`lm`, {command}`!process`, {command}`ps`, {command}`bl`, {command}`~`, {command}`x`, {command}`!vad`, {command}`vmmap`, {command}`!pte` and {command}`vars` show **tables**. In a narrow pane the least important columns are hidden first, and columns with nothing in them are left out. {command}`x` shows the `$n` variable that holds each match, and {command}`!vad` and {command}`vmmap` highlight memory that is both writable and executable, apart from the copy-on-write sections every image has.
- **Memory dumps** such as {command}`db`, {command}`dd` and {command}`dq` dim zero values and show unprintable bytes as `·`, and {command}`dqs` shows the symbol for each value.
- {command}`dt`, {command}`wt` and {command}`!hvpartitions` show **trees** you can fold, and {command}`.help` groups the commands into categories you can fold. `.help <command>` shows a card with the command's usage and details.
- {command}`r` shows a register grid, and {command}`u`, {command}`ub` and {command}`uf` color instructions with Tern's syntax colors. To copy an instruction, right-click its line and choose **Copy**.
- {command}`ls` and {command}`lsa` show source highlighted for its language, with line numbers and the current line marked, under a header that opens the file in Tern.
- While {command}`g` waits for a stop, a timer shows how long the target has been running.
- Long tasks, such as downloading and indexing symbols or writing a dump with {command}`.dump`, show a progress bar.

Commands that aren't listed here print text as usual.

### When you get text instead

ntoseye checks for Tern when it starts. This works over ssh, but not inside tmux, screen or zellij. To get plain text in Tern, set `TERN_TSP=0`. `--plain-repl` also gives you text, but without completion or history.

Output that another program captures (MCP, the Python SDK, the DAP console and `.foreach`) is always text, and so are `.logopen` transcripts.

If your Tern is too old to draw these views, you get text, and ntoseye tells you so when it starts. Usually this means Tern's session daemon is still running the version from before an update. Choose **Restart Tern** in Tern's command palette to switch to the new one.

### The palette

Press **Alt+P** at the prompt to open the palette, a searchable list over the pane. Its tabs list the commands (with your recent lines), your whole history, the symbols, the types and the processes. **Ctrl+R** opens it on your history.

Type to search, choose with the arrow keys or the mouse, and press **Tab** to change tabs. **Enter** puts your choice in the prompt, and **Escape** closes the palette without changing anything.

The palette opens on the tab that fits what you're typing:

- On the command name, it shows the commands, with help for the selected one under the list. Your choice replaces the line.
- On an argument, it shows the symbols, the types for {command}`dt`, or the processes for a command that takes one. Your choice replaces the word you started, so typing `u NtClo` and pressing **Alt+P** finds `nt!NtClose`.
- With nothing typed, picking a process puts `.process /p <pid>` in the prompt.

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
