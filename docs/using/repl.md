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

- The prompt is Tern's own input field at the bottom of the pane, under a status bar with the backend, the thread, whether the target is running, and the keys. **Tab** opens the completions in a popup at the caret, which narrows as you type. The line is colored as you type it, with an unknown command in red. The newest earlier line that starts with what you typed shows dim after the caret, and **→** or **End** takes it. **↑** and **↓** go through the history, **Ctrl+Z** undoes, and a pasted block becomes one line of commands separated by `;`.
- A stop is a card. A chip in its head says why the target stopped, such as `breakpoint #0`, `exception 0xC0000005` or `bugcheck`, in the color of the card's ring: the accent for a breakpoint, amber for an exception, red for a bugcheck. Hover over an exception's chip to see the name of its status code. Beside the chip is how long the target ran. The card holds the thread, the registers (folded), the code at the stop with the current instruction marked, and the stack. After a stop on the same thread, the folded registers name the registers that changed since that stop, such as `registers rsp rip changed`, and open with those values in amber. The {command}`display` expressions are a table at the end of the card, with the values that changed in amber. The first stop after the guest reboots is a card with a `reboot` chip that says whether the module list is available yet.
- A bugcheck is a red card with the bugcheck's name and code, its parameters and what they mean, the faulting module and the trap frames. {command}`!analyze` shows its report as one card, with a section for each part of the report.
- {command}`.trap` is a card with a chip for the kind of entry that built the frame, such as `system call` or `exception`. A register that the entry doesn't save shows `-`, and the chip's tooltip says which ones. Trap frames in a bugcheck card use the same layout.
- {command}`k`, {command}`lm`, {command}`!process`, {command}`ps`, {command}`bl`, {command}`~`, {command}`x`, {command}`!vad`, {command}`vmmap`, {command}`!pte` and {command}`vars` are tables. In a narrow pane, their less important columns hide first, and a column that no row fills is left out. {command}`x` shows the `$n` variable that holds each match, and {command}`!vad` and {command}`vmmap` highlight memory that is both writable and executable, except the copy-on-write sections that every image has.
- Memory dumps such as {command}`db`, {command}`dd` and {command}`dq` dim the zero values and show a byte that isn't printable as `·`, and {command}`dqs` lists the symbol of each value.
- {command}`dt`, {command}`wt` and {command}`!hvpartitions` are trees that you can fold, and {command}`.help` folds by category. `.help <command>` is a card with the command's usage and details.
- {command}`r` is a register grid, and {command}`u`, {command}`ub` and {command}`uf` color instructions with Tern's syntax colors. To copy an instruction line, right-click it and choose **Copy**.
- {command}`ls` and {command}`lsa` show source in Tern's highlighting for the file's language, with line numbers and the current line marked, under a header that opens the file in Tern. A stop at a line of a file that {command}`.srcpath` finds shows that source in the card, and the disassembly folds under it.
- While {command}`g` waits for a stop, a timer shows how long the target has run.
- Long tasks, such as downloading and indexing symbols and writing a dump with {command}`.dump`, show a Tern progress bar.

Other commands print text. ntoseye asks the terminal when it starts, so this also works over ssh, but not inside tmux, screen or zellij. Output that a host captures (MCP, the Python SDK, the DAP console, `.foreach`) and `.logopen` transcripts are always text. For text in Tern, set `TERN_TSP=0` or use `--plain-repl`.

A Tern too old to draw these views, such as a session daemon still running the version from before an update, gets text, and ntoseye says so when it starts. To run the updated version, use **Restart Tern** in Tern's command palette.

### The palette

In Tern, press **Alt+P** at the prompt to open the palette, a search sheet over the pane. Its tabs list the commands with your recent lines, all your earlier lines, the symbols, the types and the processes. **Ctrl+R** opens it on the earlier lines. Type to search, use the arrow keys or the mouse to choose, press **Tab** to change tabs, and press **Enter** to put your choice in the prompt, or **Escape** to close the palette without a change.

The palette opens on the tab for what you are typing. For the command word it shows the commands, with the selected command's help under the list, and your choice replaces the line. For an argument it shows the symbols, the types for {command}`dt`, or the processes for a command that takes one, and your choice replaces the word you started. So `u NtClo` and **Alt+P** finds `nt!NtClose`. With an empty line, a process becomes `.process /p <pid>`.

### The browser

In Tern, {command}`browse` or **F2** at the prompt opens a full-screen browser over the pane. It shows code at the instruction pointer or at the address you give, or memory if the address isn't executable, one pointer per row with the symbol it points into. Use the arrow keys to move the cursor, and **Shift+↑** and **Shift+↓** or **Space** to move a page. **Enter** follows the branch or call under the cursor, the memory that an instruction addresses (`[rip+…]`), or the pointer in a memory row, and **Backspace** goes back. **Tab** shows the same address as memory or as code, **G** goes to an address or expression, **B** sets or clears a breakpoint at the instruction under the cursor, and **.** goes to the instruction pointer. **Escape** closes the browser and leaves the pane as it was, with the breakpoints that you set or cleared listed under the prompt. Tern keeps **Page Up** and **Page Down** to scroll the view.

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
