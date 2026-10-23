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

As you type, the rest of the most recent earlier line that starts with what you've typed appears dimmed after the cursor: type `bp` and see `bp nt!NtClose` if that's the last breakpoint you set. Press **→**, **End** or **Ctrl+E** to accept it, or **Ctrl+→** to accept it a word at a time. **Enter** runs only what you typed. With `NO_COLOR` set, nothing is suggested, since only its dimming sets a suggestion apart from what you typed. ntoseye keeps your history in `~/.ntoseye/history`.

With `--plain-repl`, ntoseye reads commands line by line without completion or history, so you can pipe a command file into it.

ntoseye shows color only when the output goes to a terminal. If you redirect the output, or if `NO_COLOR` is set, the output is plain text, and so are the prompt and its completion menu. With `TERM=dumb`, as in Emacs's `M-x shell`, ntoseye also reads commands as `--plain-repl` does, since that terminal can't move the cursor for the line editor.

The prompt marks where each command and its output start and end, as a shell does for its terminal (OSC 133). A terminal that reads these marks, such as Ghostty, kitty, WezTerm, iTerm2, Windows Terminal, the VS Code terminal or Tern, can then jump from one command to the next, select a command's output, or flag one that reported an error.

When the target ran for 10 seconds or more before it stopped, ntoseye asks the terminal for a desktop notification, such as `ntoseye: breakpoint #0 hit at nt!NtClose on processor 2`, so you can turn to something else while it runs. kitty shows it only while its window is out of view. Ghostty, iTerm2 and other terminals that read OSC 9 show it each time, and a terminal that reads neither shows nothing. A stop you cause yourself, with Ctrl+C or `break`, sends none.

The window title names the prompt's processor and backend, and where the target stopped (`ntoseye - 3: kd - nt!NtClose+0x5`) or that it runs. ntoseye gives the title back when it exits. While the target runs, and while ntoseye downloads symbols or writes a dump, it reports progress to the terminal (OSC 9;4), which kitty, Ghostty, iTerm2 and Windows Terminal show on the window or tab.

## In Tern

[Tern](https://stencil.so/tern) is Stencil's terminal. When you run ntoseye in it, you type commands in Tern's own input field, with completion popups and a searchable [palette](#the-palette). Results print as text, as in any other terminal. Other terminals aren't affected.

Tern support is experimental. It's built on a protocol that is still changing, so a Tern update can change how the prompt looks or behaves.

### The prompt

You type commands in Tern's input field at the bottom of the pane. The status bar above it shows the backend, the current thread, whether the target is running, and the main keys.

- **Tab** shows completions in a popup at the cursor, and the list narrows as you keep typing. The popup lists up to 100. When there are more, such as every command on an empty line, its last row says how many. Keep typing to narrow the list, or choose that row (or press **Alt+P**) to search them all in the [palette](#the-palette).
- The line is colored as you type, and a command name that doesn't exist turns red.
- If an earlier line starts with what you've typed, the rest of the most recent one appears dimmed after the cursor. Press **→** or **End** to accept it.
- **↑** and **↓** step through your history, and **Ctrl+Z** undoes.
- When you paste several lines, they become one line, with `;` between the commands.
- **Alt+P** opens the [palette](#the-palette), and **Ctrl+R** opens it on your history.

If Tern doesn't answer when the prompt opens, ntoseye switches to its regular line editor for the rest of the session. Restart ntoseye to get Tern's input field back.

While {command}`g` waits for a stop, a timer shows how long the target has been running, and it stays behind with how long the target ran. Long tasks, such as downloading and indexing symbols or writing a dump with {command}`.dump`, show a progress bar.

### When you get the line editor instead

ntoseye checks for Tern when it starts. This works over ssh, but not inside tmux, screen or zellij. To use the regular line editor in Tern, set `TERN_TSP=0`. `--plain-repl` reads commands line by line, without completion or history.

If your Tern is too old for ntoseye's prompt, you get the regular line editor, and ntoseye tells you so when it starts. Usually this means Tern's session daemon is still running the version from before an update. Choose **Restart Tern** in Tern's command palette to switch to the new one.

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
