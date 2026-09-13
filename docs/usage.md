# REPL usage

Command names follow WinDbg: the first name is canonical, and friendly aliases (`ps`, `threads`, `vcpu`, `vmmap`, `attach`, `si`, `ni`, and `finish`) still work.

Expressions accept symbols, numeric literals, registers, casts, arithmetic, indexing, and pointer reads. A bare module name is its base address (`? nt`, `u nt+0x1000`):

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

## Execution control

- `g [address]` (`continue`) - Resume VM execution.
- `gh [address]` - Resume and mark the current exception handled.
- `gn [address]` - Resume and pass the current exception to Windows (KD only).
- `break` - Break or pause VM execution.
- `t` (`si`) - Single-step into the current instruction.
- `p or ni` - Step over the current instruction.
- `pa <address>` - Step over repeatedly until an address is reached.
- `ta <address>` - Step into repeatedly until an address is reached.
- `pc` - Step over until the next call instruction.
- `tc` - Step into until the next call instruction.
- `pt` - Step over until the next return instruction.
- `tt` - Step into until the next return instruction.
- `ph` - Step over until the next branch instruction.
- `th` - Step into until the next branch instruction.
- `gu or finish` - Run until the current function returns.
- `wt [count]` - Watch and trace calls until the current function returns.
- `.reboot` (`reboot`, `.restart`, `restart`) - Reboot the debug target and reload its kernel context.
- `.crash` (`crash`) - Force a `MANUALLY_INITIATED_CRASH` bugcheck (`0xE2`); Windows writes its crash dump first (often a minute, ignoring break-ins), then reboots or breaks in.

## Frames and context

- `r [register[=expression]]` (`registers`) - Display CPU registers or assign one register.
- `kn|k|kb|kp|kv [count]` - Display a stack; `kp` adds PDB parameter locations and `kv` adds provenance.
- `.frame [/r] [N]` (`frame`) - Select or display a zero-based stack frame; `/r` also displays recovered registers.
- `.cxr [address]` - Select a CONTEXT record, or reset the selected context.
- `.ecxr` - Select the current exception context.
- `.exr <address|-1>` - Display an `EXCEPTION_RECORD64`.
- `.trap [address-expression]` (`trap`) - Decode and display a `_KTRAP_FRAME`, defaulting to the current thread's saved frame.
- `.thread [ethread|tid]` - Switch the register and stack context to a Windows thread.
- `.process [/i] [/p] [/r] [eprocess|pid]` - Select a process address space for inspection.
- `.context <dtb>` - Set the translation base used for inspection.
- `~` (`vcpus`) - List vCPU contexts and their RIP values.
- `vcpu <id>` - Switch to a different vCPU context.
- `address <address-expression>` - Describe what an address belongs to (a module section or VAD region).

## Memory

Virtual memory display commands:

- `db <address> [L<count>|length|end]` - Display memory as bytes.
- `dw <address> [L<count>|length|end]` - Display memory as words (2 bytes).
- `dW <address> [L<count>|length|end]` - Display memory as words with an ASCII column.
- `dc <address> [L<count>|length|end]` - Display memory as doublewords with an ASCII column.
- `dd <address> [L<count>|length|end]` - Display memory as doublewords (4 bytes).
- `dq <address> [L<count>|length|end]` - Display memory as quadwords (8 bytes).
- `dp <address> [L<count>|length|end]` - Display memory as pointer-sized values.
- `dds <address> [L<count>|length|end]` - Display memory as doublewords, annotating values that resolve to symbols.
- `dqs <address> [L<count>|length|end]` (`dps`) - Display memory as quadwords, annotating values that resolve to symbols.
- `dyb <address> [L<count>|length|end]` - Display memory as binary values with their bytes.
- `dpp <address> [L<count>|length|end]` - Display pointers, dereference them, and annotate symbols.
- `da <address> [max-chars]` - Display a NUL-terminated ASCII string.
- `du <address> [max-chars]` - Display a NUL-terminated UTF-16 string.
- `ds <address>` - Display an ANSI_STRING descriptor and its buffer.
- `dS <address>` - Display a UNICODE_STRING descriptor and its buffer.

Disassembly and virtual memory writes:

- `u <address> [L<count>|end]` (`disasm`) - Disassemble at a symbol or address; `L<count>` counts instructions (default 8), an end address bounds bytes.
- `uf [address]` - Disassemble the function containing an address.
- `ub <address> [L<count>]` - Disassemble instructions ending at an address.
- `eb <address> <value...>` - Write one or more bytes to memory.
- `ew <address> <value...>` - Write one or more words (2 bytes) to memory.
- `ed <address> <value...>` - Write one or more doublewords (4 bytes) to memory.
- `eq <address> <value...>` - Write one or more quadwords (8 bytes) to memory.
- `ea <address> "text"` - Write an ANSI string to memory.
- `eu <address> "text"` - Write a UTF-16 string to memory.
- `eza <address> "text"` - Write a NUL-terminated ANSI string to memory.
- `ezu <address> "text"` - Write a NUL-terminated UTF-16 string to memory.
- `.writemem <file> <address> [L<len>|end]` - Write a virtual memory range to a file.
- `.readmem <file> <address> [L<len>|end]` - Read a file into a virtual memory range.
- `.formats <expression>` - Display an expression in common numeric formats.
- `f <address> <hex bytes> [L<count>|length|end]` - Fill memory with a repeated byte pattern.
- `s <address> <hex bytes> [length]` - Search memory for a byte pattern.

Physical memory commands use guest-physical addresses:

- `!db <address> [L<count>|length|end]` - Display guest-physical memory as bytes.
- `!dw <address> [L<count>|length|end]` - Display guest-physical memory as words.
- `!dd <address> [L<count>|length|end]` - Display guest-physical memory as doublewords.
- `!dq <address> [L<count>|length|end]` - Display guest-physical memory as quadwords.
- `!eb <address> <value...>` - Write one or more bytes to guest-physical memory.
- `!ed <address> <value...>` - Write one or more doublewords to guest-physical memory.
- `!eq <address> <value...>` - Write one or more quadwords to guest-physical memory.

## Types

- `dt [-r[N]] [-a[N]] [-v] [-y] [-l <field>] [module!]<type> [address] [field-pattern...]` - Display a type layout or decoded structure.
- `dl [-b] <address> <maxcount> [size]` - Dump a bounded `_LIST_ENTRY` chain.
- `!list -t [module!]<type>.<field> -x "<commands>" <address>` - Run commands for every element of a typed LIST_ENTRY chain.

For `dt`, `-r` expands nested structures, `-a` expands bounded arrays, `-v` shows field sizes, `-y` uses case-insensitive prefix matching, and `-l <field>` walks a LIST_ENTRY field. Nested field paths are dotted, and field patterns support `*` and `?`.

## Symbols

- `x <query>  or  x <module>!<query>` - Fuzzy-search symbols by name; `*` and `?` are globs.
- `ln <address>` - List the nearest symbol to an address.
- `? <expression>` (`ev`) - Evaluate an expression.
- `set $<name> <expression>` - Define a convenience variable usable in expressions as `$<name>`.
- `vars` - List defined convenience variables and result slots.
- `unset $<name>` - Remove a convenience variable.
- `.sympath [<directory|http-server> ...]` - Display or replace the ordered symbol source path.
- `.sympath+ <directory|http-server> ...` - Append entries to the ordered symbol source path.
- `.symfix` - Restore the ntoseye cache and Microsoft symbol server defaults.
- `.srcpath [<local-root|recorded-prefix=local-root> ...]` - Display or replace ordered local source path mappings.
- `.srcpath+ <local-root|recorded-prefix=local-root> ...` - Append local source path mappings.
- `dv [address]` - Display procedure locals and parameters at an address.
- `.reload [module]` - Reload symbols for one module or every module in the current scope.
- `ld <module>` - Force symbol source selection and indexing for one module.
- `lmv [module]` - Display detailed per-module symbol status and PDB identity.

Symbol queries also support `^` prefix, `$` suffix, `'` exact, `!` negation, and space-separated AND operators.

## Breakpoints and watchpoints

The shared breakpoint grammar follows WinDbg. Code breakpoints use `/1` (one-shot), `/p <pid>` (process scope), `/t <ethread>` (thread scope), and `/w "<expr>"` (conditional shorthand), followed by a target, optional pass count, `if <expr>`, and `do "<commands>"`; `ba` uses the same options except `/w` and adds `<access><size>`. `/t` is parsed as a thread scope, but current backends report thread-scoped breakpoints as unsupported. Conditions use the normal expression grammar: comparisons, bitwise operations, and short-circuiting `!`, `&&`, and `||` can be combined with parentheses. Write ranges explicitly (`0 < @rax && @rax < 0n10`) rather than as chained comparisons. Multi-command actions must be quoted, like WinDbg; a trailing `gc` continues after the action.

```text
bp nt!KeBugCheckEx @rcx == 0x50 && (@rdx & 0xff) != 0
bu /1 /p 1234 mydriver!DriverEntry
bu mydriver.c:42 10 if @rcx != 0 do "r; gc"
bm mydriver!Dispatch*
ba w8 nt!KiBalanceSetManagerLastCheckTick
```

- `bp [/1] [/p <pid>] [/t <ethread>] [/w "<expr>"] <address> [<passes>] [if <expr>] [do "<commands>"]` - Set a breakpoint.
- `bu [/1] [/p <pid>] [/t <ethread>] [/w "<expr>"] <symbol> [<passes>] [if <expr>] [do "<commands>"]` - Set a deferred symbolic breakpoint.
- `bm [/1] [/p <pid>] [/t <ethread>] [/w "<expr>"] <symbol-pattern> [<passes>] [if <expr>] [do "<commands>"]` - Set deferred symbolic breakpoints for matching symbols.
- `ba [/1] [/p <pid>] [/t <ethread>] <access><size> <address> [<passes>] [if <expr>] [do "<commands>"]` - Set a hardware debug-register breakpoint (KD backend only); `e` is execute, `r` is read/write, `w` is write, and sizes are 1, 2, 4, or 8 bytes (execute is 1).
- `bl` - List all breakpoints.
- `bc <id|id-id|*>` - Clear one or more breakpoints by ID.
- `bd <id|id-id|*>` - Disable one or more breakpoints by ID.
- `be <id|id-id|*>` - Enable one or more breakpoints by ID.
- `bpc <id> <condition|clear>` - Update or clear a breakpoint condition.
- `bs <id> <commands|clear>` (`bpa`) - Set or clear a breakpoint command action.
- `br <id> <newid>` - Renumber a breakpoint.
- `bpp <id> <passes>` - Reset a breakpoint pass count.

## Processes and threads

- `!process [eprocess|pid|0] [flags] [image-name]` - List or inspect Windows processes; `!process 0 0` lists all, bit 1 adds process detail, bit 2 adds threads, and bit 4 adds each thread's stack.
- `!thread [ethread|tid] [flags] [count]` (`thread`) - Display a Windows thread and optionally its kernel stack; legacy `thread <tid> k|r [count]` forms remain available.
- `!stacks [0|1|2] [filter]` (`stacks`) - Show every thread's state, wait reason, and top stack symbol.
- `!running [-i] [-t]` (`running`) - Show the thread running on each processor.
- `!ready [processor]` (`ready`) - List bounded dispatcher-ready queues, optionally for one processor.
- `!dpcs` (`dpcs`) - List deferred procedure calls queued on each processor.
- `!timer [address-expression]` (`timer`) - List kernel timers or decode one `_KTIMER`.
- `!apc [process|thread]` (`apc`) - List kernel and user APCs for the selected thread, process, or all threads.
- `threads [filter]` - List Windows threads, optionally filtered by process, PID, TID, or ETHREAD.
- `ps [filter]` - List running processes.
- `lm [m <pattern>] [v] [u|k] [t]` - List loaded modules.
- `drivers [filter]` - List driver objects from the `\\Driver` object directory.
- `attach <pid>` - Attach to a process by PID.
- `detach` - Detach from the current process.

## CPU

- `!pcr [processor]` (`pcr`) - Display the selected processor's KPCR essentials.
- `!prcb [processor]` (`prcb`) - Display the selected processor's KPRCB essentials.
- `!irql [processor]` (`irql`) - Display the current IRQL for a processor.
- `!idt [vector]` (`idt`) - Decode one IDT entry or the bounded 256-entry IDT (AMD64 only).
- `!gdt` (`gdt`) - Decode the current processor's bounded GDT (AMD64 only).
- `rdmsr [/p <processor>] <msr>` - Read a model-specific register from a halted processor.
- `wrmsr <msr> <value>` - Write a model-specific register on the current processor.
- `!cpuinfo` (`cpuinfo`) - Display vendor, family, model, stepping, speed, and feature bits.

## Memory manager

- `!vm [flags]` (`vm`) - Display system memory, pool, PTE, page-file, and process usage; flag `1` omits per-process rows.
- `!pfn <pfn> | !pfn -a <physical-address>` (`pfn`) - Decode an `_MMPFN` entry; a bare argument is always a page frame number.
- `!vtop <directory-base> <virtual-address>` (`vtop`) - Translate a virtual address with an explicit directory base.
- `!ptov <physical-address>` (`ptov`) - Find current-directory-base virtual mappings of a physical address (AMD64 only).
- `!pool <address-expression>` (`pool`) - Inspect the pool page containing an address.
- `!poolused [flags] [tag]` (`poolused`) - Aggregate pool tracker usage by tag across every processor's tag table; flags `2`/`4` sort by nonpaged/paged bytes, `1` adds alloc/free counts; `tag` is case-sensitive and accepts `*`/`?`.
- `!poolfind <tag> [0|1]` (`poolfind`) - Find pool blocks with a matching tag.
- `!lookaside [address]` (`lookaside`) - List or decode GENERAL_LOOKASIDE caches.
- `!pte <address>` (`pte`) - Display page table entries for an address.
- `!memusage [process-limit]` - Show bounded system and per-process memory-use counters.

## Objects and I/O

- `!object <object-expression>` (`object`) - Inspect an executive object header and body.
- `!drvobj <driver-object-expression-or-name>` (`drvobj`) - Inspect a DRIVER_OBJECT, its device chain, and dispatch table.
- `!devobj <device-object-expression>` (`devobj`) - Inspect a DEVICE_OBJECT and its attached stack.
- `!irp <address-expression>` (`irp`) - Inspect an IRP and its current IO_STACK_LOCATION.
- `irps [process-filter|driver-filter]` - Discover in-flight IRPs from thread IrpLists and device CurrentIrp.
- `!handle [handle-expression]` - List bounded handles for the selected process, or inspect one handle.
- `!fileobj <address-expression>` - Decode a FILE_OBJECT and its device/name relationships.
- `!locks [resource-address-expression]` - Inspect one ERESOURCE, or enumerate the symbol-backed resource list.
- `callbacks [symbol-filter]` - Enumerate process, thread, and image notification callbacks.
- `ssdt` - Dump the SSDT and shadow SSDT.

## User mode

- `!peb [address]` (`peb`) - Decode the attached process environment block and its loader list.
- `!teb [address]` (`teb`) - Decode a thread environment block.
- `!dlls [-c <address>]` (`dlls`) - List modules from the attached process loader lists.
- `!gle` (`gle`) - Display the current thread's last Win32 and NT status values.
- `!vad [pid|eprocess]` (`vmmap`) - Display a process's VAD tree; defaults to the selected process context. `vmmap [address|filter]` is the flat region view.
- `!chkimg [-d] [-v] [-nospec] <module>` (`chkimg`) - Compare executable module sections with the cached on-disk image after relocation. Known kernel self-patches (import optimization, retpoline, `KiPatchSelf` retargets) are counted separately; `-nospec` drops them from the report.

## Security

- `!sd <address> [1]` (`sd`) - Decode a SECURITY_DESCRIPTOR and its ACLs.
- `!acl <address>` (`acl`) - Decode an ACL and its ACEs.
- `!sid <address>` (`sid`) - Decode a SID in guest memory.
- `!objsd <object>` (`objsd`) - Decode the security descriptor referenced by an object header.
- `!token` - Inspect the selected or current process primary token.
- `!session [-s <id>]` (`session`) - List sessions and the processes grouped into each session.
- `!sprocess [session] [flags] [image]` (`sprocess`) - List processes in a session; `session` is decimal, `-1` = current, `-4` = all; non-zero flags select the detailed form; `image` is a glob filter.

## Analysis

- `!analyze [-v] [-show <bugcheck-code> [p1 p2 p3 p4]] [-hang]` (`analyze`) - Short crash verdict (bugcheck line, failure signature, culprit, verifier/WHEA findings, relevant modules); `-v` adds the full bugcheck arguments, faulting context, stack, and every module; `-show` decodes a bugcheck code without a crash; `-hang` triages per-processor waits.
- `!error <code>` (`!ntstatus`) - Decode an NTSTATUS, Win32, or HRESULT error code.
- `vertarget` (`version`) - Display target, kernel, symbol, processor, and debugger version information.
- `.time` - Display target UTC time and system uptime.
- `.lastevent` - Show the most recently observed target event.
- `sxe [-c <commands>] [-f <break|gh|gn>] <exception-code|alias>` - Break when an exception occurs.
- `sxd [-c <commands>] [-f <break|gh|gn>] <exception-code|alias>` - Pass first-chance exceptions and break on second chance.
- `sxn [-c <commands>] [-f <break|gh|gn>] <exception-code|alias>` - Notify and pass exceptions without breaking.
- `sxi [-c <commands>] [-f <break|gh|gn>] <exception-code|alias>` - Pass exceptions without breaking or notification.
- `sx or sxl` - List configured exception policies.
- `sxr` - Reset exception policies to default break behavior.

## Session

- `.hh [command]` (`help`, `.help`) - List commands or display detailed help for one command.
- `.echo <text>` (`echo`) - Print text without expression interpretation.
- `.printf "format" [arguments...]` - Format debugger values using WinDbg-style printf specifiers.
- `.cls` - Clear the terminal screen when stdout is a terminal.
- `.logopen <file>` - Start a debugger transcript, replacing any existing file.
- `.logappend <file>` - Start a debugger transcript, appending to the file.
- `.logclose` - Close the debugger transcript.
- `n [8|10|16]` - Display or set the default numeric radix for REPL expressions.
- `aliases` - List command aliases.
- `alias <name> <expansion>` - Define a command alias.
- `unalias <name>` - Remove a command alias.
- `reload-scripts` - Reload custom commands and aliases.
- `.dump [/f] [/ma] <file>` (`dump`) - Write a full PAGEDU64 kernel dump from the halted target.
- `dbgprint [count]` - Show captured guest debug output (DbgPrint).
- `capabilities` - Display backend capabilities.
- `status` - Display current VM status.
- `q` (`quit`) - Exit the application.

Aliases use `alias <name> <expansion>`. `${1}` is the first argument passed to the alias, `${2}` is the second, and `${*}` expands to all alias arguments separated by spaces. Alias expansions can contain command lists separated by semicolons.

```text
alias ubp bp ${1}; g
alias pe dt _EPROCESS poi(nt!PsInitialSystemProcess) ${1}
unalias ubp
```

Aliases are saved in `~/.ntoseye/aliases`; `reload-scripts` reloads aliases and custom Python commands.
