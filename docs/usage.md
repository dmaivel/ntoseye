# REPL usage

Command names follow WinDbg. The first name is canonical, and friendly aliases (`ps`, `threads`, `vcpu`, `vmmap`, `attach`, `si`, `ni`, and `finish`) still work.

## Expressions

Expressions combine raw addresses with typed source objects. Symbols evaluate to addresses, registers to values, and a bare module name to its base address (`? nt`, `u nt+0x1000`).

WinDbg's memory operators read a fixed width and apply no source type. `by` reads one byte, `wo` two, `dwo` four, and `poi` or `qwo` eight. The `$p`-prefixed forms (`$pby`, `$pwo`, `$pdwo`, `$pqwo`, `$ppoi`) read the same widths from physical memory.

```text
ev @rip
ev poi(nt!PsInitialSystemProcess)
ev dwo(nt!KdDebuggerEnabled)
ev $pdwo(0x1000)
ev ((_EPROCESS*)poi(nt!PsInitialSystemProcess))->UniqueProcessId
```

`?` prints a raw expression as a 16-digit address, and a typed expression as its type with the value that `dt` and the editor show (`ULONG 0x1a`, `_DEVICE_TYPE 0n34 ( FILE_DEVICE_DISK )`). An aggregate has no numeric value, so `?` reports where it lives and the command that expands it.

### Numbers and radix

The REPL follows WinDbg's hexadecimal default radix, so a bare `1000` is `0x1000`. `n 10` switches the session default, and `n 8` and `n 16` select octal and hexadecimal. Per-number prefixes override the session radix.

| Spelling | Radix |
| --- | --- |
| `0x1000`, `4ab3h` | hexadecimal |
| `0n10` | decimal |
| `0t17` | octal |
| `0y1010`, `0b1010` | binary |

A prefix with no digits reads as zero, so `0x` is `0`. A token beginning with `a`-`f` is a name first and falls back to hexadecimal only when no symbol matches it, while a token beginning with a digit is always a number in the current radix. Use `0x...` when an address must be unambiguously numeric. WinDbg's separated addresses (``fffff803`1a2b3c4d``) are accepted and always read as hexadecimal, whatever the session radix.

Process selectors (`attach`, `.process`, `!process`, `!vad`, and `bp /p`) interpret bare digits as decimal PIDs, matching process listings and completion. `attach 3888` selects PID 3888. If no PID matches, the selector is evaluated as an expression. Explicit radix prefixes always take precedence.

### Operators

Operators follow MASM, in both spellings where WinDbg has two. The levels below run from tightest binding to loosest.

1. postfix `.`, `->`, `[]`
2. prefix `+ - ~ ! not hi low` and casts
3. `* / mod %`
4. `+ -`
5. `<< >> >>>`
6. `< <= > >=`
7. `= == !=`
8. `and &`
9. `xor ^`
10. `or |`
11. `&&`
12. `||`

`&&` and `||` short-circuit. `=` and `==` both test equality; assign registers with `r rax=1`. Comparisons cannot chain: write `a < b && b < c`, not `a < b < c`.

Arithmetic and comparisons are unsigned `u64` operations. The one exception is `>>>`, MASM's arithmetic shift, which propagates the sign bit. Narrow scalar reads are zero-extended, and a signed source variable does not make `<` a signed comparison. `+` and `-` always use byte offsets, even on typed pointers, while typed `[]` indexing scales by the element size.

`$vvalid(address, length)` tests whether a range reads, `$iment(base)` returns an image's PE entry point, and `$scmp`/`$sicmp`/`$spat` compare or wildcard-match two quoted strings. `@@masm( ... )` names this evaluator explicitly. `@@c++( ... )` and `@@( ... )` are rejected, since WinDbg's C++ evaluator scales pointer arithmetic and this one does not.

### Registers and pseudo-registers

Registers take `@rax`, or a bare `rax` that a source local or module symbol of the same name shadows, including subregisters like `@eax` and `@ah`. Pseudo-registers take `$name` or WinDbg's `@$name`. The set is `$ip`, `$scopeip`, `$ra`, `$csp`, `$retreg`, `$proc`, `$thread`, `$teb`, `$tid`, `$tpid`, `$frame`, `$ptrsize`, `$pagesize`, `$exp`, `$exr_code`, `$peb`, `$exentry`, `$bug_code` with `$bug_param1`-`$bug_param4`, the twenty user slots `$t0`-`$t19`, and this debugger's own `$dtb`, `$ntbase`, and result slots `$0`-`$N`. `vars` lists what is currently available.

When a Windows thread is selected, `vars` also lists available thread pseudo-registers: `$thread`, `$ethread`, `$kthread`, `$tid`, `$pid`, `$proc`, `$process`, `$eprocess`, `$teb`, `$threadstart`, `$startaddress`, `$win32start`, `$win32startaddress`, `$kernelstack`, `$stackbase`, `$stacklimit`, `$trapframe`, `$priority`, `$basepriority`, `$waitirql`, `$stackresident`, and `$kernelstackresident`.

`$ra` is the caller of the current scope, recovered with one unwind step, so `g @$ra` runs to the return address, and `.frame 2` followed by `? $ra` names frame 3.

`$bug_code` and `$bug_param1`-`$bug_param4` read `nt!KiBugCheckData` and stay zero until the target bugchecks. `!analyze` decodes the same array. `$exr_code` is the exception code of the current stop's record (`.lastevent`), and a pause or step stop carries no exception record, which leaves it absent.

`$peb` is the process context's user-mode PEB, read from its `_EPROCESS`. A System-context stop has none, and the expression says so rather than returning zero. `$exentry` is the PE entry point of the image that context is running, the same value `$iment` gives for its base.

Unsupported WinDbg spellings and their replacements:

| Refused | Use instead |
| --- | --- |
| `$bp0` | `bl`, since breakpoint state belongs to the host |
| a bare `.` for `$ip` | `$ip`, since `.` is the member operator |
| `@@c++( ... )`, `@@( ... )` | `@@masm( ... )` |

`$ea`/`$ea2` and `$fnsucc` are absent. The effective addresses of the last instruction are not tracked, and `$fnsucc` needs a function's PDB return type to judge a return value.

### Symbol names

A symbol name may be module-qualified (`nt!KeBugCheck`), carry C++ members (`ST_STORE<SM_TRAITS>::StStart`, `MyClass__Member`), or be bare. WinDbg's bare `!name` qualifier is not accepted, because `!` negates here, so `!name` reports the ambiguity and names both fixes (`not name` to negate, `module!name` for the symbol). A `<...>` template list is part of a name only when its closing `>` is followed by `::`, so `index < 0n10` remains a comparison.

### Types and members

Typed member and element access produces values, not field addresses. Use `->` on a typed pointer, `.` on a struct or union, and `&` for an object's storage address. Explicit pointer casts introduce a layout for raw addresses, and the cast has to be grouped before the member access.

```text
ev ((_IRP*)@rcx)->IoStatus.Status
ev &((_IRP*)@rcx)->IoStatus.Status
dd &((_IRP*)@rcx)->IoStatus.Status L1
ev ((dword*)@rax)[0n3]
```

`dt` gets the type from its first argument, so its address expression needs no cast.

```text
dt _EPROCESS poi(nt!PsInitialSystemProcess) UniqueProcessId
```

### Locals

With private PDBs, local variables and parameters are available in the selected frame, or in the current stopped frame. Scalar locals are read at their declared width, whether stored in memory or in a recovered register. A pointer local evaluates to the pointer value, not to its stack-slot address.

```text
ev index
ev Irp->IoStatus.Status != 0
.printf "index=%u status=%x" index Irp->IoStatus.Status
```

`&index` gives the storage address of a local held in memory and fails for one held in a register. Structs and arrays project into members and elements, or expand in the editor, but have no numeric value, so pass `&object` to `dt` to inspect their storage. An optimized-out local, an unsupported type, or an unreadable value reports an error rather than falling back to a symbol address. Expression errors in `.printf` are reported instead of echoing an unsubstituted specifier.

Unqualified names resolve to a local or parameter in the selected frame before symbols, numbers, registers, pseudo-variables, or module bases. Use `module!index`, `@rax`, or `0x...` to select another interpretation. `$!index` requires a local and fails if it is out of scope or private symbols are missing.

### Migrating from the old cast syntax

Earlier releases used `(TYPE)address->field` to compute a field address. Aggregate address casts are gone, and a scalar cast now truncates a value to the requested width instead of annotating an address.

| Old | New |
| --- | --- |
| `(TYPE)address->field` | `&((TYPE*)address)->field` for the address, `((TYPE*)address)->field` for the value |
| `*(dword)address` | `dwo(address)`, or `*((dword*)address)` to keep the type |

`poi` remains a raw pointer-sized read, and `*` on a typed pointer accesses its pointee. Pointer casts have to be grouped before member or element access, because postfix operations bind more tightly than casts and unary operators.

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

- `r [register[=expression]]` (`registers`) - Display CPU registers or assign one register. A 128-bit register (`xmm0`, ARM64 `v0`) displays at full width; assign its 64-bit halves (`xmm0l`/`xmm0h`, `v0l`/`v0h`).
- `kn|k|kb|kp|kv [count]` - Display a stack; `kp` adds PDB parameter locations and `kv` adds provenance.
- `.frame [/r] [N]` (`frame`) - Select or display a zero-based stack frame; `/r` also displays recovered registers.
- `.cxr [address]` - Select a CONTEXT record, or reset the selected context.
- `.ecxr` - Select the current exception context.
- `.exr <address|-1>` - Display an `EXCEPTION_RECORD64`.
- `.trap [address-expression]` (`trap`) - Decode and display a `_KTRAP_FRAME`, defaulting to the current thread's saved frame. A trap frame names no process, so a user-mode frame resolves in the selected process; `.trap` warns when its address lies outside every module there. Select the owning thread or process first (`.thread`, `.process /p`).
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
- `ds <address>` - Display an ANSI_STRING descriptor and its buffer (32-bit layout under `.effmach x86`).
- `dS <address>` - Display a UNICODE_STRING descriptor and its buffer (32-bit layout under `.effmach x86`).

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
- `.pagein [/p <pid|eprocess>] <address>` - Make a paged-out address resident through the guest's debugger worker; `/p` attaches the worker to a process first, which user-space addresses need. The guest does the work, so the target resumes and comes back halted at `nt!DbgBreakPointWithStatus` rather than where it was.

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

`dt -l`, `!list -t`, and `dl` all treat the address you give them as the first element, like WinDbg, so the walk emits every node up to the return to that address. `dl` follows `Blink` instead with `-b`. A list head and a record link are indistinguishable in memory, so starting at a list head (rather than `poi(ListHead)`) prints the head as one pseudo-record instead of dropping a real record; an empty list, whose link points at itself, prints nothing. The walks keep whatever they collected and report null links, cycles, unreadable links, and reaching the entry bound; `dl` reaching its requested count is not reported. Scheduler queue walks use the same termination policy.

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
- `ls [.] [first][,count]` - List source lines of the current scope's file (the file `$scopeip` maps to, found through `.srcpath`). A bare `ls` continues after the previous `ls`/`lsa`; `.` restarts at the current line; `count` defaults to 10.
- `lsa [address][,first][,count]` - List source lines around an address (default `$scopeip`): `first` is an offset from the address's line (default -5), `count` defaults to 12, and the line at the address is marked `>`.
- `dv [address]` - Display procedure locals and parameters at an address.
- `.reload [module]` - Reload symbols for one module or every module in the current scope.
- `ld <module>` - Force symbol source selection and indexing for one module.
- `lmv [module]` - Display detailed per-module symbol status and PDB identity.
- `.fetchimage <module>` - Download a loaded module's PE file into the symbol cache and print its path. The file is looked up by the TimeDateStamp and SizeOfImage in the module's mapped header, so it is the build that is running; open it in a disassembler to get a database that rebases onto the live module.

Symbol queries also support `^` prefix, `$` suffix, `'` exact, `!` negation, and space-separated AND operators.

## Breakpoints and watchpoints

The shared breakpoint grammar follows WinDbg. Code breakpoints use `/1` (one-shot), `/p <pid>` (process scope), `/t <ethread>` (thread scope), `/c <processor>` (processor scope), and `/w "<expr>"` (conditional shorthand), followed by a target, optional pass count, `if <expr>`, and `do "<commands>"`; `ba` uses the same options except `/w` and adds `<access><size>`. `/c` has no WinDbg equivalent.

Conditions use the normal expression grammar. Comparisons, bitwise operations, and short-circuiting `!`, `&&`, and `||` can be combined with parentheses. Write ranges explicitly (`0 < @rax && @rax < 0n10`) rather than as chained comparisons; chained equality (`a == b == c`) is refused for the same reason and names `&&` as the fix. Multi-command actions must be quoted, like WinDbg, and a trailing `gc` continues after the action.

```text
bp nt!KeBugCheckEx @rcx == 0x50 && (@rdx & 0xff) != 0
bu /1 /p 1234 mydriver!DriverEntry
bu mydriver.c:42 10 if @rcx != 0 do "r; gc"
bm mydriver!Dispatch*
ba w8 nt!KiBalanceSetManagerLastCheckTick
```

- `bp [/1] [/p <pid>] [/t <tid|ethread>] [/c <processor>] [/w "<expr>"] <address> [<passes>] [if <expr>] [do "<commands>"]` - Set a breakpoint.
- `bu [/1] [/p <pid>] [/t <tid|ethread>] [/c <processor>] [/w "<expr>"] <symbol> [<passes>] [if <expr>] [do "<commands>"]` - Set a deferred symbolic breakpoint.
- `bm [/1] [/p <pid>] [/t <tid|ethread>] [/c <processor>] [/w "<expr>"] <symbol-pattern> [<passes>] [if <expr>] [do "<commands>"]` - Set deferred symbolic breakpoints for matching symbols.
- `ba [/1] [/p <pid>] [/t <tid|ethread>] [/c <processor>] <access><size> <address> [<passes>] [if <expr>] [do "<commands>"]` - Set a hardware debug-register breakpoint (not available on a dump or the `memory` backend); `e` is execute, `r` is read/write, `w` is write, and sizes are 1, 2, 4, or 8 bytes (execute is 1).
- `bl` - List all breakpoints. The status column reads `e` enabled, `d` disabled, `o` owed.
- `bc <id|id-id|*>` - Clear one or more breakpoints by ID.
- `bd <id|id-id|*>` - Disable one or more breakpoints by ID.
- `be <id|id-id|*>` - Enable one or more breakpoints by ID.
- `bpc <id> <condition|clear>` - Update or clear a breakpoint condition.
- `bs <id> <commands|clear>` (`bpa`) - Set or clear a breakpoint command action.
- `br <id> <newid>` - Renumber a breakpoint.
- `bpp <id> <passes>` - Reset a breakpoint pass count.

A kernel code breakpoint can target a non-resident page. KD records the site and writes the breakpoint when the page arrives. Until then, `bl` shows `o` (owed).

User-space code breakpoints require resident memory. If the page is absent, set the breakpoint after the code has run, or use `ba e1 <address>`, which requires no memory write.

A `ba e1` stop can precede the instruction page fault, leaving no bytes to disassemble. Registers and the stack remain available. Use `t` to execute the fetch and bring the page in; `p` needs to decode the instruction first.

`/p` filters reported hits; it does not change how a breakpoint is installed. Kernel sites are always target-managed. User-space sites are patched through the selected process’s page tables. Shared physical pages can therefore trap other processes too; those hits are discarded but still incur debugger round trips.

`/t` filters the same way, against the Windows thread the stop belongs to. It takes what `!thread` takes: a thread id, an ETHREAD, or a KTHREAD. No target programs a breakpoint per thread. A software site is a byte in a page every thread shares, and a debug register belongs to a processor that any thread may be scheduled on, so every thread executing the site still traps and the debugger discards the hits belonging to other threads. Discarding costs a step-over and a resume per hit, so a filter on a site the whole system calls slows the session down. A hit whose thread cannot be resolved is reported rather than discarded, so a filter never loses a stop silently.

`/c` filters by processor instead, taking the number `~` lists. It is checked against the vCPU the stop was reported on, which costs nothing to know, so unlike `/t` it adds no walk. A processor the guest does not have is rejected when the breakpoint is set, because a filter that can never match is a breakpoint that silently never fires.

KD has a fixed 32-entry software-breakpoint table. A session killed with `SIGKILL` leaves its entries installed and can prevent later breakpoints at those addresses.

Attach reclaims entries that no live session owns, restores displaced instructions, and reports the count. A colliding install also reclaims stale entries and retries. `bc *` only clears the current session’s handles. Normal exit, `SIGTERM`, and `SIGHUP` release them.

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
- `!devstack <device-object|devnode>` (`devstack`) - Display a device stack top-down (`!DevObj`, `!DrvObj`, `!DevExt`, object name) from any device in it or its device node, marking the argument with `>`, then the PDO's device node.
- `!devnode [node|0] [-r]` (`devnode`) - Display a PnP device node (instance path, service, state and state history, flags, problem code, pending IRP); no argument or `0` is the root, `-r` (or WinDbg's trailing `1`) lists the subtree one node per line.
- `!pnptriage` (`pnptriage`) - Walk the device tree and report nodes with a problem code, nodes not started, and nodes with a pending PnP IRP.
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
- `!heap [-s] [-h|-a <heap>] [-x <address>] [-p -a <address>]` (`heap`) - Summarize, walk, or search the attached process's user-mode heaps. NT heaps are decoded through `_HEAP.Encoding`, with legacy-LFH blocks resolved through their user block regions; segment heaps decode VS chunks, LFH blocks, page allocations, and large allocations with the keys in `ntdll!RtlpHpHeapGlobals`. `-a` lists every entry, chunk, and block; `-x` finds the block containing an address. A heap is named by its index in the PEB list or its address. In a WOW64 process the heaps are the 32-bit ones, decoded with `ntdll32`'s layouts and keys.
- `!gle` (`gle`) - Display the current thread's last Win32 and NT status values.
- `!vad [pid|eprocess]` (`vmmap`) - Display a process's VAD tree; defaults to the selected process context. `vmmap [address|filter]` is the flat region view.
- `!chkimg [-d] [-v] [-nospec] <module>` (`chkimg`) - Compare executable module sections with the cached on-disk image after relocation. Known kernel self-patches (import optimization, retpoline, `KiPatchSelf` retargets) are counted separately; `-nospec` drops them from the report.

### WOW64 processes

A 32-bit process on an x64 kernel (`_EPROCESS.WoW64Process` set) is marked `WOW64` by `.process`, in the `Wow64` column of `!process`/`ps`, and by its `Wow64Peb` in process detail. Attaching to one loads both loader lists: the native `ntdll` and `wow64*.dll`, and the 32-bit modules, whose symbols come from their x86 PDBs. The 32-bit ntdll is addressed as `ntdll32` (`x ntdll32!Rtl*`, `bu ntdll32!RtlAllocateHeap`); every other 32-bit module keeps its name. x86 public symbols are shown undecorated (`RtlAllocateHeap`, not `_RtlAllocateHeap@12`).

Types follow the same rule: a bare name resolves the kernel's layout, `ntdll32!_PEB` the 32-bit one, and the nested types of a 32-bit layout stay 32-bit (`dt ntdll32!_LDR_DATA_TABLE_ENTRY <address>` reads 4-byte pointers and `_UNICODE_STRING`s). `!peb` adds the `PEB32` block and its process parameters, `!teb` the `TEB32` behind `WowTebOffset`, `!gle` the 32-bit TEB's last error, and `!heap` walks the 32-bit heaps.

Code in a 32-bit module disassembles as x86 (`u`, `ub`, `uf`, DAP disassembly); `.effmach x86|amd64|.` overrides the choice. `.effmach x86` also makes `ds`/`dS` decode 32-bit string descriptors with the `ntdll32` layout; the SDK's `read_unicode_string`/`read_ansi_string` take `bits=32` for the same. Not supported: walking the x86 user stack. `k` on a WOW64 thread ends at the `wow64cpu` transition frame; the 32-bit frames beyond it are not unwound.

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
- `!verifier [module]` (`verifier`) - Display Driver Verifier's level (decoded options), global statistics, and the verified driver list from `ViTargetDriversAvl` plus configured-but-unloaded drivers from `VfSuspectDriversList`; with a module, that driver's per-driver counters, image, signing level, and load counts.
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
- `.effmach [x86|amd64|auto|.]` - Display or set the effective code machine. `x86` and `amd64` override automatic code-bitness detection; `auto` or `.` clears the override. `x86` also makes `ds`/`dS` read 32-bit (WOW64) string descriptors.
- `aliases` - List command aliases.
- `alias <name> <expansion>` - Define a command alias.
- `unalias <name>` - Remove a command alias.
- `reload-scripts` - Reload custom commands and aliases.
- `.dump [/f] [/ma] <file>` (`dump`) - Write a full PAGEDU64 kernel dump from the halted target.
- `.kdfiles [<map-file>] [-m <target> <host>] [-d <target>] [-c]` - Serve driver images to the target from the host, so a rebuilt driver loads without being copied into the guest. See [the driver replacement map](kdfiles.md).
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
