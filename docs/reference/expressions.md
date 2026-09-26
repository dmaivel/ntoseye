# Expressions

Expressions combine raw addresses with typed source objects. Symbols evaluate to addresses, registers to values, and a bare module name to its base address (`? nt`, `u nt+0x1000`).

WinDbg's memory operators read a fixed width and apply no source type. `by` reads one byte, `wo` two, `dwo` four, and `poi` or `qwo` eight. The `$p`-prefixed forms (`$pby`, `$pwo`, `$pdwo`, `$pqwo`, `$ppoi`) read the same widths from physical memory.

```text
ev @rip
ev poi(nt!PsInitialSystemProcess)
ev dwo(nt!KdDebuggerEnabled)
ev $pdwo(0x1000)
ev ((_EPROCESS*)poi(nt!PsInitialSystemProcess))->UniqueProcessId
```

{command}`?` prints a raw expression as a 16-digit address, and a typed expression as its type with the value that {command}`dt` and the editor show (`ULONG 0x1a`, `_DEVICE_TYPE 0n34 ( FILE_DEVICE_DISK )`). An aggregate has no numeric value, so {command}`?` reports where it lives and the command that expands it.

## Numbers and radix

The REPL follows WinDbg's hexadecimal default radix, so a bare `1000` is `0x1000`. `n 10` switches the session default, and `n 8` and `n 16` select octal and hexadecimal. Per-number prefixes override the session radix.

| Spelling | Radix |
| --- | --- |
| `0x1000`, `4ab3h` | hexadecimal |
| `0n10` | decimal |
| `0t17` | octal |
| `0y1010`, `0b1010` | binary |

A prefix with no digits reads as zero, so `0x` is `0`. A token beginning with `a`-`f` is a name first and falls back to hexadecimal only when no symbol matches it, while a token beginning with a digit is always a number in the current radix. Use `0x...` when an address must be unambiguously numeric. WinDbg's separated addresses (``fffff803`1a2b3c4d``) are accepted and always read as hexadecimal, whatever the session radix.

Process selectors ({command}`attach`, {command}`.process`, {command}`!process`, {command}`!vad`, and `bp /p`) interpret bare digits as decimal PIDs, matching process listings and completion. `attach 3888` selects PID 3888. If no PID matches, the selector is evaluated as an expression. Explicit radix prefixes always take precedence.

## Operators

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

## Registers and pseudo-registers

Registers take `@rax`, or a bare `rax` that a source local or module symbol of the same name shadows, including subregisters like `@eax` and `@ah`. Pseudo-registers take `$name` or WinDbg's `@$name`. The set is `$ip`, `$scopeip`, `$ra`, `$csp`, `$retreg`, `$proc`, `$thread`, `$teb`, `$tid`, `$tpid`, `$frame`, `$ptrsize`, `$pagesize`, `$exp`, `$exr_code`, `$peb`, `$exentry`, `$bug_code` with `$bug_param1`-`$bug_param4`, the twenty user slots `$t0`-`$t19`, and this debugger's own `$dtb`, `$ntbase`, and result slots `$0`-`$N`. {command}`vars` lists what is currently available.

When a Windows thread is selected, {command}`vars` also lists available thread pseudo-registers: `$thread`, `$ethread`, `$kthread`, `$tid`, `$pid`, `$proc`, `$process`, `$eprocess`, `$teb`, `$threadstart`, `$startaddress`, `$win32start`, `$win32startaddress`, `$kernelstack`, `$stackbase`, `$stacklimit`, `$trapframe`, `$priority`, `$basepriority`, `$waitirql`, `$stackresident`, and `$kernelstackresident`.

`$ra` is the caller of the current scope, recovered with one unwind step, so `g @$ra` runs to the return address, and `.frame 2` followed by `? $ra` names frame 3.

`$bug_code` and `$bug_param1`-`$bug_param4` read `nt!KiBugCheckData` and stay zero until the target bugchecks. {command}`!analyze` decodes the same array. `$exr_code` is the exception code of the current stop's record ({command}`.lastevent`), and a pause or step stop carries no exception record, which leaves it absent.

`$peb` is the process context's user-mode PEB, read from its `_EPROCESS`. A System-context stop has none, and the expression says so rather than returning zero. `$exentry` is the PE entry point of the image that context is running, the same value `$iment` gives for its base.

Unsupported WinDbg spellings and their replacements:

| Refused | Use instead |
| --- | --- |
| `$bp0` | {command}`bl`, since breakpoint state belongs to the host |
| a bare `.` for `$ip` | `$ip`, since `.` is the member operator |
| `@@c++( ... )`, `@@( ... )` | `@@masm( ... )` |

`$ea`/`$ea2` and `$fnsucc` are absent. The effective addresses of the last instruction are not tracked, and `$fnsucc` needs a function's PDB return type to judge a return value.

## Symbol names

A symbol name may be module-qualified (`nt!KeBugCheck`), carry C++ members (`ST_STORE<SM_TRAITS>::StStart`, `MyClass__Member`), or be bare. WinDbg's bare `!name` qualifier is not accepted, because `!` negates here, so `!name` reports the ambiguity and names both fixes (`not name` to negate, `module!name` for the symbol). A `<...>` template list is part of a name only when its closing `>` is followed by `::`, so `index < 0n10` remains a comparison.

## Types and members

Typed member and element access produces values, not field addresses. Use `->` on a typed pointer, `.` on a struct or union, and `&` for an object's storage address. Explicit pointer casts introduce a layout for raw addresses, and the cast has to be grouped before the member access, because postfix operations bind more tightly than casts and unary operators. `poi` is a raw pointer-sized read, while `*` on a typed pointer reads its pointee; a scalar cast truncates a value to the requested width.

```text
ev ((_IRP*)@rcx)->IoStatus.Status
ev &((_IRP*)@rcx)->IoStatus.Status
dd &((_IRP*)@rcx)->IoStatus.Status L1
ev ((dword*)@rax)[0n3]
```

{command}`dt` gets the type from its first argument, so its address expression needs no cast.

```text
dt _EPROCESS poi(nt!PsInitialSystemProcess) UniqueProcessId
```

## Locals

With private PDBs, local variables and parameters are available in the selected frame, or in the current stopped frame. Scalar locals are read at their declared width, whether stored in memory or in a recovered register. A pointer local evaluates to the pointer value, not to its stack-slot address.

```text
ev index
ev Irp->IoStatus.Status != 0
.printf "index=%u status=%x" index Irp->IoStatus.Status
```

`&index` gives the storage address of a local held in memory and fails for one held in a register. Structs and arrays project into members and elements, or expand in the editor, but have no numeric value, so pass `&object` to {command}`dt` to inspect their storage. An optimized-out local, an unsupported type, or an unreadable value reports an error rather than falling back to a symbol address. Expression errors in {command}`.printf` are reported instead of echoing an unsubstituted specifier.

Unqualified names resolve to a local or parameter in the selected frame before symbols, numbers, registers, pseudo-variables, or module bases. Use `module!index`, `@rax`, or `0x...` to select another interpretation. `$!index` requires a local and fails if it is out of scope or private symbols are missing.
