# Expressions

An expression can mix raw addresses and typed source objects. A symbol gives an address, a register gives its value, and a bare module name gives the base address of the module, for example `? nt` or `u nt+0x1000`.

The WinDbg memory operators read a fixed width and do not apply a source type:

- `by` reads one byte.
- `wo` reads two bytes.
- `dwo` reads four bytes.
- `poi` and `qwo` read eight bytes.

The forms with the `$p` prefix, `$pby`, `$pwo`, `$pdwo`, `$pqwo`, and `$ppoi`, read the same widths from physical memory.

```text
ev @rip
ev poi(nt!PsInitialSystemProcess)
ev dwo(nt!KdDebuggerEnabled)
ev $pdwo(0x1000)
ev ((_EPROCESS*)poi(nt!PsInitialSystemProcess))->UniqueProcessId
```

In the condition of a hypercall breakpoint ({command}`!hvbp`), these operators read the memory of the hypercall's caller: the `$p` forms its guest physical memory, and the others its virtual memory ([hypercall breakpoints](../using/breakpoints.md#hypercall-breakpoints)).

The {command}`?` command prints a raw expression as a 16-digit address. For a typed expression, it prints the type and the value that {command}`dt` and the editor show, such as `ULONG 0x1a` or `_DEVICE_TYPE 0n34 ( FILE_DEVICE_DISK )`. An aggregate has no numeric value, so {command}`?` shows its location and the command that expands it.

## Numbers and radix

The REPL uses the WinDbg default radix, hexadecimal, so a bare `1000` is `0x1000`. `n 10` sets the session default to decimal, `n 8` to octal, and `n 16` to hexadecimal. A prefix on a number overrides the session radix for that number.

| Spelling | Radix |
| --- | --- |
| `0x1000`, `4ab3h` | hexadecimal |
| `0n10` | decimal |
| `0t17` | octal |
| `0y1010` (also `0b1010` in the decimal and octal radixes) | binary |

A prefix with no digits has the value zero, so `0x` is `0`.

As in WinDbg, `0b` is not a prefix in the hexadecimal radix. For example, `0b1010` is `0xb1010`, and `eb @rsp 0a 0b` writes `0x0b`.

The first character of a token sets how `ntoseye` reads it. A token that starts with a digit is always a number in the current radix. A token that starts with `a`-`f` is first read as a name, and is read as a hexadecimal number only if no symbol matches. If an address must be a number and nothing else, use `0x...`.

`ntoseye` also accepts the WinDbg separated addresses, for example ``fffff803`1a2b3c4d``, and always reads them as hexadecimal, in all session radixes.

Process selectors read bare digits as decimal PIDs, the same format that process listings and completion use. These commands take a process selector:

- {command}`attach`
- {command}`.process`
- {command}`!process`
- {command}`!vad`
- `bp /p`

For example, `attach 3888` selects PID 3888. If no PID matches, `ntoseye` evaluates the selector as an expression. An explicit radix prefix always has priority.

## Operators

The operators follow MASM, and where WinDbg has two spellings for an operator, both are available. The list gives the precedence levels, from level 1, which binds most tightly, to level 12, which binds most loosely.

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

`&&` and `||` short-circuit. `=` and `==` both test equality, so use `r rax=1` to set a register.

You cannot chain comparisons, so write `a < b && b < c` instead of `a < b < c`.

Arithmetic and comparisons are unsigned `u64` operations. The only exception is `>>>`, the MASM arithmetic shift, which copies the sign bit into the new high bits. Narrow scalar reads are zero-extended, and a signed source variable does not make `<` a signed comparison. `+` and `-` always use byte offsets, also on typed pointers, but typed `[]` indexing scales the index by the element size.

The evaluator has these functions:

- `$vvalid(address, length)` tests if a range is readable.
- `$iment(base)` gives the PE entry point of an image.
- `$scmp`, `$sicmp`, and `$spat` compare two quoted strings, or match them with wildcards.

`@@masm( ... )` selects this evaluator explicitly. `ntoseye` does not accept `@@c++( ... )` or `@@( ... )`, because the WinDbg C++ evaluator scales pointer arithmetic and this evaluator does not.

## Registers and pseudo-registers

Write a register as `@rax` or as a bare `rax`. If a source local or a module symbol has the same name, that name hides the bare register name. Subregisters such as `@eax` and `@ah` are also available.

Write a pseudo-register as `$name` or in the WinDbg form `@$name`. These pseudo-registers are available:

- `$ip`, `$scopeip`, `$ra`, `$csp`, `$retreg`, `$proc`, `$thread`, `$teb`, `$tid`, `$tpid`, `$frame`, `$ptrsize`, `$pagesize`, `$exp`, `$exr_code`, `$peb`, and `$exentry`
- `$bug_code` and `$bug_param1`-`$bug_param4`
- the twenty user slots `$t0`-`$t19`
- the pseudo-registers that only `ntoseye` has: `$dtb`, `$ntbase`, and the result slots `$0`-`$N`

{command}`vars` shows the items that are available now. If a Windows thread is selected, it also shows the available thread pseudo-registers, which are `$thread`, `$ethread`, `$kthread`, `$tid`, `$pid`, `$proc`, `$process`, `$eprocess`, `$teb`, `$threadstart`, `$startaddress`, `$win32start`, `$win32startaddress`, `$kernelstack`, `$stackbase`, `$stacklimit`, `$trapframe`, `$priority`, `$basepriority`, `$waitirql`, `$stackresident`, and `$kernelstackresident`.

`$ra` is the caller of the current scope, which `ntoseye` finds with one unwind step, so `g @$ra` runs to the return address. After `.frame 2`, `? $ra` shows frame 3.

`$bug_code` and `$bug_param1`-`$bug_param4` read `nt!KiBugCheckData`, the same array that {command}`!analyze` decodes. Their value is zero until the target has a bugcheck.

`$exr_code` is the exception code in the exception record of the current stop, which {command}`.lastevent` shows. A pause stop or a step stop has no exception record, so `$exr_code` is not available after such a stop.

`$peb` is the user-mode PEB of the process context, which `ntoseye` reads from the `_EPROCESS` of that process. A stop in the System context has no PEB, so the expression gives an error and does not return zero.

`$exentry` is the PE entry point of the image that the process context runs. `$iment` gives the same value for the base of that image.

`ntoseye` does not accept these WinDbg spellings:

| Not accepted | Use instead |
| --- | --- |
| `$bp0` | {command}`bl`, because the host keeps the breakpoint state. |
| a bare `.` for `$ip` | `$ip`, because the `.` character is the member operator. |
| `@@c++( ... )`, `@@( ... )` | `@@masm( ... )` |

`$ea`, `$ea2`, and `$fnsucc` are not available. `ntoseye` does not record the effective addresses of the last instruction, and `$fnsucc` needs the PDB return type of a function to evaluate a return value.

## Symbol names

A symbol name can be module-qualified, for example `nt!KeBugCheck`, can have C++ members, for example `ST_STORE<SM_TRAITS>::StStart` or `MyClass__Member`, or can be a bare name.

`ntoseye` does not accept the WinDbg bare `!name` qualifier, because `!` is the negation operator here. For `!name`, it shows a message about the ambiguity with the two possible corrections: `not name` to negate the value, or `module!name` to get the symbol.

A `<...>` template list is part of a name only if `::` follows its closing `>`, so `index < 0n10` stays a comparison.

## Types and members

Typed member access and typed element access give values, not field addresses. Use `->` on a typed pointer, `.` on a struct or union, and `&` to get the storage address of an object.

An explicit pointer cast gives a layout to a raw address. Because postfix operations bind more tightly than casts and unary operators, put the cast in parentheses before the member access.

`poi` reads a raw pointer-sized value, and `*` on a typed pointer reads the object that the pointer points to. A scalar cast truncates a value to the width of the cast type.

```text
ev ((_IRP*)@rcx)->IoStatus.Status
ev &((_IRP*)@rcx)->IoStatus.Status
dd &((_IRP*)@rcx)->IoStatus.Status L1
ev ((dword*)@rax)[0n3]
```

{command}`dt` gets the type from its first argument, so its address expression does not need a cast.

```text
dt _EPROCESS poi(nt!PsInitialSystemProcess) UniqueProcessId
```

## Locals

With private PDBs, you can use the local variables and parameters of the selected frame or of the current stopped frame.

`ntoseye` reads a scalar local at its declared width, whether the local is in memory or in a recovered register. A pointer local gives the pointer value, not the address of its stack slot.

```text
ev index
ev Irp->IoStatus.Status != 0
.printf "index=%u status=%x" index Irp->IoStatus.Status
```

`&index` gives the storage address of a local in memory, and gives an error for a local in a register.

You can get the members of a struct and the elements of an array, and expand them in the editor, but structs and arrays have no numeric value. To examine their storage, give `&object` to {command}`dt`.

If a local is optimized out, has an unsupported type, or cannot be read, `ntoseye` gives an error and does not use a symbol address as a fallback. If an expression in {command}`.printf` has an error, `ntoseye` shows the error and does not print the specifier without a substitution.

`ntoseye` first looks for an unqualified name as a local or parameter in the selected frame, and a local or parameter has priority over symbols, numbers, registers, pseudo-variables, and module bases. To select a different meaning, use `module!index`, `@rax`, or `0x...`.

`$!index` must refer to a local, and gives an error if the local is out of scope or the private symbols are missing.
