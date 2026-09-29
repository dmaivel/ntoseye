# Expressions

An expression can use raw addresses and typed source objects together. Each item in an expression has a value:

- A symbol gives an address.
- A register gives its value.
- A bare module name gives the base address of the module, for example `? nt` or `u nt+0x1000`.

The WinDbg memory operators read a fixed width. They do not apply a source type.

- `by` reads one byte.
- `wo` reads two bytes.
- `dwo` reads four bytes.
- `poi` and `qwo` read eight bytes.

The forms with the `$p` prefix read the same widths from physical memory. These forms are `$pby`, `$pwo`, `$pdwo`, `$pqwo`, and `$ppoi`.

```text
ev @rip
ev poi(nt!PsInitialSystemProcess)
ev dwo(nt!KdDebuggerEnabled)
ev $pdwo(0x1000)
ev ((_EPROCESS*)poi(nt!PsInitialSystemProcess))->UniqueProcessId
```

The {command}`?` command prints a result as follows:

- For a raw expression, it prints a 16-digit address.
- For a typed expression, it prints the type and the value that {command}`dt` and the editor show. Examples are `ULONG 0x1a` and `_DEVICE_TYPE 0n34 ( FILE_DEVICE_DISK )`.
- An aggregate has no numeric value. For an aggregate, {command}`?` shows the location of the aggregate and the command that expands it.

## Numbers and radix

The REPL uses the WinDbg default radix, which is hexadecimal. So a bare `1000` is `0x1000`. `n 10` sets the session default to decimal. `n 8` sets octal, and `n 16` sets hexadecimal. A prefix on a number overrides the session radix for that number.

| Spelling | Radix |
| --- | --- |
| `0x1000`, `4ab3h` | hexadecimal |
| `0n10` | decimal |
| `0t17` | octal |
| `0y1010` (also `0b1010` in the decimal and octal radixes) | binary |

A prefix with no digits has the value zero. For example, `0x` is `0`.

In the hexadecimal radix, `0b` is not a prefix. This is the same as in WinDbg. For example, `0b1010` is `0xb1010`, and `eb @rsp 0a 0b` writes `0x0b`.

The first character of a token sets how `ntoseye` reads the token:

- If a token starts with a digit, it is always a number in the current radix.
- If a token starts with `a`-`f`, `ntoseye` first reads it as a name. If no symbol matches, `ntoseye` reads it as a hexadecimal number.

If an address must be a number and nothing else, use `0x...`.

`ntoseye` also accepts the WinDbg separated addresses, for example ``fffff803`1a2b3c4d``. It always reads these addresses as hexadecimal, in all session radixes.

Process selectors read bare digits as decimal PIDs. Process listings and completion use the same format. These commands use process selectors:

- {command}`attach`
- {command}`.process`
- {command}`!process`
- {command}`!vad`
- `bp /p`

For example, `attach 3888` selects PID 3888. If no PID matches, `ntoseye` evaluates the selector as an expression. An explicit radix prefix always has priority.

## Operators

The operators follow MASM. If WinDbg has two spellings for an operator, both spellings are available. The list shows the precedence levels. Level 1 binds most tightly, and level 12 binds most loosely.

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

`&&` and `||` short-circuit. `=` and `==` both test equality. To set a register, use `r rax=1`.

You cannot chain comparisons. For example, write `a < b && b < c`. Do not write `a < b < c`.

Arithmetic and comparisons are unsigned `u64` operations. The only exception is `>>>`, which is the MASM arithmetic shift. It copies the sign bit into the new high bits. These rules also apply:

- Narrow scalar reads are zero-extended.
- A signed source variable does not make `<` a signed comparison.
- `+` and `-` always use byte offsets, also on typed pointers.
- Typed `[]` indexing scales the index by the element size.

The evaluator has these functions:

- `$vvalid(address, length)` tests if a range is readable.
- `$iment(base)` gives the PE entry point of an image.
- `$scmp`, `$sicmp`, and `$spat` compare two quoted strings, or match them with wildcards.

`@@masm( ... )` selects this evaluator explicitly. `ntoseye` does not accept `@@c++( ... )` and `@@( ... )`. The reason is that the WinDbg C++ evaluator scales pointer arithmetic, and this evaluator does not.

## Registers and pseudo-registers

To use a register, write `@rax` or a bare `rax`. If a source local or a module symbol has the same name, that name hides the bare register name. Subregisters such as `@eax` and `@ah` are also available.

To use a pseudo-register, write `$name` or the WinDbg form `@$name`. These pseudo-registers are available:

- `$ip`, `$scopeip`, `$ra`, `$csp`, `$retreg`, `$proc`, `$thread`, `$teb`, `$tid`, `$tpid`, `$frame`, `$ptrsize`, `$pagesize`, `$exp`, `$exr_code`, `$peb`, and `$exentry`
- `$bug_code` and `$bug_param1`-`$bug_param4`
- the twenty user slots `$t0`-`$t19`
- the pseudo-registers that only `ntoseye` has: `$dtb`, `$ntbase`, and the result slots `$0`-`$N`

{command}`vars` shows the items that are available now.

If a Windows thread is selected, {command}`vars` also shows the available thread pseudo-registers. These are `$thread`, `$ethread`, `$kthread`, `$tid`, `$pid`, `$proc`, `$process`, `$eprocess`, `$teb`, `$threadstart`, `$startaddress`, `$win32start`, `$win32startaddress`, `$kernelstack`, `$stackbase`, `$stacklimit`, `$trapframe`, `$priority`, `$basepriority`, `$waitirql`, `$stackresident`, and `$kernelstackresident`.

`$ra` is the caller of the current scope. `ntoseye` gets it with one unwind step. So `g @$ra` runs to the return address. After `.frame 2`, `? $ra` shows frame 3.

`$bug_code` and `$bug_param1`-`$bug_param4` read `nt!KiBugCheckData`. Their value is zero until the target has a bugcheck. {command}`!analyze` decodes the same array.

`$exr_code` is the exception code in the exception record of the current stop. {command}`.lastevent` shows this stop. A pause stop or a step stop has no exception record. After such a stop, `$exr_code` is not available.

`$peb` is the user-mode PEB of the process context. `ntoseye` reads it from the `_EPROCESS` of that process. A stop in the System context has no PEB. In this case, the expression gives an error and does not return zero.

`$exentry` is the PE entry point of the image that the process context runs. `$iment` gives the same value for the base of that image.

The table shows the WinDbg spellings that `ntoseye` does not accept, and what to use.

| Not accepted | Use instead |
| --- | --- |
| `$bp0` | {command}`bl`. The host keeps the breakpoint state. |
| a bare `.` for `$ip` | `$ip`. The `.` character is the member operator. |
| `@@c++( ... )`, `@@( ... )` | `@@masm( ... )` |

`$ea`, `$ea2`, and `$fnsucc` are not available:

- `ntoseye` does not record the effective addresses of the last instruction.
- `$fnsucc` needs the PDB return type of a function to evaluate a return value.

## Symbol names

A symbol name can have one of these forms:

- A module-qualified name, for example `nt!KeBugCheck`.
- A name with C++ members, for example `ST_STORE<SM_TRAITS>::StStart` or `MyClass__Member`.
- A bare name.

`ntoseye` does not accept the WinDbg bare `!name` qualifier, because `!` is the negation operator here. For `!name`, `ntoseye` shows a message about the ambiguity. The message gives the two possible corrections:

- Use `not name` to negate the value.
- Use `module!name` to get the symbol.

A `<...>` template list is part of a name only if `::` follows its closing `>`. So `index < 0n10` stays a comparison.

## Types and members

Typed member access and typed element access give values. They do not give field addresses. Use these operators:

- `->` on a typed pointer.
- `.` on a struct or union.
- `&` to get the storage address of an object.

An explicit pointer cast gives a layout to a raw address. Put the cast in parentheses before the member access. This is necessary because postfix operations bind more tightly than casts and unary operators.

`poi` reads a raw pointer-sized value. `*` on a typed pointer reads the object that the pointer points to. A scalar cast truncates a value to the width of the cast type.

```text
ev ((_IRP*)@rcx)->IoStatus.Status
ev &((_IRP*)@rcx)->IoStatus.Status
dd &((_IRP*)@rcx)->IoStatus.Status L1
ev ((dword*)@rax)[0n3]
```

{command}`dt` gets the type from its first argument. So its address expression does not need a cast.

```text
dt _EPROCESS poi(nt!PsInitialSystemProcess) UniqueProcessId
```

## Locals

If you have private PDBs, you can use local variables and parameters. They are available in the selected frame, or in the current stopped frame.

`ntoseye` reads a scalar local at its declared width. This rule applies to a local in memory and to a local in a recovered register. A pointer local gives the pointer value. It does not give the address of its stack slot.

```text
ev index
ev Irp->IoStatus.Status != 0
.printf "index=%u status=%x" index Irp->IoStatus.Status
```

`&index` gives the storage address of a local in memory. For a local in a register, `&index` gives an error.

You can get the members of a struct and the elements of an array. You can also expand them in the editor. But structs and arrays have no numeric value. To examine their storage, give `&object` to {command}`dt`.

`ntoseye` gives an error in these cases:

- The local is optimized out.
- The type of the local is not supported.
- The value cannot be read.

In these cases, `ntoseye` does not use a symbol address as a fallback.

If an expression in {command}`.printf` has an error, `ntoseye` shows the error. It does not print the specifier without a substitution.

`ntoseye` first looks for an unqualified name as a local or parameter in the selected frame. A local or parameter has priority over symbols, numbers, registers, pseudo-variables, and module bases. To select a different meaning, use `module!index`, `@rax`, or `0x...`.

`$!index` must refer to a local. It gives an error if the local is out of scope or if the private symbols are missing.
