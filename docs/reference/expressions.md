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

As in WinDbg's C++ expressions, the pseudo-registers that hold the address of a kernel structure are typed pointers: `$proc`, `$process` and `$eprocess` are `nt!_EPROCESS *`, `$thread` and `$ethread` are `nt!_ETHREAD *`, `$kthread` is `nt!_KTHREAD *`, `$teb` is `nt!_TEB *`, and `$peb` is `nt!_PEB *`. So `? @$proc->UniqueProcessId` reads the field, and arithmetic such as `@$proc+0x1d0` still adds bytes.

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

## dx

{command}`dx` evaluates a typed expression and shows its value with its type, then its fields, as WinDbg's `dx` lays them out: the fields in the order the PDB declares them, a bitfield's bits beside its offset, and types in WinDbg's C spelling, such as `unsigned long` and `_DEVICE_OBJECT *`. `-r<depth>` sets how many levels of fields it shows: 1 by default, and `-r0` for the value alone. For a pointer to a structure, it shows the structure's fields. Numbers in a `dx` expression are decimal unless written with `0x`, as in C++. This is the stack location of a mouse read that `!irp` showed in a crash dump:

```text
dx -r1 (*((nt!_IO_STACK_LOCATION *)0xffff9888a0c64cb0))
(*((nt!_IO_STACK_LOCATION *)0xffff9888a0c64cb0))                 [Type: _IO_STACK_LOCATION]
    [+0x000] MajorFunction    : 0x3 [Type: unsigned char]
    [+0x001] MinorFunction    : 0x0 [Type: unsigned char]
    [+0x002] Flags            : 0x0 [Type: unsigned char]
    [+0x003] Control          : 0x1 [Type: unsigned char]
    [+0x008] Parameters       [Type: <unnamed-tag>]
    [+0x028] DeviceObject     : 0xffff9888a0a71060 [Type: _DEVICE_OBJECT *]
    [+0x030] FileObject       : 0xffff9888a3bae6d0 [Type: _FILE_OBJECT *]
    [+0x038] CompletionRoutine : 0x0 : 0x0 [Type: long (__cdecl*)(_DEVICE_OBJECT *,_IRP *,void *)]
    [+0x040] Context          : 0x0 [Type: void *]
```

A field gives its value, and a pseudo-register its typed pointer. As in WinDbg, a pointer to a number shows the number it points to, a `char *` or `wchar_t *` its string, and a function pointer the function, and a cast takes a type as C writes it:

```text
dx ((nt!_EPROCESS*)@$proc)->UniqueProcessId
((nt!_EPROCESS*)@$proc)->UniqueProcessId : 0x8d8 [Type: void *]
dx -r0 @$thread
@$thread                 : 0xffff9888a3f4e080 [Type: _ETHREAD *]
dx (unsigned long *)&((nt!_EPROCESS*)@$proc)->Flags
(unsigned long *)&((nt!_EPROCESS*)@$proc)->Flags                 : 0xffff9888a3f022b4 : 0x144d0c01 [Type: unsigned long *]
    0x144d0c01 [Type: unsigned long]
```

### The debugger data model

`dx` also reads WinDbg's debugger data model: `Debugger.Sessions`, `@$cursession`, `@$curprocess`, and `@$curthread`. A session has `Processes`, indexed by process ID, the Idle process first as in WinDbg. A process has `Name`, `Id`, `Threads`, indexed by thread ID, `Modules`, indexed from 0, `Io.Handles`, indexed by handle, and `KernelObject`. A thread has `Id` and `KernelObject`, and its line says where it is, as WinDbg's does: the instruction a running thread's processor is at, or where a waiting thread's context switch will return. A module has `BaseAddress`, `Name`, and `Size`, and a string has `Length`. `.Count()` counts a collection, and an index is decimal unless written with `0x`, as in C++:

```text
dx @$curprocess
@$curprocess                 : svchost.exe
    KernelObject     [Type: _EPROCESS]
    Name             : svchost.exe
    Id               : 0xcbc
    Threads
    Modules
    Io
dx @$curprocess.Threads.Count()
@$curprocess.Threads.Count() : 0x18
dx -r1 Debugger.Sessions[0].Processes[4].Threads.Take(2)
Debugger.Sessions[0].Processes[4].Threads.Take(2)
    [0xc]            : nt!KiSwapContext+0x76 (fffff806`791064d6)
    [0x10]           : nt!KiSwapContext+0x76 (fffff806`791064d6)
```

`KernelObject` is the typed `_EPROCESS` or `_ETHREAD`, and an expression reads on from it as from any typed value, such as `dx @$curprocess.KernelObject.UniqueProcessId`. `-r2` and deeper expand the objects under the first level, a `KernelObject` into its fields.

A handle has `Handle`, `Type`, `GrantedAccess`, and `Object`, its `_OBJECT_HEADER`. After the header's fields come, as in WinDbg, a named object's `ObjectName`, its `ObjectType`, and `UnderlyingObject`, the object as its type, such as a `_FILE_OBJECT` for a file or an `_EPROCESS` for a process. This is a handle of lsass.exe in a kernel dump:

```text
dx -r1 @$cursession.Processes.Where(p => p.Name == "lsass.exe").First().Io.Handles.Where(h => h.Type == "Event").First()
@$cursession.Processes.Where(p => p.Name == "lsass.exe").First().Io.Handles.Where(h => h.Type == "Event").First()
    Handle           : 0x4
    Type             : Event
    GrantedAccess    : 0x1f0003
    Object           [Type: _OBJECT_HEADER]
```

Where `ntoseye` differs from WinDbg: `GrantedAccess` is the access mask in hex, where WinDbg names the rights (`Delete | ReadControl | ... | QueryState | ModifyState`); a process's `Modules` are its own user-mode modules, and the kernel's only for a process that has none (System, Idle, vmmem), where WinDbg lists the kernel's for every process; and a process or thread has no `Index`, `Handle`, `Environment`, `Devices`, `Stack`, or `Registers`.

### Queries

A collection takes WinDbg's LINQ queries, each with a lambda (`p => ...`) where it needs one: `Where`, `Select`, `SelectMany`, `First`, `Last`, `Any`, `All`, `Count`, `OrderBy`, `OrderByDescending`, `Take`, and `Skip`. `new { Name = p.Name, PID = p.Id }` makes an object with those fields, each named as WinDbg requires. Strings compare with `==` and `<` (a string is never equal to a number), join with `+`, and have `Contains`, `StartsWith`, `EndsWith`, `ToLower`, `ToUpper`, and `Length`. A lambda's typed values, such as a `KernelObject`'s fields, work with C++'s operators and casts, and a typed pointer's fields read with `.` as with `->`. Integers take the types WinDbg's `dx` gives them: a literal is an `int`, or an `__int64` when it does not fit one, an unsigned operand makes the result unsigned, and an unsigned result shows in hex, a signed one in decimal. As in WinDbg, the elements keep their keys through `Where`, `Select`, `OrderBy`, `Take`, and `Skip`, and `SelectMany` numbers them from 0:

```text
dx -r2 @$cursession.Processes.Select(p => new {Name = p.Name, PID = p.Id, SignatureLevel = p.KernelObject.SignatureLevel & 0xF}).OrderBy(p => p.SignatureLevel).Take(2)
@$cursession.Processes.Select(p => new {Name = p.Name, PID = p.Id, SignatureLevel = p.KernelObject.SignatureLevel & 0xF}).OrderBy(p => p.SignatureLevel).Take(2)
    [0x0]
        Name             : Idle
        PID              : 0x0
        SignatureLevel   : 0x0
    [0x84]
        Name             : Secure System
        PID              : 0x84
        SignatureLevel   : 0x0
dx Debugger.Sessions[0].Processes.Where(p => p.Name == "explorer.exe").First().Io.Handles.Where(h => h.Type == "File").Select(h => h.Object.UnderlyingObject.FileName).Take(3)
Debugger.Sessions[0].Processes.Where(p => p.Name == "explorer.exe").First().Io.Handles.Where(h => h.Type == "File").Select(h => h.Object.UnderlyingObject.FileName).Take(3)
    [0x54]           : "\Windows\System32" [Type: _UNICODE_STRING]
    [0x14c]          : "" [Type: _UNICODE_STRING]
    [0x1c0]          : "\Windows\en-US\explorer.exe.mui" [Type: _UNICODE_STRING]
```

A query reads a property of each element, not of the collection, as in WinDbg: `.Where(...).First().KernelObject` reads the first match's, and `.Select(p => p.KernelObject)` each one's. `GroupBy`, `Distinct`, aggregates such as `Sum`, functions of your own, and JavaScript are not supported, and `dx` names the queries it has.

`Debugger.Utility.Collections.FromListEntry(head, "nt!_EPROCESS", "ActiveProcessLinks")` walks the `_LIST_ENTRY` list at `head` and gives each record on it as the type named, whose field the link is, so a query runs over any kernel list:

```text
dx -r2 Debugger.Utility.Collections.FromListEntry(*(nt!_LIST_ENTRY*)&nt!PsActiveProcessHead, "nt!_EPROCESS", "ActiveProcessLinks").Select(p => new {Name = (char*)p.ImageFileName, Pid = p.UniqueProcessId}).Take(2)
Debugger.Utility.Collections.FromListEntry(*(nt!_LIST_ENTRY*)&nt!PsActiveProcessHead, "nt!_EPROCESS", "ActiveProcessLinks").Select(p => new {Name = (char*)p.ImageFileName, Pid = p.UniqueProcessId}).Take(2)
    [0x0]
        Name             : 0xffffd48c4a6be378 : "System" [Type: char *]
        Pid              : 0x4 [Type: void *]
    [0x1]
        Name             : 0xffffd48c4a7aa378 : "Secure System" [Type: char *]
        Pid              : 0x84 [Type: void *]
```

`dx -g` shows a collection as a grid, a row for each element and a column for each of its fields, framed as WinDbg's console frames it:

```text
dx -g Debugger.Sessions[0].Processes.Where(p => p.Name == "explorer.exe").First().Io.Handles.Select(h => new { Type = h.Type, Name = h.Object.ObjectName }).Where(o => o.Name != "").Take(4)
===============================================================
=           = Type         = Name                             =
===============================================================
= [0x48]    - Directory    - KnownDlls                        =
= [0x68]    - Mutant       - SM0:5164:304:WilStaging_02       =
= [0x6c]    - Directory    - BaseNamedObjects                 =
= [0x70]    - Semaphore    - SM0:5164:304:WilStaging_02_p0    =
===============================================================
```

As in WinDbg, `dx` lists the first 100 elements of a collection and then `[...]`. A format after the expression changes that: `, <count>` lists that many, and `, d` shows the data model's integers and keys in decimal:

```text
dx -r1 @$cursession.Processes.Take(3), d
@$cursession.Processes.Take(3), d
    [0]              : Idle
    [4]              : System
    [132]            : Secure System
```

`ntoseye` does not have WinDbg's NatVis views, which summarize some types on their line (`Driver "\Driver\mouclass"` for a `_DRIVER_OBJECT`, `{134357425713268397}` for a `_LARGE_INTEGER`) and replace some expansions with their own lists: `dx` shows the type's fields, as WinDbg's `dx -nv` does. A `_UNICODE_STRING` still reads as its text.

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
