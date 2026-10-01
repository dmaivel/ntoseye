# Breakpoints and watchpoints

All breakpoint commands share one grammar, which follows WinDbg. A code breakpoint command starts with its options:

- `/1`: one-shot.
- `/p <pid>`: process scope.
- `/t <ethread>`: thread scope.
- `/c <processor>`: processor scope. WinDbg does not have this option.
- `/w "<expr>"`: conditional shorthand.

After the options come a target, an optional pass count, `if <expr>`, and `do "<commands>"`. The {command}`ba` command takes the same options and adds `<access><size>`.

Conditions use the normal expression grammar, so you can combine comparisons, bitwise operations, and the short-circuit operators `!`, `&&`, and `||` with parentheses. Write a range explicitly, for example `0 < @rax && @rax < 0n10`. `ntoseye` gives an error for a chained comparison such as `0 < @rax < 0n10` because it is ambiguous. In C, this expression compares the result of `0 < @rax` (0 or 1) with `0n10` instead of testing a range. Chained equality (`a == b == c`) gives the same error for the same reason, and the error message tells you to use `&&`.

If a breakpoint action has more than one command, put quotes around it, as in WinDbg. `gc` or a plain `g` continues from the breakpoint at any position in the action, including inside a `j` or `.if` branch such as `bp nt!NtClose "j (@rcx == 0) 'kb; g' ; 'g'"`, and the commands after it do not run.

`ntoseye` does not accept other run-control commands in an action:

- `g <address>`
- `p`
- `t`
- `gu`
- `gh`
- `gn`

```text
bp nt!KeBugCheckEx @rcx == 0x50 && (@rdx & 0xff) != 0
bu /1 /p 1234 mydriver!DriverEntry
bu mydriver.c:42 10 if @rcx != 0 do "r; gc"
bm mydriver!Dispatch*
ba w8 nt!KiBalanceSetManagerLastCheckTick
```

A target is a symbol name as the PDB records it, including C++ template arguments and Rust generic arguments, for example `bp mydriver!mydriver::impl$0::tally<u32>` and `bp nt!ST_STORE<SM_TRAITS>::StStart`. Inside the argument list, you can use a space only after a comma.

{command}`bm` sets breakpoints only on code symbols, so it skips any data, such as vtables, that the pattern also matches.

## Breakpoints on non-resident pages

You can set a kernel code breakpoint on a page that is not resident. KD records the site and writes the breakpoint when the page comes into memory, and until then {command}`bl` shows `o` (owed).

A user-space code breakpoint needs resident memory. If the page is not resident, set the breakpoint after the code has run, or use `ba e1 <address>`, which does not write to memory.

A `ba e1` stop can occur before the instruction page fault, when there are no bytes to disassemble but the registers and the stack are still available. Use {command}`t` to execute the fetch and bring the page into memory. {command}`p` cannot do this, because it must decode the instruction first.

## Scope filters

`/p` filters the hits that `ntoseye` reports and does not change how it installs the breakpoint. The target always manages kernel sites, and `ntoseye` patches user-space sites through the page tables of the selected process, so a breakpoint in a shared physical page can also trap other processes. `ntoseye` discards those hits, but each of them still causes debugger round trips.

`/t` is the same kind of filter. It compares the Windows thread of the stop with the thread that you specify, and it takes the same values as {command}`!thread`: a thread ID, an ETHREAD, or a KTHREAD.

No target sets a breakpoint for one thread. A software site is a byte in a page that all threads share, and a debug register belongs to a processor on which Windows can schedule any thread. Every thread that executes the site traps, and `ntoseye` discards the hits of the other threads. Each discarded hit costs a step-over and a resume, so a filter on a site that the whole system calls slows the session down. If `ntoseye` cannot find the thread of a hit, it reports the hit instead of discarding it, so a filter does not hide a stop from you.

{command}`wt` and the SDK's `step_over()`, `step_out()`, and step-until walks wait for their own thread, and they keep this cost down with a free debug register. Such a step watches the thread's `KTHREAD.State` and sets its breakpoints only while Windows is about to run the thread or runs it, so the other threads that run the same code do not stop the target while the thread waits. Without a free slot, the breakpoints stay set for the whole wait.

`/c` filters on the processor. It takes a processor number as {command}`~` shows it, and `ntoseye` compares this number with the vCPU that reported the stop. Because `ntoseye` gets this vCPU at no cost, `/c` does not add a walk the way `/t` does.

If the guest does not have that processor, `ntoseye` gives an error when you set the breakpoint, because the filter can never match and the breakpoint can never stop.

## The KD breakpoint table

KD has a software-breakpoint table with a fixed size of 32 entries. If you kill a session with `SIGKILL`, its entries stay installed and can prevent later breakpoints at the same addresses.

When `ntoseye` attaches, it reclaims the entries that no live session owns, restores the displaced instructions, and reports how many entries it reclaimed. If an install collides with an entry, it also reclaims stale entries and tries the install again. `bc *` clears only the handles of the current session, and a normal exit, `SIGTERM`, or `SIGHUP` releases them.

## Stopping at a driver load

`sxe ld:<module>` stops the target when that kernel image loads, and `sxe ld` without a module name stops the target at every kernel image load.

`ntoseye` matches the module name case-insensitively, with or without its extension, and you can use the wildcards `*` and `?`, for example `sxe ld:mydriver`, `sxe ld:MyDriver.sys`, or `sxe ld:my*`.

At the stop:

- The module is in the module list.
- The symbols of the module are loaded.
- The deferred {command}`bu` breakpoints in the module are armed.
- The `DriverEntry` of the module has not run.

A breakpoint that you set at this stop therefore catches the initialization of the driver. The stop shows the WinDbg line `ModLoad: <base> <end>   <image>` above the usual stop context.

The other load filter commands are:

- `sxn ld[:<module>]` shows the `ModLoad:` line and continues.
- `sxd` and `sxi` let the load continue and show nothing.
- `sxe -c "<commands>" ld:<module>` runs the commands at the stop. The `-f` option does not apply to `ld`.
- {command}`sx` lists the filters.
- {command}`sxr` clears the filters.

A filter with a module name has priority over `ld` without a module name, so `sxe ld` together with `sxi ld:ksecdd` stops at every load except the `ksecdd` load.

```text
sxe ld:mydriver
g
bp mydriver!MyDispatchCreate
g
```

### The load trap on the `gdb` backend

KD and KDNET get a load notification from the target for each load, but a GDB stub does not send load notifications. On the `gdb` backend, `ntoseye` therefore sets its own breakpoint, the load trap, at `nt!DbgLoadImageSymbols`.

The kernel calls `nt!DbgLoadImageSymbols` for each kernel image that it maps, after it adds the image to its list and before the entry point of the image runs. It makes this call even when kernel debugging is not enabled.

The trap is in place only while something waits for a load, which is either an `sxe`/`sxn ld` filter or a breakpoint in a module that has not loaded, such as `bu mydriver!DriverEntry`. `ntoseye` sets the trap when the target resumes and at least one item waits for a load, and it tells you when it does. It removes the trap at the first resume or load after which no item waits, and when it exits. Memory reads do not show the trap.

If a session is killed while the trap is in place, the trap stays in the guest. The rules above keep this time as short as possible, and the [site journal](#the-site-journal) repairs the trap at the next attach.

A GDB stub also does not report a reboot, so the trap does not stay in place across a reboot. `ntoseye` finds the new kernel at the first stop after the new kernel runs, and it does not stop for the loads during boot before that stop. This is expected, and the `gdb` backend does not support stopping at boot-time loads: the trap would have to be planted after the new kernel is in memory and before it loads its boot drivers, and without a reboot notification that is a race with the kernel that `ntoseye` would not win consistently. To debug a boot-start driver, use `kd` or `kdnet`, which report each load during boot.

While the trap is in place, each load briefly halts the target so that `ntoseye` can refresh the module list, after which it resumes the target. If a filter stops at the load, `ntoseye` does not resume the target.

## Stopping at a driver unload

`sxe ud:<module>` stops the target when that kernel image unloads, and `sxe ud` without a module name stops at every unload. Module names match as they do for `ld`. The stop comes after the driver's unload routine has run and before the image leaves the module list, so the module is still listed with its symbols, and the stack shows the unload path (`nt!MiUnloadSystemImage`, called from `nt!IopDeleteDriver`). The stop shows the WinDbg line `Unload module <image> at <base>` above the usual stop context.

`sxn ud[:<module>]` shows that line and continues, `sxd` and `sxi` let the unload continue and show nothing, and `sxe -c "<commands>" ud:<module>` runs the commands at the stop. Load and unload filters are separate, so `sxe ld:mydriver` does not stop at the unload of `mydriver`.

```text
sxe ud:mydriver
g
k
```

On the `gdb` backend, `ntoseye` plants an unload trap the same way as the load trap, at `nt!DbgUnLoadImageSymbols` and `nt!DbgUnLoadImageSymbolsUnicode`, the kernel functions that report an unload. The unload trap is in place only while an `sxe`/`sxn ud` filter is set, and a breakpoint that waits for its module does not keep it.

## User-mode breakpoints in shared pages

The `gdb` backend sets no software breakpoint in user space, whatever the scope. A GDB stub writes and removes the `int3` through the page tables of the vCPU that it has selected, and that vCPU might not map the page, for example a vCPU that is stopped in the Windows hypervisor or that runs a Hyper-V guest. The byte would then stay in shared code after the session, and the next process to run it would trap in the guest. Under VBS, a step or {command}`wt` that goes on into user space marks each next instruction with a free hardware breakpoint slot instead. A step over a call or a {command}`gu` that returns there ends with an error. Use a hardware breakpoint ({command}`ba` `e1`) to stop in user space.

A software breakpoint is an `int3` byte in a physical frame, and all processes that map an image page share that frame. For example, `bu /p <pid> user32!PeekMessageW` puts the byte in the single frame that backs `user32.dll` for the whole machine, so every process that calls that function traps.

The scope is a filter on the host. `ntoseye` compares the process that trapped with the scope of the breakpoint, and if the hit belongs to a different process, it *absorbs* the hit and does not report it. To absorb a hit, `ntoseye` takes four steps:

1. It removes the byte.
2. It single-steps the instruction.
3. It writes the byte back.
4. It resumes the target.

No view shows the injected byte. `ntoseye` hides a site in every read that reaches the frame that contains it, so each process that maps a shared page shows the original instruction. If a process has its own memory at the same address instead of the shared frame, `ntoseye` does not change reads of that memory. Only the debugger views hide the `int3`, and the guest still executes it.

### The site journal

The breakpoint table of the target does not contain these bytes, so before `ntoseye` writes a byte, it records the site in `~/.ntoseye/sites/` together with the frame, the kernel base of the boot, and the original bytes.

When `ntoseye` exits, detaches, or gets a terminating signal, it removes the byte and the record. If a session ends without this cleanup, for example because it is killed or crashes, the byte and the record stay.

The next attach to the same boot writes the original bytes back and shows how many sites it restored. This attach can use the same endpoint or a different one, for example a `kdnet` attach after a `gdb` session was killed.

`ntoseye` restores a site only while the frame still contains the breakpoint followed by the recorded bytes. If the guest has restored or reused the frame since the session ended, `ntoseye` leaves the frame unchanged.

`ntoseye` sets kernel breakpoints through the breakpoint API of the target. The Windows KD breakpoint table keeps its entries after a session ends without cleanup, and the next session releases them, but the breakpoint table of a GDB stub does not always keep its entries. Under VBS, an `int3` that such a session set in kernel code stays after the next connect. On the `gdb` backend, `ntoseye` therefore also records kernel sites in the journal, including the [bugcheck trap](bugchecks.md#how-the-crash-is-caught).

### The cost of an absorb

An absorb halts all vCPUs, so a breakpoint on a shared symbol that the system calls often costs the absorb rate multiplied by the cost of one absorb. This cost applies even when the scoped process does not run.

The table shows measurements on a Windows 11 guest with 4 vCPUs, with the breakpoint on `nt!NtCreateFile` while a file-enumeration loop was running.

| Transport | Host service per absorb | Absorbs/s sustained | Guest speed |
| --- | --- | --- | --- |
| KDCOM (emulated UART) | ~30 ms | 16 | ~5% |
| KDNET | ~1 ms | 125 | ~50% |

Use KDNET for work with many breakpoints. Each absorb takes a few KD request/reply round trips, and over an emulated UART, KDCOM needs about 2 ms for each request, which is the largest part of the cost. On KDNET, the remaining cost is the time that the guest needs to freeze and thaw its own processors, and no change in the debugger can remove it.

You can also reduce the cost in these ways:

- Scope the breakpoint to a symbol that the rest of the system does not call. A breakpoint in the image of the target traps only the processes of that image.
- Use `ba e1`, which needs no byte in the page and so writes nothing to a shared frame. `ntoseye` sets the debug registers on every processor and not for one thread, so `ba e1` still traps in each process that runs the code, and there are only four slots.

A pass count or a condition does not reduce the number of absorbs, because `ntoseye` absorbs each hit that a pass count or a false condition skips. It evaluates the condition at each hit before it resumes the target, so a condition that reads guest memory through KD adds KD requests to every hit.
