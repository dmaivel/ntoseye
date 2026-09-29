# Breakpoints and watchpoints

All breakpoint commands use one grammar, and this grammar follows WinDbg. A code breakpoint command starts with its options:

- `/1`: one-shot.
- `/p <pid>`: process scope.
- `/t <ethread>`: thread scope.
- `/c <processor>`: processor scope. WinDbg does not have this option.
- `/w "<expr>"`: conditional shorthand.

After the options, the command takes a target, an optional pass count, `if <expr>`, and `do "<commands>"`. The {command}`ba` command takes the same options. It also adds `<access><size>`.

Conditions use the normal expression grammar. You can combine comparisons, bitwise operations, and the short-circuit operators `!`, `&&`, and `||` with parentheses. Write a range explicitly, for example `0 < @rax && @rax < 0n10`. Do not write a range as a chained comparison. For the same reason, `ntoseye` gives an error for chained equality (`a == b == c`). The error message tells you to use `&&`.

If a breakpoint action has more than one command, put quotes around it, as in WinDbg. `gc` or a plain `g` continues from the breakpoint at any position in the action. This includes a `j` or `.if` branch, for example `bp nt!NtClose "j (@rcx == 0) 'kb; g' ; 'g'"`. The commands after `gc` or `g` do not run.

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

A target is a symbol name as the PDB records it. The name includes C++ template arguments and Rust generic arguments, for example `bp mydriver!mydriver::impl$0::tally<u32>` and `bp nt!ST_STORE<SM_TRAITS>::StStart`. In the argument list, you can use a space only after a comma.

{command}`bm` sets breakpoints only on code symbols. If the pattern also matches data, such as vtables, `bm` skips the data.

## Breakpoints on non-resident pages

You can set a kernel code breakpoint on a page that is not resident. KD records the site and writes the breakpoint when the page comes into memory. Until then, {command}`bl` shows `o` (owed).

A user-space code breakpoint needs resident memory. If the page is not resident, do one of these steps:

- Set the breakpoint after the code has run.
- Use `ba e1 <address>`. This breakpoint does not write to memory.

A `ba e1` stop can occur before the instruction page fault. In this case, there are no bytes to disassemble. The registers and the stack are still available. Use {command}`t` to execute the fetch and bring the page into memory. {command}`p` must decode the instruction first, so it cannot do this step.

## Scope filters

`/p` is a filter on the hits that `ntoseye` reports. It does not change how `ntoseye` installs the breakpoint:

- The target always manages kernel sites.
- `ntoseye` patches user-space sites through the page tables of the selected process.

So a breakpoint in a shared physical page can also trap other processes. `ntoseye` discards those hits. But each of those hits still causes debugger round trips.

`/t` is a filter of the same type. It compares the Windows thread of the stop with the thread that you specify. It takes the same values as {command}`!thread`:

- A thread ID.
- An ETHREAD.
- A KTHREAD.

No target sets a breakpoint for one thread. There are two reasons:

- A software site is a byte in a page that all threads share.
- A debug register belongs to a processor, and Windows can schedule any thread on that processor.

So each thread that executes the site traps, and `ntoseye` discards the hits of the other threads. Each discarded hit costs a step-over and a resume. So a filter on a site that the whole system calls makes the session slower. If `ntoseye` cannot find the thread of a hit, it reports the hit and does not discard it. So a filter does not hide a stop from you.

`/c` is a filter on the processor. It takes a processor number as {command}`~` shows it. `ntoseye` compares this number with the vCPU that reported the stop. `ntoseye` gets this vCPU at no cost. So unlike `/t`, `/c` does not add a walk.

If the guest does not have the processor, `ntoseye` gives an error when you set the breakpoint. `ntoseye` gives this error because the filter can never match, so the breakpoint can never stop.

## The KD breakpoint table

KD has a software-breakpoint table with a fixed size of 32 entries. If you kill a session with `SIGKILL`, its entries stay installed. These entries can prevent later breakpoints at the same addresses.

When `ntoseye` attaches, it does these steps:

- It reclaims the entries that no live session owns.
- It restores the displaced instructions.
- It reports the number of reclaimed entries.

If an install collides with an entry, `ntoseye` also reclaims stale entries and tries the install again. `bc *` clears only the handles of the current session. A normal exit, `SIGTERM`, and `SIGHUP` release these handles.

## Stopping at a driver load

`sxe ld:<module>` stops the target when that kernel image loads. `sxe ld` without a module name stops the target at each kernel image load.

`ntoseye` matches the module name without case sensitivity. You can write the name with or without its extension. You can use the wildcards `*` and `?`. Examples are `sxe ld:mydriver`, `sxe ld:MyDriver.sys`, and `sxe ld:my*`.

At the stop, these conditions are true:

- The module is in the module list.
- The symbols of the module are loaded.
- The deferred {command}`bu` breakpoints in the module are armed.
- The `DriverEntry` of the module has not run.

So a breakpoint that you set at this stop catches the initialization of the driver. The stop shows the WinDbg line `ModLoad: <base> <end>   <image>` above the usual stop context.

The other load filter commands do these actions:

- `sxn ld[:<module>]` shows the `ModLoad:` line and continues.
- `sxd` and `sxi` let the load continue and show nothing.
- `sxe -c "<commands>" ld:<module>` runs the commands at the stop. The `-f` option does not apply to `ld`.
- {command}`sx` lists the filters.
- {command}`sxr` clears the filters.

A filter with a module name has priority over `ld` without a module name. For example, `sxe ld` together with `sxi ld:ksecdd` stops at each load except the `ksecdd` load. `ntoseye` does not support module unload (`ud`) filters.

```text
sxe ld:mydriver
g
bp mydriver!MyDispatchCreate
g
```

### The load trap on the `gdb` backend

KD and KDNET get a load notification from the target for each load. A GDB stub does not send load notifications. So on the `gdb` backend, `ntoseye` sets its own breakpoint at `nt!DbgLoadImageSymbols`. This breakpoint is the load trap.

The kernel calls `nt!DbgLoadImageSymbols` for each kernel image that it maps. The call occurs after the kernel adds the image to its list and before the entry point of the image runs. The kernel makes this call also when kernel debugging is not enabled.

The trap is in place only while an item waits for a load. These items wait for a load:

- An `sxe`/`sxn ld` filter.
- A breakpoint in a module that has not loaded, for example `bu mydriver!DriverEntry`.

`ntoseye` controls the trap as follows:

- `ntoseye` sets the trap when the target resumes and at least one item waits for a load. `ntoseye` tells you when it sets the trap.
- `ntoseye` removes the trap at the first resume or load after which no item waits.
- `ntoseye` removes the trap when it exits.
- Memory reads do not show the trap.

If a session is killed while the trap is in place, the trap stays in the guest. The rules above keep this time as short as possible. The [site journal](#the-site-journal) repairs the trap at the next attach.

A GDB stub also does not report a reboot. So the trap does not stay in place across a reboot. `ntoseye` finds the new kernel at the first stop after the new kernel runs. `ntoseye` does not stop for the loads during boot before that stop. KD reports each of these loads.

While the trap is in place, each load halts the target for a short time. `ntoseye` refreshes the module list and then resumes the target. If a filter stops at the load, `ntoseye` does not resume the target.

## User-mode breakpoints in shared pages

A software breakpoint is an `int3` byte in a physical frame. All processes that map an image page share that page. For example, `bu /p <pid> user32!PeekMessageW` puts the byte in the single frame that backs `user32.dll` for the whole machine. So each process that calls that function traps.

The scope is a filter on the host. `ntoseye` compares the process that trapped with the scope of the breakpoint. If the hit belongs to a different process, `ntoseye` *absorbs* the hit. To absorb a hit, `ntoseye` does these steps:

1. It removes the byte.
2. It single-steps the instruction.
3. It writes the byte back.
4. It resumes the target.

`ntoseye` does not report an absorbed hit.

No view shows the injected byte. `ntoseye` hides a site in each read that reaches the frame that contains the site. So each process that maps a shared page shows the original instruction. If a process has its own memory at the same address, and not the shared frame, `ntoseye` does not change reads of that memory. Only the debugger views hide the `int3`. The guest still executes it.

### The site journal

The breakpoint table of the target does not contain these bytes. So before `ntoseye` writes a byte, it records the site in `~/.ntoseye/sites/`. The record contains these items:

- The frame.
- The kernel base of the boot.
- The original bytes.

When `ntoseye` exits, detaches, or gets a terminating signal, it removes the byte and the record. A session can end without this cleanup, for example if it is killed or if it crashes. Then the byte and the record stay.

The next attach to the same boot writes the original bytes back. This attach can use the same endpoint or a different endpoint. An example is a `kdnet` attach after a `gdb` session was killed. `ntoseye` shows how many sites it restored.

`ntoseye` restores a site only while the frame still contains the breakpoint followed by the recorded bytes. If the guest has restored or reused the frame after the session ended, `ntoseye` does not change the frame.

`ntoseye` sets kernel breakpoints through the breakpoint API of the target. The Windows KD breakpoint table keeps its entries after a session ends without cleanup, and the next session releases them. The breakpoint table of a GDB stub does not always keep its entries. Under VBS, an `int3` that such a session set in kernel code stays after the next connect. So on the `gdb` backend, `ntoseye` also records kernel sites in the journal. These sites include the [bugcheck trap](bugchecks.md#how-the-crash-is-caught).

### The cost of an absorb

An absorb halts all vCPUs. So a breakpoint on a shared symbol that the system calls frequently has a cost. This cost is the absorb rate multiplied by the cost of one absorb. The cost applies also when the scoped process does not run.

The table shows measurements on a Windows 11 guest with 4 vCPUs. The breakpoint was on `nt!NtCreateFile`, and a file-enumeration loop was running.

| Transport | Host service per absorb | Absorbs/s sustained | Guest speed |
| --- | --- | --- | --- |
| KDCOM (emulated UART) | ~30 ms | 16 | ~5% |
| KDNET | ~1 ms | 125 | ~50% |

Use KDNET for work with many breakpoints. Each absorb is a small number of KD request/reply round trips. Over an emulated UART, KDCOM needs approximately 2 ms for each request. This time is the largest part of the cost. On KDNET, the remaining cost is the time that the guest needs to freeze and thaw its own processors. No change in the debugger can remove this cost.

You can also decrease the cost in these ways:

- Scope the breakpoint to a symbol that the rest of the system does not call. A breakpoint in the image of the target traps only the processes of that image.
- Use `ba e1`. It does not need a byte in the page, so it writes nothing to a shared frame. But here, AMD64 debug registers are per processor. So `ba e1` still traps for each process. Also, there are only four slots.
- Use a cheap condition in place of a pass count. Both absorb hits. But a false condition stops sooner.
