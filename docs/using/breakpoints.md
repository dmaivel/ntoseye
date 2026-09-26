# Breakpoints and watchpoints

The shared breakpoint grammar follows WinDbg. Code breakpoints use `/1` (one-shot), `/p <pid>` (process scope), `/t <ethread>` (thread scope), `/c <processor>` (processor scope), and `/w "<expr>"` (conditional shorthand), followed by a target, optional pass count, `if <expr>`, and `do "<commands>"`; {command}`ba` takes the same options and adds `<access><size>`. `/c` has no WinDbg equivalent.

Conditions use the normal expression grammar. Comparisons, bitwise operations, and short-circuiting `!`, `&&`, and `||` can be combined with parentheses. Write ranges explicitly (`0 < @rax && @rax < 0n10`) rather than as chained comparisons; chained equality (`a == b == c`) is refused for the same reason and names `&&` as the fix. Multi-command actions must be quoted, like WinDbg, and a trailing `gc` continues after the action.

```text
bp nt!KeBugCheckEx @rcx == 0x50 && (@rdx & 0xff) != 0
bu /1 /p 1234 mydriver!DriverEntry
bu mydriver.c:42 10 if @rcx != 0 do "r; gc"
bm mydriver!Dispatch*
ba w8 nt!KiBalanceSetManagerLastCheckTick
```

A kernel code breakpoint can target a non-resident page. KD records the site and writes the breakpoint when the page arrives. Until then, {command}`bl` shows `o` (owed).

User-space code breakpoints require resident memory. If the page is absent, set the breakpoint after the code has run, or use `ba e1 <address>`, which requires no memory write.

A `ba e1` stop can precede the instruction page fault, leaving no bytes to disassemble. Registers and the stack remain available. Use {command}`t` to execute the fetch and bring the page in; {command}`p` needs to decode the instruction first.

`/p` filters reported hits; it does not change how a breakpoint is installed. Kernel sites are always target-managed. User-space sites are patched through the selected process’s page tables. Shared physical pages can therefore trap other processes too; those hits are discarded but still incur debugger round trips.

`/t` filters the same way, against the Windows thread the stop belongs to. It takes what {command}`!thread` takes: a thread id, an ETHREAD, or a KTHREAD. No target programs a breakpoint per thread. A software site is a byte in a page every thread shares, and a debug register belongs to a processor that any thread may be scheduled on, so every thread executing the site still traps and the debugger discards the hits belonging to other threads. Discarding costs a step-over and a resume per hit, so a filter on a site the whole system calls slows the session down. A hit whose thread cannot be resolved is reported rather than discarded, so a filter never loses a stop silently.

`/c` filters by processor instead, taking the number {command}`~` lists. It is checked against the vCPU the stop was reported on, which costs nothing to know, so unlike `/t` it adds no walk. A processor the guest does not have is rejected when the breakpoint is set, because a filter that can never match is a breakpoint that silently never fires.

KD has a fixed 32-entry software-breakpoint table. A session killed with `SIGKILL` leaves its entries installed and can prevent later breakpoints at those addresses.

Attach reclaims entries that no live session owns, restores displaced instructions, and reports the count. A colliding install also reclaims stale entries and retries. `bc *` only clears the current session’s handles. Normal exit, `SIGTERM`, and `SIGHUP` release them.

## User-mode breakpoints in shared pages

A software breakpoint is an `int3` written into a physical frame, and an image page is shared by every process mapping it. `bu /p <pid> user32!PeekMessageW` puts the byte in the single frame backing `user32.dll` for the whole machine, so every process calling that function traps. Scoping is a host-side filter: `ntoseye` compares the trapping process against the breakpoint's scope and *absorbs* a hit belonging to anyone else, removing the byte, single-stepping the instruction, writing the byte back and resuming without reporting anything.

No view shows the injected byte. A site is masked out of any read reaching the frame it was written into, so the original instruction appears under every process mapping a shared page, while a process that merely has its own memory at the same address is left alone. Only the debugger's views hide the `int3`; the guest still executes it.

The target's own breakpoint table knows nothing of these bytes, so `ntoseye` records each one in `~/.ntoseye/sites/` before writing it: the frame, the kernel base of the boot, and the original bytes. Exiting, detaching, or a terminating signal removes the byte and the record. A session that dies without that cleanup (killed, crashed) leaves both behind, and the next attach to the same target in the same boot writes the original bytes back and says how many it restored. It restores a site only while the frame still holds the breakpoint followed by the recorded bytes; a frame the guest has since restored or reused is left alone.

An absorb halts every vCPU, so a breakpoint on a busy shared symbol costs the absorb rate times the absorb cost whether or not the scoped process ever runs. Measured on a 4-vCPU Windows 11 guest, breakpoint on `nt!NtCreateFile`, file-enumeration loop running:

| Transport | Host service per absorb | Absorbs/s sustained | Guest speed |
| --- | --- | --- | --- |
| KDCOM (emulated UART) | ~30 ms | 16 | ~5% |
| KDNET | ~1 ms | 125 | ~50% |

Use KDNET for breakpoint-heavy work. Each absorb is a handful of KD request/reply round trips, and KDCOM's ~2 ms per request over an emulated UART dominates everything else. Over KDNET what remains is the guest freezing and thawing its own processors, which no debugger-side change can remove.

Three other ways to cut the cost: scope to a symbol the rest of the system does not call, since a breakpoint in the target's own image traps only that image's processes; use `ba e1`, which needs no byte in the page and so writes nothing to a shared frame, though AMD64 debug registers are per-processor here so it still traps for every process and there are only four slots; or prefer a cheap condition over a pass count, since both absorb but a false condition stops sooner.
