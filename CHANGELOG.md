# Changelog

What changed in each release of ntoseye, newest first. The command-line tool, the Python package on PyPI, and the Rust crate on crates.io share one version number.

<!--
Keeping this file:

- Add a line under "## Unreleased" in the commit that makes the change users will notice: a new command, option or SDK API, changed behavior or output, a fixed bug, a removal. Refactors, tests, CI and docs rewording get none. Start the section at the top if it is not there.
- Group the lines under "### Added", "### Changed", "### Fixed" and "### Removed", in that order, leaving out empty groups. A fix to something not yet released is no "Fixed" line; amend the line that added it. A change that breaks scripts starts with "**Breaking:**" and comes first in its group.
- A release with a theme opens with one or two sentences before the groups, saying what users can now do. A release without one goes straight to the groups.
- Say what users can now do, or what went wrong and no longer does, not how. Name commands and SDK APIs in backticks as users type them.
- Link only with absolute https://ntoseye.com/... URLs. The same text is shown in the GitHub release, in this file on GitHub, and on the docs site, which each resolve a relative link differently.
- To release, rename "## Unreleased" to "## vX.Y.Z (YYYY-MM-DD)", the version in Cargo.toml. The release workflow refuses a tag whose version has no section here, or an empty one; dist publishes the section as the release notes, under the tag as the release title.
-->

## Unreleased

### Added

- `--sympath-append <directory>` adds a directory of local PDBs to the symbol path from the start, such as a driver's build output. ntoseye finds a PDB there both as a plain file and in symbol-store layout, and you can give the option more than once.

### Fixed

- `bp`, `bu` and `g <address>` refuse an address inside an instruction, where the breakpoint corrupted the instruction and could crash the guest, and name the instruction that the address is inside. Where ntoseye cannot check an address, such as code with nothing near it that says where instructions start, they set the breakpoint and warn. `/a` skips the check for `bp` and `bu`. See [where a code breakpoint can go](https://ntoseye.com/using/breakpoints/#where-a-code-breakpoint-can-go).
- `bp <file>:<line>` sets a source breakpoint, as `bu` does. It used to fail with an expression error.
- `--pdb-server` given both before and after a subcommand, as in `ntoseye --pdb-server <a> mcp --pdb-server <b>`, now uses every server. It used to keep only the servers after the subcommand.
- With the `gdb` backend, a breakpoint hit that ntoseye passes over by itself, such as another process's under `/p`, a pass count or a false condition, no longer leaves the guest halted between MCP calls, SDK calls or DAP requests, and a stop between calls shows in the status at once. Before, the guest stayed frozen at the hit until the next command that waited, while the status said it was running.

## v0.47.0 (2026-10-07)

ntoseye now draws its REPL natively in Tern, Stencil's terminal (experimental).

### Added

- In Tern, Stencil's terminal, the REPL draws its results natively (experimental): a stop is a card that names why it stopped in a chip and holds the thread, the registers folded, the code at the stop and the stack, and a bugcheck and `!analyze` are red cards; `.trap` is a card with its registers and the kind of entry that built it; `k`, `lm`, `!process`, `ps`, `bl`, `~`, `x`, `!vad`, `vmmap`, `!pte`, `vars` and the memory dumps (`db`, `dd`, `dq`, `dqs`, …) are tables; `.help <command>` is a card; `dt`, `wt` and `!hvpartitions` are trees that fold; `r`, `u` and `uf` use Tern's colors; `ls`, `lsa` and a stop at a source line show the source highlighted with its line marked; and a timer shows how long `g` has run, and long tasks such as downloading and indexing symbols and `.dump` show a progress bar. The prompt is Tern's own input field: Tab's completions narrow in a popup as you type, the line is colored as it is typed, Ctrl+Z undoes, and a paste becomes one line of commands. Alt+P opens a palette that searches the commands and recent lines, the symbols, the types and the processes, Ctrl+R opens it on the earlier lines, and it puts the choice in the prompt. Other terminals, captured output and `.logopen` transcripts keep the text, `TERN_TSP=0` turns it off, and a Tern too old to draw the views gets text with a warning saying so ([details](https://ntoseye.com/using/repl/#in-tern)).
- After a stop on the same thread as the one before, the stop display marks the registers that changed since: yellow in the register grid, and in Tern the folded registers name them (`registers rsp rip changed`) and show their values in amber.
- `display <expression>` shows the expression's value at the end of every stop, marked when it changed since the last stop, as gdb's `display` does; `display` alone lists the displays and `undisplay` removes them. In Tern they are a table in the stop card.
- In Tern (experimental), `browse` or F2 at the prompt opens a full-screen code and memory browser. It pages through disassembly, and through memory as a hex view with a byte cursor, bytes colored by kind and an inspector beside it of the values at the cursor, or as pointers with their symbols. Enter follows branches, `[rip+…]` operands and pointers and Backspace goes back, `g` goes to an expression with completions, `/` finds text, bytes or a pointer, and `b` sets or clears breakpoints in code, only where decoding from the function's start confirms an instruction begins, and write watchpoints in memory.

### Fixed

- When its terminal goes away (a closed pane or a dropped ssh session), the REPL now removes its breakpoints, leaves the guest running and exits, as `q` does. It used to spin a CPU core at its prompt and keep the guest halted under the debugger until it was killed.

## v0.46.0 (2026-10-05)

ntoseye can now debug inside a Windows Sandbox or Hyper-V VM on Intel hosts, not only read it: break on the guest's code and data, step its threads, and change its memory and registers.

### Added

- Breakpoints and steps in a Windows Sandbox or Hyper-V VM (experimental, gdb backend): `ba` in a `.partition` view sets a hardware breakpoint or data watch that stops only on that guest's VPs, `/c` in the view names one of them, and its `/p`, `/t` and condition read that guest. `g` from the view runs the target, and the hit shows the guest's view on the VP that hit it. `t`, `p` and `gu` there step the guest's thread, and `g <address>` runs to an address in the guest. `eb`, `ed` and the other writes there change the guest's memory, and `r` changes the registers of a VP that a vCPU runs at the stop, such as one that hit a breakpoint. In the SDK, `breakpoints.add(..., hardware=True)`, `step()`, `step_over()`, `step_out()` and `run_to()` after `select_partition()` do the same, and `Breakpoint.partition` names the guest. See https://ntoseye.com/vbs/guest-partitions/#breakpoints-in-a-guest-partition.
- `lm a <address>` shows only the module that contains an address, and finds a kernel module for a kernel address even while a process is selected, as in WinDbg.

### Fixed

- `!dlls`, `lm`, `!vad` and the SDK's `Process.modules` name a user-mode module whose loader entry's name is paged out, instead of showing `<unknown>`: the name comes from the file that the image's VAD maps. On a desktop guest, this was about 8% of the user-mode modules.

## v0.45.0 (2026-10-03)

ntoseye can now debug the Windows hypervisor itself on Intel hosts. It can walk hypervisor partitions and virtual processors, inspect and disassemble guest memory, including WSL2, decode hypercalls and break on them based on the caller, and unwind hypervisor stacks. Kernel module unloads can now stop the debugger too, just like module loads.

### Added

- `sxe`/`sxn`/`sxd`/`sxi` `ud[:<module>]` stop on, report, or ignore kernel module unloads the way `ld` handles loads, with `-c` to run commands at the stop; the stop comes after the driver's unload routine, while the module is still listed with its symbols. The SDK has `Exceptions.module_events` and `Stop.ModuleUnload`; DAP reports the stop reason `module unload`.
- `~` accepts the vCPU id it lists in place of a processor number (`~p01.03s`, `~p01.03k`, `~p01.03r`), ignoring case.
- `Registers.get(name, default=None)` returns a register's value, or `default` when the register file (for example an unwound frame) does not hold it.
- `DisassembledInstruction` has `length`, `mnemonic` and `operands`; each `Operand` describes a register, memory, immediate or branch operand, so scripts no longer need to parse `asm`.
- `!hvpartitions` shows the Windows hypervisor's partitions as a tree with their privileges and each VP's processor, VTL, where it left off and its last exit; `!hvvps` lists a partition's VPs and the processors that run them. `~`, the stop line and the MCP trailer (`runs partition 0x4 VP 2`) name a vCPU that runs a guest partition (Hyper-V VM, WSL2, Sandbox) as `partition 0x4 VP 2`; the SDK's run status has it as `running_vp`. The SDK has `dbg.hypervisor_partitions()` and `VirtualProcessor.processors`. Hypervisor commands need the memory or gdb backend, or kd/kdnet with host memory, and say so otherwise.
- `!hvept <gpa>` (or `-v <address>` for a root virtual address) walks each VTL's extended page tables and shows the host address, access, page size and memory type; `!hveptdiff` lists the guest physical ranges VTL0 and VTL1 map differently. The SDK has `HypervisorVtl.translate()` and `VirtualProcessor.ept_differences()`.
- `!hvvmcs [-msr|-io]` shows every field of a VTL's Enlightened VMCS, the MSRs it intercepts or passes (named, e.g. `IA32_EFER`), and its intercepted I/O ports. The SDK has `HypervisorVtl.vmcs_fields()`, `msr_intercepts()` and `io_intercepts()`.
- `!hvd` reads and `!hvu` disassembles a guest partition's memory, virtual (4-level long-mode guests) or with `-p` physical. Like `!hvept`, `!hveptdiff` and `!hvvmcs`, they default to the VP the current processor runs. The SDK has `HypervisorVtl.read()`, `translate_virtual()` and `disassemble()`.
- `!hvcalls` lists the hypervisor's hypercall table with TLFS names, rep/variable-header flags, input/output sizes and handlers (`-a` includes unimplemented codes); `hv!` now has names for the hypercall handlers and `hv!VmExitEntry`, usable in `k`, `u`, `ln`, `x` and expressions. The SDK has `dbg.hypercalls()`.
- A saved VTL state shows the VM exit's qualification, interruption info and instruction length, and the guest's general-purpose registers recovered from the hypervisor's exit entry code, which `r`, expressions and stacks use. A state that may describe the previous exit is marked "(may be one exit behind)" and is not selected automatically; a hardware breakpoint on `hv!VmExitEntry` stops with a current state. The SDK has `SavedVtlState.general_registers` and `may_be_stale`.
- At a hypervisor stop, the stop header, `~` and `.vtlcxr` name the guest VP the processor serves and decode the hypercall being handled (code, TLFS name, flags); `!hvcall` shows its full input, including XMM fast calls, rep lists and extended GVA flush ranges with their addresses, page counts and page sizes. The hypercall page shows as module `hvcall` (`hvcall!Hypercall`, `hvcall!VtlReturn64`). MCP, DAP thread names and the SDK (`Cpu.serving`, `SavedVtlState.hypercall`) show the same.
- `!hvbp <call> [partition [vp]]` stops on a hypercall only from the given caller; its condition is evaluated on the caller's registers and reads the caller's memory, so `$pqwo(rdx)` tests a slow call's input. The SDK has `Breakpoints.add_hypercall()`, `Breakpoint.hypercall`, and `Cpu.hypercall_caller()`, which gives a `when=` callback the caller's registers, decoded call and memory.
- `!hvexit <reason> [partition [vp]]` stops on a VM exit by its reason (`cpuid`, `rdmsr`, `wrmsr`, `ept_violation`, or the number), only from the given caller; its condition sees the caller's registers at the exit, so `!hvexit wrmsr if @rcx==0x6e0` stops on writes of `IA32_TSC_DEADLINE`. The guest runs far slower while it is set, as every exit is checked, so a guest partition's VPs barely run and a filter on one rarely stops; `!hvbp` stops on their hypercalls. The SDK has `Breakpoints.add_exit()` and `Breakpoint.vm_exit`.
- `!hvr [partition vp [vtl]]` shows the registers of any hypervisor VP, such as a WSL2 VP blocked in `HLT` that no processor runs: those of the vCPU that runs it, of the exit a vCPU handles for it, or that it saved at its last exit. The SDK has `VirtualProcessor.registers()`.
- `.partition <id>` inspects the Windows guest of a hypervisor partition, such as a Windows Sandbox, in place of the target, read-only: `lm`, `!process`, `dt`, `u` and `k` read its kernel with its symbols, and its VPs are the threads. `.partition 1` returns to the target, and a partition that runs no Windows kernel, such as WSL2's, is refused with that reason. The SDK has `Debugger.select_partition()` and `Debugger.partition`; MCP's trailer says which partition is inspected.
- Hypervisor stacks unwind from the hypervisor's own unwind data when a copy of the running `hvix64.exe` is in the symbol cache or a local store (`.fetchimage /f <file>`, `Symbols.import_image()` add one), and otherwise from function prologs, marked `[prolog]`. The few functions whose unwind data leaves out their stack allocation, such as the external-interrupt exit handler from build 22621 on, unwind from their prologs too. The SDK's `Cpu.backtrace()` walks a processor's own stack, the hypervisor's when it is halted there, and with `vtl=` from where a VTL left off as the hypervisor saved it.
- `.vtlcxr 1` selects the state the hypervisor saved for VTL1, so `k`, `r`, `u` and expressions inspect the secure kernel where it left off (read-only); `.vtlcxr` returns to VTL0.
- In DAP, a vCPU halted in the hypervisor shows the hypervisor's own frames first, then a label frame, then the saved VTL state's frames.

### Changed

- **Breaking:** `Exceptions.module_loads` is replaced by `Exceptions.module_events`, which lists the unload filters (`sx* ud`) along with the load filters.
- **Breaking:** MCP's `command` tool no longer takes `format`, and rejects a call that passes it: it returns the REPL's text with its `[target ...]` trailer. For typed results, use the Python SDK.
- The hypervisor image is named `hv` as in WinDbg (`hv+0x…` instead of `hvix64+0x…`), and expressions accept `hv` in the hypervisor's context.
- On the gdb backend, software breakpoints in user space are refused (use `ba e1`); single steps into user space use debug-register sites, while a run to a user-space address (`p` over a call, `gu`) ends with an error. Previously stray `int3`s could be left in shared user code.
- Software breakpoints in the Windows hypervisor's code are refused with a pointer to `ba e1`, instead of left pending forever; NT breakpoints can still be set from the hypervisor's context.
- On the gdb backend, a breakpoint whose condition or filter declines many hits a second slows the target much less: a declined hit no longer rewrites the site journal on disk.
- On the gdb backend under VBS, single steps (`t`, `step()`, and the walks built on them, such as `wt` and `trace_calls`) are about 15% faster and use less host CPU: replies from the stub are read buffered, and a step no longer selects its vCPU again after the vCPU's own stop.
- `u` without an address works as in WinDbg: it starts at the instruction pointer, and continues after the previous `u` until the target runs or another frame, thread, or process is selected.
- `!peb`, `!teb`, `!gle` and `!dlls` no longer need `.process`: without one they decode the current thread's process, as in WinDbg.

### Fixed

- `t` after `~Ns` on kd/kdnet steps processor N instead of leaving it unmoved, and breakpoints on the stopped processor keep hitting afterwards; on ARM64 targets, stepping another processor is refused instead of hanging.
- Ctrl+C, a DAP `pause`/`disconnect`, or a server termination signal now break in on a step that never stops, instead of the session hanging until the transport times out; walks (`ta`, `pa`, `wt`, `step(until=)`) end on the first Ctrl+C.
- A walk (`step(until=)`, `step_over(until=)`, `run_to(step=)`) that its `timeout=` or Ctrl+C cuts short now returns a `Stop.Interrupt`, as `run_to()` and `step_out()` do, instead of a `Stop.Step`. A `Stop.Step` had seemed to say the walk ended on an instruction in NT even when it was broken into in the Windows hypervisor, where the next step was refused.
- Ctrl+C in the REPL now stops the target when a breakpoint whose hits are declined (condition, `/t` filter, other process) fires constantly.
- REPL errors from `g`, `t`, `r`, `~` and `.thread` show their message instead of an internal form such as `DebugInfo("…")`, and `bp` or `ba` on a backend that cannot set them names the backend instead of "the current backend does not support this".
- In DAP, a Debug Console command after one that moved the context (`.thread`, `.cxr`, `!thread`) runs instead of failing with "stale frame id" until the client walks the stack again.
- Code that profile-guided optimization split off from its function, far from every symbol, is named after that function through its chained unwind data (`nt!IopXxxControlFile+0x22bddf`) in stacks, disassembly, `ln` and the SDK's `symbols.nearest()`, instead of `nt+0xb1552f` or "no symbol found".
- `wt`, `p`, `gu` and the SDK's `step_over`/`step_out` no longer follow the wrong thread, wait forever for a thread that exited, or crawl under load on code every thread runs; a walk whose thread exits ends with an error.
- A gdbserver step or continue that cannot start now reports SIGINT, so gdb's `next`/`step` no longer loop.
- On the gdb backend, a `bp` on `nt!DbgLoadImageSymbols` (or the unload functions) now stops when no `sx` filter surfaces the event.
- On the gdb backend, the data address QEMU sends with a vCPU's next stop when that vCPU's watchpoint hit lost the race to another vCPU's stop no longer misclassifies the stop: a stop on an execute breakpoint is no longer mistaken for a plain stop, and a stop on a breakpoint is no longer reported as a data watchpoint's hit.
- On the gdb backend under VBS, a step or a resume from a breakpoint no longer gives up with "letting every vCPU run for 1s did not free it" when it should not. The debugger's own work between the vCPUs' runs counted against that second, and the first time a session finds a vCPU in the Windows hypervisor that work takes over half a second. And a vCPU waiting in an interrupt handler failed the step whenever the last run caught the handler in a call into the hypervisor, such as a spin loop's long-wait notification; the step now ends in the handler, as it does when the last run finds the handler in NT.
- On the gdb backend under VBS, a data watchpoint's hit that another vCPU makes while a step or a resume from a breakpoint lets the other vCPUs run is no longer lost: a step ends on it (`step()` returns that stop), and a resume reports it as its stop.
- On the gdb backend under VBS, a step or a resume from a breakpoint that waits on the other vCPUs no longer lets them run only a few milliseconds at a time when one of them is stopped on a breakpoint: that vCPU ended every run at once, and is now held for every other run.
- On the gdb backend under VBS, a step no longer ends in a guest partition's code (WSL2, a Hyper-V VM) when the Windows hypervisor runs that partition's VP on the stepped vCPU's processor while NT waits there, after which the next step failed with "Bad virtual address". The step waits for NT to run there again, and a step of a vCPU that runs a guest partition's VP is refused, naming the VP.
- `Breakpoint.delete()` no longer raises for a breakpoint that is already gone (such as a fired one-shot), and a stale handle no longer deletes a newer breakpoint that reuses its id.
- `.thread` on a thread whose vCPU is in the hypervisor selects where NT left off instead of the hypervisor's registers.
- `.vtl 0` after `.vtl 1` at a hypervisor stop returns to the stop's view instead of the hypervisor's registers.
- VTL1's saved state is listed even before the secure kernel was looked up.
- A saved VTL state is no longer reported as current after the processor has switched to another VTL or VP.
- `k` at a hypervisor stop no longer repeats addresses or lists NT addresses as hypervisor frames; scan frames are always marked `[scan]`.
