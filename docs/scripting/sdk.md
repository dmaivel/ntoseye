# Python SDK

The `ntoseye` package gives standalone Python programs access to debugger inspection and run control. The native wheel is self-contained: it does not need a separate installation of `ntoseye`, and it installs the `ntoseye` command itself.

The package includes type stubs that are generated from the extension itself. Editor completion, type checkers, and docstrings describe the API.

## Install

```sh
pip install ntoseye
```

To build and install the extension from a checkout:

```sh
cd python
python3 -m venv .venv
. .venv/bin/activate
pip install maturin
maturin develop --release
```

## Attach and inspect

By default, `attach()` uses the `kd` backend. To use a different one, set `backend` to `kdnet`, `gdb`, `memory`, or `dmp`, whichever applies to your target.

- `connect` gives the transport endpoint, or the dump path.
- The `kdnet` backend needs `key`.
- The `memory` backend is passive and cannot stop or resume the guest. For run control, use `kd` or `gdb`.
- The `dmp` backend reads an offline dump.

```python
import ntoseye

with ntoseye.attach(backend="kd") as dbg:
    proc = dbg.processes[1234]             # Process, keyed by PID
    print(proc.name, hex(proc.eprocess))
    print(proc.memory.read(proc.peb.addr, 16).hex() if proc.peb else "no PEB")
```

When the `with` block ends, or when you call `dbg.close()`, the debugger removes its breakpoints, resumes the guest, and ends the session, which releases the connection and the target's single-instance lock. You can then attach to the target again, but the old debugger and its handles raise `NtoseyeError` if you use them.

A `Debugger` groups its API into namespaces instead of flat `inspect_*` methods.

| Namespace | Contents |
| --- | --- |
| `dbg.memory`, `dbg.physical` | Kernel virtual memory and guest-physical memory |
| `dbg.symbols`, `dbg.types`, `dbg.modules` | Kernel symbols, PDB types, and loaded modules |
| `dbg.processes`, `dbg.threads`, `dbg.cpus` | Processes, threads, and processors, each with a key |
| `dbg.breakpoints`, `dbg.exceptions` | Breakpoint handles and exception policies |
| `dbg.inspect`, `dbg.drivers` | System-wide reports and decoders, and driver objects |
| `dbg.secure_kernel` | The VBS secure kernel and its trustlets (VTL1). Read-only. |

`dbg.processes` is keyed by PID. If no process has that PID, `dbg.processes[pid]` raises `KeyError` and `.get(pid)` returns `None`. `dbg.processes.find(name)` returns a list of the processes whose image name matches exactly, ignoring case.

A process has views that use its own address space:

- `proc.memory`
- `proc.symbols`
- `proc.types`
- `proc.modules`
- `proc.threads`
- `proc.regions`
- `proc.heaps`

Use these views directly, without selecting or attaching to a global process.

Handles such as `Process`, `Module`, `Thread`, `Frame`, and struct cursors are stamped with the target generation. After a reboot (`Stop.Reboot`), discard the old handles and query them again, because an old handle raises `ntoseye.StaleHandleError` when you use it. Old handles stay hashable and printable, so a set or dict that holds them continues to work.

If your code caches raw addresses, use `dbg.generation` to detect a rebuild. `Breakpoint` handles are not stamped: breakpoints stay after a reboot, and ntoseye resolves symbolic breakpoints again in the new kernel.

## Memory, symbols, and types

Each memory object uses one specific address space: `dbg.memory` is kernel virtual memory, `proc.memory` is the virtual memory of that process, and `dbg.physical` is physical memory without translation.

```python
kernel_fn = dbg.symbols["nt!KeBugCheckEx"]
proc_module = proc.modules["ntdll"]
print(hex(kernel_fn), proc_module.name, hex(proc_module.base))
print(dbg.memory.read(kernel_fn, 16).hex())
```

To find a type, use `dbg.types[name]` or `proc.types[name]`. `Type.fields` maps names to `Field` layouts in offset order, and for an enum, `Type.values` maps member names to values. `.at(address)` makes a live cursor, and `.read()` returns a snapshot dictionary.

You can get the fields of a cursor as attributes. Pointer fields stay integer addresses, so to dereference a typed pointer, use `follow("Field")`. `address_of("Field")` gives the address of a field (C's `&cursor->Field`) for a watchpoint or a raw read.

`Type.walk(head, "Links")` follows an intrusive `_LIST_ENTRY` list and gives cursors to its records, and `cursor.walk("HeadField", "_RECORD", "Links")` does the same from a cursor.

```python
entry = proc.object                         # live _EPROCESS cursor
print(entry.Pcb.DirectoryTableBase)          # nested typed field access
links = entry["ActiveProcessLinks"]          # works even if a field name collides
params = proc.peb.follow("ProcessParameters") if proc.peb else None
if params is not None:
    print(params.CommandLine)
```

If the value of a PDB enum field is a defined member, the field returns a cached `IntEnum` member, and other values stay plain `int` values.

To read or assign a field with no risk of a name collision, use `cursor["Field"]`, because the usual `cursor.Field` form can find a cursor member first. A `Struct` cursor reads live data and stays tied to its original address space.

`memory.disassemble(address, count)` returns `DisassembledInstruction` records. Besides the text (`asm`), each one has its `length`, its `mnemonic`, and its `operands` in order. An `Operand` has a `kind` (`register`, `memory`, `immediate`, `branch`, or `other`) and the fields for that kind: the register as written and the full register it is part of (`r8d` and `r8`), the base, index, scale, displacement, size, and segment of a memory operand, or the value of an immediate or a branch target. So code that follows instructions does not have to parse `asm`:

```python
for ins in dbg.memory.disassemble(kernel_fn, 8):
    for op in ins.operands:
        if op.kind == "memory" and op.base == "rsp":
            print(hex(ins.ip), ins.mnemonic, op.displacement, op.size)
```

## Secure kernel (VTL1)

:::{important}
VTL1 inspection is experimental. To see what it supports on which guests and hosts, read [VBS and the Windows hypervisor](../platforms/vbs.md).
:::

When VBS runs, `dbg.secure_kernel` is the secure kernel, which ntoseye finds in host memory the first time you use it. This works with the `memory` and `gdb` backends, and with `kd` or `kdnet` when they read host memory. If VBS does not run, or if the backend cannot get to VTL1 memory, `dbg.secure_kernel` raises `NtoseyeError`.

The `memory`, `symbols`, `types`, and `modules` views of the secure kernel use its system address space, in the same way that `proc.memory` uses the address space of a process. `trustlets` lists the processes of the secure kernel. Each trustlet has the same views, bound to its own address space, and its `process` attribute gives its NT side.

```python
sk = dbg.secure_kernel
head = sk.symbols["securekernel!SkpsProcessList"]
print(sk.memory.read_u64(head), [m.name for m in sk.modules])
for trustlet in sk.trustlets:                # LsaIso.exe, trustlet_id 1, ...
    print(trustlet.pid, trustlet.name, trustlet.trustlet_id, hex(trustlet.dtb))
```

These views are read-only, so writes raise `NtoseyeError`, as do operations that read the NT state about an address (`describe`, `page_in`, and `ptov`). A memory view does not have CPU registers, so `sk.eval("@rip")` always raises an error, even at a VTL1 stop.

Secure-kernel symbols resolve in these views and at live VTL1 stops, but not in NT address spaces. The public `securekernel.pdb` has no types, so to use an NT type, write the `nt!` prefix, for example `sk.types["nt!_LIST_ENTRY"]`. ntoseye does not list the user-mode modules of a trustlet.

### Breakpoints in secure-kernel code

With `backend="gdb"` on AMD64 QEMU/KVM, you can stop inside a loaded secure-kernel module with a hardware execution breakpoint, which does not change the code of the module.

```python
dbg.interrupt()
sk = dbg.secure_kernel
address = sk.symbols["securekernel!SkeSelectProcessAddressSpace"]
bp = dbg.breakpoints.add(address, hardware=True)
try:
    stop = dbg.run(timeout=10.0)
    if isinstance(stop, ntoseye.Stop.Breakpoint) and bp in stop.breakpoints:
        print(stop.symbol, stop.cpu.registers["rip"], stop.cpu.registers["cr3"])
        print(dbg.command("k"))
finally:
    dbg.interrupt()
    bp.delete()
```

`stop.cpu.registers` shows the real stopped CPU. At a VTL1 stop it is read-only, and `stop.thread` and `stop.process` are `None` instead of the suspended NT thread and process. `run()` continues normally.

Hardware execution breakpoints support these options:

- Conditions
- `when=`
- Pass counts
- One-shot operation
- Processor filters

They share the hardware slots and resolve only once, and you must make them again after a reboot.

`step()`, `step_over()`, `step_out()`, `run_to()`, and `trace_calls()` work at VTL1 stops. In secure-kernel code, their temporary breakpoints are debug-register breakpoints in free slots, so these functions never patch the code.

ntoseye does not accept NT process and thread filters, software breakpoints, or data watches in secure modules. For more information, see [VTL1 limits and tested configuration](../platforms/vbs.md).

### Saved VTL state

Under VBS, idle vCPUs usually stop in the Windows hypervisor itself. For a vCPU that stopped there, `cpu.saved_vtl` lists the VTL states that the hypervisor saved for its virtual processor, VTL0 first, as the {command}`.vtlcxr` command does.

Each `SavedVtlState` holds this data:

- The location where the VTL stopped: `rip`, `symbol`, and `rsp`.
- The control registers and the segment registers of the VTL.
- The last VM exit of the VTL: `exit_reason` and `exit_reason_name`, and its detail: `exit_qualification`, `exit_interruption_info`, and `exit_instruction_length`, as the Intel SDM defines them.
- `current`, which shows if this is the current VTL: the VTL that the hypervisor was entered from, or is about to enter.
- `host_rip` and `host_rsp`, the hypervisor's VM-exit entry point and the stack it runs on.
- `general_registers`, the guest's RAX to R15 at the last exit (`saved.general_registers.rbx`, or `.to_dict()`), read where the hypervisor's entry code saved them. It is `None` except for the current VTL once the vCPU is past the entry code's stores, and when the entry code cannot be read. A vCPU that stopped on a breakpoint on `host_rip` has not saved them yet, and there they are its own registers. Experimental.
- `may_be_stale`, which is `True` when the vCPU is stopped on `host_rip` other than by a breakpoint there. KVM writes the eVMCS when it enters the hypervisor, and a stop from outside can fall between a VM exit and that entry, so the state may still describe the previous exit. The guest's general-purpose registers are then still in `cpu.registers`. A breakpoint on `host_rip` fires after the write, so its stop shows the current exit.
- `evmcs`, the physical address of the Enlightened VMCS that ntoseye read the state from.

The list needs the `hv-evmcs` enlightenment on the VM, and is empty without it or when the saved state fails validation. For more information, see [where NT left off under the hypervisor](../platforms/vbs.md#where-nt-left-off-under-the-hypervisor).

Because ntoseye unwinds the NT thread on that vCPU from the saved VTL0 state, `backtrace()` walks the NT stack while `cpu.symbol` still gives a location in the hypervisor:

```python
for cpu in dbg.cpus:
    print(cpu.id, cpu.symbol)                  # p01.01 hvix64+0x3a6bde
    for saved in cpu.saved_vtl:
        print("   ", saved.vtl, saved.symbol, saved.exit_reason_name)  # 0 nt!HalProcessorIdle+0xf HLT
    if cpu.thread:
        for frame in cpu.thread.backtrace(limit=5):
            print("   ", frame.symbol)              # nt!HalProcessorIdle+0xf, nt!PpmIdleDefaultExecute+0x2b, ...
```

### Memory of a vCPU

`cpu.memory` reads through the page tables that the vCPU has loaded, whatever their owner. These page tables can be:

- The page tables of the kernel or of a process, as for `dbg.memory` or `proc.memory`.
- A VTL1 root, as for `sk.memory`.
- The address space of the hypervisor, where `hvix64` is mapped, for a vCPU that stopped in the Windows hypervisor.

It uses the root that is loaded when you read `cpu.memory`. A root outside NT and VTL1 is read-only, as VTL1 is: writes, `describe`, `page_in`, and `ptov` raise `NtoseyeError`, and `search` reports its matches as `foreign`.

```python
cpu = next(cpu for cpu in dbg.cpus if cpu.saved_vtl)
hv = cpu.memory                                 # the hypervisor's address space
print(hex(hv.dtb), hv.translate(cpu.rip))
print(hv.disassemble(cpu.rip, 4))
```

## Run control and breakpoints

`run(timeout=None)` resumes the target and waits, and `wait(timeout=None)` waits without resuming it. Both return a `Stop` when ntoseye sees a stop, or `None` when the timeout expires. Timeouts are in seconds, and `None` waits with no time limit.

`cont()` resumes the target without waiting, and `interrupt()` breaks in and returns a `Stop`.

### Steps

`step()`, `step_over()`, `step_out()`, and `run_to()` give synchronous run control:

- `step(until="call")` steps to the next call instruction, and the values `"ret"` and `"branch"` step to the next instruction of that type.
- `run_to(addr, step="over")` single-steps to an address instead of running there.

`step_over()` across a call and `step_out()` stop only when the stepping thread returns, so if that thread waits, the step waits as long.

A step-until walk (`until=` or `run_to(step=)`) also follows the thread that it started in. If an interrupt switches that thread out during a step, the walk waits until the thread executes that instruction at the same call depth, on any vCPU.

These functions, and also `step(until=...)` and `step_over(until=...)`, have a `timeout=` argument in seconds. When the timeout expires, the function interrupts the target at its current location and returns that stop.

`trace_calls()` records the call tree until the current function returns, the same as {command}`wt`.

### Stops

While the target is stopped, its stop stays current until the target moves again. `dbg.stop`, `wait()`, and `interrupt()` all return this stop, and reading it does not consume it.

The stop kinds are `ntoseye.Stop.Breakpoint`, `.Exception`, `.Interrupt`, `.Step`, `.ModuleLoad`, `.ModuleUnload`, `.Bugcheck`, and `.Reboot`. To examine the specific stop, use `isinstance`, which works on Python 3.9 and later. The shared fields include `rip`, `symbol`, `thread`, `process`, `cpu`, and `breakpoints`.

For the other stop kinds, `stop.breakpoints` is empty, so `if bp in stop.breakpoints:` works without checking the stop type first. A crash dump that you open with `backend="dmp"` is stopped at its bugcheck, so its `dbg.stop` is a `Stop.Bugcheck`.

```python
bp = dbg.breakpoints.add("nt!NtCreateFile")
stop = dbg.run(timeout=10.0)
if stop is None:
    print("still running")
elif isinstance(stop, ntoseye.Stop.Breakpoint) and bp in stop.breakpoints:
    print("hit", stop.symbol, stop.thread)
```

### Exceptions and module loads

`dbg.exceptions.set(code, mode)` sets an exception policy, for example `"av"` or `0xC0000005`, or a module filter, as the REPL's {command}`sx` commands do: `"ld"` or `"ld:<module>"` for loads, `"ud"` or `"ud:<module>"` for unloads. `dbg.exceptions.module_events` lists the module filters, each with its `event` (`"ld"` or `"ud"`).

With a `"break"` load filter, the load of a matching kernel module stops the target as `Stop.ModuleLoad`, whose `module` field is the loaded `Module`. The stop occurs before the module's `DriverEntry` runs, and the deferred breakpoints in the module are already armed. A `"break"` unload filter stops as `Stop.ModuleUnload` after the driver's unload routine has run, while the module is still listed.

```python
dbg.exceptions.set("ld:mydriver", "break")
stop = dbg.run()
if isinstance(stop, ntoseye.Stop.ModuleLoad):
    print(stop.module.name, hex(stop.module.base))
    dbg.breakpoints.add("mydriver!MyDispatchCreate")
```

### Breakpoint handles and conditions

`dbg.breakpoints` is a live collection that you can iterate over, keyed by breakpoint ID. A breakpoint handle owns its state: to change it, set `bp.enabled`, `bp.condition`, or `bp.pass_count`, and to remove the breakpoint, call `bp.delete()`.

`add()` accepts a debugger-expression condition with `condition=` or a Python predicate with `when=`:

```python
bp = dbg.breakpoints.add(
    "nt!NtCreateFile",
    when=lambda stop: stop.process is not None and stop.process.pid == 1234,
)
```

A `when` callback runs on the thread that waits in `run()`, `wait()`, `run_to()`, `step()`, `step_over()`, or `step_out()`, and receives the `Stop`.

- If the callback returns false, ntoseye resumes past the hit. For a step or `run_to(step=...)`, the step continues.
- If the callback raises an exception, ntoseye returns the hit and puts the error in `stop.condition_error`.

The callback must not resume or step the target, or add or delete breakpoints, and ntoseye raises an error if it does. If the breakpoint hits when no call waits, the target stays stopped until a later wait.

`command()` keeps the REPL behavior and does not call `when` predicates, so a hit during a command that resumes the target stops the target there.

The `condition=` argument is a debugger expression, not a Python callback. A breakpoint can have a `condition=` or a `when` callback but not both, so assigning to `bp.condition` while a `when` callback is attached raises `ValueError`.

### Threads and Ctrl+C

The session runs on its own thread, and you can use a `Debugger` from any Python thread. The session thread runs the calls one at a time, and calls that wait (`run()`, `wait()`, and a `command()` that resumes the target) release the GIL so that other threads continue to run.

Ctrl+C (`KeyboardInterrupt`) stops a wait, a step, or a trace early, and the call raises `KeyboardInterrupt`. After an interrupted `run()` or `wait()`, the target continues to run until you call `interrupt()`. During a `command()` that resumes the target, Ctrl+C breaks in as in the REPL, and the call then raises `KeyboardInterrupt` with the target stopped.

Between calls, the session thread continues to service the guest. It immediately resumes hits in the wrong process and hits where the `condition=` is false, so the guest does not stay frozen until your next call.

## Commands, errors, and build identity

`dbg.command(line, timeout=None)` runs a REPL command and returns its text output. The REPL state, including aliases, the radix, and `$vars`, stays between calls. If a command resumes the target, `timeout` is the time limit for the stop, which is then available as `dbg.stop`.

For structured results, use the typed SDK methods, for example `dbg.inspect.triage()` instead of parsing the output of `dbg.command("!analyze -v")`.

All SDK exceptions derive from `ntoseye.NtoseyeError`:

- `MemoryAccessError` reports a guest range that is not readable, or only partly readable.
- `TargetRunningError` means that the operation needs a stopped target.
- `SymbolNotFoundError` also derives from `LookupError`.
- `StaleHandleError` identifies a handle from before a reboot.

The SDK raises `ValueError` before it touches the target when an argument is not one of its fixed choices, for example `backend="windbg"` or `until="calls"`, or when a combination of arguments is not valid, for example `backend="kdnet"` without `key`.

Decoded results, for example `dbg.inspect.pci()`, `thread.inspect()`, a `Field`, a `Symbol`, or a `MemoryRegion`, are records with one typed property for each field, so an editor can complete the property names and a type checker finds a misspelled name. [Results](../reference/sdk/index.md#results) lists each property.

A result always has every field of its class. If a field does not apply, its value is `None`, or empty or false where the documentation of the field says so. You can also read a record as a mapping, with `keys()` and `record["field"]`. `to_dict()` returns the same fields that the MCP server reports, and you can call it on a record, a process, a thread, a module, a CPU, a driver, or a breakpoint.

`ntoseye.build` is the commit stamp in the compiled extension: `<commit>`, `<commit>-dirty`, or `unknown`. After you rebuild, compare this value if a long-lived Python interpreter might still have an older native module loaded.

## REPL custom commands

Scripts can also add commands to the REPL that use the same API through a borrowed `Debugger`. For more information, see [custom REPL commands](commands.md).
