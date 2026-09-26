"""
The ntoseye SDK's native module. Import from `ntoseye`, which re-exports
all of it.
"""

from collections.abc import Callable, Sequence
from typing import Any, Final, Literal, final

__version__: Final[str]
"""
The ntoseye release this extension was built as.
"""

build: Final[str]
"""
The git commit this extension was built from (`<commit>`,
`<commit>-dirty`, or `unknown`), to detect a stale extension in a
long-lived interpreter.
"""

@final
class AddressModule:
    """
    Loaded-module context for a structured memory-search hit.
    """
    def __repr__(self, /) -> str: ...
    @property
    def base(self, /) -> int:
        """
        The module's base address.
        """
    @property
    def name(self, /) -> str:
        """
        The module's image name.
        """
    @property
    def offset(self, /) -> int:
        """
        The hit's offset from `base`.
        """
    @property
    def size(self, /) -> int:
        """
        The module's image size.
        """
    def to_dict(self, /) -> dict[str, Any]: ...

class Breakpoint:
    """
    A breakpoint handle. Breakpoints outlive target rebuilds (symbolic ones
    re-resolve after a reboot), so the handle is not generation-stamped; it
    goes invalid only when the breakpoint is deleted.
    """
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    @property
    def action(self, /) -> str |None:
        """
        Optional command action (`do` in WinDbg).
        """
    @property
    def address(self, /) -> int:
        """
        Address of the latest resolution.
        """
    @property
    def condition(self, /) -> str |None:
        """
        Optional expression condition.
        """
    @condition.setter
    def condition(self, /, condition: str |None) -> None:
        """
        Assigning an expression while a `when=` callback is attached raises
        `ValueError`, as passing both to `add()` does.
        """
    def delete(self, /) -> None:
        """
        Remove this breakpoint.
        """
    @property
    def enabled(self, /) -> bool:
        """
        Whether this breakpoint is enabled.
        """
    @enabled.setter
    def enabled(self, /, enabled: bool) -> None: ...
    @property
    def hit_count(self, /) -> int:
        """
        Number of physical hits.
        """
    @property
    def id(self, /) -> int:
        """
        Stable breakpoint id.
        """
    @property
    def one_shot(self, /) -> bool:
        """
        Whether the breakpoint is removed after its first surfaced hit.
        """
    @one_shot.setter
    def one_shot(self, /, one_shot: bool) -> None: ...
    @property
    def pass_count(self, /) -> int:
        """
        Requested hit count before surfacing.
        """
    @pass_count.setter
    def pass_count(self, /, pass_count: int) -> None: ...
    @property
    def process(self, /) -> Process |None:
        """
        Process restriction, if the breakpoint is process-scoped.
        """
    @property
    def processor(self, /) -> int |None:
        """
        Processor filter, if any.
        """
    @property
    def remaining_pass_count(self, /) -> int:
        """
        Hits remaining before this breakpoint surfaces.
        """
    @property
    def resolved(self, /) -> bool:
        """
        Whether the site is armed at an address. A symbolic breakpoint whose
        module is not loaded yet stays unresolved until it loads.
        """
    @property
    def specification(self, /) -> str |None:
        """
        Symbol or source identity used to create this breakpoint.
        """
    @property
    def symbol(self, /) -> str |None:
        """
        Resolved display symbol, if known.
        """
    @property
    def temporary(self, /) -> bool:
        """
        Whether this is a temporary run-to breakpoint.
        """
    @property
    def thread(self, /) -> Thread |None:
        """
        Windows thread restriction, if present.
        """
    def to_dict(self, /) -> dict[str, Any]:
        """
        The breakpoint's state as a plain `dict`, the shape MCP renders.
        """
    @property
    def valid(self, /) -> bool:
        """
        Whether the breakpoint is still present in this session.
        """

@final
class BreakpointIterator:
    """
    Iterator over `dbg.breakpoints`.
    """
    def __iter__(self, /) -> BreakpointIterator: ...
    def __next__(self, /) -> Breakpoint: ...

@final
class Breakpoints:
    """
    Code breakpoints and data watchpoints, keyed by id (`dbg.breakpoints`).
    """
    def __contains__(self, id: int, /) -> bool: ...
    def __getitem__(self, id: int, /) -> Breakpoint:
        """
        Look up a breakpoint id, raising `KeyError` when it is absent.
        """
    def __iter__(self, /) -> BreakpointIterator:
        """
        Iterate a fresh snapshot of breakpoint handles.
        """
    def __len__(self, /) -> int:
        """
        Number of live breakpoints.
        """
    def add(self, /, target: int |str, condition: str |None = None, *, hardware: bool = False, when: Callable[[Stop], object] |None = None, pass_count: int = 0, one_shot: bool = False, process: Process |int |None = None, thread: Thread |int |None = None, processor: Cpu |int |None = None, action: str |None = None) -> Breakpoint:
        """
        Add a code breakpoint at an address or symbolic spec.
        
        `hardware=True` arms a debug-register execute breakpoint instead of
        patching code: the target resolves to an address once, now, and the
        site does not re-resolve after a module reload or reboot. It is the
        only kind the secure kernel (VTL1) accepts, e.g.
        `add(dbg.secure_kernel.symbols["securekernel!Func"], hardware=True)`.
        """
    def add_pattern(self, /, pattern: str, condition: str |None = None, *, when: Callable[[Stop], object] |None = None, pass_count: int = 0, one_shot: bool = False, process: Process |int |None = None, thread: Thread |int |None = None, processor: Cpu |int |None = None, action: str |None = None, limit: int = 256) -> list[Breakpoint]:
        """
        Add symbol-identity breakpoints for matching glob names (`bm`).
        """
    def add_source(self, /, file: str, line: int, condition: str |None = None, *, when: Callable[[Stop], object] |None = None, pass_count: int = 0, one_shot: bool = False, process: Process |int |None = None, thread: Thread |int |None = None, processor: Cpu |int |None = None, action: str |None = None) -> list[Breakpoint]:
        """
        Add source breakpoints for every address matching `file:line`.
        """
    def get(self, /, id: int) -> Breakpoint |None:
        """
        Look up a breakpoint id, returning `None` when it is absent.
        """
    def watch(self, /, target: int |str, *, access: Literal["write", "read_write"] = ..., length: int = 1, condition: str |None = None, when: Callable[[Stop], object] |None = None, pass_count: int = 0, one_shot: bool = False, process: Process |int |None = None, thread: Thread |int |None = None, processor: Cpu |int |None = None, action: str |None = None) -> Watchpoint:
        """
        Add a hardware data watchpoint.
        """

@final
class Cpu:
    """
    One processor, identified by its backend vCPU id (such as `"p1.1"`).
    """
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    def gdt(self, /) -> Record:
        """
        Decode this processor's GDT (`!gdt`).
        """
    @property
    def id(self, /) -> str:
        """
        The backend vCPU id.
        """
    def idt(self, /, vector: int |None = None) -> Record:
        """
        Decode one IDT vector, or the bounded full table (`!idt`).
        """
    def info(self, /) -> Record:
        """
        Read processor vendor, family, model, speed, and feature bits (`!cpuinfo`).
        """
    def irql(self, /) -> Record:
        """
        Read this processor's current IRQL (`!irql`).
        """
    @property
    def msr(self, /) -> Msrs:
        """
        Model-specific registers: `cpu.msr[0xC0000082]`, `cpu.msr["IA32_LSTAR"]`.
        """
    def pcr(self, /) -> Record:
        """
        Decode this processor's KPCR and KPRCB essentials (`!pcr`).
        """
    def prcb(self, /) -> Record:
        """
        Decode this processor's `_KPRCB` (`!prcb`).
        """
    @property
    def process(self, /) -> Process |None:
        """
        The process whose page tables are loaded on this processor.
        """
    @property
    def registers(self, /) -> Registers:
        """
        This processor's live register file (writable while halted in NT;
        read-only at a recognized VTL1 stop).
        """
    @property
    def rip(self, /) -> int |None:
        """
        The instruction pointer (needs a halted target).
        """
    @property
    def saved_vtl(self, /) -> list[str]:
        """
        For a vCPU halted in the Windows hypervisor (VBS), where its VTLs
        left off, from the hypervisor's saved state: `["VTL0
        nt!HalProcessorIdle+0xf"]`, plus VTL1 when the hypervisor was entered
        from it or is about to enter it. Needs the VM's `hv-evmcs`; empty
        otherwise, or when the saved state fails validation.
        """
    @property
    def symbol(self, /) -> str |None:
        """
        The symbol at `rip`, if one resolved.
        """
    @property
    def thread(self, /) -> Thread |None:
        """
        The Windows thread running on this processor.
        """
    def to_dict(self, /) -> dict[str, Any]:
        """
        The processor as a plain `dict`, the shape MCP renders.
        """

@final
class CpuIterator:
    """
    Iterator over `dbg.cpus`.
    """
    def __iter__(self, /) -> CpuIterator: ...
    def __next__(self, /) -> Cpu: ...

@final
class Cpus:
    """
    The target's processors, in backend vCPU order (`dbg.cpus`); listing
    them needs a halted target.
    """
    def __getitem__(self, index: int, /) -> Cpu: ...
    def __iter__(self, /) -> CpuIterator: ...
    def __len__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    def get(self, /, index: int) -> Cpu |None: ...

@final
class Debugger:
    """
    A live debugging session. As a context manager, leaving the `with` block
    closes it (`close()`): every breakpoint is removed, the target resumes, and
    the session ends.
    
    Usable from any Python thread: calls are serialized on the session's own
    thread, and a call that waits (`run()`, `wait()`) releases the GIL. Ctrl+C
    (`KeyboardInterrupt`) during a call ends a wait, step, or trace early and
    raises; during a resuming `command()` it breaks in, as in the REPL. Between
    calls the session keeps servicing the guest, resuming wrong-process and
    false-condition breakpoint hits so the guest never sits frozen. A debugger
    handed to a REPL custom command is valid only on the REPL's thread, for
    that command.
    """
    def __enter__(self, /) -> Debugger: ...
    def __exit__(self, /, _exc_type: Any, _exc_value: Any, _traceback: Any) -> bool: ...
    def __repr__(self, /) -> str: ...
    @property
    def breakpoints(self, /) -> Breakpoints:
        """
        Code breakpoints and data watchpoints: `.add(...)`, `.watch(...)`,
        iteration, `[id]`.
        """
    @property
    def capabilities(self, /) -> list[Record]:
        """
        The backend's capability matrix as `{capability, label, supported}`
        records: which operations the transport supports.
        """
    def close(self, /) -> None:
        """
        Remove every breakpoint, leave the target running, and end the
        session: the connection and the target's single-instance lock are
        released, so the target can be attached again, and this debugger and
        its handles raise from then on. Closing again does nothing. On failure
        the target is left halted, the session stays open, and the error is
        raised. A borrowed (REPL command) debugger does not own the session
        and leaves it alone.
        """
    @property
    def coherent(self, /) -> bool:
        """
        False after a reboot until the kernel's module list exists: kernel
        symbols and breakpoints work, process/module enumeration does not yet.
        """
    def command(self, /, line: str, timeout: float |None = None) -> str:
        """
        Run a REPL command line and return its text output (styling stripped).
        Commands that resume the target wait for the next stop, up to
        `timeout` seconds; the stop is then `dbg.stop`.
        """
    def cont(self, /, disposition: Literal["handled", "not_handled"] = ...) -> None:
        """
        Resume without waiting, acknowledging the current exception as
        `handled` or `not_handled` (KD only).
        """
    @property
    def cpus(self, /) -> Cpus:
        """
        The target's processors (vCPUs): `cpus[0].registers.rip`.
        """
    def crash(self, /) -> None:
        """
        Crash the target on purpose (`.crash`), producing a bugcheck stop.
        """
    def debug_log(self, /, since: int = 0) -> Record:
        """
        Captured guest debug output (DbgPrint) since sequence `since`:
        `{lines: [{seq, timestamp_ms, text}], next_seq, dropped}`. Pass the
        previous `next_seq` to poll only new lines.
        """
    @property
    def drivers(self, /) -> Drivers:
        """
        Driver objects from the object manager's `Driver` directory:
        `drivers["Disk"]`, `.at(addr)`.
        """
    def eval(self, /, expr: str) -> int:
        """
        Evaluate a debugger (MASM) expression in kernel scope to an integer;
        registers are the stopped vCPU's.
        """
    @property
    def exceptions(self, /) -> Exceptions:
        """
        Exception stop policies (`sx*`): `.set(code, mode)`, iteration, `.reset()`.
        """
    @property
    def generation(self, /) -> int:
        """
        How many times the guest has been rebuilt (reboots). Handles from an
        older generation raise `StaleHandleError`; cache this beside raw
        addresses to know when they went stale.
        """
    @property
    def inspect(self, /) -> Inspect:
        """
        System-wide reports and decode-by-address helpers (`!vm`, `!pool`, ...).
        """
    def interrupt(self, /) -> Stop:
        """
        Break into the running target and return the resulting stop.
        """
    @property
    def memory(self, /) -> Memory:
        """
        Kernel virtual memory: the kernel's own page tables. User addresses
        are not mapped here; read them through `process.memory`.
        """
    @property
    def modules(self, /) -> Modules:
        """
        Loaded kernel modules: `modules["nt"]`, iteration, `.at(addr)`.
        """
    def notices(self, /) -> list[str]:
        """
        Drain the diagnostics the debugger raised since the last call (a
        breakpoint that failed to re-arm, a reclaimed breakpoint slot, host
        memory that stopped matching after a reload).
        """
    @property
    def physical(self, /) -> Memory:
        """
        Guest-physical memory, untranslated.
        """
    @property
    def processes(self, /) -> Processes:
        """
        Running processes keyed by PID: `processes[4]`, `.find(name)`.
        """
    def reboot(self, /) -> None:
        """
        Reboot the target (`.reboot`). The next stop is a `Stop.Reboot`.
        """
    def reload(self, /) -> None:
        """
        Rebuild guest state now (rediscover the kernel). Stops already do this
        when the backend reports a reload; this forces it.
        """
    def run(self, /, timeout: float |None = None, *, disposition: Literal["handled", "not_handled"] = ...) -> Stop |None:
        """
        Resume and wait for the next stop, auto-resuming past wrong-process and
        false-conditional hits. Returns the `Stop`, or `None` if the target is
        still running after `timeout` seconds.
        """
    def run_to(self, /, target: int |str, timeout: float |None = None, *, step: Literal["over", "into"] |None = None) -> Stop |None:
        """
        Run until `target` (an address, or a symbolic `module!name[+off]`) is
        reached (`g <addr>`), or with `step="over"`/`"into"` single-step there
        (`pa`/`ta`). Other stops en route are returned as they are; with
        `timeout`, an unreached target is interrupted where it is.
        """
    @property
    def secure_kernel(self, /) -> SecureKernel:
        """
        The VBS secure kernel (VTL1): read-only `memory`, `symbols`, `types`,
        `modules`, and `trustlets`. Discovered on first use from host memory;
        raises `NtoseyeError` when VBS is not running or the backend cannot
        read host memory. Experimental.
        """
    def step(self, /, until: Literal["call", "ret", "branch"] |None = None) -> Stop:
        """
        Single-step one instruction, or with `until` ("call", "ret", "branch")
        step into until the next such instruction (`tc`/`tt`/`th`).
        """
    def step_out(self, /) -> Stop:
        """
        Run until the current function returns (`gu`).
        """
    def step_over(self, /, until: Literal["call", "ret", "branch"] |None = None) -> Stop:
        """
        Step over the current instruction, or with `until` step over until the
        next call/ret/branch (`pc`/`pt`/`ph`).
        """
    @property
    def stop(self, /) -> Stop |None:
        """
        The current stop while the target is halted, `None` while it runs.
        """
    @property
    def symbols(self, /) -> Symbols:
        """
        Kernel-scope symbols: `symbols["nt!KeBugCheckEx"]`, `nearest(addr)`,
        `search(query)`, the symbol and source paths.
        """
    @property
    def threads(self, /) -> Threads:
        """
        Every Windows thread keyed by TID: `threads[tid]`, `.at(ethread)`.
        """
    def trace_calls(self, /, limit: int = 10000) -> Record:
        """
        Trace calls until the current function returns (`wt`), single-stepping
        at most `limit` instructions: `{end, error, instructions, root}`, where
        `root` is the call tree and `end` says why tracing stopped.
        """
    @property
    def types(self, /) -> Types:
        """
        Kernel-scope PDB types: `types["_EPROCESS"].at(addr)`.
        """
    def wait(self, /, timeout: float |None = None) -> Stop |None:
        """
        Wait for the next stop without resuming. Returns the current stop at
        once when already halted, `None` if still running after `timeout`.
        """
    def write_dump(self, /, path: str) -> int:
        """
        Write a full `PAGEDU64` kernel dump of the halted target to `path`
        (`.dump /f`). Returns the number of unreadable pages zero-filled.
        """

@final
class Device:
    """
    One `_DEVICE_OBJECT`.
    """
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    @property
    def address(self, /) -> int:
        """
        The `_DEVICE_OBJECT` address.
        """
    def inspect(self, /) -> Record:
        """
        Inspect this `_DEVICE_OBJECT` and its attachment stack.
        """
    def to_dict(self, /) -> dict[str, Any]: ...

@final
class Diagnostic:
    """
    One field that reads independently: `value` when it did, `error` when it
    did not. Truthy exactly when available.
    """
    def __bool__(self, /) -> bool: ...
    def __eq__(self, other: object, /) -> bool: ...
    def __repr__(self, /) -> str: ...
    @property
    def available(self, /) -> bool: ...
    @property
    def error(self, /) -> str |None: ...
    @property
    def source(self, /) -> str |None: ...
    def to_dict(self, /) -> dict[str, Any]:
        """
        The `{available, value, error[, source]}` dict the MCP surface returns.
        """
    @property
    def value(self, /) -> Any: ...

@final
class Driver:
    """
    One `_DRIVER_OBJECT`, with the device objects it created.
    """
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    @property
    def devices(self, /) -> list[Device]:
        """
        The device objects this driver created.
        """
    def inspect(self, /) -> Record:
        """
        Inspect the `_DRIVER_OBJECT`, its devices, and dispatch table.
        """
    @property
    def name(self, /) -> str:
        """
        The driver object's name.
        """
    @property
    def object(self, /) -> int:
        """
        The `_DRIVER_OBJECT` address.
        """
    @property
    def size(self, /) -> int:
        """
        The driver image's size.
        """
    @property
    def start(self, /) -> int:
        """
        The driver image's base address.
        """
    def to_dict(self, /) -> dict[str, Any]:
        """
        The driver object as a plain `dict`, the shape MCP renders.
        """

@final
class DriverIterator:
    """
    Iterator over `dbg.drivers`.
    """
    def __iter__(self, /) -> DriverIterator: ...
    def __next__(self, /) -> Driver: ...

@final
class Drivers:
    """
    Driver objects from the object manager's `Driver` directory, keyed by
    name (`dbg.drivers`).
    """
    def __contains__(self, name: str, /) -> bool: ...
    def __getitem__(self, name: str, /) -> Driver: ...
    def __iter__(self, /) -> DriverIterator: ...
    def __len__(self, /) -> int: ...
    def at(self, /, addr: int) -> Driver |None:
        """
        Find the driver object or image containing `addr`.
        """
    def get(self, /, name: str) -> Driver |None:
        """
        Find a driver object by name, with or without its directory prefix.
        """

@final
class Exceptions:
    """
    Per-exception stop policies (`dbg.exceptions`, `sx*`).
    """
    def __iter__(self, /) -> RecordIterator:
        """
        Iterate configured exception-policy records.
        """
    def __len__(self, /) -> int:
        """
        Number of configured policies.
        """
    def __repr__(self, /) -> str: ...
    def reset(self, /) -> None:
        """
        Remove all configured policies; ordinary exceptions break by default.
        """
    def set(self, /, code: int |str, mode: Literal["break", "second_chance", "notify", "ignore"], *, disposition: Literal["handled", "not_handled"] |None = None) -> None:
        """
        Configure an exception's stop policy (`sxe`/`sxd`/`sxn`/`sxi`).
        """

@final
class Export:
    """
    One PE export, by name or ordinal only; a forwarder has no address.
    """
    def __repr__(self, /) -> str: ...
    @property
    def address(self, /) -> int |None:
        """
        The exported address, `None` for a forwarder.
        """
    @property
    def forwarder(self, /) -> str |None:
        """
        The forwarding target (`OTHER.Function`), for a forwarder.
        """
    @property
    def name(self, /) -> str |None:
        """
        The export name, `None` for an ordinal-only export.
        """
    @property
    def ordinal(self, /) -> int:
        """
        The export ordinal.
        """
    def to_dict(self, /) -> dict[str, Any]: ...

@final
class Field:
    """
    A PDB field layout: name, byte offset, byte size, and type spelling.
    """
    def __repr__(self, /) -> str: ...
    @property
    def name(self, /) -> str:
        """
        The field name.
        """
    @property
    def offset(self, /) -> int:
        """
        Byte offset within the containing type.
        """
    @property
    def size(self, /) -> int:
        """
        Size in bytes.
        """
    def to_dict(self, /) -> dict[str, Any]: ...
    @property
    def type(self, /) -> str:
        """
        The PDB type spelling.
        """

@final
class Frame:
    """
    One recovered stack frame with the register context used for locals.
    """
    def __eq__(self, other: object, /) -> bool: ...
    def __getitem__(self, name: str, /) -> int |None:
        """
        Resolve a local variable by name.
        """
    def __hash__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    @property
    def index(self, /) -> int:
        """
        The frame's position, 0 being the innermost.
        """
    @property
    def ip(self, /) -> int:
        """
        The frame's instruction pointer.
        """
    @property
    def locals(self, /) -> dict[str, int |None]:
        """
        Local variables evaluated in this frame's recovered context.
        """
    @property
    def registers(self, /) -> Registers:
        """
        The frame's registers: the live file for the innermost frame of a running
        thread (writable), otherwise the recovered subset (read-only).
        """
    @property
    def source(self, /) -> str |None:
        """
        How the frame was recovered (unwind data, frame pointer, ...).
        """
    @property
    def sp(self, /) -> int:
        """
        The frame's stack pointer.
        """
    @property
    def symbol(self, /) -> str |None:
        """
        The symbol at `ip`, if one resolved.
        """
    @property
    def thread(self, /) -> Thread |None:
        """
        The thread this stack belongs to.
        """
    def to_dict(self, /) -> dict[str, Any]: ...

@final
class Heap:
    """
    One heap of a process, from its PEB heap list.
    """
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    @property
    def address(self, /) -> int:
        """
        The heap address.
        """
    @property
    def index(self, /) -> int:
        """
        The heap's index in the PEB list.
        """
    def inspect(self, /, list_entries: bool = False) -> Record:
        """
        Decode this heap (`!heap -h`); `list_entries` materializes entries.
        """
    def to_dict(self, /) -> dict[str, Any]: ...

@final
class HeapIterator:
    """
    Iterator over `proc.heaps`.
    """
    def __iter__(self, /) -> HeapIterator: ...
    def __next__(self, /) -> Heap: ...

@final
class Heaps:
    """
    A process's PEB heap list.
    """
    def __contains__(self, index: int, /) -> bool: ...
    def __getitem__(self, index: int, /) -> Heap: ...
    def __iter__(self, /) -> HeapIterator: ...
    def __len__(self, /) -> int: ...
    def find_block(self, /, addr: int) -> Record:
        """
        Find the heap block containing `addr` (`!heap -x`).
        """
    def get(self, /, index: int) -> Heap |None: ...

@final
class Inspect:
    """
    System-wide reports and decode-by-address helpers (`dbg.inspect`); the
    results are `Record`s shaped like the MCP JSON output.
    """
    def __repr__(self, /) -> str: ...
    def acl(self, /, address: int) -> Record:
        """
        Decode an ACL and its ACEs (`!acl`).
        """
    def apcs(self, /, target: Process |Thread |int |None = None) -> Record:
        """
        Decode kernel and user APC queues for all threads, a process, or a thread (`!apc`).
        """
    def bugcheck(self, /) -> Record |None:
        """
        Analyze the current bugcheck, or return `None` when the target is not bugchecking.
        """
    def callbacks(self, /) -> list[Record]:
        """
        Enumerate process, thread, and image notification callbacks.
        """
    def context_record(self, /, address: int) -> Frame:
        """
        Decode a CONTEXT record and return its register set as a `Frame` (`.cxr`).
        """
    def device(self, /, address: int) -> Device:
        """
        Return a handle for the `_DEVICE_OBJECT` at `address` (`!devobj`).
        """
    def device_stack(self, /, device_or_node: Device |int) -> Record:
        """
        Decode the device stack containing a device object or devnode (`!devstack`).
        """
    def devnode(self, /, node: int |None = None, recurse: bool = False) -> Record:
        """
        Decode a PnP device node and optionally its bounded subtree (`!devnode`).
        """
    def dpcs(self, /) -> Record:
        """
        Report DPCs queued on each processor (`!dpcs`).
        """
    def exception_record(self, /, address: int) -> Record:
        """
        Decode an `EXCEPTION_RECORD64` (`.exr`).
        """
    def file_object(self, /, address: int) -> Record:
        """
        Decode a `_FILE_OBJECT` (`!fileobj`).
        """
    def irp(self, /, address: int) -> Record:
        """
        Decode an in-flight `_IRP` and its current I/O stack location (`!irp`).
        """
    def irps(self, /, filter: str |None = None) -> list[Record]:
        """
        Find in-flight IRPs, optionally filtered by process or driver (`irps`).
        """
    def lookaside(self, /, address: int) -> Record:
        """
        Decode one `GENERAL_LOOKASIDE` (`!lookaside address`).
        """
    def lookasides(self, /) -> Record:
        """
        List exported nonpaged and paged `GENERAL_LOOKASIDE` lists (`!lookaside`).
        """
    def memusage(self, /, process_limit: int = 64) -> Record:
        """
        Return bounded system and per-process memory-use counters (`!memusage`).
        """
    def object(self, /, address: int) -> Record:
        """
        Decode an executive object header and resolve its type and name (`!object`).
        """
    def object_security(self, /, object: int) -> Record:
        """
        Decode the security descriptor referenced by an object's header (`!objsd`).
        """
    def peb(self, /, process: Process, address: int |None = None) -> Record:
        """
        Decode a process PEB and its parameters and loader-list heads (`!peb`).
        """
    def pfn(self, /, value: int, physical_address: bool = False) -> Record:
        """
        Decode an `_MMPFN` by page-frame number or physical address (`!pfn`).
        """
    def pnp_triage(self, /) -> Record:
        """
        Report device nodes with PnP problems (`!pnptriage`).
        """
    def pool(self, /, address: int) -> Record:
        """
        Decode the pool page or big-pool allocation containing `address` (`!pool`).
        """
    def pool_find(self, /, tag: str, pool_type: str |None = None) -> Record:
        """
        Find pool allocations by tag, optionally restricted to a pool type (`!poolfind`).
        """
    def pool_usage(self, /, tag: str |None = None, *, sort: str = "tag", include_counts: bool = False) -> Record:
        """
        Aggregate pool tracker usage by tag (`!poolused`).
        """
    def ready(self, /, processor: int |None = None) -> Record:
        """
        Read bounded dispatcher-ready queues for every processor or one (`!ready`).
        """
    def resource(self, /, address: int) -> Record:
        """
        Decode an executive resource (`!locks address`).
        """
    def resources(self, /, limit: int = 256) -> Record:
        """
        Enumerate the symbol-backed executive-resource list (`!locks`).
        """
    def running(self, /, include_idle: bool = False, include_stacks: bool = False) -> Record:
        """
        Report current, next, and idle threads on each processor (`!running`).
        """
    def security_descriptor(self, /, address: int, annotate_well_known: bool = False) -> Record:
        """
        Decode a security descriptor, including owner/group SIDs and ACLs (`!sd`).
        """
    def sessions(self, /, session: int |None = None) -> Record:
        """
        List sessions and their processes, optionally selecting one (`!session`).
        """
    def sid(self, /, address: int) -> Record:
        """
        Decode a SID to its string form, authority, and well-known name (`!sid`).
        """
    def ssdt(self, /) -> list[Record]:
        """
        Dump the kernel SSDT and initialized win32k shadow table (`!ssdt`).
        """
    def stacks(self, /, level: int = 0, filter: str |None = None) -> Record:
        """
        Report thread states, wait reasons, and bounded stacks (`!stacks`).
        """
    def teb(self, /, thread: Thread, address: int |None = None) -> Record:
        """
        Decode a thread TEB and its WOW64 companion (`!teb`).
        """
    def time(self, /) -> Record:
        """
        Report target system time and uptime (`.time`).
        """
    def timer(self, /, address: int) -> Record:
        """
        Decode a `_KTIMER` and its DPC (`!timer address`).
        """
    def timers(self, /) -> Record:
        """
        Read bounded kernel timer-table entries and their DPCs (`!timer`).
        """
    def trap_frame(self, /, address: int) -> Record:
        """
        Decode a `_KTRAP_FRAME` at `address` (`.trap`).
        """
    def triage(self, /) -> Record:
        """
        Build the structured one-shot crash/debug report (`!analyze`).
        """
    def verifier(self, /) -> Record:
        """
        Report Driver Verifier configuration and statistics (`!verifier`).
        """
    def version(self, /) -> Record:
        """
        Target, kernel, symbol, processor, and debugger version information (`vertarget`).
        """
    def vm(self, /, include_processes: bool = True) -> Record:
        """
        Report system memory, pool, PTE, and page-file counters (`!vm`).
        """

@final
class Memory:
    """
    A guest address space: `dbg.memory` (kernel), `proc.memory`, `dbg.physical`.
    """
    def describe(self, /, addr: int) -> Record:
        """
        Describe the loaded module, kernel region, or process VAD containing `addr`.
        """
    def disassemble(self, /, addr: int, count: int) -> list[Record]:
        """
        Disassemble `count` instructions at `addr` (`u`).
        """
    def disassemble_back(self, /, addr: int, count: int) -> list[Record]:
        """
        Disassemble the `count` instructions ending at `addr` (`ub`).
        """
    def disassemble_function(self, /, addr: int) -> list[Record]:
        """
        Disassemble the runtime function containing `addr` (`uf`).
        """
    @property
    def dtb(self, /) -> int:
        """
        The directory-table base used by this space.
        """
    def page_in(self, /, addr: int) -> bool:
        """
        Make `addr` resident with the guest debugger worker (`.pagein`). The
        worker resumes the guest and returns with it stopped at its completion;
        that stop is reflected by `dbg.stop`.
        """
    @property
    def pointer_size(self, /) -> int:
        """
        The guest pointer width in bytes (`$ptrsize`).
        """
    def ptov(self, /, physical: int) -> Record:
        """
        Reverse-map a physical address through this space's page tables (`!ptov`).
        """
    def read(self, /, addr: int, n: int) -> bytes:
        """
        Read `n` bytes; virtual reads mask this debugger's breakpoint opcodes.
        """
    def read_ansi_string(self, /, addr: int, bits: int |None = None) -> str:
        """
        Decode the `_STRING`/`ANSI_STRING` descriptor at `addr` (`ds`). `bits`
        selects the layout as for `read_unicode_string`.
        """
    def read_pointer(self, /, addr: int) -> int:
        """
        Read a pointer-sized value at `addr` (`poi`).
        """
    def read_string(self, /, addr: int, max_len: int = 256) -> str:
        """
        Read a NUL-terminated ANSI string at `addr` (`da`).
        """
    def read_u16(self, /, addr: int) -> int:
        """
        Read a little-endian 16-bit integer.
        """
    def read_u32(self, /, addr: int) -> int:
        """
        Read a little-endian 32-bit integer.
        """
    def read_u64(self, /, addr: int) -> int:
        """
        Read a little-endian 64-bit integer.
        """
    def read_u8(self, /, addr: int) -> int:
        """
        Read one little-endian byte.
        """
    def read_unicode_string(self, /, addr: int, bits: int |None = None) -> str:
        """
        Decode the `_UNICODE_STRING` descriptor at `addr` (`dS`). `bits`
        selects the layout: 32 for a WOW64 process's x86 descriptors, 64 for
        native ones; by default the `.effmach` setting decides.
        """
    def read_wstring(self, /, addr: int, max_len: int = 256) -> str:
        """
        Read a NUL-terminated UTF-16 string at `addr` (`du`).
        """
    def search(self, /, pattern: bytes, start: int, length: int) -> list[MemorySearchMatch]:
        """
        Find overlapping matches and include symbol/module/VAD context.
        """
    def translate(self, /, addr: int) -> int |None:
        """
        Translate a virtual address through this space's page tables (`!vtop`).
        """
    def translation(self, /, addr: int) -> Record:
        """
        The full page-table walk and final translation (`!pte` + `!vtop`).
        """
    def write(self, /, addr: int, data: bytes) -> None:
        """
        Write bytes to this address space.
        """
    def write_u16(self, /, addr: int, value: int) -> None:
        """
        Write a little-endian 16-bit integer.
        """
    def write_u32(self, /, addr: int, value: int) -> None:
        """
        Write a little-endian 32-bit integer.
        """
    def write_u64(self, /, addr: int, value: int) -> None:
        """
        Write a little-endian 64-bit integer.
        """
    def write_u8(self, /, addr: int, value: int) -> None:
        """
        Write a little-endian byte.
        """

@final
class MemoryRegion:
    """
    One VAD/context region (`proc.regions` items, search-hit context).
    """
    def __repr__(self, /) -> str: ...
    @property
    def commit_charge(self, /) -> int |None:
        """
        Committed pages charged to the region.
        """
    @property
    def details(self, /) -> str |None:
        """
        A description: the mapped file, or the kernel region kind.
        """
    @property
    def end(self, /) -> int:
        """
        End of the region (exclusive).
        """
    @property
    def private_memory(self, /) -> bool |None:
        """
        Whether the region is private (not shared or mapped).
        """
    @property
    def protection(self, /) -> int |None:
        """
        The VAD protection value, when known.
        """
    @property
    def start(self, /) -> int:
        """
        First address of the region.
        """
    def to_dict(self, /) -> dict[str, Any]: ...
    @property
    def vad_type(self, /) -> int |None:
        """
        The VAD type, when known.
        """

@final
class MemoryRegionIterator:
    """
    Iterator over `proc.regions`.
    """
    def __iter__(self, /) -> MemoryRegionIterator: ...
    def __next__(self, /) -> MemoryRegion: ...

@final
class MemorySearchMatch:
    """
    A memory-search hit with symbol and location context.
    """
    def __repr__(self, /) -> str: ...
    @property
    def address(self, /) -> int:
        """
        Where the pattern matched.
        """
    @property
    def kind(self, /) -> str:
        """
        What the address is: a module, a kernel region, a process VAD,
        physical memory, or `vtl1`.
        """
    @property
    def module(self, /) -> AddressModule |None:
        """
        The module containing the match, if any.
        """
    @property
    def offset(self, /) -> int:
        """
        The match's offset from the search start.
        """
    @property
    def region(self, /) -> MemoryRegion |None:
        """
        The VAD region containing the match, for process addresses.
        """
    @property
    def section(self, /) -> str |None:
        """
        The module section containing the match, if any.
        """
    @property
    def symbol(self, /) -> str |None:
        """
        The nearest symbol, if one resolved.
        """
    def to_dict(self, /) -> dict[str, Any]: ...
    @property
    def va_type(self, /) -> str |None:
        """
        The kernel virtual-address region type, for kernel addresses.
        """

@final
class Module:
    """
    One loaded image in the kernel or a process address space.
    """
    def __eq__(self, other: object, /) -> bool: ...
    def __getitem__(self, name: str, /) -> int:
        """
        Resolve a symbol from this module to its address.
        """
    def __hash__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    @property
    def base(self, /) -> int:
        """
        Base address of the loaded image.
        """
    def check_image(self, /, include_diffs: bool = False) -> Record:
        """
        Compare executable sections against the cached image (`!chkimg`).
        """
    @property
    def exports(self, /) -> list[Export]:
        """
        Exports from the mapped PE export directory.
        """
    def fetch_image(self, /) -> str:
        """
        Fetch the matching image from the symbol server cache (`.fetchimage`).
        """
    @property
    def file_version(self, /) -> str |None:
        """
        File version from the image's version resource.
        """
    def image(self, /, zero_fill: bool = False) -> bytes:
        """
        The mapped image in memory layout, for pefile/LIEF. Raises
        `MemoryAccessError` on an unreadable page unless `zero_fill` is set,
        which zeroes such pages instead (a kernel's discarded INIT section).
        """
    def inspect(self, /) -> Record:
        """
        Symbol status, load diagnostics and PDB identity (`lmv`).
        """
    @property
    def name(self, /) -> str:
        """
        Image name.
        """
    @property
    def path(self, /) -> str |None:
        """
        Full image path, when the loader recorded one.
        """
    @property
    def product_version(self, /) -> str |None:
        """
        Product version from the image's version resource.
        """
    def reload_symbols(self, /) -> Record:
        """
        Select, fetch, and index symbols for this module (`ld`, `.reload`).
        """
    @property
    def sections(self, /) -> list[Section]:
        """
        PE sections and their mapped permissions.
        """
    @property
    def size(self, /) -> int:
        """
        Size of the mapped image.
        """
    @property
    def symbols(self, /) -> Record:
        """
        Module symbol and PDB identity (`lmv`).
        """
    @property
    def timestamp(self, /) -> int |None:
        """
        PE timestamp, when present in the loader record.
        """
    def to_dict(self, /) -> dict[str, Any]:
        """
        The module as a plain `dict`, the shape MCP renders.
        """
    def verifier(self, /) -> Record:
        """
        Return verifier data for this driver module.
        """

@final
class ModuleIterator:
    """
    Iterator over `dbg.modules` / `proc.modules`.
    """
    def __iter__(self, /) -> ModuleIterator: ...
    def __next__(self, /) -> Module: ...

@final
class Modules:
    """
    A module collection: `dbg.modules` (kernel), `proc.modules` (loader
    lists), or `dbg.secure_kernel.modules` (the secure kernel's).
    """
    def __contains__(self, name: str, /) -> bool: ...
    def __getitem__(self, name: str, /) -> Module: ...
    def __iter__(self, /) -> ModuleIterator: ...
    def __len__(self, /) -> int: ...
    def at(self, /, addr: int) -> Module |None:
        """
        The module containing `addr`, or `None` when no module contains it.
        """
    def get(self, /, name: str) -> Module |None:
        """
        Look up a module by short name, case-insensitively (`"nt"` names ntoskrnl).
        """
    @property
    def termination(self, /) -> Record |None:
        """
        How a process's loader lists ended (`termination` and
        `wow64_termination`, each `{kind, address, error}`), to tell a complete
        list from a corrupt or truncated one; `None` for kernel modules.
        """

@final
class Msrs:
    """
    Model-specific registers on one processor (`rdmsr`/`wrmsr`, KD only).
    """
    def __getitem__(self, key: int |str, /) -> int: ...
    def __repr__(self, /) -> str: ...
    def __setitem__(self, key: int |str, value: int, /) -> None: ...

@final
class NameIterator:
    """
    Iterator over names: a record's fields, a register file's registers.
    """
    def __iter__(self, /) -> NameIterator: ...
    def __next__(self, /) -> str: ...

@final
class Process:
    """
    One process: identity fields plus views bound to its address space.
    """
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    def apcs(self, /) -> Record:
        """
        Decode kernel and user APC queues for this process (`!apc`).
        """
    @property
    def dtb(self, /) -> int:
        """
        The process page-table root.
        """
    @property
    def eprocess(self, /) -> int:
        """
        The `_EPROCESS` virtual address.
        """
    def eval(self, /, expr: str) -> int:
        """
        Evaluate a debugger expression in this process's symbol scope.
        """
    def handle(self, /, value: int) -> Record:
        """
        Decode a handle in this process's handle table.
        """
    def handles(self, /, limit: int = 256) -> Record:
        """
        Enumerate up to `limit` handles in this process's handle table.
        """
    @property
    def heaps(self, /) -> Heaps:
        """
        The heaps in this process's PEB.
        """
    @property
    def memory(self, /) -> Memory:
        """
        Virtual memory through this process's page tables.
        """
    @property
    def modules(self, /) -> Modules:
        """
        Modules from this process's PEB loader lists.
        """
    @property
    def name(self, /) -> str:
        """
        The image name.
        """
    @property
    def object(self, /) -> Struct:
        """
        The process `_EPROCESS` cursor.
        """
    @property
    def peb(self, /) -> Struct |None:
        """
        The process `_PEB` cursor, or `None` when it has no PEB.
        """
    @property
    def pid(self, /) -> int:
        """
        The process identifier.
        """
    @property
    def ppid(self, /) -> int:
        """
        The parent process identifier.
        """
    @property
    def regions(self, /) -> Regions:
        """
        The process VAD regions (`!vad` / `vmmap`).
        """
    @property
    def session(self, /) -> int |None:
        """
        The Windows session identifier.
        """
    @property
    def symbols(self, /) -> Symbols:
        """
        Symbols resolved in this process's address space.
        """
    @property
    def threads(self, /) -> Threads:
        """
        Windows threads owned by this process.
        """
    def to_dict(self, /) -> dict[str, Any]:
        """
        The process's identity as a plain `dict` (`pid`, `name`, `dtb`,
        `eprocess`, `wow64`), the shape MCP renders.
        """
    def token(self, /) -> Record:
        """
        The process token and its security information.
        """
    @property
    def types(self, /) -> Types:
        """
        PDB types and cursors bound to this process's address space.
        """
    @property
    def wow64(self, /) -> bool:
        """
        Whether this process has a WOW64 (32-bit) PEB.
        """

@final
class ProcessIterator:
    """
    Iterator over `dbg.processes`.
    """
    def __iter__(self, /) -> ProcessIterator: ...
    def __next__(self, /) -> Process: ...

@final
class Processes:
    """
    Running processes keyed by PID (`dbg.processes`). Iterating walks the
    process list afresh; `find(name)` matches image names.
    """
    def __contains__(self, key: Any, /) -> bool: ...
    def __getitem__(self, pid: int, /) -> Process: ...
    def __iter__(self, /) -> ProcessIterator: ...
    def __len__(self, /) -> int: ...
    def find(self, /, name: str) -> list[Process]:
        """
        Find every exact image-name match, case-insensitively.
        """
    def get(self, /, pid: int) -> Process |None:
        """
        Find a process by PID; a missing PID returns `None`.
        """

@final
class Record:
    """
    An immutable, ordered set of named fields with attribute access.
    """
    def __contains__(self, key: str, /) -> bool: ...
    def __dir__(self, /) -> list[str]: ...
    def __eq__(self, other: object, /) -> bool: ...
    def __getattr__(self, name: str, /) -> Any: ...
    def __getitem__(self, key: str, /) -> Any: ...
    def __iter__(self, /) -> NameIterator: ...
    def __len__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    def get(self, /, key: str, default: Any |None = None) -> Any:
        """
        The field, or `default` when the record has no such field.
        """
    def items(self, /) -> list[tuple[str, Any]]:
        """
        `(name, value)` pairs, in order.
        """
    def keys(self, /) -> list[str]:
        """
        The field names, in order.
        """
    def to_dict(self, /) -> dict[str, Any]:
        """
        A plain nested `dict` (records and diagnostics converted throughout),
        the shape the MCP `format=json` surface returns.
        """
    def values(self, /) -> list[Any]:
        """
        The field values, in order.
        """

@final
class RecordIterator:
    """
    Iterator over records, such as `dbg.exceptions`.
    """
    def __iter__(self, /) -> RecordIterator: ...
    def __next__(self, /) -> Record: ...

@final
class Regions:
    """
    A process's VAD region collection (`!vad`).
    """
    def __contains__(self, addr: int, /) -> bool: ...
    def __getitem__(self, addr: int, /) -> MemoryRegion: ...
    def __iter__(self, /) -> MemoryRegionIterator: ...
    def __len__(self, /) -> int: ...
    def at(self, /, addr: int) -> MemoryRegion |None:
        """
        Find the VAD region containing `addr`, or return `None`.
        """

@final
class Registers:
    """
    A register file bound to a vCPU or recovered frame context.
    """
    def __contains__(self, name: str, /) -> bool: ...
    def __getattr__(self, name: str, /) -> int: ...
    def __getitem__(self, name: str, /) -> int: ...
    def __iter__(self, /) -> NameIterator: ...
    def __len__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    def __setattr__(self, name: str, value: Any, /) -> None: ...
    def __setitem__(self, name: str, value: int, /) -> None: ...
    def items(self, /) -> list[tuple[str, int]]:
        """
        `(name, value)` pairs, sorted by name.
        """
    def keys(self, /) -> list[str]:
        """
        The register names, sorted.
        """
    def to_dict(self, /) -> dict[str, int]:
        """
        The registers as a plain `dict`, sorted by name.
        """

@final
class Section:
    """
    One PE section: its name, RVA, mapped size, and `rwx` permissions.
    """
    def __repr__(self, /) -> str: ...
    @property
    def name(self, /) -> str:
        """
        The section name (`.text`).
        """
    @property
    def permissions(self, /) -> str:
        """
        Mapped permissions as `rwx`, `-` for a missing one.
        """
    @property
    def rva(self, /) -> int:
        """
        Its offset from the image base.
        """
    @property
    def size(self, /) -> int:
        """
        Its mapped size.
        """
    def to_dict(self, /) -> dict[str, Any]: ...

@final
class SecureKernel:
    """
    The secure kernel (`securekernel.exe`) running in VTL1, with views bound to
    its system address space. Read-only: writes raise `NtoseyeError`.
    """
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    @property
    def base(self, /) -> int:
        """
        Base address of `securekernel.exe`.
        """
    @property
    def dtb(self, /) -> int:
        """
        The secure kernel's system page-table root.
        """
    def eval(self, /, expr: str) -> int:
        """
        Evaluate a debugger expression in the secure kernel's symbol scope.
        Registers are VTL0 state and are refused.
        """
    @property
    def memory(self, /) -> Memory:
        """
        Virtual memory through the secure kernel's system page tables.
        """
    @property
    def modules(self, /) -> Modules:
        """
        Modules the secure kernel loaded (`securekernel.exe`, `skci.dll`, ...).
        """
    @property
    def symbols(self, /) -> Symbols:
        """
        Symbols of the secure kernel's modules (`securekernel!...`). NT's
        symbols do not resolve here.
        """
    @property
    def trustlets(self, /) -> list[Trustlet]:
        """
        The secure kernel's processes (trustlets), walked afresh and validated
        against the NT process list. Raises `NtoseyeError` when this build's
        process layout is not recognized.
        """
    @property
    def types(self, /) -> Types:
        """
        PDB types read through VTL1 memory. The public secure-kernel PDB
        carries no types; name NT's explicitly (`nt!_LIST_ENTRY`).
        """

class Stop:
    """
    Why the target stopped. Every stop is one of the nested kinds; test with
    `isinstance(stop, Stop.Breakpoint)` or `match`. A stop is bound to the
    target generation it happened in.
    """
    def __repr__(self, /) -> str: ...
    @property
    def breakpoints(self, /) -> list[Breakpoint]:
        """
        Breakpoint or watchpoint handles for this stop; empty on other kinds,
        so `bp in stop.breakpoints` works on any stop.
        """
    @property
    def cpu(self, /) -> Cpu:
        """
        Processor that stopped.
        """
    @property
    def process(self, /) -> Process |None:
        """
        Process whose page tables were active at this stop, if known.
        """
    def record(self, /) -> Record:
        """
        Decode the current exception record (`.exr -1`).
        """
    @property
    def rip(self, /) -> int |None:
        """
        Instruction pointer captured at this stop.
        """
    @property
    def symbol(self, /) -> str |None:
        """
        Nearest symbol captured at this stop, if one resolved.
        """
    @property
    def thread(self, /) -> Thread |None:
        """
        Windows thread executing on the stopped vCPU, if known.
        """
    def to_dict(self, /) -> dict[str, Any]: ...
    @final
    class Breakpoint(Stop):
        """
        A code breakpoint or data-watchpoint hit. `condition_error` is set when
        its condition failed to evaluate; such a hit is surfaced, not skipped.
        """
        __match_args__: Final = ("condition_error", "_context")
        def __new__(cls, /, condition_error: str |None, _context: _StopContext) -> Stop.Breakpoint: ...
        @property
        def _context(self, /) -> _StopContext: ...
        @property
        def condition_error(self, /) -> str |None:
            """
            Why the breakpoint's condition failed to evaluate, if it did.
            """
    @final
    class Bugcheck(Stop):
        """
        The guest is bugchecking (BSOD); `info` is the bugcheck analysis.
        """
        __match_args__: Final = ("info", "_context")
        def __new__(cls, /, info: Record |None, _context: _StopContext) -> Stop.Bugcheck: ...
        @property
        def _context(self, /) -> _StopContext: ...
        @property
        def info(self, /) -> Record |None:
            """
            The bugcheck analysis (`!analyze`'s code, parameters, and culprit).
            """
    @final
    class Exception(Stop):
        """
        A Windows exception: `code` (NTSTATUS), whether it is the first chance,
        and the faulting address.
        """
        __match_args__: Final = ("code", "first_chance", "address", "_context")
        def __new__(cls, /, code: int, first_chance: bool |None, address: int |None, _context: _StopContext) -> Stop.Exception: ...
        @property
        def _context(self, /) -> _StopContext: ...
        @property
        def address(self, /) -> int |None:
            """
            The faulting address, when the exception carries one.
            """
        @property
        def code(self, /) -> int:
            """
            The exception's NTSTATUS code.
            """
        @property
        def first_chance(self, /) -> bool |None:
            """
            Whether this is the first chance (`None` when the backend does not say).
            """
    @final
    class Interrupt(Stop):
        """
        A break-in (`interrupt()`), or another stop without an exception code.
        """
        __match_args__: Final = ("_context",)
        def __new__(cls, /, _context: _StopContext) -> Stop.Interrupt: ...
        @property
        def _context(self, /) -> _StopContext: ...
    @final
    class Reboot(Stop):
        """
        The guest rebooted; every earlier handle is now stale. While `coherent`
        is false the kernel's module list does not exist yet: kernel symbols
        and breakpoints work, and `run()` lets boot continue.
        """
        __match_args__: Final = ("kernel_base", "coherent", "_context")
        def __new__(cls, /, kernel_base: int |None, coherent: bool, _context: _StopContext) -> Stop.Reboot: ...
        @property
        def _context(self, /) -> _StopContext: ...
        @property
        def coherent(self, /) -> bool:
            """
            Whether the kernel's module list exists yet.
            """
        @property
        def kernel_base(self, /) -> int |None:
            """
            The new kernel's base address (moved by KASLR).
            """
    @final
    class Step(Stop):
        """
        A completed step.
        """
        __match_args__: Final = ("_context",)
        def __new__(cls, /, _context: _StopContext) -> Stop.Step: ...
        @property
        def _context(self, /) -> _StopContext: ...

@final
class Struct:
    """
    A PDB type bound to an address in an address space: a reflective cursor.
    """
    def __dir__(self, /) -> list[str]:
        """
        PDB fields and the cursor's public members, for tab completion.
        """
    def __eq__(self, other: object, /) -> bool: ...
    def __getattr__(self, name: str, /) -> Any:
        """
        Reflective field access; missing fields raise `AttributeError`.
        """
    def __getitem__(self, key: str |int, /) -> Any:
        """
        The field value, or an integer sibling cursor index (`((T*)p)[i]`).
        """
    def __hash__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    def __setattr__(self, name: str, value: Any, /) -> None:
        """
        `cursor.Field = value`; only actual PDB fields are assignable.
        """
    def __setitem__(self, name: str, value: Any, /) -> None:
        """
        Write a PDB field by name.
        """
    @property
    def addr(self, /) -> int:
        """
        Address this cursor refers to.
        """
    def address_of(self, /, name: str) -> int:
        """
        The address of field `name`, as C's `&cursor->name`: what a watchpoint
        or a raw read needs. A bitfield's address is its storage unit's.
        """
    def cast(self, /, type_name: str) -> Struct:
        """
        Reinterpret this address as another PDB type.
        """
    def follow(self, /, name: str) -> Struct:
        """
        Follow a pointer field to its typed target.
        """
    def read(self, /) -> dict[str, Any]:
        """
        Read one whole-struct snapshot into a dictionary; nested struct fields are omitted.
        """
    def to_dict(self, /) -> dict[str, Any]: ...
    @property
    def type(self, /) -> Type:
        """
        The PDB type of this cursor.
        """
    def walk(self, /, head_field: str, record_type: str, link_field: str) -> list[Struct]:
        """
        Walk a list whose head is a field of this cursor.
        """

@final
class Symbol:
    """
    A symbol identity nearest to an address.
    """
    def __repr__(self, /) -> str: ...
    def __str__(self, /) -> str: ...
    @property
    def address(self, /) -> int:
        """
        The symbol's address.
        """
    @property
    def module(self, /) -> str:
        """
        The module the symbol belongs to.
        """
    @property
    def name(self, /) -> str:
        """
        The symbol name.
        """
    @property
    def offset(self, /) -> int:
        """
        How far past the symbol the queried address is.
        """
    def to_dict(self, /) -> dict[str, Any]: ...

@final
class Symbols:
    """
    Symbol lookup scoped to an address space: `dbg.symbols`, `proc.symbols`.
    """
    def __contains__(self, name: str, /) -> bool:
        """
        Whether at least one symbol candidate has this name.
        """
    def __getitem__(self, name: str, /) -> int:
        """
        Resolve a symbol to its address, raising `SymbolNotFoundError` when absent.
        """
    def candidates(self, /, name: str) -> list[Record]:
        """
        Return every exact candidate, including module and private-compiland provenance.
        """
    def get(self, /, name: str) -> int |None:
        """
        Resolve a symbol to its address, or return `None` when absent.
        """
    def locals_at(self, /, addr: int) -> list[Record]:
        """
        List PDB local/parameter layouts covering `addr`, without evaluating values.
        """
    def nearest(self, /, addr: int) -> Symbol |None:
        """
        Return the nearest symbol identity, or `None` if no symbol covers `addr`.
        """
    @property
    def path(self, /) -> list[str]:
        """
        Ordered symbol sources (`.sympath`); assignment replaces the full path.
        """
    @path.setter
    def path(self, /, sources: Sequence[str]) -> None: ...
    def reload(self, /) -> Record:
        """
        Reload symbols in this space and re-resolve symbolic breakpoints.
        """
    def reset_path(self, /) -> None:
        """
        Restore the default symbol sources (`.symfix`).
        """
    def search(self, /, query: str, limit: int = 50) -> list[Record]:
        """
        Fuzzy-search symbol names; `module!query` scopes the search to a module.
        """
    def source_addresses(self, /, file: str, line: int) -> list[int]:
        """
        Resolve a source file and line to every matching loaded address.
        """
    def source_location(self, /, addr: int) -> Record |None:
        """
        Resolve an address to PDB source metadata and its remapped local path.
        """
    @property
    def source_path(self, /) -> list[str]:
        """
        Ordered source-path mappings (`.srcpath`); assignment replaces them.
        """
    @source_path.setter
    def source_path(self, /, paths: Sequence[str]) -> None: ...

@final
class Thread:
    """
    One Windows thread. The ETHREAD address is its identity within a debugger.
    """
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    def apcs(self, /) -> Record:
        """
        Decode this thread's APC lists (`!apc`).
        """
    def backtrace(self, /, limit: int = 64) -> list[Frame]:
        """
        Recover this thread's stack from live registers or its parked context.
        """
    @property
    def cpu(self, /) -> Cpu |None:
        """
        The processor the thread is running on, or `None` when it is not running.
        """
    @property
    def ethread(self, /) -> int:
        """
        The `_ETHREAD` address: the thread's identity.
        """
    def inspect(self, /) -> Record:
        """
        Thread summary and saved scheduling details (`!thread`).
        """
    @property
    def kthread(self, /) -> int:
        """
        The `_KTHREAD` address.
        """
    def last_error(self, /) -> Record:
        """
        Decode the thread's Win32 last-error and NTSTATUS values (`!gle`).
        """
    @property
    def object(self, /) -> Struct:
        """
        The typed `_ETHREAD` object.
        """
    @property
    def pid(self, /) -> int |None:
        """
        The owning process's id.
        """
    @property
    def process(self, /) -> Process |None:
        """
        The owning process.
        """
    @property
    def state(self, /) -> int |None:
        """
        The scheduler state, a `_KTHREAD_STATE` member (`IntEnum`).
        """
    @property
    def teb(self, /) -> Struct |None:
        """
        The process-bound `_TEB`, or `None` for kernel threads.
        """
    @property
    def tid(self, /) -> int |None:
        """
        The thread id (`None` for a thread that has none, like idle threads).
        """
    def to_dict(self, /) -> dict[str, Any]:
        """
        The thread as a plain `dict`, the shape MCP renders.
        """
    def trap_frame(self, /) -> Record:
        """
        Decode the saved `_KTRAP_FRAME` (`!trap`).
        """
    @property
    def wait_reason(self, /) -> int |None:
        """
        Why the thread waits, a `_KWAIT_REASON` member (`IntEnum`).
        """

@final
class ThreadIterator:
    """
    Iterator over `dbg.threads` / `proc.threads`.
    """
    def __iter__(self, /) -> ThreadIterator: ...
    def __next__(self, /) -> Thread: ...

@final
class Threads:
    """
    A thread collection: `dbg.threads` (all) or `proc.threads`.
    """
    def __contains__(self, tid: int, /) -> bool: ...
    def __getitem__(self, tid: int, /) -> Thread:
        """
        Resolve a TID, raising `KeyError` when it is not present.
        """
    def __iter__(self, /) -> ThreadIterator: ...
    def __len__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    def at(self, /, address: int) -> Thread:
        """
        Resolve an ETHREAD or KTHREAD address.
        """
    def get(self, /, tid: int) -> Thread |None:
        """
        Resolve a TID, returning `None` when it is not present.
        """

@final
class Trustlet:
    """
    An isolated user-mode process (trustlet) in VTL1, such as `LsaIso.exe`.
    Its views read through the trustlet's own page tables, which map its user
    half and the secure kernel. Read-only.
    """
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    @property
    def address(self, /) -> int:
        """
        Address of the secure kernel's process object for this trustlet.
        """
    @property
    def dtb(self, /) -> int:
        """
        The trustlet's page-table root.
        """
    def eval(self, /, expr: str) -> int:
        """
        Evaluate a debugger expression in this trustlet's address space.
        """
    @property
    def memory(self, /) -> Memory:
        """
        Virtual memory through the trustlet's page tables.
        """
    @property
    def name(self, /) -> str:
        """
        The image name, from the NT process.
        """
    @property
    def pid(self, /) -> int:
        """
        The NT process ID of the trustlet's VTL0 counterpart.
        """
    @property
    def process(self, /) -> Process |None:
        """
        The NT process (VTL0 side), or `None` once it has exited.
        """
    @property
    def symbols(self, /) -> Symbols:
        """
        The secure kernel's symbols, resolved in this trustlet's address space.
        The trustlet's own user-mode modules are not enumerated.
        """
    def to_dict(self, /) -> dict[str, Any]:
        """
        The trustlet's identity as a plain `dict` (`pid`, `name`,
        `trustlet_id`, `dtb`, `address`), the shape `!trustlets` lists.
        """
    @property
    def trustlet_id(self, /) -> int:
        """
        The trustlet ID from its creation attributes (1 for `LsaIso.exe`).
        """
    @property
    def types(self, /) -> Types:
        """
        PDB types read through the trustlet's memory (`nt!` types by name).
        """

@final
class Type:
    """
    A named PDB struct/union layout or enum definition.
    """
    def __repr__(self, /) -> str: ...
    def at(self, /, addr: int) -> Struct:
        """
        Bind this layout to an address as a reflective struct cursor.
        """
    @property
    def fields(self, /) -> dict[str, Field]:
        """
        Field layouts by name, in offset order. Enums have no fields.
        """
    @property
    def name(self, /) -> str:
        """
        PDB type name (for example, `_EPROCESS`).
        """
    @property
    def size(self, /) -> int:
        """
        Size in bytes, including the underlying storage width for enums.
        """
    def to_dict(self, /) -> dict[str, Any]: ...
    @property
    def values(self, /) -> dict[str, int]:
        """
        Enum members by name, in declaration order; raises for structs and
        unions.
        """
    def walk(self, /, head: int, link_field: str) -> list[Struct]:
        """
        Walk an intrusive list whose head is at `head` and whose links are `link_field`.
        """

@final
class Types:
    """
    PDB types scoped to an address space: `dbg.types`, `proc.types`.
    """
    def __contains__(self, key: Any, /) -> bool: ...
    def __getitem__(self, name: str, /) -> Type:
        """
        Resolve a struct, union, or enum by PDB name; unknown names raise `KeyError`.
        """
    def __repr__(self, /) -> str: ...
    def get(self, /, name: str) -> Type |None:
        """
        Return the named type, or `None` when it does not resolve.
        """

@final
class Watchpoint(Breakpoint):
    """
    A hardware data watchpoint.
    """
    @property
    def access(self, /) -> str:
        """
        Data access type (`"write"` or `"read_write"`).
        """
    @property
    def length(self, /) -> int:
        """
        Width of the watched memory access in bytes.
        """

@final
class _StopContext:
    """
    Rust-only snapshot backing the shared properties of a typed stop.
    """

def _cli_main() -> int:
    """
    Run the `ntoseye` command line on `sys.argv` and return its exit status:
    the wheel's `ntoseye` script. The GIL is released for the whole session;
    custom commands take it back while they run.
    """

def attach(backend: Literal["kd", "kdnet", "gdb", "memory", "dmp"] = ..., connect: str |None = None, key: str |None = None, memory_source: Literal["auto", "host", "kd"] = ...) -> Debugger:
    """
    Attach to a guest and return a `Debugger`.
    
    `backend` is one of `"kd"` (default), `"kdnet"`, `"gdb"`, `"memory"`, or
    `"dmp"`. `connect` is the backend target: socket path / address for
    kd/kdnet/gdb, or the dump file path for dmp; the per-backend default is used
    when omitted (except dmp, which requires a path). `key` is required for
    kdnet. `memory_source` is `auto`, `host`, or `kd` for KD/KDNET.
    
    kd/kdnet/gdb take a per-target instance lock before building the backend, so
    a second live attach against the same target fails fast rather than racing
    on the handshake the first session owns; memory/dmp are passive.
    """

def decode_error(code: int) -> Record:
    """
    Decode an NTSTATUS, Win32, or HRESULT code to its name and description
    (`!error`). Needs no target.
    """
