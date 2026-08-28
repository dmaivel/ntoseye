"""Type stubs for the ntoseye Python SDK (a Rust extension module).

Drive the ntoseye Windows kernel debugger from Python. See the project README
and `examples/` for usage.
"""

from typing import Any, Literal

__version__: str

class NtoseyeError(Exception):
    """Base class for errors raised by the SDK."""

class MemoryAccessError(NtoseyeError):
    """A guest memory access fault (unmapped page, partial read/write). Catch
    this to skip unreadable regions in sparse-memory walks without swallowing
    other errors."""

class AddressModule:
    """Loaded-module context for a structured memory-search hit."""

    @property
    def name(self) -> str: ...
    @property
    def base(self) -> int: ...
    @property
    def size(self) -> int: ...
    @property
    def offset(self) -> int: ...
    def to_dict(self) -> dict[str, Any]: ...
    def __repr__(self) -> str: ...

class MemoryRegion:
    """VAD/context region for a structured memory-search hit."""

    @property
    def start(self) -> int: ...
    @property
    def end(self) -> int: ...
    @property
    def protection(self) -> int | None: ...
    @property
    def vad_type(self) -> int | None: ...
    @property
    def private_memory(self) -> bool | None: ...
    @property
    def commit_charge(self) -> int | None: ...
    @property
    def details(self) -> str | None: ...
    def to_dict(self) -> dict[str, Any]: ...
    def __repr__(self) -> str: ...

class MemorySearchMatch:
    """A memory-search hit with symbol and location context."""

    @property
    def address(self) -> int: ...
    @property
    def offset(self) -> int: ...
    @property
    def symbol(self) -> str | None: ...
    @property
    def kind(self) -> str: ...
    @property
    def module(self) -> AddressModule | None: ...
    @property
    def section(self) -> str | None: ...
    @property
    def va_type(self) -> str | None: ...
    @property
    def region(self) -> MemoryRegion | None: ...
    def to_dict(self) -> dict[str, Any]: ...
    def __repr__(self) -> str: ...

class Breakpoint:
    """A live code-breakpoint or data-watchpoint handle."""

    @property
    def id(self) -> int: ...
    @property
    def address(self) -> int | None: ...
    @property
    def symbol(self) -> str | None: ...
    @property
    def scope(self) -> str: ...
    @property
    def condition(self) -> str | None: ...
    @property
    def resolved(self) -> bool: ...
    @property
    def deferred(self) -> bool: ...
    @property
    def specification(self) -> str | None: ...
    @property
    def pass_count(self) -> int: ...
    @property
    def hit_count(self) -> int: ...
    @property
    def remaining_pass_count(self) -> int: ...
    @property
    def one_shot(self) -> bool: ...
    @property
    def action(self) -> str | None: ...
    @property
    def temporary(self) -> bool: ...
    @property
    def watchpoint(self) -> bool: ...
    @property
    def watch_access(self) -> Literal["write", "read_write"] | None: ...
    @property
    def watch_length(self) -> int | None: ...
    @property
    def valid(self) -> bool: ...
    def is_valid(self) -> bool: ...
    @property
    def enabled(self) -> bool: ...
    @enabled.setter
    def enabled(self, value: bool) -> None: ...
    def clear(self) -> None: ...
    def delete(self) -> None: ...
    def enable(self) -> None: ...
    def disable(self) -> None: ...
    def to_dict(self) -> dict[str, Any]: ...
    def __eq__(self, other: object) -> bool: ...
    def __hash__(self) -> int: ...
    def __repr__(self) -> str: ...

class StopOutcome:
    """A run-control result. Use predicates for control flow and `breakpoints`
    for breakpoint identity; `reason` is for display/logging."""

    @property
    def reason(self) -> str: ...
    @property
    def running(self) -> bool: ...
    @property
    def timed_out(self) -> bool: ...
    @property
    def breakpoint_stop(self) -> bool: ...
    @property
    def watchpoint(self) -> bool: ...
    @property
    def exception(self) -> bool: ...
    @property
    def step(self) -> bool: ...
    @property
    def bugcheck(self) -> bool: ...
    @property
    def target_reloaded(self) -> bool: ...
    @property
    def reload(self) -> bool: ...
    @property
    def halted(self) -> bool: ...
    @property
    def terminal(self) -> bool: ...
    @property
    def rip(self) -> int | None: ...
    @property
    def symbol(self) -> str | None: ...
    @property
    def process(self) -> tuple[int, str] | None: ...
    @property
    def breakpoints(self) -> list[Breakpoint]: ...
    @property
    def breakpoint(self) -> Breakpoint | None: ...
    @property
    def breakpoint_ids(self) -> list[int]: ...
    @property
    def breakpoint_id(self) -> int | None: ...
    @property
    def address(self) -> int | None: ...
    @property
    def temporary(self) -> bool | None: ...
    @property
    def condition_error(self) -> str | None:
        """Error from evaluating a breakpoint/watchpoint condition. Such a stop
        is surfaced rather than silently skipped."""
        ...
    @property
    def exception_code(self) -> int | None: ...
    @property
    def first_chance(self) -> bool | None: ...
    @property
    def exception_address(self) -> int | None: ...
    @property
    def bugcheck_info(self) -> dict[str, Any] | None: ...
    @property
    def kernel_base(self) -> int | None: ...
    @property
    def coherent(self) -> bool | None: ...
    def to_dict(self) -> dict[str, Any]: ...
    def get(self, key: str, default: Any = None) -> Any: ...
    def __getitem__(self, key: str) -> Any: ...
    def __contains__(self, key: str) -> bool: ...
    def __repr__(self) -> str: ...

def attach(
    backend: str = "kd",
    connect: str | None = None,
    key: str | None = None,
    memory_source: str = "auto",
) -> Debugger:
    """Attach to a guest and return a `Debugger`.

    `backend` is one of `"kd"` (default), `"kdnet"`, `"gdb"`, `"memory"`, or
    `"dmp"`. `connect` is the backend target (socket path / listen address); a
    per-backend default is used when omitted. `key` is required for KDNET.
    `memory_source` is `"auto"`, `"host"`, or `"kd"` for KD/KDNET.
    """
    ...

class Debugger:
    """A live debugging session. Usable as a context manager."""

    # --- memory ---
    def read(self, addr: int, len: int) -> bytes:
        """Read `len` bytes of guest virtual memory."""
        ...
    def write(self, addr: int, data: bytes) -> None:
        """Write bytes to guest virtual memory."""
        ...
    def read_u8(self, addr: int) -> int: ...
    def read_u16(self, addr: int) -> int: ...
    def read_u32(self, addr: int) -> int: ...
    def read_u64(self, addr: int) -> int: ...
    def write_u8(self, addr: int, value: int) -> None: ...
    def write_u16(self, addr: int, value: int) -> None: ...
    def write_u32(self, addr: int, value: int) -> None: ...
    def write_u64(self, addr: int, value: int) -> None: ...
    def search(self, start: int, pattern: bytes, length: int) -> list[int]:
        """Search `length` bytes from `start` for `pattern`; return match addresses."""
        ...
    def search_details(self, start: int, pattern: bytes, length: int) -> list[MemorySearchMatch]:
        """Search memory and return rows with address, offset, symbol, and location context."""
        ...

    # --- expressions / symbols / types ---
    def eval(self, expr: str) -> int:
        """Evaluate a debugger expression to an address/integer."""
        ...
    def symbol_candidates(self, name: str) -> list[dict[str, Any]]:
        """Exact PDB symbol matches with module/visibility/compiland provenance."""
        ...
    def nearest_symbol(self, addr: int) -> dict[str, Any]:
        """Nearest symbol as `{address, module, name, offset}`."""
        ...
    def search_symbols(self, query: str, limit: int = 50) -> list[dict[str, Any]]:
        """Fuzzy-search symbols; use `module!query` to scope one module."""
        ...
    def source_location(self, addr: int) -> dict[str, Any] | None:
        """PDB source location and remapped local path for an address."""
        ...
    def source_addresses(self, file: str, line: int) -> list[int]:
        """Every loaded address matching a PDB source file and line."""
        ...
    def procedure_locals(self, addr: int) -> list[dict[str, Any]]:
        """Private locals/parameters in scope; scalar values when safely readable."""
        ...
    def type_size(self, ty: str) -> int: ...
    def offset_of(self, ty: str, field: str) -> int: ...
    def fields(self, ty: str) -> list[tuple[str, int, int, str]]:
        """Field layout: `(name, offset, size, type)` tuples sorted by offset."""
        ...
    def enum_values(self, name: str) -> list[tuple[str, int]]:
        """Variants of a PDB enum as `(name, value)` tuples, in declaration order
        (e.g. `_MI_SYSTEM_VA_TYPE`, `_KWAIT_REASON`)."""
        ...
    def read_struct(self, ty: str, addr: int) -> dict[str, Any]:
        """Read a struct at `addr`; `{field: value}` (ints, bitfields, or bytes).

        For walking instances prefer `type(ty).at(addr)`, which gives a
        reflective cursor (`proc.UniqueProcessId`) instead of restating `ty`.
        """
        ...
    def type(self, name: str) -> Type:
        """Resolve a PDB type into a reflective `Type` handle.

        The (expensive) layout scan happens once here; `.at(addr)` then binds it
        to an address as a `Struct` cursor with attribute access::

            proc = dbg.type("_EPROCESS").at(eprocess)
            proc.UniqueProcessId          # -> int
            proc.ImageFileName            # CHAR[15] -> str (NUL-trimmed)
            proc.Pcb.DirectoryTableBase   # nested struct chains
        """
        ...
    def closest_symbol(self, addr: int) -> str | None:
        """Nearest symbol as `module!name+0x..`, or `None`."""
        ...
    def disassemble(self, addr: int, count: int) -> list[tuple[int, str, str, str | None]]:
        """Disassemble `count` instructions: `(ip, hex, asm, comment)` tuples."""
        ...
    def inspect_trap_frame(self, address: int | None = None) -> dict[str, Any]:
        """Decode an x64 `_KTRAP_FRAME` at `address`, or the current Windows
        thread's saved trap frame when omitted. Returns `{address, rip_symbol,
        frame}` with the decoded register fields in `frame`."""
        ...
    def backtrace(self, limit: int = 64) -> list[tuple[int, int, str, str]]:
        """Walk the current thread's call stack: `(ip, sp, symbol, source)` tuples.

        `source` is `"current"`, `"unwind"`, or `"scan"`.
        """
        ...
    def walk_list(self, record_type: str, link_field: str, head: int) -> list[Struct]:
        """Walk an intrusive `_LIST_ENTRY` from a bare head address.

        Returns a `Struct` cursor per record::

            head = dbg.eval("PsLoadedModuleList")
            for m in dbg.walk_list("_KLDR_DATA_TABLE_ENTRY", "InLoadOrderLinks", head):
                print(m.BaseDllName)   # _UNICODE_STRING auto-decodes to str

        For a list whose head is a struct field, use `Struct.list`.
        """
        ...
    def current_dtb(self) -> int: ...
    def pte_walk(self, addr: int) -> dict[str, Any]:
        """Walk the page tables for `addr`.

        Returns `{"address": int, "levels": [...]}`, where each level dict has
        `level`, `address`, `value`, `pfn`, `present`, `large_page`, `writable`,
        `user`, `nx`, and `flags`. Large-page mappings return fewer levels.
        """
        ...

    # --- registers ---
    def read_register(self, name: str) -> int: ...
    def registers(self) -> dict[str, int]: ...
    def write_register(self, name: str, value: int) -> None:
        """Set a register on the current thread (read-modify-write of the
        register file). Halt the VM first; a running guest has no coherent
        register file to patch."""
        ...

    # --- execution control ---
    def cont(self, disposition: Literal["handled", "not_handled"] = "handled") -> None:
        """Resume the VM, acknowledging the current exception as handled or
        not handled and stepping past a breakpoint at RIP first. `not_handled`
        requires the KD backend."""
        ...
    def step(self) -> StopOutcome:
        """Single-step one instruction (re-arms breakpoints and re-selects the
        stopped thread). Returns a `StopOutcome` (a `step` stop at the landed-on
        instruction), matching `step_over()`/`step_out()`. Requires the VM
        halted."""
        ...
    def step_over(self) -> StopOutcome:
        """Step over the current instruction (run to a call's return site, else
        single-step). Blocks until done; returns a `StopOutcome`. Requires the
        VM halted."""
        ...
    def step_out(self) -> StopOutcome:
        """Step out of the current function (run to the caller's return address).
        Blocks until done; returns a `StopOutcome`. Requires the VM halted."""
        ...
    def interrupt(self) -> None:
        """Pause the VM (adopts the stopped thread as the current one)."""
        ...
    def set_current_thread(self, thread: str) -> None:
        """Select the current inspection thread (a vCPU id) so
        registers/backtrace/step operate on it."""
        ...
    @property
    def current_thread(self) -> str:
        """The currently selected inspection thread id."""
        ...
    def is_running(self) -> bool: ...
    def status(self) -> dict[str, Any]:
        """Read-only run-control snapshot (where am I): `{running, current_thread,
        rip, symbol, process, coherent, kernel_base}`. `rip`/`symbol` are None
        while running. `coherent` is False when the guest rebooted and rediscovery
        is still pending, so enumeration is not yet meaningful; wait for it
        instead. `kernel_base` changes across a reboot; cache it to invalidate
        stale addresses."""
        ...
    def wait_for_stop(self, timeout_ms: int | None = None) -> StopOutcome:
        """Wait for the next stop WITHOUT resuming, up to `timeout_ms` (None blocks,
        polling for KeyboardInterrupt). Returns a `StopOutcome`; `halted` is
        true immediately if the VM is already parked with nothing pending. Does
        not resume; use `cont()` (or `run()`) to advance."""
        ...
    def run(
        self,
        timeout_ms: int | None = None,
        *,
        disposition: Literal["handled", "not_handled"] = "handled",
    ) -> StopOutcome:
        """Resume and wait for the next meaningful stop, auto-resuming past
        wrong-process and false-conditional breakpoint hits. `not_handled`
        requires the KD backend. With `timeout_ms` set, returns an outcome with
        `running` true if nothing stopped in that window (poll again); with
        `None`, blocks until a stop."""
        ...
    def bugcheck(self) -> dict[str, Any] | None:
        """Analyze the current bugcheck (BSOD) from `nt!KiBugCheckData`. Returns
        `{code, code_hex, name, description, driver, args, fault, trap_frames,
        source}` (each trap frame is `{address, rip_symbol, frame, error}` with
        decoded `_KTRAP_FRAME` registers in `frame`, or `None` plus an `error`
        explaining why decoding failed) or `None` if the guest is not bugchecking."""
        ...
    def triage(self) -> dict[str, Any]:
        """Build a one-shot crash/debug report with status, bugcheck or exception,
        stack, modules, dump metadata, failure signature, culprit evidence,
        verifier/WHEA findings, and blackbox-stream availability."""
        ...
    def reload(self) -> None:
        """Rebuild guest state after a reboot/reload."""
        ...

    # --- breakpoints ---
    def set_breakpoint(self, addr: int, condition: str | None = None) -> int:
        """Set a code breakpoint; returns its id. Requires the VM halted.

        `condition` uses the normal expression grammar and is re-evaluated each
        hit. Comparisons, bitwise operators, and short-circuiting `!`, `&&`, and
        `||` may be combined; a bare expression is true when non-zero.
        """
        ...
    def breakpoint(self, target: int | str, condition: str | None = None) -> Breakpoint:
        """Set a code breakpoint from an address or expression; returns a live
        breakpoint handle. Requires the VM halted."""
        ...
    def set_symbol_breakpoint(
        self, symbol: str, condition: str | None = None
    ) -> Breakpoint:
        """Set a reload-stable symbol breakpoint, retaining it while deferred."""
        ...
    def set_source_breakpoint(
        self, file: str, line: int, condition: str | None = None
    ) -> list[Breakpoint]:
        """Set all matching `file:line` identities, or one deferred identity."""
        ...
    def watchpoint(
        self,
        target: int | str,
        *,
        access: Literal["write", "read_write"] = "write",
        length: Literal[1, 2, 4, 8] = 1,
        condition: str | None = None,
    ) -> Breakpoint:
        """Watch data access at an address or expression; returns a live handle.
        `read_write` reflects x86's inability to trap reads without writes.
        Watches are global across guest address spaces and currently require KD.
        Requires the VM halted."""
        ...
    def clear_breakpoint(self, id: int | Breakpoint) -> None:
        """Clear a breakpoint or watchpoint by id or handle. Requires the VM halted."""
        ...
    def enable_breakpoint(self, id: int | Breakpoint) -> None:
        """Re-arm a disabled breakpoint or watchpoint. Requires the VM halted."""
        ...
    def disable_breakpoint(self, id: int | Breakpoint) -> None:
        """Disable a breakpoint or watchpoint without forgetting it.
        Requires the VM halted."""
        ...
    def breakpoints(self) -> list[Breakpoint]:
        """Installed code breakpoints and data watchpoints as live handles.
        `watchpoint`, `watch_access`, and `watch_length` distinguish data
        watches; every entry can be cleared/enabled/disabled directly."""
        ...

    # --- process context ---
    def attach_process(self, pid: int) -> str:
        """Switch inspection context to a process; returns its name."""
        ...
    def detach(self) -> None:
        """Return to the default (kernel) inspection context."""
        ...
    def current_process(self) -> tuple[int, str, int] | None:
        """`(pid, name, eprocess)` of the attached process, or `None`."""
        ...
    def memory_map(self) -> list[dict[str, Any]]:
        """VAD regions of the attached process (requires `attach_process`)."""
        ...

    # --- enumeration ---
    def processes(self, filter: str | None = None) -> list[Struct]:
        """Running processes as `_EPROCESS` cursors. `filter` narrows the list:
        a numeric filter is an exact pid, anything else a case-insensitive name
        substring.

        Read fields off each: `proc.UniqueProcessId`, `proc.ImageFileName`,
        `proc.addr` (the EPROCESS VA), or `proc.threads()`.
        """
        ...
    def process(self, target: str) -> Struct:
        """Resolve a single process by pid or name substring to its `_EPROCESS`
        cursor. Raises if nothing matches or a name is ambiguous; use
        `processes(filter)` for the full matching list."""
        ...
    def kernel_modules(self) -> list[tuple[str, int, int]]:
        """`(name, base, size)` tuples (kernel modules, regardless of attach state)."""
        ...
    def modules(self) -> list[tuple[str, int, int]]:
        """`(name, base, size)` tuples for the current scope: the attached
        process's user-mode modules when attached, else the kernel modules."""
        ...
    def driver_objects(self) -> list[tuple[str, int, int, int]]:
        """`(name, object, driver_start, driver_size)` tuples."""
        ...
    def threads(self) -> list[dict[str, Any]]:
        """Windows threads as dicts `{tid, pid, process_name, ethread, kthread,
        eprocess, state, wait_reason, active}`, where `active` is the vCPU id
        currently running the thread (e.g. `"p1.1"`) or `None`."""
        ...
    def vcpus(self) -> list[dict[str, Any]]:
        """Per-vCPU state as dicts `{id, rip, context, symbol, error}`; the
        address space (`"kernel"` / process name / `"unknown"`) and nearest
        symbol each vCPU is executing. Requires the VM halted."""
        ...
    def capabilities(self) -> list[tuple[str, bool]]:
        """Backend capability matrix as `(label, supported)` tuples."""
        ...

    # --- structured inspectors ---
    def describe_address(self, addr: int) -> dict[str, Any]:
        """Describe what `addr` belongs to: `{address, dtb, kind, module, section,
        va_type, region}`. `kind` is
        kernel-module/user-image/kernel-region/private/mapped/unknown;
        `va_type` is the MM region name (e.g. KernelStacks, PagedPool) for a
        kernel address; `module`/`section`/`va_type`/`region` are None when not
        applicable. Complements `pte_walk` (how it's mapped) with where it lives."""
        ...
    def inspect_irp(self, addr: int) -> dict[str, Any]:
        """Decode an `_IRP` and its current `_IO_STACK_LOCATION`."""
        ...
    def inspect_driver_object(self, addr: int) -> dict[str, Any]:
        """Decode a `_DRIVER_OBJECT` (accepts a pointer to one): header fields,
        device chain, and the 28-entry `MajorFunction` dispatch table."""
        ...
    def inspect_device_object(self, addr: int) -> dict[str, Any]:
        """Decode a `_DEVICE_OBJECT` (accepts a pointer to one) and its
        `AttachedDevice` stack."""
        ...
    def inspect_object_header(self, addr: int) -> dict[str, Any]:
        """Decode the executive `_OBJECT_HEADER` for an object body or header;
        resolves the type and name."""
        ...
    def handles(self, limit: int = 256) -> dict[str, Any]:
        """Enumerate bounded handles for the selected/current process."""
        ...
    def inspect_handle(self, handle: int) -> dict[str, Any]:
        """Decode one handle from the selected/current process handle table."""
        ...
    def inspect_process_token(self) -> dict[str, Any]:
        """Decode the selected/current process primary token."""
        ...
    def inspect_file_object(self, addr: int) -> dict[str, Any]:
        """Decode a `_FILE_OBJECT` and its device/name relationships."""
        ...
    def inspect_resource(self, addr: int) -> dict[str, Any]:
        """Decode one executive resource."""
        ...
    def resources(self, limit: int = 256) -> dict[str, Any]:
        """Enumerate the symbol-backed executive-resource list."""
        ...
    def memory_usage(self, process_limit: int = 64) -> dict[str, Any]:
        """Return bounded system and per-process memory-use counters."""
        ...
    def notify_callbacks(self) -> list[dict[str, Any]]:
        """Process/thread/image notification callbacks (`Psp*NotifyRoutine`)."""
        ...
    def ssdt(self) -> list[dict[str, Any]]:
        """The kernel SSDT and, when initialized, the win32k shadow table, as
        `{label, base, limit, entries:[...]}` dicts."""
        ...
    def discover_irps(self, filter: str | None = None) -> list[dict[str, Any]]:
        """Discover in-flight IRPs from thread `IrpList`s and device `CurrentIrp`.
        `filter` scopes processes (pid/name) and driver names."""
        ...

    # --- misc ---
    def run_command(self, line: str) -> None:
        """Run any REPL command (output goes to stdout)."""
        ...
    def debug_log(self, since_seq: int = 0) -> dict[str, Any]:
        """Captured guest debug output (DbgPrint) since sequence `since_seq`;
        returns a cursored snapshot for polling. Empty on gdb/memory backends."""
        ...
    def close(self) -> None:
        """Restore all breakpoints, then resume; on failure, leave the target halted."""
        ...
    def __enter__(self) -> Debugger: ...
    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> bool: ...
    def __repr__(self) -> str: ...

class Type:
    """A resolved PDB type. Created via `Debugger.type(name)`."""

    name: str
    size: int
    fields: list[tuple[str, int, int, str]]
    def offset(self, field: str) -> int:
        """Byte offset of `field` within the type."""
        ...
    def at(self, addr: int) -> Struct:
        """Bind this layout to `addr`, returning a reflective `Struct` cursor."""
        ...
    def __getitem__(self, field: str) -> tuple[str, int, int, str]:
        """`type["field"]` -> `(name, offset, size, type)`."""
        ...
    def __repr__(self) -> str: ...

class Struct:
    """A PDB type bound to a guest address: a reflective struct cursor.

    Field access reads from the current inspection context. Scalars become
    ints, bitfields their masked value, CHAR/UCHAR arrays a NUL-trimmed `str`
    (e.g. `ImageFileName`), other sized aggregates `bytes`, and nested
    struct/union fields a child `Struct` (so accesses chain). Pointer fields
    return the raw address; use `follow()` for a typed deref.
    """

    addr: int
    type_name: str
    fields: list[str]
    def read_field(self, name: str) -> Any:
        """Explicit field read (same as `self.name` / `self[name]`)."""
        ...
    def write_field(self, name: str, value: int | bytes) -> None:
        """Write a field (the explicit form of `self.name = value`).

        Scalars/pointers take an `int` (encoded to the field width); bitfields
        take an `int` (read-modify-write); sized aggregates take `bytes` of
        exactly the field size. Writes guest memory in the current context.
        """
        ...
    def follow(self, name: str) -> Struct:
        """Follow a pointer field to a typed child cursor (type from the PDB)."""
        ...
    def list(self, head_field: str, record_type: str, link_field: str) -> list[Struct]:
        """Walk an intrusive `_LIST_ENTRY` whose head is `head_field` of this struct.

        `record_type`/`link_field` give the record layout and its embedded link
        (CONTAINING_RECORD). Returns a `Struct` cursor per record.
        """
        ...
    def threads(self) -> list[Struct]:
        """Walk this process's threads (`_EPROCESS.ThreadListHead` -> `_ETHREAD`)."""
        ...
    def unicode_string(self, name: str) -> str:
        """Decode a `_UNICODE_STRING` field to `str` (such fields also auto-decode)."""
        ...
    def read_unicode_string(self) -> str:
        """Decode the `_UNICODE_STRING` this cursor points at to `str`."""
        ...
    def read(self) -> dict[str, Any]:
        """Read the whole struct as a `{field: value}` dict (nested structs omitted)."""
        ...
    def __getattr__(self, name: str) -> Any: ...
    def __setattr__(self, name: str, value: int | bytes) -> None: ...
    def __getitem__(self, name: str) -> Any: ...
    def __dir__(self) -> list[str]: ...
    def __repr__(self) -> str: ...
