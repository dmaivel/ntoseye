"""Type stubs for the ntoseye Python SDK (a Rust extension module).

Drive the ntoseye Windows kernel debugger from Python. See the project README
and `examples/` for usage.
"""

from typing import Any, Iterator, Literal

__version__: str

class NtoseyeError(Exception):
    """Base class for errors raised by the SDK."""

class MemoryAccessError(NtoseyeError):
    """A guest memory access fault (unmapped page, partial read/write). Catch
    this to skip unreadable regions in sparse-memory walks without swallowing
    other errors."""

class Record:
    """An immutable, ordered set of named fields with attribute access: what
    every structured result (`backtrace()` frames, `threads()`, `status()`,
    the inspectors) returns. `record.ip`, or `record["ip"]`; `in`, `len`,
    iteration over field names, `keys()`/`values()`/`items()`/`get()`, and
    `to_dict()` for the plain nested dict the MCP JSON surface documents.
    Addresses are ints; `repr` shows them as hex."""

    def __getattr__(self, name: str) -> Any: ...
    def __getitem__(self, key: str) -> Any: ...
    def __contains__(self, key: str) -> bool: ...
    def __len__(self) -> int: ...
    def __iter__(self) -> Iterator[str]: ...
    def keys(self) -> list[str]: ...
    def values(self) -> list[Any]: ...
    def items(self) -> list[tuple[str, Any]]: ...
    def get(self, key: str, default: Any = None) -> Any: ...
    def to_dict(self) -> dict[str, Any]: ...

class Diagnostic:
    """One field that reads independently of its record: `value` when it did,
    `error` when it did not. Truthy exactly when available, so
    `if peb.ldr: use(peb.ldr.value)`. Metrics also carry `source`, the
    provenance of the value (`"dump header"`, `"KDBG"`, ...)."""

    @property
    def available(self) -> bool: ...
    @property
    def value(self) -> Any: ...
    @property
    def error(self) -> str | None: ...
    @property
    def source(self) -> str | None: ...
    def __bool__(self) -> bool: ...
    def to_dict(self) -> dict[str, Any]: ...

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
    @condition.setter
    def condition(self, value: str | None) -> None:
        """Replace or clear the break condition (`bpc`); applies at the next hit."""
        ...
    @property
    def resolved(self) -> bool: ...
    @property
    def deferred(self) -> bool: ...
    @property
    def specification(self) -> str | None: ...
    @property
    def pass_count(self) -> int: ...
    @pass_count.setter
    def pass_count(self, value: int) -> None:
        """Reset the hit number to break on (`bpp`; GDB's ignore count)."""
        ...
    @property
    def hit_count(self) -> int: ...
    @property
    def remaining_pass_count(self) -> int: ...
    @property
    def one_shot(self) -> bool: ...
    @one_shot.setter
    def one_shot(self, value: bool) -> None: ...
    @property
    def action(self) -> str | None: ...
    @action.setter
    def action(self, value: str | None) -> None:
        """Set or clear the REPL command string run at each hit (`bs`)."""
        ...
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
    def halted(self) -> bool: ...
    @property
    def terminal(self) -> bool: ...
    @property
    def rip(self) -> int | None: ...
    @property
    def symbol(self) -> str | None: ...
    @property
    def attached_process(self) -> Record | None:
        """The inspection scope at the stop as `{pid, name, dtb, eprocess}`. This
        is the operator's selection (`.process`) and persists across resumes, so
        it is not necessarily what the guest was executing."""
        ...
    @property
    def stopped_process(self) -> Record | None:
        """The process whose page tables the stopped vCPU had loaded, resolved
        from CR3 at the stop."""
        ...
    @property
    def stopped_thread(self) -> Record | None:
        """The Windows thread the stopped vCPU was running, walked from its
        KPRCB. Its owner can differ from `stopped_process` when the thread is
        attached to another address space."""
        ...
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
    def bugcheck_info(self) -> Record | None: ...
    @property
    def kernel_base(self) -> int | None: ...
    @property
    def coherent(self) -> bool | None: ...
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
    @property
    def pointer_size(self) -> int:
        """Pointer width in bytes (`$ptrsize`); 8 on both supported architectures."""
        ...
    def read_pointer(self, addr: int) -> int:
        """Read a pointer-sized value (`poi`)."""
        ...
    def read_string(self, addr: int, max_len: int = 256) -> str:
        """Read a NUL-terminated ANSI string (`da`)."""
        ...
    def read_wstring(self, addr: int, max_len: int = 256) -> str:
        """Read a NUL-terminated UTF-16 string (`du`)."""
        ...
    def read_unicode_string(self, addr: int) -> str:
        """Decode the `_UNICODE_STRING` descriptor at `addr` (`dS`)."""
        ...
    def read_ansi_string(self, addr: int) -> str:
        """Decode the `ANSI_STRING` descriptor at `addr` (`ds`)."""
        ...
    def read_physical(self, addr: int, len: int) -> bytes:
        """Read guest-physical memory (`!db`)."""
        ...
    def write_physical(self, addr: int, data: bytes) -> None:
        """Write guest-physical memory (`!eb`)."""
        ...
    def vtop(self, addr: int, dtb: int | None = None) -> int | None:
        """Translate a virtual address to physical through `dtb` (default: the
        current context); `None` when not present (`!vtop`)."""
        ...
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
    def symbol_candidates(self, name: str) -> list[Record]:
        """Exact PDB symbol matches with module/visibility/compiland provenance."""
        ...
    def nearest_symbol(self, addr: int) -> Record:
        """Nearest symbol as `{address, module, name, offset}`."""
        ...
    def search_symbols(self, query: str, limit: int = 50) -> list[Record]:
        """Fuzzy-search symbols; use `module!query` to scope one module."""
        ...
    def source_location(self, addr: int) -> Record | None:
        """PDB source location and remapped local path for an address."""
        ...
    def source_addresses(self, file: str, line: int) -> list[int]:
        """Every loaded address matching a PDB source file and line."""
        ...
    def procedure_locals(self, addr: int | None = None) -> list[Record]:
        """Private locals/parameters in scope at `addr`, defaulting to the selected
        frame (`select_frame`) or the halted RIP (`dv`); scalar values when safely
        readable in the current register context."""
        ...
    def type_size(self, ty: str) -> int: ...
    def offset_of(self, ty: str, field: str) -> int: ...
    def fields(self, ty: str) -> Record:
        """Type layout `{name, size, fields: [{name, offset, size, type}]}`,
        fields sorted by offset."""
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
    def disassemble(self, addr: int, count: int) -> list[Record]:
        """Disassemble `count` instructions as `{ip, hex, asm, comment}` dicts."""
        ...
    def inspect_trap_frame(self, address: int | None = None) -> Record:
        """Decode an x64 `_KTRAP_FRAME` at `address`, or the current Windows
        thread's saved trap frame when omitted. Returns `{address, rip_symbol,
        frame}` with the decoded register fields in `frame`."""
        ...
    def backtrace(self, limit: int = 64) -> list[Record]:
        """Walk the current thread's call stack as `{ip, sp, symbol, source,
        source_location}` dicts.

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
    def pte_walk(self, addr: int) -> Record:
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
    def select_thread(self, thread: int | None) -> str | None:
        """Select a Windows thread (`.thread`) by tid, ETHREAD, or KTHREAD as the
        inspection context. Returns the vCPU id when the thread is running (live
        registers), `None` when it is parked (stack only). `None` resets to the
        backend's current vCPU. Requires the VM halted."""
        ...
    def selected_thread(self) -> Record | None:
        """The `.thread` selection in the `threads()` dict shape, or `None`."""
        ...
    def thread(self, thread: int) -> Struct:
        """Resolve a tid / ETHREAD / KTHREAD to its `_ETHREAD` cursor."""
        ...
    def select_frame(self, index: int | None) -> Record | None:
        """Select stack frame `index` (`.frame N`) so registers, locals, and
        expressions use its recovered register file; returns `{index, ip, sp}`.
        `None` returns to the live frame. Requires a halted, live (not parked) thread."""
        ...
    def selected_frame(self) -> Record | None:
        """The selected frame as `{index, ip, sp}`, or `None` at the live frame."""
        ...
    def backtrace_thread(self, thread: int, limit: int = 64) -> Record:
        """Walk any Windows thread's stack without selecting it: `{ethread, tid,
        source, frames}` with `backtrace()`-shaped frames."""
        ...
    def run_to(self, target: int | str, timeout_ms: int | None = None) -> StopOutcome:
        """Run until `target` is reached (`g <address>`) via a temporary breakpoint.
        Other stops en route are returned as-is. With `timeout_ms`, an unreached
        target is interrupted where it is and the outcome is `halted`."""
        ...
    def set_exception_policy(
        self,
        code: int | str,
        mode: Literal["break", "second_chance", "notify", "ignore"],
        *,
        disposition: Literal["handled", "not_handled"] | None = None,
    ) -> None:
        """Stop policy for an exception code (`sxe`/`sxd`/`sxn`/`sxi`; GDB's
        `handle`). `code` is an NTSTATUS or a WinDbg alias (`"av"`, `"sse"`).
        `notify` and `ignore` both continue without stopping outside the REPL.
        `disposition` fixes the acknowledgment of a continued exception (`-f gh`/`-f gn`).
        Applies to `run()`, `wait_for_stop()`, and `run_to()`."""
        ...
    def exception_policies(self) -> list[Record]:
        """Configured policies as `{code, alias, mode, disposition, command}` (`sx`)."""
        ...
    def reset_exception_policies(self) -> None:
        """Forget every exception policy (`sxr`)."""
        ...
    def read_msr(self, msr: int | str, processor: int | None = None) -> int:
        """Read a model-specific register (`rdmsr`); accepts IA32_* names. KD only,
        halted."""
        ...
    def write_msr(self, msr: int | str, value: int, processor: int | None = None) -> None:
        """Write a model-specific register (`wrmsr`). KD only, halted."""
        ...
    def is_running(self) -> bool: ...
    def status(self) -> Record:
        """Read-only run-control snapshot (where am I): `{running, current_thread,
        rip, symbol, attached_process: {pid, name, eprocess} | None,
        stopped_process: {pid, name, eprocess} | None, stopped_thread | None,
        coherent, kernel_base}`. `attached_process` is the inspection scope
        (`.process`), which persists across resumes; `stopped_process` owns the
        page tables the stopped vCPU has loaded and `stopped_thread` is the
        Windows thread it is running.
        `rip`/`symbol` are None while running. `coherent` is False when the guest
        rebooted and rediscovery
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
    def bugcheck(self) -> Record | None:
        """Analyze the current bugcheck (BSOD) from `nt!KiBugCheckData`. Returns
        `{code, code_hex, name, description, driver, args, fault, trap_frames,
        source}` (each trap frame is `{address, rip_symbol, frame, error}` with
        decoded `_KTRAP_FRAME` registers in `frame`, or `None` plus an `error`
        explaining why decoding failed) or `None` if the guest is not bugchecking."""
        ...
    def triage(self) -> Record:
        """Build a one-shot crash/debug report with status, bugcheck or exception,
        stack, modules, dump metadata, failure signature, culprit evidence,
        verifier/WHEA findings, and blackbox-stream availability."""
        ...
    def reload(self) -> None:
        """Rebuild guest state after a reboot/reload."""
        ...
    symbol_path: list[str]
    """Ordered symbol sources (`.sympath`): `cache*<dir>`, directories, `http(s)://`
    servers. Assign a list to replace them."""
    def add_symbol_path(self, source: str) -> None:
        """Append a symbol source (`.sympath+`)."""
        ...
    def reset_symbol_path(self) -> None:
        """Restore the default symbol sources (`.symfix`)."""
        ...
    source_path: list[str]
    """Ordered source-path mappings (`.srcpath`): `<root>` or `<prefix>=<root>`."""
    def add_source_path(self, mapping: str) -> None:
        """Append a source-path mapping (`.srcpath+`)."""
        ...
    def reload_symbols(self, module: str | None = None) -> Record:
        """Reload symbols for one module or every module in scope (`.reload`), then
        re-resolve symbolic breakpoints. Returns `{total, loaded, unloaded, no_pdb,
        skipped, failed, diagnostic_count, diagnostics}`."""
        ...
    def write_dump(self, path: str) -> int:
        """Write a full `PAGEDU64` kernel dump of the halted target (`.dump /f`);
        returns the number of unreadable pages that were zero-filled."""
        ...
    def version(self) -> Record:
        """Target, kernel, symbol, processor, and debugger version information
        (`vertarget`)."""
        ...
    def target_time(self) -> Record:
        """Target system time and uptime (`.time`)."""
        ...

    # --- breakpoints ---
    def breakpoint(
        self,
        target: int | str,
        condition: str | None = None,
        *,
        pass_count: int = 0,
        one_shot: bool = False,
        process: int | None = None,
        action: str | None = None,
    ) -> Breakpoint:
        """Set a code breakpoint from an address or expression; returns a live
        breakpoint handle. Requires the VM halted.

        `condition` uses the normal expression grammar and is re-evaluated each
        hit. Comparisons, bitwise operators, and short-circuiting `!`, `&&`, and
        `||` may be combined; a bare expression is true when non-zero.
        `pass_count` is the hit number to break on (`bp <target> <passes>`),
        `one_shot` clears the breakpoint after its first reported hit (`/1`),
        `process` limits reported hits to one pid's address space (`/p`), and
        `action` is a REPL command string run at each hit (`do "..."`).
        """
        ...
    def set_symbol_breakpoint(
        self,
        symbol: str,
        condition: str | None = None,
        *,
        pass_count: int = 0,
        one_shot: bool = False,
        process: int | None = None,
        action: str | None = None,
    ) -> Breakpoint:
        """Set a reload-stable symbol breakpoint (`bu`), retaining it while deferred.
        Options as for `breakpoint()`."""
        ...
    def set_pattern_breakpoints(
        self,
        pattern: str,
        condition: str | None = None,
        *,
        pass_count: int = 0,
        one_shot: bool = False,
        process: int | None = None,
        action: str | None = None,
        limit: int = 256,
    ) -> list[Breakpoint]:
        """Set one symbol breakpoint per symbol matching a `*`/`?` glob, optionally
        `module!`-qualified (`bm`). Raises when nothing matches."""
        ...
    def set_source_breakpoint(
        self,
        file: str,
        line: int,
        condition: str | None = None,
        *,
        pass_count: int = 0,
        one_shot: bool = False,
        process: int | None = None,
        action: str | None = None,
    ) -> list[Breakpoint]:
        """Set all matching `file:line` identities, or one deferred identity.
        Options as for `breakpoint()`."""
        ...
    def watchpoint(
        self,
        target: int | str,
        *,
        access: Literal["write", "read_write"] = "write",
        length: Literal[1, 2, 4, 8] = 1,
        condition: str | None = None,
        pass_count: int = 0,
        one_shot: bool = False,
        process: int | None = None,
        action: str | None = None,
    ) -> Breakpoint:
        """Watch data access at an address or expression; returns a live handle.
        `read_write` reflects x86's inability to trap reads without writes.
        Watches are global across guest address spaces and currently require KD.
        Requires the VM halted. Options as for `breakpoint()`."""
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
    def current_process(self) -> Record | None:
        """`{pid, name, dtb, eprocess}` of the attached process, or `None`."""
        ...
    def memory_map(self, pid: int | None = None) -> list[Record]:
        """VAD regions of process `pid` (default: the attached process) as
        dicts `{start, end, size, protection, vad_type, private_memory,
        commit_charge, details}`."""
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
    def kernel_modules(self) -> list[Record]:
        """Kernel modules (regardless of attach state) as `{name, short_name,
        base, end, size, time_date_stamp?, checksum?, file_version?,
        product_version?}` dicts."""
        ...
    def modules(self) -> list[Record]:
        """Modules for the current scope, same shape as `kernel_modules()`: the
        attached process's user-mode modules when attached, else the kernel
        modules."""
        ...
    def driver_objects(self) -> list[Record]:
        """Driver objects as `{name, object, driver_start, driver_size,
        device_object, driver_unload}` dicts."""
        ...
    def threads(self) -> list[Record]:
        """Windows threads as dicts `{tid, pid, process_name, ethread, kthread,
        eprocess, state, state_name, wait_reason, wait_reason_name, active}`,
        where `active` is the vCPU id currently running the thread (e.g.
        `"p1.1"`) or `None`."""
        ...
    def vcpus(self) -> list[Record]:
        """Per-vCPU state as dicts `{id, rip, context, symbol, error}`; the
        address space (`"kernel"` / process name / `"unknown"`) and nearest
        symbol each vCPU is executing. Requires the VM halted."""
        ...
    def capabilities(self) -> list[Record]:
        """Backend capability matrix as `{capability, label, supported}` dicts."""
        ...

    # --- structured inspectors ---
    def describe_address(self, addr: int) -> Record:
        """Describe what `addr` belongs to: `{address, dtb, kind, module, section,
        va_type, region}`. `kind` is
        kernel-module/user-image/kernel-region/private/mapped/unknown;
        `va_type` is the MM region name (e.g. KernelStacks, PagedPool) for a
        kernel address; `module`/`section`/`va_type`/`region` are None when not
        applicable. Complements `pte_walk` (how it's mapped) with where it lives."""
        ...
    def inspect_irp(self, addr: int) -> Record:
        """Decode an `_IRP` and its current `_IO_STACK_LOCATION`."""
        ...
    def inspect_driver_object(self, addr: int) -> Record:
        """Decode a `_DRIVER_OBJECT` (accepts a pointer to one): header fields,
        device chain, and the 28-entry `MajorFunction` dispatch table."""
        ...
    def inspect_device_object(self, addr: int) -> Record:
        """Decode a `_DEVICE_OBJECT` (accepts a pointer to one) and its
        `AttachedDevice` stack."""
        ...
    def inspect_object_header(self, addr: int) -> Record:
        """Decode the executive `_OBJECT_HEADER` for an object body or header;
        resolves the type and name."""
        ...
    def handles(self, limit: int = 256) -> Record:
        """Enumerate bounded handles for the selected/current process."""
        ...
    def inspect_handle(self, handle: int) -> Record:
        """Decode one handle from the selected/current process handle table."""
        ...
    def inspect_process_token(self) -> Record:
        """Decode the selected/current process primary token."""
        ...
    def inspect_file_object(self, addr: int) -> Record:
        """Decode a `_FILE_OBJECT` and its device/name relationships."""
        ...
    def inspect_resource(self, addr: int) -> Record:
        """Decode one executive resource."""
        ...
    def resources(self, limit: int = 256) -> Record:
        """Enumerate the symbol-backed executive-resource list."""
        ...
    def memory_usage(self, process_limit: int = 64) -> Record:
        """Return bounded system and per-process memory-use counters."""
        ...
    def notify_callbacks(self) -> list[Record]:
        """Process/thread/image notification callbacks (`Psp*NotifyRoutine`)."""
        ...
    def ssdt(self) -> list[Record]:
        """The kernel SSDT and, when initialized, the win32k shadow table, as
        `{label, base, limit, entries:[...]}` dicts."""
        ...
    def discover_irps(self, filter: str | None = None) -> list[Record]:
        """Discover in-flight IRPs from thread `IrpList`s and device `CurrentIrp`.
        `filter` scopes processes (pid/name) and driver names."""
        ...

    # --- structured inspectors: CPU ---
    def inspect_pcr(self, processor: int | None = None) -> Record:
        """KPCR/KPRCB essentials for `processor` (default: current vCPU's): thread
        pointers, IDTR/GDTR/TSS, IRQL (`!pcr`)."""
        ...
    def inspect_prcb(self, processor: int | None = None) -> Record:
        """`_KPRCB` counters, thread pointers, and processor state (`!prcb`)."""
        ...
    def inspect_irql(self, processor: int | None = None) -> Record:
        """Current IRQL and level name (`!irql`); debugger-observed at a KD break-in."""
        ...
    def inspect_idt(self, vector: int | None = None, processor: int | None = None) -> Record:
        """One IDT vector or the bounded 256-entry table with handler symbols, gate
        types, non-nt hooks, and `KiIsrThunk` hints (`!idt`; AMD64 only)."""
        ...
    def inspect_gdt(self, processor: int | None = None) -> Record:
        """The bounded GDT (`!gdt`; AMD64 only)."""
        ...
    def inspect_cpuinfo(self, processor: int | None = None) -> Record:
        """Vendor, family/model/stepping, speed, feature bits (`!cpuinfo`)."""
        ...

    # --- structured inspectors: scheduler ---
    def running(self, include_idle: bool = False, include_stacks: bool = False) -> Record:
        """The current/next/idle thread per processor, optionally with a short
        kernel stack each (`!running`)."""
        ...
    def ready_queues(self, processor: int | None = None) -> Record:
        """Bounded dispatcher-ready queues (`!ready`)."""
        ...
    def dpc_queues(self) -> Record:
        """DPCs queued on each processor (`!dpcs`)."""
        ...
    def timers(self) -> Record:
        """Bounded kernel timer-table entries with their DPCs (`!timer`)."""
        ...
    def inspect_timer(self, address: int) -> Record:
        """Decode one `_KTIMER` and its DPC (`!timer <address>`)."""
        ...
    def apcs(self, target: int | str | None = None) -> Record:
        """Kernel and user APCs (`!apc`): `None` the selected thread, `"*"` every
        thread, an int a thread (tid/ETHREAD) or else a process (pid/EPROCESS), a
        string a process-name substring."""
        ...
    def stacks(self, level: int = 0, filter: str | None = None) -> Record:
        """Every thread's state, wait reason, and top symbol (`!stacks`); `level`
        1/2 add bounded stacks; `filter` matches process names or symbols."""
        ...

    # --- structured inspectors: user mode ---
    def inspect_peb(self, address: int | None = None) -> Record:
        """The attached process's PEB (or the one at `address`), process parameters,
        loader-list heads, and the WOW64 PEB when present (`!peb`)."""
        ...
    def inspect_teb(self, address: int | None = None) -> Record:
        """The selected thread's TEB (or the one at `address`) plus the WOW64 TEB
        when present (`!teb`)."""
        ...
    def loader_modules(self, containing: int | None = None) -> Record:
        """Modules from the attached process loader lists, optionally only the one
        containing an address (`!dlls`)."""
        ...
    def last_error(self) -> Record:
        """The selected thread's last Win32 error and NT status with names (`!gle`)."""
        ...
    def check_image(self, module: str, include_diffs: bool = False) -> Record:
        """Compare a module's executable sections with the on-disk image after
        relocation (`!chkimg`); kernel self-patches are counted separately."""
        ...

    # --- structured inspectors: heap ---
    def heap_summary(self) -> Record:
        """Every heap in the attached process PEB with kind and sizes (`!heap`)."""
        ...
    def inspect_heap(self, heap: int, list_entries: bool = False) -> Record:
        """One NT or segment heap by PEB-list index (when it exists) or address
        (`!heap -h`); `list_entries` materializes every entry/chunk/block (`-a`)."""
        ...
    def find_heap_block(self, address: int) -> Record:
        """The heap allocation containing `address` (`!heap -x`)."""
        ...

    # --- structured inspectors: memory manager ---
    def inspect_vm(self, include_processes: bool = True) -> Record:
        """System memory, pool, PTE, page-file counters and per-process rows (`!vm`)."""
        ...
    def inspect_pfn(self, value: int, physical_address: bool = False) -> Record:
        """Decode an `_MMPFN` by page frame number, or physical address (`!pfn`)."""
        ...
    def inspect_translation(self, addr: int, dtb: int | None = None) -> Record:
        """Every page-table level and the final physical address of `addr` through
        `dtb` (default: current context) (`!vtop`)."""
        ...
    def ptov(self, physical: int) -> Record:
        """Bounded reverse walk: current-DTB virtual mappings of a physical address
        (`!ptov`; AMD64 only)."""
        ...
    def inspect_pool(self, address: int) -> Record:
        """The pool page or big-pool allocation containing `address` (`!pool`)."""
        ...
    def pool_usage(
        self,
        tag: str | None = None,
        *,
        sort: Literal["tag", "nonpaged", "paged"] = "tag",
        include_counts: bool = False,
    ) -> Record:
        """Pool tracker usage by tag (`!poolused`); `tag` is a case-sensitive glob."""
        ...
    def pool_find(self, tag: str, pool_type: Literal["nonpaged", "paged"] | None = None) -> Record:
        """Bounded scan for pool blocks with a matching tag (`!poolfind`)."""
        ...
    def lookaside_lists(self) -> Record:
        """The exported nonpaged and paged lookaside lists (`!lookaside`)."""
        ...
    def inspect_lookaside(self, address: int) -> Record:
        """Decode one `GENERAL_LOOKASIDE` (`!lookaside <address>`)."""
        ...

    # --- structured inspectors: security ---
    def inspect_security_descriptor(self, address: int, annotate_well_known: bool = False) -> Record:
        """Decode a `SECURITY_DESCRIPTOR` with its owner/group and DACL/SACL (`!sd`)."""
        ...
    def inspect_acl(self, address: int) -> Record:
        """Decode an ACL and its ACEs (`!acl`)."""
        ...
    def inspect_sid(self, address: int) -> Record:
        """Decode a SID to its string form, authority, and well-known name (`!sid`)."""
        ...
    def inspect_object_security(self, object: int) -> Record:
        """The security descriptor referenced by an object's header (`!objsd`)."""
        ...
    def sessions(self, session: int | None = None) -> Record:
        """Sessions and their processes (`!session`); `-1` is the current session."""
        ...
    def session_processes(
        self, session: int | None = None, detailed: bool = False, image_glob: str | None = None
    ) -> Record:
        """Processes in a session (`!sprocess`): `None` the attached process's, `-1`
        current, `-4` all; `image_glob` filters case-insensitively."""
        ...

    # --- structured inspectors: PnP ---
    def inspect_devnode(self, node: int | None = None, recurse: bool = False) -> Record:
        """A PnP device node (default: root) with state history, problem code, and
        pending IRP; `recurse` adds the bounded subtree (`!devnode`)."""
        ...
    def inspect_device_stack(self, device_or_node: int) -> Record:
        """The device stack top-down from any device object or node in it (`!devstack`)."""
        ...
    def pnp_triage(self) -> Record:
        """Device nodes with problems, not started, or with pending IRPs (`!pnptriage`)."""
        ...

    # --- structured inspectors: verifier / target ---
    def verifier_status(self) -> Record:
        """Driver Verifier level, statistics, and driver lists (`!verifier`)."""
        ...
    def verifier_driver(self, module: str) -> Record:
        """One verified driver's image, signing level, and counters (`!verifier <module>`)."""
        ...
    @staticmethod
    def decode_error(code: int) -> Record:
        """Decode an NTSTATUS, Win32, or HRESULT code (`!error`); needs no target."""
        ...

    # --- misc ---
    def run_command(self, line: str) -> str:
        """Run any REPL command (`"dt _EPROCESS"`, `"lm"`, `"!analyze"`) and
        return its text output, styling stripped. The escape hatch for commands
        without a typed method. Commands that resume the target block until
        the next stop, like `cont()`/`run()`."""
        ...
    def debug_log(self, since_seq: int = 0) -> Record:
        """Captured guest debug output (DbgPrint) since sequence `since_seq`;
        returns a cursored snapshot for polling. Empty on gdb/memory backends."""
        ...
    def notices(self) -> list[str]:
        """Drain the diagnostics the debugger raised since the last call (a
        breakpoint that failed to re-arm at a stop, a reclaimed stranded
        breakpoint slot, host memory that stopped matching after a reload).
        The REPL prints these as warnings; the SDK leaves them to you."""
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
    (e.g. `ImageFileName`), other arrays a `list` of elements decoded by the
    same rules (struct elements are child cursors, e.g.
    `drv.MajorFunction[14]`), other sized aggregates `bytes`, and nested
    struct/union fields a child `Struct` (so accesses chain). Pointer fields
    return the raw address; use `follow()` for a typed deref. `cursor[i]` with
    an int is typed-pointer indexing: the cursor `i` elements along.
    """

    addr: int
    type_name: str
    fields: list[str]
    size: int
    def cast(self, type_name: str) -> Struct:
        """Reinterpret this address as another PDB type (`(OTHER*)addr`)."""
        ...
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
    def __getitem__(self, key: str | int) -> Any:
        """`cursor["Field"]` reads a field; `cursor[i]` returns the sibling cursor
        `i` elements along (`addr + i * size`)."""
        ...
    def __dir__(self) -> list[str]: ...
    def __repr__(self) -> str: ...
