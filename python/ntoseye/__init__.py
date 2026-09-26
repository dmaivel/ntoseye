"""Python SDK for the ntoseye Windows kernel debugger.

    import ntoseye

    with ntoseye.attach() as dbg:
        nt = dbg.modules["nt"]
        for proc in dbg.processes:
            print(proc.pid, proc.name)
        bp = dbg.breakpoints.add("nt!NtCreateFile")
        stop = dbg.run(timeout=5.0)
        if stop is not None and bp in stop.breakpoints:
            print(stop.thread.backtrace())

See `docs/scripting/sdk.md` and `examples/` for more.
"""

from ._ntoseye import *  # noqa: F403 (every class and function the extension exports)
from ._ntoseye import __version__


class NtoseyeError(Exception):
    """Base class for every error the SDK raises."""


class MemoryAccessError(NtoseyeError):
    """A guest memory access fault: an unmapped page, or a partial read or
    write."""


class TargetRunningError(NtoseyeError):
    """The operation needs a halted target; `interrupt()` first."""


class StaleHandleError(NtoseyeError):
    """The handle is from before the target was rebuilt (a reboot); re-query
    it."""


class SymbolNotFoundError(NtoseyeError, LookupError):
    """A symbol that does not resolve; also a `LookupError`, like any mapping
    miss."""
