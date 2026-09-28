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

from __future__ import annotations

from typing import Any, Generic, TypeVar, final

from ._ntoseye import *  # noqa: F403 (every class and function the extension exports)
from ._ntoseye import BaseRecord, __version__

_T = TypeVar("_T")


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


@final
class Diagnostic(Generic[_T]):
    """One field that reads on its own and can fail: `value` when it read,
    `error` when it did not. Truthy exactly when available. Generic over its
    value: a property typed `Diagnostic[int]` reads an `int`."""

    __slots__ = ("_value", "_error", "_source", "_metric", "_hex")

    def __init__(
        self, value: _T | None, error: str | None, source: str | None, metric: bool, hex: bool
    ) -> None:
        self._value = value
        self._error = error
        self._source = source
        self._metric = metric
        self._hex = hex

    @property
    def value(self) -> _T | None:
        """The value read; `None` when unavailable (or when `None` was read)."""
        return self._value

    @property
    def error(self) -> str | None:
        """Why the value could not be read; `None` when it was."""
        return self._error

    @property
    def available(self) -> bool:
        """Whether the value was read."""
        return self._error is None

    @property
    def source(self) -> str | None:
        """Where a metric's value came from (`"dump header"`, `"KDBG"`, ...);
        `None` for a field that is not a metric, or an unknown source."""
        return self._source

    def __bool__(self) -> bool:
        return self._error is None

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Diagnostic):
            return NotImplemented
        return (self._value, self._error, self._source, self._metric) == (
            other._value,
            other._error,
            other._source,
            other._metric,
        )

    __hash__ = None  # type: ignore[assignment]

    def __repr__(self) -> str:
        if self._error is not None:
            return f"Diagnostic(error={self._error!r})"
        if self._hex and isinstance(self._value, int):
            return f"Diagnostic({self._value:#x})"
        return f"Diagnostic({_summary(self._value)})"

    def to_dict(self) -> dict[str, Any]:
        """The `{available, value, error[, source]}` dict the MCP surface
        returns (`source` only for a metric)."""
        out: dict[str, Any] = {
            "available": self._error is None,
            "value": _plain(self._value),
            "error": self._error,
        }
        if self._metric:
            out["source"] = self._source
        return out


def _summary(value: object) -> str:
    """A one-line rendering: scalars in full, records and lists by size."""
    if isinstance(value, BaseRecord):
        return f"{type(value).__name__}(<{len(value)} fields>)"
    if isinstance(value, list):
        return f"[<{len(value)} items>]"
    return repr(value)


def _plain(value: object) -> object:
    """`value` with records and diagnostics converted to dicts throughout."""
    if isinstance(value, (BaseRecord, Diagnostic)):
        return value.to_dict()
    if isinstance(value, list):
        return [_plain(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_plain(item) for item in value)
    return value
