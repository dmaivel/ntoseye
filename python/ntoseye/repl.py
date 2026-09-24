"""REPL command scripting helpers for ntoseye.

Command scripts in `~/.ntoseye/commands/` import this module. Inside the
REPL (the `ntoseye` command this package installs, or a build with embedded
Python) `register_command` is the REPL's own; anywhere else it raises, so a
command script run outside the REPL fails clearly.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Any, TypeVar

from . import Debugger

_F = TypeVar("_F", bound=Callable[..., Any])


class _Completion:
    __slots__ = ("strat",)

    def __init__(self, strat: str) -> None:
        self.strat = strat


Process = _Completion("process")
Symbol = _Completion("symbol")
Expression = _Completion("expression")
Type = _Completion("type")
Driver = _Completion("driver")
Thread = _Completion("thread")
Vcpu = _Completion("vcpu")
Breakpoint = _Completion("breakpoint")
Alias = _Completion("alias")


try:
    from ._repl_host import register_command  # type: ignore[import-not-found]  # embedded REPL only
except ImportError:

    def register_command(
        name: str,
        help: str,
        fn: Callable[..., Any],
        strategies: list[str] | None = None,
    ) -> None:
        """Register a REPL command called as ``fn(dbg, *raw_args)``; ``dbg`` is
        a borrowed ``Debugger``, valid only until the command returns."""
        raise RuntimeError(
            "ntoseye.repl.register_command is only available inside the ntoseye REPL"
        )


def command(name: str, help: str, **completions: _Completion) -> Callable[[_F], _F]:
    """Decorator form of ``register_command``: keyword arguments bind completion
    markers to the command's parameters by name. ``dbg`` (the first
    parameter) is a borrowed ``Debugger``, valid only until the command
    returns."""
    def deco(fn: _F) -> _F:
        params = list(inspect.signature(fn).parameters)[1:]
        strategies = []
        for param in params:
            marker = completions.get(param)
            strategies.append(marker.strat if isinstance(marker, _Completion) else "none")
        register_command(name, help, fn, strategies)
        return fn

    return deco


__all__ = [
    "Debugger",
    "register_command",
    "command",
    "Process",
    "Symbol",
    "Expression",
    "Type",
    "Driver",
    "Thread",
    "Vcpu",
    "Breakpoint",
    "Alias",
]
