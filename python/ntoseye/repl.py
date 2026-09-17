"""REPL command scripting helpers for ntoseye.

This module is provided by the embedded ntoseye REPL at script-load time. The
package copy exists so editors can resolve `import ntoseye.repl as repl`, and so
running a REPL command script under a normal Python interpreter fails with a
clear error instead of an import error.
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


def register_command(
    name: str,
    help: str,
    fn: Callable[..., Any],
    strategies: list[str] | None = None,
) -> None:
    raise RuntimeError(
        "ntoseye.repl.register_command is only available inside the ntoseye REPL"
    )


def command(name: str, help: str, **completions: _Completion) -> Callable[[_F], _F]:
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
