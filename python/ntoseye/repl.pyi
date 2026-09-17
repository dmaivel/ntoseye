"""Type stubs for ntoseye in-REPL command scripts."""

from collections.abc import Callable
from typing import Any, TypeVar

from . import Debugger as Debugger

_F = TypeVar("_F", bound=Callable[..., Any])

class _Completion:
    strat: str

Process: _Completion
Symbol: _Completion
Expression: _Completion
Type: _Completion
Driver: _Completion
Thread: _Completion
Vcpu: _Completion
Breakpoint: _Completion
Alias: _Completion

def register_command(
    name: str,
    help: str,
    fn: Callable[..., Any],
    strategies: list[str] | None = None,
) -> None: ...
def command(name: str, help: str, **completions: _Completion) -> Callable[[_F], _F]: ...
