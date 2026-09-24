"""The SDK surface that needs no target: exceptions, argument validation,
the REPL-only helpers, and the checked-in stub matching the built module."""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

import ntoseye
import ntoseye.repl
from ntoseye import _ntoseye as native


def test_native_errors_raise_the_package_classes() -> None:
    # Port 1 refuses at once; the error comes from Rust and must be the class
    # defined in `ntoseye/__init__.py`, not a private native copy.
    with pytest.raises(ntoseye.NtoseyeError):
        ntoseye.attach("gdb", "127.0.0.1:1")


@pytest.mark.parametrize(
    "kwargs", [{"backend": "windbg"}, {"backend": "dmp"}, {"backend": "kdnet"}]
)
def test_attach_rejects_bad_arguments_before_connecting(kwargs: dict[str, str]) -> None:
    # A spelling outside the Literal, a dump without its path, and kdnet
    # without its key.
    with pytest.raises(ValueError):
        ntoseye.attach(**kwargs)  # type: ignore[arg-type]


def test_decode_error_needs_no_target() -> None:
    record = ntoseye.decode_error(0xC0000005)
    assert record.name == "STATUS_ACCESS_VIOLATION"
    assert record.kind == "NTSTATUS"


def test_repl_commands_raise_outside_the_repl() -> None:
    with pytest.raises(RuntimeError):

        @ntoseye.repl.command("y", "help", pid=ntoseye.repl.Process)
        def y(dbg: ntoseye.Debugger, pid: str) -> None: ...


def _public(names: object) -> set[str]:
    return {name for name in names if not name.startswith("_")}  # type: ignore[attr-defined]


def _stub_members(node: ast.ClassDef | ast.Module) -> dict[str, ast.AST]:
    members: dict[str, ast.AST] = {}
    for child in node.body:
        if isinstance(child, (ast.FunctionDef, ast.ClassDef)):
            members[child.name] = child
        elif isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Name):
            members[child.target.id] = child
    return members


def _compare(runtime: object, stub: ast.ClassDef | ast.Module, path: str) -> list[str]:
    stub_members = _stub_members(stub)
    runtime_names = _public(vars(runtime))
    problems = [f"{path}.{name}: not in the stub" for name in runtime_names - stub_members.keys()]
    problems += [
        f"{path}.{name}: in the stub only" for name in _public(stub_members) - runtime_names
    ]
    for name in runtime_names & stub_members.keys():
        member = getattr(runtime, name)
        node = stub_members[name]
        if inspect.isclass(member) and isinstance(node, ast.ClassDef):
            problems += _compare(member, node, f"{path}.{name}")
    return problems


def test_checked_in_stub_matches_the_built_module() -> None:
    # The wheel ships `_ntoseye.pyi` as checked in. Regenerate it with
    # `maturin develop --generate-stubs` after changing the Rust surface.
    stub = Path(native.__file__).with_name("_ntoseye.pyi")
    tree = ast.parse(stub.read_text(), filename=str(stub))
    assert _compare(native, tree, "_ntoseye") == []
