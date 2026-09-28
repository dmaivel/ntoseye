"""Results from a live guest hold what the checked-in stub says they do: every
property of every result class, recursively, including what each
`Diagnostic` holds, and each result has exactly the fields its class
declares (see `conftest.py`)."""

from __future__ import annotations

import ast
from collections.abc import Callable, Iterable
from pathlib import Path

import ntoseye
from ntoseye import BaseRecord, Debugger, Diagnostic, Record

STUB = ast.parse(Path(ntoseye.__file__).with_name("_ntoseye.pyi").read_text())
CLASSES = {node.name: node for node in STUB.body if isinstance(node, ast.ClassDef)}
BUILTINS: dict[str, type] = {
    "str": str,
    "bool": bool,
    "bytes": bytes,
    "float": float,
}


def returns(cls: str, name: str) -> ast.expr:
    """The stub's return annotation of `cls.name` (a method or property)."""
    for node in CLASSES[cls].body:
        if isinstance(node, ast.FunctionDef) and node.name == name and node.returns:
            return node.returns
    raise LookupError(f"{cls}.{name} is not in the stub")


def every(checks: Iterable[bool]) -> bool:
    """Whether every check passed, running them all so each mismatch is
    recorded."""
    return all(list(checks))


class Checker:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.forms: set[str] = set()

    def value(self, value: object, hint: ast.expr, path: str) -> bool:
        """Whether `value` is of type `hint`, recording why not."""
        errors = len(self.errors)
        ok = self._value(value, hint, path)
        if ok:
            del self.errors[errors:]
        return ok

    def _value(self, value: object, hint: ast.expr, path: str) -> bool:
        if isinstance(hint, ast.BinOp) and isinstance(hint.op, ast.BitOr):
            return self.value(value, hint.left, path) or self.value(value, hint.right, path)
        if isinstance(hint, ast.Constant) and hint.value is None:
            return self.fail(value is None, path, value, "None")
        if isinstance(hint, ast.Subscript):
            return self.generic(value, ast.unparse(hint.value), hint.slice, path)
        assert isinstance(hint, ast.Name), ast.unparse(hint)
        if hint.id == "Any":
            return True
        if hint.id == "int":
            return self.fail(isinstance(value, int) and not isinstance(value, bool), path, value, "int")
        if hint.id in BUILTINS:
            return self.fail(isinstance(value, BUILTINS[hint.id]), path, value, hint.id)
        if not self.fail(isinstance(value, getattr(ntoseye, hint.id)), path, value, hint.id):
            return False
        return not isinstance(value, BaseRecord) or self.record(value, path)

    def generic(self, value: object, base: str, args: ast.expr, path: str) -> bool:
        items = args.elts if isinstance(args, ast.Tuple) else [args]
        if base == "list":
            if not isinstance(value, list):
                return self.fail(False, path, value, "list")
            return every(self.value(item, items[0], f"{path}[{i}]") for i, item in enumerate(value))
        if base == "dict":
            if not isinstance(value, dict):
                return self.fail(False, path, value, "dict")
            return every(self.value(v, items[1], f"{path}[{k!r}]") for k, v in value.items())
        assert base == "Diagnostic", base
        if not isinstance(value, Diagnostic):
            return self.fail(False, path, value, "Diagnostic")
        self.forms.add("available" if value.available else "unavailable")
        if value.source is not None:
            self.forms.add("source")
        if not value.available:
            return self.fail(value.value is None, path, value.value, "None (unavailable)")
        return self.value(value.value, items[0], f"{path}.value")

    def record(self, record: BaseRecord, path: str) -> bool:
        if isinstance(record, Record):
            self.forms.add("Record")
            return True
        self.forms.add("class")
        cls = type(record).__name__
        properties = [
            node.name
            for node in CLASSES[cls].body
            if isinstance(node, ast.FunctionDef)
            and any(ast.unparse(d) == "property" for d in node.decorator_list)
        ]
        self.fail(len(properties) == len(record), path, record, f"{len(properties)} fields")
        return every(
            self.value(getattr(record, name), returns(cls, name), f"{path}.{name}")
            for name in properties
        )

    def fail(self, ok: bool, path: str, value: object, expected: str) -> bool:
        if not ok:
            self.errors.append(f"{path}: {type(value).__name__} {value!r:.60} is not {expected}")
        return ok


def results(dbg: Debugger) -> list[tuple[object, str, Callable[[], object]]]:
    """(owner, method, call) for results that hold every kind of field: nested
    classes, unions, lists, `Record`s, diagnostics that did and did not read,
    and metrics with a source."""
    inspect = dbg.inspect
    cpu = next(iter(dbg.cpus))
    user = next(p for p in dbg.processes if p.name.lower() in {"lsass.exe", "explorer.exe", "svchost.exe"})
    heap = next(iter(user.heaps))
    kernel = dbg.modules["nt"]
    thread = next(t for t in user.threads if t.teb is not None)
    return [
        (inspect, "vm", inspect.vm),
        (inspect, "version", inspect.version),
        (inspect, "time", inspect.time),
        (inspect, "pci", inspect.pci),
        (inspect, "devnode", inspect.devnode),
        (inspect, "running", lambda: inspect.running(include_idle=True, include_stacks=True)),
        (inspect, "dpcs", inspect.dpcs),
        (inspect, "ipi", inspect.ipi),
        (inspect, "timers", inspect.timers),
        (inspect, "peb", lambda: inspect.peb(user)),
        (inspect, "teb", lambda: inspect.teb(thread)),
        (cpu, "pcr", cpu.pcr),
        (cpu, "prcb", cpu.prcb),
        (cpu, "gdt", cpu.gdt),
        (cpu, "idt", cpu.idt),
        (user, "token", user.token),
        (user, "handles", user.handles),
        (heap, "inspect", heap.inspect),
        (kernel, "inspect", kernel.inspect),
        (kernel, "headers", lambda: kernel.headers(exports=True, imports=True)),
        (kernel, "image_info", kernel.image_info),
        (thread, "inspect", thread.inspect),
    ]


def test_results_match_their_stub_types(halted: Debugger) -> None:
    checker = Checker()
    for owner, method, call in results(halted):
        checker.value(call(), returns(type(owner).__name__, method), f"{type(owner).__name__}.{method}()")
    assert checker.errors == []
    # The sample must keep exercising every kind of field.
    assert checker.forms >= {"class", "Record", "available", "unavailable", "source"}
