"""Check SDK values against the type annotations the stub declares for them:
unions, lists, dicts, what a `Diagnostic` holds, and a result class's
properties, recursively. Used by `test_stub_types.py` on a live guest, and
run by the Rust tests (`src/view/shape.rs`) against each field wrapper's
declared hint, which the stub prints."""

from __future__ import annotations

import ast
from collections.abc import Iterable, Mapping

import ntoseye
from ntoseye import BaseRecord, Diagnostic, Record

BUILTINS: dict[str, type] = {
    "str": str,
    "bool": bool,
    "bytes": bytes,
    "float": float,
}


def returns(cls: ast.ClassDef, name: str) -> ast.expr:
    """The return annotation of method or property `name` of `cls`."""
    for node in cls.body:
        if isinstance(node, ast.FunctionDef) and node.name == name and node.returns:
            return node.returns
    raise LookupError(f"{cls.name}.{name} is not in the stub")


def every(checks: Iterable[bool]) -> bool:
    """Whether every check passed, running them all so each mismatch is
    recorded."""
    return all(list(checks))


def class_name(hint: ast.expr) -> str | None:
    """The name `hint` gives a class by: `Pcr`, or `ntoseye.Pcr` as a field
    wrapper's hint spells it."""
    if isinstance(hint, ast.Name):
        return hint.id
    if isinstance(hint, ast.Attribute) and ast.unparse(hint.value) == "ntoseye":
        return hint.attr
    return None


class Checker:
    """Records every mismatch in `errors`, and in `forms` the kinds of values
    seen, so a caller can tell its sample exercised them."""

    def __init__(self, classes: Mapping[str, ast.ClassDef]) -> None:
        # The stub's classes: a record of one is checked property by
        # property; a record of a class the stub lacks (a test's), by name.
        self.classes = classes
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
            return self.generic(value, class_name(hint.value), hint.slice, path)
        name = class_name(hint)
        assert name is not None, ast.unparse(hint)
        if name == "Any":
            return True
        if name == "None":
            return self.fail(value is None, path, value, "None")
        if name == "int":
            return self.fail(isinstance(value, int) and not isinstance(value, bool), path, value, "int")
        if name in BUILTINS:
            return self.fail(isinstance(value, BUILTINS[name]), path, value, name)
        cls = getattr(ntoseye, name, None)
        if isinstance(cls, type):
            ok = isinstance(value, cls)
        else:
            ok = type(value).__name__ == name and type(value).__module__ == "ntoseye"
        if not self.fail(ok, path, value, name):
            return False
        return not isinstance(value, BaseRecord) or self.record(value, path)

    def generic(self, value: object, base: str | None, args: ast.expr, path: str) -> bool:
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
        cls = self.classes.get(type(record).__name__)
        if cls is None:
            return True
        properties = [
            node.name
            for node in cls.body
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
