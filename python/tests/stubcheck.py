"""Check SDK values against the type annotations the stub declares for them:
unions, lists, dicts, `Literal`s, what a `Diagnostic` holds, and a result
class's properties (with its base's, for a variant class nested in its base),
recursively. Used by `test_stub_types.py` on a live guest,
and run by the Rust tests (`src/hosts/python/record.rs`, `hints`) against each
field type's declared hint, which the stub prints."""

from __future__ import annotations

import ast
from collections.abc import Iterable, Mapping

import ntoseye
from ntoseye import BaseRecord, Diagnostic

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


def stub_classes(stub: ast.Module) -> dict[str, ast.ClassDef]:
    """The stub's classes by qualified name: `Pcr`, and `Stop.Breakpoint` for
    a variant class nested in its base."""
    classes: dict[str, ast.ClassDef] = {}

    def add(body: list[ast.stmt], prefix: str) -> None:
        for node in body:
            if isinstance(node, ast.ClassDef):
                classes[prefix + node.name] = node
                add(node.body, f"{prefix}{node.name}.")

    add(stub.body, "")
    return classes


def class_name(hint: ast.expr) -> str | None:
    """The qualified name `hint` gives a class by: `Pcr` or `Stop.Breakpoint`,
    or `ntoseye.Pcr` and `typing.Literal` as a field type's hint spells them."""
    if isinstance(hint, ast.Name):
        return hint.id
    if isinstance(hint, ast.Attribute):
        if ast.unparse(hint.value) in ("ntoseye", "typing", "builtins"):
            return hint.attr
        outer = class_name(hint.value)
        return None if outer is None else f"{outer}.{hint.attr}"
    return None


def sdk_class(name: str) -> type | None:
    """The `ntoseye` class with qualified name `name`, if there is one."""
    found: object = ntoseye
    for part in name.split("."):
        found = getattr(found, part, None)
    return found if isinstance(found, type) else None


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
        cls = sdk_class(name)
        if cls is not None:
            ok = isinstance(value, cls)
        else:
            # A class the stub lacks (a test's): by name, through its bases,
            # so a nested variant class is its base's type.
            ok = any(
                c.__qualname__ == name and c.__module__ == "ntoseye" for c in type(value).__mro__
            )
        if not self.fail(ok, path, value, name):
            return False
        return not isinstance(value, BaseRecord) or self.record(value, path)

    def generic(self, value: object, base: str | None, args: ast.expr, path: str) -> bool:
        items = args.elts if isinstance(args, ast.Tuple) else [args]
        if base == "Literal":
            self.forms.add("Literal")
            texts = [item.value for item in items if isinstance(item, ast.Constant)]
            assert len(texts) == len(items), ast.unparse(args)
            ok = isinstance(value, str) and value in texts
            return self.fail(ok, path, value, f"one of {texts}")
        if base == "list":
            if not isinstance(value, list):
                return self.fail(False, path, value, "list")
            return every(self.value(item, items[0], f"{path}[{i}]") for i, item in enumerate(value))
        if base == "dict":
            if not isinstance(value, dict):
                return self.fail(False, path, value, "dict")
            self.forms.add("dict")
            return every(
                self.value(k, items[0], f"{path} key {k!r}")
                and self.value(v, items[1], f"{path}[{k!r}]")
                for k, v in value.items()
            )
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
        self.forms.add("class")
        qualname = type(record).__qualname__
        if "." in qualname:
            self.forms.add("variant")
        cls = self.classes.get(qualname)
        if cls is None:
            return True
        # Each property's declaring class: a variant's own, else its base's.
        properties: dict[str, ast.ClassDef] = {}
        for owner in self.lineage(cls):
            for node in owner.body:
                if (
                    isinstance(node, ast.FunctionDef)
                    and any(ast.unparse(d) == "property" for d in node.decorator_list)
                    and node.name not in properties
                ):
                    properties[node.name] = owner
        fields = len(record.to_dict())
        self.fail(len(properties) == fields, path, record, f"{len(properties)} fields")
        return every(
            self.value(getattr(record, name), returns(owner, name), f"{path}.{name}")
            for name, owner in properties.items()
        )

    def lineage(self, cls: ast.ClassDef) -> list[ast.ClassDef]:
        """`cls`, then the stub classes it derives from, nearest first."""
        found = [cls]
        for base in cls.bases:
            name = class_name(base)
            if name is not None and name in self.classes:
                found += self.lineage(self.classes[name])
        return found

    def fail(self, ok: bool, path: str, value: object, expected: str) -> bool:
        if not ok:
            self.errors.append(f"{path}: {type(value).__name__} {value!r:.60} is not {expected}")
        return ok
