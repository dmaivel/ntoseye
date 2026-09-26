"""Generated reference pages for the ntoseye documentation.

`reference/commands/` is written from the REPL command registry, one page per
category (the grouping `.hh` prints), each command a `command` object that
`` {command}`name` `` links to under any of its names.

`reference/command-line/` is `ntoseye --help` and each subcommand's.

`reference/sdk/` is written from the Python SDK's checked-in type stub
(`python/ntoseye/_ntoseye.pyi`) and `ntoseye.repl`, one page per class.

These directories are regenerated on every build and are not checked in. The
command and command-line help come from `ntoseye --dump-command-reference`: the
JSON file named by `NTOSEYE_COMMAND_REFERENCE`, or else `cargo run` in the
repository.
"""

from __future__ import annotations

import ast
import builtins
import copy
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from docutils.parsers.rst import directives
from sphinx.application import Sphinx
from sphinx.domains.std import GenericObject
from sphinx.errors import ExtensionError
from sphinx.ext import intersphinx
from sphinx.roles import XRefRole

ROOT = Path(__file__).resolve().parents[2]
STUB = ROOT / "python" / "ntoseye" / "_ntoseye.pyi"
REPL_MODULE = ROOT / "python" / "ntoseye" / "repl.py"

# Reading order of the command categories; any category not listed follows,
# alphabetically, so a new one still gets a page.
CATEGORY_ORDER = [
    "execution and stack",
    "breakpoints and events",
    "memory and disassembly",
    "symbols, types, and expressions",
    "processes and modules",
    "user mode",
    "cpu",
    "memory manager",
    "objects and I/O",
    "security",
    "analysis",
    "target control",
    "session",
]
CATEGORY_TITLES = {"cpu": "CPU"}

# Special methods a reader calls through syntax, and so worth listing.
PROTOCOL_METHODS = {
    "__call__",
    "__contains__",
    "__delitem__",
    "__enter__",
    "__exit__",
    "__getattr__",
    "__getitem__",
    "__iter__",
    "__len__",
    "__setattr__",
    "__setitem__",
}


# ---------------------------------------------------------------------------
# The `command` object type


class CommandDirective(GenericObject):
    """A REPL command: its canonical name is the signature, and `:aliases:`
    names it too, so a role naming any alias links here.

    The anchor spells punctuation out (`.vtlcxr` is `command-dot-vtlcxr`). The
    default keeps dots, and the search page rebuilds an anchor from the name
    split at its last dot, so a dot command's hit would miss its target."""

    option_spec = {**GenericObject.option_spec, "aliases": directives.unchanged}

    def handle_signature(self, sig: str, signode) -> str:
        name = super().handle_signature(sig, signode)
        signode["_toc_name"] = name
        return name

    def add_target_and_index(self, name: str, sig: str, signode) -> None:
        node_id = f"command-{anchor(name)}"
        signode["ids"].append(node_id)
        self.state.document.note_explicit_target(signode)
        std = self.env.domains.standard_domain
        for each in [name, *self.options.get("aliases", "").split()]:
            std.note_object(self.objtype, each, node_id, location=signode)
            self.indexnode["entries"].append(
                ("pair", f"{each}; command", node_id, "", None)
            )

    def _object_hierarchy_parts(self, sig_node) -> tuple[str, ...]:
        return (sig_node["_toc_name"],)

    def _toc_entry_name(self, sig_node) -> str:
        return sig_node["_toc_name"]


PUNCTUATION = {".": "dot-", "!": "bang-", "~": "tilde", "?": "question", "+": "-plus"}


class CommandRole(XRefRole):
    """`` {command}`!process` `` links to `!process`. Sphinx roles read a
    leading `!` as 'do not link' and drop it, which would turn every
    extension command into plain text; here the name keeps it."""

    def run(self):
        self.disabled = False
        return super().run()


def anchor(name: str) -> str:
    """Case is kept: `ds` and `dS` are different commands."""
    spelled = "".join(PUNCTUATION.get(c, c) for c in name)
    return re.sub(r"[^A-Za-z0-9]+", "-", spelled).strip("-")


# ---------------------------------------------------------------------------
# Command reference


def load_reference() -> dict:
    """`{"cli": [...], "commands": [...]}` from `--dump-command-reference`."""
    path = os.environ.get("NTOSEYE_COMMAND_REFERENCE")
    if path:
        return json.loads(Path(path).read_text())
    run = subprocess.run(
        [
            "cargo",
            "run",
            "--release",
            "--quiet",
            "--bin",
            "ntoseye",
            "--",
            "--dump-command-reference",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if run.returncode != 0:
        raise ExtensionError(
            "ntoseye --dump-command-reference failed "
            "(set NTOSEYE_COMMAND_REFERENCE to a saved dump to skip the build):\n"
            + run.stderr
        )
    return json.loads(run.stdout)


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def title(category: str) -> str:
    return CATEGORY_TITLES.get(category, category[0].upper() + category[1:])


def command_pages(commands: list[dict]) -> dict[str, str]:
    pages = {}
    by_category: dict[str, list[dict]] = {}
    for command in commands:
        by_category.setdefault(command["category"], []).append(command)
    categories = [c for c in CATEGORY_ORDER if c in by_category] + sorted(
        c for c in by_category if c not in CATEGORY_ORDER
    )

    index = [
        "# Commands",
        "",
        "Every command the REPL accepts, grouped as `.hh` lists them. The text is",
        "the REPL's own help: `.hh <command>` prints the same.",
        "",
        "```{toctree}",
        ":maxdepth: 1",
        "",
        *(slug(category) for category in categories),
        "```",
        "",
    ]
    pages["index.md"] = "\n".join(index)

    for category in categories:
        lines = [f"# {title(category)}", ""]
        for command in sorted(by_category[category], key=lambda c: c["names"][0]):
            canonical, *aliases = command["names"]
            lines.append(f":::{{command}} {canonical}")
            if aliases:
                lines.append(f":aliases: {' '.join(aliases)}")
            lines.append("")
            lines.append(command["summary"])
            lines.append("")
            lines.append("```text")
            lines.append(command["usage"])
            lines.append("```")
            if aliases:
                lines.append("")
                lines.append("Also: " + ", ".join(f"`{alias}`" for alias in aliases))
            if command["details"]:
                lines.append("")
                lines.append(command["details"])
            lines.append(":::")
            lines.append("")
        pages[f"{slug(category)}.md"] = "\n".join(lines)
    return pages


# ---------------------------------------------------------------------------
# Command-line reference


def command_line_pages(cli: list[dict]) -> dict[str, str]:
    """One page: `ntoseye --help`, then each subcommand's."""
    lines = [
        "# Command line",
        "",
        "`ntoseye --help` and each subcommand's `--help`, as the installed",
        "binary prints them. Options listed for `ntoseye` itself go before or",
        "after a subcommand.",
        "",
    ]
    for entry in cli:
        heading = "Usage" if entry["name"] == "ntoseye" else f"`{entry['name']}`"
        lines += [f"## {heading}", "", "```text", entry["help"].rstrip(), "```", ""]
    return {"index.md": "\n".join(lines)}


# ---------------------------------------------------------------------------
# SDK reference


class Qualify(ast.NodeTransformer):
    """Spell imported typing names out in full, so the Python domain resolves
    them against the Python docs (`python_use_unqualified_type_names` shows
    them short again). A builtin type named like a documented member (`object`
    beside `Process.object`) is spelled `builtins.object`: bare, the Python
    domain would match the member by suffix. `resolve_builtin` maps it back."""

    def __init__(
        self, imports: dict[str, str], members: frozenset[str] | set[str] = frozenset()
    ) -> None:
        self.imports = imports
        self.members = members

    def visit_Name(self, node: ast.Name) -> ast.AST:
        full = self.imports.get(node.id)
        if full is None and node.id in self.members and isinstance(
            getattr(builtins, node.id, None), type
        ):
            full = f"builtins.{node.id}"
        if full is None:
            return node
        module, _, name = full.rpartition(".")
        value: ast.expr = ast.Name(module.split(".")[0])
        for part in module.split(".")[1:]:
            value = ast.Attribute(value, part)
        return ast.copy_location(ast.Attribute(value, name), node)


def imported_names(module: ast.Module) -> dict[str, str]:
    names = {}
    for node in module.body:
        if isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            for alias in node.names:
                names[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return names


def annotation(node: ast.expr | None, qualify: Qualify) -> str | None:
    if node is None:
        return None
    return ast.unparse(qualify.visit(copy.deepcopy(node)))


def signature(fn: ast.FunctionDef, qualify: Qualify, method: bool) -> str:
    args = qualify.visit(copy.deepcopy(fn.args))
    if method and not is_static(fn):
        if args.posonlyargs:
            args.posonlyargs.pop(0)
        elif args.args:
            args.args.pop(0)
    text = f"{fn.name}({ast.unparse(args)})"
    returns = annotation(fn.returns, qualify)
    return f"{text} -> {returns}" if returns else text


def decorators(fn: ast.FunctionDef | ast.ClassDef) -> set[str]:
    names = set()
    for decorator in fn.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if isinstance(target, ast.Name):
            names.add(target.id)
        elif isinstance(target, ast.Attribute):
            names.add(target.attr)
    return names


def is_static(fn: ast.FunctionDef) -> bool:
    return "staticmethod" in decorators(fn)


def docstring(node: ast.AST) -> str:
    return ast.get_docstring(node) or ""


def public(name: str) -> bool:
    return not name.startswith("_") or name in PROTOCOL_METHODS


def attribute_docs(body: list[ast.stmt]) -> dict[str, str]:
    """Docstrings written as a string literal right after an assignment."""
    docs = {}
    for first, second in zip(body, body[1:]):
        target = None
        if isinstance(first, ast.AnnAssign) and isinstance(first.target, ast.Name):
            target = first.target.id
        elif isinstance(first, ast.Assign) and isinstance(first.targets[0], ast.Name):
            target = first.targets[0].id
        if (
            target
            and isinstance(second, ast.Expr)
            and isinstance(second.value, ast.Constant)
            and isinstance(second.value.value, str)
        ):
            docs[target] = ast.get_docstring(ast.Module([second], []), clean=True) or ""
    return docs


class Block:
    """A directive and the blocks nested in it, fenced with enough colons to
    contain them."""

    def __init__(self, head: str, options: list[str], body: str) -> None:
        self.head = head
        self.options = options
        self.body = body
        self.children: list[Block] = []

    def depth(self) -> int:
        return 1 + max((child.depth() for child in self.children), default=0)

    def render(self) -> str:
        fence = ":" * (2 + self.depth())
        lines = [f"{fence}{{{self.head}", *self.options, ""]
        if self.body:
            lines += [self.body, ""]
        for child in self.children:
            lines += [child.render(), ""]
        lines.append(fence)
        return "\n".join(lines)


def class_block(node: ast.ClassDef, qualify: Qualify) -> Block:
    options = []
    if "final" in decorators(node):
        options.append(":final:")
    body = docstring(node)
    bases = [ast.unparse(base) for base in node.bases]
    if bases:
        links = ", ".join(f"{{py:class}}`{base}`" for base in bases)
        body = f"Subclass of {links}.\n\n{body}".strip()
    block = Block(f"py:class}} {node.name}", options, body)

    for child in node.body:
        if isinstance(child, ast.ClassDef) and public(child.name):
            block.children.append(class_block(child, qualify))
        elif isinstance(child, ast.FunctionDef) and public(child.name):
            kinds = decorators(child)
            if "setter" in kinds or "deleter" in kinds:
                continue
            if "property" in kinds:
                options = []
                returns = annotation(child.returns, qualify)
                if returns:
                    options.append(f":type: {returns}")
                block.children.append(
                    Block(f"py:property}} {child.name}", options, docstring(child))
                )
                continue
            options = []
            if "staticmethod" in kinds:
                options.append(":staticmethod:")
            if "classmethod" in kinds:
                options.append(":classmethod:")
            block.children.append(
                Block(
                    f"py:method}} {signature(child, qualify, method=True)}",
                    options,
                    docstring(child),
                )
            )
    return block


def data_block(name: str, type_: str | None, doc: str) -> Block:
    return Block(f"py:data}} {name}", [f":type: {type_}"] if type_ else [], doc)


def sdk_pages() -> dict[str, str]:
    pages = {}
    stub = ast.parse(STUB.read_text())
    members = {
        node.name
        for node in ast.walk(stub)
        if isinstance(node, (ast.FunctionDef, ast.ClassDef))
    }
    qualify = Qualify(imported_names(stub), members)
    docs = attribute_docs(stub.body)

    classes = sorted(
        (node for node in stub.body if isinstance(node, ast.ClassDef) and public(node.name)),
        key=lambda node: node.name.lower(),
    )
    module_blocks = []
    for node in stub.body:
        if isinstance(node, ast.FunctionDef) and public(node.name):
            module_blocks.append(
                Block(
                    f"py:function}} {signature(node, qualify, method=False)}",
                    [],
                    docstring(node),
                )
            )
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            module_blocks.append(
                data_block(
                    node.target.id,
                    annotation(node.annotation, qualify),
                    docs.get(node.target.id, ""),
                )
            )

    for node in classes:
        page = [
            f"# {node.name}",
            "",
            "```{py:currentmodule} ntoseye",
            "```",
            "",
            class_block(node, qualify).render(),
            "",
        ]
        pages[f"{node.name}.md"] = "\n".join(page)

    index = [
        "# Python API",
        "",
        "The `ntoseye` package's API, generated from the type stub the package",
        "ships. For how the pieces fit together, see the [SDK guide](../../scripting/sdk.md).",
        "",
        "## Module `ntoseye`",
        "",
        "```{py:module} ntoseye",
        "```",
        "",
        *(block.render() + "\n" for block in module_blocks),
        "## Module `ntoseye.repl`",
        "",
        repl_module_markdown(),
        "",
        "## Classes",
        "",
        "```{toctree}",
        ":maxdepth: 1",
        "",
        *(node.name for node in classes),
        "```",
        "",
    ]
    pages["index.md"] = "\n".join(index)
    return pages


def repl_module_markdown() -> str:
    """`ntoseye.repl`: its registration functions and completion markers, in
    `__all__` order. Functions defined in either branch of a `try` count."""
    module = ast.parse(REPL_MODULE.read_text())
    qualify = Qualify(imported_names(module))
    exported = next(
        (
            [ast.literal_eval(element) for element in node.value.elts]
            for node in module.body
            if isinstance(node, ast.Assign)
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "__all__"
        ),
        [],
    )

    functions: dict[str, ast.FunctionDef] = {}
    markers: dict[str, str] = {}
    for node in ast.walk(module):
        if isinstance(node, ast.FunctionDef) and node.col_offset <= 4:
            functions.setdefault(node.name, node)
    for node in module.body:
        if (
            isinstance(node, ast.Assign)
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id == "_Completion"
        ):
            markers[node.targets[0].id] = ast.literal_eval(node.value.args[0])

    blocks = [
        "```{py:module} ntoseye.repl",
        "```",
        "",
        docstring(module),
        "",
    ]
    for name in exported:
        if name in functions:
            fn = functions[name]
            blocks.append(
                Block(
                    f"py:function}} {signature(fn, qualify, method=False)}",
                    [],
                    docstring(fn),
                ).render()
            )
        elif name in markers:
            blocks.append(
                data_block(
                    name,
                    None,
                    f"Completion marker: binds a command parameter to "
                    f"{markers[name]} completion in `command(..., param={name})`.",
                ).render()
            )
        elif name == "Debugger":
            blocks.append(
                "`Debugger` is re-exported from `ntoseye`; a command receives a "
                "borrowed {py:class}`ntoseye.Debugger`."
            )
        else:
            raise ExtensionError(f"ntoseye.repl exports {name!r}, which the docs do not know")
        blocks.append("")
    return "\n".join(blocks)


# ---------------------------------------------------------------------------


def resolve_builtin(app: Sphinx, env, node, contnode):
    """Resolve `builtins.X`, which `Qualify` writes for a builtin that
    collides with a member name, as the Python docs' bare `X`."""
    target = node.get("reftarget", "")
    if node.get("refdomain") != "py" or not target.startswith("builtins."):
        return None
    bare = node.deepcopy()
    bare["reftarget"] = target.removeprefix("builtins.")
    return intersphinx.missing_reference(app, env, bare, contnode)


def generate(app: Sphinx) -> None:
    reference = Path(app.srcdir) / "reference"
    dump = load_reference()
    sync(reference / "commands", command_pages(dump["commands"]))
    sync(reference / "command-line", command_line_pages(dump["cli"]))
    sync(reference / "sdk", sdk_pages())


def sync(out: Path, pages: dict[str, str]) -> None:
    """Make `out` hold exactly `pages`, touching only files that differ.
    Rewriting unchanged pages would make Sphinx reread them and would set a
    file watcher such as sphinx-autobuild rebuilding forever."""
    out.mkdir(parents=True, exist_ok=True)
    for stale in out.iterdir():
        if stale.name not in pages:
            if stale.is_dir():
                shutil.rmtree(stale)
            else:
                stale.unlink()
    for name, text in pages.items():
        path = out / name
        if not path.exists() or path.read_text() != text:
            path.write_text(text)


def root_404(app: Sphinx, exception: Exception | None) -> None:
    """Cloudflare answers a missing path with the site's `/404.html`, but the
    dirhtml builder writes the not-found page as `404/index.html`. Its links
    are absolute (`notfound_urls_prefix`), so a copy works at the root."""
    if exception is not None or app.builder.name != "dirhtml":
        return
    page = Path(app.outdir) / "404" / "index.html"
    if page.exists():
        shutil.copyfile(page, Path(app.outdir) / "404.html")


def setup(app: Sphinx) -> dict:
    app.add_object_type(
        "command", "command", indextemplate="pair: %s; command", objname="REPL command"
    )
    app.add_directive_to_domain("std", "command", CommandDirective, override=True)
    app.add_role_to_domain("std", "command", CommandRole(), override=True)
    app.connect("builder-inited", generate)
    app.connect("missing-reference", resolve_builtin)
    app.connect("build-finished", root_404)
    return {"parallel_read_safe": True, "parallel_write_safe": True}
