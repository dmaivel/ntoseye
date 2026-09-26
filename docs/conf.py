import sys
import tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "_ext"))

with open(HERE.parent / "Cargo.toml", "rb") as cargo:
    release = tomllib.load(cargo)["workspace"]["package"]["version"]

project = "ntoseye"
author = "dmaivel"
copyright = "dmaivel"
version = release

extensions = [
    "myst_parser",
    "sphinx.ext.intersphinx",
    "ntoseye_docs",
]

# A toolchain virtualenv kept in `docs/.venv` would otherwise be read as
# pages: its packages ship READMEs and templates.
exclude_patterns = ["_build", ".venv"]

myst_enable_extensions = ["colon_fence"]
# Anchors for `page.md#heading` links, as GitHub slugs them.
myst_heading_anchors = 4

intersphinx_mapping = {"python": ("https://docs.python.org/3", None)}
python_use_unqualified_type_names = True
# Private SDK types (`_F`, `_Completion`) appear in signatures but are not
# documented on purpose.
nitpick_ignore_regex = [("py:class", r"_\w+")]

html_theme = "furo"
html_static_path = ["_static"]
html_js_files = ["sidebar-scroll.js"]
html_title = "ntoseye"
html_logo = "../media/ntoseye.svg"
html_theme_options = {
    "source_repository": "https://github.com/dmaivel/ntoseye/",
    "source_branch": "master",
    "source_directory": "docs/",
}
