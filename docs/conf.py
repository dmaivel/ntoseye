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
    "notfound.extension",
    "sphinx.ext.intersphinx",
    "ntoseye_docs",
]

# A toolchain virtualenv kept in `docs/.venv`, or `wrangler dev`'s local state
# in `docs/.wrangler`, would otherwise be read as pages.
exclude_patterns = ["_build", ".venv", ".wrangler"]

myst_enable_extensions = ["colon_fence"]
# Anchors for `page.md#heading` links, as GitHub slugs them.
myst_heading_anchors = 4

intersphinx_mapping = {"python": ("https://docs.python.org/3", None)}
python_use_unqualified_type_names = True
# Private SDK types (`_F`, `_Completion`) appear in signatures but are not
# documented on purpose.
nitpick_ignore_regex = [("py:class", r"_\w+")]

html_theme = "furo"
# The site is built with `-b dirhtml` and served from the domain root, so pages
# are `ntoseye.com/<path>/`, the URLs Cloudflare serves without a redirect.
html_baseurl = "https://ntoseye.com/"
html_static_path = ["_static"]
html_js_files = ["sidebar-scroll.js"]

# Cloudflare serves /404.html for any missing path, at any depth, so its links
# must be absolute. The extension's default prefix is Read the Docs' /en/latest/.
notfound_urls_prefix = "/"
notfound_context = {
    "title": "Page not found",
    "body": "<h1>Page not found</h1>\n\n<p>This page does not exist. It may have moved: try the search box, or start from the <a href=\"/\">home page</a>.</p>",
}
html_title = "ntoseye"
html_logo = "../media/ntoseye.svg"
html_theme_options = {
    "source_repository": "https://github.com/dmaivel/ntoseye/",
    "source_branch": "master",
    "source_directory": "docs/",
}
