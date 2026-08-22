#!/usr/bin/env python3
"""Walk the loaded-module list with reflective cursors.

`walk_list` follows the intrusive `_LIST_ENTRY` at `PsLoadedModuleList`, yielding
a `_KLDR_DATA_TABLE_ENTRY` cursor per module. `BaseDllName`/`FullDllName` are
`_UNICODE_STRING` fields, so they auto-decode to `str` on attribute access; no
manual Length/Buffer dance. Uses the passive `memory` backend.

    python3 walk_modules.py
"""

import argparse
import ntoseye

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--backend", default="memory", choices=["memory", "gdb", "kd"])
    ap.add_argument("--connect", default=None)
    args = ap.parse_args()

    dbg = ntoseye.attach(backend=args.backend, connect=args.connect)

    head = dbg.eval("PsLoadedModuleList")
    modules = dbg.walk_list("_KLDR_DATA_TABLE_ENTRY", "InLoadOrderLinks", head)

    print(f"{len(modules)} loaded modules\n")
    print(f"  {'DllBase':>18}  {'Size':>9}  Name")
    for m in modules:
        # BaseDllName is a _UNICODE_STRING -> auto-decoded to str.
        print(f"  {m.DllBase:#18x}  {m.SizeOfImage:>9}  {m.BaseDllName}")


if __name__ == "__main__":
    main()
