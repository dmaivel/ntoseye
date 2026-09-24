#!/usr/bin/env python3
"""Walk the loaded-module list with reflective struct cursors.

`Type.walk()` follows the intrusive `_LIST_ENTRY` at `PsLoadedModuleList`,
yielding a `_KLDR_DATA_TABLE_ENTRY` cursor per module. `_UNICODE_STRING`
fields auto-decode to `str`; use `cursor["Field"]` when a PDB field name
collides with a cursor attribute. Uses the passive `memory` backend.

    python3 walk_modules.py
"""

import argparse
import ntoseye


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--backend", default="memory", choices=["memory", "gdb", "kd"])
    ap.add_argument("--connect", default=None)
    args = ap.parse_args()

    with ntoseye.attach(backend=args.backend, connect=args.connect) as dbg:
        head = dbg.eval("nt!PsLoadedModuleList")
        entries = dbg.types["_KLDR_DATA_TABLE_ENTRY"].walk(head, "InLoadOrderLinks")

        print(f"{len(entries)} loaded modules\n")
        print(f"  {'DllBase':>18}  {'Size':>9}  Name")
        for entry in entries:
            print(f"  {entry.DllBase:#18x}  {entry.SizeOfImage:>9}  {entry.BaseDllName}")


if __name__ == "__main__":
    main()
