#!/usr/bin/env python3
"""Inspect processes with reflective `_EPROCESS` cursors.

`dbg.processes()` yields `_EPROCESS` cursors whose fields are plain attributes -
`proc.UniqueProcessId`, `proc.ImageFileName`; with no type ever restated.
Nested structs chain (`proc.Pcb.DirectoryTableBase`), and `proc.threads()` walks
the thread list to `_ETHREAD` cursors. Uses the passive `memory` backend.

    python3 walk_struct.py
"""

import argparse
import ntoseye

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--backend", default="memory", choices=["memory", "gdb", "kd"])
    ap.add_argument("--connect", default=None)
    args = ap.parse_args()

    dbg = ntoseye.attach(backend=args.backend, connect=args.connect)

    header = f"  {'PID':>6}  {'ImageFileName':<16}  {'DirBase':>18}  {'#Thr':>5}  EPROCESS"
    print(header)
    for proc in sorted(dbg.processes(), key=lambda p: p.UniqueProcessId)[:12]:
        image = proc.ImageFileName               # CHAR[15] auto-decodes to str
        dir_base = proc.Pcb.DirectoryTableBase  # nested _KPROCESS, chained
        nthreads = len(proc.threads())          # _ETHREAD list walk
        print(f"  {proc.UniqueProcessId:>6}  {image:<16}  {dir_base:#18x}  {nthreads:>5}  {proc.addr:#x}")


if __name__ == "__main__":
    main()
