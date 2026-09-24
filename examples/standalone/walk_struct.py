#!/usr/bin/env python3
"""Inspect processes with reflective `_EPROCESS` cursors.

`dbg.processes` yields process handles; each `.object` is a live `_EPROCESS`
cursor. Nested structs chain (`entry.Pcb.DirectoryTableBase`), and process
threads are available through the process-bound `proc.threads` namespace.
Uses the passive `memory` backend.

    python3 walk_struct.py
"""

import argparse
import ntoseye


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--backend", default="memory", choices=["memory", "gdb", "kd"])
    ap.add_argument("--connect", default=None)
    args = ap.parse_args()

    with ntoseye.attach(backend=args.backend, connect=args.connect) as dbg:
        header = f"  {'PID':>6}  {'ImageFileName':<16}  {'DirBase':>18}  {'#Thr':>5}  EPROCESS"
        print(header)
        for proc in sorted(dbg.processes, key=lambda p: p.pid)[:12]:
            entry = proc.object
            image = entry.ImageFileName
            dir_base = entry.Pcb.DirectoryTableBase
            print(
                f"  {proc.pid:>6}  {image:<16}  {dir_base:#18x}  "
                f"{len(proc.threads):>5}  {entry.addr:#x}"
            )


if __name__ == "__main__":
    main()
