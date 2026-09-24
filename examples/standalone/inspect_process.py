#!/usr/bin/env python3
"""Inspect a process through its address-space-bound views.

A `Process` exposes its own `memory`, `modules`, and `threads`; no global
process selection is needed. Uses the passive `memory` backend.

    python3 inspect_process.py
    python3 inspect_process.py --name explorer.exe
"""

import argparse
import ntoseye


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--backend", default="memory", choices=["memory", "gdb", "kd"])
    ap.add_argument("--connect", default=None)
    ap.add_argument("--name", default="lsass.exe", help="process image name to inspect")
    args = ap.parse_args()

    with ntoseye.attach(backend=args.backend, connect=args.connect) as dbg:
        matches = dbg.processes.find(args.name)
        if not matches:
            raise SystemExit(f"process {args.name!r} not found")
        proc = matches[0]

        print(f"{proc.name} (pid {proc.pid}, eprocess {proc.eprocess:#x}, dtb {proc.dtb:#x})")
        print(f"  ActiveThreads   : {proc.object.ActiveThreads}")
        print(f"  threads         : {len(proc.threads)}")
        # Alternate access: `proc.object["ActiveProcessLinks"]` reads the same
        # field. It is needed only when a field is named like a cursor member
        # (`addr`, `type`, `read`, ...) or when assigning to a field.
        print(f"  ActiveLinks     : {proc.object.ActiveProcessLinks.Flink:#x}")

        if proc.peb is None:
            print("  PEB             : unavailable")
        else:
            print(f"  PEB             : {proc.peb.addr:#x}")
            print(f"  user bytes      : {proc.memory.read(proc.peb.addr, 16).hex()}")


if __name__ == "__main__":
    main()
