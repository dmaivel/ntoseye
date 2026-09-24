#!/usr/bin/env python3
"""List running processes and loaded kernel modules.

Uses the passive `memory` backend for read-only live-VM introspection, so it
never pauses or otherwise interferes with the guest. Select another backend
with `--backend` when desired.

    python3 list_processes.py
    python3 list_processes.py --backend gdb --connect 127.0.0.1:1234
"""

import argparse
import ntoseye


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--backend", default="memory", choices=["memory", "gdb", "kd"])
    ap.add_argument("--connect", default=None, help="backend target (socket/addr)")
    args = ap.parse_args()

    with ntoseye.attach(backend=args.backend, connect=args.connect) as dbg:
        procs = dbg.processes
        print(f"{len(procs)} processes:")
        print(f"  {'PID':>6}  {'NAME':<24} EPROCESS")
        for proc in sorted(procs, key=lambda p: p.pid):
            print(f"  {proc.pid:>6}  {proc.name:<24} {proc.eprocess:#x}")

        mods = list(dbg.modules)
        print(f"\n{len(mods)} kernel modules (first 10):")
        for module in mods[:10]:
            print(f"  {module.base:#018x}  {module.size:>#9x}  {module.name}")


if __name__ == "__main__":
    main()
