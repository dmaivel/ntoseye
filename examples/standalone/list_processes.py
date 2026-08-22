#!/usr/bin/env python3
"""List running processes and loaded kernel modules.

Uses the passive `memory` backend (read-only /dev/kvm introspection), so it
never pauses or interferes with the guest.

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

    dbg = ntoseye.attach(backend=args.backend, connect=args.connect)

    procs = dbg.processes()  # _EPROCESS cursors
    print(f"{len(procs)} processes:")
    print(f"  {'PID':>6}  {'NAME':<24} EPROCESS")
    for proc in sorted(procs, key=lambda p: p.UniqueProcessId):
        print(f"  {proc.UniqueProcessId:>6}  {proc.ImageFileName:<24} {proc.addr:#x}")

    mods = dbg.kernel_modules()
    print(f"\n{len(mods)} kernel modules (first 10):")
    for name, base, size in mods[:10]:
        print(f"  {base:#018x}  {size:>#9x}  {name}")


if __name__ == "__main__":
    main()
