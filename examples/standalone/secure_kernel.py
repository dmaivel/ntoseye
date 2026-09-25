#!/usr/bin/env python3
"""Inspect the VBS secure kernel (VTL1) and its trustlets (experimental).

`dbg.secure_kernel` is the secure kernel's system address space: its
`memory`, `symbols`, `types`, and `modules`. The public secure-kernel PDB has
no types, so NT's are named explicitly: here `nt!_KLDR_DATA_TABLE_ENTRY`
walks the secure kernel's own `SkLoadedModuleList`. Each trustlet carries the
same views bound to its own address space. The views are read-only. Needs VBS
running in the guest and host memory access; uses the passive `memory`
backend.

    python3 secure_kernel.py
"""

import argparse
import sys

import ntoseye


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--backend", default="memory", choices=["memory", "gdb", "kd"])
    ap.add_argument("--connect", default=None)
    args = ap.parse_args()

    with ntoseye.attach(backend=args.backend, connect=args.connect) as dbg:
        try:
            sk = dbg.secure_kernel
        except ntoseye.NtoseyeError as error:
            sys.exit(f"no secure kernel: {error}")
        print(f"securekernel at {sk.base:#x}, system DTB {sk.dtb:#x}\n")

        head = sk.symbols["securekernel!SkLoadedModuleList"]
        entries = sk.types["nt!_KLDR_DATA_TABLE_ENTRY"].walk(head, "InLoadOrderLinks")
        print(f"  {'DllBase':>18}  {'Size':>9}  Name")
        for entry in entries:
            print(f"  {entry.DllBase:#18x}  {entry.SizeOfImage:>9}  {entry.BaseDllName}")

        # A trustlet's root maps the secure kernel at the same physical page.
        header = sk.memory.translate(sk.base)
        print(f"\n  {'NT PID':>6}  {'ID':>3}  {'DTB':>18}  Image")
        for trustlet in sk.trustlets:
            shared = trustlet.memory.translate(sk.base) == header
            print(
                f"  {trustlet.pid:>6}  {trustlet.trustlet_id:>3}  {trustlet.dtb:#18x}  "
                f"{trustlet.name}{'' if shared else '  (does not map the secure kernel!)'}"
            )


if __name__ == "__main__":
    main()
