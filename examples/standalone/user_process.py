#!/usr/bin/env python3
"""Inspect a user process's PEB, loader modules, and heaps.

Process-bound cursors and collections read through that process's address
space without changing global debugger state. Uses the passive `memory`
backend; `--backend kd` is available when the target is attached over KD.

    python3 user_process.py --process lsass.exe
    python3 user_process.py --process explorer.exe --backend kd
"""

import argparse
import ntoseye


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--backend", default="memory", choices=["memory", "gdb", "kd"])
    ap.add_argument("--connect", default=None)
    ap.add_argument("--process", default="lsass.exe")
    ap.add_argument("--modules", type=int, default=8, help="loader modules to list")
    args = ap.parse_args()

    with ntoseye.attach(backend=args.backend, connect=args.connect) as dbg:
        matches = dbg.processes.find(args.process)
        if not matches:
            raise SystemExit(f"process {args.process!r} not found")
        proc = matches[0]
        print(f"{proc.name} (pid {proc.pid})")

        peb = proc.peb
        if peb is None:
            print("\nPEB unavailable")
        else:
            print(f"\nPEB {peb.addr:#x}")
            print(f"  image base   {peb.ImageBaseAddress:#x}")
            params = peb.follow("ProcessParameters")
            print(f"  command line {params.CommandLine}")
            print(f"  cwd          {params.CurrentDirectory.DosPath}")

        modules = list(proc.modules)
        print(f"\n{len(modules)} loader modules (first {args.modules}):")
        for module in modules[: args.modules]:
            print(f"  {module.base:#018x}  {module.size:>#9x}  {module.name}")

        try:
            heaps = list(proc.heaps)
        except ntoseye.NtoseyeError as exc:
            print(f"\nheaps unavailable: {exc}")
        else:
            print(f"\n{len(heaps)} heaps:")
            for heap in heaps:
                print(f"  #{heap.index}  {heap.address:#x}")
            if heaps:
                detail = heaps[0].inspect()
                if detail.error:
                    print(f"heap #0 details unavailable: {detail.error}")
                else:
                    print(f"heap #0: {detail}")


if __name__ == "__main__":
    main()
