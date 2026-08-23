#!/usr/bin/env python3
"""Attach to a process and inspect it in its own address space.

Demonstrates the context manager, process-context switching (`attach_process`),
and reading a struct from the attached process. Uses the passive `memory`
backend.

    python3 inspect_process.py
    python3 inspect_process.py --name explorer.exe
"""

import argparse
import ntoseye

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--backend", default="memory", choices=["memory", "gdb", "kd"])
    ap.add_argument("--connect", default=None)
    ap.add_argument("--name", default="lsass.exe", help="process image name to attach to")
    args = ap.parse_args()

    with ntoseye.attach(backend=args.backend, connect=args.connect) as dbg:
        proc = next((p for p in dbg.processes() if p.ImageFileName == args.name), None)
        if proc is None:
            raise SystemExit(f"process {args.name!r} not found")
        pid = proc.UniqueProcessId

        print(f"attaching to {args.name} (pid {pid}, eprocess {proc.addr:#x})")
        dbg.attach_process(pid)  # subsequent *user* memory reads target this process
        print("current process:", dbg.current_process())

        # The _EPROCESS cursor reads kernel memory, so its fields read directly.
        print(f"  UniqueProcessId : {proc.UniqueProcessId}")
        print(f"  ImageFileName   : {proc.ImageFileName}")
        print(f"  ActiveThreads   : {proc.ActiveThreads}")
        print(f"  threads (walked): {len(proc.threads())}")

        dbg.detach()


if __name__ == "__main__":
    main()
