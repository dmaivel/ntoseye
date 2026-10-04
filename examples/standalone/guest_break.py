#!/usr/bin/env python3
"""Break in a Windows guest of the Windows hypervisor, and step it (experimental).

In a guest partition's view (`dbg.select_partition(id)`), a hardware
breakpoint (`breakpoints.add(..., hardware=True)`) is the guest's: `run()`
runs the target, and the hit returns in the guest's view, on the VP that ran
the code. The script breaks on a function of the guest's kernel (`nt!NtClose`
by default), prints which process and thread reached it and their stack, then
steps a few instructions (`step()`) and out to the caller (`step_out()`). Each
step runs the target until the thread reaches its next instruction, on
whichever VP runs it. An idle guest calls few functions, so use the guest
while the script runs. Needs the `gdb` backend and the VM's `hv-evmcs`
enlightenment.

    python3 guest_break.py --partition 4
    python3 guest_break.py --partition 4 --function nt!NtCreateFile --steps 5
"""

from __future__ import annotations

import argparse

import ntoseye


def where(stop: ntoseye.Stop) -> str:
    rip = f"{stop.rip:#018x}" if stop.rip is not None else "?"
    return f"{stop.cpu.id}  {rip}  {stop.symbol or '?'}"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--connect", default=None)
    ap.add_argument("--partition", type=lambda text: int(text, 0), required=True)
    ap.add_argument("--function", default="nt!NtClose", help="where to break, in the guest")
    ap.add_argument("--steps", type=int, default=3, help="instructions to step before stepping out")
    ap.add_argument("--timeout", type=float, default=60.0, help="seconds to wait for the guest")
    ap.add_argument("--frames", type=int, default=8, help="frames of the stack at the hit")
    args = ap.parse_args()

    with ntoseye.attach(backend="gdb", connect=args.connect) as dbg:
        dbg.interrupt()
        try:
            dbg.select_partition(args.partition)
        except ntoseye.NtoseyeError as error:
            raise SystemExit(f"partition {args.partition:#x} cannot be shown: {error}")

        bp = dbg.breakpoints.add(args.function, hardware=True)
        print(f"breakpoint {bp.id} at {bp.address:#x} ({args.function}) in partition {args.partition:#x}")
        try:
            hit = dbg.run(timeout=args.timeout)
        finally:
            if dbg.stop is None:
                dbg.interrupt()
            bp.delete()
        if not isinstance(hit, ntoseye.Stop.Breakpoint):
            raise SystemExit(f"{args.function} was not reached; use the guest while the script runs")

        # The hit shows the guest's view, on the VP that ran the code.
        thread = hit.thread
        who = f"{thread.process.name} TID {thread.tid}" if thread and thread.process else "an unknown thread"
        shown = f"partition {dbg.partition:#x}" if dbg.partition is not None else "the target"
        print(f"hit on {hit.cpu.id} in {shown}, by {who}:")
        for frame in hit.cpu.backtrace(limit=args.frames):
            print(f"  {frame.ip:#018x}  {frame.symbol or '?'}")

        for _ in range(args.steps):
            print(f"t   {where(dbg.step())}")
        print(f"gu  {where(dbg.step_out(timeout=args.timeout))}")


if __name__ == "__main__":
    main()
