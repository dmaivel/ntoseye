#!/usr/bin/env python3
"""Stop at a function, step to a call, and print its bounded call tree.

Requires an execution-control backend (`gdb` or `kd`). GDB single-steps slowly,
so the trace instruction limit defaults to 2000.

    python3 call_trace.py --backend gdb --connect 127.0.0.1:1234
    python3 call_trace.py --symbol nt!KeWaitForSingleObject --limit 2000 --timeout 20
"""

import argparse
import json
import ntoseye


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--backend", default="kd", choices=["gdb", "kd"])
    ap.add_argument("--connect", default=None)
    ap.add_argument("--symbol", default="nt!KeWaitForSingleObject")
    ap.add_argument("--limit", type=int, default=2000, help="maximum trace instructions")
    ap.add_argument("--timeout", type=float, default=20.0, help="seconds to wait for the breakpoint")
    args = ap.parse_args()

    with ntoseye.attach(backend=args.backend, connect=args.connect) as dbg:
        dbg.interrupt()
        bp = dbg.breakpoints.add(args.symbol)
        print(f"breakpoint {bp.id} at {args.symbol} = {bp.address:#x}")

        timed_out = False
        timeout = None if args.timeout == 0 else args.timeout
        try:
            stop = dbg.run(timeout=timeout)
            if stop is None:
                timed_out = True
                print(f"timeout waiting for {args.symbol} after {args.timeout:g}s")
                return
            if bp not in stop.breakpoints:
                print(f"stop: {type(stop).__name__} ({stop.symbol or '?'})")
                return

            call_stop = dbg.step(until="call")
            print(f"step-until-call: {call_stop.symbol or '?'}")
            trace = dbg.trace_calls(limit=args.limit)
            print(json.dumps(trace.to_dict(), indent=2, default=str))
        finally:
            if timed_out:
                dbg.interrupt()
            bp.delete()
            print("breakpoint cleanup complete; debugger session closing.")


if __name__ == "__main__":
    main()
