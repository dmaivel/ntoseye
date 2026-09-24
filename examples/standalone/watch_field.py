#!/usr/bin/env python3
"""Watch a processor's current-thread pointer and report its writer.

Requires an execution-control backend (`gdb` or `kd`). The `_KPRCB.CurrentThread`
pointer changes on context switches; the example watches one processor's field
and prints the stopping symbol and thread stack.

    python3 watch_field.py --backend gdb --connect 127.0.0.1:1234
    python3 watch_field.py --timeout 15
"""

import argparse
import ntoseye


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--backend", default="kd", choices=["gdb", "kd"])
    ap.add_argument("--connect", default=None)
    ap.add_argument("--cpu", type=int, default=0, help="processor whose _KPRCB field to watch")
    ap.add_argument("--timeout", type=float, default=15.0, help="seconds to wait; 0 waits forever")
    args = ap.parse_args()

    with ntoseye.attach(backend=args.backend, connect=args.connect) as dbg:
        dbg.interrupt()
        prcb = dbg.types["_KPRCB"].at(dbg.cpus[args.cpu].prcb().kprcb)
        target = prcb.address_of("CurrentThread")
        watch = dbg.breakpoints.watch(target, access="write", length=8, processor=args.cpu)
        print(f"write watchpoint {watch.id} at CPU {args.cpu} _KPRCB.CurrentThread = {watch.address:#x}")

        timed_out = False
        timeout = None if args.timeout == 0 else args.timeout
        try:
            stop = dbg.run(timeout=timeout)
            if stop is None:
                timed_out = True
                print(f"timeout waiting for a write after {args.timeout:g}s")
            elif watch not in stop.breakpoints:
                print(f"stop: {type(stop).__name__} ({stop.symbol or '?'})")
            else:
                print(f"writer: {stop.symbol or '?'}")
                thread = stop.thread
                if thread is None:
                    print("thread: unavailable")
                else:
                    print(f"thread: tid={thread.tid}")
                    try:
                        for frame in thread.backtrace(limit=5):
                            print(f"  #{frame.index} {frame.symbol or hex(frame.ip)}")
                    except ntoseye.NtoseyeError as exc:
                        print(f"backtrace unavailable: {exc}")
        finally:
            if timed_out:
                dbg.interrupt()
            watch.delete()
            print("watchpoint cleanup complete; debugger session closing.")


if __name__ == "__main__":
    main()
