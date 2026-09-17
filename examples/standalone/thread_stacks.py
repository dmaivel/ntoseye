#!/usr/bin/env python3
"""Walk one process's threads, selecting each as the inspection context and
printing its stack, then select a stack frame of the live thread.

`select_thread()` returns the vCPU id when the thread is running on one (its
registers become live), or `None` when it is parked (stack only). Terminated
threads have no stack left to walk and are reported as such. Requires a
halted target, so an execution-control backend (`gdb` or `kd`).

    python3 thread_stacks.py --process lsass.exe
    python3 thread_stacks.py --process System --frames 3
"""

import argparse
import ntoseye

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--backend", default="kd", choices=["gdb", "kd"])
    ap.add_argument("--connect", default=None)
    ap.add_argument("--process", default="lsass.exe")
    ap.add_argument("--frames", type=int, default=4, help="frames to print per thread")
    args = ap.parse_args()

    dbg = ntoseye.attach(backend=args.backend, connect=args.connect)
    dbg.interrupt()
    try:
        proc = next((p for p in dbg.processes() if p.ImageFileName == args.process), None)
        if proc is None:
            raise SystemExit(f"process {args.process!r} not found")

        threads = proc.threads()
        print(f"{args.process}: {len(threads)} threads\n")
        for thread in threads:
            vcpu = dbg.select_thread(thread.addr)
            info = dbg.selected_thread()
            where = f"on {vcpu}" if vcpu else "parked"
            print(
                f"tid {info.tid:>5}  {info.state_name:<10} {info.wait_reason_name or '-':<14} {where}"
            )
            try:
                for frame in dbg.backtrace(args.frames):
                    print(f"      {frame.ip:#x}  {frame.symbol}")
            except ntoseye.NtoseyeError as exc:
                print(f"      (no stack: {exc})")
        dbg.select_thread(None)

        # Back on the live thread: select a caller frame so registers and
        # locals reflect it, then return to frame 0.
        print("\nlive thread, frame 1 selected:")
        frame = dbg.select_frame(1)
        print(f"  {frame.index}: ip={frame.ip:#x} sp={frame.sp:#x} ({dbg.closest_symbol(frame.ip)})")
        print(f"  rsp now reads {dbg.registers()['rsp']:#x}")
        dbg.select_frame(None)
    finally:
        dbg.cont()


if __name__ == "__main__":
    main()
