#!/usr/bin/env python3
"""Walk one process's thread handles and their stack-frame handles.

Thread stacks and frames are bound to their owners, so no thread/frame
selection state is needed. The default `kd` backend also reports which CPU a
running thread uses; `--backend memory` reads stacks from a paused VM without
pausing or resuming it.

    python3 thread_stacks.py --process lsass.exe
    python3 thread_stacks.py --backend memory --process System --frames 3
"""

import argparse
import ntoseye


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--backend", default="kd", choices=["memory", "gdb", "kd"])
    ap.add_argument("--connect", default=None)
    ap.add_argument("--process", default="lsass.exe")
    ap.add_argument("--frames", type=int, default=4, help="frames to print per thread")
    args = ap.parse_args()

    with ntoseye.attach(backend=args.backend, connect=args.connect) as dbg:
        if args.backend != "memory":
            dbg.interrupt()

        matches = dbg.processes.find(args.process)
        if not matches:
            raise SystemExit(f"process {args.process!r} not found")
        proc = matches[0]
        threads = list(proc.threads)
        print(f"{proc.name}: {len(threads)} threads\n")

        for thread in threads:
            cpu = thread.cpu if args.backend != "memory" else None
            where = f"on {cpu.id}" if cpu else ("paused snapshot" if args.backend == "memory" else "parked")
            print(
                f"tid {thread.tid or '?':>5}  state={thread.state!s:<10} "
                f"wait={thread.wait_reason!s:<14} {where}"
            )
            try:
                for frame in thread.backtrace(args.frames):
                    print(f"      {frame.ip:#x}  {frame.symbol}")
            except ntoseye.NtoseyeError as exc:
                print(f"      (no stack: {exc})")

        if args.backend != "memory":
            live = next((thread for thread in threads if thread.cpu is not None), None)
            if live is not None:
                frames = live.backtrace()
                if len(frames) > 1:
                    frame = frames[1]
                    registers = frame.registers
                    print("\nframe 1 on the live thread:")
                    print(f"  ip={frame.ip:#x} sp={frame.sp:#x} ({frame.symbol})")
                    if "rsp" in registers:
                        print(f"  frame rsp={registers.rsp:#x}")


if __name__ == "__main__":
    main()
