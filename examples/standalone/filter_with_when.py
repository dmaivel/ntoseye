#!/usr/bin/env python3
"""Use a Python `when` predicate to stop only in a named process.

A predicate that raises is surfaced on the stop as `stop.condition_error`.
Requires an execution-control backend (`gdb` or `kd`).

    python3 filter_with_when.py --backend gdb --connect 127.0.0.1:1234
    python3 filter_with_when.py --name explorer.exe --count 10 --timeout 20
"""

import argparse
import ntoseye


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--backend", default="kd", choices=["gdb", "kd"])
    ap.add_argument("--connect", default=None)
    ap.add_argument("--name", default="svchost.exe", help="image name to accept")
    ap.add_argument("--count", type=int, default=5, help="number of matching hits")
    ap.add_argument("--timeout", type=float, default=20.0, help="seconds per wait; 0 waits forever")
    args = ap.parse_args()

    wanted_name = args.name.casefold()
    with ntoseye.attach(backend=args.backend, connect=args.connect) as dbg:
        dbg.interrupt()

        def matches_process(stop: ntoseye.Stop) -> bool:
            process = stop.process
            return process is not None and process.name.casefold() == wanted_name

        bp = dbg.breakpoints.add("nt!NtCreateFile", when=matches_process)
        print(f"breakpoint {bp.id} at nt!NtCreateFile; filtering for {args.name}")

        timed_out = False
        timeout = None if args.timeout == 0 else args.timeout
        hits = 0
        try:
            while hits < args.count:
                stop = dbg.run(timeout=timeout)
                if stop is None:
                    timed_out = True
                    print(f"timeout waiting for a stop after {args.timeout:g}s")
                    break
                if bp not in stop.breakpoints:
                    print(f"stop: {type(stop).__name__} ({stop.symbol or '?'})")
                    if isinstance(stop, (ntoseye.Stop.Bugcheck, ntoseye.Stop.Reboot)):
                        break
                    continue
                if isinstance(stop, ntoseye.Stop.Breakpoint) and stop.condition_error is not None:
                    print(f"when predicate failed: {stop.condition_error}")
                    break

                process = stop.process
                if process is None:
                    print("breakpoint hit without a process context")
                    continue
                thread = stop.thread
                tid = thread.tid if thread is not None and thread.tid is not None else "?"
                registers = stop.cpu.registers
                first_argument = registers.rcx if "rcx" in registers else 0
                hits += 1
                print(
                    f"hit #{hits}: process={process.name} pid={process.pid} "
                    f"tid={tid} rcx={first_argument:#x}"
                )
        finally:
            if timed_out:
                dbg.interrupt()
            bp.delete()
            print("breakpoint cleanup complete; debugger session closing.")


if __name__ == "__main__":
    main()
