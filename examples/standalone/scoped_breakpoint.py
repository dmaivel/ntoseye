#!/usr/bin/env python3
"""Break only in one process, then step out and run to an address.

Sets a process-scoped, pass-counted breakpoint with a debugger-expression
condition, uses `step_out()` / `run_to()`, then demonstrates a one-shot
breakpoint. Requires an execution-control backend (`gdb` or `kd`) and a
running process to scope to.

    python3 scoped_breakpoint.py --process notepad.exe
    python3 scoped_breakpoint.py --process lsass.exe --symbol nt!NtOpenKey --condition "rdx != 0"
"""

import argparse
import ntoseye


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--backend", default="kd", choices=["gdb", "kd"])
    ap.add_argument("--connect", default=None)
    ap.add_argument("--process", required=True, help="image name to scope the breakpoint to")
    ap.add_argument("--symbol", default="nt!KiSwapThread")
    ap.add_argument("--condition", default="rcx != 0", help="break only when this expression is true")
    ap.add_argument("--passes", type=int, default=3, help="hits to skip before the first stop")
    ap.add_argument("--timeout", type=float, default=20.0, help="seconds; 0 waits forever")
    args = ap.parse_args()

    with ntoseye.attach(backend=args.backend, connect=args.connect) as dbg:
        dbg.interrupt()
        matches = dbg.processes.find(args.process)
        if not matches:
            raise SystemExit(f"process {args.process!r} not found")
        proc = matches[0]

        bp = dbg.breakpoints.add(
            args.symbol,
            condition=args.condition,
            process=proc,
            pass_count=args.passes,
        )
        print(
            f"breakpoint {bp.id} at {args.symbol} scope={bp.process.name if bp.process else '-'} "
            f"passes={bp.pass_count} if {bp.condition}"
        )

        timeout = None if args.timeout == 0 else args.timeout
        try:
            while True:
                stop = dbg.run(timeout=timeout)
                if stop is None:
                    dbg.interrupt()
                    raise SystemExit(f"no hit within {args.timeout:g}s (is {args.process} doing anything?)")
                if bp in stop.breakpoints:
                    break
                if isinstance(stop, (ntoseye.Stop.Bugcheck, ntoseye.Stop.Reboot)):
                    raise SystemExit(f"target stopped with {type(stop).__name__} before the breakpoint")
                print(f"other stop: {type(stop).__name__} at {stop.rip!r}; waiting again")

            stopped_in = stop.process
            name = stopped_in.name if stopped_in else "unknown process"
            pid = stopped_in.pid if stopped_in else "?"
            print(f"\nstop in {name} (pid {pid}), {type(stop).__name__}:")
            if stop.thread:
                for frame in stop.thread.backtrace(4):
                    print(f"  {frame.ip:#x}  {frame.symbol}")

            out = dbg.step_out()
            rip = out.rip or 0
            print(f"\nstep_out -> {rip:#x} ({out.symbol or dbg.symbols.nearest(rip)})")

            rows = dbg.memory.disassemble(rip, 3)
            if len(rows) < 3:
                raise SystemExit("could not decode three instructions at the return address")
            target = rows[2].ip
            reached = dbg.run_to(target, timeout=timeout)
            if reached is None:
                raise SystemExit(f"run_to {target:#x} timed out")
            print(f"run_to {target:#x} -> {type(reached).__name__} at {reached.rip!r}")

            bp.delete()
            once = dbg.breakpoints.add(args.symbol, process=proc, one_shot=True)
            stop = dbg.run(timeout=timeout)
            if stop is None:
                dbg.interrupt()
                once.delete()
                print("\none-shot breakpoint did not fire in time; removed it")
            else:
                print(f"\none-shot breakpoint {once.id} fired; still listed: {once.valid}")
        finally:
            for handle in list(dbg.breakpoints):
                try:
                    handle.delete()
                except ntoseye.NtoseyeError:
                    pass
            print("breakpoints cleared; debugger session closing.")


if __name__ == "__main__":
    main()
