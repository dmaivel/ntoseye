#!/usr/bin/env python3
"""Break only in one process, only when a condition holds, then step out and
run to an address.

Sets a process-scoped breakpoint with a pass count and a condition, waits for
it, shows where it stopped, and uses `step_out()` / `run_to()` to move within
the caller. Finishes with a one-shot breakpoint, which removes itself on its
first hit. Requires an execution-control backend (`gdb` or `kd`) and a running
process to scope to.

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
    ap.add_argument("--timeout-ms", type=int, default=20000)
    args = ap.parse_args()

    dbg = ntoseye.attach(backend=args.backend, connect=args.connect)
    dbg.interrupt()

    proc = next((p for p in dbg.processes() if p.ImageFileName == args.process), None)
    if proc is None:
        dbg.cont()
        raise SystemExit(f"process {args.process!r} not found")
    pid = proc.UniqueProcessId

    bp = dbg.breakpoint(args.symbol, process=pid, pass_count=args.passes, condition=args.condition)
    print(f"breakpoint {bp.id} at {args.symbol} scope={bp.scope} passes={bp.pass_count} if {bp.condition}")

    try:
        stop = dbg.run(timeout_ms=args.timeout_ms)
        if stop.running:
            dbg.interrupt()
            raise SystemExit(f"no hit within {args.timeout_ms}ms (is {args.process} doing anything?)")
        stopped_in = dbg.status().stopped_process
        print(f"\nhit in {stopped_in.name} (pid {stopped_in.pid}):")
        for frame in dbg.backtrace(4):
            print(f"  {frame.ip:#x}  {frame.symbol}")

        out = dbg.step_out()
        print(f"\nstep_out -> {out.rip:#x} ({dbg.closest_symbol(out.rip)})")

        # Run to the third instruction from here: a temporary breakpoint, not
        # three single-steps.
        target = [row.ip for row in dbg.disassemble(out.rip, 3)][2]
        reached = dbg.run_to(target, timeout_ms=args.timeout_ms)
        print(f"run_to {target:#x} -> {reached.reason} at {reached.rip:#x}")

        bp.clear()
        once = dbg.breakpoint(args.symbol, process=pid, one_shot=True)
        stop = dbg.run(timeout_ms=args.timeout_ms)
        if stop.running:
            dbg.interrupt()
            once.clear()
            print("\none-shot breakpoint did not fire in time; removed it")
        else:
            print(f"\none-shot breakpoint {once.id} fired; still listed: {once.valid}")
    finally:
        for bp in dbg.breakpoints():
            bp.clear()
        dbg.cont()
        print("\nbreakpoints cleared, VM resumed.")


if __name__ == "__main__":
    main()
