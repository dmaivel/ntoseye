#!/usr/bin/env python3
"""Set a breakpoint, run until it hits, and inspect context.

Requires an execution-control backend (`gdb` or `kd`); the passive `memory`
backend cannot set breakpoints or control execution.

    python3 breakpoint_trace.py --backend gdb --connect 127.0.0.1:1234
    python3 breakpoint_trace.py --symbol nt!KeWaitForSingleObject --hits 5
"""

import argparse
import ntoseye

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--backend", default="kd", choices=["gdb", "kd"])
    ap.add_argument("--connect", default=None)
    ap.add_argument("--symbol", default="nt!KeWaitForSingleObject")
    ap.add_argument("--hits", type=int, default=3, help="how many times to run-to-hit")
    ap.add_argument(
        "--timeout-ms",
        type=int,
        default=10000,
        help="max time to wait for each stop; use 0 to wait indefinitely",
    )
    args = ap.parse_args()

    dbg = ntoseye.attach(backend=args.backend, connect=args.connect)
    dbg.interrupt()

    bp = dbg.breakpoint(args.symbol)
    print(f"breakpoint {bp.id} at {args.symbol} = {bp.address:#x}\n")

    timed_out = False
    resume_on_exit = True
    try:
        hits = 0
        timeout = None if args.timeout_ms == 0 else args.timeout_ms
        while hits < args.hits:
            stop = dbg.run(timeout_ms=timeout)
            if stop.running:
                timed_out = True
                print(f"timeout waiting for a stop after {args.timeout_ms}ms")
                break

            rip = stop.rip or 0
            sym = stop.symbol or dbg.closest_symbol(rip)
            if bp not in stop.breakpoints:
                print(
                    f"stop: {stop.reason}  rip={rip:#x} ({sym})  "
                    f"bp={stop.breakpoint_id}  exception={stop.exception_code}"
                )
                if stop.terminal:
                    resume_on_exit = False
                    break
                continue

            hits += 1
            regs = dbg.registers()
            print(
                f"hit #{hits}: rip={rip:#x} ({sym})  "
                f"bp={bp.id}  rcx={regs.get('rcx', 0):#x}"
            )
            # show the next two instructions at the hit
            for ip, _hex, asm, comment in dbg.disassemble(rip, 2):
                c = f"   ; {comment}" if comment else ""
                print(f"    {ip:#x}: {asm}{c}")
    finally:
        if timed_out:
            dbg.interrupt()
        try:
            bp.clear()
            cleared = True
        except ntoseye.NtoseyeError as exc:
            cleared = False
            print(f"\nbreakpoint cleanup skipped: {exc}")

        if resume_on_exit:
            dbg.cont()
            if cleared:
                print("\nbreakpoint cleared, VM resumed.")
            else:
                print("\nVM resumed.")
        elif cleared:
            print("\nbreakpoint cleared, VM left halted.")


if __name__ == "__main__":
    main()
