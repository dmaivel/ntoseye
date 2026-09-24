#!/usr/bin/env python3
"""Set a breakpoint, run until it hits, and inspect the stop context.

Requires an execution-control backend (`gdb` or `kd`); the passive `memory`
backend cannot set breakpoints or control execution.

    python3 breakpoint_trace.py --backend gdb --connect 127.0.0.1:1234
    python3 breakpoint_trace.py --symbol nt!KeWaitForSingleObject --hits 5
"""

import argparse
import ntoseye


def nearest(dbg: ntoseye.Debugger, address: int) -> str:
    symbol = dbg.symbols.nearest(address)
    return str(symbol) if symbol else "?"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--backend", default="kd", choices=["gdb", "kd"])
    ap.add_argument("--connect", default=None)
    ap.add_argument("--symbol", default="nt!KeWaitForSingleObject")
    ap.add_argument("--hits", type=int, default=3, help="how many times to run-to-hit")
    ap.add_argument("--timeout", type=float, default=10.0, help="seconds per wait; 0 waits forever")
    args = ap.parse_args()

    with ntoseye.attach(backend=args.backend, connect=args.connect) as dbg:
        dbg.interrupt()
        bp = dbg.breakpoints.add(args.symbol)
        print(f"breakpoint {bp.id} at {args.symbol} = {bp.address:#x}\n")

        timed_out = False
        try:
            hits = 0
            timeout = None if args.timeout == 0 else args.timeout
            while hits < args.hits:
                stop = dbg.run(timeout=timeout)
                if stop is None:
                    timed_out = True
                    print(f"timeout waiting for a stop after {args.timeout:g}s")
                    break

                rip = stop.rip or 0
                symbol = stop.symbol or nearest(dbg, rip)
                if bp not in stop.breakpoints:
                    print(f"stop: {type(stop).__name__}  rip={rip:#x} ({symbol})")
                    if isinstance(stop, (ntoseye.Stop.Bugcheck, ntoseye.Stop.Reboot)):
                        break
                    continue

                hits += 1
                registers = stop.cpu.registers
                rcx = registers.rcx if "rcx" in registers else 0
                print(f"hit #{hits}: rip={rip:#x} ({symbol})  bp={bp.id}  rcx={rcx:#x}")
                for row in dbg.memory.disassemble(rip, 2):
                    comment = f"   ; {row.comment}" if row.comment else ""
                    print(f"    {row.ip:#x}: {row.asm}{comment}")
        finally:
            if timed_out:
                dbg.interrupt()
            try:
                bp.delete()
            except ntoseye.NtoseyeError as exc:
                print(f"breakpoint cleanup skipped: {exc}")

            print("breakpoint cleanup complete; debugger session closing.")


if __name__ == "__main__":
    main()
