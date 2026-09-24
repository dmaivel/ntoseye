#!/usr/bin/env python3
"""Exercise run control and live `Breakpoint` handles.

Runs to a breakpoint, single-steps a few instructions, lists breakpoint
handles, and toggles one through its `enabled` property. Requires an
execution-control backend (`gdb` or `kd`).

    python3 step_and_handles.py --symbol nt!KeWaitForSingleObject --steps 5
    python3 step_and_handles.py --backend gdb --connect 127.0.0.1:1234
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
    ap.add_argument("--steps", type=int, default=5, help="how many instructions to single-step")
    ap.add_argument("--timeout", type=float, default=10.0, help="seconds; 0 waits forever")
    args = ap.parse_args()

    with ntoseye.attach(backend=args.backend, connect=args.connect) as dbg:
        dbg.interrupt()
        bp = dbg.breakpoints.add(args.symbol)
        print(f"breakpoint {bp.id} at {args.symbol} = {bp.address:#x}\n")

        try:
            timeout = None if args.timeout == 0 else args.timeout
            while True:
                stop = dbg.run(timeout=timeout)
                if stop is None:
                    print(f"timeout waiting for {args.symbol} after {args.timeout:g}s")
                    dbg.interrupt()
                    return
                if isinstance(stop, (ntoseye.Stop.Bugcheck, ntoseye.Stop.Reboot)):
                    print(f"stop: {type(stop).__name__} before reaching the breakpoint")
                    return
                if bp in stop.breakpoints:
                    break

            rip = stop.rip or 0
            print(f"hit {bp.id} at {rip:#x} ({stop.symbol or nearest(dbg, rip)})\n")

            print(f"single-stepping {args.steps} instruction(s):")
            for number in range(1, args.steps + 1):
                step = dbg.step()
                ip = step.rip or 0
                symbol = step.symbol or nearest(dbg, ip)
                rows = dbg.memory.disassemble(ip, 1)
                asm = rows[0].asm if rows else "?"
                print(f"  step #{number}: {type(step).__name__}  rip={ip:#x} ({symbol})  {asm}")

            print("\nbreakpoint list (handles):")
            listed = list(dbg.breakpoints)
            for handle in listed:
                print(
                    f"  #{handle.id} at {handle.address:#x} ({handle.symbol})  "
                    f"enabled={handle.enabled}  valid={handle.valid}"
                )

            same = next((handle for handle in listed if handle == bp), None)
            print(f"\nlisted handle == our handle: {same is not None}")
            if same is not None:
                same.enabled = False
                print(f"after disable: enabled={bp.enabled}")
                same.enabled = True
                print(f"after enable:  enabled={bp.enabled}")
        finally:
            try:
                bp.delete()
            except ntoseye.NtoseyeError as exc:
                print(f"breakpoint cleanup skipped: {exc}")

            print("breakpoint cleanup complete; debugger session closing.")


if __name__ == "__main__":
    main()
