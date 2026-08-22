#!/usr/bin/env python3
"""Exercise the handle-based run-control surface: `step()` returning a
`StopOutcome`, and `breakpoints()` yielding live `Breakpoint` handles.

Runs to a breakpoint, single-steps a few instructions (printing where each
step lands), then walks the breakpoint list as handles and toggles one in
place. Requires an execution-control backend (`gdb` or `kd`).

    python3 step_and_handles.py --symbol nt!KeWaitForSingleObject --steps 5
    python3 step_and_handles.py --backend gdb --connect 127.0.0.1:1234
"""

import argparse
import ntoseye

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--backend", default="kd", choices=["gdb", "kd"])
    ap.add_argument("--connect", default=None)
    ap.add_argument("--symbol", default="nt!KeWaitForSingleObject")
    ap.add_argument("--steps", type=int, default=5, help="how many instructions to single-step")
    ap.add_argument(
        "--timeout-ms",
        type=int,
        default=10000,
        help="max time to wait for the breakpoint; use 0 to wait indefinitely",
    )
    args = ap.parse_args()

    dbg = ntoseye.attach(backend=args.backend, connect=args.connect)
    dbg.interrupt()

    bp = dbg.breakpoint(args.symbol)
    print(f"breakpoint {bp.id} at {args.symbol} = {bp.address:#x}\n")

    resume_on_exit = True
    try:
        # Run to the breakpoint once, then single-step from there.
        timeout = None if args.timeout_ms == 0 else args.timeout_ms
        while True:
            stop = dbg.run(timeout_ms=timeout)
            if stop.running:
                print(f"timeout waiting for {args.symbol} after {args.timeout_ms}ms")
                dbg.interrupt()
                return
            if stop.terminal:
                print(f"stop: {stop.reason} before reaching the breakpoint")
                resume_on_exit = False
                return
            if bp in stop.breakpoints:
                break

        rip = stop.rip or 0
        print(f"hit {bp.id} at {rip:#x} ({stop.symbol or dbg.closest_symbol(rip)})\n")

        # --- step(): each single-step returns a StopOutcome at the landed-on rip ---
        print(f"single-stepping {args.steps} instruction(s):")
        for n in range(1, args.steps + 1):
            s = dbg.step()
            ip = s.rip or 0
            sym = s.symbol or dbg.closest_symbol(ip)
            asm = next((row[2] for row in dbg.disassemble(ip, 1)), "?")
            print(f"  step #{n}: reason={s.reason}  rip={ip:#x} ({sym})  {asm}")

        # --- breakpoints(): the list yields the same live handles ---
        print("\nbreakpoint list (as handles):")
        listed = dbg.breakpoints()
        for h in listed:
            print(
                f"  #{h.id} at {h.address:#x} ({h.symbol})  "
                f"scope={h.scope}  enabled={h.enabled}  valid={h.valid}"
            )

        # The listed handle is the same breakpoint we set (handle equality).
        same = next((h for h in listed if h == bp), None)
        print(f"\nlisted handle == our handle: {same is not None}")

        # Toggle it in place through the handle, observing live state.
        if same is not None:
            same.disable()
            print(f"after disable(): enabled={bp.enabled}")
            same.enable()
            print(f"after enable():  enabled={bp.enabled}")
    finally:
        try:
            bp.clear()
            cleared = True
        except ntoseye.NtoseyeError as exc:
            cleared = False
            print(f"\nbreakpoint cleanup skipped: {exc}")

        if resume_on_exit:
            dbg.cont()
            print("\nbreakpoint cleared, VM resumed." if cleared else "\nVM resumed.")
        elif cleared:
            print("\nbreakpoint cleared, VM left halted.")


if __name__ == "__main__":
    main()
