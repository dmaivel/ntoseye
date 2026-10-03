#!/usr/bin/env python3
"""Watch a hypercall from one Windows hypervisor partition (experimental).

A hypercall breakpoint (`breakpoints.add_hypercall()`) fires in the
hypervisor's handler of one call, from one partition. Its `when=` callback
reads the caller through `stop.cpu.hypercall_caller()`: here it counts the
callers for a while without stopping, then lets one hit stop. The stop shows
the hypervisor's own stack (`cpu.backtrace()`), the decoded call, and, for a
Windows guest, the stack in the guest's kernel of the VP that made the call,
through `select_partition()`. An idle guest makes few hypercalls, so use the
guest while the script runs. Needs the `gdb` backend and the VM's `hv-evmcs`
enlightenment.

    python3 hypercall_watch.py --partition 7
    python3 hypercall_watch.py --partition 7 --call HvCallFlushVirtualAddressList --seconds 20
"""

import argparse
import time
from collections import Counter

import ntoseye


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--connect", default=None)
    ap.add_argument("--partition", type=lambda text: int(text, 0), required=True)
    ap.add_argument("--call", default="HvCallSendSyntheticClusterIpi", help="TLFS name or call code")
    ap.add_argument("--seconds", type=float, default=10.0, help="how long to count before a hit stops")
    ap.add_argument("--timeout", type=float, default=30.0, help="seconds to wait for a hit after that")
    ap.add_argument("--frames", type=int, default=8, help="frames per stack")
    args = ap.parse_args()

    with ntoseye.attach(backend="gdb", connect=args.connect) as dbg:
        dbg.interrupt()
        callers: Counter[tuple[int, int]] = Counter()
        deadline: float = time.monotonic() + args.seconds

        def count_caller(stop: ntoseye.Stop) -> bool:
            caller = stop.cpu.hypercall_caller()
            if caller is None:
                return True
            callers[(caller.vp_index, caller.vtl)] += 1
            return time.monotonic() >= deadline

        bp = dbg.breakpoints.add_hypercall(args.call, args.partition, when=count_caller)
        call = bp.hypercall
        name = call.name if call is not None and call.name else args.call
        print(f"breakpoint {bp.id}: {name} from partition {args.partition:#x}, counting callers for {args.seconds:g}s")
        try:
            stop = dbg.run(timeout=args.seconds + args.timeout)
        finally:
            if dbg.stop is None:
                dbg.interrupt()
            bp.delete()

        for (vp, vtl), count in sorted(callers.items()):
            print(f"  VP {vp} VTL{vtl}: {count} calls")
        if not isinstance(stop, ntoseye.Stop.Breakpoint):
            raise SystemExit("no call stopped; use the guest while the script runs")

        cpu = stop.cpu
        caller = cpu.hypercall_caller()
        if caller is None:
            raise SystemExit(f"stopped on {cpu.id}, but its caller is unknown")
        summary = caller.hypercall.summary if caller.hypercall else "(input not decoded)"
        print(f"\nstopped on {cpu.id}: partition {caller.partition_id:#x} VP {caller.vp_index} VTL{caller.vtl}: {summary}")
        print(f"the hypervisor on {cpu.id}:")
        for frame in cpu.backtrace(limit=args.frames):
            print(f"  {frame.ip:#018x}  {frame.symbol or '?'}")

        # The caller's handle goes stale when the view switches: keep its numbers.
        partition, vp = caller.partition_id, caller.vp_index
        try:
            dbg.select_partition(partition)
        except ntoseye.NtoseyeError as error:
            raise SystemExit(f"no Windows guest to read: {error}")
        try:
            guest_cpu = dbg.cpus[vp]
            print(f"the guest's VP {vp} ({guest_cpu.id}):")
            for frame in guest_cpu.backtrace(limit=args.frames):
                print(f"  {frame.ip:#018x}  {frame.symbol or '?'}")
        finally:
            dbg.select_partition(1)


if __name__ == "__main__":
    main()
