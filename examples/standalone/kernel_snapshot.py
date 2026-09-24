#!/usr/bin/env python3
"""One-screen kernel snapshot: version, CPUs, pool usage, and sessions.

The default `kd` backend inspects per-CPU state and reads model-specific
registers. Use `--backend memory` for passive reads from a paused guest; the
memory backend cannot halt to query CPUs or read MSRs.
An optional full dump is written while the target is halted.

    python3 kernel_snapshot.py
    python3 kernel_snapshot.py --backend memory
    python3 kernel_snapshot.py --dump /tmp/snapshot.dmp
"""

import argparse
import ntoseye


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--backend", default="kd", choices=["memory", "gdb", "kd"])
    ap.add_argument("--connect", default=None)
    ap.add_argument("--dump", default=None, help="also write a full kernel dump here")
    args = ap.parse_args()

    with ntoseye.attach(backend=args.backend, connect=args.connect) as dbg:
        if args.backend != "memory":
            dbg.interrupt()

        print("target:")
        print(f"  {dbg.inspect.version()}")

        if args.backend == "memory":
            print("\nper-CPU state and MSRs require an execution-control backend; skipped for memory.")
        else:
            print("\nprocessors:")
            for cpu in dbg.cpus:
                thread = cpu.thread
                where = f"tid {thread.tid}" if thread and thread.tid is not None else "no current thread"
                print(f"  cpu {cpu.id}: {where}, rip={cpu.rip!r}, irql={cpu.irql()}")

        if args.backend == "kd" and len(dbg.cpus):
            print("\nmsrs (cpu 0):")
            cpu = dbg.cpus[0]
            for name in ("IA32_EFER", "IA32_LSTAR", "IA32_GS_BASE", "IA32_KERNEL_GS_BASE"):
                print(f"  {name:<20} {cpu.msr[name]:#018x}")

        print(f"\nnonpaged pool usage:\n  {dbg.inspect.pool_usage(sort='nonpaged')}")
        print(f"\nsessions:\n  {dbg.inspect.sessions()}")

        if args.dump:
            unreadable = dbg.write_dump(args.dump)
            print(f"\nwrote {args.dump} ({unreadable} unreadable pages)")

    if args.dump:
        with ntoseye.attach(backend="dmp", connect=args.dump) as dump:
            print(f"reopened dump: {dump.inspect.version()}")


if __name__ == "__main__":
    main()
