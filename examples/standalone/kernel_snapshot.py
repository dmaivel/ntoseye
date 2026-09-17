#!/usr/bin/env python3
"""One-screen kernel health snapshot: version, per-CPU state, IRQL, MSRs, the
biggest pool consumers, and sessions. Optionally writes a full kernel dump of
the halted target and reopens it.

Requires a halted target for the per-CPU and MSR views, so an
execution-control backend (`kd` for MSRs).

    python3 kernel_snapshot.py
    python3 kernel_snapshot.py --dump /tmp/snapshot.dmp
"""

import argparse
import ntoseye

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--backend", default="kd", choices=["gdb", "kd"])
    ap.add_argument("--connect", default=None)
    ap.add_argument("--pool-rows", type=int, default=5)
    ap.add_argument("--dump", default=None, help="also write a full kernel dump here")
    args = ap.parse_args()

    dbg = ntoseye.attach(backend=args.backend, connect=args.connect)
    dbg.interrupt()
    try:
        v = dbg.version()
        print(
            f"Windows {v.major_version}.{v.minor_version} build {v.build_number} "
            f"{v.architecture} {v.product}, {v.processors} CPUs, up {v.uptime}"
        )
        print(f"kernel {v.kernel.name} @ {v.kernel.base:#x}, symbols {v.symbol_status}")

        print("\nprocessors:")
        for cpu in dbg.running(include_idle=True).processors:
            irql = dbg.inspect_irql(cpu.index)
            if cpu.current_thread:
                thread = cpu.current_thread.value
                where = f"tid {thread.tid.value} in {thread.process_name.value}"
            else:
                where = f"current thread unreadable: {cpu.current_thread.error}"
            print(f"  cpu {cpu.index}: {where}, irql {irql.value.value} ({irql.level_name.value})")

        if args.backend == "kd":
            print("\nmsrs:")
            for name in ("IA32_EFER", "IA32_LSTAR", "IA32_GS_BASE", "IA32_KERNEL_GS_BASE"):
                print(f"  {name:<20} {dbg.read_msr(name):#018x}")

        usage = dbg.pool_usage(sort="nonpaged")
        print(f"\ntop nonpaged pool tags ({usage.tracker_status}):")
        for row in usage.rows[: args.pool_rows]:
            print(f"  {row.tag_name:<6} nonpaged {row.nonpaged_bytes:>12,}  paged {row.paged_bytes:>12,}")

        print("\nsessions:")
        for session in dbg.sessions().sessions:
            names = ", ".join(p.name for p in session.processes[:5])
            print(f"  session {session.id}: {len(session.processes)} processes ({names}, ...)")

        if args.dump:
            unreadable = dbg.write_dump(args.dump)
            print(f"\nwrote {args.dump} ({unreadable} unreadable pages)")
    finally:
        dbg.cont()
        dbg.close()

    if args.dump:
        with ntoseye.attach(backend="dmp", connect=args.dump) as dump:
            print(f"reopened: build {dump.version().build_number}, {len(dump.processes())} processes")


if __name__ == "__main__":
    main()
