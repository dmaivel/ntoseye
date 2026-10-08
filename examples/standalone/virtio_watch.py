#!/usr/bin/env python3
"""Watch the guest's virtio queues for a stall, with two looks a set time apart.

For each queue that a virtio-win driver's private PDB types, prints what moved
between the looks: the buffers the driver published, the device completed, and
the driver took back; queues that are idle and moved nothing are only counted,
unless you give `--all`. Like `!virtio`, it flags a queue whose returned
buffers the driver did not take back, and a request queue whose device held
requests and returned none. A queue that the device fills when it has
something (receive, events) holds buffers on purpose and is not flagged for
it. With `--vring`, it lists the buffers that a flagged queue holds, with the
request each one carries (`inspect.vring()`).

The default `memory` backend reads guest RAM while the guest runs. With `gdb`
or `kd`, the guest is halted for each look and runs in between. Exits 1 when
a queue is flagged.

    python3 virtio_watch.py
    python3 virtio_watch.py --interval 10 --vring
    python3 virtio_watch.py --backend kd
"""

from __future__ import annotations

import argparse
import sys
import time

import ntoseye

# A queue by its device and its own address and descriptor table: a driver
# that sets its device up again can get a queue at the same address, with
# counters that start over, but rarely the same table.
Key = tuple[str, int, int]


def queues(devices: list[ntoseye.VirtioDevice]) -> dict[Key, ntoseye.Virtqueue]:
    return {
        (device.location, queue.address, queue.desc or 0): queue
        for device in devices
        if device.driver is not None
        for queue in device.driver.queues
    }


def stall(before: ntoseye.Virtqueue, now: ntoseye.Virtqueue, moved: dict[str, int | None], seconds: float) -> str | None:
    """`!virtio`'s rule for a queue that should have moved and did not."""
    if before.returned and now.returned and moved["taken back"] == 0:
        due = ", though an interrupt was due" if now.interrupt_due else ""
        return f"not taken back for {seconds:.1f} s{due}"
    returned_any = moved["completed"] if moved["completed"] is not None else moved["taken back"]
    if now.role == "requests" and before.with_device and now.with_device and returned_any == 0 and not now.returned:
        return f"the device returned nothing for {seconds:.1f} s"
    return None


def show_ring(dbg: ntoseye.Debugger, module: str, queue: ntoseye.Virtqueue) -> None:
    ring = dbg.inspect.vring(queue.address, module)
    for label, buffers in (("with the device", ring.with_device), ("returned", ring.returned)):
        for buffer in buffers:
            count = len(buffer.descriptors)
            what = buffer.request or buffer.broken or f"{count} descriptor{'' if count == 1 else 's'}"
            print(f"      {label} [{buffer.position}] head {buffer.head}: {what}")
    if ring.broken:
        print(f"      ring: {ring.broken}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--backend", default="memory", choices=["memory", "gdb", "kd"])
    ap.add_argument("--connect", default=None)
    ap.add_argument("--interval", type=float, default=5.0, help="seconds between the two looks")
    ap.add_argument("--vring", action="store_true", help="list the buffers of each flagged queue")
    ap.add_argument("--all", action="store_true", help="also list the queues that are idle and moved nothing")
    args = ap.parse_args()
    if args.interval < 0.5:
        ap.error("--interval must be at least 0.5 s, or the guest barely runs between the looks")

    flagged = 0
    with ntoseye.attach(backend=args.backend, connect=args.connect) as dbg:
        halts = args.backend != "memory"
        if halts:
            dbg.interrupt()
        first = queues(dbg.inspect.virtio())
        started = time.monotonic()
        if not halts:
            time.sleep(args.interval)
        elif (stop := dbg.run(timeout=args.interval)) is not None:
            print(f"the guest stopped before the second look: {stop!r}")
            raise SystemExit(2)
        else:
            dbg.interrupt()
        seconds = time.monotonic() - started
        devices = dbg.inspect.virtio()

        for device in devices:
            name = f"{device.location} {device.kind} ({device.service or 'no driver'})"
            if device.driver is None:
                print(f"{name}: {device.driver_missing}")
                continue
            print(f"{name}, {len(device.driver.queues)} queues, {seconds:.1f} s apart:")
            quiet = 0
            for now in device.driver.queues:
                label = f"  q{now.index:<2} {now.name or '':<10}"
                if now.error:
                    print(f"{label} unreadable: {now.error}")
                    continue
                before = first.get((device.location, now.address, now.desc or 0))
                if before is None:
                    print(f"{label} {now.state} (set up again since the first look)")
                    continue
                if before.progress is None or now.progress is None:
                    print(f"{label} {now.state} (no counters to compare)")
                    continue
                b, n = before.progress, now.progress
                moved: dict[str, int | None] = {
                    "published": (n.published - b.published) % n.modulus,
                    "completed": (n.completed - b.completed) % n.modulus
                    if n.completed is not None and b.completed is not None
                    else None,
                    "taken back": (n.taken_back - b.taken_back) % n.modulus,
                }
                counts = ", ".join(f"+{v} {k}" for k, v in moved.items() if v is not None)
                why = stall(before, now, moved, seconds)
                idle = not (any(moved.values()) or now.with_device or now.returned or before.with_device)
                if idle and why is None and not args.all:
                    quiet += 1
                    continue
                print(f"{label} {counts}; {now.state}")
                if why is not None:
                    flagged += 1
                    print(f"      !! {why}")
                    if args.vring:
                        show_ring(dbg, device.driver.module, now)
            if quiet:
                print(f"  ({quiet} idle queues moved nothing)")

    print(f"\n{flagged} flagged")
    sys.exit(1 if flagged else 0)


if __name__ == "__main__":
    main()
