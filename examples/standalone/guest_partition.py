#!/usr/bin/env python3
"""Inspect the Windows guests of the Windows hypervisor's partitions (experimental).

Each guest partition, such as a Windows Sandbox or a Hyper-V VM, runs a kernel
of its own. `dbg.select_partition(id)` inspects a Windows guest in place of the
target, read-only, until `select_partition(1)` returns to the target; handles
minted on one side of a switch go stale on the other. A partition without a
Windows kernel, such as WSL2's, is refused, and the script prints why. The
host trims the memory of an idle guest, which then reads as not mapped, so use
the process you want to read just before you run the script. Needs the `gdb`
backend, which halts the target, and the VM's `hv-evmcs` enlightenment.

    python3 guest_partition.py
    python3 guest_partition.py --partition 7 --process cmd.exe
"""

import argparse

import ntoseye


def frame_names(frames: list[ntoseye.Frame]) -> str:
    return " <- ".join(frame.symbol or f"{frame.ip:#x}" for frame in frames)


def show_guest(dbg: ntoseye.Debugger, target_nt: tuple[int | None, int], args: argparse.Namespace) -> None:
    nt = dbg.modules["nt"]
    # A Windows Sandbox runs the host's own Windows image; a VM runs its own.
    same = (nt.timestamp, nt.size) == target_nt
    print(f"  nt at {nt.base:#x}{' (the target kernel image)' if same else ''}, {len(dbg.processes)} processes")
    for cpu in dbg.cpus:
        print(f"  {cpu.id}: {frame_names(cpu.backtrace(limit=args.frames))}")

    if args.process is None:
        return
    for process in dbg.processes.find(args.process):
        print(f"\n  {process.name} (PID {process.pid})")
        for thread in process.threads:
            print(f"    TID {thread.tid}")
            try:
                frames = thread.backtrace(limit=64)
            except ntoseye.NtoseyeError as error:
                print(f"      (no stack: {error})")
                continue
            for frame in frames:
                print(f"      {frame.ip:#018x}  {frame.symbol or '?'}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--backend", default="gdb", choices=["gdb", "kd"])
    ap.add_argument("--connect", default=None)
    ap.add_argument("--partition", type=lambda text: int(text, 0), help="one partition ID")
    ap.add_argument("--process", help="image name whose thread stacks to print")
    ap.add_argument("--frames", type=int, default=4, help="frames per VP stack")
    args = ap.parse_args()

    with ntoseye.attach(backend=args.backend, connect=args.connect) as dbg:
        dbg.interrupt()
        try:
            partitions = dbg.hypervisor_partitions()
        except ntoseye.NtoseyeError as error:
            raise SystemExit(f"no Windows hypervisor partitions: {error}")
        target = dbg.modules["nt"]
        target_nt = (target.timestamp, target.size)

        for partition in partitions:
            if partition.parent_id is None or args.partition not in (None, partition.id):
                continue
            print(f"partition {partition.id:#x}: {len(partition.virtual_processors)} VPs")
            try:
                dbg.select_partition(partition.id)
            except ntoseye.NtoseyeError as error:
                print(f"  not inspected: {error}")
                continue
            try:
                show_guest(dbg, target_nt, args)
            finally:
                dbg.select_partition(1)
            print()


if __name__ == "__main__":
    main()
