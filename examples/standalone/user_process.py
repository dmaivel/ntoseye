#!/usr/bin/env python3
"""Look inside a user-mode process: PEB, loader modules, and heaps.

Attaches the inspection scope to the process so user-mode reads resolve
through its page tables, then uses the structured inspectors (`!peb`,
`!dlls`, `!heap`) and a `_UNICODE_STRING` read. Read-only, so the passive
`memory` backend is enough.

    python3 user_process.py --process lsass.exe
    python3 user_process.py --process explorer.exe --backend kd
"""

import argparse
import ntoseye

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--backend", default="memory", choices=["memory", "gdb", "kd"])
    ap.add_argument("--connect", default=None)
    ap.add_argument("--process", default="lsass.exe")
    ap.add_argument("--modules", type=int, default=8, help="loader modules to list")
    args = ap.parse_args()

    with ntoseye.attach(backend=args.backend, connect=args.connect) as dbg:
        proc = next((p for p in dbg.processes() if p.ImageFileName == args.process), None)
        if proc is None:
            raise SystemExit(f"process {args.process!r} not found")
        image = dbg.read_unicode_string(proc.SeAuditProcessCreationInfo.ImageFileName)
        print(f"{args.process} (pid {proc.UniqueProcessId}) {image}")

        dbg.attach_process(proc.UniqueProcessId)

        # Fields that can fail to read on their own are `Diagnostic`s: truthy
        # when they read, `.value` for the result, `.error` otherwise.
        peb = dbg.inspect_peb()
        print(f"\nPEB {peb.address:#x}")
        print(f"  image base   {peb.image_base_address.value:#x}")
        if peb.process_parameters_detail:
            params = peb.process_parameters_detail.value
            print(f"  command line {params.command_line.value}")
            print(f"  cwd          {params.current_directory.value}")
        else:
            print(f"  parameters   unreadable: {peb.process_parameters_detail.error}")

        modules = dbg.loader_modules().modules
        print(f"\n{len(modules)} loader modules (first {args.modules}):")
        for m in modules[: args.modules]:
            print(f"  {m.base_address:#018x}  {m.size:>#9x}  {m.name}")

        heaps = dbg.heap_summary().heaps
        print(f"\n{len(heaps)} heaps:")
        for h in heaps:
            print(f"  #{h.index}  {h.address:#x}  {h.kind}")
        detail = dbg.inspect_heap(heaps[0].address)
        seg = detail.segment
        if seg:
            print(
                f"\nheap #0 segment heap: {seg.committed_pages} committed pages, "
                f"{seg.reserved_pages} reserved, granule {seg.granule}"
            )
        elif detail.nt:
            nt = detail.nt
            print(f"\nheap #0 NT heap: {nt}")

        dbg.detach()


if __name__ == "__main__":
    main()
