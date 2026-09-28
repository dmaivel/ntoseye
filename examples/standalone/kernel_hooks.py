#!/usr/bin/env python3
"""Audit kernel dispatch tables and callbacks for code outside where it belongs.

Checks three places rootkits and security products hook:
- SSDT entries that do not land in `nt` (or, for the shadow table, `win32k*`);
- process, thread, and image notify callbacks, each named with the module
  that holds it, and flagged when no loaded module does;
- each processor's IDT gates whose handler lies outside NT (skipped with
  `--backend memory`, which cannot read the vCPUs' IDTR).

An IDT gate that could not be read is reported as such rather than guessed
at. Exits 1 when anything is flagged, so it can gate a test run.

    python3 kernel_hooks.py
    python3 kernel_hooks.py --backend memory
"""

import argparse
import sys

import ntoseye


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--backend", default="kd", choices=["memory", "gdb", "kd"])
    ap.add_argument("--connect", default=None)
    args = ap.parse_args()

    flagged = 0
    with ntoseye.attach(backend=args.backend, connect=args.connect) as dbg:
        if args.backend != "memory":
            dbg.interrupt()

        print("SSDT:")
        for table in dbg.inspect.ssdt():
            expected = "win32k" if "win32k" in table.label else "nt"
            foreign = [e for e in table.entries if not (e.module or "").lower().startswith(expected)]
            print(f"  {table.label}: {len(table.entries)} entries, {len(foreign)} outside {expected}")
            for entry in foreign:
                print(f"    [{entry.index:#x}] {entry.target:#x} {entry.symbol or entry.module or 'no module'}")
            flagged += len(foreign)

        print("\nnotify callbacks:")
        for callback in dbg.inspect.callbacks():
            module = dbg.modules.at(callback.function)
            where = callback.symbol or (module.name if module else None)
            if module is None:
                flagged += 1
                where = "!! outside every loaded module"
            print(f"  {callback.kind:<8} {callback.function:#018x}  {where}")

        if args.backend == "memory":
            print("\nIDT: skipped (the memory backend cannot read the vCPUs' IDTR)")
        else:
            print("\nIDT:")
            for cpu in dbg.cpus:
                idt = cpu.idt()
                outside = sum(1 for gate in idt.entries if gate.non_nt_hook.value)
                print(f"  cpu {cpu.id}: {len(idt.entries)} gates, {outside} outside NT")
                for gate in idt.entries:
                    if not gate.non_nt_hook:  # the check itself could not be read
                        print(f"    vector {gate.vector:#04x}: unreadable ({gate.non_nt_hook.error})")
                    elif gate.non_nt_hook.value:
                        flagged += 1
                        handler = gate.handler.value
                        target = gate.symbol.value or (f"{handler:#x}" if handler is not None else "?")
                        print(f"    vector {gate.vector:#04x}: {target}")
                if idt.truncated:
                    print("    listing truncated")

    print(f"\n{flagged} flagged")
    sys.exit(1 if flagged else 0)


if __name__ == "__main__":
    main()
