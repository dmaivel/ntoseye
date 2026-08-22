#!/usr/bin/env python3
"""Search memory and inspect structured match objects.

Scans a small range around a symbol for a common byte pattern (`48` by default)
and prints the typed `MemorySearchMatch` fields returned by `search_details`.
Uses the passive `memory` backend.

    python3 search_details.py
    python3 search_details.py --symbol nt!NtOpenProcess --pattern 488b --length 0x400
"""

import argparse
import ntoseye


def parse_int(text: str) -> int:
    return int(text, 0)


def parse_pattern(text: str) -> bytes:
    cleaned = text.replace(" ", "").replace("\\x", "")
    if len(cleaned) % 2:
        raise argparse.ArgumentTypeError("hex pattern must have an even number of digits")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e)) from e


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--backend", default="memory", choices=["memory", "gdb", "kd"])
    ap.add_argument("--connect", default=None)
    ap.add_argument("--symbol", default="nt!KeBugCheckEx", help="symbol or expression to scan at")
    ap.add_argument("--pattern", default="48", type=parse_pattern, help="hex bytes to find")
    ap.add_argument("--length", default=0x1000, type=parse_int, help="bytes to scan")
    ap.add_argument("--limit", default=16, type=int, help="matches to print")
    args = ap.parse_args()

    dbg = ntoseye.attach(backend=args.backend, connect=args.connect)

    start = dbg.eval(args.symbol)
    hits = dbg.search_details(start, args.pattern, args.length)

    print(
        f"{len(hits)} matches for {args.pattern.hex()} "
        f"in {args.length:#x} bytes at {args.symbol} ({start:#x})"
    )
    print(f"  {'ADDRESS':>18}  {'OFFSET':>8}  {'KIND':<14}  {'MODULE':<24}  SECTION  SYMBOL")
    for hit in hits[: args.limit]:
        module = hit.module
        module_name = module.name if module else "-"
        section = hit.section or "-"
        symbol = hit.symbol or "-"
        print(
            f"  {hit.address:#018x}  {hit.offset:#8x}  "
            f"{hit.kind:<14}  {module_name:<24}  {section:<7}  {symbol}"
        )

    if len(hits) > args.limit:
        print(f"\n... {len(hits) - args.limit} more matches not shown")


if __name__ == "__main__":
    main()
