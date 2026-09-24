#!/usr/bin/env python3
"""Print stop context, structured triage, and an available thread backtrace.

Open an offline Windows kernel dump with the `dmp` backend. Missing bugcheck,
thread, triage, or stack data is reported without preventing the other output.

    python3 crash_triage.py MEMORY.DMP
    python3 crash_triage.py MEMORY.DMP --json
"""

from __future__ import annotations

import argparse
import json
import ntoseye


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("dump", help="path to a Windows kernel dump")
    ap.add_argument("--json", action="store_true", help="print records as JSON")
    args = ap.parse_args()

    with ntoseye.attach("dmp", args.dump) as dbg:
        stop = dbg.stop
        bugcheck_info: dict[str, object] | None = None
        if isinstance(stop, ntoseye.Stop.Bugcheck) and stop.info is not None:
            bugcheck_info = stop.info.to_dict()

        triage: dict[str, object] | None = None
        triage_error: str | None = None
        try:
            triage = dbg.inspect.triage().to_dict()
        except ntoseye.NtoseyeError as exc:
            triage_error = str(exc)

        thread = stop.thread if stop is not None else None
        thread_data: dict[str, object] | None = thread.to_dict() if thread is not None else None
        frames: list[ntoseye.Frame] = []
        backtrace_error: str | None = None
        if thread is not None:
            try:
                frames = thread.backtrace(limit=16)
            except ntoseye.NtoseyeError as exc:
                backtrace_error = str(exc)

        report: dict[str, object] = {
            "stop": stop.to_dict() if stop is not None else None,
            "bugcheck_info": bugcheck_info,
            "triage": triage,
            "triage_error": triage_error,
            "thread": thread_data,
            "backtrace": [frame.to_dict() for frame in frames],
            "backtrace_error": backtrace_error,
        }
        if args.json:
            print(json.dumps(report, indent=2, default=str))
            return

        if stop is None:
            print("stop: unavailable")
        else:
            print(f"stop: {stop!r}")
        if isinstance(stop, ntoseye.Stop.Bugcheck):
            print(f"bugcheck info: {bugcheck_info if bugcheck_info is not None else 'unavailable'}")
        else:
            print(f"stop is {type(stop).__name__}, not a Bugcheck")
        if triage is None:
            print(f"triage unavailable: {triage_error or 'no report'}")
        else:
            print("triage:")
            print(json.dumps(triage, indent=2, default=str))
        if thread is None:
            print("thread backtrace: unavailable")
        elif backtrace_error is not None:
            print(f"thread backtrace unavailable: {backtrace_error}")
        else:
            print(f"thread backtrace (tid={thread.tid}):")
            for frame in frames:
                print(f"  #{frame.index} {frame.symbol or hex(frame.ip)}")


if __name__ == "__main__":
    main()
