# Examples

Standalone [Python SDK](../../docs/sdk.md) scripts. Run one directly, e.g. `python list_processes.py`, against a guest with the debug transport up. Each takes `--backend`/`--connect`; the read-only ones default to the passive `memory` backend and never pause the guest, the rest need `kd` or `gdb`.

| Script | Shows |
| --- | --- |
| `list_processes.py` | Process and kernel-module listing (read-only). |
| `walk_modules.py` | Walking `PsLoadedModuleList` with typed struct cursors (read-only). |
| `walk_struct.py` | `_EPROCESS` field access through cursors (read-only). |
| `inspect_process.py` | Attaching the inspection scope to a process and walking its threads (read-only). |
| `user_process.py` | PEB, loader modules, and heaps of a user process; `_UNICODE_STRING` reads (read-only). |
| `search_details.py` | Memory search with per-hit module/section/symbol attribution (read-only). |
| `kernel_snapshot.py` | Version, per-CPU thread and IRQL, MSRs, top pool tags, sessions; optional full dump write and reopen. |
| `breakpoint_trace.py` | A breakpoint and a `run()` loop with `StopOutcome`. |
| `step_and_handles.py` | `step()`, live `Breakpoint` handles, enable/disable in place. |
| `scoped_breakpoint.py` | Process-scoped, conditional, pass-counted, and one-shot breakpoints; `step_out()` and `run_to()`. |
| `thread_stacks.py` | `select_thread()` over a process's threads (parked stacks, swapped-out and terminated ones reported), `select_frame()`. |
