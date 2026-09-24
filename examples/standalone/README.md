# Examples

Standalone [Python SDK](../../docs/sdk.md) scripts. Run one directly, e.g. `python list_processes.py`. Most read-only scripts default to the passive `memory` backend and never pause the guest. `kernel_snapshot.py` and `thread_stacks.py` keep the `kd` default for CPU views but accept `--backend memory` for passive inspection. Scripts that control execution default to `kd` and require `gdb` or `kd`; timeouts are in seconds (`--timeout 0` means wait indefinitely where supported).

| Script | Shows |
| --- | --- |
| `list_processes.py` | Process handles keyed by PID and loaded kernel modules (read-only). |
| `walk_modules.py` | `Type.walk()` and typed cursors for `PsLoadedModuleList` (read-only). |
| `walk_struct.py` | `_EPROCESS` fields and a process-bound thread namespace (read-only). |
| `inspect_process.py` | Process-bound memory and PEB inspection without global process selection (read-only). |
| `user_process.py` | PEB/process-parameter cursors, loader modules, and heap handles (read-only). |
| `search_details.py` | `Memory.search()` and per-hit module/section/symbol attribution (read-only). |
| `kernel_snapshot.py` | Version, pool usage, and sessions; `kd`/`gdb` also inspect CPUs, `kd` reads MSRs, and `--dump` writes/reopens a dump. |
| `breakpoint_trace.py` | A breakpoint handle, typed stops, and a `run()` loop. |
| `step_and_handles.py` | `step()`, live `Breakpoint` handles, and the writable `enabled` property. |
| `scoped_breakpoint.py` | Process-scoped, conditional, pass-counted, and one-shot breakpoints; `step_out()` and `run_to()`. |
| `filter_with_when.py` | Python `when` predicates for stopping only in a named process. |
| `watch_field.py` | A write watchpoint on `_KPRCB.CurrentThread`, with writer symbol and thread backtrace. |
| `call_trace.py` | `step(until="call")` and a bounded `trace_calls()` call tree. |
| `crash_triage.py` | Offline dump stop context, triage report, and an available thread backtrace. |
| `thread_stacks.py` | Process-bound thread and frame handles, including parked-thread stacks; `--backend memory` reads a paused VM passively, while the default `kd` also reports a running thread's CPU. |
