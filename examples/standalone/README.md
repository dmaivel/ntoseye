# Examples

This directory contains standalone [Python SDK](../../docs/scripting/sdk.md) scripts. To run a script, start it directly, for example `python list_processes.py`.

Most read-only scripts use the passive `memory` backend by default. These scripts do not pause the guest.

`kernel_snapshot.py` and `thread_stacks.py` use `kd` by default, for the CPU views. For passive inspection, use `--backend memory` with these scripts.

Scripts that control execution use `kd` by default. They need `gdb` or `kd`. Timeouts are in seconds. If a script supports it, `--timeout 0` makes the script wait with no time limit.

| Script | Shows |
| --- | --- |
| `list_processes.py` | Process handles keyed by PID and loaded kernel modules (read-only). |
| `walk_modules.py` | `Type.walk()` and typed cursors for `PsLoadedModuleList` (read-only). |
| `walk_struct.py` | `_EPROCESS` fields and a process-bound thread namespace (read-only). |
| `inspect_process.py` | Process-bound memory and PEB inspection, with no global process selection (read-only). |
| `user_process.py` | PEB/process-parameter cursors, loader modules, and heap handles (read-only). |
| `search_details.py` | `Memory.search()` and per-hit module/section/symbol attribution (read-only). |
| `kernel_snapshot.py` | Version, pool usage, and sessions. With `kd` or `gdb`, it also inspects CPUs. With `kd`, it reads MSRs. `--dump` writes a dump and opens it again. |
| `pci_devices.py` | All PCI functions in `lspci` style. For a vendor/device that you select, the BARs, capabilities, and command/status flags (`kd` or `gdb`). |
| `kernel_hooks.py` | SSDT entries outside `nt`/`win32k`, notify callbacks by owning module, and IDT gates outside NT. It reads `Diagnostic` fields. If it flags an item, it exits with code 1. |
| `breakpoint_trace.py` | A breakpoint handle, typed stops, and a `run()` loop. |
| `step_and_handles.py` | `step()`, live `Breakpoint` handles, and the writable `enabled` property. |
| `scoped_breakpoint.py` | Process-scoped, conditional, pass-counted, and one-shot breakpoints; `step_out()` and `run_to()`. |
| `filter_with_when.py` | Python `when` predicates that stop only in a named process. |
| `watch_field.py` | A write watchpoint on `_KPRCB.CurrentThread`, with writer symbol and thread backtrace. |
| `call_trace.py` | `step(until="call")` and a bounded `trace_calls()` call tree. |
| `crash_triage.py` | Offline dump stop context, triage report, and an available thread backtrace. |
| `thread_stacks.py` | Process-bound thread and frame handles, including the stacks of parked threads. `--backend memory` reads a paused VM passively. The default `kd` backend also shows the CPU of a running thread. |
| `secure_kernel.py` | The modules of the VBS secure kernel, walked with `nt!` types in VTL1 memory. The address spaces of its trustlets. Read-only and experimental. Needs VBS. |
