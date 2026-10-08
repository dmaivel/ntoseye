# Examples

This directory contains standalone [Python SDK](../../docs/scripting/sdk.md) scripts, which you run directly, for example `python list_processes.py`.

Most read-only scripts use the passive `memory` backend by default and do not pause the guest. `kernel_snapshot.py` and `thread_stacks.py` use `kd` by default for their CPU views, but accept `--backend memory` for passive inspection.

Scripts that control execution use `kd` by default and need `gdb` or `kd`. Timeouts are in seconds, and where a script supports it, `--timeout 0` makes it wait with no time limit.

The scripts about the Windows hypervisor's partitions use `gdb`, and need the VM's `hv-evmcs` enlightenment and a guest that runs under the hypervisor, such as a Windows Sandbox.

| Script | Shows |
| --- | --- |
| `list_processes.py` | Process handles keyed by PID and loaded kernel modules (read-only). |
| `walk_modules.py` | `Type.walk()` and typed cursors for `PsLoadedModuleList` (read-only). |
| `walk_struct.py` | `_EPROCESS` fields and a process-bound thread namespace (read-only). |
| `inspect_process.py` | Process-bound memory and PEB inspection, with no global process selection (read-only). |
| `user_process.py` | PEB/process-parameter cursors, loader modules, and heap handles (read-only). |
| `search_details.py` | `Memory.search()` and per-hit module/section/symbol attribution (read-only). |
| `kernel_snapshot.py` | Version, pool usage, and sessions. It also inspects CPUs with `kd` or `gdb` and reads MSRs with `kd`, and `--dump` writes a dump and opens it again. |
| `pci_devices.py` | All PCI functions in `lspci` style, and the BARs, capabilities, and command/status flags of a vendor/device that you select (`kd` or `gdb`). |
| `kernel_hooks.py` | SSDT entries outside `nt`/`win32k`, notify callbacks by owning module, and IDT gates outside NT, read from `Diagnostic` fields. It exits with code 1 if it flags an item. |
| `virtio_watch.py` | Two looks at every virtio queue a set time apart (read-only): what each queue's driver published, the device completed, and the driver took back in between, and the queues that `!virtio` would call stuck. `--vring` lists the requests that a stuck queue holds. It exits with code 1 if it flags a queue, and needs the private PDBs of the virtio-win drivers. |
| `breakpoint_trace.py` | A breakpoint handle, typed stops, and a `run()` loop. |
| `step_and_handles.py` | `step()`, live `Breakpoint` handles, and the writable `enabled` property. |
| `scoped_breakpoint.py` | Process-scoped, conditional, pass-counted, and one-shot breakpoints; `step_out()` and `run_to()`. |
| `filter_with_when.py` | Python `when` predicates that stop only in a named process. |
| `watch_field.py` | A write watchpoint on `_KPRCB.CurrentThread`, with writer symbol and thread backtrace. |
| `call_trace.py` | `step(until="call")` and a bounded `trace_calls()` call tree. |
| `crash_triage.py` | Offline dump stop context, triage report, and an available thread backtrace. |
| `thread_stacks.py` | Process-bound thread and frame handles, including the stacks of parked threads. `--backend memory` reads a paused VM passively, and the default `kd` backend also shows the CPU of a running thread. |
| `secure_kernel.py` | The modules of the VBS secure kernel, walked with `nt!` types in VTL1 memory, and the address spaces of its trustlets (read-only and experimental; needs VBS). |
| `guest_partition.py` | The Windows guests of the hypervisor's partitions, such as a Windows Sandbox, through `select_partition()`: each guest's kernel, process count, and VP stacks, and with `--process`, a process's thread stacks. A partition without a Windows kernel, such as WSL2's, is reported (read-only and experimental). |
| `hypercall_watch.py` | A hypercall breakpoint on one partition whose `when=` callback counts the callers through `hypercall_caller()`, then one stop with the hypervisor's own stack (`Cpu.backtrace()`) and the stack of the calling VP in the guest's kernel (experimental). |
| `guest_break.py` | A hardware breakpoint in a Windows guest's kernel, set in its view: the process, thread, and stack that reached it, then `step()` and `step_out()` on that thread (experimental). |
