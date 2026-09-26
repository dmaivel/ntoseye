# Troubleshooting

Common problems, by symptom. Integration-specific problems are covered with each integration: [driver replacement](../using/kdfiles.md#troubleshooting) and [disassembler integration](../integrations/gdbserver.md#troubleshooting).

## Attaching

**`VM process not found`.** `ntoseye` finds the VM by its hypervisor process: a process with `/dev/kvm` open (KVM/QEMU), a `vmware-vmx` process with `/dev/vmmon` open (VMware), or `qemu-aarch64-softmmu` (UTM). The VM must be powered on. To debug a target whose memory is not on this host, use `kd` or `kdnet` with `--memory-source kd`, which reads everything through the target.

**`permission denied reading from VM process`** (Linux). The kernel's Yama policy stops `ntoseye` from reading another process's memory. Either run `ntoseye` as root, or allow it for the session with `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`.

**`permission denied accessing VM process`** (macOS). Reading UTM's QEMU needs root: run `sudo ntoseye ...`. See the [UTM setup](../setup/utm.md).

**`Another instance of ntoseye is already attached`.** The `kd`, `kdnet`, and `gdb` backends allow one session per target. Close the other session, or use the `memory` backend alongside it, which is passive.

**The KD handshake times out.** Windows must be booted with kernel debugging on (`bcdedit /debug on` plus matching `/dbgsettings`), and its serial port or network settings must match the host's. `ntoseye` waits 8 seconds for the first handshake; for a slow guest, raise it with `NTOSEYE_KD_TIMEOUT=<seconds>`. The per-hypervisor pages under [Setting up](../setup/backends.md) list the exact settings.

**KDNET on QEMU never connects.** QEMU's default Hyper-V vendor ID makes Windows pick Hyper-V's synthetic debug device, which QEMU does not provide. Set the vendor ID to `KVMKVMKVM` and power the VM fully off and on; see [KVM/QEMU](../setup/kvm-qemu.md#kdnet). `ntoseye configure` does this for libvirt guests.

**The guest hangs with the `gdb` backend.** Turn kernel debug mode off in the guest (`bcdedit /debug off`). With it on, Windows expects a KD debugger to answer breaks, and nothing on the GDB side does. See [KVM/QEMU](../setup/kvm-qemu.md#gdb-stub).

**UTM kills the VM when the `gdb` backend attaches.** Turn "Use Hypervisor" off in the VM's QEMU settings; see [UTM](../setup/utm.md#gdb-stub).

**The guest's own hypervisor does not boot under nested virtualization** (VBS, Hyper-V, WSL2). On the tested host `host-passthrough` failed and a custom CPU model with `vmx` worked; see [KVM/QEMU](../setup/kvm-qemu.md#virtualization-based-security-vbs).

## Symbols

**{command}`lm` shows a module's symbols as `failed`,** or its frames stay `module+offset`. Microsoft has not published a PDB for that build, or the download failed. Add your own symbol server ahead of Microsoft's with `--pdb-server <url>` (repeatable) or `NTOSEYE_PDB_SERVERS="<url>;<url>"`, or point {command}`.sympath` at local PDBs; see [Symbols and source](../using/symbols.md). `--force-download-symbols` downloads again even when the cache has a copy.

**A module shows `fetching`.** Its symbols are downloading in the background; frames in it read `module+offset` until they arrive.

## Breakpoints and stepping

**A breakpoint scoped to one process slows the whole guest.** A user-mode breakpoint in a shared DLL traps every process that runs the code, and the hits outside its scope are resumed one by one. [Breakpoints in shared pages](../using/breakpoints.md#user-mode-breakpoints-in-shared-pages) measures the cost and lists ways around it.

**Breakpoints fail at some addresses after a session was killed.** KD has a 32-entry breakpoint table, and a session killed with `SIGKILL` leaves its entries installed. The next attach reclaims entries no live session owns; see [Breakpoints](../using/breakpoints.md).

**A step is refused under VBS.** With Windows running its own hypervisor, the `gdb` backend cannot step `syscall`, `sysret`, `int`, or far transfers; use `kd` or `kdnet` for those. See [VBS and the Windows hypervisor](../platforms/vbs.md).

## Memory

**A read fails on a page that should exist.** The page may be paged out to disk. {command}`.pagein` asks the guest to bring it back; see [paged-out memory](../using/memory.md#paged-out-memory).

**Large reads over KD are slow.** Every read over KD is a round trip to the target. When the VM runs on this host, read its memory directly with `--memory-source host` (the default `auto` does when it can); see [Memory and paging](../using/memory.md).

## Diagnostic output

These environment variables make `ntoseye` explain what it is doing, on standard error:

| Variable | Prints |
| --- | --- |
| `NTOSEYE_KD_TRACE=1` | Every KD request and reply, with the time since the first line |
| `NTOSEYE_KD_TRACE_BYTES=1` | The raw bytes on the KD transport |
| `NTOSEYE_GDB_TRACE=1` | Every GDB remote protocol packet, both to the hypervisor's stub and, for `ntoseye gdbserver`, to its client |
| `NTOSEYE_UNWIND_TRACE=1` | Each step of every stack unwind, to diagnose a wrong or short stack |

## Reporting a bug

Open an issue on [GitHub](https://github.com/dmaivel/ntoseye/issues) with `ntoseye --version`, the output of {command}`vertarget` and {command}`capabilities`, the backend and hypervisor you use, and, if it helps, a trace from one of the variables above.
