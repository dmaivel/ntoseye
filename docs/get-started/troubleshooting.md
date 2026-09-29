# Troubleshooting

This page lists common problems by symptom. Problems that are specific to an integration are on the page of that integration: [driver replacement](../using/kdfiles.md#troubleshooting) and [disassembler integration](../integrations/gdbserver.md#troubleshooting).

## Attaching

**`VM process not found`.** `ntoseye` did not find the hypervisor process of the VM. It looks for one of these processes:

- A process with `/dev/kvm` open (KVM/QEMU).
- A `vmware-vmx` process with `/dev/vmmon` open (VMware).
- A `qemu-aarch64-softmmu` process (UTM).

Make sure that the VM is powered on. If the memory of the target is not on this host, use `kd` or `kdnet` with `--memory-source kd`, which reads all data through the target.

**`permission denied reading from VM process`** (Linux). The Yama policy of the Linux kernel prevents `ntoseye` from reading the memory of another process. Either run `ntoseye` as root, or allow the access for the session with `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`.

**`permission denied accessing VM process`** (macOS). `ntoseye` must run as root to read the memory of the UTM QEMU process, so run `sudo ntoseye ...`. See the [UTM setup](../setup/utm.md).

**`Another instance of ntoseye is already attached`.** The `kd`, `kdnet`, and `gdb` backends allow only one session for each target. Close the other session, or use the `memory` backend, which is passive, at the same time as the other session.

**The KD handshake times out.** For a handshake, Windows must boot with kernel debugging on, and its serial port or network settings must match the host settings. `ntoseye` waits 8 seconds for the first handshake. To fix the problem:

- Make sure that Windows boots with kernel debugging on: `bcdedit /debug on`, with matching `/dbgsettings`.
- Make sure that the serial port or network settings of Windows match the host settings. The pages for each hypervisor under [Setting up](../setup/backends.md) list the settings.
- If the guest is slow, increase the timeout with `NTOSEYE_KD_TIMEOUT=<seconds>`.

**KDNET on QEMU never connects.** With the default Hyper-V vendor ID of QEMU, Windows selects the Hyper-V synthetic debug device, which QEMU does not supply. To fix the problem:

1. Set the vendor ID to `KVMKVMKVM`. For libvirt guests, `ntoseye configure` makes this change.
2. Power the VM fully off, then power it on again.

See [KVM/QEMU](../setup/kvm-qemu.md#kdnet).

**The guest hangs with the `gdb` backend.** When kernel debug mode is on, Windows expects a KD debugger to reply to breaks, and nothing on the GDB side replies. Turn kernel debug mode off in the guest with `bcdedit /debug off`. See [KVM/QEMU](../setup/kvm-qemu.md#gdb-stub).

**`the VM runs under HVF`** (the `gdb` backend under UTM). QEMU versions before 10.1 terminate a VM that runs under HVF when a debugger attaches to its GDB stub, so `ntoseye` does not connect to the VM and shows this error. To work around it, do one of the following:

- Turn off "Use Hypervisor" in the QEMU settings of the VM.
- Use the `memory`, `kd`, or `kdnet` backend.
- If your UTM has QEMU 10.1 or later, set `NTOSEYE_GDB_ON_HVF=1` so that `ntoseye` connects under HVF.

See [UTM](../setup/utm.md#gdb-stub).

**The guest's own hypervisor does not boot under nested virtualization** (VBS, Hyper-V, WSL2). On the tested host, the `host-passthrough` CPU model failed and a custom CPU model with `vmx` worked. See [KVM/QEMU](../setup/kvm-qemu.md#virtualization-based-security-vbs).

## Symbols

**{command}`lm` shows a module's symbols as `failed`,** or its frames stay `module+offset`. Microsoft did not publish a PDB for that build, or the download failed. To fix it, do one of the following:

- Add your own symbol server before the Microsoft server. Use `--pdb-server <url>` or `NTOSEYE_PDB_SERVERS="<url>;<url>"`. You can use `--pdb-server` more than once.
- Set {command}`.sympath` to a location with local PDBs.

See [Symbols and source](../using/symbols.md).

For a driver that you built in the guest, `ntoseye` can [rebuild the PDB from guest memory](../using/symbols.md). If this fails, {command}`lmv` shows the reason (`guest memory: ...`). Rebuild the driver to put the PDB back into the file cache.

To download the symbols again when the cache has a copy, use `--force-download-symbols`.

**A module shows `fetching`.** `ntoseye` downloads the symbols of the module in the background, and until the download completes, the frames in the module show as `module+offset`.

## Breakpoints and stepping

**A user-mode breakpoint over KD fails with `NTSTATUS 0xc0000001 for api 0x313e`.** When VBS is on, Windows does not allow the debugger to write to user-mode code, and `ntoseye` always writes breakpoints through KD. The `--memory-source` option does not change this because it controls only reads. Use a hardware execution breakpoint instead ({command}`ba` `e1`, or `hardware=True` in the SDK), which hits without writing to memory. There are four hardware breakpoint slots.

**A breakpoint scoped to one process slows the whole guest.** A user-mode breakpoint in a shared DLL stops each process that runs the code, and `ntoseye` resumes each hit outside the scope of the breakpoint, one at a time. [Breakpoints in shared pages](../using/breakpoints.md#user-mode-breakpoints-in-shared-pages) shows the cost and lists workarounds.

**Breakpoints fail at some addresses after a session was killed.** KD has a breakpoint table with 32 entries. If a session is killed with `SIGKILL`, its entries stay installed until the next attach, which frees the entries that no live session owns. See [Breakpoints](../using/breakpoints.md).

## Memory

**A read fails on a page that should exist.** The page can be paged out to disk, and {command}`.pagein` tells the guest to bring it back. See [paged-out memory](../using/memory.md#paged-out-memory).

**Large reads over KD are slow.** Each read over KD is a round trip to the target. If the VM runs on this host, read its memory directly with `--memory-source host`, which the default, `auto`, does when it can. See [Memory and paging](../using/memory.md).

## Diagnostic output

These environment variables make `ntoseye` show what it does on standard error.

| Variable | Prints |
| --- | --- |
| `NTOSEYE_KD_TRACE=1` | Each KD request and reply, with the time since the first line |
| `NTOSEYE_KD_TRACE_BYTES=1` | The raw bytes on the KD transport |
| `NTOSEYE_GDB_TRACE=1` | Each GDB remote protocol packet to the stub of the hypervisor and, for `ntoseye gdbserver`, each packet to its client |
| `NTOSEYE_UNWIND_TRACE=1` | Each step of each stack unwind, to diagnose a wrong or short stack |

## Reporting a bug

Open an issue on [GitHub](https://github.com/dmaivel/ntoseye/issues) and include:

- The output of `ntoseye --version`.
- The output of {command}`vertarget` and {command}`capabilities`.
- The backend and the hypervisor that you use.
- If it helps, a trace from one of the variables above.
