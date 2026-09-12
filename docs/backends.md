# Choosing a backend

`ntoseye` can talk to the target four ways. Pick with `--backend kd` (default), `--backend kdnet`, `--backend gdb`, or `--backend memory`.

| Capability | `kd` (default) | `kdnet` | `gdb` | `memory` |
| --- | --- | --- | --- | --- |
| Transport | Windows KD over a serial pipe (KDCOM) | Windows KD over encrypted UDP | Hypervisor GDB stub | Direct VM-process memory |
| Guest configuration | Kernel debugging enabled | Kernel network debugging enabled | None | None |
| Host VM configuration | Serial socket | Reachable virtual NIC | Listening GDB stub | None |
| Execution control | Yes | Yes | Yes | No |
| Kernel breakpoints | Yes | Yes | Yes | No |
| Usermode breakpoints | AMD64 only | AMD64 only | No | No |
| Hardware watchpoints | AMD64 only | AMD64 only | No | No |

## Hypervisor setup

Host-side configuration is specific to the hypervisor:

- [KVM/QEMU (including libvirt/virt-manager)](kvm-qemu.md)
- [VMware Workstation](vmware.md)
- [UTM (macOS, Apple Silicon)](utm.md)

## Supported live environments

Any Windows 10/11 target reachable over the network is debuggable with `kdnet` (see the [KDNET guide](kdnet.md)); that path has nothing hypervisor-specific in it. The combinations below are where `ntoseye` additionally reads VM memory directly, sets the VM up with `ntoseye configure`, and offers the `gdb` and `memory` backends:

| Host OS | Hypervisor | Guest architecture | `kd` | `kdnet` | `gdb` | `memory` |
| --- | --- | --- | --- | --- | --- | --- |
| Linux | KVM/QEMU | AMD64 | Yes | Yes | Yes | Yes |
| Linux | VMware Workstation | AMD64 | Yes | Yes | Yes | Yes |
| macOS | UTM (QEMU/HVF) | ARM64 | Yes | Yes | No | Yes |

Other hypervisors are untested with these integrations. Crash-dump analysis is currently AMD64-only.

The initial KD handshake timeout is 8 seconds by default. For unusually slow guests, override it with `NTOSEYE_KD_TIMEOUT=<seconds>`.

## KDNET

Guest, host, and per-hypervisor setup for the `kdnet` backend is in the [KDNET guide](kdnet.md). In the guest, `kdnet.exe <host-ip> 50000` does the whole configuration and prints the key; on the host, `ntoseye --backend kdnet --kdnet-key <key>`.

## KD and KDNET memory sources

KD and KDNET accept `--memory-source auto|host|kd`:

- `auto` (default) uses direct VM-process memory only after its kernel PE header and live module-list links match the KD target; otherwise it falls back to KD.
- `host` requires matching direct VM-process memory and fails on mismatch.
- `kd` forces target-mediated reads: kernel-space addresses, and user-space addresses of the process the current processor is running (AMD64), go through `DbgKdReadVirtualMemory`; everything else through `DbgKdReadPhysicalMemory` behind a host page walk whose translations are cached until the target next runs. Writes use `DbgKdWritePhysicalMemory`.

The `kd` source needs no hypervisor or VM-process access, so AMD64 and ARM64 Windows VMs or physical machines can be debugged across any routable network. Memory-backed commands require the target to be halted; remote latency also makes large scans slower than direct host memory. Every read is a request/reply round trip. Over KDCOM on an emulated UART the request alone costs about 3 ms before the target sees it: QEMU's 16550 hands the guest one byte per main-loop iteration at the FIFO trigger level KDCOM programs, and a KD request plus its ACK is ~90 bytes host-to-guest. The reply direction is cheap (~5 µs/byte), and KDNET has no such floor. So over KDCOM what matters is how many reads a step needs, not how many bytes; prefer `--memory-source host` (the `auto` default) whenever the VM is local:

- Module images are never copied whole. Attach reads each module's headers with one probe; the unwinder fetches 2 KiB blocks of `.pdata`/`.rdata` as its lookups touch them and keeps them for the session, and a stack walk reads the stack a page at a time.
- A module's PDB is remembered by the image identity the symbol server uses (`~/.ntoseye/symbols/identities`, keyed by file name, `TimeDateStamp`, and `SizeOfImage`, all of which the loader's module list already carries). A module seen in an earlier session is identified with no reads from the target; `lm` shows such modules' symbol source as `cached`. A remembered PDB that fails to load is forgotten and the module rediscovered from the target.

Process, kernel-module, and driver-object lists are walked only when something needs them (a listing command, a tab completion, a break context in a user-mode process) and the first walk per halt serves every later use until the target runs again. The process walk reads one span per `_EPROCESS` and consults the PEB only for names the kernel's 15-byte `ImageFileName` may have truncated, so the prompt after attach and each stop no longer waits on a full process walk.

## Memory introspection

The `memory` backend requires no guest or VM debug transport configuration:

```bash
ntoseye --backend memory
```

Execution control, registers, execution-context selection, breakpoints, debug output, bugcheck stops, and reload detection are unavailable in this mode. Run `capabilities` in the REPL for the exact backend feature matrix.
