# Choosing a backend

`ntoseye` can talk to a live target four ways. Pick with `--backend kd` (default), `--backend kdnet`, `--backend gdb`, or `--backend memory`. Crash-dump mode is a separate offline attach mode selected with `--dump <file>`.

| Capability | `kd` (default) | `kdnet` | `gdb` | `memory` | `--dump` |
| --- | --- | --- | --- | --- | --- |
| Transport | Windows KD over a serial pipe (KDCOM) | Windows KD over encrypted UDP | Hypervisor GDB stub | Direct VM-process memory | Offline crash-dump file |
| Guest configuration | Kernel debugging enabled | Kernel network debugging enabled | None | None | None |
| Host VM configuration | Serial socket | Reachable virtual NIC | Listening GDB stub | None | None |
| Execution control | Yes | Yes | Yes | No | No |
| Registers | Yes | Yes | Yes | No | Yes (crash context) |
| Memory reads | Yes | Yes | Yes | Yes | Yes |
| Kernel breakpoints | Yes | Yes | Yes | No | No |
| Usermode breakpoints | Yes | Yes | No | No | No |
| Hardware watchpoints | Yes | Yes | No | No | No |
| Model-specific registers | Yes | Yes | No | No | No |
| Reboot / forced crash | Yes | Yes | No | No | No |

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

Other hypervisors are untested with these integrations. Crash-dump analysis supports AMD64 and ARM64 dumps.

The initial KD handshake timeout is 8 seconds by default. For unusually slow guests, override it with `NTOSEYE_KD_TIMEOUT=<seconds>`.

## KDNET

Guest, host, and per-hypervisor setup for the `kdnet` backend is in the [KDNET guide](kdnet.md). In the guest, `kdnet.exe <host-ip> 50000` does the whole configuration and prints the key; on the host, `ntoseye --backend kdnet --kdnet-key <key>`.

## KD and KDNET memory sources

KD and KDNET accept `--memory-source auto|host|kd`:

- `auto` (default) reads direct VM-process memory only after its kernel PE header and live module-list links match the KD target; otherwise it falls back to KD.
- `host` requires matching direct VM-process memory and fails on mismatch.
- `kd` forces target-mediated reads: kernel-space addresses under any process context, and user-space addresses of the process the current processor is running (AMD64), go through `DbgKdReadVirtualMemory`; user space of any other process goes through `DbgKdReadPhysicalMemory` behind a host page walk whose translations are cached until the target next runs. Session space resolves in the halted processor's session, as in WinDbg.

The source controls reads. Where the target can service virtual writes, all sources use `DbgKdWriteVirtualMemory`; other addresses use a page walk and `DbgKdWritePhysicalMemory`. Virtual writes preserve guest write protection, copy-on-write, and residency handling. Physical or host-memory writes bypass those protections, and edits follow the physical frame if the guest remaps it.

The host mapping's identity is re-checked after a guest reboot rebuilds debugger state, not just at attach.

The `kd` source needs no hypervisor or VM-process access, so AMD64 and ARM64 Windows VMs or physical machines can be debugged across any routable network. Memory-backed commands require the target to be halted; remote latency also makes large scans slower than direct host memory. Every read is a request/reply round trip. Over KDCOM on an emulated UART the request alone costs about 2 ms before the target sees it: QEMU's 16550 hands the guest one byte per main-loop iteration at the FIFO trigger level KDCOM programs, and a KD request plus its ACK is ~90 bytes host-to-guest. The reply then costs about 5 µs per byte (a 2 KiB read is ~12 ms), and KDNET has neither floor. Prefer `--memory-source host` (the `auto` default) whenever the VM is local; otherwise the session is shaped to need few, short reads:

- Virtual reads through the target are served from a cache of 512-byte lines for as long as the target stays halted. A miss fetches from its line to the end of the request, so the fields of one structure cost a single request between them while a large read still costs the same 2 KiB requests it always did. The cache is dropped when the target runs and whenever the debugger writes memory or installs or removes a breakpoint.
- The host page walk (user space of a process other than the halted processor's) reads page-table entries in the same 512-byte lines, so adjacent pages share their upper-level entries and their run of PTEs; other physical reads get no read-ahead, since they may touch a device. A process's loader list is walked once per halt, however many of its threads are unwound.
- Module images are never copied whole. Attach reads each module's headers with one probe; the unwinder fetches 2 KiB blocks of `.pdata`/`.rdata` as its lookups touch them and keeps them for the session, and a stack walk reads the stack a page at a time.
- A module's PDB is remembered by the image identity the symbol server uses (`~/.ntoseye/symbols/identities`, keyed by file name, `TimeDateStamp`, and `SizeOfImage`, all of which the loader's module list already carries). A module seen in an earlier session is identified with no reads from the target; `lm` shows such modules' symbol source as `cached`. A remembered PDB that fails to load is forgotten and the module rediscovered from the target.

Process, kernel-module, and driver-object lists are walked only when something needs them (a listing command, a tab completion, a break context in a user-mode process) and the first walk per halt serves every later use until the target runs again. The process walk reads one span per `_EPROCESS` and consults the PEB only for names the kernel's 15-byte `ImageFileName` may have truncated, so the prompt after attach and each stop no longer waits on a full process walk.

## Memory introspection

The `memory` backend requires no guest or VM debug transport configuration:

```bash
ntoseye --backend memory
```

Execution control, registers, execution-context selection, breakpoints, debug output, bugcheck stops, and reload detection are unavailable in this mode. Run `capabilities` in the REPL for the exact backend feature matrix.
