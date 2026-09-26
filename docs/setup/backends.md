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
| Hardware watchpoints | Yes | Yes | Yes | No | No |
| Model-specific registers | Yes | Yes | No | No | No |
| Reboot / forced crash | Yes | Yes | No | No | No |
| Bugcheck stops | Reported by the target | Reported by the target | Trapped at `nt!KeBugCheckEx` | No | Read from the dump |
| [VTL1 inspection](../platforms/vbs.md) (AMD64) | Host memory source only | Host memory source only | Yes | Yes | No |

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
| macOS | UTM (QEMU/HVF) | ARM64 | Yes | Yes | Yes (see below) | Yes |

Other hypervisors are untested with these integrations. Crash-dump analysis supports AMD64 and ARM64 dumps.

Under UTM the `gdb` backend needs "Use Hypervisor" turned off, because QEMU aborts the VM when a debugger enables guest debugging on HVF; the [UTM guide](utm.md) has the details. The other backends are unaffected, since none of them asks the hypervisor for debug traps.

The initial KD handshake timeout is 8 seconds by default. For unusually slow guests, override it with `NTOSEYE_KD_TIMEOUT=<seconds>`.

## KDNET

Guest, host, and per-hypervisor setup for the `kdnet` backend is in the [KDNET guide](kdnet.md). In the guest, `kdnet.exe <host-ip> 50000` does the whole configuration and prints the key; on the host, `ntoseye --backend kdnet --kdnet-key <key>`.

## Memory sources

KD and KDNET read guest memory from the VM process on this host when they can, and through the target otherwise; `--memory-source auto|host|kd` chooses. The [memory guide](../using/memory.md#where-reads-come-from) explains each source, writes, and paged-out memory.

## Memory introspection

The `memory` backend requires no guest or VM debug transport configuration:

```bash
ntoseye --backend memory
```

Execution control, registers, execution-context selection, breakpoints, debug output, bugcheck stops, and reload detection are unavailable in this mode. Run {command}`capabilities` in the REPL for the exact backend feature matrix.

## Secure kernel (VTL1)

`.vtl 1` and {command}`!trustlets` need direct host memory: the `memory` and `gdb` backends, or `kd`/`kdnet` while reads come from host memory. Only `gdb` stops, steps, and breaks in VTL1. See the [VBS guide](../platforms/vbs.md) for what each backend supports there.
