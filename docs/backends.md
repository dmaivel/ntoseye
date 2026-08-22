# Choosing a backend

`ntoseye` can talk to the guest three ways. Pick with `--backend kd` (default), `--backend gdb`, or `--backend memory`.

| Capability | `kd` (default) | `gdb` | `memory` |
| --- | --- | --- | --- |
| Transport | Windows KD over a serial pipe | Hypervisor GDB stub | Direct VM-process memory |
| Guest configuration | Kernel debugging enabled | None | None |
| Host VM configuration | Serial socket | Listening GDB stub | None |
| Execution control | Yes | Yes | No |
| Kernel breakpoints | Yes | Yes | No |
| Usermode breakpoints | AMD64 only | No | No |
| Hardware watchpoints | AMD64 only | No | No |

## Hypervisor setup

Host-side configuration is specific to the hypervisor:

- [KVM/QEMU (including libvirt/virt-manager)](kvm-qemu.md)
- [VMware Workstation](vmware.md)
- [UTM (macOS, Apple Silicon)](utm.md)

## Supported live environments

Live support depends on the host OS, hypervisor, and guest architecture. The currently supported combinations are:

| Host OS | Hypervisor | Guest architecture | `kd` | `gdb` | `memory` |
| --- | --- | --- | --- | --- | --- |
| Linux | KVM/QEMU | AMD64 | Yes | Yes | Yes |
| Linux | VMware Workstation | AMD64 | Yes | Yes | Yes |
| macOS | UTM (QEMU/HVF) | ARM64 | Yes | No | Yes |

Combinations not listed above are untested. Crash-dump analysis is currently AMD64-only.

The initial KD handshake timeout is 8 seconds by default. For unusually slow guests, override it with `NTOSEYE_KD_TIMEOUT=<seconds>`.

## Memory introspection

The `memory` backend requires no guest or VM debug transport configuration:

```bash
ntoseye --backend memory
```

Execution control, registers, execution-context selection, breakpoints, debug output, bugcheck stops, and reload detection are unavailable in this mode. Run `capabilities` in the REPL for the exact backend feature matrix.
