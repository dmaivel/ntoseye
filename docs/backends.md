# Choosing a backend

`ntoseye` can talk to the guest three ways. Pick with `--backend kd` (default), `--backend gdb`, or `--backend memory`.

| Capability | `kd` (default) | `gdb` | `memory` |
| --- | --- | --- | --- |
| Transport | Windows KD over a serial pipe | Hypervisor GDB stub | Direct VM-process memory |
| Guest configuration | Kernel debugging enabled | None | None |
| Host VM configuration | Serial socket | Listening GDB stub | None |
| Hypervisors | KVM/QEMU, VMware, UTM | KVM/QEMU, VMware | KVM/QEMU, VMware, UTM |
| Guest architectures | AMD64, ARM64 | AMD64 | AMD64, ARM64 |
| Execution control | Yes | Yes | No |
| Kernel breakpoints | Yes | Yes | No |
| Usermode breakpoints | AMD64 only | No | No |
| Hardware watchpoints | AMD64 only | No | No |

ARM64 guests are supported through `kd` and `memory` under UTM; `gdb` and crash-dump analysis remain AMD64-only.

The initial KD handshake timeout is 8 seconds by default. For unusually slow guests, override it with `NTOSEYE_KD_TIMEOUT=<seconds>`.

## Hypervisor setup

Host-side configuration is specific to the hypervisor:

- [KVM/QEMU (including libvirt/virt-manager)](kvm-qemu.md)
- [VMware Workstation](vmware.md)
- [UTM (macOS, Apple Silicon)](utm.md)

## Memory introspection

The `memory` backend requires no guest or VM debug transport configuration:

```bash
ntoseye --backend memory
```

Execution control, registers, execution-context selection, breakpoints, debug output, bugcheck stops, and reload detection are unavailable in this mode. Run `capabilities` in the REPL for the exact backend feature matrix.
