# Choosing a backend

`ntoseye` can talk to the guest three ways. Pick with `--backend kd` (default), `--backend gdb`, or `--backend memory`.

| Capability | `kd` (default) | `gdb` | `memory` |
| --- | --- | --- | --- |
| Transport | Windows KD over a serial pipe | Hypervisor GDB stub | Direct VM-process memory |
| Guest configuration | Kernel debugging enabled | None | None |
| Host VM configuration | Serial socket | Listening GDB stub | None |
| Guest architectures | AMD64, ARM64 | AMD64 | AMD64, ARM64 |
| Execution control | Yes | Yes | No |
| Kernel breakpoints | Yes | Yes | No |
| Usermode breakpoints | AMD64 only | No | No |
| Hardware watchpoints | AMD64 only | No | No |

ARM64 guests are supported through `kd` and `memory` under UTM; `gdb` and crash-dump analysis remain AMD64-only.

> [!NOTE]
> Do not enable kernel debug mode (`bcdedit /debug on`) in the guest when using the `gdb` backend. That setting is only for the `kd` backend, and the `gdb` backend's whole advantage is that the guest is unaware it's being debugged. With debug mode on, the kernel changes behaviour (anti-debug code, PatchGuard) and expects a KD debugger to service breaks, while nothing on the `gdb` side answers the KD transport, so the guest can hang on `DbgBreakPoint`/exceptions. Leave debug mode off.

The initial KD handshake timeout is 8 seconds by default. For unusually slow guests, override it with `NTOSEYE_KD_TIMEOUT=<seconds>`.

## Memory introspection

The `memory` backend requires no guest or VM debug transport configuration:

```bash
ntoseye --backend memory
```

Execution control, registers, execution-context selection, breakpoints, debug output, bugcheck stops, and reload detection are unavailable in this mode. Run `capabilities` in the REPL for the exact backend feature matrix.

## Hypervisor setup

Host-side configuration is specific to the hypervisor:

- [KVM/QEMU (including libvirt/virt-manager)](kvm-qemu.md)
- [VMware Workstation](vmware.md)
- [UTM (macOS, Apple Silicon)](utm.md)
