# Choosing a backend

`ntoseye` can talk to the guest four ways. Pick with `--backend kd` (default), `--backend kdnet`, `--backend gdb`, or `--backend memory`.

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

Live support depends on the host OS, hypervisor, and guest architecture. The currently supported combinations are:

| Host OS | Hypervisor | Guest architecture | `kd` | `kdnet` | `gdb` | `memory` |
| --- | --- | --- | --- | --- | --- | --- |
| Linux | KVM/QEMU | AMD64 | Yes | Yes | Yes | Yes |
| Linux | VMware Workstation | AMD64 | Yes | Yes | Yes | Yes |
| macOS | UTM (QEMU/HVF) | ARM64 | Yes | Yes | No | Yes |

Combinations not listed above are untested. Crash-dump analysis is currently AMD64-only.

The initial KD handshake timeout is 8 seconds by default. For unusually slow guests, override it with `NTOSEYE_KD_TIMEOUT=<seconds>`.

## KDNET

`ntoseye configure` prompts for the host IPv4 address, applies any required hypervisor changes, and prints the guest and launch commands.

Hypervisor-specific requirements:

- [KVM/QEMU](kvm-qemu.md#kdnet): set the libvirt Hyper-V vendor ID to `KVMKVMKVM`, then completely power off and restart the VM; a Windows reboot is insufficient. `ntoseye configure` applies the vendor override automatically.
- [VMware Workstation](vmware.md#kdnet): no additional virtual hardware configuration is needed, but the guest's bridged, NAT, or host-only NIC must be able to reach the selected host address.
- [UTM](utm.md#kdnet): disable Secure Boot before changing the Windows BCD debug settings and ensure the guest NIC can reach the selected macOS address. Use `--memory-source kd` for a fully remote session that needs no root or UTM-process access.

For manual setup, the Windows steps are common to every hypervisor. From an elevated guest prompt, prefer Microsoft's `kdnet.exe <host-ip> 50000` utility. It validates the debug NIC, configures its PCI `busparams`, and prints the four-part encryption key. The equivalent manual setup is:

```powershell
bcdedit /debug on
bcdedit /dbgsettings net hostip:<host-ip> port:50000
bcdedit /set "{dbgsettings}" busparams <bus>.<device>.<function>
```

Use the host address described by the applicable [hypervisor setup guide](#hypervisor-setup), permit inbound UDP on the selected port, and reboot Windows. Then start `ntoseye` with the printed key:

```bash
ntoseye --backend kdnet --kdnet-key 1.2.3.4
```

KDNET listens on `0.0.0.0:50000` by default. Use `--connect <listen-address>:<port>` to select another listener.

## KD and KDNET memory sources

KD and KDNET accept `--memory-source auto|host|kd`:

- `auto` (default) uses direct VM-process memory only after its kernel PE header and live module-list links match the KD target; otherwise it falls back to KD.
- `host` requires matching direct VM-process memory and fails on mismatch.
- `kd` forces authenticated `DbgKdReadPhysicalMemory` and `DbgKdWritePhysicalMemory` requests.

The `kd` source needs no hypervisor or VM-process access, so AMD64 and ARM64 Windows VMs or physical machines can be debugged across any routable network. Memory-backed commands require the target to be halted; remote latency also makes large scans slower than direct host memory.

## Memory introspection

The `memory` backend requires no guest or VM debug transport configuration:

```bash
ntoseye --backend memory
```

Execution control, registers, execution-context selection, breakpoints, debug output, bugcheck stops, and reload detection are unavailable in this mode. Run `capabilities` in the REPL for the exact backend feature matrix.
