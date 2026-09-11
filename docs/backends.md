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

A guest restart does not require reattaching. The target pokes the listener every three seconds in every state; once it has accepted a session key, its pokes carry the host port its data channel is bound to, and the listener leaves those alone since answering one would rekey a working session. A rebooted target has no data channel and pokes with that field zero, so the listener answers it at once: the session key is renegotiated, the KD packet stream restarts, and the stop is reported as a target reload.

Attach therefore waits for the target's next poke, up to three seconds. A target still sending data for an earlier session (the debugger was killed while it was stopped) is poked back and offers immediately instead. The break-in goes out the moment the session exists, and a stopped target that swallowed it is reset half a second later, so attach completes within a few milliseconds of the poke either way.

## KD and KDNET memory sources

KD and KDNET accept `--memory-source auto|host|kd`:

- `auto` (default) uses direct VM-process memory only after its kernel PE header and live module-list links match the KD target; otherwise it falls back to KD.
- `host` requires matching direct VM-process memory and fails on mismatch.
- `kd` forces target-mediated reads: kernel-space addresses go through `DbgKdReadVirtualMemory`, everything else through `DbgKdReadPhysicalMemory` behind a host page walk whose translations are cached until the target next runs. Writes use `DbgKdWritePhysicalMemory`.

The `kd` source needs no hypervisor or VM-process access, so AMD64 and ARM64 Windows VMs or physical machines can be debugged across any routable network. Memory-backed commands require the target to be halted; remote latency also makes large scans slower than direct host memory. KDNET returns at most 1096 bytes per request, so attach reads only the parts of each module image that symbols and unwinding need (`.rdata`, `.pdata`, the debug directory) and leaves code and data sections to the on-disk image.

Process, kernel-module, and driver-object lists are walked only when something needs them (a listing command, a tab completion, a break context in a user-mode process) and the first walk per halt serves every later use until the target runs again. The process walk reads one span per `_EPROCESS` and consults the PEB only for names the kernel's 15-byte `ImageFileName` may have truncated, so the prompt after attach and each stop no longer waits on a full process walk.

## Memory introspection

The `memory` backend requires no guest or VM debug transport configuration:

```bash
ntoseye --backend memory
```

Execution control, registers, execution-context selection, breakpoints, debug output, bugcheck stops, and reload detection are unavailable in this mode. Run `capabilities` in the REPL for the exact backend feature matrix.
