# Choosing a backend

`ntoseye` can connect to a live target in four ways, which you select with `--backend kd` (default), `--backend kdnet`, `--backend gdb`, or `--backend memory`. Crash-dump mode is a separate offline attach mode that you select with `--dump <file>`.

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

The host configuration depends on the hypervisor:

- [KVM/QEMU (including libvirt/virt-manager)](kvm-qemu.md)
- [VMware Workstation](vmware.md)
- [UTM (macOS, Apple Silicon)](utm.md)

## Supported live environments

You can debug any Windows 10/11 target on the network with `kdnet` (see the [KDNET guide](kdnet.md)), because the `kdnet` backend has no hypervisor-specific parts. For the combinations in the table below, `ntoseye` also reads VM memory directly, configures the VM with `ntoseye configure`, and supplies the `gdb` and `memory` backends.

| Host OS | Hypervisor | Guest architecture | `kd` | `kdnet` | `gdb` | `memory` |
| --- | --- | --- | --- | --- | --- | --- |
| Linux | KVM/QEMU | AMD64 | Yes | Yes | Yes | Yes |
| Linux | VMware Workstation | AMD64 | Yes | Yes | Yes | Yes |
| macOS | UTM (QEMU/HVF) | ARM64 | Yes | Yes | Yes (see below) | Yes |

We did not test these integrations with other hypervisors. Crash-dump analysis supports AMD64 and ARM64 dumps.

On UTM, the `gdb` backend needs "Use Hypervisor" turned off, because QEMU versions before 10.1 abort the VM when a debugger enables guest debugging on HVF. If "Use Hypervisor" is on, `ntoseye` does not connect. If your QEMU version has the fix, set `NTOSEYE_GDB_ON_HVF=1` to override this check. The [UTM guide](utm.md) has the details. The other backends do not have this problem, because they do not ask the hypervisor for debug traps.

The initial KD handshake times out after 8 seconds by default. For very slow guests, set `NTOSEYE_KD_TIMEOUT=<seconds>` to change it.

## KDNET

The [KDNET guide](kdnet.md) has the guest, host, and hypervisor setup for the `kdnet` backend. In summary:

1. In the guest, run `kdnet.exe <host-ip> 50000`, which does all of the configuration and shows the key.
2. On the host, run `ntoseye --backend kdnet --kdnet-key <key>`.

## Memory sources

When possible, KD and KDNET read guest memory from the VM process on this host, and otherwise they read it through the target. To select the source, use `--memory-source auto|host|kd`. The [memory guide](../using/memory.md#where-reads-come-from) explains each source, writes, and paged-out memory.

## Memory introspection

The `memory` backend needs no debug transport configuration in the guest or in the VM:

```bash
ntoseye --backend memory
```

These functions are not available in this mode:

- execution control
- registers
- execution-context selection
- breakpoints
- debug output
- bugcheck stops
- reload detection

To see the backend's full feature matrix, run {command}`capabilities` in the REPL.

You can still read threads. {command}`!thread`, {command}`!stacks`, {command}`!findstack`, {command}`!uniqstack`, and {command}`!process` with flag 4 walk the stack of each thread from the data that the thread saved on its kernel stack when it last stopped running. {command}`.thread` selects a thread the same way, and {command}`k`, {command}`.frame`, and {command}`r` of a selected frame then operate on that thread's stack. Each walk reads the stack again, as it is at that time.

A thread that is running on a processor at that moment has no stack to show, because its processor's registers are not available. The same is true on all backends while the target runs.

## Secure kernel (VTL1)

`.vtl 1` and {command}`!trustlets` need direct host memory, which these backends supply:

- the `memory` backend
- the `gdb` backend
- the `kd` and `kdnet` backends, while reads come from host memory

Only the `gdb` backend can stop, step, and break in VTL1. The [VBS guide](../platforms/vbs.md) shows what each backend supports in VTL1.
