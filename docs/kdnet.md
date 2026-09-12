# KDNET

KDNET runs Windows kernel debugging over the guest's virtual NIC as encrypted UDP. It needs no serial device and no VM-process access, so it works for AMD64 and ARM64 guests alike and across any routable network.

`ntoseye configure` prompts for the host IPv4 address, applies any required hypervisor changes, and prints the guest and launch commands below with the addresses filled in. The rest of this page is the manual equivalent.

## 1. Hypervisor

Pick the host address the guest can reach and apply the hypervisor's requirements:

- [KVM/QEMU](kvm-qemu.md#kdnet): set the libvirt Hyper-V vendor ID to `KVMKVMKVM`, then completely power off and restart the VM; a Windows reboot is insufficient. `ntoseye configure` applies the vendor override automatically.
- [VMware Workstation](vmware.md#kdnet): no additional virtual hardware configuration is needed, but the guest's bridged, NAT, or host-only NIC must be able to reach the selected host address.
- [UTM](utm.md#kdnet): disable Secure Boot before changing the Windows BCD debug settings and ensure the guest NIC can reach the selected macOS address.

Permit inbound UDP on the selected port (50000 by default) through the host firewall.

## 2. Guest

From an elevated prompt in the guest, run Microsoft's `kdnet.exe` (shipped with the Windows Debugging Tools under `Debuggers\x64` or `Debuggers\arm64`):

```powershell
kdnet.exe <host-ip> 50000
```

It validates the debug NIC, configures its PCI `busparams`, enables debugging, and prints the four-part encryption key. Reboot Windows.

If `kdnet.exe` is not available, first find the debug NIC's PCI address:

```powershell
PS> Get-NetAdapterHardwareInfo

Name        Segment Bus Device Function Slot NumaNode PcieLinkSpeed PcieLinkWidth Version
----        ------- --- ------ -------- ---- -------- ------------- ------------- -------
Ethernet 4        0   6      0        0    0                Unknown
```

`Bus`, `Device`, and `Function` are the three parts of `busparams`, in decimal: this adapter is `6.0.0`. (Device Manager shows the same on the adapter's General tab as `Location: PCI bus 6, device 0, function 0`.) Then:

```powershell
bcdedit /debug on
bcdedit /dbgsettings net hostip:<host-ip> port:50000
bcdedit /set "{dbgsettings}" busparams 6.0.0
```

`bcdedit /dbgsettings` prints the key it generated.

## 3. Host

Start `ntoseye` with the printed key:

```bash
ntoseye --backend kdnet --kdnet-key 1.2.3.4
```

KDNET listens on `0.0.0.0:50000` by default. Use `--connect <listen-address>:<port>` to select another listener. Memory comes from the VM process when it is local and matches the target (`--memory-source auto`); add `--memory-source kd` for a fully remote session, which is also the mode for ARM64 guests under UTM. See [memory sources](backends.md#kd-and-kdnet-memory-sources).

## Attach and reboot behaviour

A guest restart does not require reattaching. The target pokes the listener every three seconds in every state; once it has accepted a session key, its pokes carry the host port its data channel is bound to, and the listener leaves those alone since answering one would rekey a working session. A rebooted target has no data channel and pokes with that field zero, so the listener answers it at once: the session key is renegotiated, the KD packet stream restarts, and the stop is reported as a target reload.

Attach therefore waits for the target's next poke, up to three seconds. A target still sending data for an earlier session (the debugger was killed while it was stopped) is poked back and offers immediately instead. The break-in goes out the moment the session exists, and a stopped target that swallowed it is reset half a second later, so attach completes within a few milliseconds of the poke either way.
