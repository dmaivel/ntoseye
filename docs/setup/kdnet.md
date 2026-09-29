# KDNET

KDNET sends Windows kernel debugging traffic as encrypted UDP through the NIC of the target. Because it needs no serial device and no access to the VM process, it works for AMD64 and ARM64 targets and across any routable network.

`ntoseye configure` asks for the host IPv4 address, makes the necessary hypervisor changes, and shows the guest and launch commands from this page with the addresses filled in. The rest of this page describes how to do the same steps manually.

## 1. Hypervisor

Select a host address that the target can reach. The hypervisors that `ntoseye` integrates with have their own requirements:

- [KVM/QEMU](kvm-qemu.md#kdnet): Set the libvirt Hyper-V vendor ID to `KVMKVMKVM`, then power off the VM completely and start it again, because a Windows reboot is not enough. `ntoseye configure` sets the vendor override automatically.
- [VMware Workstation](vmware.md#kdnet): You do not need to configure more virtual hardware, but the bridged, NAT, or host-only NIC of the guest must be able to reach the selected host address.
- [UTM](utm.md#kdnet): Disable Secure Boot before you change the Windows BCD debug settings, and make sure that the guest NIC can reach the selected macOS address.

Other targets that Windows can debug over KDNET need no configuration on the host. If a host firewall filters inbound UDP, allow the selected port, which is 50000 by default.

## 2. Guest

Microsoft's `kdnet.exe` is part of the Windows Debugging Tools, in `Debuggers\x64` or `Debuggers\arm64`. Run it from an elevated prompt in the guest:

```powershell
kdnet.exe <host-ip> 50000
```

`kdnet.exe` validates the debug NIC, configures the PCI `busparams` of the NIC, enables debugging, and shows the four-part encryption key. Then reboot Windows.

If `kdnet.exe` is not available, first find the PCI address of the debug NIC:

```powershell
PS> Get-NetAdapterHardwareInfo

Name        Segment Bus Device Function Slot NumaNode PcieLinkSpeed PcieLinkWidth Version
----        ------- --- ------ -------- ---- -------- ------------- ------------- -------
Ethernet 4        0   6      0        0    0                Unknown
```

`Bus`, `Device`, and `Function` are the three parts of `busparams`, in decimal, so the value for this adapter is `6.0.0`. Device Manager shows the same data on the General tab of the adapter, as `Location: PCI bus 6, device 0, function 0`.

Then configure debugging with `bcdedit`:

```powershell
bcdedit /debug on
bcdedit /dbgsettings net hostip:<host-ip> port:50000
bcdedit /set "{dbgsettings}" busparams 6.0.0
```

`bcdedit /dbgsettings` shows the key that it generated.

## 3. Host

Start `ntoseye` with the key from the guest:

```bash
ntoseye --backend kdnet --kdnet-key 1.2.3.4
```

By default, KDNET listens on `0.0.0.0:50000`. To use a different listener, use `--connect <listen-address>:<port>`.

With `--memory-source auto`, ntoseye reads memory from the VM process when the VM is local and matches the target. For a fully remote session, add `--memory-source kd`, which is also the mode that ARM64 guests under UTM use. See [memory sources](../using/memory.md#where-reads-come-from).

## Attach and reboot behavior

You do not need to attach again after a guest restart.

The target sends a poke to the listener every three seconds, in every state. After the target accepts a session key, its pokes contain the host port of its data channel, and the listener does not answer them, because an answer would change the key of a working session.

A rebooted target has no data channel, so the port field in its pokes is zero and the listener answers such a poke immediately. ntoseye and the target then negotiate a new session key, the KD packet stream starts again, and ntoseye reports the stop as a target reload.

Because the listener waits for pokes, an attach waits up to three seconds for the next poke from the target. If the debugger was killed while the target was stopped, the target can still send data for the earlier session. In that case, the listener sends a poke back to the target, and the target sends its offer immediately instead.

ntoseye sends the break-in as soon as the session exists, and the attach usually completes a few milliseconds after the poke. If a stopped target receives the break-in but does not respond to it, ntoseye sends a KD reset packet half a second later.
