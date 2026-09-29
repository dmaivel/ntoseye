# KDNET

KDNET sends Windows kernel debugging traffic as encrypted UDP through the NIC of the target. It does not need a serial device or access to the VM process. So it works for AMD64 and ARM64 targets, and across any routable network.

`ntoseye configure` does these steps:

- It asks for the host IPv4 address.
- It makes the necessary hypervisor changes.
- It shows the guest commands and the launch commands from this page, with the addresses filled in.

The rest of this page tells how to do the same steps manually.

## 1. Hypervisor

Select a host address that the target can reach. The hypervisors that `ntoseye` integrates with have their own requirements:

- [KVM/QEMU](kvm-qemu.md#kdnet): Set the libvirt Hyper-V vendor ID to `KVMKVMKVM`. Then power off the VM completely and start it again. A Windows reboot is not sufficient. `ntoseye configure` sets the vendor override automatically.
- [VMware Workstation](vmware.md#kdnet): You do not need to configure more virtual hardware. But the bridged, NAT, or host-only NIC of the guest must be able to reach the selected host address.
- [UTM](utm.md#kdnet): Disable Secure Boot before you change the Windows BCD debug settings. Make sure that the guest NIC can reach the selected macOS address.

Other targets that Windows can debug over KDNET need no configuration on the host. If a host firewall filters inbound UDP, allow the selected port. The default port is 50000.

## 2. Guest

Microsoft's `kdnet.exe` is part of the Windows Debugging Tools. It is in `Debuggers\x64` or `Debuggers\arm64`. Run it from an elevated prompt in the guest:

```powershell
kdnet.exe <host-ip> 50000
```

`kdnet.exe` does these steps:

- It validates the debug NIC.
- It configures the PCI `busparams` of the NIC.
- It enables debugging.
- It shows the four-part encryption key.

Then reboot Windows.

If `kdnet.exe` is not available, first find the PCI address of the debug NIC:

```powershell
PS> Get-NetAdapterHardwareInfo

Name        Segment Bus Device Function Slot NumaNode PcieLinkSpeed PcieLinkWidth Version
----        ------- --- ------ -------- ---- -------- ------------- ------------- -------
Ethernet 4        0   6      0        0    0                Unknown
```

`Bus`, `Device`, and `Function` are the three parts of `busparams`, in decimal. For this adapter, the value is `6.0.0`. Device Manager shows the same data on the General tab of the adapter, as `Location: PCI bus 6, device 0, function 0`.

Then run these commands:

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

With `--memory-source auto`, ntoseye reads memory from the VM process if the VM is local and matches the target. For a fully remote session, add `--memory-source kd`. ARM64 guests under UTM also use this mode. See [memory sources](../using/memory.md#where-reads-come-from).

## Attach and reboot behavior

You do not need to attach again after a guest restart.

The target sends a poke to the listener every three seconds, in every state. After the target accepts a session key, its pokes contain the host port of its data channel. The listener does not answer these pokes, because an answer would change the key of a session that works.

A rebooted target has no data channel, so the port field in its pokes is zero. The listener answers such a poke immediately. Then:

- ntoseye and the target negotiate a new session key.
- The KD packet stream starts again.
- ntoseye reports the stop as a target reload.

So an attach waits up to three seconds for the next poke from the target.

A target can still send data for an earlier session. This occurs if the debugger was killed while the target was stopped. In that case, the listener sends a poke back to the target, and the target sends its offer immediately.

ntoseye sends the break-in as soon as the session exists. A stopped target can receive the break-in and not respond to it. In that case, ntoseye sends a KD reset packet half a second later. So in both cases, the attach completes a few milliseconds after the poke.
