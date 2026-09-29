# KVM/QEMU

To configure a libvirt/virt-manager guest automatically, run `ntoseye configure`. It keeps the existing serial devices, uses the next free guest COM port, makes a backup of the domain XML, and shows the guest instructions with the assigned debug port. Later, `ntoseye configure` can also remove the transports that ntoseye manages. For plain QEMU or for manual configuration, follow the sections below.

## KD over a serial socket

This is the default backend. To enable kernel debugging in the guest, run these commands as Administrator, then restart the guest:

```
bcdedit /debug on
bcdedit /dbgsettings serial debugport:1 baudrate:115200
```

If the KD chardev becomes COM2, use `debugport:2` (see the virt-manager warning below).

For plain QEMU, add a Unix-socket chardev and connect a serial port to it:

```
-chardev socket,id=kd,path=/tmp/ntoseye-kd.sock,server=on,wait=off -serial chardev:kd
```

Then run `ntoseye` to connect.

:::{warning}
virt-manager automatically adds a `<serial>` console device on COM1 to
every VM, so you must choose one of these options:

- Replace that device with a device that points to the KD socket. KD is
  then COM1, so use `debugport:1`.
- Keep that device, and add the KD chardev through `qemu:commandline`. KD
  is then COM2, so use `debugport:2`.
:::

**Option A (recommended):** Replace the automatically added serial device. KD is then COM1, so `debugport:1` is correct.

```xml
<serial type="unix">
  <source mode="bind" path="/tmp/ntoseye-kd.sock"/>
  <target type="isa-serial" port="0"/>
</serial>
```

**Option B:** Keep the automatically added serial device, and add the KD chardev through `qemu:commandline`. If KD is COM2, use `debugport:2`.

```xml
<domain xmlns:qemu="http://libvirt.org/schemas/domain/qemu/1.0" type="kvm">
  ...
  <qemu:commandline>
    <qemu:arg value="-chardev"/>
    <qemu:arg value="socket,id=kd,path=/tmp/ntoseye-kd.sock,server=on,wait=off"/>
    <qemu:arg value="-serial"/>
    <qemu:arg value="chardev:kd"/>
  </qemu:commandline>
</domain>
```

## KDNET

KDNET uses the guest's virtual NIC instead of a serial device. The host address depends on the network:

- If the libvirt/QEMU VM uses `<interface type="user">`, QEMU usually shows the host to the guest as `10.0.2.2`, so use that address.
- For bridged networking, use the address of the host on the bridged network.

QEMU/KVM guests must not report the default `Microsoft Hv` hypervisor vendor. When KDNET sees this vendor, it identifies the hypervisor as real Hyper-V and selects the Hyper-V synthetic debug device, which QEMU does not supply. Keep the Hyper-V enlightenments, and add this child element to the libvirt `<hyperv>` block:

```xml
<vendor_id state="on" value="KVMKVMKVM"/>
```

After you change the CPU identity, power off the VM fully and start it again, because a Windows restart does not make a new QEMU CPU. The OSR [QEMU/KVM KDNET analysis](https://www.osr.com/blog/2021/10/05/using-windbg-over-kdnet-on-qemu-kvm/) has more background. Then follow the [KDNET guide](kdnet.md) with the host address that you selected.

## GDB stub

This is the fallback backend for guests that do not have Windows KD configured. Make QEMU's gdbstub available on `127.0.0.1:1234`, then run `ntoseye` with `--backend gdb`.

:::{note}
If you use the `gdb` backend, do not enable kernel debug mode
(`bcdedit /debug on`) in the guest, because that setting is only for the
`kd` backend. The advantage of the `gdb` backend is that the guest does
not detect the debugger. If debug mode is on, two problems occur:

- The kernel changes its behavior (anti-debug code, PatchGuard).
- The kernel expects a KD debugger to process breaks, but nothing on the
  GDB side replies on the KD transport, so the guest can hang on
  `DbgBreakPoint` or on exceptions.

Keep debug mode off.
:::

For plain QEMU, add `-s -S` to the qemu command.

For virt-manager, add these lines to the XML configuration:

```xml
<domain xmlns:qemu="http://libvirt.org/schemas/domain/qemu/1.0" type="kvm">
  ...
  <qemu:commandline>
    <qemu:arg value="-s"/>
    <qemu:arg value="-S"/>
  </qemu:commandline>
</domain>
```

## Memory introspection

The `memory` backend needs no host or guest configuration. [Choosing a backend](backends.md) describes what it can and cannot do.

## Virtualization-based security (VBS)

[Secure-kernel inspection](../platforms/vbs.md) needs VBS running in the guest, which in turn needs nested virtualization (`vmx`) in the VM. Other debugging works better with VBS off (see [Should VBS be on?](../platforms/vbs.md#should-vbs-be-on)). To check whether VBS runs, use `msinfo32` in the guest. Memory integrity (HVCI) is not necessary.

We tested a Core i9-14900F host with a Windows 11 guest. On this host, the guest's hypervisor did not start with `<cpu mode="host-passthrough"/>`, but a custom Skylake model with `vmx` added works. The configuration below keeps the existing Hyper-V enlightenments and CPU topology, with Secure Boot off:

```xml
<cpu mode="custom" match="exact">
  <model fallback="forbid">Skylake-Client-v4</model>
  <topology sockets="1" dies="1" cores="2" threads="2"/>  <!-- keep your existing topology -->
  <feature policy="require" name="vmx"/>
</cpu>
```

For plain QEMU, use `-cpu Skylake-Client-v4,+vmx` and the existing `hv_*` flags. After you change the CPU model, power off the VM fully and start it again. The configuration above is only the one that we tested, and VBS might start with `host-passthrough` on other hosts.

A vCPU can halt in the Windows hypervisor. To see [where NT left off](../platforms/vbs.md#where-nt-left-off-under-the-hypervisor) on such a vCPU, also enable the `hv-evmcs` enlightenment:

- For libvirt, add `<evmcs state="on"/>` to the `<hyperv>` block. This element also needs `<vapic state="on"/>`.
- For plain QEMU, add `hv-evmcs` and `hv-vapic` to `-cpu`.

After you add the enlightenment, power off the VM and start it again.

The [VBS guide](../platforms/vbs.md) explains how the `gdb` backend operates when Windows runs its own hypervisor, including stops inside the hypervisor, steps without the trap flag, and breakpoints in VTL1.
