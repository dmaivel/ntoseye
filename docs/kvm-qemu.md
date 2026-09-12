# KVM/QEMU

Run `ntoseye configure` to configure a libvirt/virt-manager guest automatically. It preserves existing serial devices, uses the next free guest COM port, backs up the domain XML, and can remove ntoseye-managed transports later. The command prints guest instructions with the assigned debug port. For plain QEMU or manual configuration, follow the sections below.

## KD over a serial socket

Default backend. In the guest, enable kernel debugging (run as Administrator, then reboot):

```
bcdedit /debug on
bcdedit /dbgsettings serial debugport:1 baudrate:115200
```

Use `debugport:2` instead of `:1` if the KD chardev ends up as COM2 (see the virt-manager warning below).

Plain QEMU: add a Unix-socket chardev and route a serial port to it:

```
-chardev socket,id=kd,path=/tmp/ntoseye-kd.sock,server=on,wait=off -serial chardev:kd
```

Then connect: `ntoseye`.

> [!WARNING]
> virt-manager auto-adds a `<serial>` console device on every VM, which
> claims COM1. Either replace that device with one pointing at the KD socket
> (KD becomes COM1, use `debugport:1`), or leave it and add the KD chardev
> via `qemu:commandline` (KD becomes COM2, use `debugport:2`).

**Option A (recommended):** replace the auto-added serial. KD is COM1, `debugport:1` is correct.

```xml
<serial type="unix">
  <source mode="bind" path="/tmp/ntoseye-kd.sock"/>
  <target type="isa-serial" port="0"/>
</serial>
```

**Option B:** keep the auto-added serial and append the KD chardev via `qemu:commandline`. If KD is COM2, use `debugport:2`.

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

KDNET uses the guest's virtual NIC instead of a serial device. For a libvirt/QEMU VM using `<interface type="user">`, QEMU normally exposes the host to the guest as `10.0.2.2`; use that as the host address. For bridged networking, use the host's address on the bridged network.

QEMU/KVM guests must not report the default `Microsoft Hv` hypervisor vendor. KDNET interprets that identity as real Hyper-V and selects Hyper-V's synthetic debug device, which QEMU does not provide. Keep the Hyper-V enlightenments but add this child to the libvirt `<hyperv>` block:

```xml
<vendor_id state="on" value="KVMKVMKVM"/>
```

Power the VM completely off and start it again after changing the CPU identity; a Windows reboot does not recreate the QEMU CPU. See OSR's [QEMU/KVM KDNET analysis](https://www.osr.com/blog/2021/10/05/using-windbg-over-kdnet-on-qemu-kvm/). Then follow the [KDNET guide](kdnet.md) using the selected host address.

## GDB stub

Fallback backend for guests that are not configured for Windows KD. Expose QEMU's gdbstub on `127.0.0.1:1234`, then run with `--backend gdb`.

> [!NOTE]
> Do not enable kernel debug mode (`bcdedit /debug on`) in the guest when using the `gdb` backend. That setting is only for the `kd` backend, and the `gdb` backend's whole advantage is that the guest is unaware it is being debugged. With debug mode on, the kernel changes behaviour (anti-debug code, PatchGuard) and expects a KD debugger to service breaks, while nothing on the GDB side answers the KD transport, so the guest can hang on `DbgBreakPoint` or exceptions. Leave debug mode off.

Plain QEMU: append `-s -S` to the qemu command.

virt-manager: add the following to the XML configuration:

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

No host or guest configuration needed; see [Choosing a backend](backends.md) for what the `memory` backend can and cannot do.
