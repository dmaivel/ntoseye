# KVM/QEMU

libvirt/virt-manager users can configure the debug transport automatically: run `ntoseye virsh`, pick the domain, choose _configure debug transports_, then the backend. `ntoseye virsh` can also remove ntoseye-managed debug transports later. Prefer editing the XML yourself? Follow the sections below.

## GDB stub

Fallback backend for guests that are not configured for Windows KD. Expose QEMU's gdbstub on `127.0.0.1:1234`, then run with `--backend gdb` (do not enable kernel debug mode in the guest; see [Choosing a backend](backends.md)).

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

## Memory introspection

No host or guest configuration needed; see [Choosing a backend](backends.md) for what the `memory` backend can and cannot do.
