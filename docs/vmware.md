# VMware Workstation

Run `ntoseye configure` to select a registered VMware VM and configure it automatically. It preserves existing serial devices, uses the next free guest COM port, backs up the `.vmx` file, and prints the matching guest instructions. Power the VM off before configuring it, and only keep one VMware VM powered on while using `ntoseye`. For manual configuration, follow the sections below.

## KD over a serial socket

In the guest, enable kernel debugging (run as Administrator, then reboot):

```
bcdedit /debug on
bcdedit /dbgsettings serial debugport:1 baudrate:115200
```

Configure the first virtual serial port (guest COM1) as a server-side pipe:

```ini
serial0.present = "TRUE"
serial0.fileType = "pipe"
serial0.fileName = "/tmp/ntoseye-kd.sock"
serial0.pipe.endPoint = "server"
serial0.startConnected = "TRUE"
serial0.yieldOnMsrRead = "TRUE"
```

If another virtual serial device already occupies COM1, configure the next `serialN` entry and use the corresponding `debugport:N+1`.

Then connect: `ntoseye`.

## GDB stub

VMware Workstation provides its own GDB remote stub. Add the following to the VM's `.vmx` file:

```ini
debugStub.listen.guest64 = "TRUE"
debugStub.port.guest64 = "1234"
```

Then run with `--backend gdb`. Do not enable kernel debug mode in the guest; see the [GDB backend warning](kvm-qemu.md#gdb-stub).

Legacy VMware stubs that do not expose an AMD64 XML target description are unsupported; use KD or the `memory` backend instead.

## Memory introspection

No host or guest configuration needed; see [Choosing a backend](backends.md) for what the `memory` backend can and cannot do.
