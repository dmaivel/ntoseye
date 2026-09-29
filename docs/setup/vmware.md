# VMware Workstation

Use `ntoseye configure` to select a registered VMware VM and configure it automatically. It keeps the existing serial devices, uses the next free guest COM port, makes a backup of the `.vmx` file, and shows the guest instructions for this configuration.

Power off the VM before you run `ntoseye configure`, and keep only one VMware VM powered on while you use `ntoseye`. To configure the VM manually, follow the sections below.

## KD over a serial socket

1. In the guest, open a shell as Administrator and run these commands to enable kernel debugging:

   ```
   bcdedit /debug on
   bcdedit /dbgsettings serial debugport:1 baudrate:115200
   ```

2. Restart the guest.
3. Configure the first virtual serial port (guest COM1) as a server-side pipe:

   ```ini
   serial0.present = "TRUE"
   serial0.fileType = "pipe"
   serial0.fileName = "/tmp/ntoseye-kd.sock"
   serial0.pipe.endPoint = "server"
   serial0.startConnected = "TRUE"
   serial0.yieldOnMsrRead = "TRUE"
   ```

4. Run `ntoseye` to connect.

If another virtual serial device uses COM1, configure the next `serialN` entry and use `debugport:N+1` in the `bcdedit /dbgsettings` command.

## KDNET

KDNET uses the guest's virtual NIC and does not need a serial device. Choose a host IP address that the guest can reach through its bridged, NAT, or host-only VMware network, then follow the [KDNET guide](kdnet.md).

## GDB stub

VMware Workstation has its own GDB remote stub. To use it, add these lines to the VM's `.vmx` file:

```ini
debugStub.listen.guest64 = "TRUE"
debugStub.port.guest64 = "1234"
```

Then start ntoseye with `--backend gdb`.

:::{warning}
Do not enable kernel debug mode in the guest. The [GDB backend warning](kvm-qemu.md#gdb-stub) explains why.
:::

ntoseye does not support legacy VMware stubs that do not give an AMD64 XML target description, so use KD or the `memory` backend with them.

## Memory introspection

The `memory` backend needs no host or guest configuration. For what it can and cannot do, see [Choosing a backend](backends.md).
