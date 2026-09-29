# VMware Workstation

Use `ntoseye configure` to select a registered VMware VM and configure it automatically. The command does these steps:

- It keeps the existing serial devices.
- It uses the next free guest COM port.
- It makes a backup of the `.vmx` file.
- It shows the guest instructions for this configuration.

Before you run `ntoseye configure`, power off the VM. When you use `ntoseye`, keep only one VMware VM powered on.

To configure the VM manually, follow the sections below.

## KD over a serial socket

1. In the guest, open a shell as Administrator. Run these commands to enable kernel debugging:

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

If another virtual serial device uses COM1, configure the next `serialN` entry. Then use `debugport:N+1` in the `bcdedit /dbgsettings` command.

## KDNET

KDNET uses the virtual NIC of the guest and does not need a serial device.

1. Choose a host IP address that the guest can reach through its VMware network. The network can be bridged, NAT, or host-only.
2. Follow the [KDNET guide](kdnet.md).

## GDB stub

VMware Workstation has its own GDB remote stub. To use it:

1. Add these lines to the `.vmx` file of the VM:

   ```ini
   debugStub.listen.guest64 = "TRUE"
   debugStub.port.guest64 = "1234"
   ```

2. Start ntoseye with `--backend gdb`.

:::{warning}
Do not enable kernel debug mode in the guest. For the reason, see the [GDB backend warning](kvm-qemu.md#gdb-stub).
:::

ntoseye does not support legacy VMware stubs that do not give an AMD64 XML target description. With these stubs, use KD or the `memory` backend.

## Memory introspection

The `memory` backend needs no host or guest configuration. For what the `memory` backend can do and what it cannot do, see [Choosing a backend](backends.md).
