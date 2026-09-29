# UTM (macOS, Apple Silicon)

This page is for a Windows 11 ARM64 VM in [UTM](https://mac.getutm.app) (QEMU/HVF).

`ntoseye configure` can configure the VM for you. It does these steps:

- It lets you select a stopped UTM VM.
- It updates the QEMU arguments of the VM through the UTM scripting API.
- It makes a backup of the previous arguments.
- It shows the commands for the guest and the launch command.

To configure the VM manually, do the steps below.

## KD over a serial socket

1. Make sure that UTM does not use Secure Boot. `bcdedit` is not available when Secure Boot is on. First disable Secure Boot in the QEMU settings of the VM, or disable the TPM.
2. In the guest, open PowerShell as Administrator. Enable kernel debugging:
   ```
   bcdedit /debug on
   bcdedit /dbgsettings serial debugport:1 baudrate:115200
   ```
3. Restart the guest.
4. In the QEMU Arguments section of UTM, add these arguments. Replace `YOU` in the path with your user name.
   ```
   -chardev
   socket,id=kd,path=/Users/YOU/Library/Containers/com.utmapp.QEMUHelper/Data/tmp/ntoseye-kd.sock,server=on,wait=off
   -serial
   chardev:kd
   ```
   The path must be the same as the `--connect` path in the next step. UTM puts QEMU in a sandbox, so the socket is in the QEMUHelper container.
5. Connect `ntoseye` to the same socket. On macOS, `ntoseye` must run as root to read the memory of the VM.
   ```bash
   sudo ntoseye --backend kd --connect "$HOME/Library/Containers/com.utmapp.QEMUHelper/Data/tmp/ntoseye-kd.sock"
   ```

## KDNET

KDNET uses the virtual NIC of the guest. It does not use a serial device.

1. Choose a macOS host IP address that the guest can reach through its UTM network.
2. Follow the [KDNET guide](kdnet.md). While you change the BCD debug settings, UTM must not use Secure Boot.

To get ARM64 memory through the target, use `ntoseye --backend kdnet --kdnet-key 1.2.3.4 --memory-source kd`. This command does not need root access or access to the UTM process. `ntoseye configure` shows this command.

## GDB stub

First, turn off "Use Hypervisor" in the QEMU settings of the VM. The guest then runs under TCG. TCG is much slower, but it fully supports the `gdb` backend.

:::{warning}
If HVF is enabled, QEMU before 10.1 kills the VM when a debugger asks it to trap debug exceptions. QEMU gets `HV_BAD_ARGUMENT` from `hv_vcpu_set_trap_debug_exceptions` ([qemu#2895](https://gitlab.com/qemu-project/qemu/-/issues/2895)). This problem occurs on UTM 4.7.5 and UTM 5.0.5. UTM 5.0.5 ships QEMU 10.0.12.

To prevent this, `ntoseye` does not accept the `gdb` backend for a VM that started with `-accel hvf`. If your UTM ships QEMU 10.1 or later, set `NTOSEYE_GDB_ON_HVF=1` to connect with HVF on. `sudo` drops the environment of the caller, so set the variable in the `sudo` command: `sudo NTOSEYE_GDB_ON_HVF=1 ntoseye --backend gdb`.
:::

1. Add this argument to the QEMU Arguments of the VM:

   ```
   -s
   ```

2. Wait until the guest shows the desktop. Under TCG, the guest boots slowly. If the guest has not started its kernel, `ntoseye` cannot find anything.

3. Start `ntoseye` as root, so that it can read the memory of the VM:

   ```bash
   sudo ntoseye --backend gdb
   ```

## Memory introspection

The `memory` backend needs no configuration on the host or the guest. On macOS, `ntoseye` must run as root. For what the `memory` backend can do and cannot do, see [Choosing a backend](backends.md).
