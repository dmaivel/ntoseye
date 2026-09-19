# UTM (macOS, Apple Silicon)

For a Windows 11 ARM64 VM under [UTM](https://mac.getutm.app) (QEMU/HVF). Run `ntoseye configure` to select a stopped UTM VM, update its QEMU arguments through UTM's scripting API, back up the previous arguments, and print the guest and launch commands. For manual configuration, follow the steps below.

## KD over a serial socket

1. In the guest, enable kernel debugging (Administrator PowerShell, then reboot):
   ```
   bcdedit /debug on
   bcdedit /dbgsettings serial debugport:1 baudrate:115200
   ```
   UTM must not use Secure Boot (`bcdedit` is unavailable under it: disable Secure Boot in the VM's QEMU settings first or disable the TPM).
2. In UTM's QEMU Arguments section, add the following (substitute your username in the path):
   ```
   -chardev
   socket,id=kd,path=/Users/YOU/Library/Containers/com.utmapp.QEMUHelper/Data/tmp/ntoseye-kd.sock,server=on,wait=off
   -serial
   chardev:kd
   ```
   The path must match the `--connect` path below because UTM sandboxes QEMU and the socket lives inside the QEMUHelper container.
3. `ntoseye` must run as root on macOS to read the VM's memory. Connect to that same socket:
   ```bash
   sudo ntoseye --backend kd --connect "$HOME/Library/Containers/com.utmapp.QEMUHelper/Data/tmp/ntoseye-kd.sock"
   ```

## KDNET

KDNET uses the guest's virtual NIC instead of a serial device. Choose a macOS host IP that the guest can reach through its UTM network, then follow the [KDNET guide](kdnet.md). UTM must not use Secure Boot while changing the BCD debug settings. Use `ntoseye --backend kdnet --kdnet-key 1.2.3.4 --memory-source kd` for target-mediated ARM64 memory with no root or UTM-process access; `ntoseye configure` prints this command.

## GDB stub

Turn off "Use Hypervisor" in the VM's QEMU settings first. With HVF enabled, QEMU kills the VM as soon as a debugger asks it to trap debug exceptions (`HV_BAD_ARGUMENT` from `hv_vcpu_set_trap_debug_exceptions`, seen on UTM 4.7.5 and 5.0.5); the guest then runs under TCG instead, which is considerably slower but supports the backend fully.

Add to the VM's QEMU Arguments:

```
-s
```

Then, as root so `ntoseye` can read the VM's memory:

```bash
sudo ntoseye --backend gdb
```

Give the guest time to reach the desktop before attaching: under TCG it boots slowly, and a guest that has not started its kernel yet has nothing to find.

## Memory introspection

No host or guest configuration needed, but `ntoseye` must run as root on macOS; see [Choosing a backend](backends.md) for what the `memory` backend can and cannot do.
