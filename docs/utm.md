# UTM (macOS, Apple Silicon)

For a Windows 11 ARM64 VM under [UTM](https://mac.getutm.app) (QEMU/HVF).

## KD over a serial socket

1. In the guest, enable kernel debugging (Administrator PowerShell, then reboot):
   ```
   bcdedit /debug on
   bcdedit /dbgsettings serial debugport:1 baudrate:115200
   ```
   UTM must not use Secure Boot (`bcdedit` is unavailable under it: disable Secure Boot in the VM's QEMU settings first or disable the TPM).
2. In UTM's QEMU advanced settings, add a serial device (substitute your username in the path):
   ```
   -chardev socket,id=kd,path=/Users/YOU/Library/Containers/com.utmapp.QEMUHelper/Data/tmp/ntoseye-kd.sock,server=on,wait=off -serial chardev:kd
   ```
   The path must match the `--connect` path below, as UTM sandboxes QEMU, so the socket lives inside the QEMUHelper container, not `/tmp`.
3. `ntoseye` must run as root on macOS to read the VM's memory. Connect to that same socket:
   ```bash
   sudo -E ntoseye --backend kd --connect ~/Library/Containers/com.utmapp.QEMUHelper/Data/tmp/ntoseye-kd.sock
   ```
   (`sudo -E` preserves `HOME` so the `~` expands for the sandbox path; on first attach the kernel waits at `nt!DbgBreakPoint` on the idle processor.)

## Memory introspection

No host or guest configuration needed, but `ntoseye` must run as root on macOS; see [Choosing a backend](backends.md) for what the `memory` backend can and cannot do.
