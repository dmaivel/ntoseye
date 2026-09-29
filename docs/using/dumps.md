# Crash dumps

Use this command to analyse a Windows kernel crash dump (`.dmp`) offline. You do not need a running VM.

```bash
ntoseye --dump /path/to/MEMORY.DMP
```

`ntoseye` supports these dump types:

- full dumps
- kernel dumps
- kernel triage dumps (small dumps or minidumps)

A BSOD dump automatically gives you the crash registers, the stack trace, and the bugcheck analysis. A live system dump (bugcheck 0x161) contains memory but no exception context.

Available commands include {command}`ps`, {command}`lm`, {command}`dt`, {command}`dq`/{command}`db`/{command}`dd`, {command}`dqs`, {command}`da`/{command}`du`, {command}`analyze`, {command}`trap`, {command}`x`, {command}`ev`, {command}`drivers`, and {command}`s`. The dump is read-only. So execution control, breakpoints, and writes to registers or memory are not available.

The Python SDK can also analyse dumps:

```python
import ntoseye
dbg = ntoseye.attach("dmp", connect="/path/to/MEMORY.DMP")
```

The MCP server can also analyse dumps. You can load a dump in two ways:

- Give `--dump` when you start the server: `ntoseye mcp --dump /path/to/MEMORY.DMP`.
- Start the server with `ntoseye mcp` and no flags. The client can then load a dump later with the `open` tool. Set `backend: dump`, and set `connect` to the dump path.

## Writing a dump from a live target

To write a dump from a live halted target, use this WinDbg-compatible command:

```text
.dump [/f] [/ma] <file>
```

The command writes a `PAGEDU64` full kernel dump as a stream, one page at a time. It needs a live halted target with memory introspection. A static crash-dump session cannot write another dump.

The command supports AMD64 and ARM64 targets. The `MachineImageType` in the header and the embedded `CONTEXT` record follow the architecture of the target. The command accepts `/f` and `/ma` as full-dump switches. To open the file again, use `ntoseye --dump <file>`.

The command first writes to a temporary file in the same directory as the destination. The temporary file has mode `0600`. After the write is complete, the command renames the temporary file to the destination. So the resulting dump is readable by its owner, and the umask does not change this.

If you press Ctrl+C, or if the write fails, the command removes the temporary file. An existing dump at the destination does not change. So to replace a dump, you need disk space for the new file and the old file at the same time.

If the command cannot read a guest page, it writes zeros for that page. The command output shows the number of these pages. If a target has more than 42 physical-memory runs, the command gives an error and does not write a dump. The command does this because the full dump would be incomplete.

## Generating dumps

### Live dump from the host

You can make a dump from the host, and the guest does not crash. The result is a live system dump (bugcheck 0x161):

```bash
virsh dump <domain> /tmp/win.dmp --memory-only --format=win-dmp
```

This command needs the `vmcoreinfo` feature on the domain. For libvirt guests, `ntoseye configure` can enable this feature. The guest also needs the virtio-win `fwcfg` driver.

### Dump from a BSOD

After a real BSOD, Windows writes `C:\Windows\MEMORY.DMP` when the guest boots again. The setting for this dump is System Properties > Startup and Recovery > "Kernel memory dump". Windows first writes the dump to the page file. So you must use one of these configurations:

- Keep a page file on `C:` that is at least as large as the dump. In the Virtual Memory dialog, click **Set** before you click OK. If you do not click **Set**, the dialog discards the change and does not tell you.
- Keep paging disabled (see [Recommended guest tweaks](#recommended-guest-tweaks)), and configure a dedicated dump file. Set these values under `HKLM\SYSTEM\CurrentControlSet\Control\CrashControl`:
  - `DedicatedDumpFile` (REG_SZ), for example `C:\dedicated.sys`
  - `DumpFileSize` (DWORD), the size in MB

To force the crash, use Sysinternals NotMyFault or the `CrashOnCtrlScroll` registry switch.

If the guest boots in debug mode and a debugger is attached, continue past the bugcheck with {command}`g`. For more information, see [Bugchecks](bugchecks.md#after-the-bugcheck). If you do not continue, Windows waits in the debugger and does not write the dump.

When the guest is shut off, copy the dump to the host with [guestfs-tools](https://libguestfs.org/):

```bash
virt-copy-out -d <domain> /Windows/MEMORY.DMP /tmp/
```

You can also use a different guest-to-host channel. Examples are an SMB share, a virtiofs share, and scp.

## Recommended guest tweaks

We recommend that you disable memory paging and memory compression in the guest. This is not necessary, but it prevents memory-related problems. Do this one time for each Windows installation. Run these commands in an Administrator PowerShell:

```
Get-CimInstance Win32_ComputerSystem | Set-CimInstance -Property @{ AutomaticManagedPagefile = $false }
Get-CimInstance Win32_PageFileSetting | Remove-CimInstance
Disable-MMAgent -MemoryCompression
Restart-Computer
```

:::{note}
Windows first writes a BSOD crash dump to the page file. So if paging is disabled, Windows does not write `MEMORY.DMP`. To get the dump, set a dedicated dump file (see [Dump from a BSOD](#dump-from-a-bsod)).
:::
