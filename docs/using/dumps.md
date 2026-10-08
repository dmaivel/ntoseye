# Crash dumps

To analyse a Windows kernel crash dump (`.dmp`) offline, without a running VM, use:

```bash
ntoseye --dump /path/to/MEMORY.DMP
```

`ntoseye` supports full dumps, kernel dumps, and kernel triage dumps (small dumps or minidumps).

A BSOD dump automatically gives you the crash registers, the stack trace, and the bugcheck analysis. A live system dump (bugcheck 0x161) contains memory but no exception context.

Available commands include {command}`ps`, {command}`lm`, {command}`dt`, {command}`dq`/{command}`db`/{command}`dd`, {command}`dqs`, {command}`da`/{command}`du`, {command}`analyze`, {command}`trap`, {command}`x`, {command}`ev`, {command}`drivers`, and {command}`s`. Because the dump is read-only, execution control, breakpoints, and writes to registers or memory are not available.

The Python SDK can also analyse dumps:

```python
import ntoseye
dbg = ntoseye.attach("dmp", connect="/path/to/MEMORY.DMP")
```

So can the MCP server, which can load a dump in two ways:

- Give `--dump` when you start the server: `ntoseye mcp --dump /path/to/MEMORY.DMP`.
- Start the server with `ntoseye mcp` and no flags, and let the client load a dump later with the `open` tool, with `backend: dump` and `connect` set to the dump path.

## Tagged data and blackboxes

When Windows writes a BSOD dump, it calls the bugcheck callbacks that drivers and the kernel registered, and each can add a block of data to the dump, tagged with a GUID. {command}`.enumtag` lists them, as in WinDbg, with their size, who writes them, and their first bytes:

```text
{F57308DF-CC45-4E01-AD76-29A4EBB010EC} - 0xc8 bytes  nt!PopBlackBoxBsdGuid: boot status data (!blackboxbsd)
  C8 00 00 00 01 00 00 00 00 1E 01 00 00 00 00 00  ................
  00 00 00 00 00 00 00 00 03 00 0C C0 00 00 40 00  ..............@.
  9F FB B7 C0 5E 55 DD 01 0F C3 15 19 BC 02 00 00  ....^U..........
  01 01 CC 00 BC 02 00 00 BA 02 00 00 BB 02 00 00  ................
  ... 0x88 more bytes; .enumtag {F57308DF-CC45-4E01-AD76-29A4EBB010EC} shows them all
```

A Windows 11 dump holds about twenty of these blocks, from the kernel, KMDF, StorPort, the display stack, pci.sys and the SMBIOS driver. `ntoseye` names each tag that Windows writes. For a driver's own tag, it looks for the GUID's bytes in the images of the kernel modules and names the global that holds it. `.enumtag <tag>` shows every byte of one block. Full, kernel and triage dumps carry these blocks. A live dump that the system takes without a bugcheck has none.

Five of the blocks are Windows' blackboxes, which these commands decode as WinDbg does:

| Command | Shows |
| --- | --- |
| {command}`!blackboxbsd` | The boot status data (`bootstat.dat`): whether the last boot succeeded and shut down, the boot IDs of the last successful and abnormal shutdowns, and the power and feature configuration state. |
| {command}`!blackboxntfs` | NTFS's slow I/O timeouts, with the IRP, SCB and waiting thread, and its oplock break timeouts, with the processes involved. |
| {command}`!blackboxpnp` | The Plug and Play event in progress or the last one: the device, its problem code, and the veto. |
| {command}`!blackboxwinlogon` | What winlogon was doing. |
| {command}`!blackboxpci` | The PCI functions with their command and status registers. |

{command}`analyze` summarizes the first four in one line each.

KMDF adds two blocks: a copy of one driver's In-Flight Recorder log, and the list of KMDF drivers. {command}`!wdfkd.wdfcrashdump` shows both. See [KMDF drivers in a crash dump](kmdf.md#in-a-crash-dump).

A driver can add its own data the same way, with `KeRegisterBugCheckReasonCallback` and `KbCallbackSecondaryDumpData`. To decode it in a script, read the block with the SDK:

```python
blocks = dbg.inspect.version().dump.tagged_blocks
data = dbg.inspect.read_tagged("{12345678-1234-1234-1234-123456789abc}")
```

## Writing a dump from a live target

To write a dump from a live halted target, use the WinDbg-compatible command:

```text
.dump [/f] [/ma] <file>
```

It streams a `PAGEDU64` full kernel dump one page at a time. It needs a live halted target with memory introspection, so a static crash-dump session cannot write another dump.

The command supports AMD64 and ARM64 targets, and the `MachineImageType` in the header and the embedded `CONTEXT` record follow the architecture of the target. It accepts `/f` and `/ma` as full-dump switches. To open the file again, use `ntoseye --dump <file>`.

The command first writes to a temporary file with mode `0600` in the same directory as the destination, and renames it to the destination when the write is complete, so the resulting dump is readable by its owner whatever the umask.

If you press Ctrl+C or the write fails, the command removes the temporary file and an existing dump at the destination does not change. This means that replacing a dump needs disk space for the new file and the old file at the same time.

If the command cannot read a guest page, it writes zeros for that page and shows the number of these pages in its output. If a target has more than 42 physical-memory runs, the command gives an error and does not write a dump, because the full dump would be incomplete.

## Generating dumps

### Live dump from the host

You can make a dump from the host without crashing the guest. The result is a live system dump (bugcheck 0x161):

```bash
virsh dump <domain> /tmp/win.dmp --memory-only --format=win-dmp
```

This needs the `vmcoreinfo` feature on the domain, which `ntoseye configure` can enable for libvirt guests. The guest also needs the virtio-win `fwcfg` driver.

### Dump from a BSOD

After a real BSOD, Windows writes `C:\Windows\MEMORY.DMP` when the guest boots again. The setting for this dump is System Properties > Startup and Recovery > "Kernel memory dump". Because Windows first writes the dump to the page file, you must use one of these configurations:

- Keep a page file on `C:` that is at least as large as the dump. In the Virtual Memory dialog, click **Set** before you click OK. If you do not click **Set**, the dialog discards the change without telling you.
- Keep paging disabled (see [Recommended guest tweaks](#recommended-guest-tweaks)), and configure a dedicated dump file. Set these values under `HKLM\SYSTEM\CurrentControlSet\Control\CrashControl`:
  - `DedicatedDumpFile` (REG_SZ), for example `C:\dedicated.sys`
  - `DumpFileSize` (DWORD), the size in MB

To force the crash, use Sysinternals NotMyFault or the `CrashOnCtrlScroll` registry switch.

If the guest boots in debug mode and a debugger is attached, continue past the bugcheck with {command}`g` (see [Bugchecks](bugchecks.md#after-the-bugcheck)). If you do not continue, Windows waits in the debugger and does not write the dump.

When the guest is shut off, copy the dump to the host with [guestfs-tools](https://libguestfs.org/):

```bash
virt-copy-out -d <domain> /Windows/MEMORY.DMP /tmp/
```

You can also use a different guest-to-host channel, such as an SMB share, a virtiofs share, or scp.

## Recommended guest tweaks

We recommend that you disable memory paging and memory compression in the guest. This is not necessary, but it prevents memory-related problems. Do this once for each Windows installation, in an Administrator PowerShell:

```
Get-CimInstance Win32_ComputerSystem | Set-CimInstance -Property @{ AutomaticManagedPagefile = $false }
Get-CimInstance Win32_PageFileSetting | Remove-CimInstance
Disable-MMAgent -MemoryCompression
Restart-Computer
```

:::{note}
Windows first writes a BSOD crash dump to the page file, so if paging is disabled, Windows does not write `MEMORY.DMP` unless you set a dedicated dump file (see [Dump from a BSOD](#dump-from-a-bsod)).
:::
