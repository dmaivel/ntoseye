# Crash dumps

Analyse a Windows kernel crash dump (`.dmp`) offline, without a running VM:

```bash
ntoseye --dump /path/to/MEMORY.DMP
```

Full and kernel dumps, plus kernel triage (small/minidump) dumps, are supported. BSOD dumps give you the crash registers, stack trace, and bugcheck analysis automatically; live system dumps (bugcheck 0x161) have memory but no exception context.

Available commands include `ps`, `lm`, `dt`, `dq`/`db`/`dd`, `dqs`, `da`/`du`, `analyze`, `trap`, `x`, `ev`, `drivers`, and `s`. Execution control, breakpoints, and register/memory writes are not available (the dump is read-only).

The Python SDK supports dump analysis as well:

```python
import ntoseye
dbg = ntoseye.attach("dmp", connect="/path/to/MEMORY.DMP")
```

So does the MCP server: pass `--dump` at startup (`ntoseye --dump /path/to/MEMORY.DMP mcp`), or start it with `ntoseye mcp` (no flags) and let the client load a dump later via the `open` tool with `backend: dump` and the dump path as `connect`.

## Writing a dump from a live target

From a live halted target, use the WinDbg-compatible command:

```text
.dump [/f] [/ma] <file>
```

This streams a `PAGEDU64` full kernel dump page by page. It requires a live halted target with memory introspection and is currently supported only for AMD64; a static crash-dump session cannot write another dump. `/f` and `/ma` are accepted as full-dump switches. The resulting file can be reopened with `ntoseye --dump <file>`.

The writer streams into a temporary file beside the destination (mode `0600`) and renames it over the destination only after the write completes, so the resulting dump is owner-readable regardless of umask. Ctrl+C or a write failure leaves an existing dump unchanged and removes the temporary file. Replacing a dump therefore requires space for the new file alongside the old one. Unreadable guest pages are zero-filled and counted in the command output. Targets with more than 42 physical-memory runs are rejected rather than producing an incomplete full dump.

## Generating dumps

From the host, without crashing the guest (produces a live system dump, bugcheck 0x161):

```bash
virsh dump <domain> /tmp/win.dmp --memory-only --format=win-dmp
```

This needs the domain's `vmcoreinfo` feature (`ntoseye configure` can enable it for libvirt guests) and the virtio-win `fwcfg` driver installed in the guest.

From a real BSOD, Windows writes `C:\Windows\MEMORY.DMP` on the boot after the crash (System Properties > Startup and Recovery > "Kernel memory dump"). The dump is staged through the page file, so pick one:

- keep a page file on `C:` at least as large as the dump (in the Virtual Memory dialog, click **Set** before OK, or it silently discards the change), or
- keep paging disabled (see [Recommended guest tweaks](#recommended-guest-tweaks)) and configure a dedicated dump file instead, under `HKLM\SYSTEM\CurrentControlSet\Control\CrashControl`: `DedicatedDumpFile` (REG_SZ, e.g. `C:\dedicated.sys`) and `DumpFileSize` (DWORD, MB).

Force the crash with Sysinternals NotMyFault or the `CrashOnCtrlScroll` registry switch. If the guest is booted in debug mode with a debugger attached, continue past the bugcheck (`g`), otherwise Windows waits in the debugger instead of writing the dump.

Copy the dump out to the host with [guestfs-tools](https://libguestfs.org/) while the guest is shut off:

```bash
virt-copy-out -d <domain> /Windows/MEMORY.DMP /tmp/
```

(or use any guest-to-host channel: an SMB/virtiofs share, scp, etc.)

## Recommended guest tweaks

Although not required, disabling memory paging and compression in the guest avoids memory-related issues. This only needs to be done once per Windows installation (Administrator PowerShell):

```
Get-CimInstance Win32_ComputerSystem | Set-CimInstance -Property @{ AutomaticManagedPagefile = $false }
Get-CimInstance Win32_PageFileSetting | Remove-CimInstance
Disable-MMAgent -MemoryCompression
Restart-Computer
```

Note: BSOD crash dumps are staged through the page file, so with paging disabled Windows won't write `MEMORY.DMP` unless you set a dedicated dump file (see [Generating dumps](#generating-dumps)).
