# Crash dumps

To analyse a Windows kernel crash dump (`.dmp`) offline, without a running VM, use:

```bash
ntoseye --dump /path/to/MEMORY.DMP
```

`ntoseye` supports full dumps, kernel dumps, and kernel triage dumps (small dumps or minidumps). The same option opens a Windows user-mode minidump of one process; see [user-mode minidumps](#user-mode-minidumps).

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
dump = dbg.inspect.version().dump                # None on a live target
blocks = dump.tagged_blocks if dump else []
data = dbg.inspect.read_tagged("{12345678-1234-1234-1234-123456789abc}")
```

## ETW sessions in a minidump

In a live target or a full or kernel dump, the `!wmitrace` commands read the ETW trace sessions from kernel memory. A minidump does not hold that memory. But for each session that is started with `EVENT_TRACE_ADDTO_TRIAGE_DUMP`, the kernel saves the trace buffers in the dump as tagged data, `nt!EtwSecondaryDumpDataGuid` in {command}`.enumtag`. On Windows 11 these sessions are EventLog-System, WiFiSession, CldFltLog and the session of the RDP display driver. In a minidump, the `!wmitrace` commands read these sessions instead. {command}`!wmitrace.strdump` lists them:

```text
4 loggers in the dump's ETW data (0x294ec bytes, nt!EtwSecondaryDumpDataGuid)

ID    Name                                         Mode        Buffer size  Clock        Buffers  Data     Start time
0x0a  EventLog-System                              0x98800180  64 KiB       SystemTime   2        0x13b0   2026-10-06T06:42:28.6372592Z
0x0d  Microsoft-Windows-Rdp-Graphics-RdpIdd-Trace  0x80800002  64 KiB       PerfCounter  8        0x240    2026-10-06T06:42:28.6498837Z
0x15  WiFiSession                                  0x80800002  80 KiB       PerfCounter  8        0x27cf0  2026-10-06T06:42:28.6535093Z
0x1d  CldFltLog                                    0x90800002  4 KiB        SystemTime   2        0x90     2026-10-06T06:42:57.0344948Z
```

The kernel saves every buffer of the session, the same buffers that a kernel dump of the same crash holds in memory, and cuts each one after its last event. `!wmitrace.strdump <logger>` lists the buffers at their offsets in the tagged data:

```text
logger 0x15 'WiFiSession' in the dump's ETW data
  8 buffers of 0x14000 bytes

Offset    State           CPU  Sequence  Saved  Current  Data    Refs
+0x172a   GeneralLogging  2    1         0x0    0x80d0   0x80d0  15
+0x97fa   GeneralLogging  3    2         0x0    0xa468   0xa468  15
+0x13c62  GeneralLogging  1    3         0x0    0xae68   0xae68  15
+0x1eaca  GeneralLogging  0    4         0x0    0xa830   0xa830  15
+0x292fa  Free            0    5         0x0    0x48     0x48    0
+0x29342  Free            0    6         0x0    0x48     0x48    0
+0x2938a  Free            0    7         0x0    0x48     0x48    0
+0x293d2  Free            0    8         0x0    0x48     0x48    0
```

{command}`!wmitrace.logdump` decodes the events of these buffers, as it decodes them in memory:

```text
logger 0x0a 'EventLog-System' in the dump's ETW data
  18 events in 2 buffers (SystemTime clock), showing the last 1

[0]0004.2358::2026-10-06T18:29:29.5234029Z event {67dc0d66-3695-47c0-9642-33f76f7bd7ad} id 0 v0 opcode 0 task 0 level 5 keyword 0x0
    extended SID (0xc bytes) 010100000000000512000000
    extended PROV_TRAITS (0x38 bytes) 38004d6963726f736f66742e57696e646f77732e48797065722d562e566d5377...
    extended EVENT_SCHEMA_TL (0x36 bytes) 36008000576f726b4974656d20436f6d706c6574656400576f726b6572526f75...
    0000  43 00 74 00 72 00 6c 00 4d 00 65 00 73 00 73 00  C.t.r.l.M.e.s.s.
    0010  61 00 67 00 65 00 73 00 57 00 6f 00 72 00 6b 00  a.g.e.s.W.o.r.k.
    0020  49 00 74 00 65 00 6d 00 00 00 3f 01 00 00 00 00  I.t.e.m...?.....
    0030  00 00                                            ..
```

{command}`!wmitrace.logsave` saves the buffers of a session as an .etl file. The tagged data records only some fields of each session. {command}`!wmitrace.logger` shows them: the logger mode, the buffer size, the number of buffers, the clock type, and the start time. The counters of the session are only in a full or kernel dump.

WinDbg's `!wmitrace.strdump` lists only the first of these sessions in a minidump, and its `!wmitrace.logdump` and `!wmitrace.logsave` cannot read the buffers.

In the [Python SDK](../scripting/sdk.md), `inspect.etw_crash_sessions()` lists these sessions with their buffers, and `inspect.etw_crash_events(logger, count=None)` decodes the events of one, by its name or logger ID, oldest first. They read the sessions that Windows saved in a kernel or full dump too, while `etw_loggers()` and `etw_events()` read every session from the dump's memory.

## User-mode minidumps

A user-mode minidump (`MDMP`) holds one process: its threads with their registers, its modules, and as much of its memory as the writer captured. `--dump` recognizes one by its signature and opens it on its own terms. There is no kernel, no physical memory, and no page tables, and ntoseye does not invent them:

```bash
ntoseye --dump powershell-exception.dmp
```

```text
user-mode minidump
  process   powershell.exe (PID 4340)
  system    Windows 10.0.26200 AMD64 (26100.1.amd64fre.ge_release.240331-1435)
  written   2026-10-11T06:17:41Z
  captured  20 threads, 91 modules
  memory    1655 ranges, 259276 KiB
  exception 0xe0d7e5e1 at kernelbase!RaiseException+0x8a on thread 10f4.cc4
```

ntoseye opens Windows minidumps of AMD64 and ARM64 processes, whatever wrote them. Minidumps that Breakpad and Crashpad write on Linux, macOS, and Android use the same container but describe another operating system; ntoseye refuses them by name:

```text
error: unsupported dump: this is a Linux minidump (platform 0x8201), as Breakpad and Crashpad write; ntoseye opens Windows minidumps
```

### Writing one

Any of these writes a minidump of a running process in the guest. A dump with full memory (`MiniDumpWithFullMemory`) lets every command below read what it needs; a small one holds the thread stacks and little else.

- [ProcDump](https://learn.microsoft.com/sysinternals/downloads/procdump): `procdump -ma <name or pid>` writes a full dump now, and `procdump -ma -e <name or pid>` waits for an unhandled exception and writes the dump with its exception record.
- Task Manager: on the **Details** tab, right-click the process and choose **Create memory dump file**. It writes a full dump to `%LOCALAPPDATA%\Temp` and shows the path.
- Windows Error Reporting: under `HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps`, set `DumpType` (DWORD) to `2` for full dumps and, optionally, `DumpFolder` (REG_EXPAND_SZ). Each process that crashes from then on leaves a dump with its exception record, by default in `%LOCALAPPDATA%\CrashDumps`.
- A program can write its own with `MiniDumpWriteDump`.

Copy the file to the host as for a kernel dump.

### What works

The commands that look at one process work on the dump's own records:

- {command}`lm` lists the modules from the dump's module list and loads their PDBs from the CodeView records there, even when a module's code was not captured. {command}`~` lists the threads with their names, and `~<n>s` selects one. The prompt names the selected thread by its number in that list (`17: minidump>`), as WinDbg's `0:017>` does.
- {command}`r`, {command}`k`, and {command}`.frame` show the selected thread. {command}`.ecxr` selects the context of the exception the dump was written for, and {command}`.exr` `-1` shows its record. The stack walk uses each module's unwind data, fetching the image from the symbol server when its unwind data was not captured, and the dump's dynamic function tables for code that no module holds, such as .NET's JIT-compiled methods:

  ```text
  17: minidump> .ecxr; k
  *00 0000005ceb90e270  00007ff946b741ca  kernelbase!RaiseException+0x8a
   01 0000005ceb90e370  00007ff89b6c6a48  0x7ff89b6c6a48
   02 0000005ceb90e420  00007ff89b6c6914  0x7ff89b6c6914
   03 0000005ceb90e460  00007ff89b7931ef  0x7ff89b7931ef
   04 0000005ceb90e4d0  00007ff8f860cdfa  system.core.ni+0x5ecdfa
   05 0000005ceb90e580  00007ff8f733a15a  system.management.automation.ni+0x144a15a
  ...
   22 0000005ceb90edc0  00007ff8fae81b43  clr!CallDescrWorkerInternal+0x83
  ...
   32 0000005ceb90f8b0  00007ff948eccd87  kernel32!BaseThreadInitThunk+0x17
   33 0000005ceb90f8e0  00007ff94930caec  ntdll!RtlUserThreadStart+0x2c
  ```

- Memory commands, {command}`u`, {command}`dt`, {command}`dx`, {command}`x`, {command}`ln`, and {command}`s` read the captured memory, and say so when an address was not captured. `$teb` and `$peb` point to the selected thread's TEB and the process's PEB.
- {command}`analyze` reports the exception: its code and name, its flags and parameters (an access violation's read, write, or execute and its address, and the parameters of C++ and CLR exceptions), the faulting thread's stack, the module the exception was raised in, a failure signature, and the culprit, the first frame outside the system modules. `!analyze -v` adds the whole stack, the exception's registers, and every module. A dump written without an exception says so and shows the process and the current thread's stack instead.

  ```text
  exception
    code     0xe0d7e5e1  application-defined code (customer bit set), no standard name
    flags    0x80 (EXCEPTION_SOFTWARE_ORIGINATE)
    address  00007ff946b741ca  kernelbase!RaiseException+0x8a
    module   KERNELBASE.dll (system module)
    thread   10f4.cc4
    params   -

  failure signature
    bucket  exception:e0d7e5e1|symbol:kernelbase!raiseexception
    source  exception address

  culprit attribution
    culprit                 JIT-compiled code at 0x7ff89b6c6a48 (dynamic function table 0x7ff89b6c0020-0x7ff89b740000, no module)
    confidence              low
    called from             frame 04 system.core.ni+0x5ecdfa (System.Core.ni.dll)
    first non-system frame  00007ff89b6c6a48  frame 01 0x7ff89b6c6a48 is the first outside the system modules, in JIT-compiled code
  ```

- {command}`!teb`, {command}`!peb`, and {command}`!gle` read the selected thread's TEB, and the PEB it points to, with the layouts from ntdll's PDB. {command}`!dlls` walks the loader's module lists in the PEB.
- {command}`!handle` lists the handles the dump recorded (`MiniDumpWithHandleData`): each one's type, object name, granted access, attributes, and handle and pointer counts, with a count by type. `!handle <handle> <flags> <type>` takes WinDbg's user-mode flags. The dump records no object addresses, so none are shown.
- {command}`!address` lists the regions of the address space the dump recorded (`MiniDumpWithFullMemoryInfo`), with their state, protection, type, allocation base, and use: a module image, a thread's stack or TEB, the PEB, or a heap from the PEB's heap list. `!address <address>` shows the region holding an address, and `!address -summary` the totals:

  ```text
  0: minidump> !address @rsp
  address 000000f35cfaf788
    Usage:             Stack [~0; e24.278c]
    BaseAddress:       000000f35cfaa000
    EndAddress:        000000f35cfb0000
    RegionSize:        0000000000006000 (24.000 KiB)
    State:             00001000  MEM_COMMIT
    Protect:           00000004  PAGE_READWRITE
    Type:              00020000  MEM_PRIVATE
    AllocationBase:    000000f35cf30000
    AllocationProtect: 00000004  PAGE_READWRITE
    Captured:          all of the region; this address is captured
  ```

- {command}`!vprot` shows the same region as `VirtualQuery` would, and {command}`!heap` walks the process's heaps.
- {command}`!cs` lists the process's critical sections, as ntdll keeps them on `RtlCriticalSectionList`, with each one's owner and waiters; `!cs -l` lists only the held ones. {command}`!runaway` lists the threads by the processor time the dump's thread-info stream records: user-mode time, and with `!runaway 7` kernel-mode time and the time since each thread started.
- {command}`.time` shows when the dump was written, in UTC and in the time zone the dump records, and the process's creation time, uptime, and CPU time. A user-mode minidump records no system time or system uptime, and `.time` says so rather than guessing. {command}`vertarget` shows the Windows version, the processors, the process, and the kinds of data the dump was written with:

  ```text
  target time
    dump written      2026-10-11T06:17:41Z (0x6acb2a05)
    local time        2026-10-10T23:17:41-07:00 (Pacific Daylight Time)
    process created   2026-10-11T06:17:37Z
    process uptime    0d 00:00:04 (4 seconds)
    process CPU time  user 0 s, kernel 0 s
    system time       not recorded in a user-mode minidump
  ```

A small dump (`MiniDumpNormal`) holds the stacks but not the TEBs, the PEB, the handles, or the region list. The commands that need them name what the dump lacks:

```text
0: minidump> !teb
error: the minidump did not capture the TEB at 0xf35d172000

0: minidump> !handle
error: the minidump records no handle data (HandleDataStream)
```

Without the region list, `!address` lists the ranges of memory the dump captured instead, each with its use where it is known.

### What is refused

The dump is a snapshot of a process that no longer runs, so execution control, breakpoints, and writes to memory or registers are refused, as in a kernel dump. Commands that read kernel structures, such as {command}`!process`, {command}`!thread`, {command}`!pcr`, {command}`!pte`, {command}`!pool`, {command}`!object`, and {command}`!drvobj`, and commands that read physical memory, refuse with one message:

```text
0: minidump> !pcr
error: !pcr: this needs a kernel target; a user-mode minidump holds one process and no kernel
```

On a user-mode minidump, {command}`help` leaves these commands out of its list and says how many there are; `help <command>` still describes any of them.

The [Python SDK](../scripting/sdk.md#user-mode-minidumps), the [MCP server](../integrations/mcp.md), and the [DAP adapter](../integrations/dap.md#user-mode-minidumps) open user-mode minidumps the same way as kernel dumps.

## Writing a dump from a live target

To write a dump from a live halted target, use the WinDbg-compatible command:

```text
.dump [/f] [/ma] <file>
```

It streams a `PAGEDU64` full kernel dump one page at a time. It needs a live halted target with memory introspection, so a static crash-dump session cannot write another kernel dump; it can write a [minidump of one process](#a-minidump-of-one-process).

The command supports AMD64 and ARM64 targets, and the `MachineImageType` in the header and the embedded `CONTEXT` record follow the architecture of the target. It accepts `/f` and `/ma` as full-dump switches. To open the file again, use `ntoseye --dump <file>`.

The command first writes to a temporary file with mode `0600` in the same directory as the destination, and renames it to the destination when the write is complete, so the resulting dump is readable by its owner whatever the umask.

If you press Ctrl+C or the write fails, the command removes the temporary file and an existing dump at the destination does not change. This means that replacing a dump needs disk space for the new file and the old file at the same time.

If the command cannot read a guest page, it writes zeros for that page and shows the number of these pages in its output. If a target has more than 42 physical-memory runs, the command gives an error and does not write a dump, because the full dump would be incomplete.

### A minidump of one process

`.dump /u <file>` writes a user-mode minidump (`MDMP`) of the current process: the process that {command}`.process` or {command}`attach` selected, else the owner of the current thread. It works on a live target and on a kernel dump, so you can take one process out of a kernel dump and open it with `ntoseye --dump`, WinDbg, or another minidump reader. The minidump holds:

- each thread, with the user-mode registers that its stack walk recovers, its TEB, the used part of its user stack, and its times;
- each module of the process's loader lists, with its CodeView record, so the PDBs are found without the images;
- the regions of the address space as `VirtualQuery` reports them, so {command}`!address` and {command}`!vprot` work on the minidump;
- every committed page of the process that is in physical memory, as a full-memory minidump holds it.

A page that is in the page file is not in the minidump, and a region larger than 64 MiB, such as the CFG bitmap's reservation, is split by which of its pages are in memory. A thread whose kernel stack is not in memory, which is common in a kernel dump, has no registers in the minidump, and the command says how many threads have none. The minidump has no handle data.

```text
attach 680
.dump /u /tmp/csrss.dmp
```

The file is written and replaced the same way as a kernel dump, and Ctrl+C cancels it.

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
