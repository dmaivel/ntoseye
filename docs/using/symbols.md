# Symbols and source

## The symbol path and cache

At the start, the symbol path contains the managed cache, `~/.ntoseye/symbols`, then any servers that you give with `--pdb-server` or `NTOSEYE_PDB_SERVERS`, then Microsoft's public symbol server, and then any directories that you give with `--sympath-append`. ntoseye looks in the cache and in every local directory before it asks a server, so a PDB in one of your directories is used without a download, although the directory comes last in the list.

The cache is a symbol store in the layout that `symstore` writes and that SymSrv, IDA's PDB loader, Ghidra, and rizin read:

- PDBs are in `<file>/<GUID><age>/<file>`.
- Images are in `<file>/<TimeDateStamp><SizeOfImage>/<file>`.
- The root contains the control files `pingme.txt` and `000admin`.

Other tools can use the cache when you set their symbol path to `srv*~/.ntoseye/symbols` or to a plain directory entry. Likewise, ntoseye can use a store that another tool filled when you add that store with {command}`.sympath+`.

Versions of ntoseye up to 0.30 left flat `~/.ntoseye/symbols/*.pdb` files and a `~/.ntoseye/images` directory, which you can delete.

## Private PDBs and local source

You set the symbol path and the source path separately. The host needs the private PDB of the driver and, to show source, a copy of the source tree. If you need procedure locals, use the full linker PDB (`/DEBUG:FULL`) instead of a stripped or public PDB.

ntoseye compares the GUID and age of the selected PDB with the CodeView identity in the loaded guest image, and does not accept a PDB whose identity is different.

To add the directory that contains the PDB, use {command}`.sympath+`. The `+` keeps the managed cache and Microsoft's public symbol server in the list, while {command}`.sympath` without the `+` replaces the whole active list:

```text
.sympath+ <directory-containing-the-pdb>
```

To have the directory in the path from the start, for example a driver's build output, give it with `--sympath-append <directory>` instead. You can give `--sympath-append` more than once.

{command}`.srcpath` sets the host directory that contains the source tree:

```text
.sympath+ /home/me/symbols/mydriver
.srcpath /home/me/src/MyDriver
```

### How ntoseye finds a source file

The PDB records source paths such as `C:\Users\me\source\repos\MyDriver\src\queue.c`. ntoseye maps each such path to a file under the source directory, using the longest trailing part of the path that names a file in that directory. For example, it selects `/home/me/src/MyDriver/src/queue.c` before `/home/me/src/MyDriver/queue.c`.

ntoseye first compares names with exact case and, if no file matches, ignores case, so it still finds a file when an `#include` spells its name with a different case.

You can also give a mapping `<prefix-recorded-in-the-pdb>=<local-root>`, for example `C:\Users\me\source\repos\MyDriver=/home/me/src/MyDriver`. ntoseye then replaces the recorded prefix with the local root instead of using the longest trailing part.

### Source checksums

The compiler records a checksum of each source file in the PDB, using MD5, SHA-1, or SHA-256. If the PDB has a checksum for a file, ntoseye shows the host file only if its checksum is the same, so a file that you changed after the build is not shown with the old line numbers. For such a file, {command}`ls` reports that the file is not the source that was compiled, and the disassembly labels the location `differs`.

## PDBs rebuilt from guest memory

A driver that you build inside the guest often needs no symbol path. If no symbol directory or server has the PDB of the driver, ntoseye rebuilds the PDB from guest memory. This works because the linker wrote the file only a short time before, so Windows usually still has its pages in the file cache, either with the file open or on the standby list.

To rebuild the PDB, ntoseye:

1. Finds the file by the path in the CodeView record of the driver. If `lld-link` wrote the file under a temporary name, ntoseye also finds the file under that name.
2. Reads the file page by page through the prototype PTEs of its section.
3. Gets the size of the file from its MSF header.
4. Makes sure that the GUID and age of the file are those of the driver, and does not use the file if they are different.
5. Puts the file in the symbol cache, so that later sessions, including sessions after a reboot, have it.

After a rebuild, `lm` shows `rebuilt <path> for <driver> from guest memory`.

If Windows has used some pages of the PDB again for other data, for example after heavy memory use or after a reboot, ntoseye does not rebuild the PDB, and the error of the module shows how many pages are missing.

ntoseye tries the rebuild only if the image records the PDB with a full path. Microsoft's binaries record only a file name.

When ntoseye rebuilds a PDB depends on where it reads guest memory from. See [memory sources](memory.md#where-reads-come-from).

| Memory read from | Rebuilt |
| --- | --- |
| The host: the `gdb` and `memory` backends, and `kd`/`kdnet` with `--memory-source host`, or with `auto` after the host mapping matched. | Automatically, each time the symbols of a module load (at attach, at a stop, or at a process attach), and also by {command}`.reload`. |
| The target: `kd`/`kdnet` with `--memory-source kd`, or with `auto` after it fell back to KD. | Only by an explicit `.reload <module>` or {command}`ld`, because ntoseye must walk the kernel's file lists one KD request at a time to find the file, which takes several seconds. |

If ntoseye skips a module for this reason, the error of the module in {command}`lmv` shows `guest memory: not tried automatically while guest memory is read through the target; .reload <module> rebuilds it`.

To turn off the rebuild completely, use `--no-pdb-from-memory` or set `NTOSEYE_NO_PDB_FROM_MEMORY=1`.

:::{note}
The rebuild from guest memory is tested only on AMD64 guests.
:::

## Source breakpoints in your driver

If the driver is already loaded, force source selection and indexing once with `ld mydriver` after you change the path. Then examine the accepted PDB identity with `lmv mydriver`, set the source breakpoint with `bu MyDriver.c:42`, list the breakpoints with {command}`bl`, and continue with {command}`g`:

```text
ld mydriver
lmv mydriver
bu MyDriver.c:42
bl
g
```

{command}`lmv` shows:

- The loaded image range.
- The symbol status.
- Where ntoseye read the image from, for example guest memory.
- The GUID and age of the accepted PDB.

`.reload mydriver` does the same as `ld mydriver`, and {command}`.reload` without a module reloads all modules in the current inspection scope.

The name {command}`.reload` is reserved for the symbol reload in the Rust code of ntoseye, so to reload custom commands and aliases, use {command}`reload-scripts`.

### Set the breakpoint before the driver loads

You can also set the paths and the breakpoint before the driver loads, without {command}`ld`. `bu MyDriver.c:42` then sets a deferred breakpoint, which {command}`bl` shows as `deferred` with no address. After {command}`g`, load and trigger the driver in Windows.

When the driver loads, ntoseye refreshes the module list, loads the matching PDB, and enables the breakpoint with the same ID and its existing settings, all before `DriverEntry` runs. It does this on every live backend (see [stopping at a driver load](breakpoints.md#stopping-at-a-driver-load)), so `bu mydriver!DriverEntry` stops at the first instruction of the driver.

### Check the source hit

When the target stops at the source breakpoint, these commands check the complete private-symbol workflow:

```text
lmv mydriver
ln @rip
uf mydriver!Transform
k
dv
```

The stack and the disassembly show the mapped source locations. {command}`dv` shows the private parameters and locals of the selected frame with their register-relative or stack-relative locations and, if the current register context matches the frame, their live values.

## Inline frames

ntoseye shows a call that the compiler inlined as a separate frame, as WinDbg does. {command}`k` lists the inline frame, with the tag `[inline]`, above the frame that the call was inlined into. The inline frame shows the addresses of the frame that the call was inlined into, the name of the inlined function, and the source line in the inlined function. The caller frame shows the line of the call.

Frame numbers include inline frames, so `.frame N` selects an inline frame like any other frame. After that, {command}`dv`, {command}`ls`, and local names in expressions use the variables and source of the inlined function, and the frame that the call was inlined into lists only its own variables.

An inline frame has no registers of its own and uses the registers of its physical frame. Stop headers and {command}`ln` show the name of the physical procedure.

## Code split off from its function

Profile-guided optimization moves the rarely run blocks of a function, such as error paths, away from the function's other code, often to near the end of the image. No public symbol is near such a block, but its unwind data chains to its function's. ntoseye names the block after that function, with the offset from the function's start, so {command}`k`, {command}`ln`, and disassembly show `nt!IopXxxControlFile+0x22bddf` instead of `nt+0xb1552f`, and the name evaluates back to the same address. This needs the module's PDB, and works only for x64 code.

## WPP trace messages

A private PDB also contains the WPP trace message formats (TMF) of the driver. `tracewpp` stores the format string and the argument types of each message as an annotation in the PDB.

When the PDB is loaded, {command}`!wmitrace.logdump` shows the WPP messages of the driver as formatted text, with the provider, the function, and the text of each message. In `dbg.inspect.etw_events()`, `message.text` contains the same data.

If the PDB is not loaded, a message shows only its GUID, number, and payload bytes, and the dump shows how many messages stayed raw.

Public PDBs do not contain these annotations, except Microsoft's `Wdf01000.pdb`, which keeps the annotations of KMDF itself.

## Drivers that unload and load again

If you unload and load the driver again, keep a {command}`bu` breakpoint installed. When ntoseye detects the unload, {command}`bl` changes the breakpoint from `enabled` to `deferred`, and the breakpoint keeps all of its state:

- Its ID.
- Its source specification.
- Its conditions.
- Its pass count.
- Its hit count.
- Its action.

When ntoseye detects the module load again at a later stop, the same breakpoint becomes `enabled` at the new address.

## When symbols are loaded

ntoseye loads the symbols of kernel modules at each stop and all other symbols on demand, as the subsections below describe.

### Backtraces

A backtrace loads the symbols of the modules that its frames touch, once per session.

If a PDB is already in the cache, ntoseye indexes it immediately. A PDB that ntoseye must download is downloaded on a background thread, because a stack walk runs inside a stop render and a client can wait for that render. Until the download completes, those frames show `module+offset`, and {command}`lmv` shows `fetching`.

ntoseye shows which modules it downloads and shows a message again when it finishes. Then run {command}`k` again to see the frames of these modules.

The unwind uses the unwind data of the image instead of the PDB, so the frames are correct before and after the download.

### Process-scoped breakpoints

A process-scoped breakpoint resolves in the process that it names. For example, `bu /p <pid> user32!PeekMessageW` reads the loader list of that process and loads the symbols of `user32` without a prior `.process /p <pid>`.

A `file:line` specification loads all modules in the process, because the line can be in any of them. A process-scoped breakpoint stays deferred only if its symbol is really not in the process.

`.process /p <pid>` still loads the symbols of the whole process at the start, so use it before you browse the process.

### Deferred breakpoints

ntoseye resolves a deferred breakpoint again each time new symbols become available, whatever loaded them, for example:

- A background download that completes.
- A backtrace.
- A process attach.
- A kernel module load.

ntoseye can install the breakpoint site only when the target is halted, so a breakpoint that becomes resolvable while the guest runs is installed at the next stop.
