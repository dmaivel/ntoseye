# Symbols and source

## The symbol path and cache

At the start, the symbol path has these entries, in this order:

1. The managed cache, `~/.ntoseye/symbols`.
2. The servers that you give with `--pdb-server` or `NTOSEYE_PDB_SERVERS`, if any.
3. Microsoft's public symbol server.

The cache is a symbol store. It uses the layout that `symstore` writes. SymSrv, IDA's PDB loader, Ghidra, and rizin read this layout:

- PDBs are in `<file>/<GUID><age>/<file>`.
- Images are in `<file>/<TimeDateStamp><SizeOfImage>/<file>`.
- The root contains the control files `pingme.txt` and `000admin`.

Other tools can use the cache. Set the symbol path of the tool to `srv*~/.ntoseye/symbols` or to a plain directory entry. ntoseye can also use a store that another tool filled. Add that store with {command}`.sympath+`.

Versions of ntoseye up to 0.30 left flat `~/.ntoseye/symbols/*.pdb` files and a `~/.ntoseye/images` directory. You can delete them.

## Private PDBs and local source

You set the symbol path and the source path separately. The host needs the private PDB of the driver. To show source, the host also needs a copy of the source tree. If you need procedure locals, use the full linker PDB (`/DEBUG:FULL`). Do not use a stripped or public PDB for this.

ntoseye compares the GUID and age of the selected PDB with the CodeView identity in the loaded guest image. If they are different, ntoseye does not accept the PDB.

To add the directory that contains the PDB, use {command}`.sympath+`. The `+` keeps the managed cache and Microsoft's public symbol server in the list. {command}`.sympath` without the `+` replaces all of the active list.

```text
.sympath+ <directory-containing-the-pdb>
```

{command}`.srcpath` sets the host directory that contains the source tree:

```text
.sympath+ /home/me/symbols/mydriver
.srcpath /home/me/src/MyDriver
```

### How ntoseye finds a source file

The PDB records source paths such as `C:\Users\me\source\repos\MyDriver\src\queue.c`. ntoseye maps such a path to a file under the source directory. It uses the longest trailing part of the path that names a file in that directory. For example, it selects `/home/me/src/MyDriver/src/queue.c` before `/home/me/src/MyDriver/queue.c`.

ntoseye first compares the case of the names exactly. If no file matches, it ignores the case. This finds a file when an `#include` spells its name with a different case.

You can also give a mapping `<prefix-recorded-in-the-pdb>=<local-root>`, for example `C:\Users\me\source\repos\MyDriver=/home/me/src/MyDriver`. ntoseye then replaces the recorded prefix with the local root. It does not use the longest trailing part in this case.

### Source checksums

The compiler records a checksum of each source file in the PDB. The checksum is MD5, SHA-1, or SHA-256. If the PDB has a checksum for a file, ntoseye shows the host file only if its checksum is the same. So ntoseye does not show a file that you changed after the build with the old line numbers. For such a file:

- {command}`ls` reports that the file is not the source that was compiled.
- The disassembly labels the location `differs`.

## PDBs rebuilt from guest memory

A driver that you build inside the guest often needs no symbol path. If no symbol directory or server has the PDB of the driver, ntoseye rebuilds the PDB from guest memory. This is possible because the linker wrote the file a short time before. Windows usually still has the pages of the file in its file cache. The file can be open, or its pages can be on the standby list.

To rebuild the PDB, ntoseye does these steps:

1. It finds the file by the path in the CodeView record of the driver. If `lld-link` wrote the file under a temporary name, ntoseye also finds the file under that name.
2. It reads the file page by page through the prototype PTEs of its section.
3. It gets the size of the file from its MSF header.
4. It makes sure that the GUID and age of the file are those of the driver. If they are different, it does not use the file.
5. It puts the file in the symbol cache. So later sessions, and sessions after a reboot, have the file.

After a rebuild, `lm` shows `rebuilt <path> for <driver> from guest memory`.

Windows can use some pages of the PDB again for other data, for example after heavy memory use or after a reboot. In that case, ntoseye does not rebuild the PDB. The error of the module shows how many pages are missing.

ntoseye tries the rebuild only if the image records the PDB with a full path. Microsoft's binaries record only a file name.

When ntoseye rebuilds a PDB depends on where it reads guest memory from. See [memory sources](memory.md#where-reads-come-from).

| Memory read from | Rebuilt |
| --- | --- |
| The host: the `gdb` and `memory` backends. Also `kd`/`kdnet` with `--memory-source host`, or with `auto` after the host mapping matched. | Automatically, each time the symbols of a module load (at attach, at a stop, or at a process attach). Also by {command}`.reload`. |
| The target: `kd`/`kdnet` with `--memory-source kd`, or with `auto` after it fell back to KD. | Only by an explicit `.reload <module>` or {command}`ld`. To find the file, ntoseye must walk the kernel's file lists one KD request at a time. This takes several seconds. |

If ntoseye skips a module for this reason, the error of the module in {command}`lmv` shows `guest memory: not tried automatically while guest memory is read through the target; .reload <module> rebuilds it`.

To turn off the rebuild completely, use `--no-pdb-from-memory` or set `NTOSEYE_NO_PDB_FROM_MEMORY=1`.

:::{note}
The rebuild from guest memory is tested only on AMD64 guests.
:::

## Source breakpoints in your driver

If the driver is already loaded, do these steps after you change the path:

1. Force source selection and indexing one time with `ld mydriver`.
2. Examine the accepted PDB identity with `lmv mydriver`.
3. Set the source breakpoint with `bu MyDriver.c:42`.
4. List the breakpoints with {command}`bl`, and continue with {command}`g`.

```text
ld mydriver
lmv mydriver
bu MyDriver.c:42
bl
g
```

{command}`lmv` shows these items:

- The loaded image range.
- The symbol status.
- Where ntoseye read the image from, for example guest memory.
- The GUID and age of the accepted PDB.

`.reload mydriver` does the same as `ld mydriver`. {command}`.reload` without a module reloads all modules in the current inspection scope.

The name {command}`.reload` is reserved for the symbol reload in the Rust code of ntoseye. To reload custom commands and aliases, use {command}`reload-scripts`.

### Set the breakpoint before the driver loads

You can also set the paths and the breakpoint before the driver loads. In that case, do not use {command}`ld`. `bu MyDriver.c:42` sets a deferred breakpoint, and {command}`bl` shows it as `deferred` with no address. After {command}`g`, load and trigger the driver in Windows.

When the driver loads, ntoseye does these steps before `DriverEntry` runs:

1. It refreshes the module list.
2. It loads the matching PDB.
3. It enables the breakpoint with the same ID and its existing settings.

ntoseye does this on every live backend. See [stopping at a driver load](breakpoints.md#stopping-at-a-driver-load). So `bu mydriver!DriverEntry` stops at the first instruction of the driver.

### Check the source hit

When the target stops at the source breakpoint, these commands check the complete private-symbol workflow:

```text
lmv mydriver
ln @rip
uf mydriver!Transform
k
dv
```

The stack and the disassembly show the mapped source locations. {command}`dv` shows the private parameters and locals of the selected frame. It shows their register-relative or stack-relative locations. If the current register context matches the frame, it also shows their live values.

## Inline frames

ntoseye shows a call that the compiler inlined as a separate frame, as WinDbg does. {command}`k` lists the inline frame above the frame that the call was inlined into. The inline frame has the tag `[inline]` and shows these items:

- The addresses of the frame that the call was inlined into.
- The name of the inlined function.
- The source line in the inlined function.

The caller frame shows the line of the call.

Frame numbers include inline frames. So `.frame N` selects an inline frame in the same way as any other frame. After that, {command}`dv`, {command}`ls`, and local names in expressions use the variables and source of the inlined function. The frame that the call was inlined into lists only its own variables.

An inline frame has no registers of its own. It uses the registers of its physical frame. Stop headers and {command}`ln` show the name of the physical procedure.

## WPP trace messages

A private PDB also contains the WPP trace message formats (TMF) of the driver. `tracewpp` stores the format string and the argument types of each message as an annotation in the PDB.

When the PDB is loaded, {command}`!wmitrace.logdump` shows the WPP messages of the driver as formatted text. Each message shows the provider, the function, and the text. In MCP results and in `dbg.inspect.etw_events()`, `message.text` contains the same data.

If the PDB is not loaded, a message shows only its GUID, number, and payload bytes. The dump then shows how many messages stayed raw.

Public PDBs do not contain these annotations. The exception is Microsoft's `Wdf01000.pdb`, which keeps the annotations of KMDF itself.

## Drivers that unload and load again

If you unload and load the driver again, keep a {command}`bu` breakpoint installed. When ntoseye detects the unload, {command}`bl` changes the breakpoint from `enabled` to `deferred`. The breakpoint keeps these items:

- Its ID.
- Its source specification.
- Its conditions.
- Its pass count.
- Its hit count.
- Its action.

When ntoseye detects the module load again at a later stop, the same breakpoint becomes `enabled` at the new address.

## When symbols are loaded

ntoseye loads the symbols of kernel modules at each stop. It loads all other symbols on demand. The subsections below tell when this occurs.

### Backtraces

A backtrace loads the symbols of the modules that its frames touch. It does this one time per session.

If a PDB is already in the cache, ntoseye indexes it immediately. If ntoseye must download a PDB, it downloads it on a background thread. The reason is that a stack walk runs inside a stop render, and a client can wait for that render. Until the download completes, those frames show `module+offset`, and {command}`lmv` shows `fetching`.

ntoseye shows which modules it downloads. It shows a message again when it finishes. Then run {command}`k` again to see the frames of these modules.

The unwind uses the unwind data of the image and does not use the PDB. So the frames are correct before and after the download.

### Process-scoped breakpoints

A process-scoped breakpoint resolves in the process that it names. For example, `bu /p <pid> user32!PeekMessageW` reads the loader list of that process and loads the symbols of `user32`. You do not need to run `.process /p <pid>` first.

A `file:line` specification loads all modules in the process, because the line can be in any of them. The breakpoint stays deferred only if the symbol is really not in the process.

`.process /p <pid>` still loads the symbols of the whole process at the start. Use it before you browse the process.

### Deferred breakpoints

ntoseye resolves a deferred breakpoint again each time new symbols become available. It does this for all sources of symbols:

- A background download that completes.
- A backtrace.
- A process attach.
- A kernel module load.

ntoseye can install the breakpoint site only when the target is halted. If a breakpoint becomes resolvable while the guest runs, ntoseye installs it at the next stop.
