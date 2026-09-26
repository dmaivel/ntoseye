# Symbols and source

The symbol path starts as the managed cache (`~/.ntoseye/symbols`) followed by any `--pdb-server`/`NTOSEYE_PDB_SERVERS` servers and Microsoft's public server. The cache is a symbol store in the layout `symstore` writes and SymSrv, IDA's PDB loader, Ghidra, and rizin read: `<file>/<GUID><age>/<file>` for PDBs, `<file>/<TimeDateStamp><SizeOfImage>/<file>` for images, with the `pingme.txt`/`000admin` control files at the root. Point another tool's symbol path at it (`srv*~/.ntoseye/symbols` or a plain directory entry) and it serves that tool too; a store another tool populated serves ntoseye through {command}`.sympath+`. Flat `~/.ntoseye/symbols/*.pdb` files and `~/.ntoseye/images` are left by versions up to 0.30 and can be deleted.

Symbol and source paths are configured independently. The host needs the private PDB and, for source display, a copy of the source tree. Use the full linker PDB (`/DEBUG:FULL`, not a stripped/public PDB) when procedure locals are needed. ntoseye validates the selected PDB's GUID and age against the CodeView identity in the loaded guest image and rejects a mismatch.

Append the directory containing the PDB with {command}`.sympath+`. The `+` preserves the managed cache and Microsoft's public symbol server; bare {command}`.sympath` replaces the entire active list:

```text
.sympath+ <directory-containing-the-pdb>
```

{command}`.srcpath` maps a source-path prefix recorded in the PDB to the corresponding source directory on the host:

```text
.srcpath <source-prefix-recorded-in-pdb>=<local-source-root>
```

For example:

```text
.sympath+ /home/me/symbols/mydriver
.srcpath C:\Users\me\source\repos\MyDriver=/home/me/src/MyDriver
```

The left side of {command}`.srcpath` is a build-time source path such as the prefix shown in an unmapped source location; it is not the PDB path embedded in the image. The right side is the local directory containing the same source files.

If the driver is already loaded, force source selection and indexing once after changing the path, inspect the accepted identity, and set the source breakpoint:

```text
ld mydriver
lmv mydriver
bu MyDriver.c:42
bl
g
```

{command}`lmv` reports the loaded image range, symbol status, where the image was read from (for example, guest memory), and the accepted PDB GUID and age. `.reload mydriver` is equivalent to `ld mydriver`; {command}`.reload` without a module reloads every module in the current inspection scope.

The paths and breakpoint can also be configured before loading the driver. In that case, omit {command}`ld`: `bu MyDriver.c:42` creates a deferred breakpoint, and {command}`bl` shows `deferred` with no address. Load and trigger the driver in Windows after {command}`g`. At the next debugger stop, ntoseye refreshes the module list, loads the matching PDB, and enables the same breakpoint ID with its existing settings.

At the source hit, these commands verify the complete private-symbol workflow:

```text
lmv mydriver
ln @rip
uf mydriver!Transform
k
dv
```

The stack and disassembly include mapped source locations. {command}`dv` displays the current procedure's private parameters and locals, including register- or stack-relative locations and live values when the current register context matches the procedure.

Keep a {command}`bu` breakpoint installed if the driver will be cycled. Once ntoseye observes the unload, {command}`bl` changes it from `enabled` to `deferred` without losing its ID, source specification, conditions, pass count, hit count, or action. After the module reload is observed at a later stop, the same breakpoint becomes `enabled` at the new address.

{command}`.reload` is reserved for Rust-owned symbol reload behavior; {command}`reload-scripts` reloads custom commands and aliases.

## When symbols are loaded

Kernel modules load at each stop. Everything else is on demand:

- **A backtrace** loads symbols for the modules its frames touch, once per session. PDBs already in the cache are indexed immediately; anything that must be downloaded is fetched on a background thread, because a stack walk runs inside a stop render that a client may be waiting on. Those frames read `module+offset` until the fetch lands, and {command}`lmv` shows `fetching`. The debugger says which modules it is fetching and says so again when it finishes; re-run {command}`k` for the named frames. Unwinding itself uses the image's unwind data, not the PDB, so the frames are correct either way.
- **A process-scoped breakpoint** resolves in the process it names: `bu /p <pid> user32!PeekMessageW` reads that process's loader list and loads `user32`'s symbols itself, with no prior `.process /p <pid>`. A `file:line` specification loads every module in the process, since the line can be in any of them. Only a symbol that really is absent from the process stays deferred.
- **`.process /p <pid>`** still loads the whole process up front, which is what you want before browsing it.

A deferred breakpoint is re-resolved whenever symbols become available, whoever loaded them: a background fetch finishing, a backtrace, a process attach, or a module load observed at a stop. Installing the site needs the target halted, so a breakpoint that becomes resolvable while the guest runs is installed at the next stop.
