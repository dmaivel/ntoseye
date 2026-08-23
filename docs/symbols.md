# Private PDBs and local source

Symbol and source paths are configured independently. The host needs the private PDB and, for source display, a copy of the source tree. Use the full linker PDB (`/DEBUG:FULL`, not a stripped/public PDB) when procedure locals are needed. ntoseye validates the selected PDB's GUID and age against the CodeView identity in the loaded guest image and rejects a mismatch.

Append the directory containing the PDB with `.sympath+`. The `+` preserves the managed cache and Microsoft's public symbol server; bare `.sympath` replaces the entire active list:

```text
.sympath+ <directory-containing-the-pdb>
```

`.srcpath` maps a source-path prefix recorded in the PDB to the corresponding source directory on the host:

```text
.srcpath <source-prefix-recorded-in-pdb>=<local-source-root>
```

For example:

```text
.sympath+ /home/me/symbols/mydriver
.srcpath C:\Users\me\source\repos\MyDriver=/home/me/src/MyDriver
```

The left side of `.srcpath` is a build-time source path such as the prefix shown in an unmapped source location; it is not the PDB path embedded in the image. The right side is the local directory containing the same source files.

If the driver is already loaded, force source selection and indexing once after changing the path, inspect the accepted identity, and set the source breakpoint:

```text
ld mydriver
lmv mydriver
bu MyDriver.c:42
bl
g
```

`lmv` reports the loaded image range, symbol status, where the image was read from (for example, guest memory), and the accepted PDB GUID and age. `.reload mydriver` is equivalent to `ld mydriver`; `.reload` without a module reloads every module in the current inspection scope.

The paths and breakpoint can also be configured before loading the driver. In that case, omit `ld`: `bu MyDriver.c:42` creates a deferred breakpoint, and `bl` shows `deferred` with no address. Load and trigger the driver in Windows after `g`. At the next debugger stop, ntoseye refreshes the module list, loads the matching PDB, and enables the same breakpoint ID with its existing settings.

At the source hit, these commands verify the complete private-symbol workflow:

```text
lmv mydriver
ln @rip
uf mydriver!Transform
k
dv
```

The stack and disassembly include mapped source locations. `dv` displays the current procedure's private parameters and locals, including register- or stack-relative locations and live values when the current register context matches the procedure.

Keep a `bu` breakpoint installed if the driver will be cycled. Once ntoseye observes the unload, `bl` changes it from `enabled` to `deferred` without losing its ID, source specification, conditions, pass count, hit count, or action. After the module reload is observed at a later stop, the same breakpoint becomes `enabled` at the new address.

`.reload` is reserved for Rust-owned symbol reload behavior; `reload-scripts` reloads custom commands and aliases.
