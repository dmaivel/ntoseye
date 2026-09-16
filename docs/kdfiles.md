# Driver replacement map (`.kdfiles`)

`.kdfiles` makes the target load a driver image **from the host filesystem** instead of from its own disk, so a driver can be rebuilt and reloaded without copying the `.sys` into the VM on every iteration.

When the kernel debugger is enabled, `nt!MmLoadSystemImage` asks the debugger for the image before falling back to the copy on the target's disk. `ntoseye` answers that request from the map; an unmapped name is refused, and the target silently uses its own copy.

This feature works over KDCOM and KDNET. The `capabilities` command reports it as `host-served target files`. On the GDB, memory, and dump backends `.kdfiles` warns that the map will never be consulted.

## Usage

```
.kdfiles                        show the map and what it has served
.kdfiles <map-file>             load a WinDbg driver replacement map file
.kdfiles -m <target> <host>     add one mapping
.kdfiles -d <target>            remove one mapping
.kdfiles -c                     clear the map
```

The quick form takes the driver name and the host path.

```
kd:p1.1> .kdfiles -m mydriver.sys /home/me/build/mydriver.sys
Mapped mydriver.sys -> /home/me/build/mydriver.sys.
```

Then reload the driver in the guest (`sc stop mydriver` / `sc start mydriver`, or the loader of your choice). The debugger reports each image it serves.

```
note: kdfiles: target opened \??\C:\Users\me\source\repos\mydriver\x64\Debug\mydriver.sys
      -> /home/me/build/mydriver.sys (7920 bytes)
```

`.kdfiles` with no argument shows the map and serving totals. Use these to check whether the mapping matched and served the image.

```
kd:p1.1> .kdfiles
mydriver.sys  ->  /home/me/build/mydriver.sys

served 1 open, 7920 bytes read, 0 refused
```

Quote host paths containing spaces with either `'` or `"`.

```
kd:p1.1> .kdfiles -m mydriver.sys '/home/me/my builds/mydriver.sys'
Mapped mydriver.sys -> /home/me/my builds/mydriver.sys.
```

After rebuilding, reload the driver in the guest. The mapping does not need to be reloaded.

## Name matching

The target requests the path passed to `MmLoadSystemImage`, typically the image path recorded in the Service Control Manager database. This can differ from the host path.

Matching is case-insensitive, separator-insensitive, and suffix-based, mirroring WinDbg on Windows 10 and later.

| Map target | Matches |
| --- | --- |
| `mydriver.sys` | any directory, including `\SystemRoot\System32\drivers\mydriver.sys` and `\??\C:\build\mydriver.sys` |
| `drivers\probe.sys` | `\SystemRoot\System32\drivers\probe.sys`, but not `...\mydrivers\probe.sys` |
| `\SystemRoot\System32\drivers\probe.sys` | only that full path |

Use a bare filename to match any directory. Matching requires a `\`-delimited boundary, so `probe.sys` never matches `xprobe.sys`.

## Map files

`.kdfiles <map-file>` reads WinDbg's driver replacement map format. Each three-line record contains the literal word `map`, the target name, and the host path. Blank lines and `;` / `//` comments are ignored. Relative host paths resolve against the map file's directory.

```
; drivers.map
map
mydriver.sys
build/mydriver.sys

map
OtherDriver.sys
/home/me/other/OtherDriver.sys
```

Loading a map replaces the previous one after validating every host path.

## Behaviour and limits

- **Read-only.** The map serves driver images; target-driven writes to a host path are refused with `STATUS_ACCESS_DENIED`.
- **Takes effect on the next load.** An already-loaded image is not replaced; unload and reload the driver.
- **Signature enforcement still applies.** The served bytes go through the same validation as an on-disk image, so a test-signed driver still needs test signing enabled on the target.
- **Unmapped names fall back to the target's disk copy.**
- Handles do not survive a reboot or a reconnect; the target re-opens what it needs.
- At most 64 host files can be open at once.

## Troubleshooting

Set `NTOSEYE_KD_TRACE=1` to see every request, including the name the target asked for and the exact byte ranges it read.

```
kd: kdfiles: serving /home/me/build/mydriver.sys as \??\C:\...\mydriver.sys (7920 bytes, handle 0x1, ...)
kd: kdfiles: read handle 0x1 offset 0x0 want 3936 -> 3936 bytes
kd: kdfiles: read handle 0x1 offset 0xf60 want 3936 -> 3936 bytes
kd: kdfiles: read handle 0x1 offset 0x1ec0 want 48 -> 48 bytes
kd: kdfiles: close handle 0x1 (known: true)
```

If a driver load produces no `kdfiles` trace, check that the kernel debugger is enabled in the guest (`bcdedit /debug on`) and that the driver is being loaded by `MmLoadSystemImage` rather than already resident.

If it traces `no mapping for <name>`, compare that name against the map target; the bare-file-name form matches any directory.
