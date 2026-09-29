# Driver replacement map (`.kdfiles`)

{command}`.kdfiles` makes the target load a driver image **from the host filesystem**. The target does not use the copy on its own disk. So you can rebuild and reload a driver, and you do not have to copy the `.sys` file into the VM after each build.

If the kernel debugger is enabled, `nt!MmLoadSystemImage` first asks the debugger for the image. If the debugger does not supply the image, the target uses the copy on its own disk. `ntoseye` answers the request from the map. If the name is not in the map, `ntoseye` returns a failure for the request. The target then uses its own copy and does not show a message.

This feature works over KDCOM and KDNET. The {command}`capabilities` command shows it as `host-served target files`. On the GDB, memory, and dump backends, {command}`.kdfiles` shows a warning. The warning tells you that these backends never use the map.

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

Then reload the driver in the guest. Use `sc stop mydriver` and `sc start mydriver`, or a different loader. The debugger shows a note for each image that it serves.

```
note: kdfiles: target opened \??\C:\Users\me\source\repos\mydriver\x64\Debug\mydriver.sys
      -> /home/me/build/mydriver.sys (7920 bytes)
```

If you enter {command}`.kdfiles` with no argument, it shows the map and the totals of served files. Use these totals to make sure that the mapping matched and served the image.

```
kd:p1.1> .kdfiles
mydriver.sys  ->  /home/me/build/mydriver.sys

served 1 open, 7920 bytes read, 0 refused
```

If a host path contains spaces, put the path in quotes. You can use `'` or `"`.

```
kd:p1.1> .kdfiles -m mydriver.sys '/home/me/my builds/mydriver.sys'
Mapped mydriver.sys -> /home/me/my builds/mydriver.sys.
```

After you rebuild the driver, reload it in the guest. You do not have to load the mapping again.

## Name matching

The target asks for the path that it gives to `MmLoadSystemImage`. Usually, this is the image path in the Service Control Manager database. This path can be different from the host path.

The name match works the same as in WinDbg on Windows 10 and later. The match:

- ignores case.
- ignores differences in path separators.
- compares the end of the path (a suffix match).

| Map target | Matches |
| --- | --- |
| `mydriver.sys` | any directory, including `\SystemRoot\System32\drivers\mydriver.sys` and `\??\C:\build\mydriver.sys` |
| `drivers\probe.sys` | `\SystemRoot\System32\drivers\probe.sys`, but not `...\mydrivers\probe.sys` |
| `\SystemRoot\System32\drivers\probe.sys` | only that full path |

To match any directory, use only the file name. A match must start at a `\` boundary. So `probe.sys` does not match `xprobe.sys`.

## Map files

`.kdfiles <map-file>` reads a file in the WinDbg driver replacement map format. Each record has three lines:

1. the word `map`
2. the target name
3. the host path

`ntoseye` ignores blank lines and comments that start with `;` or `//`. `ntoseye` resolves a relative host path from the directory of the map file.

```
; drivers.map
map
mydriver.sys
build/mydriver.sys

map
OtherDriver.sys
/home/me/other/OtherDriver.sys
```

When you load a map, `ntoseye` first validates every host path. Then it replaces the previous map with the new map.

## Behaviour and limits

- **Read-only.** The map supplies driver images. If the target tries to write to a host path, `ntoseye` returns `STATUS_ACCESS_DENIED`.
- **Takes effect on the next load.** An image that is already loaded does not change. Unload the driver and load it again.
- **Signature enforcement still applies.** The target validates the served bytes the same as an image on its disk. So a test-signed driver still needs test signing enabled on the target.
- **Unmapped names fall back to the target's disk copy.** If a name is not in the map, the target loads the copy on its disk.
- File handles do not stay open after a reboot or a reconnect. The target opens the files again when it needs them.
- A maximum of 64 host files can be open at the same time.

## Troubleshooting

To see every request, set `NTOSEYE_KD_TRACE=1`. The trace shows the name that the target asked for. It also shows the byte ranges that the target read.

```
kd: kdfiles: serving /home/me/build/mydriver.sys as \??\C:\...\mydriver.sys (7920 bytes, handle 0x1, ...)
kd: kdfiles: read handle 0x1 offset 0x0 want 3936 -> 3936 bytes
kd: kdfiles: read handle 0x1 offset 0xf60 want 3936 -> 3936 bytes
kd: kdfiles: read handle 0x1 offset 0x1ec0 want 48 -> 48 bytes
kd: kdfiles: close handle 0x1 (known: true)
```

If a driver load does not make a `kdfiles` trace, do these checks:

1. Make sure that the kernel debugger is enabled in the guest (`bcdedit /debug on`).
2. Make sure that `MmLoadSystemImage` loads the driver. The driver must not be already in memory.

If the trace shows `no mapping for <name>`, compare that name with the map target. A map target that is only a file name matches any directory.
