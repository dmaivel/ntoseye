# The registry (`!reg`)

{command}`!reg` reads the registry from the configuration manager's hives in kernel memory: the hives that are loaded, and any key with its subkeys and values. It needs nothing from the guest, so it works on every backend, while the guest runs on the `memory` backend, and in a crash dump. Use it to see a driver's service key and device parameters as the driver read them, or the persistence and configuration keys of a system you are examining.

The subcommands are those of WinDbg's `!reg`: `hivelist`, `querykey` (or `q`), `keyinfo`, and `cellindex`. WinDbg's `querykey` shows only keys that the kernel has cached; `ntoseye` walks the hives themselves, so it shows any key.

## Hives

`!reg hivelist` lists each hive on `nt!CmpHiveListHead`:

```text
!reg hivelist
Hive              Stable     Volatile  Mount point                                                            File
ffff80848b22d000  0x3000     0x1000    \REGISTRY                                                              (master hive)
ffff80848b234000  0xec3000   0x3f000   \REGISTRY\MACHINE\SYSTEM                                               SYSTEM (base block)
ffff80848b2d2000  0x8000     0xc000    \REGISTRY\MACHINE\HARDWARE                                             (in memory only)
ffff80848b934000  0xb000     0x1000    \REGISTRY\MACHINE\SECURITY                                             \SystemRoot\System32\Config\SECURITY
ffff80848b936000  0x66ff000  0x584000  \REGISTRY\MACHINE\SOFTWARE                                             \SystemRoot\System32\Config\SOFTWARE
ffff80848b938000  0xe4000    0x1000    \REGISTRY\USER\.DEFAULT                                                \SystemRoot\System32\Config\DEFAULT
ffff80848b9a0000  0xc000     0x0       \REGISTRY\MACHINE\SAM                                                  \SystemRoot\System32\Config\SAM
ffff80848ff79000  0x9000     0x0       \REGISTRY\MACHINE\BCD00000000                                          \Device\HarddiskVolume1\EFI\Microsoft\Boot\BCD
ffff8084935cb000  0x3b7000   0x4000    \REGISTRY\USER\S-1-5-21-3561719566-4168452844-2155236377-1001          \??\C:\Users\msvm\ntuser.dat
ffff808492ec8000  0x237000   0x0       \REGISTRY\USER\S-1-5-21-3561719566-4168452844-2155236377-1001_Classes  \??\C:\Users\msvm\AppData\Local\Microsoft\Windows\UsrClass.dat
ffff808493e4d000  0x11000    0x0       \REGISTRY\A\{17BB2D2F-C990-458E-86FC-DBC12A29371B}                     \??\C:\ProgramData\Microsoft\Windows\AppRepository\Packages\Microsoft.UI.Xaml.CBS_9.2603.18001.0_x64__8wekyb3d8bbwe\ActivationStore.dat
...
```

Each line shows the hive's `_CMHIVE`, the bytes of its stable and volatile storage, where it is mounted, and the file it was loaded from. The boot loader loads the SYSTEM hive before the kernel records a file for it, so its line shows the name that the hive's base block records. The master hive holds `\REGISTRY` and the keys that hives are mounted at, and HARDWARE exists only in memory. Hives under `\REGISTRY\A` are application hives that a process loaded for itself (`RegLoadAppKey`), and hives under `\REGISTRY\WC` are those of app silos. The guest's `HKLM\SYSTEM\CurrentControlSet\Control\hivelist` key lists the same mount points, except the application hives.

## Keys and values

`!reg querykey` takes a key's full path, `\REGISTRY\...`, or a path that starts with `HKLM`, `HKU`, `HKCR` (the machine's classes, `HKLM\SOFTWARE\Classes`), or `HKCC`. `HKCU` is the key of whichever user a thread runs as, so give that user's `HKU\<SID>`, which `!reg hivelist` shows. Names are not case-sensitive, and a path with spaces needs no quotes.

```text
!reg querykey HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters
key \REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\Tcpip\Parameters
  link        \REGISTRY\MACHINE\SYSTEM\CurrentControlSet -> \Registry\Machine\SYSTEM\ControlSet001
  hive        ffff80848b234000
  key node    ffff80848e2b6cbc  cell 0x6abcb8
  flags       0x20 (KEY_COMP_NAME)
  last write  2026-10-11T05:20:07Z

6 of 6 subkeys
Key node          Last write            Subkeys  Values  Name
ffff80848e2b71e4  2026-10-10T08:13:33Z  7        0       Adapters
ffff80848e2b8024  2026-01-18T22:11:35Z  0        0       DNSRegisteredAdapters
ffff80848e2b8264  2026-10-10T08:13:33Z  8        0       Interfaces
ffff80848e8c092c  2024-04-01T07:26:32Z  0        0       NsiObjectSecurity
ffff80848e2baf7c  2024-04-01T07:26:32Z  0        0       PersistentRoutes
ffff80848e2bb024  2024-04-01T07:29:15Z  3        7       Winsock

12 of 12 values
Type           Name                      Data
REG_EXPAND_SZ  DataBasePath              %SystemRoot%\System32\drivers\etc
REG_SZ         Domain                    -
REG_DWORD      ForwardBroadcasts         0x0 (0)
REG_SZ         ICSDomain                 mshome.net
REG_DWORD      IPEnableRouter            0x0 (0)
REG_SZ         NameServer                -
REG_DWORD      SyncDomainWithMembership  0x1 (1)
REG_SZ         NV Hostname               win11vm
REG_SZ         Hostname                  win11vm
REG_BINARY     Health                    01000000000000002E4D97BD3759DD011A000000000000000000000000000000... (0x30 bytes)
REG_DWORD      PortTrackerEnabledMode    0x2 (2)
REG_SZ         DhcpNameServer            10.0.2.3

(data cut short; !reg querykey <path> -v <value> shows a value in full)
```

The path resolves as the kernel parses it. It starts at `\REGISTRY`, the root of the master hive, crosses from the key where a hive is mounted to the root of that hive, and follows symbolic links. `CurrentControlSet` is a symbolic link to the control set in use, and each `link` line names a link that the path went through. The key shows its full path with the names as the hive stores them. Subkeys and values are listed in the order that the kernel enumerates them, which is the order of `reg query` in the guest: the stable subkeys sorted by name, then the volatile ones, and the values in the order of the key's value list.

Each value's data is decoded by its type: `REG_SZ`, `REG_EXPAND_SZ` (not expanded), and `REG_LINK` as text, `REG_MULTI_SZ` as its strings separated by `\0`, `REG_DWORD`, `REG_DWORD_BIG_ENDIAN`, and `REG_QWORD` in hex and decimal, and the other types as hex bytes. Long strings and data are cut short. `-v` shows one value in full, the decoded data and every byte, and `-v ""` shows the default value:

```text
!reg q HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer -v DependOnService
key \REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\LanmanServer
  link        \REGISTRY\MACHINE\SYSTEM\CurrentControlSet -> \Registry\Machine\SYSTEM\ControlSet001
  hive        ffff80848b234000
  key node    ffff80848e1f6d64  cell 0x4efd60
  flags       0x20 (KEY_COMP_NAME)
  last write  2026-01-18T22:11:32Z

value DependOnService
  type        REG_MULTI_SZ (0x7)
  length      0x18 bytes, in a cell
  value node  ffff80848e1f6dc4  cell 0x4efdc0
  data        2 strings
    [0] SamSS
    [1] Srv2

  0000  53 00 61 00 6d 00 53 00 53 00 00 00 53 00 72 00  S.a.m.S.S...S.r.
  0010  76 00 32 00 00 00 00 00                          v.2.....
```

A value whose data is longer than one cell holds (16,344 bytes), such as `AppCompatCache` in `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`, is stored in big data segments, which `-v` reads and joins: `length 0x1b77a bytes, in big data segments`.

At the prompt, the Tab key completes a path one key at a time.

## Cells that are not in memory

A hive is a run of bins of cells, and the hive's cell map gives the address of each bin. The bins of a hive loaded from a file are views of the file in the address space of the Registry process, a minimal process that the kernel creates for them, and the kernel loads their pages from the file as they are used. A page that has not been used since boot, or that Windows has trimmed, is not in memory, so the cells in it cannot be read. In a crash dump, the pages of the Registry process are there only if the dump includes user memory. `!reg` shows every cell that reads and names each one that does not:

```text
!reg q HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion
...
58 of 101 subkeys
Key node          Last write            Subkeys  Values  Name
000001c124ae8984  2026-10-10T08:13:36Z  4        0       Accessibility
...
subkey cell 0x3bb8b00: the cell at 0x1c125559b00 is not in memory: bad virtual address: 0x1c125559b00
...
```

Once the guest reads those keys, for example with `reg query`, their pages are in memory, and the same command shows all 101 subkeys.

## Keys by address and cells

`!reg keyinfo` shows the key whose `_CM_KEY_NODE` is at an address in a hive, as `querykey` shows it, with the key's path found from its parents. The `Key node` column of `querykey` gives the address of each subkey. `!reg cellindex` shows where a cell index of a hive is: the directory and table of the cell map and the offset that the index selects, the map entry of the cell's block, where the entry maps the block, and the cell's address and size:

```text
!reg cellindex ffff80848b936000 764008
cell 0x764008 (stable)  hive ffff80848b936000
  map         directory 3, table 356, offset 0x8
  map entry   ffff80848b9d4160  block 000001c122105000
  address     000001c122105008  data at 000001c12210500c
  size        0x28, in use
```

The cell is in the Registry process's address space, so read its data with {command}`db` after `.process /p` selects that process.

## From Python

`dbg.inspect` has a method for each subcommand, and each returns typed records:

- `registry_hives()` for `!reg hivelist`
- `registry_key(path)` for `!reg querykey`, with the key's `subkeys` and `values`
- `registry_value(path, name)` for one value, `-v`; `""` names the default value
- `registry_key_at(hive, node)` for `!reg keyinfo`
- `registry_cell(hive, cell)` for `!reg cellindex`

A value's `data` is a `str`, a `list[str]`, an `int`, or `bytes`, by the value's type, and `raw` has its bytes. Both are `Diagnostic`s, which hold the reason when the data is not in memory:

```python
key = dbg.inspect.registry_key(r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer")
for value in key.values:
    print(value.name, value.type_name, value.data.value)

start = dbg.inspect.registry_value(r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip", "Start")
print(start.data.value)  # 0 (SERVICE_BOOT_START), an int
```
