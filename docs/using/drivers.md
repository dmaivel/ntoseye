# Developing drivers from a Linux host

A driver's edit-build-load-debug loop can run from the Linux host that runs the Windows VM. The guest still needs a kernel debugger configured ([KDNET](../setup/kdnet.md) or [KD over serial](../setup/kvm-qemu.md#kd-over-a-serial-socket)) for the steps below that serve files or load unsigned code; the GDB stub is enough for debugging a driver that already loads.

## Build

Build where the toolchain is:

- **In the guest**, with Visual Studio and the WDK, as on any Windows machine. The PDB stays in the guest; see [Symbols](#symbols).
- **On the host**, for a driver that needs neither the WDK's headers nor its libraries. A `no_std` Rust driver with no imports links with `rust-lld`:

  ```toml
  # .cargo/config.toml
  [build]
  target = "x86_64-pc-windows-msvc"

  [target.x86_64-pc-windows-msvc]
  linker = "rust-lld"
  rustflags = [
    "-C", "linker-flavor=lld-link",
    "-C", "link-arg=/DRIVER",
    "-C", "link-arg=/SUBSYSTEM:NATIVE",
    "-C", "link-arg=/ENTRY:DriverEntry",
    "-C", "link-arg=/NODEFAULTLIB",
    "-C", "link-arg=/DEBUG:FULL",
  ]
  ```

  with `crate-type = ["cdylib"]` and `panic = "abort"`. The output is a `.dll`; copy or serve it under the driver's `.sys` name. A driver built on [windows-drivers-rs](https://github.com/microsoft/windows-drivers-rs) links against the WDK and has not been tested from a Linux host.

## Load

Register the driver once in the guest:

```text
sc create mydriver type= kernel start= demand binPath= C:\drivers\mydriver.sys
```

Windows refuses an unsigned driver (`StartService` error 577) unless test signing is on (`bcdedit /set testsigning on`, then reboot) or a kernel debugger is attached: with an `ntoseye` KD session attached, `sc start mydriver` loads it.

Over KD, {command}`.kdfiles` makes the guest take the image from the host at every load, so a rebuild on the host needs no copy into the guest:

```text
.kdfiles -m mydriver.sys /home/me/mydriver/target/x86_64-pc-windows-msvc/release/mydriver.dll
```

Then `sc stop mydriver` (the driver needs a `DriverUnload`) and `sc start mydriver` load the new build. The guest also writes it over its own copy on disk. See [Driver replacement map](kdfiles.md).

## Symbols

A PDB built on the host is found by adding its directory to the symbol path: `.sympath+ /home/me/mydriver/target/x86_64-pc-windows-msvc/release`.

A PDB built in the guest needs no copy to the host. When the driver loads and no symbol directory or server has its PDB, `ntoseye` reads the file out of guest memory:

1. The driver's image records where the linker wrote its PDB (`C:\Users\me\source\repos\mydriver\x64\Debug\mydriver.pdb`) and the PDB's GUID and age.
2. The linker has just written that file, so Windows still holds its pages in the file cache: in use while the file is open, on the standby list once it is closed. `ntoseye` finds the file among the cached files by that path and reads its pages.
3. The result is used only if its GUID and age are the driver's. It is then saved to the symbol cache, so later sessions and reboots find it there; `lm` reports `rebuilt <path> for mydriver from guest memory`.

With the `gdb` backend, or KD with memory read from the host (the default when the host mapping is found), this happens by itself when the driver's symbols load. With memory read through KD (`--memory-source kd`, or `auto` that fell back to it), finding the file takes several seconds of KD requests, so it runs only on {command}`.reload` `mydriver`.

The pages have to still be there. Heavy memory use in the guest can reuse them, and a reboot empties the cache: after one, rebuild the driver, or read the PDB once in the guest (open it, or `Get-FileHash mydriver.pdb`), before loading it. A PDB with pages missing is not rebuilt, and {command}`lmv` says how many were missing. It is tried only for a PDB recorded with a full path, which a local build always has, and `--no-pdb-from-memory` turns it off. [Symbols and source](symbols.md) has the details.

Source files map to a host checkout with `.srcpath`, by path suffix.

## Stop in the driver

Set the breakpoint before loading the driver:

```text
bu mydriver!DriverEntry
```

The breakpoint stays deferred until the module loads, and arms when it does, before `DriverEntry` runs, on the KD and GDB backends alike. To stop at the load itself, before choosing breakpoints, use {command}`sxe` `ld:mydriver`.

Names are the PDB's. C++ templates and Rust generics are part of the name: `bp mydriver!mydriver::impl$0::tally<u32>`. rustc writes paths in MSVC style: `crate::module::function`, `impl$N` for impl blocks, `closure_env$N` for closures; {command}`x` `mydriver!*` lists them, and {command}`bm` sets breakpoints on the code among them.

## When it crashes

A bugcheck stops the session at the crash with the faulting frame and `!analyze` ([Bugchecks](bugchecks.md)). A KMDF driver's framework state and In-Flight Recorder log are under [KMDF drivers](kmdf.md); WPP messages format from the private PDB ([Symbols](symbols.md)).

With VBS enabled, KD cannot write breakpoints into user-mode code, so a user-mode client of the driver is debugged with hardware breakpoints (`ba e1`); see [Troubleshooting](../get-started/troubleshooting.md#breakpoints-and-stepping).
