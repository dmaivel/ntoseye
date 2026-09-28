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

`ntoseye` needs the driver's private PDB, the one the linker wrote next to the `.sys`. Where it looks depends on where you built.

### PDB on the host

Add the build directory to the symbol path, once per session:

```text
.sympath+ /home/me/mydriver/target/x86_64-pc-windows-msvc/release
```

The PDB loads when the driver does, and {command}`lmv` `mydriver` shows it.

### PDB in the guest

Usually nothing to do, provided the driver was built in the guest since the guest last booted, and preferably just before loading it. When no symbol directory or server has the PDB, `ntoseye` reads it out of the guest's memory: the build wrote it, so Windows still holds the file in its cache. The driver's image records where the PDB was written, so `ntoseye` finds it by that path, uses it only if it matches the driver, and saves it to the host's symbol cache for later sessions. The load says so:

```text
rebuilt C:\Users\me\source\repos\mydriver\x64\Debug\mydriver.pdb for mydriver.sys from guest memory
```

This happens by itself with the `gdb` backend and with KD reading memory from the host (the default). With KD reading memory through the target (`--memory-source kd`), it runs only when asked: {command}`.reload` `mydriver`.

That cache is why the build has to be recent. A reboot empties it, and memory the guest needs reclaims it over time, so the longer since the build, the likelier pages are missing. If the guest has rebooted since, or much time has passed, rebuild the driver before loading it; reading the PDB once in the guest (`Get-FileHash mydriver.pdb`) also brings it back. If it is still missing, {command}`lmv` `mydriver` says why; copy the PDB to the host and use `.sympath+` as above. [Symbols and source](symbols.md) has the details, and `--no-pdb-from-memory` turns this off.

### Source files

A PDB records source paths as they were at build time. {command}`.srcpath` maps them to a checkout on the host by path suffix, so a guest path like `C:\Users\me\source\repos\mydriver\mydriver.c` finds `/home/me/mydriver/mydriver.c`:

```text
.srcpath /home/me/mydriver
```

A file edited since the build is reported as not the source compiled, rather than shown against the wrong lines.

Usually not needed: a mapping `<recorded-prefix>=<local-root>` replaces the prefix the PDB records instead of matching by suffix, for a checkout where suffix matching could pick the wrong file (two files ending in the same path under the root):

```text
.srcpath C:\Users\me\source\repos\mydriver=/home/me/mydriver
```

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
