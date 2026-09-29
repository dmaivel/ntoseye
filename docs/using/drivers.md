# Developing drivers from a Linux host

You can edit, build, load, and debug a driver from the Linux host that runs the Windows VM.

The steps below that serve files to the guest or load unsigned code need a kernel debugger configured in the guest, either [KDNET](../setup/kdnet.md) or [KD over serial](../setup/kvm-qemu.md#kd-over-a-serial-socket). To debug a driver that already loads, the GDB stub is enough.

If the guest uses VBS, turn it off unless you test the driver with Memory integrity. See [Should VBS be on?](../platforms/vbs.md#should-vbs-be-on).

## Build

Build the driver on the machine that has the toolchain:

- **In the guest**: Use Visual Studio and the WDK, as on any Windows machine. The PDB stays in the guest.
- **On the host**: Use this option for a driver that does not need the WDK headers or libraries. A `no_std` Rust driver with no imports links with `rust-lld`:

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

  The crate also needs `crate-type = ["cdylib"]` and `panic = "abort"`. The output is a `.dll` file, which you copy or serve under the `.sys` name of the driver.

  A driver built on [windows-drivers-rs](https://github.com/microsoft/windows-drivers-rs) links against the WDK, and we did not test this type of driver from a Linux host.

## Load

Register the driver once in the guest:

```text
sc create mydriver type= kernel start= demand binPath= C:\drivers\mydriver.sys
```

Windows loads an unsigned driver only when test signing is on or a kernel debugger is attached, and otherwise gives `StartService` error 577. To turn test signing on, run `bcdedit /set testsigning on`, then restart the guest. With an `ntoseye` KD session attached, `sc start mydriver` loads the driver.

Over KD, {command}`.kdfiles` makes the guest get the image from the host each time the driver loads, so after you rebuild the driver on the host, you do not have to copy it into the guest:

```text
.kdfiles -m mydriver.sys /home/me/mydriver/target/x86_64-pc-windows-msvc/release/mydriver.dll
```

To load the new build, run `sc stop mydriver` and then `sc start mydriver`. Stopping the driver needs a `DriverUnload` routine. The guest also writes the new build over its own copy on disk. See [Driver replacement map](kdfiles.md).

## Symbols

`ntoseye` needs the private PDB of the driver, which is the PDB that the linker wrote next to the `.sys` file. Where it looks for the PDB depends on where you built the driver.

### PDB on the host

Add the build directory to the symbol path once in each session:

```text
.sympath+ /home/me/mydriver/target/x86_64-pc-windows-msvc/release
```

The PDB then loads when the driver loads, and {command}`lmv` `mydriver` shows it.

### PDB in the guest

If you built the driver in the guest after its last boot, you usually do not have to do anything. It is best to build the driver immediately before you load it.

If no symbol directory or symbol server has the PDB, `ntoseye` reads it from guest memory. Because the build wrote the PDB, Windows still keeps the file in its cache. The driver image records where the build wrote the PDB, so `ntoseye` finds the PDB at that path, uses it only if it matches the driver, and saves it to the host symbol cache for later sessions. When the driver loads, `ntoseye` shows a message:

```text
rebuilt C:\Users\me\source\repos\mydriver\x64\Debug\mydriver.pdb for mydriver.sys from guest memory
```

`ntoseye` does this automatically with the `gdb` backend, and with KD when KD reads memory from the host, which is the default. If KD reads memory through the target (`--memory-source kd`), it does this only when you run {command}`.reload` `mydriver`.

The build must be recent because `ntoseye` gets the PDB from the Windows file cache. A restart of the guest empties the cache, and over time the guest also takes back cache memory when it needs memory. The more time that passes after the build, the more likely it is that pages are missing.

If the guest restarted after the build, or if much time passed, rebuild the driver before you load it, or read the PDB once in the guest (`Get-FileHash mydriver.pdb`) to put it back into the cache. If the PDB is still missing, {command}`lmv` `mydriver` shows the reason, and you can copy the PDB to the host and use `.sympath+` as shown above.

For more information, see [Symbols and source](symbols.md). To turn off this feature, use `--no-pdb-from-memory`.

### Source files

A PDB records the source paths from the time of the build, and {command}`.srcpath` maps these paths to a checkout on the host by path suffix. For example, the guest path `C:\Users\me\source\repos\mydriver\mydriver.c` finds `/home/me/mydriver/mydriver.c`:

```text
.srcpath /home/me/mydriver
```

If you edited a file after the build, `ntoseye` reports that the file is not the compiled source and does not show it with incorrect lines.

A mapping `<recorded-prefix>=<local-root>` replaces the prefix that the PDB records and does not use suffix matching. You usually do not need one, but use a mapping if suffix matching can find the wrong file in a checkout, which can occur when two files under the root end in the same path:

```text
.srcpath C:\Users\me\source\repos\mydriver=/home/me/mydriver
```

## Stop in the driver

Set the breakpoint before you load the driver:

```text
bu mydriver!DriverEntry
```

The breakpoint stays deferred until the module loads, and `ntoseye` then arms it before `DriverEntry` runs, on both the KD and GDB backends. To stop when the driver loads, before you select breakpoints, use {command}`sxe` `ld:mydriver`, and to stop when it unloads, after its unload routine, use {command}`sxe` `ud:mydriver`.

The names come from the PDB, and C++ templates and Rust generics are part of the name, for example `bp mydriver!mydriver::impl$0::tally<u32>`. rustc writes paths in MSVC style:

- Paths: `crate::module::function`
- Impl blocks: `impl$N`
- Closures: `closure_env$N`

To list these names, use {command}`x` `mydriver!*`, and to set breakpoints on the code among them, use {command}`bm`.

## When it crashes

A bugcheck stops the session at the crash and shows the faulting frame and `!analyze`. See [Bugchecks](bugchecks.md).

For the framework state and the In-Flight Recorder log of a KMDF driver, see [KMDF drivers](kmdf.md). `ntoseye` formats WPP messages with the private PDB. See [Symbols](symbols.md).

With VBS on, KD cannot write breakpoints into user-mode code, so use hardware breakpoints (`ba e1`) to debug a user-mode client of the driver. See [Troubleshooting](../get-started/troubleshooting.md#breakpoints-and-stepping).
