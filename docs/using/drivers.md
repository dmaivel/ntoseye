# Developing drivers from a Linux host

You can edit, build, load, and debug a driver from the Linux host that runs the Windows VM.

Some steps below serve files to the guest or load unsigned code. For these steps, the guest needs a configured kernel debugger: [KDNET](../setup/kdnet.md) or [KD over serial](../setup/kvm-qemu.md#kd-over-a-serial-socket). To debug a driver that already loads, the GDB stub is sufficient.

If the guest uses VBS, turn VBS off. Keep VBS on only if you test the driver with Memory integrity. See [Should VBS be on?](../platforms/vbs.md#should-vbs-be-on).

## Build

Build the driver on the machine that has the toolchain:

- **In the guest**: Use Visual Studio and the WDK, as on any Windows machine. The PDB stays in the guest. See [Symbols](#symbols).
- **On the host**: Use this option for a driver that does not need the WDK headers or the WDK libraries. A `no_std` Rust driver with no imports links with `rust-lld`:

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

  The crate also needs `crate-type = ["cdylib"]` and `panic = "abort"`. The output is a `.dll` file. Copy or serve this file with the `.sys` name of the driver.

  A driver built on [windows-drivers-rs](https://github.com/microsoft/windows-drivers-rs) links against the WDK. We did not test this type of driver from a Linux host.

## Load

Register the driver one time in the guest:

```text
sc create mydriver type= kernel start= demand binPath= C:\drivers\mydriver.sys
```

Windows does not load an unsigned driver, and gives `StartService` error 577. Windows loads an unsigned driver only in these conditions:

- Test signing is on. To turn it on, run `bcdedit /set testsigning on`, then restart the guest.
- A kernel debugger is attached.

If an `ntoseye` KD session is attached, `sc start mydriver` loads the driver.

Over KD, {command}`.kdfiles` makes the guest get the image from the host each time the driver loads. So after you rebuild the driver on the host, you do not have to copy it into the guest:

```text
.kdfiles -m mydriver.sys /home/me/mydriver/target/x86_64-pc-windows-msvc/release/mydriver.dll
```

To load the new build, do these steps:

1. Run `sc stop mydriver`. For this step, the driver must have a `DriverUnload` routine.
2. Run `sc start mydriver`.

The guest also writes the new build over its own copy on disk. See [Driver replacement map](kdfiles.md).

## Symbols

`ntoseye` needs the private PDB of the driver. This is the PDB that the linker wrote next to the `.sys` file. The location where `ntoseye` looks for the PDB depends on where you built the driver.

### PDB on the host

Add the build directory to the symbol path. Do this one time in each session:

```text
.sympath+ /home/me/mydriver/target/x86_64-pc-windows-msvc/release
```

The PDB loads when the driver loads. {command}`lmv` `mydriver` shows the PDB.

### PDB in the guest

Usually you do not have to do anything. This is true if you built the driver in the guest after the last boot of the guest. It is best to build the driver immediately before you load it.

If no symbol directory or symbol server has the PDB, `ntoseye` reads the PDB from the guest memory. The build wrote the PDB, so Windows still keeps the file in its cache. The driver image records the location where the build wrote the PDB. `ntoseye` then does these steps:

1. It finds the PDB at the path that the driver image records.
2. It uses the PDB only if the PDB matches the driver.
3. It saves the PDB to the host symbol cache for later sessions.

When the driver loads, `ntoseye` shows a message:

```text
rebuilt C:\Users\me\source\repos\mydriver\x64\Debug\mydriver.pdb for mydriver.sys from guest memory
```

`ntoseye` does this automatically in these conditions:

- With the `gdb` backend.
- With KD, when KD reads memory from the host. This is the default.

If KD reads memory through the target (`--memory-source kd`), `ntoseye` does this only when you run {command}`.reload` `mydriver`.

The build must be recent because `ntoseye` gets the PDB from the Windows file cache. A restart of the guest empties the cache. Over time, the guest also takes back cache memory when it needs memory. So the more time since the build, the more likely it is that pages are missing.

If the guest restarted after the build, or if much time passed, rebuild the driver before you load it. Alternatively, read the PDB one time in the guest (`Get-FileHash mydriver.pdb`). This also puts the PDB back into the cache. If the PDB is still missing, {command}`lmv` `mydriver` shows the reason. In this case, copy the PDB to the host and use `.sympath+` as shown above.

For more information, see [Symbols and source](symbols.md). To turn off this feature, use `--no-pdb-from-memory`.

### Source files

A PDB records the source paths from the time of the build. {command}`.srcpath` maps these paths to a checkout on the host by path suffix. For example, the guest path `C:\Users\me\source\repos\mydriver\mydriver.c` finds `/home/me/mydriver/mydriver.c`:

```text
.srcpath /home/me/mydriver
```

If you edited a file after the build, `ntoseye` reports that the file is not the compiled source. `ntoseye` does not show the file with incorrect lines.

A mapping `<recorded-prefix>=<local-root>` replaces the prefix that the PDB records. A mapping does not use suffix matching. Usually you do not need a mapping. Use a mapping if suffix matching can find the wrong file in a checkout. This can occur if two files under the root end in the same path:

```text
.srcpath C:\Users\me\source\repos\mydriver=/home/me/mydriver
```

## Stop in the driver

Set the breakpoint before you load the driver:

```text
bu mydriver!DriverEntry
```

The breakpoint stays deferred until the module loads. When the module loads, `ntoseye` arms the breakpoint before `DriverEntry` runs. This is the same on the KD and GDB backends. To stop when the driver loads, before you select breakpoints, use {command}`sxe` `ld:mydriver`.

The names come from the PDB. C++ templates and Rust generics are part of the name, for example `bp mydriver!mydriver::impl$0::tally<u32>`. rustc writes paths in MSVC style:

- Paths: `crate::module::function`
- Impl blocks: `impl$N`
- Closures: `closure_env$N`

To list these names, use {command}`x` `mydriver!*`. To set breakpoints on the code among them, use {command}`bm`.

## When it crashes

A bugcheck stops the session at the crash. The stop shows the faulting frame and `!analyze`. See [Bugchecks](bugchecks.md).

For the framework state and the In-Flight Recorder log of a KMDF driver, see [KMDF drivers](kmdf.md). `ntoseye` formats WPP messages with the private PDB. See [Symbols](symbols.md).

With VBS on, KD cannot write breakpoints into user-mode code. So to debug a user-mode client of the driver, use hardware breakpoints (`ba e1`). See [Troubleshooting](../get-started/troubleshooting.md#breakpoints-and-stepping).
