<img align="right" width="28%" src="media/ntoseye.png">

# ntoseye ![license](https://img.shields.io/badge/license-MIT-blue)

Windows kernel debugger for Linux hosts running Windows under KVM/QEMU.

## Features

- Command line interface
- WinDbg style commands
- Kernel debugging
- PDB fetching
- Breakpointing
- Scripting API (Lua)

### Supported Windows

`ntoseye` currently only supports Windows 10 and 11 guests.

### Disclaimer

`ntoseye` will ask you if you wish to download symbols (defaults to exports if user declines). It will only download symbols from Microsoft's official symbol server. All files which will be read/written to will be located in `$XDG_CONFIG_HOME/ntoseye`.

# Getting started

## Dependencies

| Name | Version |
| ---- | ------- |
| [CMake](https://cmake.org/) | 3.5+ |
| [GCC](https://gcc.gnu.org/) | 14+ |
| [GDB](https://www.sourceware.org/gdb/) | Latest |
| [libreadline](www.gnu.org/software/readline/) | Latest |
| [Zydis](https://github.com/zyantific/zydis) | Latest |
| [LLVM](https://llvm.org/) | 15+ |
| [Lua](https://www.lua.org/) | 5.3+ |
| [sol2](https://github.com/ThePhD/sol2) | Latest |
| [curl](https://curl.se/) | Latest |

## Building

```bash
git clone https://github.com/dmaivel/ntoseye.git
cd ntoseye
mkdir build
cd build
cmake ..
cmake --build . --config Release
```

# Usage

`ntoseye` takes in no arguments to launch. It is recommended that you run the following command before running `ntoseye` or a VM:
```bash
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope 
```

Note that you may need to run `ntoseye` with `sudo` aswell.

## VM configuration

Although it is not required, many features depend on `gdbstub` being enabled.

#### QEMU

Append `-s -S` to qemu command.

#### virt-manager

Add the following to the XML configuration:
```xml
<domain xmlns:qemu="http://libvirt.org/schemas/domain/qemu/1.0" type="kvm">
  ...
  <qemu:commandline>
    <qemu:arg value="-s"/>
    <qemu:arg value="-S"/>
  </qemu:commandline>
</domain>
```

## Keybinds

| Key(s) | Description |
| - | - |
| <kbd>tab</kbd> | Tab completion. Either lists all available commands or attempts to complete the currently typed out command. |
| <kbd>ctrl+C</kbd> | Attempt a breakpoint. Will terminate the debugger if in the middle of a download or hang. |

## Commands

| Command                           | Description                                                |
|-----------------------------------|------------------------------------------------------------|
| `!pte [VirtualAddress/Symbol]` | Display the page table entries of a given virtual address. |
| `!process 0 0` | Display a list of the current active processes. |
| `.process [/p /r] OR [AddressOfEPROCESS]` | Set the current process context. |
| `break` | Breakpoint. |
| `db [VirtualAddress/Symbol] [EndAddress/L<Count>]` | Display bytes at address. |
| `g` | Continue from breakpoint. |
| `lm` | List current modules. |
| `n [10 OR 16]` | Set radix. 16 by default. |
| `q` | Quit. |
| `r OR r [Register names]` | Display registers. |
| `reload_lua` | Reload lua scripts. |
| `u [VirtualAddress/Symbol] [EndAddress/L<Count>]` | Display disassembly at address. |
| `uf [VirtualAddress/Symbol] [EndAddress/L<Count>]` | Alias for `u` command. |
| `x [Module!Function]` | Display symbols matching the string. Accepts wildcard. |
| `~ OR ~ [ProcessorNumber]` | Display current processor number or set current processor. |
| `:[CallbackName] <Args>` | Call to Lua callback. |

## Lua API

For scripts to be visible to `ntoseye`, they need to be stored in `$XDG_CONFIG_HOME/ntoseye/scripts/`. This folder is create automatically when you run `ntoseye` for the first time.

There are a few example lua scripts provided in `./examples`. Documentation is not available yet.

## Credits

Functionality regarding initialization of guest information was written with the help of the following sources:

- [vmread](https://github.com/h33p/vmread)
- [pcileech](https://github.com/ufrisk/pcileech)