# VBS and the Windows hypervisor

When virtualization-based security (VBS), Hyper-V, WSL2, or Windows Sandbox runs, Windows starts its own hypervisor (`hvix64.exe` on Intel) beneath NT, which then runs as the hypervisor's root partition. With VBS, the hypervisor also runs a second kernel, the secure kernel, in Virtual Trust Level 1 (VTL1), and each Hyper-V VM, WSL2 instance, or Windows Sandbox is a guest partition. `ntoseye` reads all of them from the host:

- [The secure kernel (VTL1)](secure-kernel.md): its memory, modules, and trustlets, and breakpoints and steps in its code.
- [Partitions and virtual processors](partitions.md): the hypervisor's partitions and VPs, the page permissions that each VTL's EPT gives, each VTL's eVMCS and intercepts, and the registers of any VP.
- [Guest partitions](guest-partitions.md): the Windows guest of a partition, such as a Windows Sandbox, inspected with its own kernel's symbols, and the raw memory and code of any guest, such as WSL2.
- [Hypercalls and VM exits](hypercalls.md): the hypervisor's hypercall table, breakpoints on a hypercall or a VM exit from a given caller, and the decoded input of a hypercall.
- [Stops in the Windows hypervisor](hypervisor-stops.md): what a vCPU that halted in the hypervisor shows, its stack, and where NT left off on it.
- [VBS internals](internals.md): what `ntoseye` reads for each of these, and how it recognizes it.

For the NT-side drivers of Hyper-V, use the usual NT module and symbol inspection.

## Should VBS be on?

VBS can run only if the VM gives nested virtualization to the guest, which is the "Virtualize Intel VT-x/EPT" option in VMware and a CPU with `vmx` in KVM/QEMU. UTM under Apple's hypervisor does not have nested virtualization. Windows 11 turns on VBS by default when the hardware allows it, and Hyper-V or WSL2 in the guest also start the hypervisor. To see if VBS runs, use `msinfo32` in the guest.

If you debug drivers or the kernel, turn off VBS unless your work needs it, because it brings these limits:

- Windows does not allow KD to write to user-mode code, so a user-mode breakpoint over KD uses one of the four hardware slots ({command}`ba` `e1`).
- The `gdb` backend cannot single-step with the trap flag, so it runs the vCPU alone to the next instruction. Sometimes a step ends early, in an interrupt handler, in another thread, or on a watchpoint hit of another vCPU ([how](internals.md#stepping-without-the-trap-flag)).
- A vCPU can stop inside the Windows hypervisor, or while it runs a guest partition's VP (WSL2, a Hyper-V VM), where you cannot step until the guest resumes.

Keep VBS on when you:

- Research VBS, the secure kernel, or the hypervisor, which is what the rest of this section is about.
- Test a driver under Memory integrity (HVCI) before release, because a production driver must load when Memory integrity is on.
- Debug a problem that occurs only when VBS is on.

To turn off VBS:

1. In the guest, run this command from an elevated prompt:

   ```text
   bcdedit /set hypervisorlaunchtype off
   ```

2. Reboot the guest.

This stops the Windows hypervisor, so Hyper-V, WSL2, and Windows Sandbox in the guest also stop. To turn the hypervisor on again, run `bcdedit /set hypervisorlaunchtype auto` and reboot the guest.

:::{important}
The features in this section need an **AMD64 guest** and are not available on ARM64 guests. Support also depends on the host CPU:

| Feature | Backends | Intel host | AMD host |
| --- | --- | --- | --- |
| VTL1 memory, symbols, and {command}`!trustlets` | `memory`, `gdb`; `kd`/`kdnet` reading host memory | Supported | Untested |
| VTL1 breakpoints and stepping | `gdb` on QEMU/KVM | Supported | Untested |
| Stepping NT while the Windows hypervisor runs | `gdb` | Supported | Untested |
| [Where NT left off](hypervisor-stops.md#where-nt-left-off-under-the-hypervisor) under the hypervisor | `gdb` | Supported (needs `hv-evmcs`) | Not supported |
| [Hypervisor partitions, virtual processors, and VTL page permissions](partitions.md) | `memory`, `gdb`; `kd`/`kdnet` reading host memory | Supported (needs `hv-evmcs`, or a `gdb` vCPU stopped in the hypervisor) | Not supported |

We tested all of these features on one host, a Core i9-14900F with QEMU/KVM, with Windows 11 guests (10.0.26100 and 10.0.26200) and memory integrity (HVCI) both off and on.

VTL1 inspection is experimental. It finds undocumented secure-kernel structures by heuristics, so it can fail on other Windows builds. If ntoseye does not recognize a structure, it shows an error instead of the data.
:::
