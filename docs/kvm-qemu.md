# KVM/QEMU

Run `ntoseye configure` to configure a libvirt/virt-manager guest automatically. It preserves existing serial devices, uses the next free guest COM port, backs up the domain XML, and can remove ntoseye-managed transports later. The command prints guest instructions with the assigned debug port. For plain QEMU or manual configuration, follow the sections below.

## KD over a serial socket

Default backend. In the guest, enable kernel debugging (run as Administrator, then reboot):

```
bcdedit /debug on
bcdedit /dbgsettings serial debugport:1 baudrate:115200
```

Use `debugport:2` instead of `:1` if the KD chardev ends up as COM2 (see the virt-manager warning below).

Plain QEMU: add a Unix-socket chardev and route a serial port to it:

```
-chardev socket,id=kd,path=/tmp/ntoseye-kd.sock,server=on,wait=off -serial chardev:kd
```

Then connect: `ntoseye`.

> [!WARNING]
> virt-manager auto-adds a `<serial>` console device on every VM, which
> claims COM1. Either replace that device with one pointing at the KD socket
> (KD becomes COM1, use `debugport:1`), or leave it and add the KD chardev
> via `qemu:commandline` (KD becomes COM2, use `debugport:2`).

**Option A (recommended):** replace the auto-added serial. KD is COM1, `debugport:1` is correct.

```xml
<serial type="unix">
  <source mode="bind" path="/tmp/ntoseye-kd.sock"/>
  <target type="isa-serial" port="0"/>
</serial>
```

**Option B:** keep the auto-added serial and append the KD chardev via `qemu:commandline`. If KD is COM2, use `debugport:2`.

```xml
<domain xmlns:qemu="http://libvirt.org/schemas/domain/qemu/1.0" type="kvm">
  ...
  <qemu:commandline>
    <qemu:arg value="-chardev"/>
    <qemu:arg value="socket,id=kd,path=/tmp/ntoseye-kd.sock,server=on,wait=off"/>
    <qemu:arg value="-serial"/>
    <qemu:arg value="chardev:kd"/>
  </qemu:commandline>
</domain>
```

## KDNET

KDNET uses the guest's virtual NIC instead of a serial device. For a libvirt/QEMU VM using `<interface type="user">`, QEMU normally exposes the host to the guest as `10.0.2.2`; use that as the host address. For bridged networking, use the host's address on the bridged network.

QEMU/KVM guests must not report the default `Microsoft Hv` hypervisor vendor. KDNET interprets that identity as real Hyper-V and selects Hyper-V's synthetic debug device, which QEMU does not provide. Keep the Hyper-V enlightenments but add this child to the libvirt `<hyperv>` block:

```xml
<vendor_id state="on" value="KVMKVMKVM"/>
```

Power the VM completely off and start it again after changing the CPU identity; a Windows reboot does not recreate the QEMU CPU. See OSR's [QEMU/KVM KDNET analysis](https://www.osr.com/blog/2021/10/05/using-windbg-over-kdnet-on-qemu-kvm/). Then follow the [KDNET guide](kdnet.md) using the selected host address.

## GDB stub

Fallback backend for guests that are not configured for Windows KD. Expose QEMU's gdbstub on `127.0.0.1:1234`, then run with `--backend gdb`.

> [!NOTE]
> Do not enable kernel debug mode (`bcdedit /debug on`) in the guest when using the `gdb` backend. That setting is only for the `kd` backend, and the `gdb` backend's whole advantage is that the guest is unaware it is being debugged. With debug mode on, the kernel changes behavior (anti-debug code, PatchGuard) and expects a KD debugger to service breaks, while nothing on the GDB side answers the KD transport, so the guest can hang on `DbgBreakPoint` or exceptions. Leave debug mode off.

Plain QEMU: append `-s -S` to the qemu command.

virt-manager: add the following to the XML configuration:

```xml
<domain xmlns:qemu="http://libvirt.org/schemas/domain/qemu/1.0" type="kvm">
  ...
  <qemu:commandline>
    <qemu:arg value="-s"/>
    <qemu:arg value="-S"/>
  </qemu:commandline>
</domain>
```

## Memory introspection

No host or guest configuration needed; see [Choosing a backend](backends.md) for what the `memory` backend can and cannot do.

## Virtualization-based security (VTL1)

[Secure-kernel inspection](usage.md#secure-kernel-vtl1) needs VBS running in the guest, which needs nested virtualization (`vmx`) exposed to the VM. `msinfo32` in the guest reports whether VBS is running. Memory integrity (HVCI) is not required.

On the tested Core i9-14900F host with a Windows 11 guest, the guest's hypervisor failed to boot under `<cpu mode="host-passthrough"/>`. A custom Skylake model with `vmx` added works, keeping the existing Hyper-V enlightenments and CPU topology, with Secure Boot off:

```xml
<cpu mode="custom" match="exact">
  <model fallback="forbid">Skylake-Client-v4</model>
  <topology sockets="1" dies="1" cores="2" threads="2"/>  <!-- keep your existing topology -->
  <feature policy="require" name="vmx"/>
</cpu>
```

Plain QEMU: `-cpu Skylake-Client-v4,+vmx` plus the existing `hv_*` flags. Power the VM completely off and start it again after changing the CPU model. Other hosts may boot VBS with `host-passthrough`; this is only the configuration that was tested here.

The GDB backend can stop in loaded secure-kernel modules with nonpatching hardware execution breakpoints: `.vtl 1`, `ba e1 securekernel!SkeSelectProcessAddressSpace`, then `g`. Real VTL1 stops expose registers, stacks, disassembly, and memory through the stopped CPU's root; `.vtl` alone remains a memory selection. See [VTL1 usage](usage.md#secure-kernel-vtl1) for restrictions. Hardware execution breakpoints were also exercised at the running `hvix64` idle address, with repeated hits and continue. Use `~` and `vcpu` to select its register/address-space context, then `ba e1 <address>`; no software code patch is needed. These are linear-address breakpoints, not VTL-tagged breakpoints, and use the same four hardware slots across vCPUs.

Hyper-V's NT-side drivers use ordinary NT module/symbol inspection. The hypervisor itself has raw memory/register inspection and image-plus-offset stack labels, not structured partition or virtual-processor enumeration. Public symbols/unwind data are unavailable for the tested hypervisor build, so this does not provide full Hyper-V internals or reliable unwinding there. Single-stepping remains disabled under the Windows hypervisor, including at VTL1 stops.

Hardware breakpoints avoid integrity-sensitive code writes, but they are not invisible or side-effect-free. KVM owns the debug-register breakpoint state while host debugging is active. Upstream [nested VMX handling](https://github.com/torvalds/linux/blob/master/arch/x86/kvm/vmx/nested.c) documents an interaction that can lose L1's own DR7 state with `KVM_GUESTDBG_USE_HW_BP`; do not assume simultaneous guest/hypervisor hardware debugging preserves both debuggers' state. The tested guest remained responsive, including with HVCI enabled; other kernel/QEMU versions and hosts remain unverified.

With VBS running, the GDB stub reports what each vCPU was executing when it halted, and an idle vCPU is usually inside the Windows hypervisor itself, with its own CR3. `ntoseye` names such a stop by the image it is in: the context reads `hypervisor` (or `VTL1` for the secure kernel), and code and stack frames read `hvix64+0x…`. Microsoft publishes no symbols for this hypervisor build and its address space does not map its unwind data, so hypervisor frames past the first are stack-scan guesses (`[scan]`). QEMU plants kernel breakpoints through the selected vCPU's page tables, which do not map NT there. Its software breakpoints apply to every vCPU, so `ntoseye` retries such a breakpoint through another vCPU halted in NT. Only when every vCPU is outside NT does it borrow the NT kernel's page tables on the selected vCPU for that one packet, restoring the vCPU's CR3 immediately. Either way `bp` and the bugcheck trap work whichever address space the vCPU stopped in. If `ntoseye` were killed during that borrowed-CR3 packet, the vCPU would resume with the wrong CR3 and the guest would crash.

> [!IMPORTANT]
> While Windows runs its own hypervisor (VBS, Hyper-V, WSL2), the GDB backend does not single-step. Windows runs nested under that hypervisor, and a KVM single step of its vCPU can complete inside the hypervisor with the trap flag still set in Windows, which then takes the trap itself; with a kernel debugger configured, that froze the tested guest. `ntoseye` reads `nt!HvlHyperVRootPartition` to tell, then refuses single steps (`t`, `p` over anything but a call, `wt`, and the SDK's stepping calls; the `single_step` capability reads unsupported). It resumes from a breakpoint by running that vCPU alone, with the others held, to a temporary breakpoint on each place the instruction can continue at; a vCPU that has not got past it after 100 ms is usually waiting on a held one, and is then broken in on and resumed normally with the breakpoint armed again. Its instruction had not run yet, so when the vCPU returns to the site the same execution reports a second hit (1-2% of hits on hot kernel functions when stress-tested under VBS). Only a vCPU still on the site after the break-in fails the resume. Use the `kd` or `kdnet` backend to step these guests.
