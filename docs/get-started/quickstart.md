# Quickstart

If you are using QEMU/KVM, VMware, or UTM, you can use `ntoseye configure` for easy setup. Otherwise, look at [KDNET](../setup/kdnet.md) instructions.

1. Power off the Windows VM.
2. Run `ntoseye configure` and select the hypervisor, virtual machine, and debugger backend. Note the `Run` command it prints.
3. Start the VM, run the printed guest setup commands in Administrator PowerShell, and reboot.
4. Run the command saved in step 2.

Run `ntoseye status` at any time to inspect configured transports, assigned guest ports, endpoints, and launch commands without changing a VM.

## Hypervisor setup

`ntoseye configure` handles automatic setup for supported libvirt, VMware Workstation, and UTM guests. For plain QEMU or manual configuration, see the [KVM/QEMU](../setup/kvm-qemu.md), [VMware](../setup/vmware.md), and [UTM](../setup/utm.md) setup guides.

For any other target, follow the [KDNET guide](../setup/kdnet.md) instead; `configure` is not needed.

## Choosing a backend

See the [backend comparison table](../setup/backends.md).

## Finding your way around

Once attached, the [Tutorial](tutorial.md) walks through a first session. [`ntoseye --help`](../reference/command-line/index.md) lists the command-line arguments. In the REPL, tab completes commands, symbols, and types and describes each, and `.hh <command>` prints a command's help; the same text makes up the [command reference](../reference/commands/index.md). If something does not work, see [Troubleshooting](troubleshooting.md).
