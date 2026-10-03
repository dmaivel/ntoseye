# Quickstart

If you use QEMU/KVM, VMware, or UTM, `ntoseye configure` gives you an easy setup. For other targets, use the [KDNET](../setup/kdnet.md) instructions.

1. Power off the Windows VM.
2. Run `ntoseye configure` and select the hypervisor, the virtual machine, and the debugger backend. Write down the `Run` command that it shows.
3. Start the VM.
4. In the guest, open PowerShell as Administrator, run the guest setup commands that `ntoseye configure` showed, and restart the guest.
5. Run the `Run` command from step 2.

To see the current configuration, run `ntoseye status`. You can run it at any time without changing a VM, and it shows the configured transports, the assigned guest ports, the endpoints, and the launch commands.

## Hypervisor setup

`ntoseye configure` sets up supported libvirt, VMware Workstation, and UTM guests automatically. For plain QEMU or for manual configuration, see the [KVM/QEMU](../setup/kvm-qemu.md), [VMware](../setup/vmware.md), and [UTM](../setup/utm.md) setup guides.

For all other targets, follow the [KDNET guide](../setup/kdnet.md), which does not need `configure`.

If the guest runs VBS and your work does not need it, turn off VBS before you debug drivers or the kernel. For more information, see [Should VBS be on?](../vbs/index.md#should-vbs-be-on)

## Choosing a backend

See the [backend comparison table](../setup/backends.md).

## Next steps

After ntoseye attaches, [Your first session](tutorial.md) shows what to do next, and [`ntoseye --help`](../reference/command-line/index.md) lists the command-line arguments.

In the REPL, press Tab to complete commands, symbols, and types, with a description of each item in the completion list. To show the help for a command, type `.hh <command>`. The [command reference](../reference/commands/index.md) contains the same help text.

If something does not work, see [Troubleshooting](troubleshooting.md).
