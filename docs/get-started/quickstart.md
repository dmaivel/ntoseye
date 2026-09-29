# Quickstart

If you use QEMU/KVM, VMware, or UTM, use `ntoseye configure` for an easy setup. For other targets, use the [KDNET](../setup/kdnet.md) instructions.

1. Power off the Windows VM.
2. Run `ntoseye configure`. Select the hypervisor, the virtual machine, and the debugger backend.
3. Write down the `Run` command that `ntoseye configure` shows.
4. Start the VM.
5. In the guest, open PowerShell as Administrator. Run the guest setup commands that `ntoseye configure` shows.
6. Restart the guest.
7. Run the `Run` command from step 3.

To see the current configuration, run `ntoseye status`. You can run it at any time, and it does not change a VM. It shows these items:

- the configured transports
- the assigned guest ports
- the endpoints
- the launch commands

## Hypervisor setup

`ntoseye configure` sets up supported libvirt, VMware Workstation, and UTM guests automatically. For plain QEMU or for manual configuration, see these setup guides:

- [KVM/QEMU](../setup/kvm-qemu.md)
- [VMware](../setup/vmware.md)
- [UTM](../setup/utm.md)

For all other targets, follow the [KDNET guide](../setup/kdnet.md). These targets do not need `configure`.

If the guest runs VBS and your work does not need VBS, turn off VBS before you debug drivers or the kernel. For more information, see [Should VBS be on?](../platforms/vbs.md#should-vbs-be-on)

## Choosing a backend

See the [backend comparison table](../setup/backends.md).

## Next steps

After ntoseye attaches, go to [Your first session](tutorial.md) for the next steps.

[`ntoseye --help`](../reference/command-line/index.md) lists the command-line arguments.

In the REPL, you can use these help features:

- Press Tab to complete commands, symbols, and types. The completion list also shows a description of each item.
- Type `.hh <command>` to show the help for a command. The [command reference](../reference/commands/index.md) contains the same help text.

If something does not work, see [Troubleshooting](troubleshooting.md).
