# Virtio devices (`!virtio`, `!vring`)

{command}`!virtio` lists the guest's virtio devices and shows how far each of their virtqueues has got, and {command}`!vring` shows one queue's buffers. They help when a paravirtual driver stops making progress: a queue tells you whether the device or the driver is holding things up.

## Devices

{command}`!virtio` without an argument lists the virtio PCI functions that pci.sys knows, with the device type and the service that drives each. It reads only guest memory, so it works on every backend, including the `memory` backend and crash dumps.

```text
04:00.0  console  1af4:1043  VirtioSerial  pdo 0xffffc888430f3060
  no queues: vioser's symbols have no virtio_device type; the driver's private PDB has it (.sympath+ <build directory>)

05:00.0  balloon  1af4:1045  BALLOON  pdo 0xffffc888430f4060
  virtio_device ffffc888439ee608 (balloon), split rings
  #  Size  Avail  Used  Driver  Free  State              virtqueue
  0  128   0      0     0       128   idle               ffffc88843c229f0
  1  128   0      0     0       128   idle               ffffc88843c23010
  2  128   1      0     0       127   1 with the device  ffffc88843c23520
```

For the queues, `ntoseye` needs the driver's private PDB. The drivers of the virtio-win project share the VirtIO library, and its structures (`virtio_device`, `virtqueue_split`) are in each driver's private PDB but not in a public one. Add the directory of your build output to the symbol path, for example with `--sympath-append` at the start or {command}`.sympath+` in the REPL. See [Symbols and source](symbols.md).

`ntoseye` finds the device's `virtio_device` in the context of the WDFDEVICE that the driver created for the device, as {command}`!wdfkd.wdfhandle` shows it. It looks in the context and in the structures the context embeds, and follows a pointer to a `virtio_device` too.

## Reading a queue

Each queue row shows these values:

| Column | Meaning |
| --- | --- |
| Size | The number of descriptors in the ring. |
| Avail | The avail index that the driver published to the device. |
| Used | The used index up to which the device returned buffers. |
| Driver | The used index up to which the driver took buffers back (`last_used`). |
| Free | The descriptors that the driver has not given out (`num_unused`). |
| State | What these indexes mean together. |

The state lists what is outstanding:

- **with the device**: buffers that the driver published and the device has not returned yet. A device may hold buffers on purpose: a receive queue or the balloon's statistics queue keeps buffers until it has something to put in them. A transmit or request queue whose count stays the same points to the device side, in QEMU.
- **returned, not yet taken back**: buffers that the device returned that the driver has not processed. If this count stays the same, the driver's interrupt or DPC did not run, or the driver turned off interrupts and did not poll.
- **added, not yet published**: buffers that the driver added that the device cannot see yet.
- **not kicked**: buffers that the driver added without notifying the device.

To see whether a queue moves, run the command again after the target ran for a while.

## A queue's buffers

{command}`!vring` `<virtqueue>` shows the ring addresses, the flags that turn off interrupts or notifications, the indexes, and each buffer that the device holds, with its descriptor chain:

```text
virtqueue ffffc88843c23520  queue 2  size 128
  desc ffffa200c8e8c000  avail ffffa200c8e8c800  used ffffa200c8e8c940
  avail idx 1  used idx 0  driver: published 1  taken back to 0  127 free  0 not kicked
  state: 1 with the device

Buffers with the device
  avail[0] head 0: [0] 0x27fff0000 len 0x64 -
```

Each descriptor shows its guest-physical address, its length, and its flags: `W` for a buffer that the device writes, `N` for a buffer that continues in the next descriptor, and `I` for a table of indirect descriptors. To read a buffer, use the physical-memory commands, for example `!db 27fff0000`.

To use {command}`!vring` with a driver that has no PDB, give the ring's size and the kernel addresses of its descriptor table, avail ring, and used ring with `/r`:

```text
!vring /r 0n128 ffffa200c8e8c000 ffffa200c8e8c800 ffffa200c8e8c940
```

The commands decode split rings. For a device that negotiated packed rings, {command}`!virtio` shows each queue's size, free descriptors, and the driver's last used index, but not the ring.
