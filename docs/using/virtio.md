# Virtio devices (`!virtio`, `!vring`)

{command}`!virtio` lists the guest's virtio devices and shows how far each of their virtqueues has got, and {command}`!vring` shows one queue's buffers. They help when a paravirtual driver stops making progress: a queue tells you whether the device or the driver is holding things up.

## Devices

{command}`!virtio` without an argument lists the virtio PCI functions that pci.sys knows, with the device type and the service that drives each. It reads only guest memory, so it works on every backend, including the `memory` backend and crash dumps.

```text
0a:00.0  net  1af4:1041  netkvm  pdo 0xffffc88844775060
  virtio_device ffffc8884cdf20f0 (netkvm), packed rings
  #  Size  Avail  Used  Driver  Free  State                virtqueue
  0  256   139    -     139     0     256 with the device  ffffc8884f8cf000
  1  256   18     -     18      256   idle                 ffffc888517f5000
  2  64    55     -     55      64    idle                 ffffc8884f1f5970

0b:00.0  block  1af4:1042  viostor  pdo 0xffffc888447164b0
  virtio_device ffffc88847d25010 (viostor), split rings
  #  Size  Avail  Used  Driver  Free  State                           virtqueue
  0  256   185    185   184     255   1 returned, not yet taken back  ffffa200d5425000
  1  256   244    244   244     256   idle                            ffffa200d54258c0
  2  256   133    133   133     256   idle                            ffffa200d5426180
  3  256   146    146   146     256   idle                            ffffa200d5426a40
```

For the queues, `ntoseye` needs the driver's private PDB. The drivers of the virtio-win project share the VirtIO library, and its structures (`virtio_device`, `virtqueue_split`, `virtqueue_packed`) are in each driver's private PDB but not in a public one. The virtio-win ISO has the PDB next to each driver, for example `NetKVM/w11/amd64/netkvm.pdb` and `viostor/w11/amd64/viostor.pdb`, and your own build writes it next to the `.sys` file. Add that directory to the symbol path with `--sympath-append` at the start or {command}`.sympath+` in the REPL. The PDB must come from the same build as the driver that runs. See [Symbols and source](symbols.md).

`ntoseye` finds the device's `virtio_device` in the state the driver keeps for the device:

- a KMDF driver (vioser, viosock, balloon, viofs, vioinput, viorng): the contexts of the WDFDEVICE that the driver created for the device, as {command}`!wdfkd.wdfhandle` shows them
- a StorPort miniport (viostor, vioscsi): the miniport's device extension, as {command}`!storagekd.storadapter` shows it
- an NDIS miniport (NetKVM): the adapter context, as {command}`!ndiskd.miniport` shows it

It accepts a `virtio_device` there, embedded or behind a pointer, when the device's queues point back at it, which the VirtIO library guarantees. So it does not depend on the names of the driver's own types.

## Reading a queue

Each queue row shows these values:

| Column | Split ring | Packed ring |
| --- | --- | --- |
| Size | The number of descriptors in the ring. | The same. |
| Avail | The avail index that the driver published to the device. | The position that the driver fills next. |
| Used | The used index up to which the device returned buffers. | `-`: the device does not publish one. |
| Driver | The used index up to which the driver took buffers back. | The position where the driver takes buffers back next. |
| Free | The descriptors that the driver has not given out. | The same. |
| State | What these mean together. | What the ring's descriptors say, read from the driver's position. |

The state lists what is outstanding:

- **with the device**: buffers that the driver gave the device and that the device has not returned yet. A device may hold buffers on purpose: a receive queue, an event queue, or the balloon's statistics queue keeps buffers until it has something to put in them. A transmit or request queue whose count stays the same points to the device side, in QEMU.
- **returned, not yet taken back**: buffers that the device returned that the driver has not processed. Right after an interrupt this is normal. If the count stays the same, the driver's interrupt or DPC did not run, or the driver turned off interrupts and did not poll.
- **added, not yet published** (split rings): buffers that the driver added that the device cannot see yet.
- **not kicked** (split rings): buffers that the driver added without notifying the device.

To see whether a queue moves, run the command again after the target ran for a while.

In the list, three or more queues in a row that no buffer has gone through since the driver set them up are one row, such as `8-63  128  0  -  0  -  never used (56 queues)` for the queues of virtio-serial's unopened ports. {command}`!virtio` with the device's address lists each of them.

## A queue's buffers

{command}`!vring` `<virtqueue>` shows the ring addresses, the flags that turn off interrupts or notifications, the indexes, each buffer that the device holds, and each buffer that it returned and the driver has not taken back, with their descriptor chains. This sample was taken with the guest stopped in vioscsi's interrupt routine, while it wrote to the disk:

```text
virtqueue ffffa200d65d4a40  queue 3  size 256
  desc ffffa200d65cd000  avail ffffa200d65ce000  used ffffa200d65ce240
  avail idx 313  used idx 313  driver: published 313  taken back to 312  255 free  0 not kicked
  state: 1 returned, not yet taken back

Returned, not yet taken back
  used[312] wrote 0x8406c head 1: [1] 0x278c565c8 len 0x30 I (3 descriptors, out 0x84033, in 0x6c)
```

Each descriptor shows its guest-physical address, its length, and its flags: `W` for a buffer that the device writes, `N` for a buffer that continues in the next descriptor, and `I` for a table of indirect descriptors. For an indirect descriptor, `!vring` reads the table and shows how many descriptors it has, how many bytes the driver gives the device (out), and how many the device can write (in). In the sample, the request is a 0x33-byte SCSI command and 0x84000 bytes of data, and the device's response has room for 0x6c bytes. A returned buffer also shows how many bytes the device wrote. To read a buffer, use the physical-memory commands, for example `!db 278c565c8`.

`ntoseye` finds the driver whose PDB describes a queue or device from the code and data it points to. To use a different module's PDB, name it after the address, for example `!vring ffffa200d65d4a40 vioscsi`.

### Packed rings

A device and driver can agree on packed rings instead of split rings, for example with `packed=on` on a QEMU virtio device. For a packed queue, {command}`!vring` shows the driver's positions and wrap counters, and walks the descriptors from the position where the driver takes buffers back next: first the buffers that the device used, then the buffers that it still holds.

```text
virtqueue ffffc8884f8cf000  queue 0  size 256  packed
  desc ffffa200d721b000  driver event ffffa200d721c000  device event ffffa200d721c004
  driver: next avail 140 (lap 0)  taken back to 140 (lap 1)  0 free
  state: 256 with the device

Buffers with the device
  [140] id 17 0x278a33000 len 0x10 I (1 descriptor, out 0x0, in 0x5fa)
  [141] id 123 0x2789c8000 len 0x10 I (1 descriptor, out 0x0, in 0x5fa)
```

Each line starts with the descriptor's position in the ring and the buffer ID. This is NetKVM's receive queue, so every descriptor is a buffer for one incoming frame.

### Without a PDB

To use {command}`!vring` with a split ring of a driver that has no PDB, give the ring's size and the kernel addresses of its descriptor table, avail ring, and used ring with `/r`:

```text
!vring /r 0n256 ffffa200d541d000 ffffa200d541e000 ffffa200d541e240
```

Without the driver's state, it cannot tell which buffers the driver has taken back.
