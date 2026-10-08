# Virtio devices (`!virtio`, `!vring`)

{command}`!virtio` lists the guest's virtio devices and shows how far each of their virtqueues has got, and {command}`!vring` shows one queue's buffers. They help when a paravirtual driver stops making progress: a queue tells you whether the device or the driver is holding things up.

## Devices

{command}`!virtio` without an argument lists the virtio PCI functions that pci.sys knows, with the device type and the service that drives each. It reads only guest memory, so it works on every backend, including the `memory` backend and crash dumps. This sample was taken while the guest wrote to the virtio-blk disk:

```text
0a:00.0  net  1af4:1041  netkvm  pdo 0xffffa002d58e1060
  virtio_device ffffa002d481c0f0 (netkvm), packed rings, event index, MSI-X
  #  Queue    Size  Avail  Used  Driver  Free  Moved  State                virtqueue
  0  rx 0     256   80     -     80      0     +0/+0  256 with the device  ffffa002dc253000
  1  tx 0     256   175    -     175     256   +0/+0  idle                 ffffa002d1adb000
  2  control  64    36     -     36      64    +0/+0  idle                 ffffa002d87fb660

  Moved: positions filled/taken back since the last look, 10.1 s of guest time ago

0b:00.0  block  1af4:1042  viostor  pdo 0xffffa002d8df6060
  virtio_device ffffa002d7e8c010 (viostor), split rings, event index, MSI-X
  #  Queue      Size  Avail  Used  Driver  Free  Moved      State                           virtqueue
  0  request 0  256   2233   2233  2233    256   +215/+215  idle                            ffffb482a58cc000
  1  request 1  256   2194   2194  2193    255   +306/+306  1 returned, not yet taken back  ffffb482a58cc8c0
  2  request 2  256   1212   1212  1212    256   +120/+120  idle                            ffffb482a58cd180
  3  request 3  256   2105   2105  2105    256   +242/+242  idle                            ffffb482a58cda40

  Moved: avail/used since the last look, 10.1 s of guest time ago
```

The line under the function names the features that change how the queues work: packed or split rings, the event index, which lets each side say when it wants to be signalled, and MSI-X interrupts.

For the queues, `ntoseye` needs the driver's private PDB. The drivers of the virtio-win project share the VirtIO library, and its structures (`virtio_device`, `virtqueue_split`, `virtqueue_packed`) are in each driver's private PDB but not in a public one. The virtio-win ISO has the PDB next to each driver, for example `NetKVM/w11/amd64/netkvm.pdb` and `viostor/w11/amd64/viostor.pdb`, and your own build writes it next to the `.sys` file. Add that directory to the symbol path with `--sympath-append` at the start or {command}`.sympath+` in the REPL. The PDB must come from the same build as the driver that runs. See [Symbols and source](symbols.md).

`ntoseye` finds the device's `virtio_device` in the state the driver keeps for the device:

- a KMDF driver (vioser, viosock, balloon, viofs, vioinput, viorng): the contexts of the WDFDEVICE that the driver created for the device, as {command}`!wdfkd.wdfhandle` shows them
- a StorPort miniport (viostor, vioscsi): the miniport's device extension, as {command}`!storagekd.storadapter` shows it
- an NDIS miniport (NetKVM): the adapter context, as {command}`!ndiskd.miniport` shows it
- a display miniport (viogpudo): the device context that the driver gave dxgkrnl. dxgkrnl's own structures have no public types, so `ntoseye` recognizes the context by the driver's copy of its `DXGKRNL_INTERFACE`, which names the adapter's FDO.

It accepts a `virtio_device` there, embedded, behind a pointer, or embedded in a structure that a pointer names (as viogpudo keeps it in its adapter object), when the device's queues point back at it, which the VirtIO library guarantees. So it does not depend on the names of the driver's own types.

## Reading a queue

Each queue row shows these values:

| Column | Split ring | Packed ring |
| --- | --- | --- |
| Queue | What the queue is for, where the virtio specification fixes it: `rx 0`, `tx 0`, and `control` for a network device, `request 0` for a block device, `port 1 rx` for a serial device. | The same. |
| Size | The number of descriptors in the ring. | The same. |
| Avail | The avail index that the driver published to the device. | The position that the driver fills next. |
| Used | The used index up to which the device returned buffers. | `-`: the device does not publish one. |
| Driver | The used index up to which the driver took buffers back. | The position where the driver takes buffers back next. |
| Free | The descriptors that the driver has not given out. | The same. |
| Moved | What the driver published and the device returned since the last look. | The positions the driver filled and took back since the last look. |
| State | What these mean together. | What the ring's descriptors say, read from the driver's position. |

The state lists what is outstanding:

- **with the device**: buffers that the driver gave the device and that the device has not returned yet. A device may hold buffers on purpose: a receive queue, an event queue, or the balloon's statistics queue keeps buffers until it has something to put in them. A transmit or request queue whose count stays the same points to the device side, in QEMU.
- **returned, not yet taken back**: buffers that the device returned that the driver has not processed. Right after an interrupt this is normal. If the count stays the same, the driver's interrupt or DPC did not run, or the driver turned off interrupts and did not poll.
- **added, not yet published** (split rings): buffers that the driver added that the device cannot see yet.
- **not kicked** (split rings): buffers that the driver added without notifying the device.

In the list, three or more queues in a row that no buffer has gone through since the driver set them up are one row, such as `8-63  128  0  -  0  -  never used (56 queues)` for the queues of virtio-serial's unopened ports. {command}`!virtio` with the device's address lists each of them.

## Is it stuck?

`ntoseye` remembers what each look showed, so the next {command}`!virtio` or {command}`!vring` shows what moved since. The first look shows `-` in the Moved column. The time between looks is the guest's own time, which stops while the guest is stopped, so two looks at the same breakpoint show nothing moved and claim nothing.

From the second look on, the state also names what did not move:

- **not taken back for N s**: the device returned buffers before the last look, and the driver has not taken any back since. When an interrupt was due for them, the state adds that too, and the next place to look is the driver's interrupt routine and DPC.
- **the device returned nothing for N s**: on a queue that carries requests, such as a transmit, request, or control queue, the device held buffers at both looks and returned none in between. The next place to look is the device side, in QEMU. A receive or event queue holds buffers on purpose, so it is never named this way.

Let the guest run for a few seconds between the looks. The commands read a running guest, so with the guest running, two calls a few seconds apart are enough, over MCP too.

## A queue's buffers

{command}`!vring` `<virtqueue>` shows the ring addresses, the indexes, when each side wants to be signalled, what moved since the last look, each buffer that the device holds, and each buffer that it returned and the driver has not taken back, with their descriptor chains. This sample was taken with the guest stopped in viostor's interrupt routine while it wrote to the disk:

```text
virtqueue ffffb482a58cc000  queue 0 (request 0)  size 256
  desc ffffb482a58c4000  avail ffffb482a58c5000  used ffffb482a58c5240
  avail idx 527  used idx 527  driver: published 527  taken back to 526  255 free  0 not kicked
  interrupts: after used idx 526 (event index); one was due for the returned buffers
  notifications: after avail idx 527 (event index)
  state: 1 returned, not yet taken back
  moved since the last look 0.0 s of guest time ago: avail +0, used +0, taken back +0

Returned, not yet taken back
  used[526] wrote 0x1 head 2: [2] 0x279181528 len 0x490 I (73 descriptors, out 0x47010, in 0x1)
```

**interrupts** says when the driver wants the device to interrupt it, and **notifications** says when the device wants the driver to notify it (kick) about new buffers:

- `on`: after every buffer.
- `off`: never, because the side set the flag that turns signals off (`NO_INTERRUPT` or `NO_NOTIFY` on a split ring). A driver that turns interrupts off must poll the queue.
- `after used idx N` or `after avail idx N`: with the event index feature, once the other side's index passes N.
- `at position N in lap L`: on a packed ring, once the other side reaches that position.

For a split ring, `!vring` also checks the returned buffers against the driver's request, as the device does. In the sample, the driver asked for an interrupt after used index 526 and the device moved to 527, so an interrupt was due, and the guest is stopped in it. Buffers returned without an interrupt due, with interrupts on, point to a driver that did not ask for one.

Each descriptor shows its guest-physical address, its length, and its flags: `W` for a buffer that the device writes, `N` for a buffer that continues in the next descriptor, and `I` for a table of indirect descriptors. For an indirect descriptor, `!vring` reads the table and shows how many descriptors it has, how many bytes the driver gives the device (out), and how many the device can write (in). In the sample, the request is a write of 0x47000 bytes with its 0x10-byte header, and the device wrote its one-byte status. A returned buffer also shows how many bytes the device wrote. To read a buffer, use the physical-memory commands, for example `!db 279181528`.

`ntoseye` finds the driver whose PDB describes a queue or device from the code and data it points to. To use a different module's PDB, name it after the address, for example `!vring ffffb482a58cc000 viostor`.

### Packed rings

A device and driver can agree on packed rings instead of split rings, for example with `packed=on` on a QEMU virtio device. For a packed queue, {command}`!vring` shows the driver's positions and wrap counters, and walks the descriptors from the position where the driver takes buffers back next: first the buffers that the device used, then the buffers that it still holds.

```text
virtqueue ffffa002dc253000  queue 0 (rx 0)  size 256  packed
  desc ffffb482a542f000  driver event ffffb482a5430000  device event ffffb482a5430004
  driver: next avail 80 (lap 0)  taken back to 80 (lap 1)  0 free
  interrupts: at position 80 in lap 1
  notifications: off (the device disabled them)
  state: 256 with the device
  moved since the last look 0.1 s of guest time ago: filled +0, taken back +0

Buffers with the device
  [80] id 13 0x27991f000 len 0x10 I (1 descriptor, out 0x0, in 0x5fa)
  [81] id 67 0x278c0d000 len 0x10 I (1 descriptor, out 0x0, in 0x5fa)
```

Each buffer line starts with the descriptor's position in the ring and the buffer ID. This is NetKVM's receive queue, so every descriptor is a buffer for one incoming frame. The driver wants an interrupt when the device uses the position it takes back next, and the device, which holds a buffer in every slot, wants no notifications.

### Without a PDB

To use {command}`!vring` with a split ring of a driver that has no PDB, give the ring's size and the kernel addresses of its descriptor table, avail ring, and used ring with `/r`:

```text
!vring /r 0n256 ffffb482a58c4000 ffffb482a58c5000 ffffb482a58c5240
```

Without the driver's state, it cannot tell which buffers the driver has taken back, or name the queue.
