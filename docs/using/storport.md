# StorPort adapters (`!storagekd.storadapter`, `!storagekd.storunit`)

{command}`!storagekd.storadapter` lists the adapters of StorPort miniports, such as the virtio-win drivers viostor and vioscsi, storahci, and stornvme, and shows one adapter with its units. {command}`!storagekd.storunit` shows one unit: its queue and each request that the miniport holds. They help when a storage miniport stops completing requests: the commands show whether a request is with the miniport, waits in StorPort, or waits because the queue is frozen, paused, or busy. The names are those of WinDbg's `storagekd` extension.

The commands read StorPort's own structures with the types in storport's public PDB, which `ntoseye` downloads like any other. They read only guest memory.

## Adapters

{command}`!storagekd.storadapter` without an argument shows one line per adapter:

```text
StorPort adapters (RaidpPortData ffffc88843055c10)
Driver    Adapter           FDO               State    Port               Location     Units  I/O
vhdmp     ffffc8884769d1a0  ffffc8884769d050  Working  \Device\RaidPort1  virtual      0      idle
storahci  ffffc8884314b1a0  ffffc8884314b050  Working  \Device\RaidPort0  PCI 00:1f.2  1      idle
```

StorPort keeps each driver that called `StorPortInitialize` on a list in its port data (`storport!RaidpPortData`), and each driver's adapters on that driver's extension, so the command finds the adapters of every miniport. Each line shows the miniport driver, the adapter extension (`_RAID_ADAPTER_EXTENSION`), the FDO that StorPort created for the device, the PnP state, the port's device name, the location (a PCI bus, device, and function, or `virtual` for a virtual miniport), the number of units, and the I/O state of the adapter. A driver without adapters is named below the table.

Windows also loads a copy of the boot disk's miniport and of a small port driver for crash dumps and hibernation, for example `dump_storahci` and `dump_storport`. These run only when Windows writes a crash dump or a hibernation file, keep their own state, and are not on StorPort's lists, so the commands do not show them. Adapters of StorPort's built-in NVMe support (`NvmeAdapterObject`) are named with a note, because their layout is different.

## One adapter

Give the adapter extension or the FDO to see the adapter and its units:

```text
!storagekd.storadapter ffffc8884314b1a0
Adapter              ffffc8884314b1a0  storahci  \Device\RaidPort0 (port 0)
Driver               storahci  DRIVER_OBJECT ffffc88843122350  _RAID_DRIVER_EXTENSION ffffc8884306ad20
State                Working
Power                D0, system Working
Device objects       FDO ffffc8884314b050  PDO ffffc88843089360  lower ffffc88843043de0
Location             PCI 00:1f.2
Adapter ID           PCI\VEN_8086&DEV_2922&SUBSYS_11001AF4&REV_02
Miniport extension   ffffc8884314fac0  (0x2d0 bytes)
Unit extension size  0x0 bytes
Paths                paging 4, crash dump 1, hibernation 0
Flags                InitializedMiniport WmiMiniPortInitialized WmiInitialized IdlePowerManagementEnabled BootAdapter InterruptsEnabled D3ColdAllowed DumpActiveNotCapable ProtocolCommandEffectsPendingUpdate FindAdapterCalled EtwEnabled AdapterInterfaceTypeInitialized
I/O                  idle  (pause count 0, busy count 0)
Gateway              ffffc8884313ce80  outstanding 0 of 31, waiting 0, busy 0, paused 0

Units
B/T/L  Unit              PDO               State    Product        I/O
0/0/0  ffffc888431531a0  ffffc88843153050  Working  QEMU HARDDISK  idle
```

**Miniport extension** is your driver's own device extension, the `HwDeviceExtension` that StorPort passes to `HwFindAdapter`, `HwStartIo`, `HwInterrupt`, and every other Hw routine. Its size is the `DeviceExtensionSize` that the driver gave in `HW_INITIALIZATION_DATA`. To read it, add your driver's private PDB to the symbol path (see [Symbols and source](symbols.md)) and use {command}`dt` with the type of your extension, for example `dt <driver>!<extension type> ffffc8884314fac0`. **Unit extension size** is the `SpecificLuExtensionSize` that the driver asked for.

**Paths** shows StorPort's counts of the device usage notifications that it received for the adapter. A count that is not zero means that a disk on the adapter holds a paging file, the crash dump, or the hibernation file. **Flags** are the bits that StorPort sets for the adapter (`_FLAGS` and `_FLAGS2` in its PDB).

StorPort passes requests to the miniport through an I/O gateway, which lets through at most a set number of requests at a time. **Gateway** shows how many requests the miniport holds, out of that maximum, how many wait for the gateway, and the gateway's busy and pause counts. The pause and busy counts on the **I/O** line are those of the adapter. They are not zero while the adapter is held back, as when the miniport pauses it (`StorPortPause`) or reports it busy (`StorPortBusy`).

Each unit line shows the unit's SCSI address as bus/target/LUN, the unit extension (`_RAID_UNIT_EXTENSION`), the PDO that StorPort created for it, its PnP state, the vendor and product from its inquiry data, and its I/O state.

## One unit

Give a unit extension, as {command}`!storagekd.storadapter` lists it, or the unit's PDO. This sample was taken with the guest stopped at a breakpoint in storahci's `HwStartIo` routine (`g storahci!AhciHwStartIo`), so one request is with the miniport:

```text
!storagekd.storunit ffffc888431531a0
Unit                 ffffc888431531a0  QEMU HARDDISK  2.5+
Address              bus 0, target 0, LUN 0
Adapter              ffffc8884314b1a0
Device object        ffffc88843153050
State                Working
Power                D0
Miniport extension   none
Flags                DeviceClaimed Enumerated Present WmiInitialized DeviceInitialized DumpActiveNotCapable RegisteredForPoFx BootUnit SupportsAtaInformation
Queue                depth 31 (unit maximum 186)
Counts               pause 0, busy 0, bypass 0, waiting 0, waiting to bypass 0
I/O                  1 with the miniport

Requests with the miniport
XRB               IRP               SRB               CPU
ffffa200b60a5030  ffffc888502c6de0  ffffa200b60a7f60  1
```

**Miniport extension** is the unit's extension that `StorPortGetLogicalUnit` returns, or `none` when the driver asked for no unit extension.

**Queue** shows the unit's device queue: its depth, which is how many requests StorPort lets the miniport hold for the unit, and the largest depth the unit allows. It also names the states that hold the queue: `Frozen` after an error, until the class driver releases the queue, and `Locked` while the class driver has locked it. **Counts** shows the unit's pause and busy counts, which are not zero while the miniport pauses the unit (`StorPortPauseDevice`) or reports it busy (`StorPortDeviceBusy`), the requests that bypass the queue, and the requests that wait in StorPort because the queue is full or held.

**Requests with the miniport** lists each request that StorPort handed to the miniport and that the miniport has not completed yet. StorPort keeps these on per-processor pending queues to time them out. Each row shows StorPort's request block (`_EXTENDED_REQUEST_BLOCK`), the IRP, which you can read with {command}`!irp`, the SRB that your `HwStartIo` routine received, and the processor whose queue holds the request. In the sample, the SRB is the one that storahci's `HwStartIo` received in `rdx`.

## Reading the I/O state

The I/O column and line say what holds the requests of an adapter or unit:

- **idle**: the miniport holds no requests, and none wait.
- **with the miniport**: requests that the miniport received and has not completed. If the same requests stay listed after the guest ran for a while, the miniport did not complete them, for example because the device did not interrupt or the driver did not call `StorPortNotification` with `RequestComplete`.
- **waiting**: requests that StorPort holds back because the queue or gateway is full, or held by one of the states below.
- **frozen**, **locked**, **paused**, **busy**: the states that hold the queue.

To see whether requests move, run the command again after the target ran for a while.
