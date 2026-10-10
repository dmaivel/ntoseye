# StorPort adapters (`!storagekd.*`)

{command}`!storagekd.storadapter` lists the adapters of StorPort miniports, such as the virtio-win drivers viostor and vioscsi, storahci, and stornvme, and shows one adapter with its units. {command}`!storagekd.storunit` shows one unit: its queue and each request that the miniport holds. They help when a storage miniport stops completing requests: the commands show whether a request is with the miniport, waits in StorPort, or waits because the queue is frozen, paused, or busy. {command}`!storagekd.storloglist` shows the history behind that state from StorPort's own log of each adapter, {command}`!storagekd.storsrb` decodes a request's SRB, and {command}`!storagekd.storclass` shows the disks and other class devices above the miniport. The names are those of WinDbg's `storagekd` extension.

The commands read StorPort's and classpnp's own structures with the types in their public PDBs, which `ntoseye` downloads like any other. They read only guest memory.

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
!storagekd.storunit ffffa08e681511a0
Unit                 ffffa08e681511a0  QEMU HARDDISK  2.5+
Address              bus 0, target 0, LUN 0
Adapter              ffffa08e6814a1a0
Device object        ffffa08e68151050
State                Working
Power                D0
Miniport extension   none
Flags                DeviceClaimed Enumerated Present WmiInitialized DeviceInitialized DumpActiveNotCapable RegisteredForPoFx BootUnit SupportsAtaInformation
Queue                depth 31 (unit maximum 186)
Counts               pause 0, busy 0, bypass 0, waiting 0, waiting to bypass 0
I/O                  1 with the miniport

Requests with the miniport
XRB               IRP               SRB               CPU  Command
ffffb3012c4d2030  ffffa08e727eede0  ffffb3012c4d4f60  1    WRITE(10) LBA 0x64b500, 8 blocks
```

**Miniport extension** is the unit's extension that `StorPortGetLogicalUnit` returns, or `none` when the driver asked for no unit extension.

**Queue** shows the unit's device queue: its depth, which is how many requests StorPort lets the miniport hold for the unit, and the largest depth the unit allows. It also names the states that hold the queue: `Frozen` after an error, until the class driver releases the queue, and `Locked` while the class driver has locked it. **Counts** shows the unit's pause and busy counts, which are not zero while the miniport pauses the unit (`StorPortPauseDevice`) or reports it busy (`StorPortDeviceBusy`), the requests that bypass the queue, and the requests that wait in StorPort because the queue is full or held.

**Requests with the miniport** lists each request that StorPort handed to the miniport and that the miniport has not completed yet. StorPort keeps these on per-processor pending queues to time them out. Each row shows StorPort's request block (`_EXTENDED_REQUEST_BLOCK`), the IRP, which you can read with {command}`!irp`, the SRB that your `HwStartIo` routine received, which {command}`!storagekd.storsrb` decodes, the processor whose queue holds the request, and the command its CDB holds. In the sample, the SRB is the one that storahci's `HwStartIo` received in `rdx`.

## Reading the I/O state

The I/O column and line say what holds the requests of an adapter or unit:

- **idle**: the miniport holds no requests, and none wait.
- **with the miniport**: requests that the miniport received and has not completed. If the same requests stay listed after the guest ran for a while, the miniport did not complete them, for example because the device did not interrupt or the driver did not call `StorPortNotification` with `RequestComplete`.
- **waiting**: requests that StorPort holds back because the queue or gateway is full, or held by one of the states below.
- **frozen**, **locked**, **paused**, **busy**: the states that hold the queue.

To see whether requests move, run the command again after the target ran for a while.

## The adapter's log

StorPort keeps a log of each adapter's last 256 events in its extension (`RaidLogList`): each request it builds, starts, and sees completed, pauses and resumes of the adapter and its units, busy and ready notifications, timeouts, resets, and PnP and power IRPs. {command}`!storagekd.storloglist` shows the last 50 entries of an adapter's log, given by its extension or FDO:

```text
StorPort log of adapter ffffa08e6814a1a0  storahci  (ring ffffa08e6814ba20, 256 entries, newest 0x1069b55)
Entry      Time (UTC)                   Event                Details
0x1069b50  2026-10-10 01:03:01.9123674  CallMiniportBuildIo  IRP ffffa08e6cd1d010 SRB ffffb3012c4a2f60 WRITE(10), SRB status PENDING
0x1069b51  2026-10-10 01:03:01.9123674  CallMiniportStartIo  IRP ffffa08e6cd1d010 SRB ffffb3012c4a2f60 WRITE(10), SRB status PENDING
0x1069b52  2026-10-10 01:03:01.9123674  MiniportCompletion   IRP ffffa08e6cd1d010 SRB ffffb3012c4a2f60 WRITE(10), SRB status SUCCESS
```

StorPort numbers the entries from 1 as it writes them, and the ring keeps the newest 256. `<start>` shows the entries from that number, `<start> <end>` that range, and `L <count>` how many. For the events of storport's request path (`CallMiniportBuildIo`, `CallMiniportStartIo`, `MiniportCompletion`), the details are the IRP, the SRB, the command's operation code, and the SRB status, which reads `PENDING` until the miniport completes the request. For any other event, they are the four parameters StorPort logged, each code address by its symbol.

A request whose `CallMiniportStartIo` entry has no `MiniportCompletion` after it is with the miniport, and a `PauseDevice` or `PauseAdapter` without its `Resume` is what holds a queue. {command}`!storagekd.storlogirp` and {command}`!storagekd.storlogsrb` show only the entries of one IRP or SRB:

```text
!storagekd.storlogirp ffffa08e6814a1a0 ffffa08e727eede0
```

## SRBs

{command}`!storagekd.storsrb` decodes an SRB, such as the one your `HwStartIo` routine receives, the SRB column of {command}`!storagekd.storunit`, or an SRB in the log:

```text
!storagekd.storsrb @rdx
SRB                  ffffb3012c4cff60  (STORAGE_REQUEST_BLOCK)
Function             EXECUTE_SCSI (0x0)
Status               SRB PENDING (0x00), SCSI GOOD
Command              WRITE(10) LBA 0x8f71948, 8 blocks  (CDB 2a 00 08 f7 19 48 00 00 08 00)
Address              port 0, path 0, target 0, LUN 0
Data                 0x1000 bytes, DataBuffer null
IRP                  ffffa08e732cade0
Flags                0x200382 (QUEUE_ACTION_ENABLE DATA_OUT NO_QUEUE_FREEZE ADAPTER_CACHE_ENABLE PORT_DRIVER_ALLOCSENSE)
Timeout              30 s
Tag                  0xa0, priority 2
Sense                255 bytes at ffffb3012c4cd3b0: not valid (no AUTOSENSE_VALID)
Contexts             class none, port ffffb3012c4cd030, miniport ffffb3012c4cd4b0
Next SRB             none

Extended data (2)
Address           Type       Length
ffffb3012c4cfff8  ScsiCdb16  0x20
ffffb3012c4d0020  IoInfo     0x18
```

This sample was taken at a breakpoint on `storahci!AhciHwStartIo`, whose second parameter is the SRB. The command takes the extended `STORAGE_REQUEST_BLOCK` that StorPort and classpnp use on Windows 8 and later, whose CDB, SCSI status, and sense buffer are in its extended data, and the legacy `SCSI_REQUEST_BLOCK`. The status shows `QUEUE_FROZEN` and `AUTOSENSE_VALID` after the SRB status, and the sense data is decoded only when `AUTOSENSE_VALID` says it is valid. An address whose `Function` and `Signature`, or `Length`, are not an SRB's is refused.

## Class devices

Above the miniport, classpnp.sys drives the disks, CD-ROMs, and other storage class devices for disk.sys and cdrom.sys. It sends each request down as a transfer packet, retries it on errors, and logs its last 16 errors. {command}`!storagekd.storclass` lists the class devices:

```text
FDO               Driver  Number  Bus   Product             Packets                     Notes
ffffa08e683b1060  disk    0       Sata  QEMU HARDDISK 2.5+  1 in flight, 34 free of 35  boot
```

With the address of an FDO, its device extension, or its private data, it shows the device, the requests in flight, and the error log:

```text
Class device         FDO ffffa08e683b1060  extension ffffa08e683b11b0  private data ffffa08e683c5040
Driver               disk, device number 0
Device               QEMU HARDDISK 2.5+  serial QM00001
Bus                  Sata, boot device
Lower devices        next ffffa08e68151050  PDO ffffa08e68151050
Capacity             128.0 GiB (0x2000000000 bytes), 512-byte sectors
Timeout              30 s, up to 4 retries
Error count          0
Transfer packets     1 in flight, 34 free of 35

Requests in flight
Packet            IRP               Client IRP        SRB               Command                            Status   Retries left
ffffa08e73a584c0  ffffa08e732cade0  ffffa08e747a2380  ffffa08e6ffef9f0  WRITE(10) LBA 0x8f71948, 8 blocks  PENDING  4

Error log (3, oldest first)
Age           P/T/L    Command                           SRB status                SCSI status      Sense                        Notes
3650.7 s ago  -/0/0/0  MODE SENSE(6) page 0x08           INVALID_REQUEST           GOOD
3650.7 s ago  -/0/0/0  MODE SENSE(6) page 0x08           INVALID_REQUEST           GOOD
2991.9 s ago  -/0/0/0  READ(10) LBA 0x547f820, 8 blocks  ABORTED, AUTOSENSE_VALID  CHECK CONDITION  sense ABORTED COMMAND 00/00  paging retried
```

A transfer packet is in flight when it is on none of classpnp's free lists: those of each NUMA node, those of each processor, and the one packet it keeps for forward progress. Each row shows the IRP that classpnp sent down, the client's IRP that the packet serves, the SRB with its command and status, and how many retries classpnp has left for it. A packet whose retries fell below the device's limit failed at least once.

The error log keeps classpnp's last 16 errors, each with its age from the guest's tick count, the port, path, target, and LUN (`-` for a port classpnp did not know), the command, the SRB and SCSI status, the sense key and additional sense code and qualifier, and whether the request was paging I/O, was retried, or went unhandled.

## From Python

`dbg.inspect` has one method for each command, and each method returns the decoded fields as typed records:

- `storport_adapters()` and `storport_adapter(address)` for {command}`!storagekd.storadapter`
- `storport_unit(address)` for {command}`!storagekd.storunit`
- `storport_log(address)` for {command}`!storagekd.storloglist`
- `srb(address)` for {command}`!storagekd.storsrb`
- `class_devices()` and `class_device(address)` for {command}`!storagekd.storclass`

An adapter's and a unit's `io` is the verdict of the I/O state column, such as `idle` or `1 with the miniport`. A log entry of the request path has its IRP, SRB, command, and SRB status as fields:

```python
for driver in dbg.inspect.storport_adapters().drivers:
    for entry in driver.adapters:
        if entry.adapter is None:
            continue
        for logged in dbg.inspect.storport_log(entry.extension).entries[-5:]:
            print(logged.number, logged.event, logged.command, logged.srb_status)
```
