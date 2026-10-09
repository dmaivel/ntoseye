# KMDF drivers (`!wdfkd`)

The `!wdfkd.*` commands read the Kernel-Mode Driver Framework's own state from `Wdf01000.sys`, using the types in Microsoft's public `Wdf01000.pdb`. They need that module loaded with its PDB, which the symbol server supplies, but you do not need the private PDB of a driver. The commands do not support UMDF drivers.

| Command | Shows |
| --- | --- |
| {command}`!wdfkd.wdfldr` | All KMDF client drivers, with each driver's name, the KMDF version that it bound to, its `_FX_DRIVER_GLOBALS`, WDFDRIVER handle, and `DRIVER_OBJECT`, and whether it has an In-Flight Recorder (IFR) log. |
| {command}`!wdfkd.wdfdriverinfo` `<driver>` | One client driver and each of its device objects, with the WDFDEVICE for each device object. |
| {command}`!wdfkd.wdfhandle` `<handle>` | The object behind a handle: its type, size, reference count, state, owner, parent, and contexts. |
| {command}`!wdfkd.wdfdevice` `<WDFDEVICE>` | A device's WDM device objects, its PnP, power, and power policy states, and its queues. |
| {command}`!wdfkd.wdfqueue` `<WDFQUEUE>` | A queue's dispatch type, state, and callbacks, the requests that wait in it, and the requests that the driver owns. |
| {command}`!wdfkd.wdflogdump` `<driver>` | A driver's IFR log, with the oldest record first. |
| {command}`!wdfkd.wdfcrashdump` `[loader]` | In a crash dump, the IFR log that KMDF saved of one driver, or with `loader`, the client drivers that KMDF recorded. |

To name a driver, use the name that {command}`!wdfkd.wdfldr` shows. The name is not case-sensitive, and the commands ignore a trailing `.sys`.

A client whose `DriverName` is empty, because it bound to KMDF without creating an `FxDriver`, is listed and named by the name of its `DRIVER_OBJECT`. For example, the name for `\Driver\kdnic` is `kdnic`.

A typical walk starts at the driver list and follows the handles down:

```
!wdfkd.wdfldr
!wdfkd.wdfdriverinfo kmdfsample
!wdfkd.wdfdevice 00003ef5edcba988
!wdfkd.wdfqueue 00003ef5edcb1238
```

## Handles

A WDF handle is the address of its object XORed with `~7`.

A handle with bit 0 set is an offset handle, which points to a `WDFOBJECT_OFFSET` inside a larger object, such as the buffer of a request. The commands subtract this offset to get the larger object.

If you give the address of an object instead of its handle, the command gives an error that shows the handle of that object.

Before a command shows an object, it checks the object's `FxObject` header, and all of these conditions must be true:

- `m_Type` is an `FX_OBJECT_TYPES` value.
- `m_ObjectState` is an `FxObjectState` value.
- `m_ObjectSize` is aligned, and it is not smaller than the class of the type.
- The context header after the object points back to the object.
- `m_Globals` belongs to a registered client driver.

If a check fails, the command gives the reason and does not show the object. The same checks apply to each object that a command reaches through a list or a pointer. When one of these objects fails, the list ends at that object, and the output shows where and why.

The client driver list is an exception, because its integrity comes from its links: the Blink of each entry must point back to the entry before it. A client whose name or `FxDriver` fails the checks therefore stays in the list, and the list shows the problem.

## The In-Flight Recorder

For each client driver, KMDF writes its own trace messages to a small ring buffer called the IFR.

{command}`!wdfkd.wdflogdump` reads the IFR backward from the newest record and shows, for each record:

- the sequence number
- the UTC time, if the log keeps timestamps
- the function
- the message

The command formats the messages from the trace message format (TMF) annotations in `Wdf01000.pdb`, so you do not need `.tmf` files. If no loaded PDB declares the message of a record, the command shows the record's message GUID, number, and argument bytes instead.

The walk ends at the first record that KMDF wrote, or where newer records overwrote older ones. The command checks the header and each record as it reads them:

- the signature
- the length
- the position
- the sequence numbers, which must decrease

If a check fails, the walk stops and reports the corruption, but keeps the records that it already read.

## In a crash dump

When Windows writes a crash dump, KMDF adds two blocks of its own to the dump's [tagged data](dumps.md#tagged-data-and-blackboxes). One is a copy of a single client driver's IFR log. KMDF picks the driver whose code the bugcheck parameters point to, or a driver that is set to keep its log in minidumps. If there is no such driver, it picks the last KMDF driver that ran on the processor that crashed. A minidump holds no other copy of an IFR log.

{command}`!wdfkd.wdfcrashdump` shows that log in the same way that {command}`!wdfkd.wdflogdump` shows a log in memory, with the same checks:

```text
IFR log of wtd (IFR header ffff9888a1377000, 0xfb8 bytes, sequence 1, timestamps)
1: 2026-10-06 06:43:00.2720777 FxIFRStart - FxIFR logging started
(1 records; reached the first record written)
```

The records are the ones that WinDbg's `!wdfkd.wdfcrashdump` shows, with two exceptions where WinDbg's walk is wrong. WinDbg shows a log's only record twice, and it leaves out the oldest record that survives in a log that has wrapped. The times are in UTC, while WinDbg shows them in the local time of the computer that runs it.

{command}`analyze` names the driver whose log the dump holds, so you know to look:

```text
KMDF log
  wtd's In-Flight Recorder log, 1 record  (!wdfkd.wdfcrashdump)
```

The other block lists the client drivers, with the KMDF version that each one bound to and its `_FX_DRIVER_GLOBALS`. `!wdfkd.wdfcrashdump loader` shows the list, and the first entry is KMDF itself. These are the first lines of the list from a Windows 11 guest:

```text
ImageName              Version      FxGlobals
Wdf01000               v1.35(0000)
PRM                    v1.15(0000)  ffff9888994e5750
acpiex                 v1.15(0000)  ffff988899cf0240
```

The command needs `Wdf01000.pdb`. `ntoseye` loads it when the dump opens, in a minidump as in a kernel dump.

## From Python

`dbg.inspect` has one method for each command, and each method returns the decoded fields as typed records:

- `wdf_loader()` for {command}`!wdfkd.wdfldr`
- `wdf_driver_info(driver)` for {command}`!wdfkd.wdfdriverinfo`
- `wdf_handle(handle)` for {command}`!wdfkd.wdfhandle`
- `wdf_device(handle)` for {command}`!wdfkd.wdfdevice`
- `wdf_queue(handle)` for {command}`!wdfkd.wdfqueue`
- `wdf_log(driver)` for {command}`!wdfkd.wdflogdump`
- `wdf_crash_log()` and `wdf_crash_drivers()` for {command}`!wdfkd.wdfcrashdump`

```python
for client in dbg.inspect.wdf_loader().clients:
    print(client.name, client.version)
for record in dbg.inspect.wdf_log("kmdfsample").records:
    print(record.sequence, record.function, record.text or record.error)
```
