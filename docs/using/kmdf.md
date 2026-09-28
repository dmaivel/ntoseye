# KMDF drivers (`!wdfkd`)

The `!wdfkd.*` commands read the Kernel-Mode Driver Framework's own state out of `Wdf01000.sys`, with the types in Microsoft's public `Wdf01000.pdb`. They need that module loaded with its PDB, which the symbol server provides; a driver's private PDB is not needed. UMDF drivers are not covered.

| Command | Shows |
| --- | --- |
| {command}`!wdfkd.wdfldr` | Every KMDF client driver: name, the KMDF version it bound to, its `_FX_DRIVER_GLOBALS`, WDFDRIVER handle, and `DRIVER_OBJECT`, and whether it has an In-Flight Recorder (IFR) log. |
| {command}`!wdfkd.wdfdriverinfo` `<driver>` | One client driver and each of its device objects with the WDFDEVICE behind it. |
| {command}`!wdfkd.wdfhandle` `<handle>` | The object a handle names: type, size, reference count, state, owner, parent, and contexts. |
| {command}`!wdfkd.wdfdevice` `<WDFDEVICE>` | A device's WDM device objects, its PnP, power, and power policy states, and its queues. |
| {command}`!wdfkd.wdfqueue` `<WDFQUEUE>` | A queue's dispatch type, state, callbacks, and the requests waiting in it and owned by the driver. |
| {command}`!wdfkd.wdflogdump` `<driver>` | A driver's IFR log, oldest record first. |

A driver is named as {command}`!wdfkd.wdfldr` lists it, without case; a trailing `.sys` is ignored. A client whose `DriverName` is empty (bound to KMDF with no `FxDriver` created) is listed and named by its `DRIVER_OBJECT`'s name, `kdnic` for `\Driver\kdnic`. A typical walk starts at the driver list and follows handles down:

```
!wdfkd.wdfldr
!wdfkd.wdfdriverinfo kmdfsample
!wdfkd.wdfdevice 00003ef5edcba988
!wdfkd.wdfqueue 00003ef5edcb1238
```

## Handles

A WDF handle is its object's address XORed with `~7`. A handle with bit 0 set is an offset handle: it points at a `WDFOBJECT_OFFSET` inside a larger object (a request's buffer, for instance), which is subtracted to reach that object. Passing an object's address instead of its handle is refused with the handle it would have.

Before an object is shown, its `FxObject` header must check out: `m_Type` is an `FX_OBJECT_TYPES` value, `m_ObjectState` an `FxObjectState` value, `m_ObjectSize` is aligned and no smaller than the type's class, the context header after the object points back at it, and `m_Globals` is a registered client driver's. Anything else is refused with the reason, not shown. The same checks apply to each object the commands reach through a list or pointer; one that fails ends that list, and the output says where and why. The client driver list is the exception: its integrity comes from its links (each entry's Blink must point back at the one before), so a client whose name or `FxDriver` does not check out is still listed, with the problem.

## The In-Flight Recorder

KMDF logs its own trace messages for each client driver into a small ring buffer, the IFR. {command}`!wdfkd.wdflogdump` walks it from the newest record back and prints each record's sequence number, UTC time (when the log keeps timestamps), function, and message. Messages are formatted from the trace message format (TMF) annotations in `Wdf01000.pdb`, so no `.tmf` files are needed. A record whose message no loaded PDB declares prints its message GUID, number, and argument bytes instead.

The walk ends at the first record written, or at the records newer ones have overwritten. The header and every record are checked as they are read (signature, length, position, and falling sequence numbers); at the first that fails the walk stops and reports the corruption, keeping the records it already read.

## From Python

`dbg.inspect` has one method per command, returning the same fields as the MCP JSON: `wdf_loader()`, `wdf_driver_info(driver)`, `wdf_handle(handle)`, `wdf_device(handle)`, `wdf_queue(handle)`, and `wdf_log(driver)`.

```python
for client in dbg.inspect.wdf_loader().clients:
    print(client.name, client.version)
for record in dbg.inspect.wdf_log("kmdfsample").records:
    print(record.sequence, record.function, record.text or record.error)
```
