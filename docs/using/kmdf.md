# KMDF drivers (`!wdfkd`)

The `!wdfkd.*` commands read the state of the Kernel-Mode Driver Framework from `Wdf01000.sys`. They use the types in the public Microsoft `Wdf01000.pdb`. The commands need that module loaded with its PDB, and the symbol server supplies this PDB. You do not need the private PDB of a driver. The commands do not support UMDF drivers.

| Command | Shows |
| --- | --- |
| {command}`!wdfkd.wdfldr` | All KMDF client drivers. For each driver: its name, the KMDF version that it bound to, its `_FX_DRIVER_GLOBALS`, WDFDRIVER handle, and `DRIVER_OBJECT`, and if it has an In-Flight Recorder (IFR) log. |
| {command}`!wdfkd.wdfdriverinfo` `<driver>` | One client driver, and each of its device objects with the WDFDEVICE for that device object. |
| {command}`!wdfkd.wdfhandle` `<handle>` | The object of a handle: its type, size, reference count, state, owner, parent, and contexts. |
| {command}`!wdfkd.wdfdevice` `<WDFDEVICE>` | The WDM device objects of a device, its PnP, power, and power policy states, and its queues. |
| {command}`!wdfkd.wdfqueue` `<WDFQUEUE>` | The dispatch type, state, and callbacks of a queue, the requests that wait in it, and the requests that the driver owns. |
| {command}`!wdfkd.wdflogdump` `<driver>` | The IFR log of a driver, with the oldest record first. |

To name a driver, use the name that {command}`!wdfkd.wdfldr` shows. The name is not case-sensitive, and the commands ignore a trailing `.sys`.

A client can have an empty `DriverName`. This occurs if the client bound to KMDF but did not create an `FxDriver`. The commands then list and name the client by the name of its `DRIVER_OBJECT`. For example, the name for `\Driver\kdnic` is `kdnic`.

A typical walk starts at the driver list and follows the handles down:

```
!wdfkd.wdfldr
!wdfkd.wdfdriverinfo kmdfsample
!wdfkd.wdfdevice 00003ef5edcba988
!wdfkd.wdfqueue 00003ef5edcb1238
```

## Handles

A WDF handle is the address of its object XORed with `~7`.

If bit 0 of a handle is set, the handle is an offset handle. An offset handle points to a `WDFOBJECT_OFFSET` inside a larger object, for example the buffer of a request. The commands subtract this offset to get the larger object.

If you give the address of an object in place of its handle, the command does not accept it. The error shows the handle of that object.

Before a command shows an object, it checks the `FxObject` header of the object. All of these conditions must be true:

- `m_Type` is an `FX_OBJECT_TYPES` value.
- `m_ObjectState` is an `FxObjectState` value.
- `m_ObjectSize` is aligned, and it is not smaller than the class of the type.
- The context header after the object points back to the object.
- `m_Globals` belongs to a registered client driver.

If a check fails, the command does not show the object and gives the reason. The same checks apply to each object that a command gets through a list or a pointer. If one of these objects fails, the list ends at that object. The output tells where and why.

The client driver list is different. Its integrity comes from its links: the Blink of each entry must point back to the entry before it. So the list still includes a client whose name or `FxDriver` fails the checks, and it shows the problem.

## The In-Flight Recorder

For each client driver, KMDF writes its own trace messages to a small ring buffer. This buffer is the IFR.

{command}`!wdfkd.wdflogdump` reads the IFR backward, from the newest record. For each record, it shows:

- the sequence number
- the UTC time, if the log keeps timestamps
- the function
- the message

The command formats the messages from the trace message format (TMF) annotations in `Wdf01000.pdb`. So you do not need `.tmf` files. If no loaded PDB declares the message of a record, the command shows the message GUID, number, and argument bytes of the record.

The walk ends at the first record that KMDF wrote, or where newer records overwrote older records. The command checks the header and each record when it reads them:

- the signature
- the length
- the position
- the sequence numbers, which must decrease

If a check fails, the walk stops and reports the corruption. The command keeps the records that it already read.

## From Python

`dbg.inspect` has one method for each command. Each method returns the same fields as the MCP JSON:

- `wdf_loader()` for {command}`!wdfkd.wdfldr`
- `wdf_driver_info(driver)` for {command}`!wdfkd.wdfdriverinfo`
- `wdf_handle(handle)` for {command}`!wdfkd.wdfhandle`
- `wdf_device(handle)` for {command}`!wdfkd.wdfdevice`
- `wdf_queue(handle)` for {command}`!wdfkd.wdfqueue`
- `wdf_log(driver)` for {command}`!wdfkd.wdflogdump`

```python
for client in dbg.inspect.wdf_loader().clients:
    print(client.name, client.version)
for record in dbg.inspect.wdf_log("kmdfsample").records:
    print(record.sequence, record.function, record.text or record.error)
```
