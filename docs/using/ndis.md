# Network miniports (`!ndiskd.*`)

The {command}`!ndiskd.miniports`, {command}`!ndiskd.miniport`, and {command}`!ndiskd.minidriver` commands show what NDIS knows about the guest's network adapters: each miniport's state and link, the miniport driver behind it, the filter drivers stacked on it, the protocols bound to it, and the OID request it is working on. They help you when you develop a miniport driver, such as NetKVM, the virtio-win driver for virtio-net devices, and an adapter does not come up, stops passing traffic, or does not finish a pause, a reset, or an OID request.

The commands have the names of the commands in WinDbg's `ndiskd` extension. They read ndis.sys's own structures (`_NDIS_MINIPORT_BLOCK`, `_NDIS_M_DRIVER_BLOCK`, `_NDIS_FILTER_BLOCK`, `_NDIS_OPEN_BLOCK`, `_NDIS_OID_REQUEST`) with the types in the public PDB of ndis.sys, so they need that PDB, which ntoseye downloads like any other. They read only guest memory, so they work on every backend and in crash dumps.

## Miniports

{command}`!ndiskd.miniports` walks ndis.sys's global list of miniports and shows one line for each miniport:

```text
Miniport          Driver    State    Media              Power  IfIndex  Name
ffffc88844dc5000  VMSNPXY   Running  Connected 10 Gbps  D0     20       Hyper-V Virtual Ethernet Adapter
ffffc8884977f1a0  vmsmp     Running  Connected 10 Gbps  D0     16       Hyper-V Virtual Switch Extension Adapter
ffffc88843a491a0  e1i68x64  Running  Connected 1 Gbps   D0     6        Intel(R) 82574L Gigabit Network Connection #2
```

| Column | Meaning |
| --- | --- |
| Miniport | The address of the miniport's `_NDIS_MINIPORT_BLOCK`. Give it to {command}`!ndiskd.miniport`. |
| Driver | The service name of the miniport driver. |
| State | The miniport state: `Initializing`, `Running`, `Pausing`, `Paused`, `Restarting`, or `Halted`. |
| Media | The media connect state, and for a connected adapter, the link speed that the miniport reported. When the receive speed differs from the transmit speed, both show. |
| Power | The device power state of the adapter. |
| IfIndex | The interface index, which `netsh` and `Get-NetAdapter` also show in the guest. |
| Name | The friendly name of the adapter. |

The list includes virtual miniports, such as Hyper-V's adapters, which have no device of their own.

## One miniport

{command}`!ndiskd.miniport` `<miniport>` shows one miniport. Without an address, it lists the miniports as {command}`!ndiskd.miniports` does.

```text
Miniport             ffffc88843a491a0  Intel(R) 82574L Gigabit Network Connection #2
Device name          \DEVICE\{1C0BA63B-C03E-46A8-9486-643BBA448622}
Instance ID          PCI\VEN_8086&DEV_10D3&SUBSYS_00008086&REV_00\4&12829b10&0&0014
NDIS version         6.50
Driver               ffffc888439f2800  e1i68x64 (e1i68x64.sys) v12.19
DRIVER_OBJECT        ffffc888439f1b60
Adapter context      ffffc88843b9d000  (dt e1i68x64!<adapter type> ffffc88843b9d000)
Device objects       FDO ffffc88843a49050  PDO ffffc888430f5060

State                Running
PnP state            Started
Power                D0
Media                Connected, Full duplex, medium 802_3, physical 802_3
Link speed           1 Gbps transmit, 1 Gbps receive
Interface            IfIndex 6, NetLuid 0x6008006000000, UP
References           12
Resets               internal 0, miniport 0, last status 0x0
Pending OID          none
Pending return NBLs  0
Flags                0x2c450218, PnP flags 0x210021

Filters (3, top first)
Filter            State    Driver       Context           Name
ffffc8884407f300  Running  wfplwfs.sys  ffffc888440809f0  Intel(R) 82574L Gigabit Network Connection #2-WFP 802.3 MAC Layer LightWeight Filter-0000
ffffc8884407d410  Running  pacer.sys    ffffc8884403e490  Intel(R) 82574L Gigabit Network Connection #2-QoS Packet Scheduler-0000
ffffc8884407b7d0  Running  wfplwfs.sys  ffffc8884407d010  Intel(R) 82574L Gigabit Network Connection #2-WFP Native MAC Layer LightWeight Filter-0000

Protocol bindings (5, NumOpens 5)
Open              Protocol  Protocol block    Context
ffffc8884711e460  LLTDIO    ffffc888471daa90  ffffc888470a55d0
ffffc8884711f010  RSPNDR    ffffc888471dba20  ffffc888471dc620
ffffc88845136460  MSLLDP    ffffc88845e5ea70  ffffc88845b16790
ffffc888440e98a0  TCPIP     ffffc8884330fb80  ffffc888440e8010
ffffc888440848a0  TCPIP6    ffffc88843336620  ffffc88844083010
```

The first part identifies the adapter:

- **Driver** is the miniport driver's `_NDIS_M_DRIVER_BLOCK`, which {command}`!ndiskd.minidriver` shows, with the driver's service, image, and version.
- **Adapter context** is the context that your driver passed to `NdisMSetMiniportAttributes`, the `MiniportAdapterContext` that NDIS gives back to each of your handlers. To see it with your own types, add your driver's private PDB to the symbol path (see [Symbols and source](symbols.md)) and run the {command}`dt` command that the line suggests with the name of your adapter structure, for example `dt netkvm!_PARANDIS_ADAPTER <address>` for NetKVM.
- **Device objects** are the FDO that NDIS created for the adapter and the PDO under it, which you can give to {command}`!devstack`. A virtual miniport has neither.

The second part shows the state of the adapter:

- **State** is the NDIS miniport state. A miniport that stays in `Pausing` has not completed its pause: a miniport completes a pause only after it has completed its outstanding sends and the receive NET_BUFFER_LISTs that it indicated have come back to it. A miniport that stays in `Restarting` or `Initializing` has not completed its restart or initialization.
- **PnP state** and **Power** are the PnP state of the device as NDIS tracks it and its device power state.
- **Resets** shows the miniport block's reset counters, `InternalResetCount` and `MiniportResetCount`, and `ResetStatus`, the NTSTATUS of the last reset.
- **Pending OID** is the OID request that NDIS passed to the miniport and that the miniport has not completed yet, with its type, its OID by its `ntddndis.h` name, and its buffer. NDIS passes a miniport one OID request at a time, apart from direct OID requests, so a request that stays pending holds up the requests behind it.
- **Pending return NBLs** is the miniport block's `PendingReturnNBLCount`, received NET_BUFFER_LISTs whose return to the miniport is pending.
- **Flags** are the raw `Flags` and `PnPFlags` of the miniport block.

**Filters** lists the filter modules on the adapter from the top of the stack down, as NDIS links them, with each filter's state, driver image, and module context (the context that the filter driver passed to `NdisFSetAttributes`). A filter with an OID request that it has not completed shows the request below the list. ntoseye checks that each filter's link to the filter above it leads back, and that the walk ends at the miniport's lowest filter. If a check fails, the list stops there with the reason.

**Protocol bindings** lists the protocols that opened the adapter, with each protocol's `_NDIS_PROTOCOL_BLOCK` and its binding context.

If you give an address that is not on NDIS's list of miniports, the command shows it only when it has the NDIS object header of a miniport block, for example a miniport that NDIS is removing, and it notes that it is not on the list. Otherwise it says that the address is not a miniport.

## Miniport drivers

{command}`!ndiskd.minidriver` lists the miniport drivers that registered with NDIS:

```text
Driver block      Service   Image             NDIS  Version  Miniports
ffffc888439f2800  e1i68x64  e1i68x64.sys      6.50  12.19    1
ffffc888439388b0  vmsmp     vmswitch.sys      6.83  19.0     1
ffffc8884332b620  VMSNPXY   VmsProxyHNic.sys  6.81  1.1      1
ffffc8884332c630  VMSNPXY   VmsProxyHNic.sys  6.83  1.1      0
```

NDIS is the NDIS version that the driver registered with, and Version is the driver's own version from its miniport characteristics. With the address of a driver block, the command shows the driver and its miniports:

```text
Driver block         ffffc888439f2800
Service              e1i68x64
Image                e1i68x64.sys  (module e1i68x64)
DRIVER_OBJECT        ffffc888439f1b60
NDIS version         6.50
Driver version       12.19

Miniports (1)
Miniport          Driver    State    Media             Power  IfIndex  Name
ffffc88843a491a0  e1i68x64  Running  Connected 1 Gbps  D0     6        Intel(R) 82574L Gigabit Network Connection #2
```

The module is the loaded image that the driver's code is in, the name that its PDB's types go by in {command}`dt`.
