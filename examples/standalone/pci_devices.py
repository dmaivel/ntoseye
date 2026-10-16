#!/usr/bin/env python3
"""List PCI functions like `lspci`, and show one device's BARs and capabilities.

Reads configuration space through the backend (`!pci`), so it needs `kd` or
`gdb` on QEMU and halts the guest while it scans (leaving the session resumes
it); the memory backend reads RAM only. Every bus is scanned by default.

    python3 pci_devices.py
    python3 pci_devices.py --backend gdb --connect localhost:1234
    python3 pci_devices.py --vendor 0x1af4            # virtio devices, in detail
    python3 pci_devices.py --vendor 0x1af4 --device 0x1045
"""

import argparse

import ntoseye


def parse_int(text: str) -> int:
    return int(text, 0)


def location(function: ntoseye.PciFunction) -> str:
    return f"{function.segment:04x}:{function.bus:02x}:{function.device:02x}.{function.function}"


def describe(function: ntoseye.PciFunction) -> None:
    header = function.header
    print(f"\n{location(function)}  {header.vendor_id:04x}:{header.device_id:04x}  "
          f"{function.class_name or 'unknown class'}  (rev {header.revision:#x})")
    if header.subsystem_vendor_id is not None and header.subsystem_id is not None:
        print(f"  subsystem  {header.subsystem_vendor_id:04x}:{header.subsystem_id:04x}")
    print(f"  command    {', '.join(header.command_flags) or '-'}")
    print(f"  status     {', '.join(header.status_flags) or '-'}")
    if header.buses is not None:
        buses = header.buses
        print(f"  buses      primary {buses.primary:#x}, secondary {buses.secondary:#x}, "
              f"subordinate {buses.subordinate:#x}")
    for bar in header.bars:
        prefetch = ", prefetchable" if bar.prefetchable else ""
        print(f"  BAR{bar.index}       {bar.address:#x} ({bar.kind}{prefetch})")
    if header.expansion_rom:  # None or 0 when there is none
        print(f"  ROM        {header.expansion_rom:#x}")
    for capability in function.capabilities + function.extended_capabilities:
        name = capability.name or f"capability {capability.id:#x}"
        version = f" v{capability.version}" if capability.version is not None else ""
        print(f"  cap @{capability.offset:#05x} {name}{version}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--backend", default="kd", choices=["gdb", "kd"])
    ap.add_argument("--connect", default=None)
    ap.add_argument("--last-bus", default=0xFF, type=parse_int, help="highest bus to scan")
    ap.add_argument("--vendor", type=parse_int, help="show only this vendor ID, in detail")
    ap.add_argument("--device", type=parse_int, help="show only this device ID, in detail")
    args = ap.parse_args()

    with ntoseye.attach(backend=args.backend, connect=args.connect) as dbg:
        dbg.interrupt()
        scan = dbg.inspect.pci(0, last_bus=args.last_bus)

    functions = [
        function
        for function in scan.functions
        if (args.vendor is None or function.header.vendor_id == args.vendor)
        and (args.device is None or function.header.device_id == args.device)
    ]
    if args.vendor is None and args.device is None:
        for function in functions:
            header = function.header
            print(f"{location(function)}  {header.vendor_id:04x}:{header.device_id:04x}  "
                  f"{function.class_name or 'unknown class'}")
    else:
        for function in functions:
            describe(function)
    if not functions:
        print("no matching PCI functions")
    if scan.interrupted:
        print("\nscan interrupted; the list is partial")


if __name__ == "__main__":
    main()
