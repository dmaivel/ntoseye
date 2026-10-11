"""Results from a live guest hold what the checked-in stub says they do: every
property of every result class, recursively, including what each
`Diagnostic` holds, and each result has exactly the fields its class
declares (see `conftest.py`). `NTOSEYE_TEST_USER_DUMP`, the path of a
Windows user-mode minidump, checks a user dump's results the same way."""

from __future__ import annotations

import ast
import os
from collections.abc import Callable
from pathlib import Path

import pytest
from stubcheck import Checker, returns

import ntoseye
from ntoseye import Debugger

STUB = ast.parse(Path(ntoseye.__file__).with_name("_ntoseye.pyi").read_text())
CLASSES = {node.name: node for node in STUB.body if isinstance(node, ast.ClassDef)}


def results(dbg: Debugger) -> list[tuple[object, str, Callable[[], object]]]:
    """(owner, method, call) for results that hold every kind of field: nested
    classes, unions, lists, `Record`s, diagnostics that did and did not read,
    and metrics with a source."""
    inspect = dbg.inspect
    cpu = next(iter(dbg.cpus))
    # Under VBS a vCPU halted in the Windows hypervisor has saved VTL states.
    hypervisor_cpu = next((c for c in dbg.cpus if c.saved_vtl), cpu)
    user = next(p for p in dbg.processes if p.name.lower() in {"lsass.exe", "explorer.exe", "svchost.exe"})
    heap = next(iter(user.heaps))
    kernel = dbg.modules["nt"]
    thread = next(t for t in user.threads if t.teb is not None)
    # A service key holds text, string list, number, and binary values.
    service = r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer"
    service_key = inspect.registry_key(service)
    service_cell = service_key.cell
    assert service_cell is not None
    found: list[tuple[object, str, Callable[[], object]]] = [
        (inspect, "vm", inspect.vm),
        (inspect, "version", inspect.version),
        (inspect, "time", inspect.time),
        (inspect, "pci", inspect.pci),
        (inspect, "devnode", inspect.devnode),
        (inspect, "running", lambda: inspect.running(include_idle=True, include_stacks=True)),
        (inspect, "dpcs", inspect.dpcs),
        (inspect, "ipi", inspect.ipi),
        (inspect, "timers", inspect.timers),
        (inspect, "peb", lambda: inspect.peb(user)),
        (inspect, "teb", lambda: inspect.teb(thread)),
        (cpu, "pcr", cpu.pcr),
        (cpu, "prcb", cpu.prcb),
    ]
    # An ARM64 processor has no descriptor tables.
    if inspect.version().architecture != "ARM64":
        found += [(cpu, "gdt", cpu.gdt), (cpu, "idt", cpu.idt)]
    return found + [
        (hypervisor_cpu, "saved_vtl", lambda: hypervisor_cpu.saved_vtl),
        (hypervisor_cpu, "serving", lambda: hypervisor_cpu.serving),
        (user, "token", user.token),
        (user, "handles", user.handles),
        (heap, "inspect", heap.inspect),
        (kernel, "inspect", kernel.inspect),
        (kernel, "headers", lambda: kernel.headers(exports=True, imports=True)),
        (kernel, "image_info", kernel.image_info),
        (thread, "inspect", thread.inspect),
        (inspect, "registry_hives", inspect.registry_hives),
        (inspect, "registry_key", lambda: inspect.registry_key(service)),
        (inspect, "registry_value", lambda: inspect.registry_value(service, "DependOnService")),
        (
            inspect,
            "registry_key_at",
            lambda: inspect.registry_key_at(service_key.hive, service_key.subkeys[0].node),
        ),
        (inspect, "registry_cell", lambda: inspect.registry_cell(service_key.hive, service_cell)),
    ]


def hypervisor_results(dbg: Debugger) -> list[tuple[object, str, Callable[[], object]]]:
    """The Windows hypervisor's results, on a target that runs it with the
    hv-evmcs enlightenment; none elsewhere."""
    try:
        vp = dbg.hypervisor_partitions()[0].virtual_processors[0]
    except ntoseye.NtoseyeError:
        return []
    vtl = vp.vtls[0]
    gpa = dbg.memory.translate(dbg.symbols["nt!KeBugCheckEx"])
    if vtl.vmcs is None or vtl.ept_pointer is None or gpa is None:
        return []
    found: list[tuple[object, str, Callable[[], object]]] = [
        (dbg, "hypercalls", dbg.hypercalls),
        (vp, "processors", lambda: vp.processors),
        (vtl, "vmcs_fields", vtl.vmcs_fields),
        (vtl, "translate", lambda: vtl.translate(gpa)),
    ]
    if 1 in vp.vtls:
        found.append((vp, "ept_differences", vp.ept_differences))
    return found


def driver_results(dbg: Debugger) -> list[tuple[object, str, Callable[[], object]]]:
    """NDIS, StorPort, classpnp, KMDF, the WPP recorder, the power manager,
    and the HAL's interrupt controllers and SMBIOS table, on a guest with a
    NIC, a StorPort disk, and a KMDF FDO; the local APIC on the kd backends,
    which switch processors for it."""
    inspect = dbg.inspect
    miniport = inspect.ndis_miniports().miniports[0]
    minidriver = inspect.ndis_minidrivers().drivers[0]
    filters = inspect.ndis_filters().filters
    filter_driver = inspect.ndis_filter_drivers().drivers[0]
    protocol = inspect.ndis_protocols().protocols[0]
    adapter = next(
        entry.adapter
        for driver in inspect.storport_adapters().drivers
        for entry in driver.adapters
        if entry.adapter is not None and any(unit.unit is not None for unit in entry.adapter.units)
    )
    unit = next(entry.extension for entry in adapter.units if entry.unit is not None)
    disk = inspect.class_devices().devices[0]
    recorded = inspect.rcdr_drivers().drivers[0].name
    # A PDO with a power IRP outstanding, such as a USB device's wait/wake.
    power_irps = inspect.power_action().irps.value
    pdo: int | None = None
    if power_irps is not None:
        pdo = next((irp.value.pdo for irp in power_irps.irps if irp.value is not None), None)
    # A KMDF FDO, which has a default I/O target, and a request that a KMDF
    # driver holds, such as the one the balloon driver keeps for statistics.
    wdf_devices = [
        inspect.wdf_device(entry.handle)
        for client in inspect.wdf_loader().clients
        if client.name is not None
        for entry in inspect.wdf_driver_info(client.name).devices
        if entry.handle is not None
    ]
    wdf_device, wdf_target = next(
        (device, target) for device in wdf_devices if (target := device.default_io_target) is not None
    )
    held = next(
        (
            request.handle
            for device in wdf_devices
            for queue in device.queues
            for request in inspect.wdf_queue(queue.handle).driver_owned
        ),
        None,
    )
    found: list[tuple[object, str, Callable[[], object]]] = [
        (inspect, "ndis_miniports", inspect.ndis_miniports),
        (inspect, "ndis_miniport", lambda: inspect.ndis_miniport(miniport.address)),
        (inspect, "ndis_minidrivers", inspect.ndis_minidrivers),
        (inspect, "ndis_minidriver", lambda: inspect.ndis_minidriver(minidriver.address)),
        (inspect, "ndis_filters", inspect.ndis_filters),
        (inspect, "ndis_filter_drivers", inspect.ndis_filter_drivers),
        (inspect, "ndis_filter_driver", lambda: inspect.ndis_filter_driver(filter_driver.address)),
        (inspect, "ndis_protocols", inspect.ndis_protocols),
        (inspect, "ndis_protocol", lambda: inspect.ndis_protocol(protocol.address)),
        (inspect, "ndis_oids", inspect.ndis_oids),
        (inspect, "storport_adapters", inspect.storport_adapters),
        (inspect, "storport_adapter", lambda: inspect.storport_adapter(adapter.extension)),
        (inspect, "storport_unit", lambda: inspect.storport_unit(unit)),
        (inspect, "storport_log", lambda: inspect.storport_log(adapter.extension)),
        (inspect, "class_devices", inspect.class_devices),
        (inspect, "class_device", lambda: inspect.class_device(disk.private_data)),
        (inspect, "rcdr_drivers", inspect.rcdr_drivers),
        (inspect, "rcdr_logs", lambda: inspect.rcdr_logs(recorded)),
        (inspect, "rcdr_log", lambda: inspect.rcdr_log(recorded)),
        (inspect, "interrupt_controllers", inspect.interrupt_controllers),
        (inspect, "smbios", inspect.smbios),
        (inspect, "power_action", inspect.power_action),
        (inspect, "wdf_device", lambda: inspect.wdf_device(wdf_device.handle)),
        (inspect, "wdf_object", lambda: inspect.wdf_object(wdf_device.handle)),
        (inspect, "wdf_io_target", lambda: inspect.wdf_io_target(wdf_target)),
    ]
    if filters:
        found.append((inspect, "ndis_filter", lambda: inspect.ndis_filter(filters[0].address)))
    if pdo is not None:
        found.append((inspect, "device_power", lambda: inspect.device_power(pdo)))
    if held is not None:
        found.append((inspect, "wdf_request", lambda: inspect.wdf_request(held)))
    # The local APIC is AMD64's.
    if (
        os.environ.get("NTOSEYE_TEST_BACKEND") in {"kd", "kdnet"}
        and inspect.version().architecture != "ARM64"
    ):
        cpu = list(dbg.cpus)[-1]
        found.append((cpu, "apic", cpu.apic))
    return found


def test_results_match_their_stub_types(halted: Debugger) -> None:
    checker = Checker(CLASSES)
    for owner, method, call in results(halted) + hypervisor_results(halted) + driver_results(halted):
        cls = type(owner).__name__
        checker.value(call(), returns(CLASSES[cls], method), f"{cls}.{method}()")
    assert checker.errors == []
    # The sample must keep exercising every kind of field.
    assert checker.forms >= {"class", "Record", "available", "unavailable", "source"}


def user_dump_results(dbg: Debugger) -> list[tuple[object, str, Callable[[], object]]]:
    """A user-mode minidump's results: its own records, and the reports
    that read its process, thread, and exception."""
    user = dbg.user_dump
    assert user is not None
    inspect = dbg.inspect
    thread = user.exception_thread or user.current_thread
    assert thread is not None
    return [
        (user, "exception", lambda: user.exception),
        (user, "handles", lambda: user.handles),
        (user, "regions", lambda: user.regions),
        (user, "unloaded_modules", lambda: user.unloaded_modules),
        (inspect, "version", inspect.version),
        (inspect, "time", inspect.time),
        (inspect, "triage", inspect.triage),
        (inspect, "peb", lambda: inspect.peb(user.process)),
        (inspect, "teb", lambda: inspect.teb(thread)),
        (thread, "last_error", thread.last_error),
    ]


def test_user_dump_results_match_their_stub_types() -> None:
    path = os.environ.get("NTOSEYE_TEST_USER_DUMP")
    if not path:
        pytest.skip("set NTOSEYE_TEST_USER_DUMP to a user-mode minidump to check its results")
    with ntoseye.attach("dmp", path) as dbg:
        checker = Checker(CLASSES)
        for owner, method, call in user_dump_results(dbg):
            cls = type(owner).__name__
            checker.value(call(), returns(CLASSES[cls], method), f"{cls}.{method}()")
        assert checker.errors == []
