"""Results from a live guest hold what the checked-in stub says they do: every
property of every result class, recursively, including what each
`Diagnostic` holds, and each result has exactly the fields its class
declares (see `conftest.py`)."""

from __future__ import annotations

import ast
from collections.abc import Callable
from pathlib import Path

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
    return [
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
        (cpu, "gdt", cpu.gdt),
        (cpu, "idt", cpu.idt),
        (hypervisor_cpu, "saved_vtl", lambda: hypervisor_cpu.saved_vtl),
        (user, "token", user.token),
        (user, "handles", user.handles),
        (heap, "inspect", heap.inspect),
        (kernel, "inspect", kernel.inspect),
        (kernel, "headers", lambda: kernel.headers(exports=True, imports=True)),
        (kernel, "image_info", kernel.image_info),
        (thread, "inspect", thread.inspect),
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


def test_results_match_their_stub_types(halted: Debugger) -> None:
    checker = Checker(CLASSES)
    for owner, method, call in results(halted) + hypervisor_results(halted):
        cls = type(owner).__name__
        checker.value(call(), returns(CLASSES[cls], method), f"{cls}.{method}()")
    assert checker.errors == []
    # The sample must keep exercising every kind of field.
    assert checker.forms >= {"class", "Record", "available", "unavailable", "source"}
