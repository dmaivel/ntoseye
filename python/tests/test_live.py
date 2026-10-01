"""Run control, `when=` predicates, handle staleness, and Ctrl+C against a
live guest (see `conftest.py`)."""

from __future__ import annotations

import os
import signal
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager

import pytest

import ntoseye
from ntoseye import Debugger, Stop

# Called on every context switch, so a running guest hits it at once.
HOT = "nt!KiSwapContext"

# How a step under VBS reports that its vCPU, run alone, entered the Windows
# hypervisor to wait on the held ones; a scenario it hits is run again.
HYPERVISOR_WAIT = "entered the Windows hypervisor before finishing the step"
# How a step reports that its vCPU, run alone, took an interrupt and waits
# in the handler on a held vCPU; from VTL1 that handler is NT's.
DIVERTED = "did not reach the next instruction"
ATTEMPTS = 3


@contextmanager
def ctrl_c_after(seconds: float) -> Iterator[None]:
    timer = threading.Timer(seconds, os.kill, (os.getpid(), signal.SIGINT))
    timer.start()
    try:
        yield
    finally:
        timer.cancel()


def require_single_step(dbg: Debugger) -> None:
    """Skip unless the target steps, and halt it in NT code: under VBS a
    break-in usually lands in the Windows hypervisor, which is not stepped."""
    if not any(row.capability == "single_step" and row.supported for row in dbg.capabilities):
        pytest.skip("this target refuses single steps")
    dbg.run_to("nt!NtClose", timeout=10.0)


def test_current_stop_is_read_not_consumed(halted: Debugger) -> None:
    require_single_step(halted)
    stop = halted.step()
    assert isinstance(stop, Stop.Step)
    # Every read of a halted target reports the stop it is halted at.
    for current in (halted.stop, halted.stop, halted.wait(0), halted.interrupt()):
        assert isinstance(current, Stop.Step)
        assert current.rip == stop.rip


def test_false_predicate_never_surfaces(halted: Debugger) -> None:
    seen: list[Stop] = []
    halted.breakpoints.add(HOT, when=lambda stop: seen.append(stop))
    assert halted.run(timeout=1.0) is None
    assert seen, "the predicate never ran"
    assert all(isinstance(stop, Stop.Breakpoint) for stop in seen)


def test_true_predicate_surfaces_its_breakpoint(halted: Debugger) -> None:
    bp = halted.breakpoints.add(HOT, when=lambda stop: True)
    stop = halted.run(timeout=5.0)
    assert isinstance(stop, Stop.Breakpoint)
    assert bp in stop.breakpoints
    assert stop.rip == bp.address


def test_failing_predicate_surfaces_with_its_error(halted: Debugger) -> None:
    halted.breakpoints.add(HOT, when=lambda stop: 1 // 0)
    stop = halted.run(timeout=5.0)
    assert isinstance(stop, Stop.Breakpoint)
    assert stop.condition_error is not None
    assert "ZeroDivisionError" in stop.condition_error


def test_steps_resume_past_false_predicates(halted: Debugger) -> None:
    require_single_step(halted)
    halted.breakpoints.add(HOT, when=lambda stop: False)
    # A hit en route is resumed like under run(); the step still completes.
    # Every hit halts the guest while its predicate runs, so under a guest
    # that switches threads constantly (a busy Hyper-V VM inside it) the
    # stepped thread can go unscheduled for long: the timeout bounds the
    # walk, which then ends as a Step where it is, never as the declined hit.
    assert isinstance(halted.step_over(until="call", timeout=60.0), Stop.Step)
    assert isinstance(halted.step_out(timeout=60.0), Stop.Step)


def test_run_to_symbol_stops_there(halted: Debugger) -> None:
    stop = halted.run_to("nt!NtClose", timeout=10.0)
    assert isinstance(stop, Stop.Step)
    assert stop.rip == halted.symbols["nt!NtClose"]


def test_trace_calls_returns_a_call_tree(halted: Debugger) -> None:
    for _ in range(ATTEMPTS):
        require_single_step(halted)
        # gdb single-steps at a few hundred instructions a second.
        trace = halted.trace_calls(limit=2_000)
        if trace.end != "diverted" and not (
            trace.end == "failed" and HYPERVISOR_WAIT in (trace.error or "")
        ):
            break
    assert trace.end in ("returned", "limit")
    assert trace.instructions > 0


def test_enum_fields_are_int_enum_members(halted: Debugger) -> None:
    states = halted.types["_KTHREAD_STATE"].values
    assert states["Running"] == 2
    thread = next(iter(halted.processes[4].threads))
    assert thread.state is not None
    assert thread.state in states.values()
    assert thread.state.name in states  # type: ignore[attr-defined]


def test_reload_makes_old_handles_stale(halted: Debugger) -> None:
    system = halted.processes[4]
    generation = halted.generation
    halted.reload()
    assert halted.generation == generation + 1
    with pytest.raises(ntoseye.StaleHandleError):
        system.name
    assert halted.processes[4].name == "System"


def test_ctrl_c_ends_run(halted: Debugger) -> None:
    start = time.monotonic()
    with ctrl_c_after(0.5), pytest.raises(KeyboardInterrupt):
        halted.run()
    assert time.monotonic() - start < 5.0


def test_ctrl_c_breaks_into_a_resuming_command(halted: Debugger) -> None:
    with ctrl_c_after(0.5), pytest.raises(KeyboardInterrupt):
        halted.command("g")
    # As in the REPL, Ctrl+C during `g` breaks in: the target is halted.
    assert halted.stop is not None


def test_secure_kernel_views_are_isolated_from_vtl0(halted: Debugger) -> None:
    try:
        sk = halted.secure_kernel
    except ntoseye.NtoseyeError as error:
        pytest.skip(f"no VTL1 on this target: {error}")
    assert sk.memory.read(sk.base, 2) == b"MZ"
    assert sk.modules["securekernel"].base == sk.base
    # Each kernel's symbols resolve only in its own address spaces.
    head = sk.symbols["securekernel!SkpsProcessList"]
    assert halted.symbols.get("securekernel!SkpsProcessList") is None
    assert sk.symbols.get("nt!KeBugCheckEx") is None
    # VTL1 is read-only, and the halted vCPU's registers are VTL0 state.
    with pytest.raises(ntoseye.NtoseyeError):
        sk.memory.write_u8(head, 0)
    with pytest.raises(ntoseye.NtoseyeError):
        sk.eval("@rip")
    halted.eval("@rip")
    for trustlet in sk.trustlets:
        assert trustlet.memory.translate(sk.base) == sk.memory.translate(sk.base)
        assert trustlet.symbols["securekernel!SkpsProcessList"] == head
        assert trustlet.process is not None and trustlet.process.pid == trustlet.pid


def test_kernel_memory_reads_at_a_stop_in_the_hypervisor(halted: Debugger) -> None:
    stop = halted.stop
    if stop is None or stop.cpu is None or not stop.cpu.saved_vtl:
        pytest.skip("the stop is not in the Windows hypervisor with saved VTL state (needs VBS and hv-evmcs)")
    # The stop's own vCPU runs on the hypervisor's page tables; the kernel
    # scope still reads NT.
    address = halted.symbols["nt!KeBugCheckEx"]
    assert halted.memory.read(address, 1) == halted.processes[4].memory.read(address, 1)


def test_hypervisor_memory_is_its_own_and_read_only(halted: Debugger) -> None:
    cpu = next((cpu for cpu in halted.cpus if cpu.saved_vtl), None)
    if cpu is None:
        pytest.skip("no vCPU halted in the Windows hypervisor with saved VTL state (needs VBS and hv-evmcs)")
    assert cpu.saved_vtl[0].vtl == 0
    assert cpu.rip is not None
    hypervisor = cpu.memory
    # The vCPU's own root, the hypervisor's, which maps the code it runs;
    # not NT's, where the VTL0 state it saved runs.
    root = 0x000F_FFFF_FFFF_F000
    assert hypervisor.dtb not in {halted.memory.dtb, cpu.saved_vtl[0].cr3 & root}
    assert hypervisor.translate(cpu.rip) is not None
    # Rewriting the byte already there would be harmless if the refusal broke.
    byte = hypervisor.read_u8(cpu.rip)
    with pytest.raises(ntoseye.NtoseyeError):
        hypervisor.write_u8(cpu.rip, byte)
    with pytest.raises(ntoseye.NtoseyeError):
        hypervisor.describe(cpu.rip)


def test_hypervisor_partitions_mirror_the_vcpus(halted: Debugger) -> None:
    """The root partition has one VP per vCPU, by index, and a VP whose vCPU
    is halted in the hypervisor keeps its VTLs' eVMCS pages in their contexts
    and runs the VTL that its current eVMCS holds: the partition walk and the
    eVMCS scan are independent readings of the same processor."""
    try:
        partitions = halted.hypervisor_partitions()
    except ntoseye.NtoseyeError as error:
        pytest.skip(f"no Windows hypervisor partitions on this target: {error}")
    root = partitions[0]
    assert root.parent_id is None
    assert "CreatePartitions" in root.privilege_names
    ids = {partition.id for partition in partitions}
    for child in partitions[1:]:
        # A child was created by a partition in the tree and cannot create
        # partitions itself; without VSM its VPs have only VTL0.
        assert child.parent_id in ids and "CreatePartitions" not in child.privilege_names
        if "AccessVSM" not in child.privilege_names:
            assert all(set(vp.vtls) == {0} for vp in child.virtual_processors)
    cpus = list(halted.cpus)
    assert [vp.index for vp in root.virtual_processors] == list(range(len(cpus)))
    # A processor has one current VP, and its number is one of the target's.
    numbers = [
        processor["number"]
        for partition in partitions
        for vp in partition.virtual_processors
        for processor in vp.processors
        if processor["number"] is not None
    ]
    assert len(numbers) == len(set(numbers)) and all(0 <= n < len(cpus) for n in numbers)
    compared = 0
    for cpu, vp in zip(cpus, root.virtual_processors):
        assert vp.vtl in vp.vtls
        # The eVMCS scan found each saved state's page by its contents; the
        # walk reaches the same page through the VP's VTL context.
        for saved in cpu.saved_vtl:
            assert vp.vtls[saved.vtl].vmcs == saved.evmcs
        current = next((saved for saved in cpu.saved_vtl if saved.current), None)
        if current is not None and not current.may_be_stale:
            assert vp.vtl == current.vtl
            compared += 1
    if compared == 0:
        pytest.skip("no vCPU halted in the hypervisor with a current saved state to compare")


def test_vtl_ept_maps_nt_in_place_and_hides_the_secure_kernel_from_vtl0(halted: Debugger) -> None:
    """The root partition's EPT maps each guest physical address to itself in
    every VTL, and VSM keeps the secure kernel's pages out of VTL0's EPT
    while VTL1 can read them, both through one address and in the comparison
    of the whole EPTs."""
    try:
        vp = halted.hypervisor_partitions()[0].virtual_processors[0]
        sk = halted.secure_kernel
    except ntoseye.NtoseyeError as error:
        pytest.skip(f"no VTL1 or partitions on this target: {error}")
    if 1 not in vp.vtls or vp.vtls[0].ept_pointer is None:
        pytest.skip("needs VBS and the hv-evmcs enlightenment")
    nt = halted.memory.translate(halted.symbols["nt!KeBugCheckEx"])
    secure = sk.memory.translate(sk.base)
    assert nt is not None and secure is not None
    for vtl in vp.vtls.values():
        mapped = vtl.translate(nt)
        assert mapped is not None and mapped.host_physical == nt and mapped.read
    hidden = vp.vtls[0].translate(secure)
    assert hidden is None or not hidden.read
    visible = vp.vtls[1].translate(secure)
    assert visible is not None and visible.host_physical == secure and visible.read
    # The comparison of the two EPTs finds the same page, in ranges that are
    # in order and do not overlap.
    differences = vp.ept_differences()
    assert all(a["end"] <= b["start"] for a, b in zip(differences, differences[1:]))
    covering = [d for d in differences if d["start"] <= secure < d["end"]]
    assert len(covering) == 1
    assert (covering[0]["vtl0"] or "-").startswith("-") and covering[0]["vtl1"].startswith("r")


def test_hypercall_table_matches_the_tlfs(halted: Debugger) -> None:
    """The hypervisor's own table describes the calls as the TLFS does:
    HvCallGetPartitionId returns an 8-byte ID, and HvCallGetVpRegisters is a
    rep call of 4-byte register names in and 16-byte values out."""
    try:
        calls = halted.hypercalls()
    except ntoseye.NtoseyeError as error:
        pytest.skip(f"no Windows hypervisor on this target: {error}")
    by_code = {call["code"]: call for call in calls}
    get_id, get_registers = by_code[0x46], by_code[0x50]
    assert get_id["name"] == "HvCallGetPartitionId" and get_id["implemented"]
    assert (get_id["rep"], get_id["output_size"]) == (False, 8)
    assert get_registers["implemented"] and get_registers["rep"]
    assert (get_registers["input_element_size"], get_registers["output_element_size"]) == (4, 16)
    assert not by_code[0]["implemented"]


def test_vmcs_fields_agree_with_the_saved_state(halted: Debugger) -> None:
    """The eVMCS fields read by name hold what ntoseye reads from the same page
    for each VTL: its EPT pointer and the RIP where it left off."""
    try:
        vp = halted.hypervisor_partitions()[0].virtual_processors[0]
    except ntoseye.NtoseyeError as error:
        pytest.skip(f"no Windows hypervisor partitions on this target: {error}")
    vtls = [vtl for vtl in vp.vtls.values() if vtl.vmcs is not None and vtl.rip is not None]
    if not vtls:
        pytest.skip("needs the hv-evmcs enlightenment")
    for vtl in vtls:
        fields = vtl.vmcs_fields()
        assert fields["revision_id"] == 1
        assert (fields["ept_pointer"], fields["guest_rip"]) == (vtl.ept_pointer, vtl.rip)


def test_child_partition_memory_reads_agree_three_ways(halted: Debugger) -> None:
    """Where a child partition's VP left off, its code reads the same through
    its page tables, through its guest physical address, and at the host
    physical address the EPT maps that to."""
    try:
        partitions = halted.hypervisor_partitions()
    except ntoseye.NtoseyeError as error:
        pytest.skip(f"no Windows hypervisor partitions on this target: {error}")
    vtl = next(
        (
            vtl
            for partition in partitions[1:]
            for vp in partition.virtual_processors
            for vtl in vp.vtls.values()
            if vtl.level == vp.vtl and vtl.rip is not None
        ),
        None,
    )
    if vtl is None or vtl.rip is None:
        pytest.skip("needs a running Hyper-V guest and the hv-evmcs enlightenment")
    translated = vtl.translate_virtual(vtl.rip)
    assert translated is not None
    guest_physical, host_physical = translated
    code = vtl.read(vtl.rip, 16)
    assert vtl.read(guest_physical, 16, physical=True) == code
    assert halted.physical.read(host_physical, 16) == code


def gdb_secure_kernel(halted: Debugger) -> ntoseye.SecureKernel:
    if os.environ.get("NTOSEYE_TEST_BACKEND") != "gdb":
        pytest.skip("VTL1 hardware execution requires the host GDB backend")
    try:
        return halted.secure_kernel
    except ntoseye.NtoseyeError as error:
        pytest.skip(f"no VTL1 on this target: {error}")


GPRS = ["rax", "rcx", "rdx", "rbx", "rbp", "rsi", "rdi"] + [f"r{i}" for i in range(8, 16)]


def test_saved_general_registers_are_the_exits(halted: Debugger) -> None:
    """The registers ntoseye reads where the hypervisor's exit entry code
    saved them are the guest's at the exit: a hardware breakpoint on
    `host_rip` sees them live, and one on the entry code's first call (every
    store is before it) sees what ntoseye then reads. The breakpoint on
    `host_rip` fires after KVM wrote the exit's eVMCS, so the state there is
    already the one the first call sees."""
    if os.environ.get("NTOSEYE_TEST_BACKEND") != "gdb":
        pytest.skip("breakpoints in the Windows hypervisor require the host GDB backend")
    cpu = next((cpu for cpu in halted.cpus if cpu.saved_vtl), None)
    if cpu is None:
        pytest.skip("no vCPU halted in the Windows hypervisor with saved VTL state (needs VBS and hv-evmcs)")
    current = next(saved for saved in cpu.saved_vtl if saved.current)
    assert current.general_registers is not None or current.may_be_stale
    host_rip = current.host_rip
    first_call = next(ins.ip for ins in cpu.memory.disassemble(host_rip, 64) if ins.mnemonic == "call")
    for _ in range(ATTEMPTS):
        entry = halted.breakpoints.add(host_rip, hardware=True)
        try:
            stop = halted.run(timeout=10.0)
        finally:
            entry.delete()
        assert isinstance(stop, Stop.Breakpoint)
        exiting = stop.cpu
        truth = {name: exiting.registers[name] for name in GPRS}
        at_entry = next(saved for saved in exiting.saved_vtl if saved.current)
        assert not at_entry.may_be_stale and at_entry.general_registers is not None
        stored = halted.breakpoints.add(first_call, hardware=True, processor=exiting)
        try:
            stop = halted.run(timeout=10.0)
        finally:
            stored.delete()
        assert isinstance(stop, Stop.Breakpoint) and stop.cpu.id == exiting.id
        saved = next(saved for saved in stop.cpu.saved_vtl if saved.current)
        assert (saved.vtl, saved.rip, saved.exit_reason) == (at_entry.vtl, at_entry.rip, at_entry.exit_reason)
        assert saved.general_registers is not None
        assert {name: getattr(saved.general_registers, name) for name in GPRS} == truth


def test_secure_hardware_breakpoint_preserves_code_and_cpu_identity(halted: Debugger) -> None:
    sk = gdb_secure_kernel(halted)
    address = sk.symbols["securekernel!SkeSelectProcessAddressSpace"]
    with pytest.raises(ntoseye.NtoseyeError):
        halted.breakpoints.add(address)
    bp = halted.breakpoints.add(address, hardware=True)
    try:
        for _ in range(2):
            stop = halted.run(timeout=10.0)
            assert isinstance(stop, Stop.Breakpoint)
            assert stop.rip == address and bp in stop.breakpoints
            assert stop.symbol == "securekernel!SkeSelectProcessAddressSpace"
            assert stop.thread is None and stop.process is None
            assert stop.cpu.thread is None and stop.cpu.process is None
            assert stop.cpu.registers["rip"] == address
    finally:
        halted.interrupt()
        bp.delete()


def test_secure_steps_use_hardware_sites_and_leave_code_unchanged(halted: Debugger) -> None:
    sk = gdb_secure_kernel(halted)
    address = sk.symbols["securekernel!SkeSelectProcessAddressSpace"]
    for attempt in range(ATTEMPTS):
        try:
            if secure_step_scenario(halted, address):
                return
        except ntoseye.NtoseyeError as error:
            if HYPERVISOR_WAIT not in str(error) or attempt == ATTEMPTS - 1:
                raise
    pytest.fail(f"all {ATTEMPTS} steps were diverted into an interrupt handler")


def secure_step_scenario(halted: Debugger, address: int) -> bool:
    """Step in the secure kernel and step out; `False` when the step was
    diverted into an interrupt handler, which leaves nothing to check."""
    bp = halted.breakpoints.add(address, hardware=True)
    try:
        assert isinstance(halted.run(timeout=10.0), Stop.Breakpoint)
        bp.delete()
        # Which sites a step plants is pinned by the Rust unit tests; this is
        # the live path. step_out's run-to site goes through the breakpoint
        # manager, which refuses a software site in the secure kernel.
        halted.notices()
        step = halted.step()
        assert isinstance(step, Stop.Step)
        assert step.rip != address
        if any(DIVERTED in notice for notice in halted.notices()):
            return False
        assert (step.symbol or "").startswith("securekernel!")
        out = halted.step_out()
        assert isinstance(out, Stop.Step)
        assert (out.symbol or "").startswith("securekernel!")
        assert out.thread is None
        assert not list(halted.breakpoints), "a temporary site was left behind"
        return True
    finally:
        halted.interrupt()
        if bp.valid:
            bp.delete()
