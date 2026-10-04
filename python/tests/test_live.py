"""Run control, `when=` predicates, handle staleness, and Ctrl+C against a
live guest (see `conftest.py`)."""

from __future__ import annotations

import os
import signal
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

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
# How a walk on the gdb backend reports that its thread went on into user
# space, where a GDB stub cannot be trusted to lift a software breakpoint.
USER_SPACE = "cannot plant a software breakpoint in user space"
# A walk following its switched-out thread ends when that thread exits
# before it runs again; another thread caught at the same function goes on.
EXITED = "exited before it went on"
# How a step refuses a vCPU halted in the Windows hypervisor, where an
# interrupt can catch it taking a VM exit.
IN_HYPERVISOR = "is halted in the Windows hypervisor"
# A step refused because the vCPU runs a guest partition's VP (WSL2, a
# Hyper-V VM), whose code is not NT's.
IN_GUEST_VP = "of a guest partition, which the Windows hypervisor put on its processor"
# A step-out refused because the stack walk found no caller, as from code
# that no module or unwind data covers.
NO_CALLER = "could not find caller return address"
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
    # A hit en route is resumed like under run(), never surfaced as the
    # step's stop. Every hit halts the guest while its predicate runs, so
    # under a guest that switches threads constantly (a busy Hyper-V VM
    # inside it) the stepped thread can go unscheduled for long; the timeout
    # then interrupts the step where it is. Waiting longer only waits: the
    # hits the test is about are declined either way.
    # Under that load the stepped thread can also exit before it gets past
    # its next instruction, which the step reports, and which leaves
    # nothing to step out of.
    try:
        over = halted.step_over(until="call", timeout=20.0)
    except ntoseye.NtoseyeError as error:
        if EXITED not in str(error):
            raise
        return
    assert isinstance(over, (Stop.Step, Stop.Interrupt))
    # Stepping out follows the same thread, which can exit under that load
    # too. The interrupt can also halt the vCPU taking a VM exit, in the
    # Windows hypervisor, or running a guest partition's VP, where no step
    # can start, or in code outside every loaded module, which no unwind data
    # leaves; a finished step is always in NT.
    try:
        out = halted.step_out(timeout=20.0)
    except ntoseye.NtoseyeError as error:
        message = str(error)
        refused_after_interrupt = isinstance(over, Stop.Interrupt) and (
            IN_HYPERVISOR in message or IN_GUEST_VP in message or NO_CALLER in message
        )
        if EXITED not in message and not refused_after_interrupt:
            raise
        return
    assert isinstance(out, (Stop.Step, Stop.Interrupt))


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
            trace.end == "failed"
            and any(
                reason in (trace.error or "") for reason in (HYPERVISOR_WAIT, USER_SPACE, EXITED)
            )
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
        processor.number
        for partition in partitions
        for vp in partition.virtual_processors
        for processor in vp.processors
        if processor.number is not None
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
    assert all(a.end <= b.start for a, b in zip(differences, differences[1:]))
    covering = [d for d in differences if d.start <= secure < d.end]
    assert len(covering) == 1
    vtl1 = covering[0].vtl1
    assert (covering[0].vtl0 or "-").startswith("-") and vtl1 is not None and vtl1.startswith("r")


def test_hypercall_table_matches_the_tlfs(halted: Debugger) -> None:
    """The hypervisor's own table describes the calls as the TLFS does:
    HvCallGetPartitionId returns an 8-byte ID, and HvCallGetVpRegisters is a
    rep call of 4-byte register names in and 16-byte values out."""
    try:
        calls = halted.hypercalls()
    except ntoseye.NtoseyeError as error:
        pytest.skip(f"no Windows hypervisor on this target: {error}")
    by_code = {call.code: call for call in calls}
    get_id, get_registers = by_code[0x46], by_code[0x50]
    assert get_id.name == "HvCallGetPartitionId" and get_id.implemented
    assert (get_id.rep, get_id.output_size) == (False, 8)
    assert get_registers.implemented and get_registers.rep
    assert (get_registers.input_element_size, get_registers.output_element_size) == (4, 16)
    assert not by_code[0].implemented


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
        assert fields.revision_id == 1
        assert (fields.ept_pointer, fields.guest_rip) == (vtl.ept_pointer, vtl.rip)


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


def test_child_partition_code_disassembles_from_its_memory(halted: Debugger) -> None:
    """Where a child partition's VP left off, its code disassembles from the
    bytes its memory holds, through its page tables or its guest physical
    address alike."""
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
    rip = vtl.rip
    translated = vtl.translate_virtual(rip)
    assert translated is not None
    guest_physical, _ = translated
    rows = vtl.disassemble(rip, 4)
    assert rows and rows[0].ip == rip
    for row, after in zip(rows, rows[1:]):
        assert after.ip == row.ip + row.length
    code = vtl.read(rip, sum(row.length for row in rows))
    assert "".join(row.hex.replace(" ", "") for row in rows) == code.hex()
    # The next guest physical page need not be the next virtual one.
    in_page = [row for row in rows if (row.ip + row.length - 1) >> 12 == rip >> 12]
    if in_page:
        physical = vtl.disassemble(guest_physical, len(in_page), physical=True)
        # Relative operands differ with the address; the instructions do not.
        assert [row.hex for row in physical] == [row.hex for row in in_page]


def test_a_cpu_walks_the_hypervisor_or_where_a_saved_vtl_left_off(halted: Debugger) -> None:
    """A vCPU halted in the Windows hypervisor walks from its live RIP, in the
    hypervisor, with frames of no Windows thread, and from where each VTL left
    off as the hypervisor saved it; a vCPU elsewhere has no saved VTL to walk
    from."""
    cpus = list(halted.cpus)
    found = next(((cpu, cpu.saved_vtl) for cpu in cpus if cpu.saved_vtl), None)
    if found is None:
        pytest.skip("no vCPU halted in the Windows hypervisor with saved VTL state (needs VBS and hv-evmcs)")
    cpu, saved = found
    frames = cpu.backtrace(limit=8)
    assert frames and frames[0].ip == cpu.rip and frames[0].thread is None
    for state in saved:
        walked = cpu.backtrace(limit=8, vtl=state.vtl)
        assert walked and walked[0].ip == state.rip, f"VTL{state.vtl}"
    elsewhere = next(
        (other for other in cpus if not other.saved_vtl and not (other.symbol or "").startswith("hv")),
        None,
    )
    if elsewhere is not None:
        with pytest.raises(ntoseye.NtoseyeError, match="not halted in the Windows hypervisor"):
            elsewhere.backtrace(vtl=0)


def select_windows_guest(halted: Debugger) -> ntoseye.HypervisorPartition:
    """Show the first guest partition that runs Windows, or skip."""
    try:
        partitions = halted.hypervisor_partitions()
    except ntoseye.NtoseyeError as error:
        pytest.skip(f"no Windows hypervisor partitions on this target: {error}")
    for partition in partitions[1:]:
        try:
            halted.select_partition(partition.id)
        except ntoseye.NtoseyeError:
            continue  # no NT kernel there (WSL2), or a VM still in its firmware
        return partition
    pytest.skip("needs a guest partition running Windows, such as a Windows Sandbox")


def test_a_guest_partition_reads_as_its_own_windows(halted: Debugger) -> None:
    """`select_partition` shows a guest partition's Windows in place of the
    target: its own kernel and processes, its VPs as the vCPUs with stacks in
    its NT, and its memory written through its EPT; partition 1 brings the
    target back."""
    root_nt = halted.symbols["nt!KeBugCheckEx"]
    guest = select_windows_guest(halted)
    try:
        assert halted.partition == guest.id
        cpus = list(halted.cpus)
        assert [cpu.id for cpu in cpus] == [
            f"p{guest.id:x}.{vp.index + 1:x}" for vp in guest.virtual_processors
        ]
        guest_nt = halted.symbols["nt!KeBugCheckEx"]
        nt = halted.modules["nt"]
        assert guest_nt != root_nt and nt.base <= guest_nt < nt.base + nt.size
        assert halted.processes.find("System")
        assert any(
            (frame.symbol or "").startswith("nt!") for cpu in cpus for frame in cpu.backtrace(limit=8)
        )
        # Used only by a bugcheck, and restored before the guest runs again.
        data = halted.symbols["nt!KiBugCheckData"]
        original = halted.memory.read(data, 8)
        try:
            halted.memory.write(data, bytes(range(1, 9)))
            assert halted.memory.read(data, 8) == bytes(range(1, 9))
        finally:
            halted.memory.write(data, original)
        assert halted.memory.read(data, 8) == original
    finally:
        halted.select_partition(1)
    assert halted.partition is None
    assert halted.symbols["nt!KeBugCheckEx"] == root_nt


def test_a_guest_partitions_breakpoint_stops_in_its_view(halted: Debugger) -> None:
    """A hardware breakpoint set in a guest partition's view is the
    partition's: a run leaves the view, and the hit shows it again on the VP
    that ran the code, its stack in the partition's NT, and a step from there
    goes on in the same function; a software one is refused there."""
    if os.environ.get("NTOSEYE_TEST_BACKEND") != "gdb":
        pytest.skip("only a debug register the host programs traps in a guest partition")
    guest = select_windows_guest(halted)
    try:
        # Every context switch runs it, so even an idle guest does soon.
        swap = halted.symbols["nt!KiSwapContext"]
        with pytest.raises(ntoseye.NtoseyeError, match="only hardware breakpoints"):
            halted.breakpoints.add(swap)
        bp = halted.breakpoints.add(swap, hardware=True)
        assert bp.partition is not None and bp.partition.partition == guest.id
        deleted = False
        try:
            stop = halted.run(timeout=30.0)
            assert stop is not None and bp in stop.breakpoints, stop
            assert halted.partition == guest.id
            vps = [f"p{guest.id:x}.{vp.index + 1:x}" for vp in guest.virtual_processors]
            assert stop.cpu.id in vps
            assert stop.rip == swap
            assert stop.cpu.backtrace(limit=1)[0].symbol == "nt!KiSwapContext"
            # Every context switch runs it: left set, it stops the step on
            # another VP's hit before the step's own site.
            bp.delete()
            deleted = True
            step = halted.step()
            assert isinstance(step, ntoseye.Stop.Step), step
            assert halted.partition == guest.id
            assert (step.symbol or "").startswith("nt!KiSwapContext+"), step.symbol
        finally:
            if not deleted:
                bp.delete()
    finally:
        halted.select_partition(1)
    assert halted.partition is None


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
    found = next(
        (
            (cpu, saved)
            for cpu in halted.cpus
            for saved in cpu.saved_vtl
            if saved.current
        ),
        None,
    )
    if found is None:
        pytest.skip("no vCPU halted in the Windows hypervisor with saved VTL state (needs VBS and hv-evmcs)")
    cpu, current = found
    host_rip = current.host_rip
    first_call = next(ins.ip for ins in cpu.memory.disassemble(host_rip, 64) if ins.mnemonic == "call")
    # The halt can catch the vCPU in the entry code before its last store,
    # with this exit's registers not yet saved.
    saving = host_rip <= cpu.registers["rip"] < first_call
    assert current.general_registers is not None or current.may_be_stale or saving
    compared = 0
    for _ in range(ATTEMPTS * 10):
        if compared == ATTEMPTS:
            break
        entry = halted.breakpoints.add(host_rip, hardware=True)
        try:
            stop = halted.run(timeout=10.0)
        finally:
            entry.delete()
        assert isinstance(stop, Stop.Breakpoint)
        exiting = stop.cpu
        truth = {name: exiting.registers[name] for name in GPRS}
        # The entry also takes the exits of a guest partition's VP (a Hyper-V
        # VM or WSL2 inside the target), whose eVMCS is then the current one:
        # none of the root VP's states is, and they hold no registers of it.
        at_entry = next((saved for saved in exiting.saved_vtl if saved.current), None)
        if at_entry is None:
            continue
        compared += 1
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
    assert compared == ATTEMPTS, f"only {compared} exits of the root partition's VPs were caught"


def test_hypercall_breakpoint_stops_only_for_its_call_and_caller(halted: Debugger) -> None:
    """A hypercall breakpoint on the root partition's synthetic IPIs stops
    where the root's VP on that processor made that call: its current saved
    state holds the code in RCX's low 16 bits. With a VP index, the stop is
    on that VP's processor, as the root's VPs are pinned to the processors
    with their numbers. A hit whose caller is unknown stops too, so only the
    stops with a known caller are checked. A root VP can go many seconds
    without the call (its processor parked by Windows at low load), so the
    VP is one seen making it."""
    if os.environ.get("NTOSEYE_TEST_BACKEND") != "gdb":
        pytest.skip("breakpoints in the Windows hypervisor require the host GDB backend")
    try:
        partitions = halted.hypervisor_partitions()
    except ntoseye.NtoseyeError as error:
        pytest.skip(f"no Windows hypervisor partitions on this target: {error}")
    root = partitions[0]
    with pytest.raises(ValueError):
        halted.breakpoints.add_hypercall("HvCallUnimplemented")
    with pytest.raises(ValueError):
        halted.breakpoints.add_hypercall(0x000B, max(p.id for p in partitions) + 1)

    def known_callers(index: int | None) -> list[ntoseye.Cpu]:
        bp = halted.breakpoints.add_hypercall("HvCallSendSyntheticClusterIpi", root.id, index)
        callers = []
        try:
            hypercall = bp.hypercall
            assert hypercall is not None
            assert (hypercall.code, hypercall.partition, hypercall.vp) == (0x000B, root.id, index)
            for _ in range(ATTEMPTS * 3):
                stop = halted.run(timeout=10.0)
                assert isinstance(stop, Stop.Breakpoint) and bp in stop.breakpoints
                saved = next((saved for saved in stop.cpu.saved_vtl if saved.current), None)
                if saved is None or saved.general_registers is None:
                    continue
                assert saved.general_registers.rcx & 0xFFFF == 0x000B
                if index is not None:
                    assert stop.cpu == halted.cpus[index]
                callers.append(stop.cpu)
        finally:
            bp.delete()
        assert callers, "no stop had a known caller"
        return callers

    caller = known_callers(None)[-1]
    known_callers(list(halted.cpus).index(caller))


def test_a_hypercall_stop_decodes_the_call_from_the_callers_registers(halted: Debugger) -> None:
    """At a stop on the root partition's synthetic IPIs, the current saved
    state's decoded hypercall is the one its registers hold: the input value
    is RCX, and the TLFS fields of a fast call are RDX (vector, then target
    VTL) and R8 (processor mask). The processor handles the root's exit, so
    a guest VP it serves is not the current one."""
    if os.environ.get("NTOSEYE_TEST_BACKEND") != "gdb":
        pytest.skip("breakpoints in the Windows hypervisor require the host GDB backend")
    try:
        root = halted.hypervisor_partitions()[0]
    except ntoseye.NtoseyeError as error:
        pytest.skip(f"no Windows hypervisor partitions on this target: {error}")
    bp = halted.breakpoints.add_hypercall("HvCallSendSyntheticClusterIpi", root.id)
    decoded = 0
    try:
        for _ in range(ATTEMPTS * 3):
            stop = halted.run(timeout=10.0)
            assert isinstance(stop, Stop.Breakpoint) and bp in stop.breakpoints
            saved = next((saved for saved in stop.cpu.saved_vtl if saved.current), None)
            if saved is None or saved.general_registers is None:
                continue
            call = saved.hypercall
            assert call is not None
            registers = saved.general_registers
            assert (call.input_value, call.code, call.name) == (
                registers.rcx,
                0x000B,
                "HvCallSendSyntheticClusterIpi",
            )
            assert call.summary.startswith("hypercall 0x000b HvCallSendSyntheticClusterIpi")
            assert [field.name for field in call.fields] == ["Vector", "TargetVtl", "ProcessorMask"]
            if call.fast:
                assert (call.input_gpa, call.output_gpa) == (None, None)
                vector, target_vtl, mask = (field.value for field in call.fields)
                assert vector == registers.rdx & 0xFFFF_FFFF
                assert target_vtl == (registers.rdx >> 32) & 0xFF
                assert mask == registers.r8
            else:
                assert call.input_gpa == registers.rdx
            served = stop.cpu.serving
            assert served is None or not served.current
            decoded += 1
    finally:
        bp.delete()
    assert decoded > 0, "no stop had the caller's registers"


# The bytes of a VMCALL, and a condition that holds for every real one: the
# caller's code at its RIP, read through the calling VTL's page tables.
VMCALL = bytes.fromhex("0f01c1")
AT_VMCALL = "(dwo(rip) & 0xffffff) == 0xc1010f"
NOT_AT_VMCALL = "(dwo(rip) & 0xffffff) != 0xc1010f"
# The fast bit of a hypercall input value (RCX) is clear: the input is in
# memory, at the guest physical address in RDX.
SLOW = "(rcx & 0x10000) == 0"
# HV_FLUSH_USE_EXTENDED_RANGE_FORMAT in a flush's Flags.
EXTENDED_RANGES = 1 << 3


def hypervisor_root(halted: Debugger) -> ntoseye.HypervisorPartition:
    """The root partition, whose flushes are frequent; skips without the
    host GDB backend or the hypervisor's partitions (`hv-evmcs`)."""
    if os.environ.get("NTOSEYE_TEST_BACKEND") != "gdb":
        pytest.skip("breakpoints in the Windows hypervisor require the host GDB backend")
    try:
        return halted.hypervisor_partitions()[0]
    except ntoseye.NtoseyeError as error:
        pytest.skip(f"no Windows hypervisor partitions on this target: {error}")


def gva_range(value: int, extended: bool) -> tuple[int, str]:
    """The first GVA of a flush's GVA range, and what it means. The extended
    format counts the pages after the first in bits 10:0, and bit 11 selects
    large pages, whose size is bit 12 (2 MiB or 1 GiB) and whose GVA is bits
    63:21; the TLFS's counts them in bits 11:0. A 4 KiB page's GVA is bits
    63:12."""
    count = (value & (0x7FF if extended else 0xFFF)) + 1
    if not extended or not value & (1 << 11):
        gva = value & ~0xFFF
        return gva, f"{gva:#x}, {count} page{'s' if count > 1 else ''}"
    gva = value & ~0x1F_FFFF
    return gva, f"{gva:#x}, {count} of {'1 GiB' if value & (1 << 12) else '2 MiB'}"


def test_flush_gva_ranges_decode_in_the_format_their_flags_select(halted: Debugger) -> None:
    """The root partition's HvCallFlushVirtualAddressList sets
    HV_FLUSH_USE_EXTENDED_RANGE_FORMAT, which the TLFS does not describe:
    each decoded GvaRange means what that layout makes of its raw value, and
    names a canonical GVA. The list follows the three header fields, in
    memory for a slow call and in the XMM registers for a fast one."""
    root = hypervisor_root(halted)
    bp = halted.breakpoints.add_hypercall("HvCallFlushVirtualAddressList", root.id)
    extended = 0
    try:
        for _ in range(ATTEMPTS):
            stop = halted.run(timeout=10.0)
            assert isinstance(stop, Stop.Breakpoint) and bp in stop.breakpoints
            caller = stop.cpu.hypercall_caller()
            assert caller is not None and caller.partition_id == root.id
            call = caller.hypercall
            assert call is not None and call.code == 0x0003
            flags = next(field.value for field in call.fields if field.name == "Flags")
            assert len(call.elements) == call.rep_count
            for element in call.elements:
                (field,) = element.fields
                assert (field.name, field.offset, field.size) == ("GvaRange", 24 + 8 * element.index, 8)
                gva, meaning = gva_range(field.value, bool(flags & EXTENDED_RANGES))
                assert field.meaning == meaning, f"GvaRange {field.value:#x}"
                assert gva >> 47 in (0, 0x1FFFF), f"GvaRange {field.value:#x} is not canonical"
                extended += bool(flags & EXTENDED_RANGES)
    finally:
        bp.delete()
    if not extended:
        pytest.skip("the root partition's flushes did not use the extended range format")


def test_a_hypercall_condition_reads_the_callers_memory(halted: Debugger) -> None:
    """A hypercall breakpoint's condition reads the caller's memory, not the
    hypervisor's: its virtual memory at its RIP holds the VMCALL, so a
    condition that tests for it holds at every hit and its negation at none,
    without an error; and its guest physical memory at a slow call's input
    GPA holds the input that the stop decodes. The root partition flushes
    every address space, so the first field of its flushes, AddressSpace, is
    0, and the Flags field that follows it varies. The root's guest physical
    addresses are host physical ones, so only the virtual read tells the
    caller's memory from the hypervisor's."""
    root = hypervisor_root(halted)
    bp = halted.breakpoints.add_hypercall(0x0003, root.id, condition=AT_VMCALL)
    try:
        for _ in range(ATTEMPTS):
            stop = halted.run(timeout=10.0)
            assert isinstance(stop, Stop.Breakpoint) and bp in stop.breakpoints
            assert stop.condition_error is None
    finally:
        bp.delete()
    bp = halted.breakpoints.add_hypercall(0x0003, root.id, condition=NOT_AT_VMCALL)
    try:
        stop = halted.run(timeout=2.0)
        assert stop is None, f"stopped at {stop!r}"
    finally:
        halted.interrupt()
        bp.delete()
    flags = 0xF
    bp = halted.breakpoints.add_hypercall(
        0x0003, root.id, condition=f"{SLOW} && $pqwo(rdx) == 0 && $pqwo(rdx + 8) == {flags:#x}"
    )
    try:
        stop = halted.run(timeout=30.0)
        assert isinstance(stop, Stop.Breakpoint) and bp in stop.breakpoints, "no slow flush of the root in 30 s"
        assert stop.condition_error is None
        caller = stop.cpu.hypercall_caller()
        assert caller is not None and caller.hypercall is not None
        call = caller.hypercall
        assert not call.fast and call.input_gpa == caller.registers["rdx"]
        assert [(field.name, field.value) for field in call.fields[:2]] == [("AddressSpace", 0), ("Flags", flags)]
    finally:
        bp.delete()


def test_a_hypercall_callback_reads_its_caller(halted: Debugger) -> None:
    """In a `when=` callback, `Cpu.hypercall_caller()` reads the caller at
    its VMCALL: the call's bytes at its RIP, and for a slow call the input
    GPA in its RDX. A vCPU that runs NT, not the hypervisor, has no caller."""
    root = hypervisor_root(halted)
    callers: list[ntoseye.HypercallCaller | None] = []
    code: list[bytes] = []
    inputs: list[tuple[int, int | None]] = []
    in_nt: list[ntoseye.HypercallCaller | None] = []

    def check(stop: Stop) -> bool:
        caller = stop.cpu.hypercall_caller()
        callers.append(caller)
        if caller is None or caller.hypercall is None:
            return True
        code.append(caller.read(caller.registers["rip"], len(VMCALL)))
        if not caller.hypercall.fast:
            inputs.append((caller.registers["rdx"], caller.hypercall.input_gpa))
        # Most flushes are fast; a slow one can take a hundred hits.
        if len(in_nt) < ATTEMPTS:
            in_nt.extend(cpu.hypercall_caller() for cpu in halted.cpus if cpu.process is not None)
        return len(code) >= ATTEMPTS and bool(inputs) and bool(in_nt)

    bp = halted.breakpoints.add_hypercall(0x0003, root.id, when=check)
    try:
        stop = halted.run(timeout=30.0)
    finally:
        halted.interrupt()
        bp.delete()
    assert isinstance(stop, Stop.Breakpoint) and bp in stop.breakpoints, (
        "no slow flush of the root, or no vCPU in NT at a flush, in 30 s"
    )
    assert stop.condition_error is None
    assert all(caller is not None and caller.partition_id == root.id and caller.root for caller in callers)
    assert set(code) == {VMCALL}
    assert all(rdx == gpa for rdx, gpa in inputs)
    assert in_nt and all(caller is None for caller in in_nt)


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
    pytest.fail(
        f"in all {ATTEMPTS} attempts the breakpoint was not reached within 10 s or the step was "
        "diverted into an interrupt handler"
    )


def secure_step_scenario(halted: Debugger, address: int) -> bool:
    """Step in the secure kernel and step out; `False` when the step was
    diverted into an interrupt handler, which leaves nothing to check, or
    when the secure kernel did not reach the breakpoint in time (a busy
    guest can keep VTL1 from switching address spaces for long)."""
    bp = halted.breakpoints.add(address, hardware=True)
    try:
        stop = halted.run(timeout=10.0)
        if isinstance(stop, Stop.Interrupt):
            return False
        assert isinstance(stop, Stop.Breakpoint)
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


def test_imported_image_lands_under_its_own_key(halted: Debugger, tmp_path: Path) -> None:
    """A PE file copied in with import_image is filed under the TimeDateStamp
    and SizeOfImage of its own header, where a lookup for that build finds
    it."""
    pe = bytearray(0x200)
    pe[0:2] = b"MZ"
    pe[0x3C:0x40] = (0x80).to_bytes(4, "little")
    pe[0x80:0x84] = b"PE\0\0"
    pe[0x84:0x86] = (0x8664).to_bytes(2, "little")
    pe[0x88:0x8C] = (0x7E57_0001).to_bytes(4, "little")
    pe[0x94:0x96] = (240).to_bytes(2, "little")
    pe[0x98:0x9A] = (0x20B).to_bytes(2, "little")
    pe[0x98 + 56 : 0x98 + 60] = (0x3000).to_bytes(4, "little")
    pe[0x98 + 60 : 0x98 + 64] = (0x200).to_bytes(4, "little")
    source = tmp_path / "ntoseyetest.exe"
    source.write_bytes(bytes(pe))
    imported = Path(halted.symbols.import_image(str(source)))
    assert imported.parts[-3:] == ("ntoseyetest.exe", "7E5700013000", "ntoseyetest.exe")
    assert imported.read_bytes() == bytes(pe)


def test_a_vm_exit_breakpoint_stops_on_its_reason_from_its_caller(halted: Debugger) -> None:
    """A VM-exit breakpoint stops only on exits with its reason from its
    caller: each stop's caller is the root partition, and the instruction at
    the caller's RIP, read from the caller's registers and memory rather
    than the hypervisor's at the entry, is the RDMSR that made the exit.
    About 40% of the root's exits are other ones (external interrupts,
    WRMSRs), so ten stops make a filter that let them through stop on one
    all but certainly."""
    root = hypervisor_root(halted)
    bp = halted.breakpoints.add_exit("rdmsr", root.id)
    try:
        assert bp.vm_exit is not None and bp.vm_exit.reason == 31
        for _ in range(10):
            stop = halted.run(timeout=10.0)
            assert isinstance(stop, Stop.Breakpoint) and bp in stop.breakpoints
            caller = stop.cpu.hypercall_caller()
            assert caller is not None and caller.partition_id == root.id
            assert caller.read(caller.registers["rip"], 2) == b"\x0f\x32"
    finally:
        bp.delete()
