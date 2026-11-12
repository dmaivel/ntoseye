"""What a breakpoint leaves in the guest, and what reads see under one, on a
live guest (see `conftest.py`). Each test pins a defect a sweep of the
debugger found: an `int3` left behind, a write that took the `int3` for the
code, a read that showed it, a run that left its site armed.

The code these tests write to and plant on is `nt!NtShutdownSystem`, which
the guest does not run while it is up, so a changed byte there is never
executed; every test puts the code back.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from ntoseye import Debugger, Stop

# Never run while the guest is up.
COLD = "nt!NtShutdownSystem"
# Called by every process many times a second.
BUSY = "nt!NtClose"


def raw(dbg: Debugger, address: int, size: int) -> bytes:
    """The bytes physical memory holds at `address`, which no masking of
    the debugger's own sites touches."""
    physical = dbg.memory.translate(address)
    assert physical is not None, f"{address:#x} is not resident"
    return dbg.physical.read(physical, size)


def require_single_step(dbg: Debugger) -> None:
    if not any(row.capability == "single_step" and row.supported for row in dbg.capabilities):
        pytest.skip("this target refuses single steps")


@pytest.fixture
def cold(halted: Debugger) -> Iterator[tuple[int, bytes]]:
    """`COLD`'s address and first 8 bytes, put back after the test."""
    address = halted.symbols[COLD]
    original = halted.memory.read(address, 8)
    yield address, original
    halted.interrupt()
    for bp in list(halted.breakpoints):
        bp.delete()
    if halted.memory.read(address, 8) != original:
        halted.memory.write(address, original)


def test_reads_under_a_breakpoint_show_the_code(halted: Debugger, cold: tuple[int, bytes]) -> None:
    address, original = cold
    halted.breakpoints.add(COLD)
    # Every way of reading the code sees what the guest runs, not the
    # breakpoint instruction: a byte view, a one-byte read (on ARM64 the
    # instruction is four bytes, so a short read covers only part of it),
    # expressions, and a typed field over it.
    assert halted.memory.read(address, 8) == original
    assert halted.memory.read_u8(address) == original[0]
    assert halted.eval(f"by({COLD})") == original[0]
    assert halted.eval(f"wo({COLD})") == int.from_bytes(original[:2], "little")
    assert halted.eval(f"dwo({COLD}+1)") == int.from_bytes(original[1:5], "little")
    data1 = halted.types["nt!_GUID"].at(address).Data1
    assert data1 == int.from_bytes(original[:4], "little")


def test_a_deleted_breakpoint_leaves_the_code_as_it_was(
    halted: Debugger, cold: tuple[int, bytes]
) -> None:
    address, original = cold
    bp = halted.breakpoints.add(COLD)
    bp.delete()
    assert raw(halted, address, 8) == original


def test_a_write_over_a_breakpoint_changes_the_code_and_keeps_the_breakpoint(
    halted: Debugger, cold: tuple[int, bytes]
) -> None:
    address, original = cold
    bp = halted.breakpoints.add(COLD)
    changed = bytes([original[0] ^ 0xFF]) + original[1:]
    halted.memory.write(address, changed[:1])
    assert halted.memory.read(address, 8) == changed
    assert bp.valid and bp.enabled
    # Copying the code onto itself through an expression must not copy the
    # breakpoint instruction: that left it in the guest for good.
    halted.command(f"eb {COLD} by({COLD})")
    assert halted.memory.read(address, 8) == changed
    bp.delete()
    assert raw(halted, address, 8) == changed


def test_run_to_an_address_leaves_no_breakpoint(halted: Debugger) -> None:
    stop = halted.run(timeout=10.0, address=BUSY)
    assert isinstance(stop, Stop.Step)
    assert not list(halted.breakpoints)


def test_a_run_handed_back_running_ends_at_the_stop_that_collects_it(halted: Debugger) -> None:
    # A command that outlasts its time hands its run back running, the run's
    # site armed; the stop a later call collects ends the run and removes the
    # site. Left armed, it stopped the thread at that address on every later
    # run.
    halted.command(f"g {BUSY}", timeout=0.0)
    stop = halted.stop or halted.wait(timeout=10.0)
    assert isinstance(stop, Stop.Step)
    assert not list(halted.breakpoints)
    assert halted.run(timeout=1.0) is None
    # One that never arrives ends at the break-in instead.
    halted.interrupt()
    halted.command(f"g {COLD}", timeout=0.3)
    assert [bp.address for bp in halted.breakpoints] == [halted.symbols[COLD]]
    halted.interrupt()
    assert not list(halted.breakpoints)


def test_a_step_that_times_out_leaves_no_breakpoint(halted: Debugger) -> None:
    require_single_step(halted)
    halted.run(timeout=10.0, address=BUSY)
    stop = halted.step_out(timeout=0.001)
    assert isinstance(stop, (Stop.Step, Stop.Interrupt))
    assert not list(halted.breakpoints)


def test_a_process_context_ends_when_the_target_runs(halted: Debugger) -> None:
    smss = halted.processes.find("smss.exe")
    if not smss:
        pytest.skip("no smss.exe to select")
    halted.command(f".process /p {smss[0].eprocess:#x}")
    stop = halted.run(timeout=10.0, address=BUSY)
    assert isinstance(stop, Stop.Step) and stop.process is not None
    # The context ended when the target ran: the stop is inspected in its
    # own process, not still in smss.
    scope = stop.inspection_process
    assert scope is None or scope.pid == stop.process.pid
