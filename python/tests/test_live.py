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


@contextmanager
def ctrl_c_after(seconds: float) -> Iterator[None]:
    timer = threading.Timer(seconds, os.kill, (os.getpid(), signal.SIGINT))
    timer.start()
    try:
        yield
    finally:
        timer.cancel()


def require_single_step(dbg: Debugger) -> None:
    # Refused over the GDB stub while Windows runs its own hypervisor.
    if not any(row.capability == "single_step" and row.supported for row in dbg.capabilities):
        pytest.skip("this target refuses single steps")


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
    assert isinstance(halted.step_over(until="call"), Stop.Step)
    assert isinstance(halted.step_out(), Stop.Step)


def test_run_to_symbol_stops_there(halted: Debugger) -> None:
    stop = halted.run_to("nt!NtClose", timeout=10.0)
    assert isinstance(stop, Stop.Step)
    assert stop.rip == halted.symbols["nt!NtClose"]


def test_trace_calls_returns_a_call_tree(halted: Debugger) -> None:
    require_single_step(halted)
    # gdb single-steps at a few hundred instructions a second.
    trace = halted.trace_calls(limit=2_000)
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


def gdb_secure_kernel(halted: Debugger) -> ntoseye.SecureKernel:
    if os.environ.get("NTOSEYE_TEST_BACKEND") != "gdb":
        pytest.skip("VTL1 hardware execution requires the host GDB backend")
    try:
        return halted.secure_kernel
    except ntoseye.NtoseyeError as error:
        pytest.skip(f"no VTL1 on this target: {error}")


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
    bp = halted.breakpoints.add(address, hardware=True)
    try:
        assert isinstance(halted.run(timeout=10.0), Stop.Breakpoint)
        bp.delete()
        # Which sites a step plants is pinned by the Rust unit tests; this is
        # the live path. step_out's run-to site goes through the breakpoint
        # manager, which refuses a software site in the secure kernel.
        step = halted.step()
        assert isinstance(step, Stop.Step)
        # Usually the next instruction; an interrupt taken on resume can
        # instead leave the step in a secure-kernel handler.
        assert step.rip != address
        assert (step.symbol or "").startswith("securekernel!")
        out = halted.step_out()
        assert isinstance(out, Stop.Step)
        assert (out.symbol or "").startswith("securekernel!")
        assert out.thread is None
        assert not list(halted.breakpoints), "a temporary site was left behind"
    finally:
        halted.interrupt()
        if bp.valid:
            bp.delete()
