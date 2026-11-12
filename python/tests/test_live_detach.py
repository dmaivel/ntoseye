"""What a session leaves in the guest once it is closed, on a live guest
(see `conftest.py`). A file of its own: it opens and closes its sessions,
which another file's session would hold the target against.
"""

from __future__ import annotations

from conftest import attach_from_env
from ntoseye import Debugger

# Never run while the guest is up.
COLD = "nt!NtShutdownSystem"


def raw(dbg: Debugger, address: int, size: int) -> bytes:
    """The bytes physical memory holds at `address`, which no masking of
    the debugger's own sites touches."""
    physical = dbg.memory.translate(address)
    assert physical is not None, f"{address:#x} is not resident"
    return dbg.physical.read(physical, size)


def test_a_detach_leaves_nothing_behind() -> None:
    """Close a session with a breakpoint planted, a run to an address still
    handed back and the guest running; a fresh session finds the code as it
    was, nothing stranded in the target's breakpoint table, and nothing a
    previous session left to restore."""
    with attach_from_env() as dbg:
        dbg.interrupt()
        address = dbg.symbols[COLD]
        original = dbg.memory.read(address, 8)
        dbg.breakpoints.add(COLD)
        dbg.command("g nt!NtSetSystemPowerState", timeout=0.3)
        assert dbg.stop is None, "the guest should still be running"
    with attach_from_env() as dbg:
        dbg.interrupt()
        assert not list(dbg.breakpoints)
        assert raw(dbg, address, 8) == original
        left = [
            notice.text
            for notice in dbg.notices()
            if "stranded" in notice.text or "previous session" in notice.text
        ]
        assert not left, left
