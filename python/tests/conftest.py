"""Live tests attach to a guest named by the environment:

    NTOSEYE_TEST_BACKEND=kd NTOSEYE_TEST_CONNECT=/tmp/ntoseye-kd.sock pytest python/tests

Without `NTOSEYE_TEST_BACKEND` they are skipped. The target is broken into
and resumed; every breakpoint a test adds is removed afterwards.

`NTOSEYE_TEST_KEY` is the KDNET key (`backend=kdnet`).

`NTOSEYE_TEST_MEMORY_SOURCE` (`auto`, `host`, or `kd`; default `auto`) picks
the KD/KDNET memory source. `kd` needs no access to the VM process, which
is how to run these without root against UTM on macOS or against a remote
target.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

import ntoseye


def attach_from_env() -> ntoseye.Debugger:
    """A debugger attached to the guest the environment names, or a skip."""
    backend = os.environ.get("NTOSEYE_TEST_BACKEND")
    if not backend:
        pytest.skip("set NTOSEYE_TEST_BACKEND (and NTOSEYE_TEST_CONNECT) to test against a guest")
    return ntoseye.attach(
        backend,  # type: ignore[arg-type]
        os.environ.get("NTOSEYE_TEST_CONNECT"),
        key=os.environ.get("NTOSEYE_TEST_KEY"),
        memory_source=os.environ.get("NTOSEYE_TEST_MEMORY_SOURCE", "auto"),  # type: ignore[arg-type]
    )


# One session per test file: a target takes one session at a time, so a
# file that closes its session and attaches again (to check what a detach
# left behind) must not find another file's session still holding it.
@pytest.fixture(scope="module")
def dbg() -> Iterator[ntoseye.Debugger]:
    with attach_from_env() as dbg:
        yield dbg


@pytest.fixture
def halted(dbg: ntoseye.Debugger) -> Iterator[ntoseye.Debugger]:
    """The debugger with the target halted; breakpoints are removed after."""
    dbg.interrupt()
    yield dbg
    dbg.interrupt()
    for bp in list(dbg.breakpoints):
        bp.delete()
