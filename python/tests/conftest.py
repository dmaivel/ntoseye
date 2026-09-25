"""Live tests attach to a guest named by the environment:

    NTOSEYE_TEST_BACKEND=kd NTOSEYE_TEST_CONNECT=/tmp/ntoseye-kd.sock pytest python/tests

Without `NTOSEYE_TEST_BACKEND` they are skipped. The target is broken into
and resumed; every breakpoint a test adds is removed afterwards.

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


@pytest.fixture(scope="session")
def dbg() -> Iterator[ntoseye.Debugger]:
    backend = os.environ.get("NTOSEYE_TEST_BACKEND")
    if not backend:
        pytest.skip("set NTOSEYE_TEST_BACKEND (and NTOSEYE_TEST_CONNECT) to test against a guest")
    with ntoseye.attach(
        backend,  # type: ignore[arg-type]
        os.environ.get("NTOSEYE_TEST_CONNECT"),
        memory_source=os.environ.get("NTOSEYE_TEST_MEMORY_SOURCE", "auto"),  # type: ignore[arg-type]
    ) as dbg:
        yield dbg


@pytest.fixture
def halted(dbg: ntoseye.Debugger) -> Iterator[ntoseye.Debugger]:
    """The debugger with the target halted; breakpoints are removed after."""
    dbg.interrupt()
    yield dbg
    dbg.interrupt()
    for bp in list(dbg.breakpoints):
        bp.delete()
