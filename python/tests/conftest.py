"""Live tests attach to a guest named by the environment:

    NTOSEYE_TEST_BACKEND=kd NTOSEYE_TEST_CONNECT=/tmp/ntoseye-kd.sock pytest python/tests

Without `NTOSEYE_TEST_BACKEND` they are skipped. The target is broken into
and resumed; every breakpoint a test adds is removed afterwards.
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
    with ntoseye.attach(backend, os.environ.get("NTOSEYE_TEST_CONNECT")) as dbg:  # type: ignore[arg-type]
        yield dbg


@pytest.fixture
def halted(dbg: ntoseye.Debugger) -> Iterator[ntoseye.Debugger]:
    """The debugger with the target halted; breakpoints are removed after."""
    dbg.interrupt()
    yield dbg
    dbg.interrupt()
    for bp in list(dbg.breakpoints):
        bp.delete()
