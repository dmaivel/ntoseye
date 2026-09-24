# ntoseye

Drive the [ntoseye](https://github.com/dmaivel/ntoseye) Windows kernel debugger
from Python, and run it from the command line.

The standalone SDK uses the 0.37 API; see [`docs/sdk.md`](../docs/sdk.md) for
address-space-bound views, run control, and the 0.36 migration table. The
package also installs the `ntoseye` command (the REPL, `ntoseye mcp`, `dap`,
and `gdbserver`), which runs Python custom commands from
`~/.ntoseye/commands/`: `uv tool install ntoseye` or `pipx install ntoseye`.

## Install

```sh
pip install ntoseye
```

Or build from source into a virtualenv with maturin:

```sh
cd python
python3 -m venv .venv
source .venv/bin/activate
pip install maturin
maturin develop --release
```

Or build a wheel and install it:

```sh
cd python
maturin build --release --out dist
pip install dist/ntoseye-*.whl
```

## Quick start

```python
import ntoseye

with ntoseye.attach() as dbg:  # defaults to the kd backend
    print(dbg.inspect.version())
    for proc in dbg.processes:
        print(proc.pid, proc.name)
```

For read-only inspection of a paused VM, select `backend="memory"`. Processes
are handles keyed by PID (`dbg.processes[pid]`); memory and modules for a
specific process are available through `proc.memory` and `proc.modules`.

## Type stubs

`ntoseye/_ntoseye.pyi` is generated from the extension by PyO3's
introspection: signatures come from the Rust types and docstrings from the
doc comments. After changing the Rust surface, regenerate it and commit the
result (CI fails when the checked-in stub differs from a fresh one):

```sh
maturin develop --release --generate-stubs
```

## Tests

```sh
pip install pytest mypy
pytest tests                        # target-free surface tests
mypy --strict -p ntoseye            # the stub and package type-check
NTOSEYE_TEST_BACKEND=kd NTOSEYE_TEST_CONNECT=/tmp/ntoseye-kd.sock pytest tests
```

The last line also runs `tests/test_live.py` against a guest: it breaks in,
steps, sets breakpoints on hot kernel functions, and resumes the guest.

## Releasing portable wheels
Release wheels are built by `.github/workflows/release.yml` with `PyO3/maturin-action` on native GitHub runners:

- Linux x86-64 and ARM64 build on `ubuntu-22.04` and `ubuntu-24.04-arm` inside the `quay.io/pypa/manylinux_2_28_*` images, producing `manylinux_2_28` wheels.
- Apple Silicon uses the native ARM64 `macos-14` runner.

Each wheel then passes `twine check` and the target-free tests (`tests/test_surface.py`) in a clean virtual environment before upload.

To reproduce a Linux release wheel locally (from the repository root, Docker required):

```sh
docker run --rm -e CARGO_TARGET_DIR=/tmp/target -e HOST_IDS="$(id -u):$(id -g)" \
  -v "$PWD":/io -w /io/python quay.io/pypa/manylinux_2_28_$(uname -m) bash -c '
  dnf install -y clang &&
  curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal &&
  source ~/.cargo/env &&
  /opt/python/cp312-cp312/bin/pip install maturin &&
  /opt/python/cp312-cp312/bin/maturin build --release --out dist --compatibility manylinux_2_28 &&
  chown -R "$HOST_IDS" dist'
```