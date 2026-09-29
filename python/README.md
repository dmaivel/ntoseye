# ntoseye

This package lets you control the [ntoseye](https://github.com/dmaivel/ntoseye)
Windows kernel debugger from Python and run it from the command line.

For address-space-bound views and run control, see
[`docs/scripting/sdk.md`](../docs/scripting/sdk.md).

The package also installs the `ntoseye` command, which gives you the REPL,
`ntoseye mcp`, `dap`, and `gdbserver`, and runs Python custom commands from
`~/.ntoseye/commands/`. To install the command in its own environment, run
`uv tool install ntoseye` or `pipx install ntoseye`.

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

For read-only inspection of a paused VM, select `backend="memory"`.

`dbg.processes` holds process handles keyed by PID (`dbg.processes[pid]`), and
each process gives its own memory and modules through `proc.memory` and
`proc.modules`.

## Type stubs

PyO3 introspection generates `ntoseye/_ntoseye.pyi` from the extension, taking
the signatures from the Rust types and the docstrings from the doc comments.

CI fails when the stub in the repository differs from a newly generated one, so
after you change the Rust surface, regenerate the stub and commit the result:

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

The last command also runs `tests/test_live.py` on a guest, which breaks in,
steps, sets breakpoints on hot kernel functions, and resumes the guest.

By default (`auto`), the tests read guest memory from the VM process when they
can. Add `NTOSEYE_TEST_MEMORY_SOURCE=kd` to read it over KD instead, which
needs no root for UTM on macOS and is required for a remote target.

## Releasing portable wheels

The workflow `.github/workflows/release.yml` builds the release wheels with `PyO3/maturin-action` on native GitHub runners:

- The Linux x86-64 and ARM64 wheels build on `ubuntu-22.04` and `ubuntu-24.04-arm` inside the `quay.io/pypa/manylinux_2_28_*` images, which makes them `manylinux_2_28` wheels.
- The Apple Silicon wheel builds on the native ARM64 `macos-14` runner.

Before the upload, each wheel must pass `twine check` and the target-free tests (`tests/test_surface.py`) in a clean virtual environment.

To make a Linux release wheel locally, run this from the repository root (Docker is required):

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