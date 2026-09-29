# ntoseye

This package lets you control the [ntoseye](https://github.com/dmaivel/ntoseye)
Windows kernel debugger from Python. It also lets you run the debugger from the
command line.

For address-space-bound views and run control, see
[`docs/scripting/sdk.md`](../docs/scripting/sdk.md).

The package also installs the `ntoseye` command. This command gives you the
REPL, `ntoseye mcp`, `dap`, and `gdbserver`. It runs Python custom commands from
`~/.ntoseye/commands/`. To install the command in its own environment, run
`uv tool install ntoseye` or `pipx install ntoseye`.

## Install

```sh
pip install ntoseye
```

You can also use maturin to build from source into a virtualenv:

```sh
cd python
python3 -m venv .venv
source .venv/bin/activate
pip install maturin
maturin develop --release
```

You can also build a wheel and install it:

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

`dbg.processes` contains process handles, with the PID as the key
(`dbg.processes[pid]`). To get the memory and the modules of one process, use
`proc.memory` and `proc.modules`.

## Type stubs

PyO3 introspection generates `ntoseye/_ntoseye.pyi` from the extension. The
signatures come from the Rust types. The docstrings come from the doc comments.

If you change the Rust surface, regenerate the stub and commit the result. CI
fails if the stub in the repository is different from a newly generated stub.
To regenerate the stub, run this command:

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

The last command also runs `tests/test_live.py` on a guest. This test does
these operations:

- It breaks in.
- It steps.
- It sets breakpoints on hot kernel functions.
- It resumes the guest.

By default, the tests read guest memory from the VM process. To read guest
memory over KD, add `NTOSEYE_TEST_MEMORY_SOURCE=kd`. With KD, UTM on macOS does
not need root. A remote target needs this variable.

## Releasing portable wheels

The workflow `.github/workflows/release.yml` builds the release wheels. It uses `PyO3/maturin-action` on native GitHub runners:

- The Linux x86-64 and ARM64 wheels build on `ubuntu-22.04` and `ubuntu-24.04-arm`, in the `quay.io/pypa/manylinux_2_28_*` images. These builds make `manylinux_2_28` wheels.
- The Apple Silicon wheel builds on the native ARM64 `macos-14` runner.

Before the upload, each wheel must pass `twine check` and the target-free tests (`tests/test_surface.py`). The workflow runs these checks in a clean virtual environment.

To make a Linux release wheel locally, you need Docker. Run this command from the repository root:

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