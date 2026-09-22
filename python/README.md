# ntoseye (Python SDK)

Drive the [ntoseye](https://github.com/dmaivel/ntoseye) Windows kernel debugger
from Python.

## Install

```sh
pip install ntoseye
```

Or build from source into a virtualenv with maturin:

```sh
cd python
python3 -m venv .venv
source .venv/bin/activate
maturin develop --release
```

Or build a wheel and install it:

```sh
cd python
maturin build --release --out dist
pip install dist/ntoseye-*.whl
```

## Releasing portable wheels

Release wheels are built by `.github/workflows/release.yml` with `PyO3/maturin-action` on native GitHub runners:

- Linux x86-64 and ARM64 build on `ubuntu-22.04` and `ubuntu-24.04-arm` inside the `quay.io/pypa/manylinux_2_28_*` images, producing `manylinux_2_28` wheels.
- Apple Silicon uses the native ARM64 `macos-14` runner.

Each wheel then passes `twine check` and an import test in a clean virtual environment before upload.

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