# ntoseye (Python SDK)

Drive the [ntoseye](https://github.com/dmaivel/ntoseye) Windows kernel debugger
from Python.

## Install

```sh
pip install ntoseye
```

Or build from source into a virtualenv with maturin:

```sh
cd ntoseye-py
python3 -m venv .venv
source .venv/bin/activate
maturin develop --release
```

Or build a wheel and install it:

```sh
cd ntoseye-py
maturin build --release --out dist
pip install dist/ntoseye-*.whl
```

## Releasing portable wheels

Release wheels are built by `.github/workflows/release.yml` on native GitHub runners:

- Linux x86-64 uses Zig and targets `manylinux_2_17`.
- Apple Silicon uses the native ARM64 `macos-14` runner.

Both wheels are smoke-tested, attached to the GitHub Release, and published to PyPI with Trusted Publishing.

For local reproduction, `./build-wheel.sh` provisions a local `.venv`, builds into `dist/`, runs `twine check`, and installs/import-tests the wheel in a throwaway virtual environment. It does not publish.