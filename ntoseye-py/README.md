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

Run `./build-wheel.sh` on each release platform. The script provisions a local `.venv` when needed, builds into a clean `dist/`, runs `twine check`, and verifies the wheel in a throwaway virtualenv.

- Linux builds use Zig and target `manylinux_2_17` so the wheel installs on non-EOL glibc distributions.
- Apple Silicon macOS builds produce a native ARM64 wheel.

Equivalent Linux build:

```sh
pip install maturin ziglang twine
maturin build --release --zig --compatibility manylinux_2_17 --out dist
```

Equivalent Apple Silicon macOS build:

```sh
pip install maturin twine
maturin build --release --out dist
```

Check and publish either wheel:

```sh
python -m twine check dist/*
python -m twine upload dist/*
```