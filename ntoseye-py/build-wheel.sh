#!/usr/bin/env bash
# Produces a portable manylinux_2_17 wheel on Linux or a native ARM64 wheel on
# Apple Silicon macOS, then runs `twine check` and an import test in a throwaway
# virtualenv. If no virtualenv is active, the script provisions a local .venv
# with the platform-specific build tools.
set -euo pipefail

cd "$(dirname "$0")"

# Use the active virtualenv if there is one; otherwise fall back to a local .venv
# (created on first run) so we never touch the system Python.
if [[ -z "${VIRTUAL_ENV:-}" ]]; then
    if [[ ! -d .venv ]]; then
        echo "==> creating .venv"
        python3 -m venv .venv
    fi
    # shellcheck disable=SC1091
    source .venv/bin/activate
fi

host_os="$(uname -s)"
host_arch="$(uname -m)"
tools=(maturin twine)
build_args=(--release --out dist)

case "$host_os" in
    Linux)
        if [[ "$host_arch" != "x86_64" ]]; then
            echo "error: Linux wheels are supported only on x86_64 (found $host_arch)" >&2
            exit 1
        fi
        tools+=(ziglang)
        build_label="manylinux_2_17"
        build_args+=(--zig --compatibility manylinux_2_17)
        ;;
    Darwin)
        if [[ "$host_arch" != "arm64" ]]; then
            echo "error: macOS wheels are supported only on Apple Silicon (found $host_arch)" >&2
            exit 1
        fi
        build_label="macOS ARM64"
        ;;
    *)
        echo "error: wheel builds are unsupported on $host_os" >&2
        exit 1
        ;;
esac

echo "==> ensuring build tools (${tools[*]})"
python -m pip install --quiet "${tools[@]}"

if [[ "$host_os" == "Linux" ]]; then
    zig_lib_dir="$(python -c "from pathlib import Path; import ziglang; print(Path(ziglang.__file__).parent / 'lib')")"
    zig_include_dir="$zig_lib_dir/libc/include"
    zig_bindgen_args="--target=x86_64-unknown-linux-gnu -isystem $zig_lib_dir/include -isystem $zig_include_dir/x86-linux-gnu -isystem $zig_include_dir/generic-glibc -isystem $zig_include_dir/x86-linux-any -isystem $zig_include_dir/any-linux-any"
    bindgen_args="${BINDGEN_EXTRA_CLANG_ARGS:-}"
    export BINDGEN_EXTRA_CLANG_ARGS="${bindgen_args:+$bindgen_args }$zig_bindgen_args"
fi

echo "==> building $build_label wheel"
rm -rf dist
maturin build "${build_args[@]}"
echo "==> twine check"
python -m twine check dist/*

# Import-test in a throwaway venv (not the build one): proves the wheel actually
# installs and re-exports its surface, which twine check never touches.
echo "==> import test"
smoke_venv="$(mktemp -d)"
trap 'rm -rf "$smoke_venv"' EXIT
python -m venv "$smoke_venv"
"$smoke_venv/bin/python" -m pip install --quiet --upgrade pip
"$smoke_venv/bin/python" -m pip install --quiet dist/*.whl
"$smoke_venv/bin/python" - <<'PY'
import ntoseye
print("version:", ntoseye.__version__)
assert hasattr(ntoseye, "attach"), "attach missing"
assert hasattr(ntoseye, "Debugger"), "Debugger missing"
for m in ("backtrace", "pte_walk", "read_struct", "disassemble"):
    assert hasattr(ntoseye.Debugger, m), f"Debugger.{m} missing"
print("import + surface OK")
PY

echo
echo "Wheel ready in dist/:"
ls -1 dist/*.whl
