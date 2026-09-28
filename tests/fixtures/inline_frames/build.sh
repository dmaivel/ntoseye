#!/bin/sh
# Rebuilds ../inline_frames.pdb, the PDB with inline sites the symbol tests
# read. Source paths are remapped so the PDB records `C:/inline_frames/...`
# and `C:/rust/...` rather than this machine's paths.
set -eu
cd "$(dirname "$0")"
sysroot=$(rustc --print sysroot)
cargo build --release --config \
    "target.x86_64-pc-windows-msvc.rustflags=['--remap-path-prefix=$PWD=C:/inline_frames', '--remap-path-prefix=$sysroot=C:/rust']"
cp target/x86_64-pc-windows-msvc/release/inline_frames.pdb ../inline_frames.pdb
