#!/usr/bin/env python3
"""Fetch x64 or ARM64 Windows kernels (ntoskrnl.exe) and their PDBs, for tests.

Winbindex (https://winbindex.m417z.com) indexes every ntoskrnl.exe that
Windows Update has shipped, x64 and ARM64 in separate indexes, with the
timestamp and image size under which
Microsoft's symbol server files it. This downloads the images that the index
lists, checks each against the index's SHA-256, and then downloads the PDB
that the image's CodeView record names. Servicing updates of one build are
separate kernels: 26100 has dozens.

    python3 tools/fetch_ntoskrnl.py ~/ntoskrnl --builds 26100 --newest 2
    python3 tools/fetch_ntoskrnl.py ~/ntoskrnl --oldest 1 --newest 1
    python3 tools/fetch_ntoskrnl.py ~/ntoskrnl-arm64 --arch arm64 --oldest 1 --newest 1

Each version is saved as ntoskrnl-10.0.<build>.<revision>.exe with a
matching .pdb. Files that are already there are kept. The images and PDBs
are Microsoft's and not redistributable, so they stay in OUT_DIR. The Rust
test that reads them:

    NTOSEYE_NTOSKRNL_DIR=~/ntoskrnl \\
        cargo test --lib store_layout -- --ignored --nocapture
"""

from __future__ import annotations

import argparse
import concurrent.futures
import gzip
import hashlib
import json
import os
import struct
import urllib.error
import urllib.request

# Each architecture's index, and the PE machine type of its kernels.
INDEXES = {
    "amd64": (
        "https://winbindex.m417z.com/data/by_filename_compressed/ntoskrnl.exe.json.gz",
        0x8664,
    ),
    "arm64": (
        "https://m417z.com/winbindex-data-arm64/by_filename_compressed/ntoskrnl.exe.json.gz",
        0xAA64,
    ),
}
SYMBOLS = "https://msdl.microsoft.com/download/symbols"
USER_AGENT = "ntoseye-tools"


def get(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=300) as response:
        return response.read()


def versions(arch: str) -> list[dict]:
    """The kernels of `arch` the index lists, oldest build and revision
    first."""
    index, machine = INDEXES[arch]
    found = []
    for sha256, entry in json.loads(gzip.decompress(get(index))).items():
        info = entry.get("fileInfo") or {}
        version = info.get("version", "").split(" ")[0]
        parts = version.split(".")
        if (
            info.get("machineType") != machine
            or len(parts) != 4
            or not info.get("timestamp")
            or not info.get("virtualSize")
        ):
            continue
        found.append(
            {
                "version": version,
                "build": int(parts[2]),
                "revision": int(parts[3]),
                "timestamp": info["timestamp"],
                "image_size": info["virtualSize"],
                "sha256": sha256,
            }
        )
    return sorted(found, key=lambda item: (item["build"], item["revision"]))


def select(found: list[dict], builds: set[int], oldest: int, newest: int) -> list[dict]:
    """Every version of `builds` (all builds when empty), or only the
    `oldest` and `newest` revisions of each when either is given."""
    chosen = []
    for build in sorted({item["build"] for item in found}):
        if builds and build not in builds:
            continue
        of_build = [item for item in found if item["build"] == build]
        if oldest or newest:
            picked = of_build[:oldest] + of_build[max(len(of_build) - newest, 0) :]
            of_build = [item for item in of_build if item in picked]
        chosen.extend(of_build)
    return chosen


def codeview(image: bytes) -> tuple[str, str]:
    """The PDB name and the symbol server key (GUID then age) of the image's
    RSDS CodeView record."""
    pe = struct.unpack_from("<I", image, 0x3C)[0]
    sections = struct.unpack_from("<H", image, pe + 6)[0]
    optional_size = struct.unpack_from("<H", image, pe + 20)[0]
    optional = pe + 24
    # PE32+: data directories start at 112; the debug directory is entry 6.
    debug_rva, debug_size = struct.unpack_from("<II", image, optional + 112 + 6 * 8)
    table = optional + optional_size

    def file_offset(rva: int) -> int:
        for index in range(sections):
            header = table + index * 40
            virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from(
                "<IIII", image, header + 8
            )
            if virtual_address <= rva < virtual_address + max(virtual_size, raw_size):
                return raw_pointer + rva - virtual_address
        raise ValueError(f"RVA {rva:#x} is in no section")

    directory = file_offset(debug_rva)
    for entry in range(debug_size // 28):
        kind, _, rva, pointer = struct.unpack_from("<IIII", image, directory + entry * 28 + 12)
        if kind != 2 or image[pointer : pointer + 4] != b"RSDS":
            continue
        data1, data2, data3 = struct.unpack_from("<IHH", image, pointer + 4)
        data4 = image[pointer + 12 : pointer + 20]
        age = struct.unpack_from("<I", image, pointer + 20)[0]
        name = image[pointer + 24 : image.index(b"\0", pointer + 24)].decode()
        key = f"{data1:08X}{data2:04X}{data3:04X}{data4.hex().upper()}{age:X}"
        return os.path.basename(name.replace("\\", "/")), key
    raise ValueError("no RSDS CodeView record")


def save(path: str, data: bytes) -> None:
    partial = path + ".partial"
    with open(partial, "wb") as file:
        file.write(data)
    os.replace(partial, path)


def fetch(item: dict, out_dir: str) -> str:
    stem = os.path.join(out_dir, f"ntoskrnl-{item['version']}")
    image_path, pdb_path = stem + ".exe", stem + ".pdb"
    if os.path.exists(image_path):
        with open(image_path, "rb") as file:
            image = file.read()
    else:
        key = f"{item['timestamp']:08X}{item['image_size']:X}"
        image = get(f"{SYMBOLS}/ntoskrnl.exe/{key}/ntoskrnl.exe")
        if hashlib.sha256(image).hexdigest() != item["sha256"]:
            return f"{item['version']}: image does not match the index's SHA-256"
        save(image_path, image)
    if not os.path.exists(pdb_path):
        name, key = codeview(image)
        save(pdb_path, get(f"{SYMBOLS}/{name}/{key}/{name}"))
    return f"{item['version']}: {image_path}"


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("out_dir")
    parser.add_argument("--arch", choices=sorted(INDEXES), default="amd64")
    parser.add_argument("--builds", type=int, nargs="*", default=[], help="as 19041 or 26100")
    parser.add_argument("--oldest", type=int, default=0, help="revisions per build, oldest first")
    parser.add_argument("--newest", type=int, default=0, help="revisions per build, newest first")
    parser.add_argument("--list", action="store_true", help="print the versions and stop")
    parser.add_argument("--jobs", type=int, default=8)
    args = parser.parse_args()
    chosen = select(versions(args.arch), set(args.builds), args.oldest, args.newest)
    if args.list:
        for item in chosen:
            print(item["version"])
        return
    os.makedirs(args.out_dir, exist_ok=True)
    with concurrent.futures.ThreadPoolExecutor(args.jobs) as pool:
        jobs = {pool.submit(fetch, item, args.out_dir): item for item in chosen}
        for job in concurrent.futures.as_completed(jobs):
            try:
                print(job.result(), flush=True)
            except (urllib.error.URLError, ValueError, OSError) as error:
                print(f"{jobs[job]['version']}: failed: {error}", flush=True)


if __name__ == "__main__":
    main()
