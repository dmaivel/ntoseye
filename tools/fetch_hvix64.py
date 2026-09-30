#!/usr/bin/env python3
"""Fetch the Windows hypervisor (hvix64.exe) of Windows builds, for tests.

Microsoft's symbol server does not serve hvix64.exe, so this takes it from
the Windows packages on Microsoft's update CDN, found through the UUP dump
API (https://uupdump.net): for each build it downloads the smallest package
that holds hvix64.exe (a few hundred MB), extracts the file with 7-Zip, and
deletes the package. The packages hold the build's release version
(10.0.x.1, or 10.0.16299.15), not later servicing builds: 19045 gives
10.0.19041.1. Windows 10 1507 to 1703 are not on UUP.

The images are Microsoft's and not redistributable; they stay in OUT_DIR.
The Rust test that reads them:

    python3 tools/fetch_hvix64.py ~/hvix64 17763 19045 22631 26100
    NTOSEYE_HVIX64_IMAGES="$(ls -1 ~/hvix64/*.exe)" \\
        cargo test --lib exit_registers -- --ignored --nocapture

Needs `curl` and `7z` on PATH.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

API = "https://api.uupdump.net"
# Packages that have carried the hypervisor, tried smallest first. Before
# Windows 10 2004, Hyper-V shipped only with Pro and above, in the edition
# pack; the edition image itself holds placeholders that point into packs.
PACKAGES = (
    "client-features-package",
    "editionpack-professional-package",
    "client-desktop-required-package",
)


def api(path: str) -> dict:
    for attempt in range(6):
        request = urllib.request.Request(
            f"{API}/{path}", headers={"User-Agent": "ntoseye-tools"}
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return json.load(response)["response"]
        except urllib.error.HTTPError as error:
            if error.code != 429 or attempt == 5:
                raise
            time.sleep(30 * (attempt + 1))
    raise RuntimeError("unreachable")


def release_build(number: str) -> dict | None:
    """The newest amd64 build of `number` that is a full release (a feature
    update or the Windows release itself), not a cumulative update."""
    builds = api(f"listid.php?search={number}&sortByDate=1")["builds"].values()
    for build in builds:
        title = build["title"]
        if (
            build["arch"] == "amd64"
            and str(build["build"]).startswith(number)
            and not title.startswith(
                ("Cumulative", "Update", "Security", "Critical", "Windows Autopilot")
            )
        ):
            return build
    return None


def fetch(number: str, out_dir: str, work: str) -> str:
    build = release_build(number)
    if build is None:
        return f"{number}: no release build on UUP"
    files = api(f"get.php?id={build['uuid']}&lang=en-us&edition=professional")["files"]
    candidates = sorted(
        (
            (name, info)
            for name, info in files.items()
            if name.lower().endswith((".esd", ".cab"))
            and any(key in name.lower() for key in PACKAGES)
        ),
        key=lambda item: int(item[1]["size"]),
    )
    for name, info in candidates:
        package = os.path.join(work, name)
        subprocess.run(["curl", "-sfL", "-o", package, info["url"]], check=True)
        listing = subprocess.run(
            ["7z", "l", package], capture_output=True, text=True, check=False
        ).stdout
        # The component store's copy: nonzero, and its directory names the
        # version (amd64_microsoft-hyper-v-drivers-hypervisor_..._10.0.x.y_...).
        members = [
            line.split()[-1]
            for line in listing.splitlines()
            if line.rstrip().endswith("/hvix64.exe")
            and "hyper-v-drivers-hypervisor" in line
            and line.split()[3] != "0"
        ]
        if members:
            subprocess.run(
                ["7z", "e", "-y", f"-o{work}", package, members[0]],
                capture_output=True,
                check=True,
            )
            version = members[0].split("_")[3]
            target = os.path.join(out_dir, f"hvix64-{version}.exe")
            shutil.move(os.path.join(work, "hvix64.exe"), target)
            os.remove(package)
            return f"{number}: {build['title']}: {name} -> {target}"
        os.remove(package)
    return f"{number}: {build['title']}: no package holds hvix64.exe"


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("out_dir")
    parser.add_argument("builds", nargs="+", help="build numbers, as 17763 or 26100")
    args = parser.parse_args()
    os.makedirs(args.out_dir, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=args.out_dir) as work:
        for number in args.builds:
            try:
                print(fetch(number, args.out_dir, work), flush=True)
            except (
                urllib.error.URLError,
                subprocess.CalledProcessError,
                KeyError,
            ) as error:
                print(f"{number}: failed: {error}", flush=True)
            time.sleep(5)


if __name__ == "__main__":
    main()
