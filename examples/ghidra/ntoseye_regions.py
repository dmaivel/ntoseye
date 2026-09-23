"""Memory regions for Ghidra's gdb agent from `ntoseye gdbserver`.

gdb runs a PE kernel under its Windows OS ABI, which has no `info proc
mappings`, so Ghidra's gdb agent gets no regions: it falls back to one
region spanning all memory and bases each module at its first section, a page
above the image base, which maps the Ghidra program one page off. This reads
the regions from the `/proc/<pid>/maps` the server generates instead, so each
module is based at its image start.

Load it through the gdb launcher's "gdb cmd args" field:

    -x /path/to/ntoseye_regions.py
"""

import os
import tempfile

import gdb
from ghidragdb import util


class RemoteMapsReader(util.RegionInfoReader):
    def get_regions(self):
        fd, local = tempfile.mkstemp(prefix="ntoseye-maps-")
        os.close(fd)
        try:
            pid = gdb.selected_inferior().pid
            gdb.execute(f"remote get /proc/{pid}/maps {local}", to_string=True)
            with open(local) as maps:
                lines = maps.read().splitlines()
        except (gdb.error, OSError):
            return []
        finally:
            os.remove(local)
        regions = []
        for line in lines:
            # start-end perms offset dev inode [path]
            fields = line.split(maxsplit=5)
            if len(fields) < 5:
                continue
            start, end = (int(bound, 16) for bound in fields[0].split("-"))
            objfile = fields[5] if len(fields) == 6 else ""
            regions.append(util.Region(start, end, int(fields[2], 16), fields[1], objfile))
        return regions


util.REGION_INFO_READER = RemoteMapsReader()
