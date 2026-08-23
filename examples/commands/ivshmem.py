# Ported from the old ivshmem_patch.lua. Drop in ~/.ntoseye/commands/.
#
# Patch the Windows IVSHMEM driver's ioctl_request_mmap to allow multiple
# concurrent handles to the shared buffer. The unpatched driver fails with
# STATUS_DEVICE_ALREADY_ATTACHED when DeviceContext->shmemMap is non-null;
# flipping the `je` over the early return into a `jmp` skips the check.

import ntoseye.repl as repl

PATTERN = b"\x48\x83\x79\x20\x00\x74\x0a"
REPLACEMENT = b"\x48\x83\x79\x20\x00\xeb\x0a"

@repl.command(
    "ivshmem_patch",
    "Patch IVSHMEM driver to skip the shared-memory size check.\n(usage: ivshmem_patch)",
)
def ivshmem_patch(dbg: repl.Debugger):
    mod = next((m for m in dbg.kernel_modules() if "ivshmem" in m[0].lower()), None)
    if not mod:
        print("ivshmem module not loaded")
        return
    name, base, size = mod
    print(f"ivshmem: {name}  base={base:#x}  size={size:#x}")

    hits = dbg.search(base, PATTERN, size)
    if not hits:
        print("pattern not found; driver may already be patched or a different build")
        return
    dbg.write(hits[0], REPLACEMENT)
    print(f"patched {len(REPLACEMENT)} bytes at {hits[0]:#x}")
