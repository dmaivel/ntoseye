import ntoseye.repl as repl


def resolve_process(dbg: repl.Debugger, target):
    try:
        pid = int(target, 0)
    except (TypeError, ValueError):
        matches = dbg.processes.find(str(target))
        return matches[0] if matches else None
    return dbg.processes.get(pid)


@repl.command(
    "hide",
    "Unlink a process from ActiveProcessLinks.\n(usage: hide <pid|name>)",
    target=repl.Process,
)
def hide(dbg: repl.Debugger, target=None):
    if not target:
        print("usage: hide <pid|name>")
        return
    process = resolve_process(dbg, target)
    if process is None:
        print(f"process {target!r} not found")
        return

    # Unlink from ActiveProcessLinks; scheduling uses a separate thread list.
    link = process.object.ActiveProcessLinks.addr
    memory = dbg.memory
    forward = memory.read_pointer(link)
    backward = memory.read_pointer(link + 8)
    memory.write_u64(backward, forward)
    memory.write_u64(forward + 8, backward)
    memory.write_u64(link, link)
    memory.write_u64(link + 8, link)
    print(f"hid {process.name} (pid {process.pid}) from process list")


@repl.command(
    "lpe",
    "Copy the SYSTEM process token onto a target process.\n(usage: lpe <pid|name>)",
    target=repl.Process,
)
def lpe(dbg: repl.Debugger, target=None):
    if not target:
        print("usage: lpe <pid|name>")
        return
    process = resolve_process(dbg, target)
    if process is None:
        print(f"process {target!r} not found")
        return

    # PsInitialSystemProcess is a PEPROCESS*; dereference it once.
    memory = dbg.memory
    system = memory.read_pointer(dbg.eval("PsInitialSystemProcess"))
    token_address = process.object.address_of("Token")
    token = memory.read_u64(system + token_address - process.object.addr)
    memory.write_u64(token_address, token)
    print(f"escalated {process.name} (pid {process.pid}) -> SYSTEM token {token:#x}")
