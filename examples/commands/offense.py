import ntoseye.repl as repl

@repl.command(
    "hide",
    "Unlink a process from ActiveProcessLinks.\n(usage: hide <pid|name>)",
    target=repl.Process,
)
def hide(dbg: repl.Debugger, target=None):
    if not target:
        print("usage: hide <pid|name>")
        return
    p = dbg.process(target)

    # Unlink from ActiveProcessLinks; the process keeps running because thread
    # scheduling uses a separate list.
    apl = p.addr + dbg.offset_of("_EPROCESS", "ActiveProcessLinks")
    flink = dbg.read_u64(apl)
    blink = dbg.read_u64(apl + 8)
    dbg.write_u64(blink, flink)       # prev->Flink = next
    dbg.write_u64(flink + 8, blink)   # next->Blink = prev
    dbg.write_u64(apl, apl)           # self-link so the victim's list is well-formed
    dbg.write_u64(apl + 8, apl)
    print(f"hid {p.ImageFileName} (pid {p.UniqueProcessId}) from process list")

@repl.command(
    "lpe",
    "Copy the SYSTEM process token onto a target process.\n(usage: lpe <pid|name>)",
    target=repl.Process,
)
def lpe(dbg: repl.Debugger, target=None):
    if not target:
        print("usage: lpe <pid|name>")
        return
    p = dbg.process(target)

    # PsInitialSystemProcess is a PEPROCESS*; deref once for the System EPROCESS.
    system = dbg.read_u64(dbg.eval("PsInitialSystemProcess"))
    token_off = dbg.offset_of("_EPROCESS", "Token")
    token = dbg.read_u64(system + token_off)
    dbg.write_u64(p.addr + token_off, token)
    print(f"escalated {p.ImageFileName} (pid {p.UniqueProcessId}) -> SYSTEM token {token:#x}")
