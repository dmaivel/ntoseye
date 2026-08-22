import ntoseye.repl as repl

@repl.command("pscount", "Count running processes.\n(usage: pscount [-v])")
def pscount(dbg: repl.Debugger, *args: str):
    procs = dbg.processes()
    print(f"{len(procs)} processes")
    if args and args[0] == "-v":
        for p in procs:
            print(f"  {p.addr:#x}")
