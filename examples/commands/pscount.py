import ntoseye.repl as repl


@repl.command("pscount", "Count running processes.\n(usage: pscount [-v])")
def pscount(dbg: repl.Debugger, *args: str):
    processes = dbg.processes
    print(f"{len(processes)} processes")
    if args and args[0] == "-v":
        for process in processes:
            print(f"  {process.eprocess:#x}  {process.pid:>6}  {process.name}")
