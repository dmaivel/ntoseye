//! The SDK driven from Python over a synthetic crash dump: no guest, no
//! symbols, so it runs everywhere `cargo test` does. It covers what the
//! target-free pytest suite cannot build (stops, handles, closing) and the
//! live suite (`python/tests/test_live.py`) does not run in CI.

use std::env::temp_dir;
use std::fs::{remove_file, write};
use std::process::id;
use std::sync::atomic::{AtomicU64, Ordering};

use super::embed::exec_script;
use crate::triage::{TriageBlock, make_triage_dump};

/// Where the dump's one captured page lives (it holds `nop`s).
const PAGE: u64 = 0xffff_f800_1234_5000;

/// Run `script` with `DUMP` bound to the path of a triage dump whose header
/// records bugcheck 0x50 at `rip = PAGE + 0x678`.
fn run_over_dump(script: &str) {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let memory = [0x90u8; 0x1000];
    let block = TriageBlock {
        address: PAGE,
        offset: 0,
        size: memory.len() as u32,
    };
    let path = temp_dir().join(format!(
        "ntoseye-sdk-{}-{}.dmp",
        id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    write(&path, make_triage_dump(&[block], &[(PAGE, &memory)])).unwrap();
    let prelude = format!(
        "import ntoseye\nfrom ntoseye import Stop\nDUMP = {:?}\nPAGE = {PAGE:#x}\n",
        path.display().to_string()
    );
    let result = exec_script(&format!("{prelude}{script}"), "dump_test.py");
    remove_file(&path).unwrap();
    result.unwrap();
}

#[test]
fn a_crash_dump_stops_at_its_bugcheck() {
    run_over_dump(
        r#"
with ntoseye.attach("dmp", DUMP) as dbg:
    stop = dbg.stop
    assert isinstance(stop, Stop.Bugcheck), repr(stop)
    assert isinstance(stop, Stop)
    assert stop.rip == PAGE + 0x678, hex(stop.rip)
    assert stop.info is not None and stop.info.code == 0x50, stop.info
    # Reading the current stop consumes nothing.
    for again in (dbg.stop, dbg.wait(0), dbg.interrupt()):
        assert isinstance(again, Stop.Bugcheck), repr(again)
"#,
    );
}

#[test]
fn errors_are_the_package_exception_classes() {
    run_over_dump(
        r#"
def raises(kind, call):
    try:
        call()
    except kind as error:
        return error
    raise AssertionError(f"expected {kind.__name__}")

with ntoseye.attach("dmp", DUMP) as dbg:
    assert dbg.memory.read(PAGE, 4) == b"\x90" * 4
    raises(ntoseye.MemoryAccessError, lambda: dbg.memory.read(0x1000, 4))
    missing = raises(ntoseye.SymbolNotFoundError, lambda: dbg.symbols["nt!NoSuchSymbol"])
    assert isinstance(missing, LookupError)
    raises(ntoseye.NtoseyeError, lambda: dbg.run(timeout=0))
"#,
    );
}

#[test]
fn closing_ends_the_session_and_its_handles() {
    run_over_dump(
        r#"
with ntoseye.attach("dmp", DUMP) as dbg:
    cpu = dbg.cpus[0]
    rip = cpu.rip
dbg.close()  # closing again does nothing
for call in (lambda: dbg.stop, lambda: cpu.rip):
    try:
        call()
    except ntoseye.NtoseyeError:
        pass
    else:
        raise AssertionError("a closed debugger still answered")
"#,
    );
}
