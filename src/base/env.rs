//! The environment variables that set something for the whole process
//! rather than for one session: diagnostic traces and escape hatches. A
//! variable reaches every way into ntoseye (the CLI, Python, MCP, DAP, the
//! GDB server) without a parameter in each, and keeps a setting that is not
//! part of the interface out of it.

use std::ffi::OsStr;
use std::sync::LazyLock;

/// Whether the on/off variable `name` is on: set to anything but nothing or
/// `0`.
pub fn switch_on(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|value| is_on(&value))
}

fn is_on(value: &OsStr) -> bool {
    !value.is_empty() && value != "0"
}

/// A diagnostic trace on standard error. `NTOSEYE_TRACE` turns traces on by
/// name, as a comma-separated list (see [`Trace::NAMES`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trace {
    /// Each KD request and reply, with the session's reload decisions and
    /// breakpoint bookkeeping, on one clock.
    Kd,
    /// The raw bytes on the KD transport, apart from [`Trace::Kd`]: the
    /// kernel's retransmissions would drown the packet trace in them.
    KdBytes,
    /// Each GDB remote protocol packet, to the hypervisor's stub and from a
    /// client of the GDB server.
    Gdb,
    /// How each breakpoint stop and step is classified and waited on.
    Step,
    /// Each step of each stack unwind.
    Unwind,
}

impl Trace {
    pub const NAMES: [(Trace, &'static str); 5] = [
        (Trace::Kd, "kd"),
        (Trace::KdBytes, "kd-bytes"),
        (Trace::Gdb, "gdb"),
        (Trace::Step, "step"),
        (Trace::Unwind, "unwind"),
    ];

    /// Whether `NTOSEYE_TRACE` names this trace.
    pub fn enabled(self) -> bool {
        static ON: LazyLock<u8> =
            LazyLock::new(|| std::env::var("NTOSEYE_TRACE").map_or(0, |list| traces_in(&list)));
        *ON & self.bit() != 0
    }

    fn bit(self) -> u8 {
        1 << self as u8
    }
}

/// The traces a `NTOSEYE_TRACE` list names, as a set of [`Trace::bit`]s.
/// Names match whole and in any case; a name no trace has is ignored.
fn traces_in(list: &str) -> u8 {
    list.split(',')
        .map(str::trim)
        .filter_map(|name| {
            Trace::NAMES
                .iter()
                .find(|(_, known)| known.eq_ignore_ascii_case(name))
        })
        .fold(0, |bits, (trace, _)| bits | trace.bit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_trace_list_turns_on_exactly_the_traces_it_names() {
        let on = |list: &str| -> Vec<Trace> {
            let bits = traces_in(list);
            Trace::NAMES
                .iter()
                .map(|&(trace, _)| trace)
                .filter(|trace| bits & trace.bit() != 0)
                .collect()
        };
        assert_eq!(on("kd, Unwind"), [Trace::Kd, Trace::Unwind]);
        assert_eq!(on("kd-bytes"), [Trace::KdBytes]);
        assert_eq!(on("gdb,,step,trace"), [Trace::Gdb, Trace::Step]);
        assert_eq!(on("k"), []);
        assert_eq!(on(""), []);
    }

    #[test]
    fn a_switch_is_off_when_empty_or_zero() {
        for (value, on) in [("", false), ("0", false), ("1", true), ("yes", true)] {
            assert_eq!(is_on(OsStr::new(value)), on, "{value:?}");
        }
    }
}
