//! Stops on the Windows hypervisor's VM exits by reason (`!hvexit`): a
//! hardware execute breakpoint on the exit entry point (an eVMCS's
//! `host_rip`), whose hits stop only for the exits the filter names. The
//! entry runs for every exit of every VP on its processor, so the reason,
//! qualification and caller are read from the eVMCS the processor has
//! loaded, which the CPU filled in at the exit.

use super::evmcs::exit_reason_name;
use super::hypercalls::HypercallCaller;
use crate::error::{Error, Result};

/// The highest basic exit reason the SDM assigns as of this writing; the
/// field is 16 bits, so higher numbers are still accepted.
const NAMED_REASONS: u16 = 80;

/// A name as typed, compared without case, spaces, `-` or `_`:
/// `ept_violation`, `EPT violation` and `eptviolation` are one name.
fn folded(name: &str) -> String {
    name.chars()
        .filter(|c| !matches!(c, ' ' | '-' | '_'))
        .flat_map(char::to_lowercase)
        .collect()
}

/// A basic exit reason by its number (decimal, or hex with `0x`) or its
/// name as `!hvvps` shows it (`cpuid`, `rdmsr`, `ept_violation`).
pub fn parse_reason(text: &str) -> Result<u16> {
    let number = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u16::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    };
    if let Some(number) = number {
        return Ok(number);
    }
    let wanted = folded(text);
    (0..=NAMED_REASONS)
        .find(|&reason| exit_reason_name(u32::from(reason)).is_some_and(|name| folded(name) == wanted))
        .ok_or_else(|| {
            Error::InvalidArgument(format!(
                "'{text}' is no VM-exit reason: give its number (Intel SDM Appendix C) or a name such as cpuid, rdmsr, wrmsr, io, ept_violation"
            ))
        })
}

/// What a VM-exit breakpoint stops on: a basic exit reason (Intel SDM
/// Vol. 3D, Appendix C), optionally only from one partition or one of its
/// VPs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitFilter {
    pub reason: u16,
    pub partition: Option<u64>,
    /// Set only with `partition`: a VP index names a VP of one partition.
    pub vp: Option<u32>,
}

impl ExitFilter {
    /// Whether a hit whose processor handles `caller`'s exit is this
    /// filter's reason from this filter's caller. As for a hypercall
    /// filter, what is not known does not decline a hit: an unknown caller
    /// matches, and so does a caller whose state is an older exit's.
    pub fn matches(&self, caller: Option<&HypercallCaller>) -> bool {
        let Some(caller) = caller else {
            return true;
        };
        if self
            .partition
            .is_some_and(|partition| partition != caller.partition)
            || self.vp.is_some_and(|vp| vp != caller.vp)
        {
            return false;
        }
        caller
            .state
            .is_none_or(|state| state.exit_reason & 0xffff == u32::from(self.reason))
    }

    /// `VM exit 48 EPT violation from partition 0x6 VP 1`.
    pub fn label(&self) -> String {
        let mut label = format!("VM exit {}", self.reason);
        if let Some(name) = exit_reason_name(u32::from(self.reason)) {
            label.push_str(&format!(" {name}"));
        }
        if let Some(partition) = self.partition {
            label.push_str(&format!(" from partition {partition:#x}"));
        }
        if let Some(vp) = self.vp {
            label.push_str(&format!(" VP {vp}"));
        }
        label
    }
}

#[cfg(test)]
mod tests {
    use super::{ExitFilter, parse_reason};
    use crate::guest::EvmcsState;
    use crate::guest::hypercalls::{HypercallCaller, HypercallInput};

    fn caller(partition: u64, vp: u32, reason: Option<u32>) -> HypercallCaller {
        HypercallCaller {
            partition,
            root: partition == 1,
            vp,
            vtl: 0,
            input: HypercallInput::NotHypercall,
            registers: Default::default(),
            state: reason.map(|reason| EvmcsState {
                exit_reason: reason,
                ..EvmcsState::at(0x1000, true)
            }),
        }
    }

    #[test]
    fn a_reason_is_a_number_or_a_name_in_any_spelling() {
        assert_eq!(parse_reason("48").unwrap(), 48);
        assert_eq!(parse_reason("0x30").unwrap(), 48);
        assert_eq!(parse_reason("ept_violation").unwrap(), 48);
        assert_eq!(parse_reason("EPT violation").unwrap(), 48);
        assert_eq!(parse_reason("cpuid").unwrap(), 10);
        assert!(parse_reason("vmlaunchx").is_err());
    }

    #[test]
    fn a_filter_takes_only_its_reason_from_its_caller() {
        let cpuid = ExitFilter {
            reason: 10,
            partition: None,
            vp: None,
        };
        let guest_vp1 = ExitFilter {
            partition: Some(6),
            vp: Some(1),
            ..cpuid
        };
        assert!(cpuid.matches(Some(&caller(1, 0, Some(10)))));
        // The high bits (failed entry, enclave) do not change the reason.
        assert!(cpuid.matches(Some(&caller(1, 0, Some(10 | 1 << 27)))));
        assert!(!cpuid.matches(Some(&caller(1, 0, Some(48)))));
        assert!(guest_vp1.matches(Some(&caller(6, 1, Some(10)))));
        assert!(!guest_vp1.matches(Some(&caller(6, 2, Some(10)))));
        assert!(!guest_vp1.matches(Some(&caller(1, 1, Some(10)))));
    }

    #[test]
    fn an_unknown_caller_or_exit_stops_rather_than_losing_the_hit() {
        let cpuid = ExitFilter {
            reason: 10,
            partition: Some(6),
            vp: None,
        };
        assert!(cpuid.matches(None));
        assert!(cpuid.matches(Some(&caller(6, 0, None))));
    }
}
