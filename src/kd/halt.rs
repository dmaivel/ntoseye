use std::collections::HashMap;

use super::ControlReport;

/// Everything the host knows about the target's registers during one halt.
///
/// A stop hands over some register state for free in its control report and
/// the rest costs a round trip, so all of it is memoized until the target
/// runs again or the host writes registers back. Every view describes the
/// same instant, which is why one entry holds them all: a report kept past
/// the `CONTEXT` it agreed with would answer for registers the host has
/// since changed, and a resume that trusted it would leave a trap flag set
/// and single-step the target forever.
///
/// The entries are private so that no caller can drop one view and keep
/// another. Invalidation takes a whole processor or nothing.
#[derive(Default)]
pub struct HaltRegisters {
    processors: HashMap<u16, ProcessorRegisters>,
}

#[derive(Default)]
struct ProcessorRegisters {
    context: Option<Vec<u8>>,
    special: Option<Vec<u8>>,
    report: Option<ControlReport>,
}

impl HaltRegisters {
    /// Adopt a stop. Nothing outlives the halt it was read in, so the only
    /// thing left afterwards is what this stop reported.
    pub fn stopped(&mut self, processor: u16, report: Option<ControlReport>) {
        self.processors.clear();
        if let Some(report) = report {
            self.processors.insert(
                processor,
                ProcessorRegisters {
                    report: Some(report),
                    ..Default::default()
                },
            );
        }
    }

    /// The target is running, so nothing the host holds describes it.
    pub fn running(&mut self) {
        self.processors.clear();
    }

    /// Forget a processor whose registers the host has written.
    pub fn invalidate(&mut self, processor: u16) {
        self.processors.remove(&processor);
    }

    pub fn context(&self, processor: u16) -> Option<&[u8]> {
        self.processors.get(&processor)?.context.as_deref()
    }

    pub fn set_context(&mut self, processor: u16, context: Vec<u8>) {
        self.processors.entry(processor).or_default().context = Some(context);
    }

    pub fn special(&self, processor: u16) -> Option<&[u8]> {
        self.processors.get(&processor)?.special.as_deref()
    }

    pub fn set_special(&mut self, processor: u16, special: Vec<u8>) {
        self.processors.entry(processor).or_default().special = Some(special);
    }

    /// What the stop reported about `processor`, while it still holds.
    ///
    /// Only the processor that stopped has a report, so a caller asking
    /// about any other one is told to go and read the registers.
    pub fn report(&self, processor: u16) -> Option<&ControlReport> {
        self.processors.get(&processor)?.report.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report() -> ControlReport {
        ControlReport(vec![0u8; 48])
    }

    #[test]
    fn a_write_that_drops_a_context_drops_the_report_with_it() {
        let mut registers = HaltRegisters::default();
        registers.stopped(0, Some(report()));
        registers.set_context(0, vec![1, 2, 3]);
        registers.set_special(0, vec![4, 5, 6]);

        registers.invalidate(0);

        assert!(registers.context(0).is_none());
        assert!(registers.special(0).is_none());
        assert!(
            registers.report(0).is_none(),
            "a report outliving the context it agreed with is what strands a trap flag"
        );
    }

    #[test]
    fn a_report_answers_only_for_the_processor_that_stopped() {
        let mut registers = HaltRegisters::default();
        registers.stopped(1, Some(report()));

        assert!(registers.report(1).is_some());
        assert!(registers.report(0).is_none());
    }

    #[test]
    fn a_stop_keeps_nothing_from_the_halt_before_it() {
        let mut registers = HaltRegisters::default();
        registers.stopped(0, Some(report()));
        registers.set_context(0, vec![1, 2, 3]);
        registers.set_special(1, vec![4, 5, 6]);

        registers.stopped(0, None);

        assert!(registers.context(0).is_none());
        assert!(registers.special(1).is_none());
        assert!(registers.report(0).is_none());
    }

    #[test]
    fn resuming_forgets_every_processor() {
        let mut registers = HaltRegisters::default();
        registers.stopped(0, Some(report()));
        registers.set_special(1, vec![4, 5, 6]);

        registers.running();

        assert!(registers.report(0).is_none());
        assert!(registers.special(1).is_none());
    }
}
