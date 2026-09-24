//! Per-processor structures: PCR, PRCB, IRQL, IDT, GDT, and CPU
//! identification, plus processor-index argument resolution.

use super::Args;
use crate::dbg_backend::processor_index_from_backend_thread_id;
use crate::error::Result;
use crate::view::{self, View};

pub(super) fn command(name: &str, args: &mut Args<'_, '_>) -> Option<Result<View>> {
    Some(match name {
        "!pcr" | "pcr" => args.processor(0).and_then(|processor| {
            let detail = args.state.ctx.inspect_pcr(processor)?;
            Ok(view::cpu::pcr(&detail))
        }),
        "!prcb" | "prcb" => args.processor(0).and_then(|processor| {
            let detail = args.target().inspect_prcb(processor)?;
            Ok(view::cpu::prcb(&detail))
        }),
        "!irql" | "irql" => args.processor(0).and_then(|processor| {
            let detail = args.target().inspect_irql(processor)?;
            Ok(view::cpu::irql(&detail))
        }),
        "!idt" | "idt" => args.opt_u16_value(0, "IDT vector").and_then(|vector| {
            let processor = args.current_processor();
            let detail = args.state.ctx.inspect_idt(processor, vector)?;
            Ok(view::cpu::idt(&detail))
        }),
        "!gdt" | "gdt" => {
            let processor = args.current_processor();
            args.state
                .ctx
                .inspect_gdt(processor)
                .map(|detail| view::cpu::gdt(&detail))
        }
        "!cpuinfo" | "cpuinfo" => args
            .target()
            .inspect_cpuinfo(args.current_processor())
            .map(|detail| view::cpu::cpuinfo(&detail)),
        _ => return None,
    })
}

impl Args<'_, '_> {
    fn current_processor(&self) -> u16 {
        processor_index_from_backend_thread_id(&self.state.ctx.current_thread).unwrap_or(0)
    }

    /// An optional processor-index argument, defaulting to the current vCPU's.
    fn processor(&self, index: usize) -> Result<u16> {
        Ok(self
            .opt_u16_value(index, "processor")?
            .unwrap_or_else(|| self.current_processor()))
    }
}
