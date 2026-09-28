//! Hang diagnosis from the processor blocks (`!qlocks`, `!ipi`) and PCI
//! (`!pcitree`, `!pci`).

use super::Args;
use crate::error::Result;
use crate::target::pci::{PCI_EXTENDED_CONFIG_SIZE, PciQuery, parse_pci_request};
use crate::view::{self, View};

pub(super) fn command(name: &str, args: &mut Args<'_, '_>) -> Option<Result<View>> {
    Some(match name {
        "!qlocks" | "qlocks" => args
            .target()
            .queued_locks()
            .map(|detail| view::hardware::queued_locks(&detail).into_view()),
        "!ipi" | "ipi" => args.opt_u16_value(0, "processor").and_then(|processor| {
            let detail = args.target().ipi_state(processor)?;
            Ok(view::hardware::ipi(&detail).into_view())
        }),
        "!pcitree" | "pcitree" => args
            .target()
            .pci_tree()
            .map(|tree| view::hardware::pci_tree(&tree).into_view()),
        "!pci" | "pci" => pci(args),
        _ => return None,
    })
}

fn pci(args: &mut Args<'_, '_>) -> Result<View> {
    let values = (0..args.argv.len())
        .map(|index| args.value(index))
        .collect::<Result<Vec<_>>>()?;
    let request = parse_pci_request(&values)?;
    // The JSON decodes extended capabilities whatever the flags say.
    let query = PciQuery {
        size: PCI_EXTENDED_CONFIG_SIZE,
        ..request.query
    };
    let scan = args.state.ctx.scan_pci(&query)?;
    Ok(view::hardware::pci(&scan, request.raw).into_view())
}
