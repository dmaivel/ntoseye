//! Memory-manager commands: page tables, address descriptions, PFNs,
//! pools, lookaside lists, and memory usage.

use super::Args;
use crate::error::{Error, Result};
use crate::target::mm::{PfnSelector, PoolType, PoolUsageSort};
use crate::view::{self, View};

pub(super) fn command(name: &str, args: &mut Args<'_, '_>) -> Option<Result<View>> {
    let argv = args.argv;
    Some(match name {
        "!memusage" => args.opt_value(0).and_then(|limit| {
            let summary = args
                .target()
                .memory_use_summary(limit.map_or(64, |limit| limit as usize))?;
            Ok(view::mm::memory_usage(&summary))
        }),
        "!pte" | "pte" => args.addr(0).and_then(|address| {
            let walk = args.target().pte_traverse(address)?;
            Ok(view::mm::pte_walk(&walk))
        }),
        "address" => args.addr(0).and_then(|address| {
            let description = args.target().describe_address(address)?;
            Ok(view::mm::address_description(&description))
        }),
        "!vm" | "vm" => args.opt_value(0).and_then(|flags| {
            let detail = args.target().inspect_vm(flags.unwrap_or(0) & 1 == 0)?;
            Ok(view::mm::vm(&detail))
        }),
        "!pfn" | "pfn" => {
            let physical = argv.first().is_some_and(|arg| *arg == "-a" || *arg == "/a");
            args.value(usize::from(physical)).and_then(|value| {
                let selector = if physical {
                    PfnSelector::PhysicalAddress(value)
                } else {
                    PfnSelector::Pfn(value)
                };
                let detail = args.target().inspect_pfn(selector)?;
                Ok(view::mm::pfn(&detail))
            })
        }
        "!vtop" | "vtop" => args.value(0).and_then(|dtb| {
            let address = args.addr(1)?;
            let detail = args.target().vtop(dtb, address)?;
            Ok(view::mm::vtop(&detail))
        }),
        "!ptov" | "ptov" => args.value(0).and_then(|physical| {
            let detail = args.target().ptov(physical)?;
            Ok(view::mm::ptov(&detail))
        }),
        "!pool" | "pool" => args.addr(0).and_then(|address| {
            let detail = args.target().inspect_pool(address)?;
            Ok(view::mm::pool_page(&detail))
        }),
        "!poolused" | "poolused" => {
            let (flags, tag) = match argv.first() {
                Some(first) => match args.eval(first) {
                    Ok(flags) => (flags.0, argv.get(1).copied()),
                    Err(_) => (0, Some(*first)),
                },
                None => (0, None),
            };
            let sort = if flags & 2 != 0 {
                PoolUsageSort::NonPagedBytes
            } else if flags & 4 != 0 {
                PoolUsageSort::PagedBytes
            } else {
                PoolUsageSort::Tag
            };
            args.target()
                .pool_usage(sort, tag, flags & 1 != 0)
                .map(|detail| view::mm::pool_usage(&detail))
        }
        "!poolfind" | "poolfind" => match argv.first() {
            Some(tag) => {
                let pool_type = match argv.get(1) {
                    Some(&"0") => Some(PoolType::NonPaged),
                    Some(&"1") => Some(PoolType::Paged),
                    _ => None,
                };
                args.target()
                    .pool_find(tag, pool_type)
                    .map(|detail| view::mm::pool_find(&detail))
            }
            None => Err(Error::DebugInfo("missing pool tag".into())),
        },
        "!lookaside" | "lookaside" => match args.opt_addr(0) {
            Ok(Some(address)) => args
                .target()
                .inspect_lookaside(address)
                .map(|detail| view::mm::lookaside(&detail)),
            Ok(None) => args
                .target()
                .lookaside_lists()
                .map(|detail| view::mm::lookaside_lists(&detail)),
            Err(error) => Err(error),
        },
        _ => return None,
    })
}
