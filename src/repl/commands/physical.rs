use crate::repl::*;

use crate::backend::MemoryOps;
use crate::error::Result;
use crate::target::{MAX_SEARCH_MATCHES, SearchStop};
use crate::types::{PhysAddr, VirtAddr};
use crate::ui;

use super::memory::{MAX_DISPLAY_BYTES, parse_write_values};
use crate::memory::{PAGE_SIZE, read_page_chunks};
use owo_colors::OwoColorize;

repl_command! {
    cmd_phys_db;
    names: ["!db"],
    usage: "!db <address> [L<count>|length|end]",
    summary: "Show guest-physical memory as bytes.",
    completion: Expression,
}

repl_command! {
    cmd_phys_dw;
    names: ["!dw"],
    usage: "!dw <address> [L<count>|length|end]",
    summary: "Show guest-physical memory as words.",
    completion: Expression,
}

repl_command! {
    cmd_phys_dd;
    names: ["!dd"],
    usage: "!dd <address> [L<count>|length|end]",
    summary: "Show guest-physical memory as doublewords.",
    completion: Expression,
}

repl_command! {
    cmd_phys_dq;
    names: ["!dq"],
    usage: "!dq <address> [L<count>|length|end]",
    summary: "Show guest-physical memory as quadwords.",
    completion: Expression,
}

repl_command! {
    cmd_phys_eb;
    names: ["!eb"],
    usage: "!eb <address> <value...>",
    summary: "Write one or more bytes to guest-physical memory.",
    completion: Expression,
}

repl_command! {
    cmd_phys_ed;
    names: ["!ed"],
    usage: "!ed <address> <value...>",
    summary: "Write one or more doublewords to guest-physical memory.",
    completion: Expression,
}

repl_command! {
    cmd_phys_eq;
    names: ["!eq"],
    usage: "!eq <address> <value...>",
    summary: "Write one or more quadwords to guest-physical memory.",
    completion: Expression,
}

repl_command! {
    cmd_phys_search;
    names: ["!search"],
    usage: "!search <value> [delta [start-pfn [end-pfn]]]",
    summary: "Search guest-physical memory for a pointer-sized value.",
    details: "The command compares each pointer-aligned quadword in the PFN range, which is all RAM by default. With no delta, it lists a quadword if it equals the value or differs from it by one bit. With a delta, it lists a quadword if it is within delta of the value or differs from value - delta by one bit. WinDbg's !search uses the same rules. Each hit shows its PFN, its offset, and the value, and from the PFN database, the PTE that maps the page and the virtual address that this PTE maps. The virtual address is blank when the PTE is not in the self-map. The command skips and counts the pages that it cannot read, and the search stops after 4096 hits or when you press Ctrl+C.",
    completion: Expression,
}

impl ReplState<'_> {
    fn read_physical_best_effort(&self, range: &AddressRange) -> Result<(Vec<u8>, Vec<bool>)> {
        read_page_chunks(range.start, range.len(), |address, buf| {
            self.ctx.target.phys.read_bytes(address.0, buf)
        })
    }

    fn display_physical_command(
        &self,
        invocation: &CommandInvocation<'_>,
        default_count: u64,
        item_size: u64,
        mode: MemoryDisplayMode,
    ) -> Result<()> {
        let range = match AddressRange::parse(
            invocation,
            &self.ctx.target,
            self.radix,
            default_count,
            item_size,
        ) {
            Ok(range) => range,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };
        if range.len() > MAX_DISPLAY_BYTES {
            error!("display range exceeds the maximum of {MAX_DISPLAY_BYTES:#x} bytes");
            return Ok(());
        }
        let (data, valid) = match self.read_physical_best_effort(&range) {
            Ok(read) => read,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let print_text = || display_memory_with_validity(range.start, &data, Some(&valid), &mode);
        #[cfg(feature = "cli")]
        native::render(
            || native::memory::dump(range.start, &data, Some(&valid), &mode),
            print_text,
        );
        #[cfg(not(feature = "cli"))]
        print_text();
        Ok(())
    }

    fn write_physical_command(
        &mut self,
        invocation: &CommandInvocation<'_>,
        command: &str,
        noun: &str,
        encode: impl Fn(u64) -> Vec<u8>,
    ) -> Result<()> {
        if invocation.argv.len() < 2 {
            outln!("{}\n", command_help(command));
            return Ok(());
        }
        let Some(VirtAddr(address)) = self.eval_or_report(invocation.arg(0).unwrap()) else {
            return Ok(());
        };
        let values = match parse_write_values(self, invocation) {
            Ok(values) => values,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };
        let mut bytes = Vec::new();
        for value in values {
            bytes.extend(encode(value));
        }
        match self
            .ctx
            .target
            .phys
            .write_bytes(address as PhysAddr, &bytes)
        {
            Ok(()) => outln!("wrote {} bytes to physical {:#x}\n", bytes.len(), address),
            Err(e) => error!("failed to write physical {}: {}", noun, e),
        }
        Ok(())
    }

    fn cmd_phys_db(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.display_physical_command(&invocation, 128, 1, MemoryDisplayMode::bytes())
    }

    fn cmd_phys_dw(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.display_physical_command(&invocation, 32, 2, MemoryDisplayMode::words())
    }

    fn cmd_phys_dd(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.display_physical_command(&invocation, 16, 4, MemoryDisplayMode::dwords())
    }

    fn cmd_phys_dq(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.display_physical_command(&invocation, 8, 8, MemoryDisplayMode::qwords())
    }

    fn cmd_phys_eb(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.write_physical_command(&invocation, "!eb", "byte", |value| vec![value as u8])
    }

    fn cmd_phys_ed(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.write_physical_command(&invocation, "!ed", "dword", |value| {
            (value as u32).to_le_bytes().to_vec()
        })
    }

    fn cmd_phys_eq(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.write_physical_command(&invocation, "!eq", "qword", |value| {
            value.to_le_bytes().to_vec()
        })
    }

    fn cmd_phys_search(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if invocation.argv.is_empty() || invocation.argv.len() > 4 {
            outln!("{}\n", command_help("!search"));
            return Ok(());
        }
        let mut values = Vec::with_capacity(invocation.argv.len());
        for arg in &invocation.argv {
            let Some(value) = self.eval_or_report(arg) else {
                return Ok(());
            };
            values.push(value.0);
        }
        let data = values[0];
        let delta = values.get(1).copied().unwrap_or(0);
        let low = data.saturating_sub(delta);
        let high = data.saturating_add(delta);
        let result = match self.ctx.target.search_physical_pointer(
            data,
            delta,
            values.get(2).copied(),
            values.get(3).copied(),
        ) {
            Ok(result) => result,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        outln!(
            "Searching PFNs in range {:x} - {:x} for [{} - {}]\n",
            result.first_pfn,
            result.last_pfn,
            ui::addr(low),
            ui::addr(high)
        );
        if !result.hits.is_empty() {
            outln!(
                "{:<10} {:<6} {:<16} {:<16} {:<16}",
                "Pfn",
                "Offset",
                "Hit",
                "Va",
                "Pte"
            );
            let page = PAGE_SIZE as u64;
            for hit in &result.hits {
                let optional = |address: Option<VirtAddr>| {
                    address.map_or_else(|| format!("{:16}", ""), |address| ui::addr(address.0))
                };
                let value = format!("{:016x}", hit.value);
                outln!(
                    "{:<10x} {:<6x} {} {} {}",
                    hit.physical / page,
                    hit.physical % page,
                    if hit.value == data {
                        value.bold().to_string()
                    } else {
                        value
                    },
                    optional(hit.va),
                    optional(hit.pte)
                );
            }
            outln!();
        }
        outln!(
            "{} {} in {:#x} pages",
            result.hits.len(),
            if result.hits.len() == 1 {
                "hit"
            } else {
                "hits"
            },
            result.pages
        );
        if result.unreadable_pages > 0 {
            outln!(
                "{}",
                format!("{:#x} unreadable pages skipped", result.unreadable_pages).bright_black()
            );
        }
        match result.stopped {
            Some(SearchStop::MatchLimit) => outln!(
                "{}",
                format!("stopped after {MAX_SEARCH_MATCHES} hits").bright_black()
            ),
            Some(SearchStop::Interrupted) => outln!("{}", "interrupted".bright_black()),
            None => {}
        }
        outln!();
        Ok(())
    }
}
