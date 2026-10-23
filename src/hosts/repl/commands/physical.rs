use owo_colors::OwoColorize;

use ntoseye_macros::{command, grammar};

use crate::base::error::Result;
use crate::base::memory::PAGE_SIZE;
use crate::base::types::VirtAddr;
use crate::hosts::repl::args::{ArgCursor, ArgCx, ArgError};
use crate::hosts::repl::*;
use crate::hosts::ui;
use crate::nt::target::{MemoryKind, PhysicalSearchResult};
use crate::session::Session;

use super::memory::{
    MemoryDump, WriteUnit, dump_memory, print_search_stop, write_address, write_memory,
    write_values,
};

/// A physical display command's `<address> [L<count>|length|end]`.
#[grammar(usage = "<address> [L<count>|length|end]", complete = [Expression, Expression])]
fn physical_range<const COUNT: u64, const SIZE: u64>(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<AddressRange, ArgError> {
    AddressRange::from_args(cx, cursor, COUNT, SIZE)
}

/// Show guest-physical memory as bytes.
#[command(
    names = ["!db"],
    category = "memory and disassembly",
    kind = Query,
    target = Kernel,
    python = none,
)]
fn physical_db(
    session: &Session,
    #[arg(parse = physical_range::<128, 1>)] range: AddressRange,
) -> Result<MemoryDump> {
    dump_memory(
        session,
        MemoryKind::Physical,
        range,
        MemoryDisplayMode::bytes(),
    )
}

/// Show guest-physical memory as words.
#[command(
    names = ["!dw"],
    category = "memory and disassembly",
    kind = Query,
    target = Kernel,
    python = none,
)]
fn physical_dw(
    session: &Session,
    #[arg(parse = physical_range::<32, 2>)] range: AddressRange,
) -> Result<MemoryDump> {
    dump_memory(
        session,
        MemoryKind::Physical,
        range,
        MemoryDisplayMode::words(),
    )
}

/// Show guest-physical memory as doublewords.
#[command(
    names = ["!dd"],
    category = "memory and disassembly",
    kind = Query,
    target = Kernel,
    python = none,
)]
fn physical_dd(
    session: &Session,
    #[arg(parse = physical_range::<16, 4>)] range: AddressRange,
) -> Result<MemoryDump> {
    dump_memory(
        session,
        MemoryKind::Physical,
        range,
        MemoryDisplayMode::dwords(),
    )
}

/// Show guest-physical memory as quadwords.
#[command(
    names = ["!dq"],
    category = "memory and disassembly",
    kind = Query,
    target = Kernel,
    python = none,
)]
fn physical_dq(
    session: &Session,
    #[arg(parse = physical_range::<8, 8>)] range: AddressRange,
) -> Result<MemoryDump> {
    dump_memory(
        session,
        MemoryKind::Physical,
        range,
        MemoryDisplayMode::qwords(),
    )
}

/// Bytes written to guest-physical memory.
pub struct PhysicalWritten {
    pub address: u64,
    pub len: usize,
}

impl Render for PhysicalWritten {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        outln!("wrote {} bytes to physical {:#x}", self.len, self.address);
    }
}

/// Write `values` as `unit`s at the physical `address`.
fn write_physical(
    session: &Session,
    address: VirtAddr,
    values: &[u64],
    unit: WriteUnit,
) -> Result<PhysicalWritten> {
    let bytes = unit.encode(values);
    write_memory(session, MemoryKind::Physical, address, &bytes, unit.noun())?;
    Ok(PhysicalWritten {
        address: address.0,
        len: bytes.len(),
    })
}

/// Write one or more bytes to guest-physical memory.
#[command(
    names = ["!eb"],
    category = "memory and disassembly",
    kind = Action,
    target = Kernel,
    writes = [Memory],
    python = none,
)]
fn physical_eb(
    session: &Session,
    #[arg(parse = write_address)] address: VirtAddr,
    #[arg(parse = write_values)] values: Vec<u64>,
) -> Result<PhysicalWritten> {
    write_physical(session, address, &values, WriteUnit::Byte)
}

/// Write one or more doublewords to guest-physical memory.
#[command(
    names = ["!ed"],
    category = "memory and disassembly",
    kind = Action,
    target = Kernel,
    writes = [Memory],
    python = none,
)]
fn physical_ed(
    session: &Session,
    #[arg(parse = write_address)] address: VirtAddr,
    #[arg(parse = write_values)] values: Vec<u64>,
) -> Result<PhysicalWritten> {
    write_physical(session, address, &values, WriteUnit::Dword)
}

/// Write one or more quadwords to guest-physical memory.
#[command(
    names = ["!eq"],
    category = "memory and disassembly",
    kind = Action,
    target = Kernel,
    writes = [Memory],
    python = none,
)]
fn physical_eq(
    session: &Session,
    #[arg(parse = write_address)] address: VirtAddr,
    #[arg(parse = write_values)] values: Vec<u64>,
) -> Result<PhysicalWritten> {
    write_physical(session, address, &values, WriteUnit::Qword)
}

/// `!search`'s value: one to four words in all, else the help.
#[grammar(usage = "<{}>", complete = [Expression])]
fn pointer_value(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<u64, ArgError> {
    if !(1..=4).contains(&cursor.remaining()) {
        return Err(ArgError::Missing);
    }
    let text = cursor.word().ok_or(ArgError::Missing)?;
    Ok(cx.eval(&text)?.0)
}

/// Search guest-physical memory for a pointer-sized value.
///
/// The command compares each pointer-aligned quadword in the PFN range,
/// which is all RAM by default. With no delta, it lists a quadword if it
/// equals the value or differs from it by one bit. With a delta, it lists a
/// quadword if it is within delta of the value or differs from value - delta
/// by one bit. WinDbg's !search uses the same rules. Each hit shows its PFN,
/// its offset, and the value, and from the PFN database, the PTE that maps
/// the page and the virtual address that this PTE maps. The virtual address
/// is `-` when the PTE is not in the self-map. The command skips and
/// counts the pages that it cannot read, and the search stops after 4096
/// hits or when you press Ctrl+C.
#[command(
    names = ["!search"],
    category = "memory and disassembly",
    kind = Query,
    target = Kernel,
    python = none,
)]
fn physical_search(
    session: &Session,
    #[arg(parse = pointer_value)] value: u64,
    #[arg(default = 0)] delta: u64,
    #[arg(name = "start-pfn")] first_pfn: Option<u64>,
    #[arg(name = "end-pfn")] last_pfn: Option<u64>,
) -> Result<PhysicalSearchResult> {
    session
        .target
        .search_physical_pointer(value, delta, first_pfn, last_pfn)
}

impl Render for PhysicalSearchResult {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        outln!(
            "Searching PFNs in range {:x} - {:x} for [{} - {}]\n",
            self.first_pfn,
            self.last_pfn,
            ui::addr(self.data.saturating_sub(self.delta)),
            ui::addr(self.data.saturating_add(self.delta))
        );
        if !self.hits.is_empty() {
            outln!(
                "{:<10} {:<6} {:<16} {:<16} {}",
                "Pfn",
                "Offset",
                "Hit",
                "Va",
                "Pte"
            );
            let page = PAGE_SIZE as u64;
            for hit in &self.hits {
                let optional = |address: Option<VirtAddr>| {
                    address.map_or_else(|| format!("{:<16}", "-"), |address| ui::addr(address.0))
                };
                let value = format!("{:016x}", hit.value);
                let line = format!(
                    "{:<10x} {:<6x} {} {} {}",
                    hit.physical / page,
                    hit.physical % page,
                    if hit.value == self.data {
                        value.bold().to_string()
                    } else {
                        value
                    },
                    optional(hit.va),
                    optional(hit.pte)
                );
                // A missing PTE pads its `-` like any other cell; the row
                // ends there, so the padding goes.
                outln!("{}", line.trim_end());
            }
            outln!();
        }
        outln!(
            "{} {} in {} pages",
            self.hits.len(),
            if self.hits.len() == 1 { "hit" } else { "hits" },
            self.pages
        );
        if self.unreadable_pages > 0 {
            outln!(
                "{}",
                format!("{} unreadable pages skipped", self.unreadable_pages).bright_black()
            );
        }
        print_search_stop(self.stopped, "hits");
    }
}
