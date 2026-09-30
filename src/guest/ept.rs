//! Translation of a guest physical address through a VTL's extended page
//! tables (EPT), the second-level address translation whose root the VTL's
//! eVMCS names. The entry format is Intel's (SDM Vol. 3C, 29.3.2).

use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::types::PhysAddr;

/// Physical-address bits of an EPT pointer or entry.
const ADDRESS: u64 = 0x000f_ffff_ffff_f000;
const READ: u64 = 1 << 0;
const WRITE: u64 = 1 << 1;
const EXECUTE: u64 = 1 << 2;
const LARGE: u64 = 1 << 7;
/// Execute access for user-mode linear addresses, with mode-based execute
/// control; bit 2 then covers supervisor mode only.
const USER_EXECUTE: u64 = 1 << 10;

/// Where a guest physical address goes through one EPT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EptTranslation {
    Mapped(EptMapping),
    /// No entry maps the address: the walk stopped at `level` (4 is the
    /// PML4), where the entry has no access bits.
    NotPresent {
        level: u8,
    },
}

/// A mapped guest physical address and the access the walk allows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EptMapping {
    pub host_physical: u64,
    /// 4 KiB, 2 MiB, or 1 GiB.
    pub page_size: u64,
    /// Each access is allowed only if every entry of the walk allows it.
    pub read: bool,
    pub write: bool,
    /// Supervisor-mode execute when `user_execute` is known, else any.
    pub execute: bool,
    /// User-mode execute, when the VTL uses mode-based execute control.
    pub user_execute: Option<bool>,
    /// The memory type of the leaf entry (0 UC, 1 WC, 4 WT, 5 WP, 6 WB).
    pub memory_type: u8,
    /// The entry of each level, from the PML4 down.
    pub entries: Vec<u64>,
}

/// Translate `gpa` through the EPT that `eptp` roots, reading qwords of
/// host physical memory with `read`. `mode_based` says whether the VTL uses
/// mode-based execute control. `None` when a table is unreadable or the
/// pointer does not describe a 4-level walk.
pub fn translate(
    eptp: u64,
    gpa: u64,
    mode_based: bool,
    mut read: impl FnMut(u64) -> Option<u64>,
) -> Option<EptTranslation> {
    // Bits 5:3 hold the walk length minus one.
    if (eptp >> 3) & 7 != 3 {
        return None;
    }
    let mut table = eptp & ADDRESS;
    let mut allowed = READ | WRITE | EXECUTE | USER_EXECUTE;
    let mut entries = Vec::with_capacity(4);
    for (level, shift) in [(4u8, 39u32), (3, 30), (2, 21), (1, 12)] {
        let entry = read(table + ((gpa >> shift) & 0x1ff) * 8)?;
        entries.push(entry);
        if entry & (READ | WRITE | EXECUTE) == 0 {
            return Some(EptTranslation::NotPresent { level });
        }
        allowed &= entry;
        if level == 1 || (entry & LARGE != 0 && level <= 3) {
            let page_size = 1u64 << shift;
            return Some(EptTranslation::Mapped(EptMapping {
                host_physical: (entry & ADDRESS & !(page_size - 1)) | (gpa & (page_size - 1)),
                page_size,
                read: allowed & READ != 0,
                write: allowed & WRITE != 0,
                execute: allowed & EXECUTE != 0,
                user_execute: mode_based.then_some(allowed & USER_EXECUTE != 0),
                memory_type: ((entry >> 3) & 7) as u8,
                entries,
            }));
        }
        table = entry & ADDRESS;
    }
    None
}

/// The access an EPT walk allows, as the entry bits (`READ`, `WRITE`,
/// `EXECUTE`, and `USER_EXECUTE` under mode-based execute control).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Access(u8);

impl Access {
    pub fn read(self) -> bool {
        self.0 & READ as u8 != 0
    }

    pub fn write(self) -> bool {
        self.0 & WRITE as u8 != 0
    }

    pub fn execute(self) -> bool {
        self.0 & EXECUTE as u8 != 0
    }

    /// User-mode execute, under mode-based execute control.
    pub fn user_execute(self) -> Option<bool> {
        (self.0 & 0x80 != 0).then_some(self.0 & 0x40 != 0)
    }

    fn of(allowed: u64, mode_based: bool) -> Self {
        let mut bits = (allowed & (READ | WRITE | EXECUTE)) as u8;
        if mode_based {
            bits |= 0x80 | if allowed & USER_EXECUTE != 0 { 0x40 } else { 0 };
        }
        Self(bits)
    }
}

/// `rwx`, with `u` or `-` added for user-mode execute under mode-based
/// execute control.
impl std::fmt::Display for Access {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bit = |allowed: bool, letter: char| if allowed { letter } else { '-' };
        write!(
            f,
            "{}{}{}",
            bit(self.read(), 'r'),
            bit(self.write(), 'w'),
            bit(self.execute(), 'x')
        )?;
        match self.user_execute() {
            Some(user) => write!(f, "{}", bit(user, 'u')),
            None => Ok(()),
        }
    }
}

/// One leaf of an EPT: `size` bytes of guest physical memory at `gpa`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Leaf {
    pub gpa: u64,
    pub size: u64,
    pub access: Access,
}

/// Every leaf of the EPT that `eptp` roots, in address order, reading each
/// 4 KiB table of host physical memory with `read_table`. `None` when a table
/// is unreadable or the pointer does not describe a 4-level walk.
pub fn leaves(
    eptp: u64,
    mode_based: bool,
    mut read_table: impl FnMut(u64) -> Option<[u64; 512]>,
) -> Option<Vec<Leaf>> {
    fn visit(
        table: u64,
        level: u8,
        base: u64,
        allowed: u64,
        mode_based: bool,
        read_table: &mut dyn FnMut(u64) -> Option<[u64; 512]>,
        out: &mut Vec<Leaf>,
    ) -> Option<()> {
        let shift = 12 + 9 * u32::from(level - 1);
        for (index, entry) in read_table(table)?.into_iter().enumerate() {
            if entry & (READ | WRITE | EXECUTE) == 0 {
                continue;
            }
            let gpa = base | ((index as u64) << shift);
            let allowed = allowed & entry;
            if level == 1 || (entry & LARGE != 0 && level <= 3) {
                out.push(Leaf {
                    gpa,
                    size: 1 << shift,
                    access: Access::of(allowed, mode_based),
                });
            } else {
                visit(
                    entry & ADDRESS,
                    level - 1,
                    gpa,
                    allowed,
                    mode_based,
                    read_table,
                    out,
                )?;
            }
        }
        Some(())
    }
    if (eptp >> 3) & 7 != 3 {
        return None;
    }
    let mut out = Vec::new();
    let all = READ | WRITE | EXECUTE | USER_EXECUTE;
    visit(
        eptp & ADDRESS,
        4,
        0,
        all,
        mode_based,
        &mut read_table,
        &mut out,
    )?;
    Some(out)
}

/// A range of guest physical memory, `start..end`, that two EPTs map
/// differently: with different access, or in one of them only (`None`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Difference {
    pub start: u64,
    pub end: u64,
    pub first: Option<Access>,
    pub second: Option<Access>,
}

/// The ranges where the leaves `first` and `second` (each in address order,
/// as [`leaves`] gives them) differ, adjacent ranges that differ the same way
/// merged.
pub fn differences(first: &[Leaf], second: &[Leaf]) -> Vec<Difference> {
    let mut bounds: Vec<u64> = first
        .iter()
        .chain(second)
        .flat_map(|leaf| [leaf.gpa, leaf.gpa + leaf.size])
        .collect();
    bounds.sort_unstable();
    bounds.dedup();
    // The access of `leaves` over `start..`, advancing `cursor` past leaves
    // that end at or before `start`.
    fn at(leaves: &[Leaf], cursor: &mut usize, start: u64) -> Option<Access> {
        while leaves
            .get(*cursor)
            .is_some_and(|leaf| leaf.gpa + leaf.size <= start)
        {
            *cursor += 1;
        }
        leaves
            .get(*cursor)
            .filter(|leaf| leaf.gpa <= start)
            .map(|leaf| leaf.access)
    }
    let (mut a, mut b) = (0, 0);
    let mut out: Vec<Difference> = Vec::new();
    for pair in bounds.windows(2) {
        let (start, end) = (pair[0], pair[1]);
        let (first, second) = (at(first, &mut a, start), at(second, &mut b, start));
        if first == second {
            continue;
        }
        match out.last_mut() {
            Some(last) if last.end == start && last.first == first && last.second == second => {
                last.end = end;
            }
            _ => out.push(Difference {
                start,
                end,
                first,
                second,
            }),
        }
    }
    out
}

/// The physical memory of a guest of the hypervisor, read through its EPT:
/// each guest physical page is translated and read from host physical memory
/// with `host`. Pages the EPT does not map are unreadable, and it is
/// read-only.
pub struct EptMemory<'a, B: MemoryOps<PhysAddr>> {
    host: &'a B,
    eptp: u64,
    mode_based: bool,
}

impl<'a, B: MemoryOps<PhysAddr>> EptMemory<'a, B> {
    pub fn new(host: &'a B, eptp: u64, mode_based: bool) -> Self {
        Self {
            host,
            eptp,
            mode_based,
        }
    }

    /// The host physical address of guest physical `gpa`.
    pub fn host_address(&self, gpa: u64) -> Result<u64> {
        let translation = translate(self.eptp, gpa, self.mode_based, |address| {
            self.host.read::<u64>(address).ok()
        });
        match translation {
            Some(EptTranslation::Mapped(mapping)) if mapping.read => Ok(mapping.host_physical),
            Some(_) => Err(Error::Hypervisor(format!(
                "guest physical {gpa:#x} is not mapped"
            ))),
            None => Err(Error::Hypervisor(
                "the EPT is unreadable or not a 4-level walk".to_string(),
            )),
        }
    }
}

impl<B: MemoryOps<PhysAddr>> MemoryOps<PhysAddr> for EptMemory<'_, B> {
    fn read_bytes(&self, addr: PhysAddr, buf: &mut [u8]) -> Result<()> {
        let mut done = 0;
        while done < buf.len() {
            let gpa = addr + done as u64;
            let in_page = (0x1000 - (gpa & 0xfff)) as usize;
            let chunk = in_page.min(buf.len() - done);
            self.host
                .read_bytes(self.host_address(gpa)?, &mut buf[done..done + chunk])?;
            done += chunk;
        }
        Ok(())
    }

    fn write_bytes(&self, _addr: PhysAddr, _buf: &[u8]) -> Result<()> {
        Err(Error::Hypervisor(
            "a guest partition's memory is read-only".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    /// A 4-level, write-back EPT pointer rooted at `root`.
    fn eptp(root: u64) -> u64 {
        root | (3 << 3) | 6
    }

    const PML4: u64 = 0x1000;
    const PDPT: u64 = 0x2000;
    const PD: u64 = 0x3000;
    const PT: u64 = 0x4000;
    const RWX: u64 = READ | WRITE | EXECUTE;
    const WB: u64 = 6 << 3;

    /// Tables mapping GPA 0x20_1000 through a 4 KiB leaf with `leaf`'s bits,
    /// and the upper levels with `upper`'s.
    fn tables(upper: u64, leaf: u64) -> HashMap<u64, u64> {
        HashMap::from([
            (PML4, PDPT | upper),
            (PDPT, PD | upper),
            (PD + 8, PT | upper),
            (PT + 8, 0x7_7000 | leaf | WB),
        ])
    }

    fn walk(memory: &HashMap<u64, u64>, gpa: u64, mode_based: bool) -> Option<EptTranslation> {
        translate(eptp(PML4), gpa, mode_based, |address| {
            Some(memory.get(&address).copied().unwrap_or(0))
        })
    }

    #[test]
    fn an_access_is_allowed_only_if_every_level_allows_it() {
        let Some(EptTranslation::Mapped(mapping)) =
            walk(&tables(READ | EXECUTE, RWX), 0x20_1234, false)
        else {
            panic!("not mapped");
        };
        assert_eq!(mapping.host_physical, 0x7_7234);
        assert_eq!(
            (mapping.read, mapping.write, mapping.execute),
            (true, false, true)
        );
        assert_eq!((mapping.page_size, mapping.memory_type), (0x1000, 6));
    }

    #[test]
    fn a_large_leaf_keeps_the_offset_within_its_page() {
        let memory = HashMap::from([
            (PML4, PDPT | RWX),
            (PDPT, PD | RWX),
            (PD + 8, 0x4020_0000 | LARGE | READ | WB),
        ]);
        let Some(EptTranslation::Mapped(mapping)) = walk(&memory, 0x2f_1234, false) else {
            panic!("not mapped");
        };
        assert_eq!(
            (mapping.host_physical, mapping.page_size),
            (0x402f_1234, 0x20_0000)
        );
        assert_eq!(
            (mapping.read, mapping.write, mapping.execute),
            (true, false, false)
        );
    }

    #[test]
    fn a_missing_entry_names_the_level_the_walk_stopped_at() {
        let memory = HashMap::from([(PML4, PDPT | RWX), (PDPT, PD | RWX)]);
        assert_eq!(
            walk(&memory, 0x20_1000, false),
            Some(EptTranslation::NotPresent { level: 2 })
        );
    }

    #[test]
    fn user_execute_is_reported_only_under_mode_based_control() {
        let memory = tables(RWX | USER_EXECUTE, READ | EXECUTE);
        let mapped = |mode_based| match walk(&memory, 0x20_1000, mode_based) {
            Some(EptTranslation::Mapped(mapping)) => mapping.user_execute,
            other => panic!("{other:?}"),
        };
        assert_eq!(mapped(false), None);
        assert_eq!(mapped(true), Some(false));
    }

    #[test]
    fn a_pointer_that_is_not_a_four_level_walk_is_refused() {
        let memory = tables(RWX, RWX);
        assert!(
            translate(PML4 | (4 << 3) | 6, 0x20_1000, false, |a| memory
                .get(&a)
                .copied())
            .is_none()
        );
    }

    /// Each table of `memory`, as 512 qwords.
    fn table_of(memory: &HashMap<u64, u64>) -> impl FnMut(u64) -> Option<[u64; 512]> + '_ {
        |table| {
            let mut entries = [0u64; 512];
            for (index, entry) in entries.iter_mut().enumerate() {
                *entry = memory
                    .get(&(table + 8 * index as u64))
                    .copied()
                    .unwrap_or(0);
            }
            Some(entries)
        }
    }

    fn access(bits: u64) -> Access {
        Access::of(bits, false)
    }

    #[test]
    fn leaves_list_every_mapping_with_the_access_of_its_walk() {
        let mut memory = tables(READ | EXECUTE, RWX);
        memory.insert(PD + 16, 0x80_0000 | LARGE | RWX | WB);
        let found = leaves(eptp(PML4), false, table_of(&memory)).unwrap();
        assert_eq!(
            found,
            [
                Leaf {
                    gpa: 0x20_1000,
                    size: 0x1000,
                    access: access(READ | EXECUTE)
                },
                Leaf {
                    gpa: 0x40_0000,
                    size: 0x20_0000,
                    access: access(READ | EXECUTE)
                },
            ]
        );
    }

    #[test]
    fn differences_split_a_large_page_where_the_other_side_differs_and_merge_runs() {
        let large = [Leaf {
            gpa: 0x20_0000,
            size: 0x20_0000,
            access: access(RWX),
        }];
        let small: Vec<Leaf> = (0..0x200u64)
            .filter(|page| *page != 7)
            .map(|page| Leaf {
                gpa: 0x20_0000 + page * 0x1000,
                size: 0x1000,
                access: access(if (3..5).contains(&page) {
                    READ | EXECUTE
                } else {
                    RWX
                }),
            })
            .collect();
        assert_eq!(
            differences(&large, &small),
            [
                Difference {
                    start: 0x20_3000,
                    end: 0x20_5000,
                    first: Some(access(RWX)),
                    second: Some(access(READ | EXECUTE)),
                },
                Difference {
                    start: 0x20_7000,
                    end: 0x20_8000,
                    first: Some(access(RWX)),
                    second: None
                },
            ]
        );
    }

    /// Host physical memory for [`EptMemory`]: page tables from `tables`,
    /// and every other byte its own address's low byte.
    struct Host(HashMap<u64, u64>);

    impl MemoryOps<PhysAddr> for Host {
        fn read_bytes(&self, addr: PhysAddr, buf: &mut [u8]) -> Result<()> {
            if let Some(entry) = self.0.get(&addr) {
                buf.copy_from_slice(&entry.to_le_bytes()[..buf.len()]);
            } else {
                for (index, byte) in buf.iter_mut().enumerate() {
                    *byte = (addr + index as u64) as u8;
                }
            }
            Ok(())
        }

        fn write_bytes(&self, _addr: PhysAddr, _buf: &[u8]) -> Result<()> {
            unreachable!()
        }
    }

    #[test]
    fn guest_memory_reads_each_page_where_the_ept_puts_it() {
        let mut memory = tables(RWX, RWX);
        // GPA 0x20_2000 goes to host 0x9_9000, not after 0x20_1000's 0x7_7000.
        memory.insert(PT + 16, 0x9_9000 | RWX | WB);
        let host = Host(memory);
        let guest = EptMemory::new(&host, eptp(PML4), false);
        let mut buf = [0u8; 4];
        guest.read_bytes(0x20_1ffe, &mut buf).unwrap();
        assert_eq!(buf, [0xfe, 0xff, 0x00, 0x01]);
        assert_eq!(guest.host_address(0x20_2010).unwrap(), 0x9_9010);
        assert!(guest.read_bytes(0x20_3000, &mut buf).is_err());
    }
}
