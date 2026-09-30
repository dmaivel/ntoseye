//! Translation of a guest physical address through a VTL's extended page
//! tables (EPT), the second-level address translation whose root the VTL's
//! eVMCS names. The entry format is Intel's (SDM Vol. 3C, 29.3.2).

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
}
