//! System PTE usage (`!sysptes`) from the bitmap allocators Windows 10 and
//! later keep in `MiState`: `Vs.SystemPteInfo` and the `SystemPtes` state's
//! view, non-cached-mapping, and kernel-stack allocators, each an
//! `_MI_SYSTEM_PTE_TYPE`.

use super::{SystemPteRun, SystemPteTypeDetail, SystemPtesDetail};
use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::layout::ParsedType;
use crate::memory::PAGE_SIZE;
use crate::target::Target;
use crate::types::VirtAddr;

const PTE_TYPE: &str = "_MI_SYSTEM_PTE_TYPE";
/// `MiState` members that hold `_MI_SYSTEM_PTE_TYPE` allocators.
const CONTAINERS: [&str; 2] = ["Vs", "SystemPtes"];
/// Most free runs listed per allocator.
const MAX_LISTED_RUNS: usize = 256;
/// `_MI_SYSTEM_PTE_TYPE.Flags` bit 0: each bitmap bit covers 16 PTEs. Read
/// from nt!MiReservePtes (build 26200): with the bit set it reserves
/// `NumberOfPtes >> 4` bits and returns `BasePte + (bit << 4)`, otherwise
/// `BasePte + bit`; the system-view allocator is the one that sets it.
const FLAG_16_PTES_PER_BIT: u32 = 1;
const PTE_SIZE: u64 = 8;
/// Most bitmap bits read per allocator: one per PTE of a 512 GiB system-VA
/// region, a 16 MiB bitmap. A larger `SizeOfBitMap` is not an allocator
/// Windows builds; only the bits within this bound are read.
const MAX_BITMAP_BITS: u64 = 1 << 27;

/// Clear-bit runs of an allocation bitmap.
#[derive(Debug, Default, PartialEq, Eq)]
struct BitmapRuns {
    clear_bits: u64,
    run_count: u64,
    largest: u64,
    /// `(first bit, length)` of the first runs, in bit order.
    runs: Vec<(u64, u64)>,
    truncated: bool,
}

/// The runs of clear bits among the first `bits` bits of `bytes`, bit 0 of
/// byte 0 first (an `RTL_BITMAP` on a little-endian target). Bits past
/// `bits` are ignored; at most `max_runs` runs are kept.
fn clear_runs(bytes: &[u8], bits: u64, max_runs: usize) -> BitmapRuns {
    let mut out = BitmapRuns::default();
    let mut run_start: Option<u64> = None;
    let close = |out: &mut BitmapRuns, start: u64, end: u64| {
        let length = end - start;
        out.clear_bits += length;
        out.run_count += 1;
        out.largest = out.largest.max(length);
        if out.runs.len() < max_runs {
            out.runs.push((start, length));
        } else {
            out.truncated = true;
        }
    };
    let bits = bits.min(bytes.len() as u64 * 8);
    let mut bit = 0u64;
    while bit < bits {
        let byte = bytes[(bit / 8) as usize];
        // Whole bytes that do not end or start a run skip bit-by-bit work.
        if bit.is_multiple_of(8) && bit + 8 <= bits && (byte == 0 || byte == 0xff) {
            match (byte, run_start) {
                (0, None) => run_start = Some(bit),
                (0xff, Some(start)) => {
                    close(&mut out, start, bit);
                    run_start = None;
                }
                _ => {}
            }
            bit += 8;
            continue;
        }
        let set = byte & (1 << (bit % 8)) != 0;
        match (set, run_start) {
            (false, None) => run_start = Some(bit),
            (true, Some(start)) => {
                close(&mut out, start, bit);
                run_start = None;
            }
            _ => {}
        }
        bit += 1;
    }
    if let Some(start) = run_start {
        close(&mut out, start, bits);
    }
    out
}

/// The virtual address a PTE in NT's self-map at `pte_base` maps: its index
/// in PTEs, shifted into a page address and sign-extended from bit 47.
fn pte_to_va(pte: VirtAddr, pte_base: VirtAddr) -> VirtAddr {
    let va = (pte.0.wrapping_sub(pte_base.0) / PTE_SIZE) << 12;
    let va = va & 0x0000_ffff_ffff_ffff;
    VirtAddr(if va & (1 << 47) != 0 {
        va | 0xffff_0000_0000_0000
    } else {
        va
    })
}

impl Target {
    /// Maps a PTE address to the virtual address it maps, when the PTE lies
    /// in NT's PTE self-map (one top-level slot: 512 GiB of PTEs; AMD64 and
    /// ARM64 lay it out alike), and to `None` for a PTE elsewhere, such as a
    /// prototype PTE. `None` without `MmPteBase`, which is read once, here.
    pub fn va_mapped_by_pte(&self) -> Option<impl Fn(VirtAddr) -> Option<VirtAddr>> {
        let pte_base: VirtAddr = self
            .guest()
            .ok()?
            .ntoskrnl
            .symbol("MmPteBase")
            .ok()?
            .read()
            .ok()?;
        Some(move |pte: VirtAddr| {
            (pte.0.wrapping_sub(pte_base.0) < 1 << 39).then(|| pte_to_va(pte, pte_base))
        })
    }

    /// Report each system-PTE bitmap allocator: its counters, the VA range
    /// it hands out, and the free runs its bitmap holds (listed when flag
    /// 0x1 is set). A build without `_MI_SYSTEM_PTE_TYPE` allocators
    /// in `MiState` (before Windows 10) is refused.
    pub fn system_ptes(&self, flags: u64) -> Result<SystemPtesDetail> {
        let list_free_runs = flags & 1 != 0;
        let guest = self.guest()?;
        let ntos = &guest.ntoskrnl;
        let types = ntos.types();
        let unsupported = |why: String| {
            Error::DebugInfo(format!(
                "no system-PTE bitmap allocator on this build ({why}); !sysptes reads the \
                 _MI_SYSTEM_PTE_TYPE allocators of Windows 10 and later"
            ))
        };
        let pte_layout = types
            .layout(PTE_TYPE)
            .map_err(|error| unsupported(error.to_string()))?;
        let info = types
            .layout("_MI_SYSTEM_INFORMATION")
            .map_err(|error| unsupported(error.to_string()))?;
        let mi_state = ntos.symbol("MiState")?.address();
        let pte_base: Option<VirtAddr> = ntos.symbol("MmPteBase").and_then(|s| s.read()).ok();
        let va_types = self
            .symbols
            .find_enum_across_modules(ntos.dtb(), "_MI_SYSTEM_VA_TYPE")
            .unwrap_or_default();

        let is_pte_type =
            |ty: &ParsedType| matches!(ty, ParsedType::Struct(name) if name == PTE_TYPE);
        let mut allocators = Vec::new();
        for container in CONTAINERS {
            let Ok(field) = info.field(container) else {
                continue;
            };
            let ParsedType::Struct(container_type) = &field.type_data else {
                continue;
            };
            let layout = types.layout(container_type)?;
            let base = mi_state + field.offset as u64;
            let mut members: Vec<_> = layout.fields.iter().collect();
            members.sort_by_key(|(_, member)| member.offset);
            for (name, member) in members {
                let at = base + member.offset as u64;
                match &member.type_data {
                    ty if is_pte_type(ty) => allocators.push((format!("{container}.{name}"), at)),
                    ParsedType::Array(inner, count) if is_pte_type(inner) => {
                        for index in 0..u64::from(*count) {
                            allocators.push((
                                format!("{container}.{name}[{index}]"),
                                at + index * pte_layout.size as u64,
                            ));
                        }
                    }
                    _ => {}
                }
            }
        }
        if allocators.is_empty() {
            return Err(unsupported(
                "MiState holds no _MI_SYSTEM_PTE_TYPE member".to_string(),
            ));
        }

        let memory = ntos.memory();
        let mut detail = SystemPtesDetail {
            flags,
            types: Vec::with_capacity(allocators.len()),
            total: 0,
            free: 0,
        };
        for (name, address) in allocators {
            let pte_type = types.struct_at(PTE_TYPE, address)?.prefetch();
            let bitmap = pte_type.embedded("Bitmap")?;
            let bitmap_bits = bitmap.read_uint("SizeOfBitMap")?;
            let buffer = bitmap.read_pointer("Buffer")?;
            let type_flags: u32 = pte_type.read_field("Flags")?;
            let ptes_per_bit = if type_flags & FLAG_16_PTES_PER_BIT != 0 {
                16
            } else {
                1
            };
            let base_pte = pte_type.read_pointer("BasePte")?;
            let va_type = pte_type.read_uint("VaType").ok().and_then(|value| {
                va_types
                    .iter()
                    .find(|(_, v)| *v as u64 == value)
                    .map(|(n, _)| n.strip_prefix("MiVa").unwrap_or(n).to_string())
            });
            let tracking = pte_type
                .embedded("TrackingBitmap")
                .and_then(|tracking| tracking.read_pointer("Buffer"))
                .is_ok_and(|buffer| !buffer.is_zero());

            let scanned_bits = bitmap_bits.min(MAX_BITMAP_BITS);
            let length = scanned_bits.div_ceil(8);
            let mut bytes = vec![0u8; length as usize];
            let mut unreadable = 0u64;
            let mut offset = 0usize;
            while offset < bytes.len() {
                let at = buffer + offset as u64;
                let chunk = (PAGE_SIZE - at.page_offset() as usize).min(bytes.len() - offset);
                let slice = &mut bytes[offset..offset + chunk];
                if memory.read_bytes(at, slice).is_err() {
                    slice.fill(0xff);
                    unreadable += chunk as u64;
                }
                offset += chunk;
            }
            let runs = clear_runs(
                &bytes,
                scanned_bits,
                if list_free_runs { MAX_LISTED_RUNS } else { 0 },
            );
            let free_runs = runs
                .runs
                .iter()
                .map(|&(bit, length)| {
                    let pte = base_pte + bit * ptes_per_bit * PTE_SIZE;
                    SystemPteRun {
                        pte,
                        va: pte_base.map(|pte_base| pte_to_va(pte, pte_base)),
                        ptes: length * ptes_per_bit,
                    }
                })
                .collect();

            let total = pte_type.read_uint("TotalSystemPtes")?;
            let free = pte_type.read_uint("TotalFreeSystemPtes")?;
            detail.total += total;
            detail.free += free;
            detail.types.push(SystemPteTypeDetail {
                name,
                address,
                va_type,
                flags: type_flags,
                ptes_per_bit,
                base_pte,
                base_va: pte_base
                    .filter(|_| !base_pte.is_zero())
                    .map(|pte_base| pte_to_va(base_pte, pte_base)),
                bitmap: buffer,
                bitmap_bits,
                total,
                free,
                failures: pte_type.read_field("PteFailures")?,
                bitmap_free: runs.clear_bits * ptes_per_bit,
                unreadable_bitmap_bytes: unreadable,
                unscanned_bitmap_bits: bitmap_bits - scanned_bits,
                free_run_count: runs.run_count,
                largest_free_run: runs.largest * ptes_per_bit,
                free_runs,
                free_runs_truncated: list_free_runs && runs.truncated,
                tracking,
            });
        }
        Ok(detail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clear_runs_cross_bytes_and_stop_at_the_bitmap_size() {
        // Bits 0-2 set, 3-12 clear (across the byte boundary), 13 set,
        // 14-15 clear; the size of 15 bits cuts the last run to one bit.
        let bytes = [0b0000_0111, 0b0010_0000];
        let runs = clear_runs(&bytes, 15, 8);
        assert_eq!(runs.runs, [(3, 10), (14, 1)]);
        assert_eq!((runs.clear_bits, runs.run_count, runs.largest), (11, 2, 10));
    }

    #[test]
    fn whole_clear_bytes_extend_a_run_started_mid_byte() {
        // Bits 4-7 clear, then two clear bytes, then a set byte.
        let bytes = [0x0f, 0x00, 0x00, 0xff];
        let runs = clear_runs(&bytes, 32, 8);
        assert_eq!(runs.runs, [(4, 20)]);
    }

    #[test]
    fn runs_past_the_listing_bound_are_counted_not_kept() {
        let bytes = [0b1010_1010];
        let runs = clear_runs(&bytes, 8, 2);
        assert_eq!(runs.runs, [(0, 1), (2, 1)]);
        assert_eq!(runs.run_count, 4);
        assert!(runs.truncated);
    }

    #[test]
    fn pte_addresses_map_back_to_kernel_vas() {
        // Build 26200 live: MmPteBase ffff910000000000, and the system-PTE
        // allocator's BasePte ffff917280000000 heads the SystemPtes region
        // at ffffe50000000000.
        let pte_base = VirtAddr(0xffff_9100_0000_0000);
        assert_eq!(
            pte_to_va(VirtAddr(0xffff_9172_8000_0000), pte_base),
            VirtAddr(0xffff_e500_0000_0000)
        );
        // A user-half PTE is not sign-extended.
        assert_eq!(
            pte_to_va(VirtAddr(0xffff_9100_0000_0008), pte_base),
            VirtAddr(0x1000)
        );
    }
}
