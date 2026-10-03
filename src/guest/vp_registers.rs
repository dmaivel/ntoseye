//! The registers of a Windows hypervisor VP that no processor runs. Its
//! exit entry saves a VP's general-purpose registers into a block the VP
//! object points at, in a 2 MiB region of the VP's own. A processor's root
//! maps only the region of the VP it runs, so the block of any other VP is
//! unmapped everywhere; the hypervisor maps it back from a descriptor the VP
//! object also points at, which holds the region's address and the page
//! directory entry that maps it. `hvix64` has no symbols, so where those
//! pointers and fields are is calibrated on the VPs whose regions are
//! mapped at a halt, must agree for all of them, and must lead every other
//! VP to the region its own block is in.

use std::collections::HashMap;

use crate::error::{Error, Result};

const PRESENT: u64 = 1;
const LARGE: u64 = 1 << 7;
const FRAME: u64 = 0x000f_ffff_ffff_f000;
/// A region is one 2 MiB page directory slot.
const REGION: u64 = 0x1f_ffff;

/// The present page directory entry that maps `va` under the AMD64 root
/// `root`, reading qwords of physical memory through `phys`; `None` when
/// a level above it is not present or maps a 1 GiB page.
pub fn pde_of(root: u64, va: u64, phys: &impl Fn(u64) -> Option<u64>) -> Option<u64> {
    let pml4e = phys((root & FRAME) + ((va >> 39) & 0x1ff) * 8)?;
    if pml4e & PRESENT == 0 {
        return None;
    }
    let pdpte = phys((pml4e & FRAME) + ((va >> 30) & 0x1ff) * 8)?;
    if pdpte & PRESENT == 0 || pdpte & LARGE != 0 {
        return None;
    }
    let pde = phys((pdpte & FRAME) + ((va >> 21) & 0x1ff) * 8)?;
    (pde & PRESENT != 0).then_some(pde)
}

/// The physical address of `va` in the region the page directory entry
/// `pde` maps: a 2 MiB page, or through its page table.
pub fn physical_in_region(pde: u64, va: u64, phys: &impl Fn(u64) -> Option<u64>) -> Option<u64> {
    if pde & PRESENT == 0 {
        return None;
    }
    if pde & LARGE != 0 {
        return Some((pde & FRAME & !REGION) | (va & REGION));
    }
    let pte = phys((pde & FRAME) + ((va >> 12) & 0x1ff) * 8)?;
    (pte & PRESENT != 0).then_some((pte & FRAME) | (va & 0xfff))
}

/// Where a VP's saved exit registers are reached from its VP object, as
/// offsets of the hypervisor build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VpRegisterLayout {
    /// The VP object's pointer to its register block.
    pub block_pointer: u64,
    /// The VP object's pointer to its region descriptor.
    pub descriptor: u64,
    /// The descriptor's copy of its region's address.
    pub region: u64,
    /// The descriptor's page directory entry that maps the region.
    pub region_pde: u64,
}

/// How far into a VP object its descriptor pointer is looked for, and how
/// far into a descriptor its fields are.
const VP_SPAN: u64 = 0x1000;
const DESCRIPTOR_SPAN: usize = 0x400;
/// A VP object is a few pages; a block pointer past this is not in it.
const MAX_BLOCK_POINTER: u64 = 0x10000;

/// A VP whose region a processor's root maps at the halt, as the exit entry
/// of its loaded eVMCS finds its block: `pointer` is the address of the
/// qword the entry loads the block address from, `region` the 2 MiB region
/// the block is in, and `region_pde` the root's page directory entry that
/// maps it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadedVp {
    pub vp: u64,
    pub pointer: u64,
    pub region: u64,
    pub region_pde: u64,
}

/// The layout under which every VP in `loaded` reaches its block and its
/// region's descriptor, reading the hypervisor's memory through `read`
/// (`None` where it is unreadable). The block pointer's offset in the VP
/// object must be the same for all of them, and exactly one pointer of the
/// VP object, with one offset of each field, must lead every one of them to
/// a descriptor that holds its region's address and page directory entry,
/// and every VP object in `vps`, mapped or not, to a descriptor that holds
/// the region its block is in. A halt maps only a few VPs' regions, and
/// another pointer of their objects can lead to the same fields by chance:
/// on 26200, the one 0x60 past the descriptor pointer points 0x80 short of
/// the descriptor in some VPs and elsewhere in the rest.
pub fn calibrate(
    loaded: &[LoadedVp],
    vps: &[u64],
    read: impl Fn(u64, usize) -> Option<Vec<u8>>,
) -> Result<VpRegisterLayout> {
    let Some(first) = loaded.first() else {
        return Err(calibration_error(
            "no VP's register region is mapped at this halt",
        ));
    };
    let block_pointer = first.pointer.wrapping_sub(first.vp);
    if block_pointer >= MAX_BLOCK_POINTER
        || loaded
            .iter()
            .any(|vp| vp.pointer.wrapping_sub(vp.vp) != block_pointer)
    {
        return Err(calibration_error(
            "the VPs' exit entries do not load their register blocks from one offset of the VP",
        ));
    }
    let mut found: Option<Vec<(u64, u64, u64)>> = None;
    for vp in loaded {
        let candidates = descriptor_candidates(vp, &read);
        found = Some(match found {
            None => candidates,
            Some(earlier) => earlier
                .into_iter()
                .filter(|c| candidates.contains(c))
                .collect(),
        });
    }
    let qword = |address: u64| {
        read(address, 8)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u64::from_le_bytes)
    };
    // A VP whose block is unknown says nothing; one whose descriptor, under
    // a candidate, names another region than its block's rules it out.
    let leads_every_vp = |&(descriptor, region, _): &(u64, u64, u64)| {
        vps.iter().all(|&vp| {
            let Some(block) = qword(vp.wrapping_add(block_pointer)).filter(|&block| block != 0)
            else {
                return true;
            };
            qword(vp.wrapping_add(descriptor))
                .and_then(|descriptor| qword(descriptor.wrapping_add(region)))
                == Some(block & !REGION)
        })
    };
    let found = found.map(|found| found.into_iter().filter(leads_every_vp).collect::<Vec<_>>());
    match found.as_deref() {
        Some([(descriptor, region, region_pde)]) => Ok(VpRegisterLayout {
            block_pointer,
            descriptor: *descriptor,
            region: *region,
            region_pde: *region_pde,
        }),
        Some([]) | None => Err(calibration_error(
            "no pointer of the VP leads every mapped VP to its region's page directory entry and every VP to its block's region",
        )),
        Some(several) => Err(calibration_error(format!(
            "{} pointers of the VP lead every mapped VP to its region's page directory entry and every VP to its block's region",
            several.len()
        ))),
    }
}

/// Every `(descriptor, region, region_pde)` offset triple under which `vp`'s
/// object points at a descriptor holding its region and page directory
/// entry.
fn descriptor_candidates(
    vp: &LoadedVp,
    read: &impl Fn(u64, usize) -> Option<Vec<u8>>,
) -> Vec<(u64, u64, u64)> {
    let Some(object) = read(vp.vp, VP_SPAN as usize) else {
        return Vec::new();
    };
    let qwords = |bytes: &[u8]| -> Vec<u64> {
        bytes
            .as_chunks::<8>()
            .0
            .iter()
            .map(|chunk| u64::from_le_bytes(*chunk))
            .collect()
    };
    let mut out = Vec::new();
    for (index, pointer) in qwords(&object).into_iter().enumerate() {
        // Hypervisor objects are in the upper half.
        if pointer >> 47 != 0x1ffff {
            continue;
        }
        let Some(descriptor) = read(pointer, DESCRIPTOR_SPAN) else {
            continue;
        };
        let fields = qwords(&descriptor);
        let at = |value: u64| {
            fields
                .iter()
                .enumerate()
                .filter(move |(_, field)| **field == value)
                .map(|(at, _)| at as u64 * 8)
        };
        for region in at(vp.region) {
            for region_pde in at(vp.region_pde) {
                out.push((index as u64 * 8, region, region_pde));
            }
        }
    }
    out
}

fn calibration_error(detail: impl std::fmt::Display) -> Error {
    Error::Hypervisor(format!(
        "where VPs keep their saved registers is not recognized: {detail}"
    ))
}

/// The general-purpose registers the VP object at `vp` saved at its last
/// exit, each at its `offsets` entry in the block, read through its
/// region's page directory entry whether or not a root maps the region:
/// `read` reads the hypervisor's memory, `phys` physical memory, a qword
/// at a time.
pub fn saved_registers(
    layout: &VpRegisterLayout,
    vp: u64,
    offsets: &[(&'static str, i64)],
    read: impl Fn(u64) -> Option<u64>,
    phys: impl Fn(u64) -> Option<u64>,
) -> Result<HashMap<&'static str, u64>> {
    let unreadable = |what: &str| Error::Hypervisor(format!("the VP's {what} is unreadable"));
    let block = read(vp.wrapping_add(layout.block_pointer))
        .ok_or_else(|| unreadable("register block pointer"))?;
    let descriptor = read(vp.wrapping_add(layout.descriptor))
        .ok_or_else(|| unreadable("region descriptor pointer"))?;
    let region = read(descriptor.wrapping_add(layout.region))
        .ok_or_else(|| unreadable("region descriptor"))?;
    let pde = read(descriptor.wrapping_add(layout.region_pde))
        .ok_or_else(|| unreadable("region descriptor"))?;
    if block & !REGION != region {
        return Err(Error::Hypervisor(format!(
            "the VP's register block {block:#x} is outside its region {region:#x}"
        )));
    }
    offsets
        .iter()
        .map(|&(name, offset)| {
            let address = block.wrapping_add_signed(offset);
            let value = physical_in_region(pde, address, &phys).and_then(&phys);
            Ok((
                name,
                value.ok_or_else(|| {
                    Error::Hypervisor(format!(
                        "the VP's register region does not map {address:#x}"
                    ))
                })?,
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{LoadedVp, VpRegisterLayout, calibrate, saved_registers};

    const LAYOUT: VpRegisterLayout = VpRegisterLayout {
        block_pointer: 0xec0,
        descriptor: 0x418,
        region: 0x248,
        region_pde: 0x278,
    };

    /// Hypervisor memory: qwords by address, zero elsewhere.
    #[derive(Default)]
    struct Memory(HashMap<u64, u64>);

    impl Memory {
        fn put(&mut self, address: u64, value: u64) {
            self.0.insert(address, value);
        }

        fn qword(&self, address: u64) -> Option<u64> {
            Some(self.0.get(&address).copied().unwrap_or(0))
        }

        fn bytes(&self, address: u64, size: usize) -> Option<Vec<u8>> {
            Some(
                (0..size as u64 / 8)
                    .flat_map(|at| self.qword(address + at * 8).unwrap().to_le_bytes())
                    .collect(),
            )
        }
    }

    /// A VP object at `vp` whose descriptor at `descriptor` names `region`
    /// and the page directory entry `pde`, and whose block pointer is
    /// `block`, laid out as [`LAYOUT`].
    fn vp(
        memory: &mut Memory,
        vp: u64,
        descriptor: u64,
        region: u64,
        pde: u64,
        block: u64,
    ) -> LoadedVp {
        memory.put(vp + LAYOUT.block_pointer, block);
        memory.put(vp + LAYOUT.descriptor, descriptor);
        memory.put(descriptor + LAYOUT.region, region);
        memory.put(descriptor + LAYOUT.region_pde, pde);
        LoadedVp {
            vp,
            pointer: vp + LAYOUT.block_pointer,
            region,
            region_pde: pde,
        }
    }

    /// The offsets are the ones under which every mapped VP's object leads
    /// to its own region and page directory entry: a pointer that leads one
    /// VP's object to a copy of them, but not the other's, is not it.
    #[test]
    fn calibration_keeps_the_pointer_every_mapped_vp_agrees_on() {
        let mut memory = Memory::default();
        let first = vp(
            &mut memory,
            0xffffe800_0026c050,
            0xffffe800_00271050,
            0xffffe700_00000000,
            0x1160de063,
            0xffffe700_00007080,
        );
        let second = vp(
            &mut memory,
            0xffffe800_00389050,
            0xffffe800_0038a6c0,
            0xffffe700_00200000,
            0x118207063,
            0xffffe700_00207080,
        );
        // A decoy: another pointer of the first VP to an object that also
        // holds its region and page directory entry.
        memory.put(first.vp + 0x478, 0xffffe800_00500000);
        memory.put(0xffffe800_00500000 + 0x248, first.region);
        memory.put(0xffffe800_00500000 + 0x278, first.region_pde);

        let read = |address, size| memory.bytes(address, size);
        assert_eq!(
            calibrate(&[first, second], &[first.vp, second.vp], read).unwrap(),
            LAYOUT
        );
        assert!(
            calibrate(&[first], &[first.vp], read).is_err(),
            "one VP leaves the decoy in"
        );
    }

    /// A halt maps only a few VPs' regions, and another pointer of their
    /// objects can lead to the same fields by chance: on 26200, the one at
    /// 0x478 points 0x80 short of the descriptor in some VPs. A VP the halt
    /// does not map rules it out, as under it that VP's descriptor does not
    /// name the region its block is in.
    #[test]
    fn an_unmapped_vp_rules_out_a_pointer_only_the_mapped_ones_agree_on() {
        let mut memory = Memory::default();
        let mapped = vp(
            &mut memory,
            0xffffe800_0038a050,
            0xffffe800_0038a6c0,
            0xffffe700_00200000,
            0x129006063,
            0xffffe700_00207080,
        );
        let unmapped = vp(
            &mut memory,
            0xffffe800_003ad050,
            0xffffe800_003b26c0,
            0xffffe700_00400000,
            0x12903f063,
            0xffffe700_00407080,
        );
        memory.put(mapped.vp + 0x478, 0xffffe800_0038a6c0 - 0x80);

        let read = |address, size| memory.bytes(address, size);
        assert!(
            calibrate(&[mapped], &[mapped.vp], read).is_err(),
            "the mapped VP alone cannot tell the two pointers apart"
        );
        assert_eq!(
            calibrate(&[mapped], &[mapped.vp, unmapped.vp], read).unwrap(),
            LAYOUT
        );
    }

    /// VPs whose exit entries load their blocks from different offsets of
    /// their objects are no layout.
    #[test]
    fn calibration_refuses_block_pointers_at_different_offsets() {
        let mut memory = Memory::default();
        let first = vp(
            &mut memory,
            0xffffe800_0026c050,
            0xffffe800_00271050,
            0xffffe700_00000000,
            0x1160de063,
            0xffffe700_00007080,
        );
        let mut second = vp(
            &mut memory,
            0xffffe800_00389050,
            0xffffe800_0038a6c0,
            0xffffe700_00200000,
            0x118207063,
            0xffffe700_00207080,
        );
        second.pointer += 8;
        assert!(
            calibrate(&[first, second], &[first.vp, second.vp], |address, size| {
                memory.bytes(address, size)
            })
            .is_err()
        );
        assert!(calibrate(&[], &[], |address, size| memory.bytes(address, size)).is_err());
    }

    /// A VP's block is read through its descriptor's page directory entry
    /// and the page table it names, at each register's offset; a block
    /// outside the descriptor's region is not the VP's.
    #[test]
    fn a_block_is_read_through_its_regions_page_table() {
        const PAGE_TABLE: u64 = 0x1160_de000;
        const PAGE: u64 = 0x1160_ea000;
        let mut memory = Memory::default();
        let loaded = vp(
            &mut memory,
            0xffffe803_c507c050,
            0xffffe803_c5080000,
            0xffffe700_00e00000,
            PAGE_TABLE | 0x63,
            0xffffe700_00e07080,
        );
        let mut phys = Memory::default();
        // The block's page is the region's eighth: PTE 7.
        phys.put(PAGE_TABLE + 7 * 8, PAGE | 0x63);
        phys.put(PAGE + 0x080, 0x1111);
        phys.put(PAGE + 0x088, 0x2222);
        let offsets = [("rax", 0), ("rcx", 8)];
        let registers = saved_registers(
            &LAYOUT,
            loaded.vp,
            &offsets,
            |a| memory.qword(a),
            |a| phys.qword(a),
        )
        .unwrap();
        assert_eq!(registers, HashMap::from([("rax", 0x1111), ("rcx", 0x2222)]));

        memory.put(loaded.vp + LAYOUT.block_pointer, 0xffffe700_00c07080);
        assert!(
            saved_registers(
                &LAYOUT,
                loaded.vp,
                &offsets,
                |a| memory.qword(a),
                |a| phys.qword(a)
            )
            .is_err()
        );
    }
}
