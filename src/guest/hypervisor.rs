//! The Windows hypervisor's partitions and virtual processors, walked with
//! the offsets [`super::hv_layout`] reads off its code. Nothing is accepted
//! unless its links check out: a partition's child list must be a well-formed
//! ring whose children name it as parent, and each VP's current VTL must be
//! the entry of its VTL array that its level selects.

use std::collections::{HashMap, HashSet};

use super::EvmcsState;
use super::hv_layout::{PartitionLayout, Value};
use crate::error::{Error, Result};

/// Children followed on one list before it counts as corrupt.
const MAX_CHILDREN: usize = 4096;
/// VTLs a VP can have (TLFS: VTL0 to VTL2).
const MAX_VTLS: u8 = 3;

/// One partition, as the hypervisor keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HvPartition {
    pub address: u64,
    pub id: u64,
    /// The parent's partition ID; `None` for the root partition.
    pub parent: Option<u64>,
    /// `HV_PARTITION_PRIVILEGE_MASK`.
    pub privileges: u64,
    pub virtual_processors: Vec<HvVirtualProcessor>,
}

/// One virtual processor of a partition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HvVirtualProcessor {
    pub index: u32,
    pub address: u64,
    /// The VTL it runs, or last ran, in.
    pub vtl: u8,
    /// Each VTL enabled on the VP, lowest first.
    pub vtls: Vec<HvVtl>,
    /// The processors whose current VP this is: the one that runs it, or
    /// ran it last.
    pub processors: Vec<HvProcessor>,
}

/// A logical processor of the hypervisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HvProcessor {
    /// Its processor block (its GS base in the hypervisor).
    pub block: u64,
    /// Its processor number, where the layout names where the block keeps it.
    pub number: Option<u32>,
}

/// One VTL of a virtual processor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HvVtl {
    pub level: u8,
    /// The hypervisor's context object for this VTL.
    pub context: u64,
    /// The physical address of the VTL's VMCS (an eVMCS under KVM), when the
    /// layout names where the context keeps it.
    pub vmcs: Option<u64>,
    /// The guest state in that eVMCS, read after the walk.
    pub state: Option<EvmcsState>,
}

fn hv_error(detail: impl std::fmt::Display) -> Error {
    Error::Hypervisor(detail.to_string())
}

/// The bits of `HV_PARTITION_PRIVILEGE_MASK` that the Hyper-V TLFS names,
/// by bit number. The hypervisor also sets bits the TLFS lists as reserved.
const PRIVILEGES: &[(u8, &str)] = &[
    (0, "AccessVpRunTimeReg"),
    (1, "AccessPartitionReferenceCounter"),
    (2, "AccessSynicRegs"),
    (3, "AccessSyntheticTimerRegs"),
    (4, "AccessIntrCtrlRegs"),
    (5, "AccessHypercallMsrs"),
    (6, "AccessVpIndex"),
    (7, "AccessResetReg"),
    (8, "AccessStatsReg"),
    (9, "AccessPartitionReferenceTsc"),
    (10, "AccessGuestIdleReg"),
    (11, "AccessFrequencyRegs"),
    (13, "AccessReenlightenmentControls"),
    (32, "CreatePartitions"),
    (33, "AccessPartitionId"),
    (34, "AccessMemoryPool"),
    (36, "PostMessages"),
    (37, "SignalEvents"),
    (38, "CreatePort"),
    (39, "ConnectPort"),
    (40, "AccessStats"),
    (43, "Debugging"),
    (44, "CpuManagement"),
    (48, "AccessVSM"),
    (49, "AccessVpRegisters"),
    (52, "EnableExtendedHypercalls"),
    (53, "StartVirtualProcessor"),
];

/// The TLFS names of the privileges set in `mask`, and the set bits it does
/// not name.
pub fn privilege_names(mask: u64) -> (Vec<&'static str>, u64) {
    let mut unnamed = mask;
    let names = PRIVILEGES
        .iter()
        .filter(|&&(bit, _)| mask & (1 << bit) != 0)
        .map(|&(bit, name)| {
            unnamed &= !(1 << bit);
            name
        })
        .collect();
    (names, unnamed)
}

/// An upper-half canonical address, where the hypervisor keeps its objects.
fn kernel_pointer(value: u64) -> bool {
    value >> 47 == 0x1ffff && value & 7 == 0
}

/// Memory of the hypervisor's address space.
pub trait HvMemory {
    fn u64_at(&self, address: u64) -> Option<u64>;
    fn u8_at(&self, address: u64) -> Option<u8>;

    fn sized(&self, address: u64, size: u8) -> Option<u64> {
        match size {
            1 => self.u8_at(address).map(u64::from),
            8 => self.u64_at(address),
            2 | 4 => {
                let low = self.u64_at(address)?;
                Some(low & ((1u64 << (u32::from(size) * 8)) - 1))
            }
            _ => None,
        }
    }
}

/// `value` evaluated on the processor whose block (GS base) is `gs`.
fn eval(value: &Value, gs: u64, memory: &impl HvMemory) -> Option<u64> {
    match value {
        Value::Gs => Some(gs),
        Value::Const(constant) => Some(*constant),
        Value::Arg(_) => None,
        Value::Add(base, offset) => Some(eval(base, gs, memory)?.wrapping_add_signed(*offset)),
        Value::Load(base, offset, size) => {
            memory.sized(eval(base, gs, memory)?.wrapping_add_signed(*offset), *size)
        }
    }
}

fn field(address: u64, offset: i64) -> u64 {
    address.wrapping_add_signed(offset)
}

/// The children of `partition`, validated: every link's back pointer is
/// the link before it, and every child names `partition` as its parent.
fn children(layout: &PartitionLayout, memory: &impl HvMemory, partition: u64) -> Option<Vec<u64>> {
    let head = field(partition, layout.children);
    let mut previous = head;
    let mut link = memory.u64_at(head)?;
    let mut found = Vec::new();
    while link != head {
        if found.len() >= MAX_CHILDREN || !kernel_pointer(link) {
            return None;
        }
        let child = field(link, -layout.sibling);
        if memory.u64_at(link + 8)? != previous
            || memory.u64_at(field(child, layout.parent))? != partition
        {
            return None;
        }
        found.push(child);
        previous = link;
        link = memory.u64_at(link)?;
    }
    (memory.u64_at(head + 8)? == previous).then_some(found)
}

/// The VP at `address`, validated: its current VTL context is the entry of
/// its VTL array at that context's level, and every enabled VTL's context
/// carries its own level.
fn virtual_processor(
    layout: &PartitionLayout,
    memory: &impl HvMemory,
    index: u32,
    address: u64,
) -> Option<HvVirtualProcessor> {
    if !kernel_pointer(address) {
        return None;
    }
    let current = memory.u64_at(field(address, layout.vp_current_vtl))?;
    let vtl = memory.u8_at(field(current, layout.vtl_level))?;
    let slot = |level: u8| memory.u64_at(field(address, layout.vp_vtls + 8 * i64::from(level)));
    if vtl >= MAX_VTLS || slot(vtl)? != current {
        return None;
    }
    // The array also holds contexts allocated for VTLs the partition never
    // enabled; the VP's mask says which are.
    let enabled = memory.sized(field(address, layout.vp_enabled_vtls), 4)?;
    if enabled & (1 << vtl) == 0 || enabled >> MAX_VTLS != 0 {
        return None;
    }
    let mut vtls = Vec::new();
    for level in (0..MAX_VTLS).filter(|level| enabled & (1 << level) != 0) {
        let context = slot(level)?;
        if !kernel_pointer(context) || memory.u8_at(field(context, layout.vtl_level)) != Some(level)
        {
            return None;
        }
        vtls.push(HvVtl {
            level,
            context,
            vmcs: None,
            state: None,
        });
    }
    Some(HvVirtualProcessor {
        index,
        address,
        vtl,
        vtls,
        processors: Vec::new(),
    })
}

/// The partition at `address`, validated with its children and VPs.
fn partition(
    layout: &PartitionLayout,
    memory: &impl HvMemory,
    address: u64,
) -> Option<(HvPartition, Vec<u64>)> {
    if !kernel_pointer(address) {
        return None;
    }
    let children = children(layout, memory, address)?;
    let mut virtual_processors = Vec::new();
    for index in 0..layout.max_vps {
        let vp = memory.u64_at(field(address, layout.vps + 8 * i64::from(index)))?;
        if vp != 0 {
            virtual_processors.push(virtual_processor(layout, memory, index, vp)?);
        }
    }
    let parent = memory.u64_at(field(address, layout.parent))?;
    let parent = match parent {
        0 => None,
        parent => Some(memory.u64_at(field(parent, layout.id))?),
    };
    Some((
        HvPartition {
            address,
            id: memory.u64_at(field(address, layout.id))?,
            parent,
            privileges: memory.u64_at(field(address, layout.privileges))?,
            virtual_processors,
        },
        children,
    ))
}

/// The VMCS address a VTL context keeps under the candidate `(object,
/// address)`.
fn vmcs_under(memory: &impl HvMemory, context: u64, (object, address): (i64, i64)) -> Option<u64> {
    let object = memory.u64_at(field(context, object))?;
    kernel_pointer(object).then(|| memory.u64_at(field(object, address)))?
}

/// Fill in each VTL's VMCS with the candidate under which the most VTL
/// contexts land on `known` VMCS pages (the eVMCS scan). With no such
/// candidate, or two that disagree as often, no VMCS is named.
fn attach_vmcs(
    layout: &PartitionLayout,
    memory: &impl HvMemory,
    known: &HashSet<u64>,
    partitions: &mut [HvPartition],
) {
    let contexts = || {
        partitions
            .iter()
            .flat_map(|p| &p.virtual_processors)
            .flat_map(|vp| vp.vtls.iter().map(|vtl| vtl.context))
    };
    let mut best: Option<((i64, i64), usize)> = None;
    let mut tied = false;
    for &candidate in &layout.vmcs {
        let hits = contexts()
            .filter(|&context| {
                vmcs_under(memory, context, candidate).is_some_and(|page| known.contains(&page))
            })
            .count();
        match best {
            _ if hits == 0 => {}
            Some((_, most)) if hits < most => {}
            Some((_, most)) if hits == most => tied = true,
            _ => {
                best = Some((candidate, hits));
                tied = false;
            }
        }
    }
    let Some((candidate, _)) = best.filter(|_| !tied) else {
        return;
    };
    for vtl in partitions
        .iter_mut()
        .flat_map(|p| &mut p.virtual_processors)
        .flat_map(|vp| &mut vp.vtls)
    {
        vtl.vmcs = vmcs_under(memory, vtl.context, candidate)
            .filter(|page| page % 0x1000 == 0 && *page != 0);
    }
}

/// Record on each VP the processor blocks among `processors` whose current VP
/// it is: a block's current-VP value must land exactly on a VP the walk
/// validated.
fn attach_processors(
    layout: &PartitionLayout,
    memory: &impl HvMemory,
    processors: &[u64],
    partitions: &mut [HvPartition],
) {
    for &block in processors {
        let current: Vec<u64> = layout
            .current_vp
            .iter()
            .filter_map(|value| eval(value, block, memory))
            .collect();
        let number = layout
            .processor_index
            .and_then(|offset| memory.sized(field(block, offset), 4))
            .map(|number| number as u32);
        for vp in partitions
            .iter_mut()
            .flat_map(|partition| &mut partition.virtual_processors)
            .filter(|vp| current.contains(&vp.address))
        {
            vp.processors.push(HvProcessor { block, number });
        }
    }
}

/// Every partition, root first, reached from the processor blocks
/// `processors`: each block's current partition, up its parents to the
/// root, then down every child list. `known` are the VMCS pages the eVMCS
/// scan found, which pick where VTL contexts keep theirs.
pub fn partitions(
    layout: &PartitionLayout,
    memory: &impl HvMemory,
    processors: &[u64],
    known: &HashSet<u64>,
) -> Result<Vec<HvPartition>> {
    let mut roots = Vec::new();
    for &gs in processors {
        for value in &layout.current_partition {
            let Some(mut address) = eval(value, gs, memory) else {
                continue;
            };
            // Climb to the root, validating each step; a candidate that does
            // not validate is a path this processor is not on.
            let mut steps = 0;
            while partition(layout, memory, address).is_some() && steps < MAX_CHILDREN {
                match memory.u64_at(field(address, layout.parent)) {
                    Some(0) => {
                        if !roots.contains(&address) {
                            roots.push(address);
                        }
                        break;
                    }
                    Some(parent) => address = parent,
                    None => break,
                }
                steps += 1;
            }
        }
    }
    match roots.as_slice() {
        [] => {
            return Err(hv_error(
                "no processor block reaches a partition that validates",
            ));
        }
        [_] => {}
        many => return Err(hv_error(format!("{} root partitions reached", many.len()))),
    }
    let mut result = Vec::new();
    let mut seen = HashSet::new();
    let mut pending = vec![roots[0]];
    while let Some(address) = pending.pop() {
        if !seen.insert(address) {
            return Err(hv_error("a partition appears twice in the tree"));
        }
        let (partition, children) = partition(layout, memory, address)
            .ok_or_else(|| hv_error(format!("partition {address:#x} changed during the walk")))?;
        result.push(partition);
        pending.extend(children.into_iter().rev());
    }
    attach_vmcs(layout, memory, known, &mut result);
    attach_processors(layout, memory, processors, &mut result);
    Ok(result)
}

/// The VP and VTL an eVMCS page belongs to, with the EPT pointer its state
/// held when the partitions were walked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VpSlot {
    pub partition: u64,
    /// The partition is the root partition.
    pub root: bool,
    pub vp: u32,
    pub vtl: u8,
    pub ept_pointer: u64,
}

/// Every eVMCS page `partitions` name, by address, with its VP and VTL.
pub fn vp_slots(partitions: &[HvPartition]) -> HashMap<u64, VpSlot> {
    partitions
        .iter()
        .flat_map(|partition| {
            partition.virtual_processors.iter().flat_map(move |vp| {
                vp.vtls.iter().filter_map(move |vtl| {
                    let state = vtl.state?;
                    Some((
                        vtl.vmcs?,
                        VpSlot {
                            partition: partition.id,
                            root: partition.parent.is_none(),
                            vp: vp.index,
                            vtl: vtl.level,
                            ept_pointer: state.ept_pointer,
                        },
                    ))
                })
            })
        })
        .collect()
}

/// The VP and VTL whose eVMCS is at `address`, now under the EPT
/// `ept_pointer`, from `slots` (the last walk's), or from a walk that `walk`
/// makes, which replaces them, when they do not know the page or knew it
/// under another EPT: a page freed with its partition and reused by a new
/// one has a new partition's EPT.
pub fn slot_for(
    slots: &mut HashMap<u64, VpSlot>,
    address: u64,
    ept_pointer: u64,
    walk: impl FnOnce() -> Option<HashMap<u64, VpSlot>>,
) -> Option<VpSlot> {
    let known = |slots: &HashMap<u64, VpSlot>| {
        slots
            .get(&address)
            .filter(|slot| slot.ept_pointer == ept_pointer)
            .copied()
    };
    if let Some(slot) = known(slots) {
        return Some(slot);
    }
    *slots = walk()?;
    known(slots)
}

/// What a vCPU on processor `number` runs when that is a guest partition's
/// VP (a Hyper-V VM or WSL2 inside the target), such as `partition 0x3 VP 1`.
/// The vCPU then shows that guest's registers, so its root is none of NT's.
/// `None` when the processor's current VP is the root partition's.
pub fn guest_vp_label(partitions: &[HvPartition], number: u16) -> Option<String> {
    let (partition, vp) = processor_guest_vp(partitions, number)?;
    Some(format!("partition {partition:#x} VP {}", vp.index))
}

/// The guest partition's VP, with its partition's ID, that processor
/// `number`'s processor block names current.
fn processor_guest_vp(
    partitions: &[HvPartition],
    number: u16,
) -> Option<(u64, &HvVirtualProcessor)> {
    partitions
        .iter()
        .filter(|partition| partition.parent.is_some())
        .find_map(|partition| {
            let vp = partition.virtual_processors.iter().find(|vp| {
                vp.processors
                    .iter()
                    .any(|processor| processor.number == Some(u32::from(number)))
            })?;
            Some((partition.id, vp))
        })
}

/// The guest partition's VP, with its partition's ID, VTL, and state, that
/// processor `number` serves at a stop in the hypervisor, when `loaded` is
/// the eVMCS its assist page names current: the VP and VTL with that
/// eVMCS, or none when it is a root VP's. When it is not known, the VP
/// whose processor block names it current, with a state that is not
/// current, as its registers are then unknown.
pub fn served_vp(
    partitions: &[HvPartition],
    loaded: Option<EvmcsState>,
    number: u16,
) -> Option<(u64, &HvVirtualProcessor, u8, Option<EvmcsState>)> {
    let Some(loaded) = loaded else {
        let (partition, vp) = processor_guest_vp(partitions, number)?;
        let state = vp
            .vtls
            .iter()
            .find(|vtl| vtl.level == vp.vtl)
            .and_then(|vtl| vtl.state)
            .map(|state| EvmcsState {
                current: false,
                ..state
            });
        return Some((partition, vp, vp.vtl, state));
    };
    partitions
        .iter()
        .filter(|partition| partition.parent.is_some())
        .find_map(|partition| {
            partition.virtual_processors.iter().find_map(|vp| {
                let vtl = vp.vtls.iter().find(|vtl| {
                    vtl.state
                        .is_some_and(|state| state.address == loaded.address)
                })?;
                Some((partition.id, vp, vtl.level, Some(loaded)))
            })
        })
}

impl super::Guest {
    /// The partition layout of the hypervisor image at `base`, derived by
    /// `derive` the first time and remembered for the boot, as a failure is.
    pub fn partition_layout(
        &self,
        base: u64,
        derive: impl FnOnce() -> Result<PartitionLayout>,
    ) -> Result<PartitionLayout> {
        let mut layouts = self
            .partition_layouts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        layouts
            .entry(base)
            .or_insert_with(|| derive().map_err(|error| error.to_string()))
            .clone()
            .map_err(Error::Hypervisor)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    struct Ram(HashMap<u64, u64>);

    impl HvMemory for Ram {
        fn u64_at(&self, address: u64) -> Option<u64> {
            Some(self.0.get(&address).copied().unwrap_or(0))
        }

        fn u8_at(&self, address: u64) -> Option<u8> {
            Some(self.0.get(&address).copied().unwrap_or(0) as u8)
        }
    }

    const GS: u64 = 0xffff_e800_0028_b000;
    const ROOT: u64 = 0xffff_e800_0000_1000;
    const CHILD: u64 = 0xffff_e800_0010_0000;

    fn layout() -> PartitionLayout {
        PartitionLayout {
            current_partition: vec![Value::Load(Box::new(Value::Gs), 0x360, 8)],
            current_vp: vec![Value::Load(Box::new(Value::Gs), 0x358, 8)],
            processor_index: Some(8),
            id: 0x4550,
            parent: 0x4540,
            children: 0x4720,
            sibling: 0x4710,
            privileges: 0x1b0,
            vps: 0x1e0,
            max_vps: 4,
            vp_current_vtl: 0x3c0,
            vp_vtls: 0x148,
            vp_enabled_vtls: 0x1b0,
            vtl_level: 0x14,
            // The first candidate is what a stray vmptrld site gives; only
            // the second lands on VMCS pages.
            vmcs: vec![(0x180, 0x188), (0x13e8, 0x188)],
        }
    }

    /// The VMCS page of the VTL context at `context`.
    fn vmcs_page(context: u64) -> u64 {
        (context & 0xff_f000) << 4
    }

    /// A VP at `vp` whose VTL0 and VTL1 contexts follow it, both enabled,
    /// running `vtl`. Each context keeps its VMCS object in itself at
    /// +0x16e8, pointed to from +0x13e8, as 10.0.26100 does.
    fn add_vp(ram: &mut HashMap<u64, u64>, partition: u64, index: u64, vp: u64, vtl: u64) {
        let contexts = [vp + 0x1000, vp + 0x3000];
        ram.insert(partition + 0x1e0 + 8 * index, vp);
        ram.insert(vp + 0x1b0, 0b11);
        for (level, context) in contexts.iter().enumerate() {
            ram.insert(vp + 0x148 + 8 * level as u64, *context);
            ram.insert(context + 0x14, level as u64);
            ram.insert(context + 0x13e8, context + 0x16e8);
            ram.insert(context + 0x16e8 + 0x188, vmcs_page(*context));
        }
        ram.insert(vp + 0x3c0, contexts[vtl as usize]);
    }

    /// A root (ID 1) whose processor block names it current, with two VPs,
    /// and one child (ID 5) with one VP running VTL1.
    fn tree() -> HashMap<u64, u64> {
        let mut ram = HashMap::new();
        ram.insert(GS + 0x360, ROOT);
        ram.insert(ROOT + 0x4550, 1);
        ram.insert(ROOT + 0x1b0, 0x002b_b9ff_0000_3fff);
        ram.insert(CHILD + 0x4550, 5);
        ram.insert(CHILD + 0x4540, ROOT);
        let (head, link) = (ROOT + 0x4720, CHILD + 0x4710);
        ram.insert(head, link);
        ram.insert(head + 8, link);
        ram.insert(link, head);
        ram.insert(link + 8, head);
        let empty = CHILD + 0x4720;
        ram.insert(empty, empty);
        ram.insert(empty + 8, empty);
        add_vp(&mut ram, ROOT, 0, 0xffff_e800_0026_c050, 0);
        add_vp(&mut ram, ROOT, 1, 0xffff_e800_0038_9050, 0);
        add_vp(&mut ram, CHILD, 0, 0xffff_e800_0050_0050, 1);
        ram
    }

    #[test]
    fn walks_the_root_then_its_children_from_a_processor_block() {
        let found = partitions(&layout(), &Ram(tree()), &[GS], &HashSet::new()).unwrap();
        let ids: Vec<_> = found.iter().map(|p| (p.id, p.parent)).collect();
        assert_eq!(ids, [(1, None), (5, Some(1))]);
        assert_eq!(found[0].virtual_processors.len(), 2);
        let vp = &found[1].virtual_processors[0];
        assert_eq!((vp.index, vp.vtl, vp.vtls.len()), (0, 1, 2));
    }

    #[test]
    fn a_vtl_context_that_is_allocated_but_not_enabled_is_not_listed() {
        let mut ram = tree();
        let vp = 0xffff_e800_0038_9050;
        ram.insert(vp + 0x1b0, 0b1);
        let found = partitions(&layout(), &Ram(ram), &[GS], &HashSet::new()).unwrap();
        let listed = &found[0].virtual_processors[1];
        let levels: Vec<_> = listed
            .vtls
            .iter()
            .map(|vtl| (vtl.level, vtl.context))
            .collect();
        assert_eq!(levels, [(0, vp + 0x1000)]);
    }

    #[test]
    fn a_vp_running_a_vtl_it_has_not_enabled_is_refused() {
        let mut ram = tree();
        ram.insert(0xffff_e800_0050_0050 + 0x1b0, 0b1);
        assert!(partitions(&layout(), &Ram(ram), &[GS], &HashSet::new()).is_err());
    }

    #[test]
    fn each_vtl_gets_the_vmcs_of_the_candidate_that_lands_on_known_pages() {
        let ram = tree();
        let known: HashSet<u64> = [0xffff_e800_0026_d050, 0xffff_e800_0038_a050]
            .into_iter()
            .map(vmcs_page)
            .collect();
        let found = partitions(&layout(), &Ram(ram), &[GS], &known).unwrap();
        for vtl in found
            .iter()
            .flat_map(|p| &p.virtual_processors)
            .flat_map(|vp| &vp.vtls)
        {
            assert_eq!(vtl.vmcs, Some(vmcs_page(vtl.context)));
        }
    }

    #[test]
    fn without_known_vmcs_pages_no_vmcs_is_named() {
        let found = partitions(&layout(), &Ram(tree()), &[GS], &HashSet::new()).unwrap();
        assert!(
            found
                .iter()
                .flat_map(|p| &p.virtual_processors)
                .flat_map(|vp| &vp.vtls)
                .all(|vtl| vtl.vmcs.is_none())
        );
    }

    #[test]
    fn a_vp_lists_the_processor_whose_current_vp_it_is() {
        let mut ram = tree();
        ram.insert(GS + 0x358, 0xffff_e800_0038_9050);
        ram.insert(GS + 8, 3);
        let found = partitions(&layout(), &Ram(ram), &[GS], &HashSet::new()).unwrap();
        let processors: Vec<_> = found
            .iter()
            .flat_map(|p| &p.virtual_processors)
            .map(|vp| (vp.index, vp.processors.clone()))
            .collect();
        let expected = HvProcessor {
            block: GS,
            number: Some(3),
        };
        assert_eq!(processors, [(0, vec![]), (1, vec![expected]), (0, vec![])]);
    }

    #[test]
    fn a_processor_on_a_child_still_reaches_the_root() {
        let mut ram = tree();
        ram.insert(GS + 0x360, CHILD);
        let found = partitions(&layout(), &Ram(ram), &[GS], &HashSet::new()).unwrap();
        assert_eq!(found[0].id, 1);
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn a_child_list_with_a_broken_back_link_is_refused() {
        let mut ram = tree();
        ram.insert(CHILD + 0x4710 + 8, 0xffff_e800_dead_0000);
        assert!(partitions(&layout(), &Ram(ram), &[GS], &HashSet::new()).is_err());
    }

    #[test]
    fn a_child_that_names_another_parent_is_refused() {
        let mut ram = tree();
        ram.insert(CHILD + 0x4540, 0xffff_e800_0077_0000);
        assert!(partitions(&layout(), &Ram(ram), &[GS], &HashSet::new()).is_err());
    }

    #[test]
    fn a_vp_whose_current_vtl_is_not_in_its_array_is_refused() {
        let mut ram = tree();
        ram.insert(0xffff_e800_0038_9050 + 0x3c0, 0xffff_e800_0099_0000);
        assert!(partitions(&layout(), &Ram(ram), &[GS], &HashSet::new()).is_err());
    }

    #[test]
    fn a_processor_running_a_guest_vp_is_labeled_with_it_and_the_roots_are_not() {
        let vp = |index, numbers: &[u32]| HvVirtualProcessor {
            index,
            address: 0,
            vtl: 0,
            vtls: Vec::new(),
            processors: numbers
                .iter()
                .map(|&number| HvProcessor {
                    block: 0,
                    number: Some(number),
                })
                .collect(),
        };
        let partition = |id, parent, virtual_processors| HvPartition {
            address: 0,
            id,
            parent,
            privileges: 0,
            virtual_processors,
        };
        let partitions = [
            partition(1, None, vec![vp(0, &[0]), vp(1, &[1]), vp(2, &[])]),
            partition(3, Some(1), vec![vp(0, &[]), vp(1, &[2, 3])]),
        ];
        let labels: Vec<_> = (0..5)
            .map(|number| guest_vp_label(&partitions, number))
            .collect();
        assert_eq!(
            labels,
            [
                None,
                None,
                Some("partition 0x3 VP 1".to_string()),
                Some("partition 0x3 VP 1".to_string()),
                None,
            ]
        );
    }

    /// At a stop in the hypervisor, the processor serves the VP whose eVMCS
    /// its assist page names loaded, whatever VP its processor block last
    /// named; a root VP's eVMCS means no guest's. Only when nothing is
    /// known loaded does the block name it, its registers then unknown.
    #[test]
    fn a_processor_serves_the_vp_whose_evmcs_it_has_loaded() {
        let vtl = |level, address| HvVtl {
            level,
            context: 0,
            vmcs: Some(address),
            state: Some(EvmcsState::at(address, false)),
        };
        let vp = |index, vtls, processor: Option<u32>| HvVirtualProcessor {
            index,
            address: 0,
            vtl: 0,
            vtls,
            processors: processor
                .map(|number| HvProcessor {
                    block: 0,
                    number: Some(number),
                })
                .into_iter()
                .collect(),
        };
        let partitions = [
            HvPartition {
                address: 0,
                id: 1,
                parent: None,
                privileges: 0,
                virtual_processors: vec![vp(3, vec![vtl(0, 0x1000), vtl(1, 0x2000)], Some(3))],
            },
            HvPartition {
                address: 0,
                id: 8,
                parent: Some(1),
                privileges: 0,
                virtual_processors: vec![
                    vp(0, vec![vtl(0, 0x5000)], Some(3)),
                    vp(1, vec![vtl(0, 0x6000)], None),
                ],
            },
        ];
        let served = |loaded: Option<u64>| {
            served_vp(
                &partitions,
                loaded.map(|address| EvmcsState::at(address, true)),
                3,
            )
            .map(|(partition, vp, vtl, state)| (partition, vp.index, vtl, state.map(|s| s.current)))
        };
        assert_eq!(served(Some(0x6000)), Some((8, 1, 0, Some(true))));
        assert_eq!(served(Some(0x2000)), None, "the root's VTL1");
        assert_eq!(served(None), Some((8, 0, 0, Some(false))));
    }

    /// A hit's caller comes from the last walk's slots without walking
    /// again; a page the walk did not know, or knew under another EPT (freed
    /// with a deleted partition and reused by a new one), walks again, and
    /// the new walk's slots replace the old.
    #[test]
    fn an_evmcs_names_its_vp_until_its_ept_changes() {
        let slot = |partition, ept_pointer| VpSlot {
            partition,
            root: false,
            vp: 1,
            vtl: 0,
            ept_pointer,
        };
        let mut slots = HashMap::from([(0x5000, slot(4, 0xa01e))]);
        let walked = std::cell::Cell::new(0);
        let walk = |result: HashMap<u64, VpSlot>| {
            walked.set(walked.get() + 1);
            Some(result)
        };

        assert_eq!(
            slot_for(&mut slots, 0x5000, 0xa01e, || walk(HashMap::new())),
            Some(slot(4, 0xa01e))
        );
        assert_eq!(walked.get(), 0, "known: no walk");

        let reused = HashMap::from([(0x5000, slot(5, 0xb01e))]);
        assert_eq!(
            slot_for(&mut slots, 0x5000, 0xb01e, || walk(reused)),
            Some(slot(5, 0xb01e))
        );
        assert_eq!(walked.get(), 1, "another EPT: walked again");

        assert_eq!(
            slot_for(&mut slots, 0x9000, 0xb01e, || walk(HashMap::new())),
            None
        );
        assert_eq!(walked.get(), 2, "unknown page: walked again");
        assert!(slots.is_empty(), "the new walk's slots replace the old");
    }
}
