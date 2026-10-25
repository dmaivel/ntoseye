//! Field offsets of the kernel's memory-compression store, read from the
//! kernel's own code. The PDB names the store manager's functions but has no
//! types for its structures, and the offsets move between Windows releases
//! (and once within 24H2's servicing), so each one comes from a function
//! that uses it. ARM64 kernels read the same anchors from A64 code
//! ([`arm64`]).

pub mod arm64;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};

use iced_x86::{
    ConditionCode, Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register,
};
use pelite::pe64::{Pe, PeView};

use super::hv_layout::ImageView;
use crate::base::error::{Error, Result};
use crate::base::memory::{ChunkFields, Compression, MemoryOps, PAGE_SIZE, StoreLayout};
use crate::base::types::VirtAddr;

/// The kernel image and the addresses of its functions, by undecorated name.
pub struct KernelCode<'a> {
    pub image: ImageView<'a>,
    pub functions: &'a HashMap<String, u64>,
}

/// The store layout `code` uses, when every anchor is found and agrees.
pub fn derive(code: &KernelCode<'_>) -> Result<StoreLayout> {
    let owner_process = owner_process(code)?;
    let region_array = region_array(code)?;
    let (back_pointer, virtual_flag) = back_pointer_and_flag(code)?;
    let (region_shift, region_offset_mask) = region_key_fields(code)?;
    let (chunk_array, chunk_fields) = chunk_fields(code)?;
    Ok(StoreLayout {
        owner_process,
        region_array,
        virtual_flag,
        back_pointer,
        region_shift,
        region_offset_mask,
        chunk_array,
        chunk_fields,
        key_tree: key_tree(code)?,
        pages_tree: pages_tree(code)?,
        redirect_next: redirect_next(code)?,
        compression: compression(code)?,
    })
}

fn layout_error(detail: impl std::fmt::Display) -> Error {
    Error::DebugInfo(format!(
        "memory-compression store layout not recognized: {detail}"
    ))
}

impl KernelCode<'_> {
    /// The address of the function named `name`.
    fn address(&self, name: &str) -> Result<u64> {
        self.functions
            .get(name)
            .copied()
            .ok_or_else(|| layout_error(format_args!("no {name}")))
    }

    /// The instructions reachable from `address` through branches, calls
    /// not followed, in address order: a function with its split-off chunks.
    fn instructions(&self, address: u64) -> Vec<Instruction> {
        const MAX: usize = 8192;
        let mut seen = BTreeMap::new();
        let mut pending = vec![address];
        while let Some(start) = pending.pop() {
            let mut ip = start;
            while !seen.contains_key(&ip) && seen.len() < MAX {
                let Some(code) = self.image.code_at(ip) else {
                    break;
                };
                let instruction = Decoder::with_ip(64, code, ip, DecoderOptions::NONE).decode();
                if instruction.is_invalid() {
                    break;
                }
                seen.insert(ip, instruction);
                match instruction.flow_control() {
                    FlowControl::UnconditionalBranch => {
                        pending.extend(near_target(&instruction));
                        break;
                    }
                    FlowControl::ConditionalBranch => pending.extend(near_target(&instruction)),
                    FlowControl::Next | FlowControl::Call | FlowControl::IndirectCall => {}
                    _ => break,
                }
                ip = instruction.next_ip();
            }
        }
        seen.into_values().collect()
    }

    /// The functions whose name `matches`.
    fn functions_where(&self, matches: impl Fn(&str) -> bool) -> Vec<u64> {
        self.functions
            .iter()
            .filter(|(name, _)| matches(name))
            .map(|(_, address)| *address)
            .collect()
    }

    /// The functions whose name starts with `prefix`.
    fn functions_named(&self, prefix: &str) -> Vec<u64> {
        self.functions_where(|name| name.starts_with(prefix))
    }

    /// The `BTreeSearchKey` of the trees whose name contains `entry`.
    fn tree_searches(&self, entry: &str) -> Vec<u64> {
        self.functions_where(|name| name.contains(entry) && name.ends_with("::BTreeSearchKey"))
    }

    /// For each of `callers`, the first argument (`rcx`) at each of its calls
    /// to one of `callees`, as `argument` reads it from the instruction that
    /// last set `rcx`; a call clobbers it.
    fn first_arguments(
        &self,
        callers: &[u64],
        callees: &[u64],
        argument: impl Fn(&Instruction) -> Option<u32>,
    ) -> Vec<Vec<u32>> {
        callers
            .iter()
            .map(|&caller| {
                let mut rcx = None;
                let mut found = Vec::new();
                for instruction in self.instructions(caller) {
                    if instruction.mnemonic() == Mnemonic::Call {
                        if near_target(&instruction).is_some_and(|t| callees.contains(&t)) {
                            found.extend(rcx);
                        }
                        rcx = None;
                    } else if writes(&instruction, Register::RCX) {
                        rcx = argument(&instruction);
                    }
                }
                found
            })
            .collect()
    }
}

fn near_target(instruction: &Instruction) -> Option<u64> {
    (instruction.op0_kind() == OpKind::NearBranch64).then(|| instruction.near_branch64())
}

/// Whether `instruction`'s first operand is `register`, at any width.
fn writes(instruction: &Instruction, register: Register) -> bool {
    instruction.op0_kind() == OpKind::Register
        && instruction.op0_register().full_register() == register
}

/// `[reg+D]`'s `D`, for a memory operand with a base and no index.
fn based_offset(instruction: &Instruction) -> Option<u32> {
    (instruction.memory_index() == Register::None
        && !matches!(instruction.memory_base(), Register::None | Register::RIP))
    .then(|| u32::try_from(instruction.memory_displacement64()).ok())
    .flatten()
}

/// The `[reg+D]` field a `mov reg,[x+D]` loads.
fn loaded_field(instruction: &Instruction) -> Option<u32> {
    (instruction.mnemonic() == Mnemonic::Mov && instruction.op1_kind() == OpKind::Memory)
        .then(|| based_offset(instruction))
        .flatten()
}

/// The registers a call may change: the Windows x64 volatile ones.
const VOLATILE: [Register; 7] = [
    Register::RAX,
    Register::RCX,
    Register::RDX,
    Register::R8,
    Register::R9,
    Register::R10,
    Register::R11,
];

/// The value `values` holds most often, when it holds it at least
/// `at_least` times and no other value as often.
fn winner(values: impl IntoIterator<Item = u32>, at_least: usize, what: &str) -> Result<u32> {
    let mut votes: HashMap<u32, usize> = HashMap::new();
    for value in values {
        *votes.entry(value).or_default() += 1;
    }
    let mut ranked: Vec<(u32, usize)> = votes.into_iter().collect();
    ranked.sort_by_key(|&(value, count)| (std::cmp::Reverse(count), value));
    match ranked.as_slice() {
        [(value, count), rest @ ..]
            if *count >= at_least && rest.first().is_none_or(|r| r.1 < *count) =>
        {
            Ok(*value)
        }
        _ => Err(layout_error(format_args!(
            "{what}: no single value in {ranked:x?}"
        ))),
    }
}

/// The one value in `values`.
fn only(values: impl IntoIterator<Item = u32>, what: &str) -> Result<u32> {
    match values.into_iter().collect::<Vec<_>>().as_slice() {
        [value] => Ok(*value),
        other => Err(layout_error(format_args!("{what}: {other:x?}"))),
    }
}

/// The store's owner-process field: the store methods switch to the
/// process that holds the regions with `KeStackAttachProcess` (or
/// `KiStackAttachProcess`), its first argument loaded from the store. Each
/// method's first attach votes, and two must agree.
fn owner_process(code: &KernelCode<'_>) -> Result<u32> {
    let attach: Vec<u64> = ["KeStackAttachProcess", "KiStackAttachProcess"]
        .iter()
        .filter_map(|name| code.functions.get(*name).copied())
        .collect();
    let methods = code.functions_named("SMKM_STORE<SM_TRAITS>::");
    let firsts = code.first_arguments(&methods, &attach, loaded_field);
    winner(
        firsts.iter().filter_map(|loads| loads.first().copied()),
        2,
        "owner process",
    )
}

/// The offsets `A` (0x100 or more) of `mov r,[x+A]` loads whose register is
/// then indexed by 8 (`[r+i*8]`): fields that point to arrays of pointers.
fn pointer_arrays(instructions: &[Instruction]) -> BTreeSet<u32> {
    let mut loaded: HashMap<Register, u32> = HashMap::new();
    let mut found = BTreeSet::new();
    for instruction in instructions {
        if matches!(instruction.mnemonic(), Mnemonic::Mov | Mnemonic::Lea)
            && instruction.op1_kind() == OpKind::Memory
            && instruction.memory_index() != Register::None
            && instruction.memory_index_scale() == 8
            && let Some(offset) = loaded.get(&instruction.memory_base().full_register())
        {
            found.insert(*offset);
        }
        if instruction.mnemonic() == Mnemonic::Call {
            loaded.retain(|register, _| !VOLATILE.contains(register));
        } else if instruction.op0_kind() == OpKind::Register {
            let register = instruction.op0_register().full_register();
            match loaded_field(instruction).filter(|offset| *offset >= 0x100) {
                Some(offset) => loaded.insert(register, offset),
                None => loaded.remove(&register),
            };
        }
    }
    found
}

/// The store's region array: the one pointer array `SmStMapVirtualRegion`
/// indexes.
fn region_array(code: &KernelCode<'_>) -> Result<u32> {
    let map = code.address("SMKM_STORE<SM_TRAITS>::SmStMapVirtualRegion")?;
    only(pointer_arrays(&code.instructions(map)), "region array")
}

/// From `StDmpSinglePageRetrieve`, the `ST_STORE`'s back pointer to the
/// store (the `rcx` it passes to the store's methods) and the flag it tests
/// on the store through it: set when regions are virtual.
fn back_pointer_and_flag(code: &KernelCode<'_>) -> Result<(u32, (u32, u8))> {
    let retrieve = code.address("ST_STORE<SM_TRAITS>::StDmpSinglePageRetrieve")?;
    let store_methods = code.functions_named("SMKM_STORE<SM_TRAITS>::");
    // Registers loaded from `[x+B]`, by register: the `B`.
    let mut loaded: HashMap<Register, u32> = HashMap::new();
    let mut back_pointers = Vec::new();
    let mut tests: Vec<(u32, u32, u8)> = Vec::new();
    for instruction in code.instructions(retrieve) {
        match instruction.mnemonic() {
            Mnemonic::Call => {
                // A store method's first argument is the store.
                if near_target(&instruction).is_some_and(|t| store_methods.contains(&t)) {
                    back_pointers.extend(loaded.get(&Register::RCX));
                }
                loaded.retain(|register, _| !VOLATILE.contains(register));
                continue;
            }
            Mnemonic::Test
                if instruction.op0_kind() == OpKind::Memory
                    && instruction.op1_kind() == OpKind::Immediate8
                    && instruction.memory_size().size() == 1
                    && instruction.immediate(1).count_ones() == 1 =>
            {
                if let (Some(back), Some(flag)) = (
                    loaded.get(&instruction.memory_base().full_register()),
                    based_offset(&instruction),
                ) {
                    tests.push((*back, flag, instruction.immediate(1).trailing_zeros() as u8));
                }
                continue;
            }
            _ => {}
        }
        if instruction.op0_kind() == OpKind::Register {
            let register = instruction.op0_register().full_register();
            let value = match (instruction.mnemonic(), instruction.op1_kind()) {
                (Mnemonic::Mov, OpKind::Memory) => based_offset(&instruction),
                (Mnemonic::Mov, OpKind::Register) => loaded
                    .get(&instruction.op1_register().full_register())
                    .copied(),
                _ => None,
            };
            match value {
                Some(offset) => loaded.insert(register, offset),
                None => loaded.remove(&register),
            };
        }
    }
    let back = winner(back_pointers, 1, "back pointer")?;
    let flags: BTreeSet<(u32, u8)> = tests
        .into_iter()
        .filter(|(through, _, _)| *through == back)
        .map(|(_, flag, bit)| (flag, bit))
        .collect();
    match flags.into_iter().collect::<Vec<_>>().as_slice() {
        [flag] => Ok((back, *flag)),
        other => Err(layout_error(format_args!(
            "virtual-region flag: {other:x?}"
        ))),
    }
}

/// The `ST_STORE` fields that split a region key, from
/// `StDmpSinglePageRetrieve`: the shift count (`mov ecx,[st+X]` then
/// `shr r,cl`) and the offset mask (a field loaded or ANDed into the value
/// that is then shifted left by 4, to bytes).
fn region_key_fields(code: &KernelCode<'_>) -> Result<(u32, u32)> {
    let retrieve = code.address("ST_STORE<SM_TRAITS>::StDmpSinglePageRetrieve")?;
    // The `[x+D]` fields each register's value came from.
    let mut origins: HashMap<Register, Vec<u32>> = HashMap::new();
    let mut shifts = Vec::new();
    let mut masks = Vec::new();
    let instructions = code.instructions(retrieve);
    for (index, instruction) in instructions.iter().enumerate() {
        let destination = (instruction.op0_kind() == OpKind::Register)
            .then(|| instruction.op0_register().full_register());
        let field = (instruction.op_count() > 1 && instruction.op1_kind() == OpKind::Memory)
            .then(|| based_offset(instruction))
            .flatten();
        match instruction.mnemonic() {
            Mnemonic::Shr
                if instruction.op1_kind() == OpKind::Register
                    && instruction.op1_register() == Register::CL =>
            {
                if let Some([shift]) = origins.get(&Register::RCX).map(Vec::as_slice) {
                    // A page-record lookup inlined here shifts too, then
                    // takes the result's highest set bit; the region shift
                    // does not.
                    let shifted = instruction.op0_register().full_register();
                    let chunk = instructions[index + 1..].iter().take(4).any(|next| {
                        next.mnemonic() == Mnemonic::Bsr
                            && next.op1_kind() == OpKind::Register
                            && next.op1_register().full_register() == shifted
                    });
                    if !chunk {
                        shifts.push(*shift);
                    }
                }
                continue;
            }
            Mnemonic::Shl
                if instruction.op1_kind() == OpKind::Immediate8
                    && instruction.immediate8() == 4 =>
            {
                if let Some(fields) = destination.and_then(|r| origins.get(&r)) {
                    // The key itself comes from a page record's first
                    // fields; the store's own fields are further in.
                    masks.extend(fields.iter().filter(|field| **field >= 0x100));
                }
                continue;
            }
            Mnemonic::And if field.is_some() => {
                if let Some(register) = destination {
                    origins.entry(register).or_default().extend(field);
                }
                continue;
            }
            _ => {}
        }
        let Some(register) = destination else {
            continue;
        };
        let origin = |register: Register| origins.get(&register).cloned().unwrap_or_default();
        let value = match (instruction.mnemonic(), instruction.op1_kind()) {
            (Mnemonic::Mov, OpKind::Memory) => field.map(|f| vec![f]),
            (Mnemonic::Mov, OpKind::Register) => origins
                .get(&instruction.op1_register().full_register())
                .cloned(),
            // An AND with a register keeps both origins.
            (Mnemonic::And, OpKind::Register) => {
                let mut both = origin(register);
                both.extend(origin(instruction.op1_register().full_register()));
                Some(both)
            }
            _ => None,
        };
        match value {
            Some(fields) => origins.insert(register, fields),
            None => origins.remove(&register),
        };
    }
    Ok((
        winner(shifts, 1, "region shift")?,
        winner(masks, 1, "region offset mask")?,
    ))
}

/// The page-record fields of `ST_PAGE_RECORD_GET`: the array of chunk
/// pointers (`[st+i*8+A]`) and the four 32-bit fields it reads from the
/// store, which are, in offset order, the shift, the per-chunk mask, the
/// record size and the header.
fn chunk_fields(code: &KernelCode<'_>) -> Result<(u32, ChunkFields)> {
    let get = code.address("ST_STORE<SM_TRAITS>::ST_PAGE_RECORD_GET")?;
    let mut arrays = BTreeSet::new();
    let mut dwords = BTreeSet::new();
    for instruction in code.instructions(get) {
        if instruction.op_count() < 2
            || instruction.op1_kind() != OpKind::Memory
            || instruction.memory_base() == Register::RSP
        {
            continue;
        }
        if instruction.memory_index() != Register::None && instruction.memory_index_scale() == 8 {
            if let Ok(offset) = u32::try_from(instruction.memory_displacement64())
                && offset != 0
            {
                arrays.insert(offset);
            }
        } else if instruction.memory_size().size() == 4
            && let Some(field) = based_offset(&instruction).filter(|f| *f >= 0x40)
        {
            dwords.insert(field);
        }
    }
    let array = only(arrays, "chunk array")?;
    match dwords.into_iter().collect::<Vec<_>>().as_slice() {
        &[shift, mask, record_size, header] => Ok((
            array,
            ChunkFields {
                shift,
                mask,
                record_size,
                header,
            },
        )),
        other => Err(layout_error(format_args!("chunk fields: {other:x?}"))),
    }
}

/// The store manager's key-to-store tree: the `rcx` that `SMKM_STORE_MGR`
/// methods pass to the frontend tree's search, `lea rcx,[mgr+K]` or
/// `add rcx,K`. Two calls must agree.
fn key_tree(code: &KernelCode<'_>) -> Result<u32> {
    let methods = code.functions_named("SMKM_STORE_MGR<SM_TRAITS>::");
    let searches = code.tree_searches("SMKM_FRONTEND_ENTRY");
    let calls = code.first_arguments(&methods, &searches, |rcx| {
        match (rcx.mnemonic(), rcx.op1_kind()) {
            (Mnemonic::Lea, _) => based_offset(rcx),
            (Mnemonic::Add, OpKind::Immediate32to64 | OpKind::Immediate8to64) => {
                u32::try_from(rcx.immediate(1)).ok()
            }
            _ => None,
        }
    });
    winner(calls.into_iter().flatten(), 2, "key-to-store tree")
}

/// From `SmStoreDecompressBuffer` (24H2 and later), the count it tests
/// first; otherwise the field loaded into `ecx` before a call to
/// `RtlDecompressBufferEx` by `StDmSinglePageCopy`.
fn compression(code: &KernelCode<'_>) -> Result<Compression> {
    if let Some(&decompress) = code.functions.get("SmStoreDecompressBuffer") {
        let instructions = code.instructions(decompress);
        let tested = |index: usize, register: Register| {
            instructions[index + 1..]
                .iter()
                .take(4)
                .any(|test| test.mnemonic() == Mnemonic::Test && writes(test, register))
        };
        return instructions
            .iter()
            .enumerate()
            .find_map(|(index, load)| {
                let counted = matches!(load.mnemonic(), Mnemonic::Mov | Mnemonic::Movsxd)
                    && load.op0_kind() == OpKind::Register
                    && load.op1_kind() == OpKind::Memory
                    && load.memory_base() == Register::RCX
                    && load.memory_size().size() == 4;
                (counted && tested(index, load.op0_register().full_register()))
                    .then(|| based_offset(load))
                    .flatten()
            })
            .map(Compression::Lz4UnlessCount)
            .ok_or_else(|| layout_error("no algorithm count in SmStoreDecompressBuffer"));
    }
    let decompress = code.address("RtlDecompressBufferEx")?;
    let copy = code.address("ST_STORE<SM_TRAITS>::StDmSinglePageCopy")?;
    let calls = code.first_arguments(&[copy], &[decompress], |ecx| {
        (ecx.mnemonic() == Mnemonic::Movzx && ecx.op1_kind() == OpKind::Memory)
            .then(|| based_offset(ecx))
            .flatten()
    });
    winner(calls.into_iter().flatten(), 1, "decompression format").map(Compression::FormatField)
}

/// The `ST_STORE`'s pages tree (page key to region key): the `rcx` that
/// `ST_STORE` methods pass to that tree's search, `lea rcx,[st+P]`, or the
/// store itself (`mov rcx,reg`) when the tree is at 0.
fn pages_tree(code: &KernelCode<'_>) -> Result<u32> {
    let methods = code.functions_named("ST_STORE<SM_TRAITS>::");
    let searches = code.tree_searches("_ST_PAGE_ENTRY");
    let calls = code.first_arguments(&methods, &searches, |rcx| {
        match (rcx.mnemonic(), rcx.op1_kind()) {
            (Mnemonic::Lea, _) => based_offset(rcx),
            (Mnemonic::Mov, OpKind::Register) => Some(0),
            _ => None,
        }
    });
    winner(calls.into_iter().flatten(), 1, "pages tree")
}

/// Where a redirecting page record (key `0xffffffff`) keeps the key it
/// redirects to: the dword the `ST_STORE` methods load from the record on
/// the path where its key compared equal to -1, an immediate or a register
/// the method set to -1. +4 to 26100, +8 from 28000.
fn redirect_next(code: &KernelCode<'_>) -> Result<u32> {
    let dword = |instruction: &Instruction| instruction.memory_size().size() == 4;
    let minus_one = |instruction: &Instruction| {
        matches!(
            instruction.op1_kind(),
            OpKind::Immediate8to32 | OpKind::Immediate32
        ) && instruction.immediate(1) as u32 == u32::MAX
    };
    let mut offsets = Vec::new();
    for function in code.functions_named("ST_STORE<SM_TRAITS>::") {
        let instructions = code.instructions(function);
        let index: HashMap<u64, usize> = instructions
            .iter()
            .enumerate()
            .map(|(i, instruction)| (instruction.ip(), i))
            .collect();
        let minus_one_registers: Vec<Register> = instructions
            .iter()
            .filter(|i| {
                matches!(i.mnemonic(), Mnemonic::Or | Mnemonic::Mov)
                    && i.op0_kind() == OpKind::Register
                    && minus_one(i)
            })
            .map(Instruction::op0_register)
            .collect();
        for (i, compare) in instructions.iter().enumerate() {
            let against_minus_one = minus_one(compare)
                || (compare.op1_kind() == OpKind::Register
                    && minus_one_registers.contains(&compare.op1_register()));
            if compare.mnemonic() != Mnemonic::Cmp
                || compare.op0_kind() != OpKind::Memory
                || !dword(compare)
                || based_offset(compare) != Some(0)
                || !against_minus_one
            {
                continue;
            }
            // The redirect path: a `je`'s target, or what follows a `jne`.
            let Some(branch) = instructions.get(i + 1) else {
                continue;
            };
            let start = match branch.condition_code() {
                ConditionCode::e => near_target(branch).and_then(|t| index.get(&t).copied()),
                ConditionCode::ne => Some(i + 2),
                _ => None,
            };
            let record = compare.memory_base();
            let next = start
                .and_then(|start| instructions.get(start..))
                .into_iter()
                .flatten()
                .take(3)
                .find(|load| {
                    load.mnemonic() == Mnemonic::Mov
                        && load.op1_kind() == OpKind::Memory
                        && load.memory_base() == record
                        && dword(load)
                })
                .and_then(based_offset);
            offsets.extend(next);
        }
    }
    winner(offsets, 1, "redirect next key")
}

/// An image's executable sections laid out by RVA, and their `(start,
/// end)` RVAs.
pub struct MappedCode {
    pub bytes: Vec<u8>,
    pub code: Vec<(u32, u32)>,
}

/// The executable sections of the image at `base`, whose header page is
/// `headers`, as `memory` maps them: laid out by RVA, with the other bytes
/// and unreadable pages zero. Over KD that is half a minute of reads, which
/// stop when `interrupt` (Ctrl+C) is raised.
pub fn mapped_code(
    memory: &impl MemoryOps<VirtAddr>,
    base: u64,
    headers: &[u8],
    interrupt: &AtomicBool,
) -> Result<MappedCode> {
    let view = PeView::from_bytes(headers).map_err(|_| layout_error("no kernel headers"))?;
    let mut bytes = vec![0u8; view.optional_header().SizeOfImage as usize];
    let code = crate::nt::pe::executable_ranges(&view);
    for &(start, end) in &code {
        for page in (start as usize..end as usize).step_by(PAGE_SIZE) {
            if interrupt.load(Ordering::Relaxed) {
                return Err(layout_error("interrupted"));
            }
            let chunk = &mut bytes[page..(page + PAGE_SIZE).min(end as usize)];
            if memory
                .read_bytes(VirtAddr(base + page as u64), chunk)
                .is_err()
            {
                chunk.fill(0);
            }
        }
    }
    Ok(MappedCode { bytes, code })
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::code_asm::*;

    const BASE: u64 = 0x1_4000_0000;

    /// A region key in r9d split as the retrieval does: its index by the
    /// shift at 0x32c, its byte offset by the mask at 0x328.
    fn region_key(a: &mut CodeAssembler) {
        a.mov(ecx, dword_ptr(rbp + 0x32c)).unwrap();
        a.mov(r12d, dword_ptr(rbp + 0x328)).unwrap();
        a.and(r12d, r9d).unwrap();
        a.shr(r9d, cl).unwrap();
        a.shl(r12d, 4).unwrap();
    }

    /// Functions assembled one per 0x100 bytes, by name.
    struct Builder {
        bytes: Vec<u8>,
        next: u32,
        functions: HashMap<String, u64>,
    }

    impl Builder {
        fn new() -> Self {
            let mut builder = Self {
                bytes: vec![0xcc; 0x4000],
                next: 0x1000,
                functions: HashMap::new(),
            };
            builder.function("KeStackAttachProcess", |a| a.ret().unwrap());
            // The page lookup searches the pages tree at the store's start.
            let pages = builder.function(
                "B_TREE<_SM_PAGE_KEY, ST_STORE<SM_TRAITS>::_ST_PAGE_ENTRY>::BTreeSearchKey",
                |a| a.ret().unwrap(),
            );
            builder.function("ST_STORE<SM_TRAITS>::StDmpSinglePageLookup", |a| {
                a.mov(rcx, rsi).unwrap();
                a.call(pages).unwrap();
                a.ret().unwrap();
            });
            // 24H2's decompression: LZ4 unless the count at 0x12c0 is set.
            builder.function("SmStoreDecompressBuffer", |a| {
                a.mov(rax, qword_ptr(rcx + 0x1d90)).unwrap();
                a.mov(eax, dword_ptr(rcx + 0x12c0)).unwrap();
                a.mov(dword_ptr(rsp + 0x10), eax).unwrap();
                a.test(eax, eax).unwrap();
                a.ret().unwrap();
            });
            // A record's chunk: its pointer from the array at 0xc0, the
            // record from the fields at 0x1c8..0x1d8.
            builder.function("ST_STORE<SM_TRAITS>::ST_PAGE_RECORD_GET", |a| {
                a.mov(r11d, dword_ptr(rcx + 0x1c8)).unwrap();
                a.mov(ebx, dword_ptr(rcx + 0x1cc)).unwrap();
                a.mov(edi, dword_ptr(rcx + 0x1d0)).unwrap();
                a.mov(esi, dword_ptr(rcx + 0x1d8)).unwrap();
                a.mov(rdx, qword_ptr(rcx + rax * 8 + 0xc0)).unwrap();
                a.ret().unwrap();
            });
            // Two manager methods searching the key-to-store tree at 0x1c0,
            // one with lea and one with add.
            let search = builder.function(
                "B_TREE<_SM_PAGE_KEY, SMKM_STORE_MGR<SM_TRAITS>::SMKM_FRONTEND_ENTRY>::BTreeSearchKey",
                |a| a.ret().unwrap(),
            );
            builder.function("SMKM_STORE_MGR<SM_TRAITS>::SmFeReadInitiate", |a| {
                a.lea(rcx, qword_ptr(rdi + 0x1c0)).unwrap();
                a.call(search).unwrap();
                a.ret().unwrap();
            });
            builder.function("SMKM_STORE_MGR<SM_TRAITS>::SmFeCheckPresent", |a| {
                a.mov(rcx, qword_ptr(rsp + 0x28)).unwrap();
                a.add(rcx, 0x1c0).unwrap();
                a.call(search).unwrap();
                a.ret().unwrap();
            });
            builder
        }

        fn function(&mut self, name: &str, body: impl FnOnce(&mut CodeAssembler)) -> u64 {
            let address = BASE + u64::from(self.next);
            let mut a = CodeAssembler::new(64).unwrap();
            body(&mut a);
            let code = a.assemble(address).unwrap();
            let start = self.next as usize;
            self.bytes[start..start + code.len()].copy_from_slice(&code);
            self.next += 0x100;
            self.functions.insert(name.to_string(), address);
            address
        }

        /// A page-record lookup that follows redirecting records (key -1)
        /// to the key at +`next`: against an immediate -1 and on to the
        /// key past a `jne`, or, with `register`, against a register set to
        /// -1 and on to the key at a `je`'s target, as 28000 does.
        fn redirect(&mut self, name: &str, next: u32, register: bool) {
            let name = format!("ST_STORE<SM_TRAITS>::{name}");
            self.function(&name, |a| {
                let mut follow = a.create_label();
                let mut done = a.create_label();
                if register {
                    a.or(r12d, -1).unwrap();
                    a.set_label(&mut done).unwrap();
                    a.cmp(dword_ptr(r9), r12d).unwrap();
                    a.je(follow).unwrap();
                    a.mov(eax, dword_ptr(r9)).unwrap();
                    a.ret().unwrap();
                    a.set_label(&mut follow).unwrap();
                    a.mov(r9d, dword_ptr(r9 + next)).unwrap();
                    a.jmp(done).unwrap();
                } else {
                    a.set_label(&mut follow).unwrap();
                    a.cmp(dword_ptr(r8), -1).unwrap();
                    a.jne(done).unwrap();
                    a.mov(r9d, dword_ptr(r8 + next)).unwrap();
                    a.jmp(follow).unwrap();
                    a.set_label(&mut done).unwrap();
                    a.ret().unwrap();
                }
            });
        }

        /// A store method that switches to the process at `owner`.
        fn attaching_method(&mut self, name: &str, owner: u32) {
            let attach = self.functions["KeStackAttachProcess"];
            self.function(&format!("SMKM_STORE<SM_TRAITS>::{name}"), |a| {
                a.mov(rcx, qword_ptr(rbx + owner)).unwrap();
                a.call(attach).unwrap();
                a.ret().unwrap();
            });
        }

        /// The region mapping, which indexes the region array at 0x1b68.
        fn region_map(&mut self) -> u64 {
            self.function("SMKM_STORE<SM_TRAITS>::SmStMapVirtualRegion", |a| {
                a.mov(rax, qword_ptr(rcx + 0x1b68)).unwrap();
                a.lea(r14, qword_ptr(rax + rdi * 8)).unwrap();
                a.ret().unwrap();
            })
        }

        /// 24H2's page retrieval: `prelude`, then the store through the back
        /// pointer at 0x320, its virtual-region flag at 0x1a95, the region
        /// key's split, and the region mapping at `map`.
        fn retrieval(&mut self, map: u64, prelude: impl FnOnce(&mut CodeAssembler)) {
            self.function("ST_STORE<SM_TRAITS>::StDmpSinglePageRetrieve", |a| {
                let mut physical = a.create_label();
                prelude(a);
                a.mov(rdi, qword_ptr(rbp + 0x320)).unwrap();
                a.test(byte_ptr(rdi + 0x1a95), 4).unwrap();
                region_key(a);
                a.je(physical).unwrap();
                a.mov(rcx, rdi).unwrap();
                a.call(map).unwrap();
                a.set_label(&mut physical).unwrap();
                a.ret().unwrap();
            });
        }

        /// The code of 24H2 from 26100.9278 on, but for its page retrieval:
        /// two store methods attach to the owner at 0x1d00, and two
        /// page-record lookups follow redirects to the key at +`next`.
        fn build_24h2(next: u32, register: bool) -> Self {
            let mut builder = Self::new();
            builder.attaching_method("SmStSwapStore", 0x1d00);
            builder.attaching_method("SmStTrimWsStore", 0x1d00);
            builder.redirect("StDmPageRecordRemove", next, register);
            builder.redirect("StDmCombinePageRecords", next, register);
            builder
        }

        fn kernel(&self) -> KernelCode<'_> {
            KernelCode {
                image: ImageView {
                    base: BASE,
                    bytes: &self.bytes,
                    code: vec![(0x1000, 0x4000)],
                    data: Vec::new(),
                },
                functions: &self.functions,
            }
        }

        fn derive(&self) -> Result<StoreLayout> {
            derive(&self.kernel())
        }
    }

    #[test]
    fn derives_the_store_fields_from_the_functions_that_use_them() {
        let mut builder = Builder::build_24h2(4, false);
        let map = builder.region_map();
        builder.retrieval(map, |_| {});
        assert_eq!(
            builder.derive().unwrap(),
            crate::base::memory::store::fixture::layout()
        );
    }

    /// 28000 moved a redirecting record's next key from +4 to +8, and
    /// compares the key with a register holding -1.
    #[test]
    fn a_redirect_is_followed_where_the_build_keeps_the_next_key() {
        let mut builder = Builder::build_24h2(8, true);
        let map = builder.region_map();
        builder.retrieval(map, |_| {});
        assert_eq!(builder.derive().unwrap().redirect_next, 8);
    }

    #[test]
    fn owner_loads_that_disagree_refuse_the_layout() {
        let mut builder = Builder::new();
        builder.attaching_method("SmStSwapStore", 0x1d00);
        builder.attaching_method("SmStTrimWsStore", 0x1d08);
        assert!(owner_process(&builder.kernel()).is_err());
        builder.attaching_method("SmStEmpty", 0x1d00);
        assert_eq!(owner_process(&builder.kernel()).unwrap(), 0x1d00);
    }

    #[test]
    fn an_inlined_page_record_lookup_is_not_the_region_shift() {
        let mut builder = Builder::build_24h2(4, false);
        let map = builder.region_map();
        builder.retrieval(map, |a| {
            // The chunk index, twice (a record and its redirect), as 24H2
            // RTM inlines it, before the region key's own split.
            for _ in 0..2 {
                a.mov(ecx, dword_ptr(rbp + 0x1c8)).unwrap();
                a.shr(edx, cl).unwrap();
                a.bsr(ecx, edx).unwrap();
            }
        });
        assert_eq!(builder.derive().unwrap().region_shift, 0x32c);
    }

    #[test]
    fn a_flag_tested_on_another_pointer_is_not_the_virtual_flag() {
        let mut builder = Builder::build_24h2(4, false);
        let map = builder.region_map();
        builder.retrieval(map, |a| {
            // A byte of a different object, before the store's flag.
            a.mov(rsi, qword_ptr(rbp + 0x578)).unwrap();
            a.test(byte_ptr(rsi + 0x8ea), 1).unwrap();
        });
        assert_eq!(builder.derive().unwrap().virtual_flag, (0x1a95, 2));
    }

    /// A call changes the volatile registers: a flag tested through one
    /// after a call is not tested through the back pointer loaded before it.
    #[test]
    fn a_register_a_call_changes_is_not_the_back_pointer() {
        let mut builder = Builder::build_24h2(4, false);
        let map = builder.region_map();
        let other = builder.function("ExAllocatePool", |a| a.ret().unwrap());
        builder.retrieval(map, |a| {
            a.mov(rax, qword_ptr(rbp + 0x320)).unwrap();
            a.call(other).unwrap();
            a.test(byte_ptr(rax + 0x8ea), 1).unwrap();
        });
        assert_eq!(builder.derive().unwrap().virtual_flag, (0x1a95, 2));
    }

    /// `exe` mapped at its own base, and its functions from its PDB's public
    /// symbols, by undecorated name.
    fn load_kernel(exe: &std::path::Path) -> (Vec<u8>, u64, HashMap<String, u64>) {
        use pdb2::FallibleIterator;
        use pelite::pe64::PeFile;
        let file = std::fs::read(exe).unwrap();
        let pe = PeFile::from_bytes(&file).unwrap();
        let base = pe.optional_header().ImageBase;
        let size = pe.optional_header().SizeOfImage as usize;
        let mut bytes = vec![0u8; size];
        let headers = (pe.optional_header().SizeOfHeaders as usize).min(size);
        bytes[..headers].copy_from_slice(&file[..headers]);
        for section in pe.section_headers() {
            let start = section.VirtualAddress as usize;
            let raw = pe.get_section_bytes(section).unwrap_or(&[]);
            let len = raw.len().min(size.saturating_sub(start));
            bytes[start..start + len].copy_from_slice(&raw[..len]);
        }
        let pdb_file = std::fs::File::open(exe.with_extension("pdb")).unwrap();
        let mut pdb = pdb2::PDB::open(pdb_file).unwrap();
        let map = pdb.address_map().unwrap();
        let globals = pdb.global_symbols().unwrap();
        let mut symbols = globals.iter();
        let mut functions = HashMap::new();
        while let Some(symbol) = symbols.next().unwrap() {
            if let Ok(pdb2::SymbolData::Public(public)) = symbol.parse()
                && let Some(rva) = public.offset.to_rva(&map)
            {
                let name = public.name.to_string();
                let name = undname::demangle(&name, undname::Flags::NAME_ONLY)
                    .unwrap_or_else(|_| name.into_owned());
                functions.insert(name, base + u64::from(rva.0));
            }
        }
        (bytes, base, functions)
    }

    /// The layout of every `ntoskrnl-<version>.exe` (with its `.pdb`) in
    /// `NTOSEYE_NTOSKRNL_DIR`, x64 or ARM64, as `tools/fetch_ntoskrnl.py`
    /// downloads them.
    /// `cargo test --lib store_layout -- --ignored --nocapture`.
    #[test]
    #[ignore = "needs kernels in NTOSEYE_NTOSKRNL_DIR"]
    fn derives_the_layout_of_real_kernels() {
        let dir = std::env::var("NTOSEYE_NTOSKRNL_DIR").expect("NTOSEYE_NTOSKRNL_DIR");
        let mut kernels: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|e| e == "exe"))
            .collect();
        kernels.sort();
        let mut failures = Vec::new();
        for exe in kernels {
            let (bytes, base, functions) = load_kernel(&exe);
            let code = crate::nt::pe::executable_ranges(&PeView::from_bytes(&bytes).unwrap());
            let kernel = KernelCode {
                image: ImageView {
                    base,
                    bytes: &bytes,
                    code,
                    data: Vec::new(),
                },
                functions: &functions,
            };
            let machine = PeView::from_bytes(&bytes).unwrap().file_header().Machine;
            let derived = match machine {
                crate::arch::IMAGE_FILE_MACHINE_ARM64 => arm64::derive(&kernel),
                _ => derive(&kernel),
            };
            match derived {
                Ok(layout) => println!("{}: {layout:x?}", exe.display()),
                // 1507 to 1607 lay the store out differently; they are not
                // supported.
                Err(error) if build(&exe) < 15063 => println!("{}: {error}", exe.display()),
                Err(error) => failures.push(format!("{}: {error}", exe.display())),
            }
        }
        assert!(failures.is_empty(), "{failures:#?}");
    }

    /// The build number in `ntoskrnl-10.0.<build>.<revision>.exe`.
    fn build(exe: &std::path::Path) -> u32 {
        let name = exe.file_stem().unwrap().to_string_lossy();
        name.split('.')
            .nth(2)
            .and_then(|b| b.parse().ok())
            .unwrap_or(0)
    }
}
