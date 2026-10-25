//! Field offsets of the kernel's memory-compression store, read from the
//! kernel's own code. The PDB names the store manager's functions but has no
//! types for its structures, and the offsets move between Windows releases
//! (and once within 24H2's servicing), so each one comes from a function
//! that uses it.

use std::collections::HashMap;

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction};

use crate::base::error::{Error, Result};

use super::hv_layout::ImageView;

/// The kernel image and the addresses of its functions, by undecorated name.
pub struct KernelCode<'a> {
    pub image: ImageView<'a>,
    pub functions: &'a HashMap<String, u64>,
}

/// Where the store keeps what a page lookup needs. `SMKM_STORE` offsets are
/// from the store; `ST_STORE` offsets are from the store's embedded
/// `ST_STORE`, at `st_store` in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreLayout {
    /// `SMKM_STORE`: the process whose address space holds the regions.
    pub owner_process: u32,
    /// `SMKM_STORE`: the pointer to the array of region entries.
    pub region_array: u32,
    /// `SMKM_STORE`: the byte and bit set when regions are virtual.
    pub virtual_flag: (u32, u8),
    /// `ST_STORE`: the pointer back to the store that embeds it.
    pub back_pointer: u32,
    /// `ST_STORE`: the shift that takes a region key to its region index.
    pub region_shift: u32,
    /// `ST_STORE`: the mask that takes a region key to its offset in the
    /// region, in 16-byte units.
    pub region_offset_mask: u32,
    /// `ST_STORE`: the array of chunk pointers that page records live in.
    pub chunk_array: u32,
    /// `ST_STORE`: the chunk shift, records-per-chunk mask, record size and
    /// chunk header size.
    pub chunk_fields: [u32; 4],
    /// `SMKM_STORE_MGR`: the tree from page key to store index.
    pub key_tree: u32,
    /// `ST_STORE`: the tree from page key to region key.
    pub pages_tree: u32,
    pub compression: Compression,
}

/// The store layout `code` uses, when every anchor is found and agrees.
pub fn derive(code: &KernelCode<'_>) -> Result<StoreLayout> {
    let owner_process = owner_process(code)?;
    let (region_array, virtual_flag, back_pointer) = region_fields(code)?;
    let (region_shift, region_offset_mask) = region_key_fields(code)?;
    let (chunk_array, chunk_fields) = chunk_fields(code)?;
    let key_tree = key_tree(code)?;
    let pages_tree = pages_tree(code)?;
    let compression = compression(code)?;
    Ok(StoreLayout {
        owner_process,
        region_array,
        virtual_flag,
        back_pointer,
        region_shift,
        region_offset_mask,
        chunk_array,
        chunk_fields,
        key_tree,
        pages_tree,
        compression,
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
        let mut seen = std::collections::BTreeMap::new();
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

    /// The functions whose name starts with `prefix`.
    fn functions_named(&self, prefix: &str) -> Vec<u64> {
        self.functions
            .iter()
            .filter(|(name, _)| name.starts_with(prefix))
            .map(|(_, address)| *address)
            .collect()
    }
}

fn near_target(instruction: &Instruction) -> Option<u64> {
    (instruction.op0_kind() == iced_x86::OpKind::NearBranch64).then(|| instruction.near_branch64())
}

/// `[reg+D]`'s `D`, for a memory operand with a base and no index.
fn based_offset(instruction: &Instruction) -> Option<u32> {
    use iced_x86::Register;
    (instruction.memory_index() == Register::None
        && !matches!(instruction.memory_base(), Register::None | Register::RIP))
    .then(|| u32::try_from(instruction.memory_displacement64()).ok())
    .flatten()
}

/// The value most of `votes` agree on, when at least two do and no other
/// value has as many.
fn agreed(votes: &HashMap<u32, usize>, what: &str) -> Result<u32> {
    let mut ranked: Vec<(u32, usize)> = votes.iter().map(|(v, n)| (*v, *n)).collect();
    ranked.sort_by_key(|(value, count)| (std::cmp::Reverse(*count), *value));
    match ranked.as_slice() {
        [(value, count), rest @ ..] if *count >= 2 && rest.first().is_none_or(|r| r.1 < *count) => {
            Ok(*value)
        }
        _ => Err(layout_error(format_args!(
            "{what}: no agreement in {ranked:x?}"
        ))),
    }
}

/// The value with the most `votes`, when no other has as many.
fn most(votes: &HashMap<u32, usize>, what: &str) -> Result<u32> {
    let mut ranked: Vec<(u32, usize)> = votes.iter().map(|(v, n)| (*v, *n)).collect();
    ranked.sort_by_key(|(value, count)| (std::cmp::Reverse(*count), *value));
    match ranked.as_slice() {
        [(value, count), rest @ ..] if rest.first().is_none_or(|r| r.1 < *count) => Ok(*value),
        _ => Err(layout_error(format_args!(
            "{what}: no single value in {ranked:x?}"
        ))),
    }
}

/// The store's owner-process field: the store methods switch to the
/// process that holds the regions with `KeStackAttachProcess` (or
/// `KiStackAttachProcess`), its first argument loaded from the store.
fn owner_process(code: &KernelCode<'_>) -> Result<u32> {
    use iced_x86::{Mnemonic, OpKind, Register};
    let attach: Vec<u64> = ["KeStackAttachProcess", "KiStackAttachProcess"]
        .iter()
        .filter_map(|name| code.address(name).ok())
        .collect();
    let mut votes: HashMap<u32, usize> = HashMap::new();
    for function in code.functions_named("SMKM_STORE<SM_TRAITS>::") {
        let mut found = None;
        let mut rcx = None;
        for instruction in code.instructions(function) {
            if instruction.mnemonic() == Mnemonic::Call {
                if near_target(&instruction).is_some_and(|t| attach.contains(&t)) {
                    found = found.or(rcx);
                }
                rcx = None;
            } else if instruction.op0_kind() == OpKind::Register
                && instruction.op0_register().full_register() == Register::RCX
            {
                rcx = (instruction.mnemonic() == Mnemonic::Mov
                    && instruction.op1_kind() == OpKind::Memory)
                    .then(|| based_offset(&instruction))
                    .flatten();
            }
        }
        if let Some(offset) = found {
            *votes.entry(offset).or_default() += 1;
        }
    }
    agreed(&votes, "owner process")
}

/// The offsets `A` (0x100 or more) of `mov r,[x+A]` loads whose register is
/// then indexed by 8 (`[r+i*8]`): fields that point to arrays of pointers.
fn pointer_arrays(instructions: &[Instruction]) -> HashMap<u32, usize> {
    use iced_x86::{Mnemonic, OpKind, Register};
    let mut loaded: HashMap<Register, u32> = HashMap::new();
    let mut found: HashMap<u32, usize> = HashMap::new();
    for instruction in instructions {
        if matches!(instruction.mnemonic(), Mnemonic::Mov | Mnemonic::Lea)
            && instruction.op1_kind() == OpKind::Memory
            && instruction.memory_index() != Register::None
            && instruction.memory_index_scale() == 8
            && let Some(offset) = loaded.get(&instruction.memory_base().full_register())
        {
            *found.entry(*offset).or_default() += 1;
        }
        if instruction.op0_kind() == OpKind::Register {
            let register = instruction.op0_register().full_register();
            match (instruction.mnemonic() == Mnemonic::Mov
                && instruction.op1_kind() == OpKind::Memory)
                .then(|| based_offset(instruction))
                .flatten()
                .filter(|offset| *offset >= 0x100)
            {
                Some(offset) => loaded.insert(register, offset),
                None => loaded.remove(&register),
            };
        }
    }
    found
}

/// The store's region array (from `SmStMapVirtualRegion`, which indexes
/// it), and from `StDmpSinglePageRetrieve` the `ST_STORE`'s back pointer to
/// the store (the `rcx` it passes to `SmStMapVirtualRegion`) and the flag it
/// tests on the store first: set when regions are virtual.
fn region_fields(code: &KernelCode<'_>) -> Result<(u32, (u32, u8), u32)> {
    use iced_x86::{Mnemonic, OpKind, Register};
    let map = code.address("SMKM_STORE<SM_TRAITS>::SmStMapVirtualRegion")?;
    let mut arrays = pointer_arrays(&code.instructions(map));
    arrays.retain(|_, count| *count > 0);
    let array = match arrays.keys().copied().collect::<Vec<_>>().as_slice() {
        [array] => *array,
        other => return Err(layout_error(format_args!("region array: {other:x?}"))),
    };
    let retrieve = code.address("ST_STORE<SM_TRAITS>::StDmpSinglePageRetrieve")?;
    let store_methods = code.functions_named("SMKM_STORE<SM_TRAITS>::");
    // Registers loaded from `[x+B]`, by register: the `B`.
    let mut loaded: HashMap<Register, u32> = HashMap::new();
    let mut back_pointers: HashMap<u32, usize> = HashMap::new();
    let mut tests: Vec<(u32, u32, u8)> = Vec::new();
    for instruction in code.instructions(retrieve) {
        match instruction.mnemonic() {
            Mnemonic::Call => {
                // A store method's first argument is the store.
                if near_target(&instruction).is_some_and(|t| store_methods.contains(&t))
                    && let Some(back) = loaded.get(&Register::RCX)
                {
                    *back_pointers.entry(*back).or_default() += 1;
                }
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
    let back = most(&back_pointers, "back pointer")?;
    let mut flags: Vec<(u32, u8)> = tests
        .into_iter()
        .filter(|(through, _, _)| *through == back)
        .map(|(_, flag, bit)| (flag, bit))
        .collect();
    flags.sort();
    flags.dedup();
    match flags.as_slice() {
        [flag] => Ok((array, *flag, back)),
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
    use iced_x86::{Mnemonic, OpKind, Register};
    let retrieve = code.address("ST_STORE<SM_TRAITS>::StDmpSinglePageRetrieve")?;
    // The `[x+D]` fields each register's value came from.
    let mut origins: HashMap<Register, Vec<u32>> = HashMap::new();
    let mut shifts: HashMap<u32, usize> = HashMap::new();
    let mut masks: HashMap<u32, usize> = HashMap::new();
    let instructions = code.instructions(retrieve);
    for (index, instruction) in instructions.iter().enumerate() {
        let instruction = *instruction;
        let destination = (instruction.op0_kind() == OpKind::Register)
            .then(|| instruction.op0_register().full_register());
        let field = (instruction.op_count() > 1 && instruction.op1_kind() == OpKind::Memory)
            .then(|| based_offset(&instruction))
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
                        *shifts.entry(*shift).or_default() += 1;
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
                    for field in fields.iter().filter(|field| **field >= 0x100) {
                        *masks.entry(*field).or_default() += 1;
                    }
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
        let value = match (instruction.mnemonic(), instruction.op1_kind()) {
            (Mnemonic::Mov, OpKind::Memory) => field.map(|f| vec![f]),
            (Mnemonic::Mov, OpKind::Register) => origins
                .get(&instruction.op1_register().full_register())
                .cloned(),
            // An AND with a register keeps both origins.
            (Mnemonic::And, OpKind::Register) => {
                let mut both = origins.get(&register).cloned().unwrap_or_default();
                both.extend(
                    origins
                        .get(&instruction.op1_register().full_register())
                        .cloned()
                        .unwrap_or_default(),
                );
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
        most(&shifts, "region shift")?,
        most(&masks, "region offset mask")?,
    ))
}

/// The page-record fields of `ST_PAGE_RECORD_GET`: the array of chunk
/// pointers (`[st+i*8+A]`) and the four 32-bit fields it reads from the
/// store, in offset order (shift, per-chunk mask, record size, header).
fn chunk_fields(code: &KernelCode<'_>) -> Result<(u32, [u32; 4])> {
    use iced_x86::{OpKind, Register};
    let get = code.address("ST_STORE<SM_TRAITS>::ST_PAGE_RECORD_GET")?;
    let mut arrays = std::collections::BTreeSet::new();
    let mut dwords = std::collections::BTreeSet::new();
    for instruction in code.instructions(get) {
        if instruction.op_count() < 2
            || instruction.op1_kind() != OpKind::Memory
            || instruction.memory_base() == Register::RSP
        {
            continue;
        }
        let offset = instruction.memory_displacement64();
        if instruction.memory_index() != Register::None && instruction.memory_index_scale() == 8 {
            if offset != 0 {
                arrays.insert(offset as u32);
            }
        } else if instruction.memory_size().size() == 4
            && let Some(field) = based_offset(&instruction).filter(|f| *f >= 0x40)
        {
            dwords.insert(field);
        }
    }
    let array = match arrays.into_iter().collect::<Vec<_>>().as_slice() {
        [array] => *array,
        other => return Err(layout_error(format_args!("chunk array: {other:x?}"))),
    };
    match dwords.into_iter().collect::<Vec<_>>().as_slice() {
        [a, b, c, d] => Ok((array, [*a, *b, *c, *d])),
        other => Err(layout_error(format_args!("chunk fields: {other:x?}"))),
    }
}

/// The store manager's key-to-store tree: the `rcx` that `SMKM_STORE_MGR`
/// methods pass to the frontend tree's search, `lea rcx,[mgr+K]` or
/// `add rcx,K`.
fn key_tree(code: &KernelCode<'_>) -> Result<u32> {
    use iced_x86::{Mnemonic, OpKind, Register};
    let searches: Vec<u64> = code
        .functions
        .iter()
        .filter(|(name, _)| {
            name.contains("SMKM_FRONTEND_ENTRY") && name.ends_with("::BTreeSearchKey")
        })
        .map(|(_, address)| *address)
        .collect();
    let mut votes: HashMap<u32, usize> = HashMap::new();
    for function in code.functions_named("SMKM_STORE_MGR<SM_TRAITS>::") {
        let mut rcx = None;
        for instruction in code.instructions(function) {
            if instruction.mnemonic() == Mnemonic::Call {
                if near_target(&instruction).is_some_and(|t| searches.contains(&t))
                    && let Some(offset) = rcx
                {
                    *votes.entry(offset).or_default() += 1;
                }
                rcx = None;
            } else if instruction.op0_kind() == OpKind::Register
                && instruction.op0_register().full_register() == Register::RCX
            {
                rcx = match (instruction.mnemonic(), instruction.op1_kind()) {
                    (Mnemonic::Lea, _) => based_offset(&instruction),
                    (Mnemonic::Add, OpKind::Immediate32to64 | OpKind::Immediate8to64) => {
                        u32::try_from(instruction.immediate(1)).ok()
                    }
                    _ => None,
                };
            }
        }
    }
    agreed(&votes, "key-to-store tree")
}

/// How a store's pages are compressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    /// Before 24H2: the `ST_STORE` word at this offset is the
    /// `RtlDecompressBuffer` format.
    FormatField(u32),
    /// From 24H2: LZ4 when the `SMKM_STORE` count at this offset is zero.
    Lz4UnlessCount(u32),
}

/// From `SmStoreDecompressBuffer` (24H2 and later), the count it tests
/// first; otherwise the field loaded into `ecx` before a call to
/// `RtlDecompressBufferEx` by `StDmSinglePageCopy`.
fn compression(code: &KernelCode<'_>) -> Result<Compression> {
    use iced_x86::{Mnemonic, OpKind, Register};
    if let Ok(decompress) = code.address("SmStoreDecompressBuffer") {
        let instructions = code.instructions(decompress);
        for (index, load) in instructions.iter().enumerate() {
            let counted = matches!(load.mnemonic(), Mnemonic::Mov | Mnemonic::Movsxd)
                && load.op1_kind() == OpKind::Memory
                && load.memory_base() == Register::RCX
                && load.memory_size().size() == 4;
            let tested = instructions[index + 1..].iter().take(4).any(|test| {
                test.mnemonic() == Mnemonic::Test
                    && test.op0_kind() == OpKind::Register
                    && test.op0_register().full_register() == load.op0_register().full_register()
            });
            if counted
                && tested
                && let Some(count) = based_offset(load)
            {
                return Ok(Compression::Lz4UnlessCount(count));
            }
        }
        return Err(layout_error(
            "no algorithm count in SmStoreDecompressBuffer",
        ));
    }
    let decompress = code.address("RtlDecompressBufferEx")?;
    let copy = code.address("ST_STORE<SM_TRAITS>::StDmSinglePageCopy")?;
    let mut votes: HashMap<u32, usize> = HashMap::new();
    let mut ecx = None;
    for instruction in code.instructions(copy) {
        if instruction.mnemonic() == Mnemonic::Call {
            if near_target(&instruction) == Some(decompress)
                && let Some(field) = ecx
            {
                *votes.entry(field).or_default() += 1;
            }
            ecx = None;
        } else if instruction.op0_kind() == OpKind::Register
            && instruction.op0_register().full_register() == Register::RCX
        {
            ecx = (instruction.mnemonic() == Mnemonic::Movzx
                && instruction.op1_kind() == OpKind::Memory)
                .then(|| based_offset(&instruction))
                .flatten();
        }
    }
    most(&votes, "decompression format").map(Compression::FormatField)
}

/// The `ST_STORE`'s pages tree (page key to region key): the `rcx` that
/// `ST_STORE` methods pass to that tree's search, `lea rcx,[st+P]`, or the
/// store itself (`mov rcx,reg`) when the tree is at 0.
fn pages_tree(code: &KernelCode<'_>) -> Result<u32> {
    use iced_x86::{Mnemonic, OpKind, Register};
    let searches: Vec<u64> = code
        .functions
        .iter()
        .filter(|(name, _)| name.contains("_ST_PAGE_ENTRY") && name.ends_with("::BTreeSearchKey"))
        .map(|(_, address)| *address)
        .collect();
    let mut votes: HashMap<u32, usize> = HashMap::new();
    for function in code.functions_named("ST_STORE<SM_TRAITS>::") {
        let mut rcx = None;
        for instruction in code.instructions(function) {
            if instruction.mnemonic() == Mnemonic::Call {
                if near_target(&instruction).is_some_and(|t| searches.contains(&t))
                    && let Some(offset) = rcx
                {
                    *votes.entry(offset).or_default() += 1;
                }
                rcx = None;
            } else if instruction.op0_kind() == OpKind::Register
                && instruction.op0_register().full_register() == Register::RCX
            {
                rcx = match (instruction.mnemonic(), instruction.op1_kind()) {
                    (Mnemonic::Lea, _) => based_offset(&instruction),
                    (Mnemonic::Mov, OpKind::Register) => Some(0),
                    _ => None,
                };
            }
        }
    }
    most(&votes, "pages tree")
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

        /// A store method that switches to the process at `owner`.
        fn attaching_method(&mut self, name: &str, owner: u32) {
            let attach = self.functions["KeStackAttachProcess"];
            self.function(&format!("SMKM_STORE<SM_TRAITS>::{name}"), |a| {
                a.mov(rcx, qword_ptr(rbx + owner)).unwrap();
                a.call(attach).unwrap();
                a.ret().unwrap();
            });
        }

        /// 24H2's page retrieval: the store through the back pointer, its
        /// virtual-region flag, then the region mapping, which indexes the
        /// region array.
        fn retrieval(&mut self, back: u32, flag: u32, array: u32) {
            let map = self.function("SMKM_STORE<SM_TRAITS>::SmStMapVirtualRegion", |a| {
                a.mov(rax, qword_ptr(rcx + array)).unwrap();
                a.lea(r14, qword_ptr(rax + rdi * 8)).unwrap();
                a.ret().unwrap();
            });
            self.function("ST_STORE<SM_TRAITS>::StDmpSinglePageRetrieve", |a| {
                let mut physical = a.create_label();
                a.mov(rdi, qword_ptr(rbp + back)).unwrap();
                a.test(byte_ptr(rdi + flag), 4).unwrap();
                region_key(a);
                a.je(physical).unwrap();
                a.mov(rcx, rdi).unwrap();
                a.call(map).unwrap();
                a.set_label(&mut physical).unwrap();
                a.ret().unwrap();
            });
        }

        fn derive(&self) -> Result<StoreLayout> {
            derive(&KernelCode {
                image: ImageView {
                    base: BASE,
                    bytes: &self.bytes,
                    code: vec![(0x1000, 0x4000)],
                    data: Vec::new(),
                },
                functions: &self.functions,
            })
        }
    }

    #[test]
    fn derives_the_store_fields_from_the_functions_that_use_them() {
        let mut builder = Builder::new();
        builder.attaching_method("SmStSwapStore", 0x1d00);
        builder.attaching_method("SmStTrimWsStore", 0x1d00);
        builder.retrieval(0x320, 0x1a95, 0x1b68);
        assert_eq!(
            builder.derive().unwrap(),
            StoreLayout {
                owner_process: 0x1d00,
                region_array: 0x1b68,
                virtual_flag: (0x1a95, 2),
                back_pointer: 0x320,
                region_shift: 0x32c,
                region_offset_mask: 0x328,
                chunk_array: 0xc0,
                chunk_fields: [0x1c8, 0x1cc, 0x1d0, 0x1d8],
                key_tree: 0x1c0,
                pages_tree: 0,
                compression: Compression::Lz4UnlessCount(0x12c0),
            }
        );
    }

    #[test]
    fn owner_loads_that_disagree_refuse_the_layout() {
        let mut builder = Builder::new();
        builder.attaching_method("SmStSwapStore", 0x1d00);
        builder.attaching_method("SmStTrimWsStore", 0x1d08);
        builder.retrieval(0x320, 0x1a95, 0x1b68);
        assert!(builder.derive().is_err());
    }

    #[test]
    fn an_inlined_page_record_lookup_is_not_the_region_shift() {
        let mut builder = Builder::new();
        builder.attaching_method("SmStSwapStore", 0x1d00);
        builder.attaching_method("SmStTrimWsStore", 0x1d00);
        builder.function("SMKM_STORE<SM_TRAITS>::SmStMapVirtualRegion", |a| {
            a.mov(rax, qword_ptr(rcx + 0x1b68)).unwrap();
            a.lea(r14, qword_ptr(rax + rdi * 8)).unwrap();
            a.ret().unwrap();
        });
        let map = builder.functions["SMKM_STORE<SM_TRAITS>::SmStMapVirtualRegion"];
        builder.function("ST_STORE<SM_TRAITS>::StDmpSinglePageRetrieve", |a| {
            // The chunk index, twice (a record and its redirect), as 24H2
            // RTM inlines it, before the region key's own split.
            for _ in 0..2 {
                a.mov(ecx, dword_ptr(rbp + 0x1c8)).unwrap();
                a.shr(edx, cl).unwrap();
                a.bsr(ecx, edx).unwrap();
            }
            a.mov(rdi, qword_ptr(rbp + 0x320)).unwrap();
            a.test(byte_ptr(rdi + 0x1a95), 4).unwrap();
            region_key(a);
            a.mov(rcx, rdi).unwrap();
            a.call(map).unwrap();
            a.ret().unwrap();
        });
        assert_eq!(builder.derive().unwrap().region_shift, 0x32c);
    }

    #[test]
    fn a_flag_tested_on_another_pointer_is_not_the_virtual_flag() {
        let mut builder = Builder::new();
        builder.attaching_method("SmStSwapStore", 0x1d00);
        builder.attaching_method("SmStTrimWsStore", 0x1d00);
        builder.function("SMKM_STORE<SM_TRAITS>::SmStMapVirtualRegion", |a| {
            a.mov(rax, qword_ptr(rcx + 0x1b68)).unwrap();
            a.lea(r14, qword_ptr(rax + rdi * 8)).unwrap();
            a.ret().unwrap();
        });
        let map = builder.functions["SMKM_STORE<SM_TRAITS>::SmStMapVirtualRegion"];
        builder.function("ST_STORE<SM_TRAITS>::StDmpSinglePageRetrieve", |a| {
            // A byte of a different object, then the store's flag.
            a.mov(rsi, qword_ptr(rbp + 0x578)).unwrap();
            a.test(byte_ptr(rsi + 0x8ea), 1).unwrap();
            a.mov(rdi, qword_ptr(rbp + 0x320)).unwrap();
            a.test(byte_ptr(rdi + 0x1a95), 4).unwrap();
            region_key(a);
            a.mov(rcx, rdi).unwrap();
            a.call(map).unwrap();
            a.ret().unwrap();
        });
        assert_eq!(builder.derive().unwrap().virtual_flag, (0x1a95, 2));
    }

    /// A kernel file's mapped image and its functions by undecorated name.
    struct LoadedKernel {
        bytes: Vec<u8>,
        base: u64,
        code: Vec<(u32, u32)>,
        functions: HashMap<String, u64>,
    }

    /// `exe` mapped, with its functions from its PDB's public symbols.
    fn load_kernel(exe: &std::path::Path) -> LoadedKernel {
        use pdb2::FallibleIterator;
        use pelite::pe64::{Pe, PeFile};
        let file = std::fs::read(exe).unwrap();
        let pe = PeFile::from_bytes(&file).unwrap();
        let base = pe.optional_header().ImageBase;
        let size = pe.optional_header().SizeOfImage as usize;
        let mut bytes = vec![0u8; size];
        let mut code = Vec::new();
        for section in pe.section_headers() {
            let start = section.VirtualAddress;
            let raw = pe.get_section_bytes(section).unwrap_or(&[]);
            let len = raw.len().min(size.saturating_sub(start as usize));
            bytes[start as usize..start as usize + len].copy_from_slice(&raw[..len]);
            if section.Characteristics & 0x2000_0000 != 0 {
                code.push((start, start + section.VirtualSize.max(len as u32)));
            }
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
        LoadedKernel {
            bytes,
            base,
            code,
            functions,
        }
    }

    /// The layout of every `ntoskrnl-<version>.exe` (with its `.pdb`) in
    /// `NTOSEYE_NTOSKRNL_DIR`, as `tools/fetch_ntoskrnl.py` downloads them.
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
            let LoadedKernel {
                bytes,
                base,
                code,
                functions,
            } = load_kernel(&exe);
            let kernel = KernelCode {
                image: ImageView {
                    base,
                    bytes: &bytes,
                    code,
                    data: Vec::new(),
                },
                functions: &functions,
            };
            match derive(&kernel) {
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
