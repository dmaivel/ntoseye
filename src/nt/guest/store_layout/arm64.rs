//! The store layout from an ARM64 kernel's code: the anchors of the AMD64
//! derivation, read from A64 code. A64 reaches a field through `add` and
//! register offsets as often as through an immediate, so each register's
//! value is followed as [`Value`] rather than read off one instruction.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use bad64::{Imm, Instruction, Op, Operand, Reg, Shift};

use super::{KernelCode, layout_error, only, winner};
use crate::base::error::Result;
use crate::base::memory::{ChunkFields, Compression, StoreLayout};

/// x0..x30; the zero register, sp and others have no slot.
fn slot(register: Reg) -> Option<usize> {
    let number = register as u32;
    if (Reg::X0 as u32..=Reg::X30 as u32).contains(&number) {
        return Some((number - Reg::X0 as u32) as usize);
    }
    if (Reg::W0 as u32..=Reg::W30 as u32).contains(&number) {
        return Some((number - Reg::W0 as u32) as usize);
    }
    None
}

/// Whether `register` is the stack pointer or the frame pointer (x29),
/// through which a function reaches its own locals.
fn frame(register: Reg) -> bool {
    matches!(register, Reg::SP | Reg::WSP | Reg::X29)
}

fn immediate(imm: &Imm) -> u64 {
    match *imm {
        Imm::Signed(value) => value as u64,
        Imm::Unsigned(value) => value,
    }
}

/// What a register holds, as far as the derivation follows it.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Value {
    /// The function's first argument, or a copy of it.
    Arg0,
    /// Another register's value, copied: nothing known about it.
    Opaque,
    Const(u64),
    /// Some pointer plus this offset (`add x1, x0, #0x1c0`).
    Offset(u32),
    /// Loaded from some pointer plus this offset: a field's value.
    Field(u32),
    /// Combined (`and`) from the fields it came from.
    Origins(BTreeSet<u32>),
}

impl Value {
    /// Whether the value moves an address by a known amount.
    fn offsets(&self) -> bool {
        matches!(self, Self::Const(_) | Self::Offset(_))
    }

    /// The constant part of an address formed from this value.
    fn displacement(&self) -> u64 {
        match self {
            Self::Const(value) => *value,
            Self::Offset(offset) => u64::from(*offset),
            _ => 0,
        }
    }

    /// The fields this value came from.
    fn origins(&self) -> BTreeSet<u32> {
        match self {
            Self::Field(field) => BTreeSet::from([*field]),
            Self::Origins(fields) => fields.clone(),
            _ => BTreeSet::new(),
        }
    }
}

/// A memory operand: its base register, immediate offset, and index
/// register with the shift it is scaled by.
struct Memory {
    base: Reg,
    offset: u64,
    index: Option<(Reg, u32)>,
}

/// The memory operand of a load or store, if it has one.
fn memory(instruction: &Instruction) -> Option<Memory> {
    instruction
        .operands()
        .iter()
        .find_map(|operand| match operand {
            Operand::MemReg(base) | Operand::MemPostIdxImm { reg: base, .. } => Some(Memory {
                base: *base,
                offset: 0,
                index: None,
            }),
            Operand::MemOffset { reg, offset, .. } => Some(Memory {
                base: *reg,
                offset: immediate(offset),
                index: None,
            }),
            Operand::MemPreIdx { reg, imm } => Some(Memory {
                base: *reg,
                offset: immediate(imm),
                index: None,
            }),
            Operand::MemExt { regs, shift, .. } => {
                let amount = match shift {
                    Some(
                        Shift::LSL(n)
                        | Shift::UXTW(n)
                        | Shift::SXTW(n)
                        | Shift::UXTX(n)
                        | Shift::SXTX(n),
                    ) => *n,
                    _ => 0,
                };
                Some(Memory {
                    base: regs[0],
                    offset: 0,
                    index: Some((regs[1], amount)),
                })
            }
            _ => None,
        })
}

/// The general registers an instruction writes first: its destination,
/// and for a load pair, both.
fn destinations(instruction: &Instruction) -> Vec<Reg> {
    let registers = |operand: &Operand| match operand {
        Operand::Reg { reg, .. } => Some(*reg),
        _ => None,
    };
    let operands = instruction.operands();
    match instruction.op() {
        Op::LDP | Op::LDPSW | Op::LDNP => operands.iter().take(2).filter_map(registers).collect(),
        _ => operands.first().and_then(registers).into_iter().collect(),
    }
}

/// Whether the instruction loads from memory into general registers.
fn loads(instruction: &Instruction) -> bool {
    matches!(
        instruction.op(),
        Op::LDR
            | Op::LDRB
            | Op::LDRH
            | Op::LDRSB
            | Op::LDRSH
            | Op::LDRSW
            | Op::LDUR
            | Op::LDURB
            | Op::LDURH
            | Op::LDURSW
            | Op::LDAR
            | Op::LDARB
            | Op::LDARH
            | Op::LDP
            | Op::LDPSW
            | Op::LDNP
    ) && destinations(instruction)
        .iter()
        .all(|r| slot(*r).is_some() || is_zero(*r))
}

fn is_zero(register: Reg) -> bool {
    matches!(register, Reg::XZR | Reg::WZR)
}

/// Register and stack-slot values through a function's instructions, in
/// address order, as the AMD64 derivation reads them.
struct Tracker {
    registers: [Option<Value>; 31],
    /// Values stored to the frame, by their offset from sp or fp, taken
    /// as one base: the functions read here set fp to sp at the end of
    /// their prologue and move neither after it.
    stack: HashMap<u64, Value>,
}

impl Tracker {
    fn new() -> Self {
        let mut registers: [Option<Value>; 31] = Default::default();
        registers[0] = Some(Value::Arg0);
        Self {
            registers,
            stack: HashMap::new(),
        }
    }

    fn get(&self, register: Reg) -> Option<&Value> {
        slot(register).and_then(|slot| self.registers[slot].as_ref())
    }

    fn set(&mut self, register: Reg, value: Option<Value>) {
        if let Some(slot) = slot(register) {
            self.registers[slot] = value;
        }
    }

    /// The constant part of `memory`'s address: its offset, plus what the
    /// base and the scaled index add.
    fn displacement(&self, memory: &Memory) -> u64 {
        let base = self.get(memory.base).map_or(0, Value::displacement);
        let index = memory.index.map_or(0, |(index, shift)| {
            self.get(index)
                .map_or(0, Value::displacement)
                .wrapping_shl(shift)
        });
        memory.offset.wrapping_add(base).wrapping_add(index)
    }

    /// The source operand as a value: a register's, or an immediate.
    fn operand(&self, operand: &Operand) -> Option<Value> {
        match operand {
            Operand::Reg { reg, .. } if is_zero(*reg) => Some(Value::Const(0)),
            Operand::Reg { reg, .. } => Some(self.get(*reg).cloned().unwrap_or(Value::Opaque)),
            Operand::Imm32 { imm, shift } | Operand::Imm64 { imm, shift } => {
                let value = immediate(imm);
                Some(Value::Const(match shift {
                    Some(Shift::LSL(amount)) => value.wrapping_shl(*amount),
                    _ => value,
                }))
            }
            Operand::Label(imm) => Some(Value::Const(immediate(imm))),
            _ => None,
        }
    }

    /// Follow `instruction`. A call changes the volatile registers, x0 to
    /// x17.
    fn step(&mut self, instruction: &Instruction) {
        let op = instruction.op();
        if is_call(op) {
            for register in &mut self.registers[..18] {
                *register = None;
            }
            return;
        }
        let operands = instruction.operands();
        if loads(instruction) {
            let Some(memory) = memory(instruction) else {
                return;
            };
            let at = self.displacement(&memory);
            for (index, register) in destinations(instruction).into_iter().enumerate() {
                let offset = at.wrapping_add((index * register.size()) as u64);
                let value = if frame(memory.base) {
                    self.stack.get(&offset).cloned()
                } else {
                    u32::try_from(offset).ok().map(Value::Field)
                };
                self.set(register, value);
            }
            return;
        }
        if matches!(op, Op::STR | Op::STUR | Op::STP)
            && let Some(memory) = memory(instruction)
            && frame(memory.base)
        {
            let sources: Vec<Reg> = operands
                .iter()
                .take(if op == Op::STP { 2 } else { 1 })
                .filter_map(|operand| match operand {
                    Operand::Reg { reg, .. } => Some(*reg),
                    _ => None,
                })
                .collect();
            for (index, register) in sources.into_iter().enumerate() {
                let offset = memory.offset.wrapping_add((index * register.size()) as u64);
                match self.get(register).cloned() {
                    Some(value) => self.stack.insert(offset, value),
                    None => self.stack.remove(&offset),
                };
            }
            return;
        }
        let Some(Operand::Reg {
            reg: destination, ..
        }) = operands.first()
        else {
            return;
        };
        let destination = *destination;
        let value = match (op, operands) {
            (Op::MOV | Op::MOVZ | Op::ADRP | Op::ADR, [_, source]) => self.operand(source),
            (Op::ADD, [_, left, right]) => {
                match (self.operand(left), self.operand(right)) {
                    (Some(Value::Const(a)), Some(Value::Const(b))) => {
                        Some(Value::Const(a.wrapping_add(b)))
                    }
                    // A register plus a known amount; the sum of two
                    // unknown values is no offset into anything.
                    (Some(left), Some(right)) if left.offsets() || right.offsets() => {
                        u32::try_from(left.displacement().wrapping_add(right.displacement()))
                            .ok()
                            .map(Value::Offset)
                    }
                    _ => None,
                }
            }
            (Op::AND, [_, left, right]) => {
                let mut fields = self.operand(left).map(|v| v.origins()).unwrap_or_default();
                fields.extend(self.operand(right).map(|v| v.origins()).unwrap_or_default());
                (!fields.is_empty()).then_some(Value::Origins(fields))
            }
            _ => None,
        };
        self.set(destination, value);
    }
}

fn is_call(op: Op) -> bool {
    matches!(
        op,
        Op::BL | Op::BLR | Op::BLRAA | Op::BLRAAZ | Op::BLRAB | Op::BLRABZ
    )
}

/// A direct branch or call's target.
fn target(instruction: &Instruction) -> Option<u64> {
    instruction
        .operands()
        .iter()
        .find_map(|operand| match operand {
            Operand::Label(imm) => Some(immediate(imm)),
            _ => None,
        })
}

/// The A64 instructions reachable from `address` through branches, calls
/// not followed, in address order: a function with its split-off chunks.
fn instructions(code: &KernelCode<'_>, address: u64) -> Vec<Instruction> {
    const MAX: usize = 8192;
    let mut seen: BTreeMap<u64, Instruction> = BTreeMap::new();
    let mut pending = vec![address];
    while let Some(start) = pending.pop() {
        let mut ip = start;
        while !seen.contains_key(&ip) && seen.len() < MAX {
            let Some(word) = code
                .image
                .code_at(ip)
                .and_then(|bytes| bytes.first_chunk::<4>())
            else {
                break;
            };
            let Ok(instruction) = bad64::decode(u32::from_le_bytes(*word), ip) else {
                break;
            };
            let op = instruction.op();
            let branch = target(&instruction);
            seen.insert(ip, instruction);
            match op {
                Op::B => {
                    pending.extend(branch);
                    break;
                }
                Op::B_EQ
                | Op::B_NE
                | Op::B_CS
                | Op::B_CC
                | Op::B_MI
                | Op::B_PL
                | Op::B_VS
                | Op::B_VC
                | Op::B_HI
                | Op::B_LS
                | Op::B_GE
                | Op::B_LT
                | Op::B_GT
                | Op::B_LE
                | Op::CBZ
                | Op::CBNZ
                | Op::TBZ
                | Op::TBNZ => pending.extend(branch),
                Op::RET
                | Op::RETAA
                | Op::RETAB
                | Op::BR
                | Op::BRAA
                | Op::BRAAZ
                | Op::BRAB
                | Op::BRABZ
                | Op::BRK
                | Op::UDF => break,
                _ => {}
            }
            ip += 4;
        }
    }
    seen.into_values().collect()
}

/// For each of `callers`, `x0` at each of its calls to one of `callees`, as
/// `read` takes it from the tracked value.
fn first_arguments(
    code: &KernelCode<'_>,
    callers: &[u64],
    callees: &[u64],
    read: impl Fn(&Value) -> Option<u32>,
) -> Vec<Vec<u32>> {
    callers
        .iter()
        .map(|&caller| {
            let mut tracker = Tracker::new();
            let mut found = Vec::new();
            for instruction in instructions(code, caller) {
                if instruction.op() == Op::BL
                    && target(&instruction).is_some_and(|t| callees.contains(&t))
                {
                    found.extend(tracker.get(Reg::X0).and_then(&read));
                }
                tracker.step(&instruction);
            }
            found
        })
        .collect()
}

fn field(value: &Value) -> Option<u32> {
    match value {
        Value::Field(field) => Some(*field),
        _ => None,
    }
}

/// The owner-process field: `x0` loaded from the store at each store
/// method's first `KeStackAttachProcess`. Two must agree.
fn owner_process(code: &KernelCode<'_>) -> Result<u32> {
    let attach: Vec<u64> = ["KeStackAttachProcess", "KiStackAttachProcess"]
        .iter()
        .filter_map(|name| code.functions.get(*name).copied())
        .collect();
    let methods = code.functions_named("SMKM_STORE<SM_TRAITS>::");
    let firsts = first_arguments(code, &methods, &attach, field);
    winner(
        firsts.iter().filter_map(|loads| loads.first().copied()),
        2,
        "owner process",
    )
}

/// The region array: the one field (0x100 or more) that
/// `SmStMapVirtualRegion` loads and then indexes, a register-offset load
/// of a pointer or the address of one (`add x2, x21, x22`).
fn region_array(code: &KernelCode<'_>) -> Result<u32> {
    let map = code.address("SMKM_STORE<SM_TRAITS>::SmStMapVirtualRegion")?;
    let mut tracker = Tracker::new();
    let mut arrays = BTreeSet::new();
    for instruction in instructions(code, map) {
        let operands = instruction.operands();
        let indexed: Vec<Reg> = match (instruction.op(), operands) {
            // `add x22, x8, w25, uxtw #3` scales the index as it adds.
            (
                Op::ADD,
                [
                    _,
                    Operand::Reg { reg: a, .. },
                    Operand::Reg { reg: b, .. } | Operand::ShiftReg { reg: b, .. },
                ],
            ) => {
                vec![*a, *b]
            }
            _ if loads(&instruction)
                && destinations(&instruction).iter().all(|r| r.size() == 8) =>
            {
                memory(&instruction)
                    .and_then(|m| m.index.map(|(index, _)| vec![m.base, index]))
                    .unwrap_or_default()
            }
            _ => Vec::new(),
        };
        arrays.extend(
            indexed
                .iter()
                .filter_map(|r| tracker.get(*r).and_then(field))
                .filter(|f| *f >= 0x100),
        );
        tracker.step(&instruction);
    }
    only(arrays, "region array")
}

/// The manager's key-to-store tree: `x0` (`add x0, xN, #K`) at the
/// manager methods' calls to the frontend tree's search. Two must agree.
fn key_tree(code: &KernelCode<'_>) -> Result<u32> {
    let methods = code.functions_named("SMKM_STORE_MGR<SM_TRAITS>::");
    let searches = code.tree_searches("SMKM_FRONTEND_ENTRY");
    let calls = first_arguments(code, &methods, &searches, |value| match value {
        Value::Offset(offset) => Some(*offset),
        _ => None,
    });
    winner(calls.into_iter().flatten(), 2, "key-to-store tree")
}

/// The pages tree: `x0` at `ST_STORE` methods' calls to its search, an
/// offset into the store, or the store itself (0).
fn pages_tree(code: &KernelCode<'_>) -> Result<u32> {
    let methods = code.functions_named("ST_STORE<SM_TRAITS>::");
    let searches = code.tree_searches("_ST_PAGE_ENTRY");
    let calls = first_arguments(code, &methods, &searches, |value| match value {
        Value::Offset(offset) => Some(*offset),
        Value::Arg0 | Value::Opaque => Some(0),
        _ => None,
    });
    winner(calls.into_iter().flatten(), 1, "pages tree")
}

fn register(operand: Option<&Operand>) -> Option<Reg> {
    match operand {
        Some(Operand::Reg { reg, .. }) => Some(*reg),
        _ => None,
    }
}

/// From `StDmpSinglePageRetrieve`, the back pointer to the store (the `x0`
/// it passes to store methods) and the flag it tests on the store through
/// it: a byte loaded through the pointer, then tested for one bit.
fn back_pointer_and_flag(code: &KernelCode<'_>) -> Result<(u32, (u32, u8))> {
    let retrieve = code.address("ST_STORE<SM_TRAITS>::StDmpSinglePageRetrieve")?;
    let store_methods = code.functions_named("SMKM_STORE<SM_TRAITS>::");
    let mut tracker = Tracker::new();
    // Byte registers by slot: the field the byte's pointer was loaded from,
    // and the byte's offset from that pointer.
    let mut bytes: HashMap<usize, (u32, u32)> = HashMap::new();
    let mut back_pointers = Vec::new();
    let mut tests = BTreeSet::new();
    for instruction in instructions(code, retrieve) {
        let operands = instruction.operands();
        let tested = register(operands.first())
            .and_then(slot)
            .and_then(|s| bytes.get(&s));
        match instruction.op() {
            Op::BL if target(&instruction).is_some_and(|t| store_methods.contains(&t)) => {
                back_pointers.extend(tracker.get(Reg::X0).and_then(field));
            }
            Op::TBZ | Op::TBNZ => {
                if let (
                    Some(&(through, at)),
                    Some(Operand::Imm32 { imm, .. } | Operand::Imm64 { imm, .. }),
                ) = (tested, operands.get(1))
                {
                    tests.insert((through, at, immediate(imm) as u8));
                }
            }
            Op::TST => {
                if let (
                    Some(&(through, at)),
                    Some(Operand::Imm32 { imm, .. } | Operand::Imm64 { imm, .. }),
                ) = (tested, operands.get(1))
                    && immediate(imm).count_ones() == 1
                {
                    tests.insert((through, at, immediate(imm).trailing_zeros() as u8));
                }
            }
            _ => {}
        }
        let byte = matches!(instruction.op(), Op::LDRB | Op::LDURB)
            .then(|| memory(&instruction))
            .flatten()
            .and_then(|m| {
                let through = tracker.get(m.base).and_then(field)?;
                Some((through, u32::try_from(tracker.displacement(&m)).ok()?))
            });
        tracker.step(&instruction);
        if is_call(instruction.op()) {
            bytes.retain(|slot, _| *slot >= 18);
        }
        for destination in destinations(&instruction) {
            if let Some(slot) = slot(destination) {
                bytes.remove(&slot);
                if let Some(byte) = byte {
                    bytes.insert(slot, byte);
                }
            }
        }
    }
    let back = winner(back_pointers, 1, "back pointer")?;
    let flags: Vec<(u32, u8)> = tests
        .into_iter()
        .filter(|(through, _, _)| *through == back)
        .map(|(_, at, bit)| (at, bit))
        .collect();
    match flags.as_slice() {
        [flag] => Ok((back, *flag)),
        other => Err(layout_error(format_args!(
            "virtual-region flag: {other:x?}"
        ))),
    }
}

/// The fields that split a region key, from `StDmpSinglePageRetrieve`: the
/// shift (`lsr w, w, w` by a field's value, not followed by the `clz` of
/// an inlined page-record lookup) and the offset mask (a field ANDed into
/// the value then shifted left by 4, to bytes).
fn region_key_fields(code: &KernelCode<'_>) -> Result<(u32, u32)> {
    let retrieve = code.address("ST_STORE<SM_TRAITS>::StDmpSinglePageRetrieve")?;
    let instructions = instructions(code, retrieve);
    let mut tracker = Tracker::new();
    let mut shifts = Vec::new();
    let mut masks = Vec::new();
    for (index, instruction) in instructions.iter().enumerate() {
        let operands = instruction.operands();
        let destination = register(operands.first());
        match (instruction.op(), operands) {
            (Op::LSR, [_, _, Operand::Reg { reg: amount, .. }]) => {
                if let Some(shift) = tracker.get(*amount).and_then(field) {
                    let chunk = instructions[index + 1..].iter().take(4).any(|next| {
                        next.op() == Op::CLZ
                            && register(next.operands().get(1)).and_then(slot)
                                == destination.and_then(slot)
                    });
                    if !chunk {
                        shifts.push(shift);
                    }
                }
            }
            (
                Op::LSL,
                [
                    _,
                    Operand::Reg { reg: source, .. },
                    Operand::Imm32 { imm, .. } | Operand::Imm64 { imm, .. },
                ],
            )
            | (
                Op::UBFIZ,
                [
                    _,
                    Operand::Reg { reg: source, .. },
                    Operand::Imm32 { imm, .. } | Operand::Imm64 { imm, .. },
                    _,
                ],
            ) if immediate(imm) == 4 => {
                if let Some(value) = tracker.get(*source) {
                    masks.extend(value.origins().into_iter().filter(|f| *f >= 0x100));
                }
            }
            _ => {}
        }
        tracker.step(instruction);
    }
    Ok((
        winner(shifts, 1, "region shift")?,
        winner(masks, 1, "region offset mask")?,
    ))
}

/// The page-record fields of `ST_PAGE_RECORD_GET`: the chunk-pointer
/// array (a pointer loaded at a constant plus a scaled index) and the four
/// 32-bit fields from 0x40 on, in offset order the shift, the per-chunk
/// mask, the record size and the header.
fn chunk_fields(code: &KernelCode<'_>) -> Result<(u32, ChunkFields)> {
    let get = code.address("ST_STORE<SM_TRAITS>::ST_PAGE_RECORD_GET")?;
    let mut tracker = Tracker::new();
    let mut arrays = BTreeSet::new();
    let mut dwords = BTreeSet::new();
    for instruction in instructions(code, get) {
        if loads(&instruction)
            && let Some(memory) = memory(&instruction)
            && !frame(memory.base)
        {
            let at = tracker.displacement(&memory);
            let destinations = destinations(&instruction);
            if memory.index.is_some() && destinations.iter().all(|r| r.size() == 8) {
                arrays.extend(u32::try_from(at).ok().filter(|a| *a != 0));
            } else if memory.index.is_none() {
                for (index, register) in destinations.iter().enumerate() {
                    if register.size() == 4
                        && let Ok(offset) = u32::try_from(at + 4 * index as u64)
                        && offset >= 0x40
                    {
                        dwords.insert(offset);
                    }
                }
            }
        }
        tracker.step(&instruction);
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

/// From `SmStoreDecompressBuffer` (24H2 on), the 32-bit field of its first
/// argument it tests first; before, the field `StDmSinglePageCopy` picks
/// the decompressor by: the `x0` of its `RtlDecompressBufferEx` call, or
/// the index into `RtlDecompressBufferProcs` where that call is inlined.
fn compression(code: &KernelCode<'_>) -> Result<Compression> {
    if let Some(&decompress) = code.functions.get("SmStoreDecompressBuffer") {
        let instructions = instructions(code, decompress);
        let mut tracker = Tracker::new();
        for (index, load) in instructions.iter().enumerate() {
            let counted = loads(load)
                .then(|| memory(load))
                .flatten()
                .filter(|m| m.index.is_none() && tracker.get(m.base) == Some(&Value::Arg0))
                .and_then(|m| {
                    let [register] = destinations(load)[..] else {
                        return None;
                    };
                    (register.size() == 4).then_some((m.offset, slot(register)?))
                });
            if let Some((offset, loaded)) = counted {
                let tested = instructions[index + 1..].iter().take(4).any(|test| {
                    matches!(test.op(), Op::CBZ | Op::CBNZ | Op::TST | Op::CMP)
                        && register(test.operands().first()).and_then(slot) == Some(loaded)
                });
                if tested && let Ok(offset) = u32::try_from(offset) {
                    return Ok(Compression::Lz4UnlessCount(offset));
                }
            }
            tracker.step(load);
        }
        return Err(layout_error(
            "no algorithm count in SmStoreDecompressBuffer",
        ));
    }
    let copy = code.address("ST_STORE<SM_TRAITS>::StDmSinglePageCopy")?;
    let decompress = code.functions.get("RtlDecompressBufferEx").copied();
    let procs = code.functions.get("RtlDecompressBufferProcs").copied();
    let mut tracker = Tracker::new();
    let mut formats = Vec::new();
    for instruction in instructions(code, copy) {
        if instruction.op() == Op::BL && decompress.is_some_and(|d| target(&instruction) == Some(d))
        {
            formats.extend(tracker.get(Reg::X0).and_then(field));
        }
        if loads(&instruction)
            && let Some(memory) = memory(&instruction)
            && let Some((index, _)) = memory.index
            && procs.is_some_and(|procs| tracker.get(memory.base) == Some(&Value::Const(procs)))
        {
            formats.extend(tracker.get(index).and_then(field));
        }
        tracker.step(&instruction);
    }
    winner(formats, 1, "decompression format").map(Compression::FormatField)
}

/// Where a redirecting page record (key `0xffffffff`) keeps the key it
/// redirects to: the dword an `ST_STORE` method loads through the record's
/// pointer on the path where the record's first dword compared equal to
/// -1 (`cmn w, #1`, or `cmp` with a register holding -1).
fn redirect_next(code: &KernelCode<'_>) -> Result<u32> {
    let mut offsets = Vec::new();
    for function in code.functions_named("ST_STORE<SM_TRAITS>::") {
        let instructions = instructions(code, function);
        let index: HashMap<u64, usize> = instructions
            .iter()
            .enumerate()
            .map(|(i, instruction)| (instruction.address(), i))
            .collect();
        let mut tracker = Tracker::new();
        // Registers holding a record's first dword, by slot: the pointer.
        let mut keys: HashMap<usize, Reg> = HashMap::new();
        for (i, compare) in instructions.iter().enumerate() {
            let operands = compare.operands();
            let compared = register(operands.first())
                .and_then(slot)
                .and_then(|s| keys.get(&s));
            let minus_one = match (compare.op(), operands.get(1)) {
                (Op::CMN, Some(Operand::Imm32 { imm, .. } | Operand::Imm64 { imm, .. })) => {
                    immediate(imm) == 1
                }
                (Op::CMP, Some(source)) => matches!(
                    tracker.operand(source),
                    Some(Value::Const(value)) if value as u32 == u32::MAX
                ),
                _ => false,
            };
            if let (Some(&record), true) = (compared, minus_one)
                && let Some(branch) = instructions.get(i + 1)
            {
                let start = match branch.op() {
                    Op::B_EQ => target(branch).and_then(|t| index.get(&t).copied()),
                    Op::B_NE => Some(i + 2),
                    _ => None,
                };
                let next = start
                    .and_then(|start| instructions.get(start..))
                    .into_iter()
                    .flatten()
                    .take(3)
                    .find_map(|load| {
                        let m = memory(load).filter(|m| m.base == record && m.index.is_none())?;
                        let [register] = destinations(load)[..] else {
                            return None;
                        };
                        (loads(load) && register.size() == 4 && m.offset != 0)
                            .then(|| u32::try_from(m.offset).ok())
                            .flatten()
                    });
                offsets.extend(next);
            }
            let first_dword = loads(compare)
                .then(|| memory(compare))
                .flatten()
                .filter(|m| m.offset == 0 && m.index.is_none() && !frame(m.base))
                .map(|m| m.base);
            tracker.step(compare);
            for destination in destinations(compare) {
                if let Some(slot) = slot(destination) {
                    keys.remove(&slot);
                    if let Some(record) = first_dword
                        && destination.size() == 4
                    {
                        keys.insert(slot, record);
                    }
                }
            }
        }
    }
    winner(offsets, 1, "redirect next key")
}

/// The store layout the ARM64 kernel `code` uses, when every anchor is
/// found and agrees.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nt::guest::hv_layout::ImageView;

    const BASE: u64 = 0x1_4000_0000;

    /// `words` as the code of `name` at BASE + 0x1000, the rest zero (`udf`).
    fn chunk_fields_of(words: &[u32]) -> Result<(u32, ChunkFields)> {
        let mut bytes = vec![0u8; 0x2000];
        for (index, word) in words.iter().enumerate() {
            bytes[0x1000 + 4 * index..][..4].copy_from_slice(&word.to_le_bytes());
        }
        let functions = HashMap::from([(
            "ST_STORE<SM_TRAITS>::ST_PAGE_RECORD_GET".to_string(),
            BASE + 0x1000,
        )]);
        chunk_fields(&KernelCode {
            image: ImageView {
                base: BASE,
                bytes: &bytes,
                code: vec![(0x1000, 0x2000)],
                data: Vec::new(),
            },
            functions: &functions,
        })
    }

    /// `ST_PAGE_RECORD_GET` as two kernels compile it: 16299 loads each
    /// field through `add x13, x15, #0xc0` (`ldr w7, [x13, #0x108]`), 26100
    /// pairs the first two through a second `add` (`ldp w5, w6, [x17]`).
    /// Both reach the chunk array through the first `add` and a scaled index.
    #[test]
    fn page_record_fields_are_found_through_added_offsets() {
        let expected = (
            0xc0,
            ChunkFields {
                shift: 0x1c8,
                mask: 0x1cc,
                record_size: 0x1d0,
                header: 0x1d8,
            },
        );
        let rs3 = [
            0xd10043ff, 0xaa0003ef, 0xb940042e, 0x910301ed, 0xb94109a7, 0x528003ea, 0xb9410da4,
            0xb94111a6, 0xb94119a5, 0x1ac725c9, 0x5ac01128, 0x4b08014b, 0x52800028, 0xb90003eb,
            0x1acb2108, 0xf86b59ab, 0xca09010a, 0xd37ced4c, 0x0a0e0088, 0xf86b6989, 0x1b067d0a,
            0x8b2a412a, 0x8b254140, 0xb9400008, 0x3100051f, 0x54000060, 0x910043ff, 0xd65f03c0,
        ];
        assert_eq!(chunk_fields_of(&rs3).unwrap(), expected);
        let ge = [
            0xaa0003e2, 0xb9400424, 0x9103004c, 0x91042191, 0x29401a25, 0x528003e7, 0xb941118f,
            0xb941198e, 0x1ac5248b, 0x5ac0116d, 0x4b0d00e9, 0x5280002d, 0x1ac921a8, 0xf8695989,
            0xca0b0108, 0xd37ced0b, 0x0a0400c8, 0x1b0f7d0a, 0xf8696968, 0x8b2a4108, 0x8b2e4100,
            0xb9400008, 0x3100051f, 0x54000241, 0xd65f03c0,
        ];
        assert_eq!(chunk_fields_of(&ge).unwrap(), expected);
    }
}
