//! Offsets of the Windows hypervisor's partition and virtual-processor
//! objects, read off its own code. `hvix64` has no public symbols, so the
//! fields are recovered from the handlers of TLFS hypercalls, found through
//! the image's hypercall table, and validated against memory before use.

use crate::error::{Error, Result};
use iced_x86::{
    Code, Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register,
};

/// Bytes of one hypercall table entry: handler, call code, then sizes.
const ENTRY_BYTES: usize = 0x18;
/// Consecutive entries whose code equals their index that make a table.
const MIN_ENTRIES: usize = 64;

pub const CALL_GET_NEXT_CHILD_PARTITION: u16 = 0x47;
pub const CALL_GET_PARTITION_ID: u16 = 0x46;
pub const CALL_ENABLE_VP_VTL: u16 = 0x0f;
pub const CALL_VTL_CALL: u16 = 0x11;
pub const CALL_VTL_RETURN: u16 = 0x12;
pub const CALL_GET_VP_REGISTERS: u16 = 0x50;
pub const CALL_SET_VP_REGISTERS: u16 = 0x51;

/// A loaded image, addressed by RVA.
pub struct ImageView<'a> {
    pub base: u64,
    pub bytes: &'a [u8],
    /// `(start, end)` RVAs of executable sections.
    pub code: Vec<(u32, u32)>,
    /// `(start, end)` RVAs of data sections that may hold the table.
    pub data: Vec<(u32, u32)>,
}

impl HypercallEntry {
    pub fn rep(&self) -> bool {
        self.flags & 1 != 0
    }

    pub fn variable_header(&self) -> bool {
        self.flags & 2 != 0
    }
}

impl ImageView<'_> {
    fn is_code(&self, va: u64) -> bool {
        va.checked_sub(self.base)
            .and_then(|rva| u32::try_from(rva).ok())
            .is_some_and(|rva| self.code.iter().any(|&(s, e)| (s..e).contains(&rva)))
    }

    fn u64_at(&self, rva: usize) -> Option<u64> {
        Some(u64::from_le_bytes(
            self.bytes.get(rva..rva + 8)?.try_into().ok()?,
        ))
    }

    fn u16_at(&self, rva: usize) -> Option<u16> {
        Some(u16::from_le_bytes(
            self.bytes.get(rva..rva + 2)?.try_into().ok()?,
        ))
    }

    /// Code starting at `va`, up to the end of its section.
    pub fn code_at(&self, va: u64) -> Option<&[u8]> {
        let rva = u32::try_from(va.checked_sub(self.base)?).ok()?;
        let &(_, end) = self.code.iter().find(|&&(s, e)| (s..e).contains(&rva))?;
        self.bytes
            .get(rva as usize..(end as usize).min(self.bytes.len()))
    }
}

/// What a register holds while a handler is followed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Value {
    /// The `n`th integer argument (rcx, rdx, r8, r9).
    Arg(u8),
    /// The processor block (the GS base).
    Gs,
    Const(u64),
    /// The value of `size` bytes at `base + offset`.
    Load(Box<Value>, i64, u8),
    /// `base + offset`.
    Add(Box<Value>, i64),
}

impl Value {
    fn plus(self, offset: i64) -> Value {
        match self {
            Value::Add(base, o) => Value::Add(base, o.wrapping_add(offset)),
            base if offset == 0 => base,
            base => Value::Add(Box::new(base), offset),
        }
    }

    /// `(base, offset)` of an address value.
    fn split(&self) -> (&Value, i64) {
        match self {
            Value::Add(base, offset) => (base, *offset),
            other => (other, 0),
        }
    }
}

fn layout_error(detail: impl std::fmt::Display) -> Error {
    Error::Hypervisor(format!("partition layout not recognized: {detail}"))
}

/// A memory access the walk resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Access {
    /// `base + index * scale + offset`, with `index` when present.
    pub base: Value,
    pub index: Option<(Value, u8)>,
    pub offset: i64,
    pub size: u8,
    pub write: Option<Value>,
}

/// Everything a walk saw.
#[derive(Debug, Default)]
pub struct Trace {
    pub accesses: Vec<Access>,
    /// `(value, immediate)` of `cmp` instructions.
    pub compares: Vec<(Value, u64)>,
    /// `(value, bit)` tested with `bt`, and `(value, mask)` ANDed or tested.
    pub bit_tests: Vec<(Value, u64)>,
    /// Direct call targets.
    pub calls: Vec<u64>,
    /// Memory values ANDed into a register (`and reg, [mem]`).
    pub and_loads: Vec<Value>,
}

const MAX_PATHS: usize = 1024;
const MAX_STEPS: usize = 16384;
const MAX_DEPTH: usize = 2;
/// Distinct register states an instruction is followed in.
const MAX_STATES: usize = 4;

type Regs = std::collections::HashMap<Register, Value>;

struct State {
    ip: u64,
    regs: Regs,
    /// Return addresses of inlined calls, with the callee-saved registers
    /// the Windows x64 ABI preserves across each.
    returns: Vec<(u64, Regs)>,
}

const NONVOLATILE: [Register; 8] = [
    Register::RBX,
    Register::RBP,
    Register::RDI,
    Register::RSI,
    Register::R12,
    Register::R13,
    Register::R14,
    Register::R15,
];

/// Follow every path from `entry` (arguments in rcx, rdx, r8, r9, or the
/// given overrides), inlining direct calls `MAX_DEPTH` deep.
pub fn walk(image: &ImageView<'_>, entry: u64, initial: &[(Register, Value)]) -> Trace {
    let mut regs: Regs = [Register::RCX, Register::RDX, Register::R8, Register::R9]
        .into_iter()
        .zip(0..)
        .map(|(r, n)| (r, Value::Arg(n)))
        .collect();
    regs.extend(initial.iter().cloned());
    let mut trace = Trace::default();
    let mut pending = vec![State {
        ip: entry,
        regs,
        returns: Vec::new(),
    }];
    let mut visited: std::collections::HashMap<(u64, usize), Vec<Regs>> = Default::default();
    let mut steps = 0;
    let mut paths = 0;
    while let Some(mut state) = pending.pop() {
        paths += 1;
        if paths > MAX_PATHS {
            break;
        }
        loop {
            steps += 1;
            if steps > MAX_STEPS {
                break;
            }
            let seen = visited.entry((state.ip, state.returns.len())).or_default();
            if seen.len() >= MAX_STATES || seen.contains(&state.regs) {
                break;
            }
            seen.push(state.regs.clone());
            let Some(code) = image.code_at(state.ip) else {
                break;
            };
            let mut decoder = Decoder::with_ip(64, code, state.ip, DecoderOptions::NONE);
            let instruction = decoder.decode();
            if instruction.code() == Code::INVALID {
                break;
            }
            let next = instruction.next_ip();
            match instruction.flow_control() {
                FlowControl::Return => match state.returns.pop() {
                    Some((back, saved)) => {
                        state.regs.retain(|r, _| !NONVOLATILE.contains(r));
                        state.regs.extend(saved);
                        state.regs.remove(&Register::RAX);
                        state.ip = back;
                    }
                    None => break,
                },
                FlowControl::Call if instruction.op0_kind() == OpKind::NearBranch64 => {
                    let target = instruction.near_branch64();
                    trace.calls.push(target);
                    state.regs.remove(&Register::RAX);
                    if state.returns.len() < MAX_DEPTH && image.code_at(target).is_some() {
                        let saved = NONVOLATILE
                            .iter()
                            .filter_map(|r| Some((*r, state.regs.get(r)?.clone())))
                            .collect();
                        state.returns.push((next, saved));
                        state.ip = target;
                    } else {
                        state.ip = next;
                    }
                }
                FlowControl::UnconditionalBranch
                    if instruction.op0_kind() == OpKind::NearBranch64 =>
                {
                    state.ip = instruction.near_branch64();
                }
                FlowControl::ConditionalBranch => {
                    pending.push(State {
                        ip: instruction.near_branch64(),
                        regs: state.regs.clone(),
                        returns: state.returns.clone(),
                    });
                    state.ip = next;
                }
                FlowControl::Next => {
                    step(&mut state.regs, &instruction, &mut trace);
                    state.ip = next;
                }
                _ => break,
            }
        }
    }
    trace
}

fn operand_value(regs: &Regs, instruction: &Instruction, n: u32) -> Option<Value> {
    match instruction.op_kind(n) {
        OpKind::Register => regs
            .get(&instruction.op_register(n).full_register())
            .cloned(),
        OpKind::Immediate8
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate64
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate32to64 => Some(Value::Const(instruction.immediate(n))),
        _ => None,
    }
}

/// The memory operand of `instruction`, resolved against `regs`.
fn memory_access(regs: &Regs, instruction: &Instruction) -> Option<Access> {
    let offset = instruction.memory_displacement64() as i64;
    let base = match (instruction.segment_prefix(), instruction.memory_base()) {
        (Register::GS, Register::None) => Value::Gs,
        (_, Register::None | Register::RIP) => return None,
        (_, base) => regs.get(&base.full_register())?.clone(),
    };
    let index = match instruction.memory_index() {
        Register::None => None,
        index => Some((
            regs.get(&index.full_register())?.clone(),
            instruction.memory_index_scale() as u8,
        )),
    };
    let (base, extra) = base.split();
    Some(Access {
        base: base.clone(),
        index,
        offset: offset.wrapping_add(extra),
        size: instruction.memory_size().size() as u8,
        write: None,
    })
}

fn loaded(access: &Access) -> Option<Value> {
    access
        .index
        .is_none()
        .then(|| Value::Load(Box::new(access.base.clone()), access.offset, access.size))
}

fn step(regs: &mut Regs, instruction: &Instruction, trace: &mut Trace) {
    let dest = (instruction.op0_kind() == OpKind::Register)
        .then(|| instruction.op0_register().full_register());
    let memory = (0..instruction.op_count())
        .any(|n| instruction.op_kind(n) == OpKind::Memory)
        .then(|| memory_access(regs, instruction))
        .flatten();
    let mnemonic = instruction.mnemonic();
    if let Some(access) = &memory
        && mnemonic != Mnemonic::Lea
    {
        let mut access = access.clone();
        if instruction.op0_kind() == OpKind::Memory && mnemonic == Mnemonic::Mov {
            access.write = Some(operand_value(regs, instruction, 1).unwrap_or(Value::Const(0)));
        }
        trace.accesses.push(access);
    }
    let source = |regs: &Regs| match instruction.op_kind(1) {
        OpKind::Memory => memory.as_ref().and_then(loaded),
        _ => operand_value(regs, instruction, 1),
    };
    match mnemonic {
        Mnemonic::Cmp => {
            if let (Some(left), Some(Value::Const(right))) = (
                match instruction.op0_kind() {
                    OpKind::Memory => memory.as_ref().and_then(loaded),
                    _ => operand_value(regs, instruction, 0),
                },
                operand_value(regs, instruction, 1),
            ) {
                trace.compares.push((left, right));
            }
            return;
        }
        Mnemonic::Bt if instruction.op1_kind() != OpKind::Register => {
            let value = match instruction.op0_kind() {
                OpKind::Memory => memory.as_ref().and_then(loaded),
                _ => operand_value(regs, instruction, 0),
            };
            if let Some(value) = value {
                trace
                    .bit_tests
                    .push((value, 1u64 << (instruction.immediate(1) & 63)));
            }
            return;
        }
        Mnemonic::And if instruction.op1_kind() == OpKind::Memory => {
            if let Some(value) = memory.as_ref().and_then(loaded) {
                trace.and_loads.push(value);
            }
        }
        Mnemonic::Test | Mnemonic::And => {
            let left =
                operand_value(regs, instruction, 0).or_else(|| memory.as_ref().and_then(loaded));
            if let (Some(a), Some(b)) = (left, source(regs)) {
                match (a, b) {
                    (Value::Const(mask), v) | (v, Value::Const(mask)) => {
                        trace.bit_tests.push((v, mask))
                    }
                    _ => {}
                }
            }
            if mnemonic == Mnemonic::Test {
                return;
            }
        }
        _ => {}
    }
    let Some(dest) = dest else { return };
    let value = match mnemonic {
        Mnemonic::Mov | Mnemonic::Movzx => source(regs),
        Mnemonic::Lea => memory
            .map(|a| match a.index {
                None => a.base.plus(a.offset),
                Some(_) => Value::Const(0),
            })
            .filter(|v| *v != Value::Const(0)),
        Mnemonic::Add | Mnemonic::Sub => match (regs.get(&dest).cloned(), source(regs)) {
            (Some(v), Some(Value::Const(c))) if !matches!(v, Value::Const(_)) => {
                Some(v.plus(if mnemonic == Mnemonic::Sub {
                    (c as i64).wrapping_neg()
                } else {
                    c as i64
                }))
            }
            _ => None,
        },
        Mnemonic::Xor
            if instruction.op1_kind() == OpKind::Register
                && instruction.op1_register().full_register() == dest =>
        {
            Some(Value::Const(0))
        }
        _ => None,
    };
    match value {
        Some(value) => regs.insert(dest, value),
        None => regs.remove(&dest),
    };
}

/// One entry of the hypercall table, as the hypervisor dispatches a call
/// code: its handler, its flags, and the sizes of its fixed input and
/// output and of each rep element.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HypercallEntry {
    pub handler: u64,
    /// Bit 0: a rep call. Bit 1: the input has a variable-size header (the
    /// TLFS `...Ex` calls). Bit 2 is set on HvCallVtlCall and
    /// HvCallVtlReturn.
    pub flags: u16,
    pub input: u16,
    pub input_element: u16,
    pub output: u16,
    pub output_element: u16,
}

/// The hypercall table, indexed by call code.
pub fn hypercall_table(image: &ImageView<'_>) -> Result<Vec<HypercallEntry>> {
    for &(start, end) in &image.data {
        let end = (end as usize).min(image.bytes.len());
        let mut rva = start as usize;
        while rva + ENTRY_BYTES * MIN_ENTRIES <= end {
            let mut entries = Vec::new();
            let mut at = rva;
            while let (Some(handler), Some(code)) = (image.u64_at(at), image.u16_at(at + 8)) {
                if usize::from(code) != entries.len() || !image.is_code(handler) {
                    break;
                }
                let field = |offset| image.u16_at(at + offset).unwrap_or(0);
                entries.push(HypercallEntry {
                    handler,
                    flags: field(0xa),
                    input: field(0xc),
                    input_element: field(0xe),
                    output: field(0x10),
                    output_element: field(0x12),
                });
                at += ENTRY_BYTES;
            }
            if entries.len() >= MIN_ENTRIES {
                return Ok(entries);
            }
            rva += 8;
        }
    }
    Err(layout_error("no hypercall table"))
}

/// Field offsets of the hypervisor's partition and VP objects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionLayout {
    /// Values reaching the current partition from the processor block.
    pub current_partition: Vec<Value>,
    /// Values reaching the VP the processor block runs, or last ran.
    pub current_vp: Vec<Value>,
    /// Where the processor block keeps its processor number (a dword).
    pub processor_index: Option<i64>,
    pub id: i64,
    pub parent: i64,
    pub children: i64,
    pub sibling: i64,
    pub privileges: i64,
    pub vps: i64,
    pub max_vps: u32,
    pub vp_current_vtl: i64,
    pub vp_vtls: i64,
    /// The VP's mask of enabled VTLs (a dword). Its VTL array also holds
    /// contexts of VTLs that are allocated but not enabled.
    pub vp_enabled_vtls: i64,
    pub vtl_level: i64,
    /// Where a VTL context may keep its VMCS's physical address, as
    /// `(object, address)`: the qword at `context + object` points to the
    /// VMCS object, whose qword at `address` is the VMCS page. The code gives
    /// candidates; memory picks the one that lands on eVMCS pages.
    pub vmcs: Vec<(i64, i64)>,
}

fn handler(table: &[HypercallEntry], code: u16) -> Result<u64> {
    table
        .get(usize::from(code))
        .map(|entry| entry.handler)
        .ok_or_else(|| layout_error(format!("no handler for hypercall {code:#x}")))
}

fn load_of(value: &Value) -> Option<(&Value, i64)> {
    match value {
        Value::Load(base, offset, 8) => Some((base, *offset)),
        _ => None,
    }
}

/// `(parent, sibling, children, id)` from the child walker that
/// `HvCallGetNextChildPartition(parent, previous)` calls: the end test
/// compares `previous.sibling.Flink` with `&previous.parent.children`, and
/// the next child's ID is loaded at a negative offset from its link.
fn child_list(image: &ImageView<'_>, table: &[HypercallEntry]) -> Result<(i64, i64, i64, i64)> {
    let entry = handler(table, CALL_GET_NEXT_CHILD_PARTITION)?;
    for callee in walk(image, entry, &[]).calls {
        let trace = walk(image, callee, &[]);
        let mut parent = None;
        let mut sibling = None;
        for access in &trace.accesses {
            if access.base == Value::Arg(1) && access.size == 8 && access.index.is_none() {
                match parent {
                    None => parent = Some(access.offset),
                    Some(_) if sibling.is_none() => sibling = Some(access.offset),
                    _ => {}
                }
            }
        }
        let (Some(parent), Some(sibling)) = (parent, sibling) else {
            continue;
        };
        let head = trace
            .accesses
            .iter()
            .find_map(|a| match (&a.base, a.index.is_none()) {
                (Value::Arg(0), true) if a.offset > sibling && a.size == 8 => Some(a.offset),
                _ => None,
            });
        let id = trace.accesses.iter().find_map(|a| match &a.base {
            Value::Load(base, offset, 8)
                if **base == Value::Arg(1) && *offset == sibling && a.offset < 0 =>
            {
                Some(sibling + a.offset)
            }
            Value::Load(base, offset, 8)
                if a.offset < 0 && load_of(base).is_none() && *offset >= 0 =>
            {
                head.map(|_| sibling + a.offset)
            }
            _ => None,
        });
        if let (Some(head), Some(id)) = (head, id) {
            return Ok((parent, sibling, head, id));
        }
    }
    Err(layout_error("child partition walker"))
}

fn gs_rooted(value: &Value) -> bool {
    match value {
        Value::Gs => true,
        Value::Load(base, _, _) | Value::Add(base, _) => gs_rooted(base),
        Value::Arg(_) | Value::Const(_) => false,
    }
}

/// `(current partition values, id, privileges)` from
/// `HvCallGetPartitionId`: it stores the current partition's ID to its
/// output after testing the AccessPartitionId privilege (bit 33).
fn partition_id(image: &ImageView<'_>, table: &[HypercallEntry]) -> Result<(Vec<Value>, i64, i64)> {
    let trace = walk(image, handler(table, CALL_GET_PARTITION_ID)?, &[]);
    let mut current = Vec::new();
    let mut id = None;
    for access in &trace.accesses {
        if let Some((base, offset)) = access.write.as_ref().and_then(load_of)
            && gs_rooted(base)
            && id.is_none_or(|id| id == offset)
        {
            id = Some(offset);
            if !current.contains(base) {
                current.push(base.clone());
            }
        }
    }
    let id = id.ok_or_else(|| layout_error("HvCallGetPartitionId stores no partition field"))?;
    let privileges = trace
        .bit_tests
        .iter()
        .find_map(|(value, mask)| match value {
            Value::Load(base, offset, 8) if mask & (1 << 33) != 0 && gs_rooted(base) => {
                Some(*offset)
            }
            _ => None,
        })
        .ok_or_else(|| layout_error("HvCallGetPartitionId tests no privilege mask"))?;
    Ok((current, id, privileges))
}

/// The VP capacities a lookup can bound its index with. Every build seen
/// holds 0x140, 0x400, or 0x800; smaller arrays indexed the same way
/// (per-VTL state) are not VPs.
const MIN_VPS: u64 = 0x100;
const MAX_VPS: u64 = 0x10000;

/// `(array, capacity)` from the VP lookup `(partition, index)`: it bounds
/// the index with an immediate and loads `partition->vps[index]`.
/// The traces of the functions the VP hypercalls call, and of those they
/// call: where the VP lookup is. Each is walked once, in parallel.
fn vp_lookup_traces(image: &ImageView<'_>, table: &[HypercallEntry]) -> Result<Vec<Trace>> {
    use rayon::prelude::*;
    let mut first = Vec::new();
    for code in [
        CALL_GET_VP_REGISTERS,
        CALL_SET_VP_REGISTERS,
        CALL_ENABLE_VP_VTL,
    ] {
        first.extend(walk(image, handler(table, code)?, &[]).calls);
    }
    first.sort_unstable();
    first.dedup();
    let walk_all = |entries: &[u64]| -> Vec<Trace> {
        entries
            .par_iter()
            .map(|&entry| walk(image, entry, &[]))
            .collect()
    };
    let mut traces = walk_all(&first);
    let mut second: Vec<u64> = traces
        .iter()
        .flat_map(|trace| trace.calls.iter().copied())
        .filter(|call| first.binary_search(call).is_err())
        .collect();
    second.sort_unstable();
    second.dedup();
    traces.extend(walk_all(&second));
    Ok(traces)
}

fn vp_array(traces: &[Trace]) -> Result<(i64, u32)> {
    let mut found: Option<(i64, u32)> = None;
    for (candidate, trace) in traces.iter().enumerate() {
        // The index may be the argument or, on paths that resolve a
        // "self" index first, a field; either way the same value is bounded
        // and then scales into the partition's array.
        let found_here = trace.accesses.iter().find_map(|a| match &a.index {
            Some((index, 8)) if a.base == Value::Arg(0) && a.size == 8 => trace
                .compares
                .iter()
                .find(|(value, imm)| value == index && (MIN_VPS..=MAX_VPS).contains(imm))
                .map(|(_, imm)| (a.offset, *imm as u32)),
            _ => None,
        });
        let (bound, array) = match found_here {
            Some((array, bound)) => (Some(bound), Some(array)),
            None => (None, None),
        };
        if let (Some(bound), Some(array)) = (bound, array) {
            match found {
                None => found = Some((array, bound)),
                Some((other, capacity)) if other == array => {
                    found = Some((array, capacity.max(bound)))
                }
                Some(other) => {
                    return Err(layout_error(format!(
                        "VP lookups disagree: {other:x?} and {:x?} in candidate {candidate}",
                        (array, bound)
                    )));
                }
            }
        }
    }
    found.ok_or_else(|| layout_error("no VP lookup"))
}

/// `(current VTL, VTL array, level)` from `HvCallVtlReturn(vp)`: it reads
/// the current VTL's level and indexes the VP's VTL array with it.
fn vtl_fields(image: &ImageView<'_>, table: &[HypercallEntry]) -> Result<(i64, i64, i64)> {
    let trace = walk(image, handler(table, CALL_VTL_RETURN)?, &[]);
    trace
        .accesses
        .iter()
        .find_map(|a| match &a.index {
            Some((Value::Load(ctx, level, 1), 8)) if a.base == Value::Arg(0) && a.size == 8 => {
                match load_of(ctx) {
                    Some((Value::Arg(0), current)) => Some((current, a.offset, *level)),
                    _ => None,
                }
            }
            _ => None,
        })
        .ok_or_else(|| layout_error("HvCallVtlReturn indexes no VTL array"))
}

/// The VP's enabled-VTL mask from `HvCallVtlCall(vp)`: it ANDs the VTLs
/// above the current one with the mask to pick the VTL to call.
fn enabled_vtls(image: &ImageView<'_>, table: &[HypercallEntry]) -> Result<i64> {
    walk(image, handler(table, CALL_VTL_CALL)?, &[])
        .and_loads
        .iter()
        .find_map(|value| match value {
            Value::Load(base, offset, 4) if **base == Value::Arg(0) => Some(*offset),
            _ => None,
        })
        .ok_or_else(|| layout_error("HvCallVtlCall reads no enabled-VTL mask"))
}

/// The values reaching the processor block's current VP: those whose
/// current VTL's level the VP hypercalls read, `[[vp + current] + level]`.
fn current_vp(
    image: &ImageView<'_>,
    table: &[HypercallEntry],
    current: i64,
    level: i64,
) -> Vec<Value> {
    let mut found = Vec::new();
    for code in [CALL_GET_VP_REGISTERS, CALL_SET_VP_REGISTERS] {
        let Ok(entry) = handler(table, code) else {
            continue;
        };
        for access in walk(image, entry, &[]).accesses {
            if access.offset == level
                && access.size == 1
                && let Some((vp, offset)) = load_of(&access.base)
                && offset == current
                && gs_rooted(vp)
                && !found.contains(vp)
            {
                found.push(vp.clone());
            }
        }
    }
    found
}

/// Where the processor block keeps its processor number: the dword from the
/// block that the VP hypercalls scale by 8 to index per-processor arrays.
/// Builds whose VP paths use no such array give none.
fn processor_index(traces: &[Trace]) -> Option<i64> {
    let mut found = Vec::new();
    for trace in traces {
        for access in &trace.accesses {
            if let Some((Value::Load(base, offset, 4), 8)) = &access.index
                && **base == Value::Gs
                && !found.contains(offset)
            {
                found.push(*offset);
            }
        }
    }
    // One number per processor: two candidates would be a guess.
    match found.as_slice() {
        [offset] => Some(*offset),
        _ => None,
    }
}

/// Instructions looked back over from a `vmptrld`.
const VMCS_WINDOW: usize = 16;

/// The last instruction in `window` that writes `register` (conditional
/// moves, which only null the pointer, are passed over).
fn last_write(window: &[Instruction], register: Register) -> Option<usize> {
    window.iter().rposition(|instruction| {
        !matches!(instruction.mnemonic(), Mnemonic::Cmove | Mnemonic::Cmovne)
            && instruction.op_count() > 0
            && instruction.op0_kind() == OpKind::Register
            && instruction.op0_register().full_register() == register
    })
}

/// Copies of a register followed back from a `vmptrld`: the compiler may
/// move the VMCS object between registers before loading from it.
const MAX_COPIES: usize = 3;

/// The instruction in `window` that last wrote `register`, followed back
/// through register-to-register copies.
fn object_load(window: &[Instruction], mut register: Register) -> Option<usize> {
    let mut end = window.len();
    for _ in 0..=MAX_COPIES {
        let write = last_write(&window[..end], register)?;
        let instruction = &window[write];
        if instruction.mnemonic() == Mnemonic::Mov
            && instruction.op1_kind() == OpKind::Register
            && instruction.op1_register().is_gpr64()
        {
            register = instruction.op1_register().full_register();
            end = write;
            continue;
        }
        return Some(write);
    }
    None
}

/// `[base + displacement]` with no index, segment, or stack base.
fn plain_memory(instruction: &Instruction) -> Option<(Register, i64)> {
    let base = instruction.memory_base();
    let displacement = instruction.memory_displacement64() as i64;
    (instruction.memory_index() == Register::None
        && !matches!(
            base,
            Register::None | Register::RIP | Register::RSP | Register::RBP
        )
        && displacement >= 0)
        .then_some((base.full_register(), displacement))
}

/// `(object, address)` candidates from every `vmptrld [r + address]`: the
/// VMCS object `r` was loaded from `[base + object]`, with `base` itself an
/// earlier `lea base, [context + offset]` when there is one.
fn vmcs_candidates(image: &ImageView<'_>) -> Vec<(i64, i64)> {
    let mut found = Vec::new();
    for &(start, end) in &image.code {
        let end = (end as usize).min(image.bytes.len());
        let Some(code) = image.bytes.get(start as usize..end) else {
            continue;
        };
        let mut decoder = Decoder::with_ip(
            64,
            code,
            image.base + u64::from(start),
            DecoderOptions::NONE,
        );
        let mut window: Vec<Instruction> = Vec::with_capacity(VMCS_WINDOW + 1);
        for instruction in &mut decoder {
            if instruction.mnemonic() == Mnemonic::Vmptrld
                && let Some((object, address)) = plain_memory(&instruction)
                && let Some(load) = object_load(&window, object)
                && window[load].mnemonic() == Mnemonic::Mov
                && window[load].op1_kind() == OpKind::Memory
                && let Some((base, mut offset)) = plain_memory(&window[load])
            {
                if let Some(lea) = last_write(&window[..load], base)
                    && window[lea].mnemonic() == Mnemonic::Lea
                    && let Some((_, add)) = plain_memory(&window[lea])
                {
                    offset += add;
                }
                if !found.contains(&(offset, address)) {
                    found.push((offset, address));
                }
            }
            if window.len() == VMCS_WINDOW {
                window.remove(0);
            }
            window.push(instruction);
        }
    }
    found
}

/// Read every field off `image`'s code. Offsets two derivations both see
/// must agree.
pub fn derive(image: &ImageView<'_>) -> Result<PartitionLayout> {
    let table = hypercall_table(image)?;
    let (parent, sibling, children, id) = child_list(image, &table)?;
    let (current_partition, stored_id, privileges) = partition_id(image, &table)?;
    if stored_id != id {
        return Err(layout_error(format!(
            "partition ID at {id:#x} by the child walker, {stored_id:#x} by HvCallGetPartitionId"
        )));
    }
    let traces = vp_lookup_traces(image, &table)?;
    let (vps, max_vps) = vp_array(&traces)?;
    let (vp_current_vtl, vp_vtls, vtl_level) = vtl_fields(image, &table)?;
    let vp_enabled_vtls = enabled_vtls(image, &table)?;
    let current_vp = current_vp(image, &table, vp_current_vtl, vtl_level);
    let processor_index = processor_index(&traces);
    let vmcs = vmcs_candidates(image);
    Ok(PartitionLayout {
        current_partition,
        current_vp,
        processor_index,
        id,
        parent,
        children,
        sibling,
        privileges,
        vps,
        max_vps,
        vp_current_vtl,
        vp_vtls,
        vp_enabled_vtls,
        vtl_level,
        vmcs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::code_asm::CodeAssembler;

    const BASE: u64 = 0x1_4000_0000;
    const TEXT: u32 = 0x1000;
    const TABLE: u32 = 0x8000;
    const CALLS: usize = 0x60;

    /// A synthetic image: each function assembled at its own slot of
    /// `.text`, and a hypercall table whose unlisted entries are a `ret`.
    struct Builder {
        bytes: Vec<u8>,
        next: u32,
        handlers: Vec<u64>,
    }

    impl Builder {
        fn new() -> Self {
            let mut builder = Self {
                bytes: vec![0xcc; 0xa000],
                next: TEXT,
                handlers: Vec::new(),
            };
            let stub = builder.function(|a| a.ret().unwrap());
            builder.handlers = vec![stub; CALLS];
            builder
        }

        /// Assemble `body` at the next slot and return its address.
        fn function(&mut self, body: impl FnOnce(&mut CodeAssembler)) -> u64 {
            let address = BASE + u64::from(self.next);
            let mut a = CodeAssembler::new(64).unwrap();
            body(&mut a);
            let code = a.assemble(address).unwrap();
            let start = self.next as usize;
            self.bytes[start..start + code.len()].copy_from_slice(&code);
            self.next += 0x100;
            address
        }

        fn handler(&mut self, code: u16, body: impl FnOnce(&mut CodeAssembler)) {
            self.handlers[usize::from(code)] = self.function(body);
        }

        fn image(&mut self) -> ImageView<'_> {
            for (code, handler) in self.handlers.iter().enumerate() {
                let entry = TABLE as usize + code * ENTRY_BYTES;
                self.bytes[entry..entry + 8].copy_from_slice(&handler.to_le_bytes());
                self.bytes[entry + 8..entry + 10].copy_from_slice(&(code as u16).to_le_bytes());
            }
            ImageView {
                base: BASE,
                bytes: &self.bytes,
                code: vec![(TEXT, TABLE)],
                data: vec![(TABLE, 0xa000)],
            }
        }
    }

    /// `HvCallGetNextChildPartition(parent, previous, out)` and its walker,
    /// as every build has them, with the list at `sibling` (head just
    /// after it) and the ID at `id`.
    fn child_walker(builder: &mut Builder, parent: i32, sibling: i32, id: i32) {
        use iced_x86::code_asm::*;
        let head = sibling + 0x10;
        let walker = builder.function(|a| {
            let mut first = a.create_label();
            let mut compare = a.create_label();
            let mut end = a.create_label();
            a.test(rdx, rdx).unwrap();
            a.je(first).unwrap();
            a.mov(rax, qword_ptr(rdx + parent)).unwrap();
            a.mov(rcx, qword_ptr(rdx + sibling)).unwrap();
            a.add(rax, head).unwrap();
            a.jmp(compare).unwrap();
            a.set_label(&mut first).unwrap();
            a.lea(rax, qword_ptr(rcx + head)).unwrap();
            a.mov(rcx, qword_ptr(rax)).unwrap();
            a.set_label(&mut compare).unwrap();
            a.cmp(rcx, rax).unwrap();
            a.je(end).unwrap();
            a.mov(rax, qword_ptr(rcx - (sibling - id))).unwrap();
            a.mov(qword_ptr(r8), rax).unwrap();
            a.set_label(&mut end).unwrap();
            a.ret().unwrap();
        });
        builder.handler(CALL_GET_NEXT_CHILD_PARTITION, |a| {
            a.call(walker).unwrap();
            a.ret().unwrap();
        });
    }

    /// `HvCallGetPartitionId(input, out)` as 10.0.26100 has it: the current
    /// partition straight from the processor block.
    fn partition_id_direct(builder: &mut Builder, id: i32) {
        use iced_x86::code_asm::*;
        builder.handler(CALL_GET_PARTITION_ID, |a| {
            let mut allowed = a.create_label();
            a.mov(rax, qword_ptr(0x360u64).gs()).unwrap();
            a.mov(r8, rdx).unwrap();
            a.bt(qword_ptr(rax + 0x1b0), 0x21).unwrap();
            a.jb(allowed).unwrap();
            a.mov(eax, 6).unwrap();
            a.ret().unwrap();
            a.set_label(&mut allowed).unwrap();
            a.mov(rcx, qword_ptr(0x360u64).gs()).unwrap();
            a.mov(rdx, qword_ptr(rcx + id)).unwrap();
            a.mov(qword_ptr(r8), rdx).unwrap();
            a.ret().unwrap();
        });
    }

    /// `HvCallGetPartitionId` as 10.0.28000 has it: a privilege helper, then
    /// the current VP's partition, whose VP is at `[gs:0]+0x358` or
    /// `[[gs:38h]]` depending on a flag in the processor block.
    fn partition_id_through_vp(builder: &mut Builder, id: i32) {
        use iced_x86::code_asm::*;
        let check = builder.function(|a| {
            a.mov(rax, qword_ptr(0u64).gs()).unwrap();
            a.mov(rdx, qword_ptr(rax + 0x358)).unwrap();
            a.mov(rdx, qword_ptr(rdx + 0x408)).unwrap();
            a.mov(rdx, qword_ptr(rdx + 0x1f0)).unwrap();
            a.and(rdx, rcx).unwrap();
            a.ret().unwrap();
        });
        builder.handler(CALL_GET_PARTITION_ID, |a| {
            let mut vp = a.create_label();
            let mut partition = a.create_label();
            a.mov(r10, rdx).unwrap();
            a.mov(rcx, 0x2_0000_0000u64).unwrap();
            a.call(check).unwrap();
            a.mov(rcx, qword_ptr(0u64).gs()).unwrap();
            a.cmp(byte_ptr(rcx + 0xf), 0).unwrap();
            a.jne(vp).unwrap();
            a.mov(rcx, qword_ptr(0x38u64).gs()).unwrap();
            a.mov(rcx, qword_ptr(rcx)).unwrap();
            a.jmp(partition).unwrap();
            a.set_label(&mut vp).unwrap();
            a.mov(rcx, qword_ptr(rcx + 0x358)).unwrap();
            a.set_label(&mut partition).unwrap();
            a.mov(rax, qword_ptr(rcx + 0x408)).unwrap();
            a.mov(rax, qword_ptr(rax + id)).unwrap();
            a.mov(qword_ptr(r10), rax).unwrap();
            a.ret().unwrap();
        });
    }

    /// A VP lookup `(partition, index, _, out)` bounding the index with
    /// `capacity` and loading from the array at `array`, called by `code`.
    fn vp_lookup(builder: &mut Builder, code: u16, array: i32, capacity: u32) {
        use iced_x86::code_asm::*;
        let lookup = builder.function(|a| {
            let mut out = a.create_label();
            a.cmp(edx, capacity).unwrap();
            a.jae(out).unwrap();
            // A per-processor count, indexed by the processor number.
            a.mov(eax, dword_ptr(8u64).gs()).unwrap();
            a.mov(r10, qword_ptr(rcx + 0x6a80)).unwrap();
            a.mov(r11d, dword_ptr(r10 + rax * 8)).unwrap();
            a.mov(eax, edx).unwrap();
            a.mov(rax, qword_ptr(rcx + rax * 8 + array)).unwrap();
            a.mov(qword_ptr(r9), rax).unwrap();
            a.set_label(&mut out).unwrap();
            a.ret().unwrap();
        });
        builder.handler(code, |a| {
            a.call(lookup).unwrap();
            a.ret().unwrap();
        });
    }

    /// `HvCallVtlReturn(vp)` and `HvCallVtlCall(vp)` as 10.0.26100 has them.
    fn vtl_calls(builder: &mut Builder) {
        use iced_x86::code_asm::*;
        builder.handler(CALL_VTL_RETURN, |a| {
            a.mov(rsi, qword_ptr(rcx + 0x3c0)).unwrap();
            a.movzx(r15d, byte_ptr(rsi + 0x14)).unwrap();
            a.mov(rdx, qword_ptr(rcx + r15 * 8 + 0x148)).unwrap();
            a.ret().unwrap();
        });
        builder.handler(CALL_VTL_CALL, |a| {
            a.mov(rdi, rcx).unwrap();
            a.mov(rax, qword_ptr(rdi + 0x3c0)).unwrap();
            a.mov(cl, byte_ptr(rax + 0x14)).unwrap();
            a.mov(eax, 1).unwrap();
            a.shl(eax, cl).unwrap();
            a.lea(r9d, dword_ptr(rax - 1)).unwrap();
            a.or(r9d, eax).unwrap();
            a.not(r9d).unwrap();
            a.and(r9d, dword_ptr(rdi + 0x1b0)).unwrap();
            a.bsf(esi, r9d).unwrap();
            a.ret().unwrap();
        });
    }

    /// A VMCS load as 10.0.28000 has it: the VP's current VTL context, a
    /// `lea` into it (nulled when there is no context), the VMCS object
    /// loaded there, then `vmptrld` of the object's physical address.
    fn vmcs_load(builder: &mut Builder) {
        use iced_x86::code_asm::*;
        builder.function(|a| {
            a.mov(rax, qword_ptr(rdi + 0x3c0)).unwrap();
            a.xor(r12d, r12d).unwrap();
            a.test(rax, rax).unwrap();
            a.lea(rdx, qword_ptr(rax + 0x1380)).unwrap();
            a.cmove(rdx, r12).unwrap();
            a.mov(rcx, qword_ptr(rdx + 0x28)).unwrap();
            a.mov(r8, qword_ptr(rcx + 0x188)).unwrap();
            a.vmptrld(qword_ptr(rcx + 0x190)).unwrap();
            a.ret().unwrap();
        });
    }

    /// `HvCallSetVpRegisters` reading the calling VP's current VTL level, as
    /// the VP hypercalls do when no VTL is named.
    fn current_vtl_level(builder: &mut Builder) {
        use iced_x86::code_asm::*;
        builder.handler(CALL_SET_VP_REGISTERS, |a| {
            a.mov(rax, qword_ptr(0x358u64).gs()).unwrap();
            a.mov(rcx, qword_ptr(rax + 0x3c0)).unwrap();
            a.mov(al, byte_ptr(rcx + 0x14)).unwrap();
            a.ret().unwrap();
        });
    }

    /// Every handler, 10.0.26100's way.
    fn build_26100() -> Builder {
        let mut builder = Builder::new();
        child_walker(&mut builder, 0x4540, 0x4710, 0x4550);
        partition_id_direct(&mut builder, 0x4550);
        vp_lookup(&mut builder, CALL_GET_VP_REGISTERS, 0x1e0, 0x800);
        vtl_calls(&mut builder);
        vmcs_load(&mut builder);
        current_vtl_level(&mut builder);
        builder
    }

    #[test]
    fn derives_every_field_from_the_handlers() {
        let mut builder = build_26100();
        let layout = derive(&builder.image()).unwrap();
        assert_eq!(
            layout,
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
                max_vps: 0x800,
                vp_current_vtl: 0x3c0,
                vp_vtls: 0x148,
                vp_enabled_vtls: 0x1b0,
                vtl_level: 0x14,
                vmcs: vec![(0x13a8, 0x190)],
            }
        );
    }

    #[test]
    fn a_current_partition_reached_two_ways_keeps_both() {
        let mut builder = build_26100();
        partition_id_through_vp(&mut builder, 0x4550);
        let layout = derive(&builder.image()).unwrap();
        let gs = |offset| Value::Load(Box::new(Value::Gs), offset, 8);
        let load = |base, offset| Value::Load(Box::new(base), offset, 8);
        assert_eq!(layout.current_partition.len(), 2);
        assert!(
            layout
                .current_partition
                .contains(&load(load(gs(0), 0x358), 0x408))
        );
        assert!(
            layout
                .current_partition
                .contains(&load(load(gs(0x38), 0), 0x408))
        );
        assert_eq!(layout.privileges, 0x1f0);
    }

    #[test]
    fn a_vmcs_object_moved_between_registers_is_still_found() {
        use iced_x86::code_asm::*;
        let mut builder = build_26100();
        builder.function(|a| {
            a.mov(rdx, qword_ptr(rax + 0x13e8)).unwrap();
            a.mov(r8, rdx).unwrap();
            a.mov(rcx, r8).unwrap();
            a.vmptrld(qword_ptr(rcx + 0x188)).unwrap();
            a.ret().unwrap();
        });
        let vmcs = derive(&builder.image()).unwrap().vmcs;
        assert!(vmcs.contains(&(0x13e8, 0x188)), "{vmcs:x?}");
    }

    #[test]
    fn partition_ids_that_disagree_refuse_the_layout() {
        let mut builder = build_26100();
        partition_id_direct(&mut builder, 0x4558);
        assert!(derive(&builder.image()).is_err());
    }

    #[test]
    fn vp_lookups_that_disagree_refuse_the_layout() {
        let mut builder = build_26100();
        vp_lookup(&mut builder, CALL_SET_VP_REGISTERS, 0x220, 0x800);
        assert!(derive(&builder.image()).is_err());
    }

    #[test]
    fn a_small_array_indexed_the_same_way_is_not_the_vps() {
        let mut builder = build_26100();
        vp_lookup(&mut builder, CALL_ENABLE_VP_VTL, 0x508, 0x96);
        assert_eq!(derive(&builder.image()).unwrap().vps, 0x1e0);
    }

    #[test]
    fn an_image_without_a_hypercall_table_has_no_layout() {
        let mut builder = build_26100();
        let mut image = builder.image();
        image.data.clear();
        assert!(derive(&image).is_err());
    }

    /// The layout of real `hvix64` builds (not redistributable), named one
    /// path per line by `NTOSEYE_HVIX64_IMAGES`, as `tools/fetch_hvix64.py`
    /// downloads them. `cargo test --lib hv_layout -- --ignored --nocapture`.
    #[test]
    #[ignore = "needs hvix64 images named by NTOSEYE_HVIX64_IMAGES"]
    fn derives_the_layout_of_real_builds() {
        use pelite::pe64::{Pe, PeFile};
        let images = std::env::var("NTOSEYE_HVIX64_IMAGES").expect("NTOSEYE_HVIX64_IMAGES");
        let mut failures = Vec::new();
        for path in images.lines().map(str::trim).filter(|p| !p.is_empty()) {
            let data = std::fs::read(path).unwrap();
            let pe = PeFile::from_bytes(&data).unwrap();
            let size = pe.optional_header().SizeOfImage as usize;
            let mut bytes = vec![0u8; size];
            let (mut code, mut sections) = (Vec::new(), Vec::new());
            for section in pe.section_headers() {
                let start = section.VirtualAddress;
                let raw = pe.get_section_bytes(section).unwrap_or(&[]);
                let len = raw.len().min(size.saturating_sub(start as usize));
                bytes[start as usize..start as usize + len].copy_from_slice(&raw[..len]);
                let end = start + section.VirtualSize.max(len as u32);
                if section.Characteristics & 0x2000_0000 != 0 {
                    code.push((start, end));
                } else {
                    sections.push((start, end));
                }
            }
            let view = ImageView {
                base: pe.optional_header().ImageBase,
                bytes: &bytes,
                code,
                data: sections,
            };
            match derive(&view) {
                Ok(layout) => println!("{path}: {layout:x?}"),
                Err(error) => failures.push(format!("{path}: {error}")),
            }
            // Every call the TLFS documents that this build implements (its
            // own handler, not the reserved code 0's) is the kind of call the
            // TLFS says, which checks where the table keeps the rep flag.
            let table = hypercall_table(&view).unwrap();
            for (code, entry) in table.iter().enumerate() {
                let code = code as u16;
                if let Some((name, rep)) = crate::guest::hypercalls::tlfs_hypercall(code)
                    && entry.handler != table[0].handler
                    && entry.rep() != rep
                {
                    failures.push(format!(
                        "{path}: {name} ({code:#x}) rep {} in the table",
                        entry.rep()
                    ));
                }
            }
        }
        assert!(failures.is_empty(), "{failures:#?}");
    }
}
