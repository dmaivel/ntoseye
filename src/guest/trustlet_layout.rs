//! Secure-kernel process offsets recovered from the secure kernel's own code.
//! Public securekernel PDBs carry symbols but not the process type, so the
//! fields `!trustlets` needs are read off the instructions that use them.

use std::collections::HashMap;

use iced_x86::{
    Code, Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, Mnemonic,
    OpAccess, OpKind, Register,
};

use crate::error::{Error, Result};

/// Upper bound for one function's decoded body.
pub const MAX_FUNCTION_BYTES: usize = 0x1000;
/// Offsets past this are not plausible for the fields read here.
const MAX_FIELD_OFFSET: u64 = 0x1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustletLayout {
    /// `SkpsProcessList` entry inside the process.
    pub links: u64,
    /// NT process ID (`SkpsInitializeProcess`'s third argument).
    pub pid: u64,
    /// Address-space root loaded into CR3.
    pub dtb: u64,
    /// First qword of the trustlet creation attributes.
    pub trustlet_id: u64,
}

impl TrustletLayout {
    /// `select` is `SkeSelectProcessAddressSpace`; `initialize` is
    /// `SkpsInitializeProcess`, which links new processes onto
    /// `process_list`.
    pub fn derive(
        select: (&[u8], u64),
        initialize: (&[u8], u64),
        process_list: u64,
    ) -> Result<Self> {
        let dtb = cr3_offset(select.0, select.1)?;
        let (links, pid, trustlet_id) = process_offsets(initialize.0, initialize.1, process_list)?;
        let layout = Self {
            links,
            pid,
            dtb,
            trustlet_id,
        };
        let fields = [links, pid, dtb, trustlet_id];
        if fields
            .iter()
            .any(|&offset| offset % 8 != 0 || offset >= MAX_FIELD_OFFSET)
            || (1..fields.len()).any(|i| fields[..i].contains(&fields[i]))
        {
            return Err(layout_error(format!("implausible offsets {layout:x?}")));
        }
        Ok(layout)
    }
}

fn layout_error(detail: impl std::fmt::Display) -> Error {
    Error::SecureKernel(format!(
        "trustlet layout not recognized in this securekernel ({detail}); kernel/module inspection remains available"
    ))
}

/// What a register is known to hold. Anything else is untracked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Value {
    /// An incoming argument register, unchanged.
    Argument(Register),
    /// `lea reg, [base + offset]` with a tracked or untracked base.
    FieldAddress { base: Register, offset: u64 },
    /// A qword loaded from `[argument + offset]`.
    ArgumentField { argument: Register, offset: u64 },
    /// A qword loaded from `[pointer]`, excluding stack slots.
    Dereferenced,
    /// The address of the process list head.
    ListHead,
}

const VOLATILE: [Register; 7] = [
    Register::RAX,
    Register::RCX,
    Register::RDX,
    Register::R8,
    Register::R9,
    Register::R10,
    Register::R11,
];

type State = HashMap<Register, Value>;

fn get(state: &State, register: Register) -> Option<Value> {
    state.get(&register.full_register()).copied()
}

/// Value produced by `instruction` into its destination register, from the
/// state before it executes.
fn produced(state: &State, instruction: &Instruction, list: u64) -> Option<Value> {
    let simple_memory =
        instruction.op1_kind() == OpKind::Memory && instruction.memory_index() == Register::None;
    match instruction.code() {
        Code::Mov_r64_rm64 if instruction.op1_kind() == OpKind::Register => {
            get(state, instruction.op1_register())
        }
        Code::Mov_r64_rm64 if simple_memory => {
            let base = instruction.memory_base();
            let offset = instruction.memory_displacement64();
            match get(state, base) {
                Some(Value::Argument(argument)) => Some(Value::ArgumentField { argument, offset }),
                _ if offset == 0
                    && !matches!(
                        base,
                        Register::None | Register::RSP | Register::RBP | Register::RIP
                    ) =>
                {
                    Some(Value::Dereferenced)
                }
                _ => None,
            }
        }
        Code::Lea_r64_m if simple_memory => {
            let base = instruction.memory_base();
            let offset = instruction.memory_displacement64();
            if base == Register::RIP {
                (offset == list).then_some(Value::ListHead)
            } else {
                Some(Value::FieldAddress { base, offset })
            }
        }
        _ => None,
    }
}

fn step(
    state: &mut State,
    info: &mut InstructionInfoFactory,
    instruction: &Instruction,
    list: u64,
) {
    let produced = produced(state, instruction, list);
    for used in info.info(instruction).used_registers() {
        if matches!(
            used.access(),
            OpAccess::Write | OpAccess::ReadWrite | OpAccess::CondWrite | OpAccess::ReadCondWrite
        ) {
            state.remove(&used.register().full_register());
        }
    }
    if instruction.mnemonic() == Mnemonic::Call {
        for register in VOLATILE {
            state.remove(&register);
        }
    }
    if let Some(value) = produced {
        state.insert(instruction.op0_register().full_register(), value);
    }
}

/// Keep only the facts both paths into a join agree on.
fn join(state: &mut State, other: &State) {
    state.retain(|register, value| other.get(register) == Some(value));
}

/// Execution never continues to the next instruction.
fn ends_path(instruction: &Instruction) -> bool {
    match instruction.flow_control() {
        FlowControl::UnconditionalBranch
        | FlowControl::IndirectBranch
        | FlowControl::Return
        | FlowControl::Exception => true,
        // int3, and `int 29h` (__fastfail).
        FlowControl::Interrupt => {
            instruction.code() == Code::Int3
                || (instruction.code() == Code::Int_imm8 && instruction.immediate8() == 0x29)
        }
        _ => false,
    }
}

/// Forward register tracking over one function body in address order,
/// calling `visit` with the state before each reachable instruction. A
/// forward branch carries its state to the target, where it is joined with
/// the fall-through state. Loops are not iterated; the walk stops at padding
/// or when no path reaches the remaining bytes.
fn walk(
    code: &[u8],
    ip: u64,
    arguments: &[Register],
    list: u64,
    mut visit: impl FnMut(&Instruction, &State),
) {
    let mut decoder = Decoder::with_ip(64, code, ip, DecoderOptions::NONE);
    let mut info = InstructionInfoFactory::new();
    let mut pending: HashMap<u64, State> = HashMap::new();
    let mut state: Option<State> = Some(
        arguments
            .iter()
            .map(|&register| (register, Value::Argument(register)))
            .collect(),
    );
    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            break;
        }
        match (state.as_mut(), pending.remove(&instruction.ip())) {
            (Some(current), Some(branched)) => join(current, &branched),
            (None, branched @ Some(_)) => state = branched,
            (Some(_), None) => {}
            (None, None) => {
                if pending.is_empty() || instruction.code() == Code::Int3 {
                    break;
                }
                continue;
            }
        }
        let Some(current) = state.as_mut() else {
            continue;
        };
        visit(&instruction, current);
        step(current, &mut info, &instruction, list);
        if matches!(
            instruction.flow_control(),
            FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch
        ) && instruction.near_branch_target() > instruction.ip()
        {
            pending
                .entry(instruction.near_branch_target())
                .and_modify(|existing| join(existing, current))
                .or_insert_with(|| current.clone());
        }
        if ends_path(&instruction) {
            state = None;
        }
    }
}

/// `mov [base + offset], reg64` with no index register.
fn qword_store(instruction: &Instruction) -> Option<(Register, u64, Register)> {
    (instruction.code() == Code::Mov_rm64_r64
        && instruction.op0_kind() == OpKind::Memory
        && instruction.memory_index() == Register::None)
        .then(|| {
            (
                instruction.memory_base().full_register(),
                instruction.memory_displacement64(),
                instruction.op1_register().full_register(),
            )
        })
}

/// The process field `SkeSelectProcessAddressSpace(process)` loads into CR3.
pub fn cr3_offset(code: &[u8], ip: u64) -> Result<u64> {
    let mut found = Vec::new();
    walk(code, ip, &[Register::RCX], 0, |instruction, state| {
        if instruction.code() == Code::Mov_cr_r64 && instruction.op0_register() == Register::CR3 {
            found.push(get(state, instruction.op1_register()));
        }
    });
    match found.as_slice() {
        [
            Some(Value::ArgumentField {
                argument: Register::RCX,
                offset,
            }),
        ] => Ok(*offset),
        _ => Err(layout_error("CR3 load")),
    }
}

/// `(links, pid, trustlet_id)` from `SkpsInitializeProcess`: the list entry
/// stored into `process_list`, the third argument stored into the process,
/// and the process field filled from a dereferenced attribute buffer.
pub fn process_offsets(code: &[u8], ip: u64, process_list: u64) -> Result<(u64, u64, u64)> {
    let mut links = Vec::new();
    let mut pid = Vec::new();
    let mut identity = Vec::new();
    walk(
        code,
        ip,
        &[Register::R8],
        process_list,
        |instruction, state| {
            if let Some((base, offset, source)) = qword_store(instruction) {
                match (get(state, source), get(state, base)) {
                    (Some(Value::Argument(Register::R8)), _) => pid.push((base, offset)),
                    (Some(Value::Dereferenced), _) => identity.push((base, offset)),
                    (
                        Some(Value::ListHead),
                        Some(Value::FieldAddress {
                            base: process,
                            offset: field,
                        }),
                    ) if offset == 0 => links.push((process.full_register(), field)),
                    _ => {}
                }
            }
        },
    );
    let [(process, links)] = links[..] else {
        return Err(layout_error("process-list insertion"));
    };
    let in_process = |stores: &[(Register, u64)], what: &str| {
        let mut offsets = stores
            .iter()
            .filter(|(base, _)| *base == process)
            .map(|&(_, offset)| offset);
        let first = offsets.next().ok_or_else(|| layout_error(what))?;
        if offsets.all(|offset| offset == first) {
            Ok(first)
        } else {
            Err(layout_error(format!("{what} is ambiguous")))
        }
    };
    Ok((
        links,
        in_process(&pid, "process ID store")?,
        in_process(&identity, "trustlet identity store")?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(hex: &str) -> Vec<u8> {
        let hex: String = hex.split_whitespace().collect();
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    // SkeSelectProcessAddressSpace, 10.0.26100.9457 (through `mov cr3`).
    const SELECT: &str = "9c fa 4c8b0c24 4c8b4140 65488b142540000000 483bca 7432 410f22d8 c3";

    #[test]
    fn cr3_offset_follows_the_register_written_to_cr3() {
        assert_eq!(cr3_offset(&bytes(SELECT), 0x1400e75e0).unwrap(), 0x40);
        // `mov r8, rdx` between the load and `mov cr3, r8`: the root is no
        // longer a process field.
        let clobbered = SELECT.replace("410f22d8", "4c8bc2 410f22d8");
        assert!(cr3_offset(&bytes(&clobbered), 0x1400e75e0).is_err());
    }

    /// Key instructions of SkpsInitializeProcess, 10.0.26100.9457, with the
    /// list-head `lea` placed so that it targets `LIST`.
    fn initialize(extra: &str) -> (Vec<u8>, u64) {
        initialize_with(extra, "cd 29")
    }

    /// `guard` follows the list-head check's `mov ecx, 3` on the path the
    /// check's `je` skips.
    fn initialize_with(extra: &str, guard: &str) -> (Vec<u8>, u64) {
        let prefix = [
            "49 8b d8",             // mov rbx, r8
            "41 b0 01",             // mov r8b, 1
            "48 8b 7d d0",          // mov rdi, [rbp-0x30]
            "48 8b cf",             // mov rcx, rdi
            "e8 00 00 00 00",       // call (clobbers volatile registers)
            "48 89 5f 38",          // mov [rdi+0x38], rbx
            "48 8b 5d 60",          // mov rbx, [rbp+0x60]
            "48 8b 45 58",          // mov rax, [rbp+0x58]
            "48 8b 08",             // mov rcx, [rax]
            "48 89 8f a0 01 00 00", // mov [rdi+0x1a0], rcx
            "48 8b 06",             // mov rax, [rsi]
            "48 89 87 a0 01 00 00", // mov [rdi+0x1a0], rax
            extra,
            "48 8b 15 b2 f0 08 00", // mov rdx, [rip+...]
        ]
        .concat();
        let ip = 0x1400a4000;
        let lea_end = ip + bytes(&prefix).len() as u64 + 7;
        let code = [
            prefix,
            "4c 8d 05 00 00 00 00".to_string(), // lea r8, [rip+0] = LIST
            "48 8d 8f e8 00 00 00".to_string(), // lea rcx, [rdi+0xe8]
            "4c 39 02".to_string(),             // cmp [rdx], r8
            "74 07".to_string(),                // je past the guard
            "b9 03 00 00 00".to_string(),       // mov ecx, 3
            guard.to_string(),                  // int 29h (__fastfail)
            "48 89 51 08".to_string(),          // mov [rcx+8], rdx
            "4c 89 01".to_string(),             // mov [rcx], r8
            "48 89 0a".to_string(),             // mov [rdx], rcx
            "c3".to_string(),
        ]
        .concat();
        (bytes(&code), lea_end)
    }

    #[test]
    fn process_offsets_match_the_examined_build() {
        let (code, list) = initialize("");
        assert_eq!(
            process_offsets(&code, 0x1400a4000, list).unwrap(),
            (0xe8, 0x38, 0x1a0)
        );
        // A different list head is not an insertion into SkpsProcessList.
        assert!(process_offsets(&code, 0x1400a4000, list + 8).is_err());
    }

    #[test]
    fn branch_joins_keep_only_values_both_paths_agree_on() {
        // Without the fast-fail, `mov ecx, 3` falls through into the list
        // insertion, so rcx no longer holds the entry address there.
        let (code, list) = initialize_with("", "90 90");
        assert!(process_offsets(&code, 0x1400a4000, list).is_err());
    }

    #[test]
    fn conflicting_identity_stores_are_rejected() {
        // mov rcx, [rax]; mov [rdi+0x1a8], rcx
        let (code, list) = initialize("48 8b 08 48 89 8f a8 01 00 00");
        assert!(process_offsets(&code, 0x1400a4000, list).is_err());
    }

    #[test]
    fn derived_layout_rejects_overlapping_fields() {
        let (code, list) = initialize("");
        let select = bytes(&SELECT.replace("4c8b4140", "4c8b4138"));
        assert!(
            TrustletLayout::derive((&select, 0x1400e75e0), (&code, 0x1400a4000), list).is_err()
        );
        let select = bytes(SELECT);
        assert_eq!(
            TrustletLayout::derive((&select, 0x1400e75e0), (&code, 0x1400a4000), list).unwrap(),
            TrustletLayout {
                links: 0xe8,
                pid: 0x38,
                dtb: 0x40,
                trustlet_id: 0x1a0,
            }
        );
    }
}
