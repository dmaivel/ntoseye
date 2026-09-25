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
    /// NT process ID.
    pub pid: u64,
    /// Address-space root loaded into CR3.
    pub dtb: u64,
    /// The trustlet ID, checked against the image's policy metadata.
    pub trustlet_id: u64,
}

impl TrustletLayout {
    /// `select` is `SkeSelectProcessAddressSpace`; `initialize` is
    /// `SkpsInitializeProcess`, which links new processes onto
    /// `process_list` and reports failures with the `start_failed` event;
    /// `policy` is `SkpsReadPolicyMetadata`. The trustlet ID has no value to
    /// validate against at runtime, so the two functions that use it must
    /// agree on where it is: the policy check must read the field the event
    /// reports.
    pub fn derive(
        select: (&[u8], u64),
        initialize: (&[u8], u64),
        policy: (&[u8], u64),
        process_list: u64,
        start_failed: u64,
    ) -> Result<Self> {
        let dtb = cr3_offset(select.0, select.1)?;
        let (links, pid, trustlet_id) =
            process_offsets(initialize.0, initialize.1, process_list, start_failed)?;
        if !policy_process_reads(policy.0, policy.1).contains(&trustlet_id) {
            return Err(layout_error(format!(
                "the policy check never reads the trustlet ID stored at {trustlet_id:#x}"
            )));
        }
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
    /// A value loaded from `[argument + offset]`.
    ArgumentField { argument: Register, offset: u64 },
    /// A value loaded from `[base + offset]`, `base` an untracked register
    /// (the process object, in `SkpsInitializeProcess`).
    Loaded { base: Register, offset: u64 },
    /// A `lea` of a global: `[rip + displacement]`.
    Global(u64),
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
fn produced(state: &State, instruction: &Instruction) -> Option<Value> {
    let simple_memory =
        instruction.op1_kind() == OpKind::Memory && instruction.memory_index() == Register::None;
    match instruction.code() {
        Code::Mov_r64_rm64 if instruction.op1_kind() == OpKind::Register => {
            get(state, instruction.op1_register())
        }
        Code::Mov_r64_rm64 | Code::Mov_r32_rm32 if simple_memory => {
            let base = instruction.memory_base();
            let offset = instruction.memory_displacement64();
            match get(state, base) {
                Some(Value::Argument(argument)) => Some(Value::ArgumentField { argument, offset }),
                None if !matches!(
                    base,
                    Register::None | Register::RSP | Register::RBP | Register::RIP
                ) =>
                {
                    Some(Value::Loaded {
                        base: base.full_register(),
                        offset,
                    })
                }
                _ => None,
            }
        }
        Code::Lea_r64_m if simple_memory => {
            let base = instruction.memory_base();
            let offset = instruction.memory_displacement64();
            Some(if base == Register::RIP {
                Value::Global(offset)
            } else {
                Value::FieldAddress { base, offset }
            })
        }
        _ => None,
    }
}

fn step(state: &mut State, info: &mut InstructionInfoFactory, instruction: &Instruction) {
    let produced = produced(state, instruction);
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
fn walk(code: &[u8], ip: u64, arguments: &[Register], mut visit: impl FnMut(&Instruction, &State)) {
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
        step(current, &mut info, &instruction);
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
    walk(code, ip, &[Register::RCX], |instruction, state| {
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

/// The fields `SkpsReadPolicyMetadata(process)` loads from or compares in
/// its process argument. It compares the image's policy trustlet ID with the
/// process's (loaded for the comparison in newer builds, compared in place
/// in 10.0.19041), so the identity is among them.
pub fn policy_process_reads(code: &[u8], ip: u64) -> Vec<u64> {
    let mut reads = Vec::new();
    walk(code, ip, &[Register::RCX], |instruction, state| {
        let reads_memory = match instruction.mnemonic() {
            Mnemonic::Mov => instruction.op1_kind() == OpKind::Memory,
            Mnemonic::Cmp => {
                instruction.op0_kind() == OpKind::Memory || instruction.op1_kind() == OpKind::Memory
            }
            _ => false,
        };
        if reads_memory
            && instruction.memory_index() == Register::None
            && get(state, instruction.memory_base()) == Some(Value::Argument(Register::RCX))
        {
            reads.push(instruction.memory_displacement64());
        }
    });
    reads
}

/// `(links, pid, trustlet_id)` from `SkpsInitializeProcess`: the list entry
/// it links onto `process_list`, and the two process fields it reports with
/// the `start_failed` ETW event (`IumProcessStartFailed`). Every examined
/// build, 10.0.19041 through 10.0.28000, loads the trustlet ID into `r9` and
/// the NT PID into the fifth argument (`[rsp+20h]`) for that event, although
/// the function itself receives them differently across releases.
pub fn process_offsets(
    code: &[u8],
    ip: u64,
    process_list: u64,
    start_failed: u64,
) -> Result<(u64, u64, u64)> {
    let mut links = Vec::new();
    let mut events = Vec::new();
    // What the last `mov dword [rsp+20h], reg` stored: the fifth argument.
    let mut fifth: Option<Value> = None;
    walk(code, ip, &[], |instruction, state| {
        if let Some((base, offset, source)) = qword_store(instruction)
            && offset == 0
            && get(state, source) == Some(Value::Global(process_list))
            && let Some(Value::FieldAddress {
                base: process,
                offset: field,
            }) = get(state, base)
        {
            links.push((process.full_register(), field));
        }
        if instruction.code() == Code::Mov_rm32_r32
            && instruction.memory_base() == Register::RSP
            && instruction.memory_index() == Register::None
            && instruction.memory_displacement64() == 0x20
        {
            fifth = get(state, instruction.op1_register());
        }
        if instruction.mnemonic() == Mnemonic::Call {
            if get(state, Register::RDX) == Some(Value::Global(start_failed)) {
                events.push((get(state, Register::R9), fifth));
            }
            fifth = None;
        }
    });
    let [(process, links)] = links[..] else {
        return Err(layout_error("process-list insertion"));
    };
    let [
        (
            Some(Value::Loaded {
                base: id_base,
                offset: trustlet_id,
            }),
            Some(Value::Loaded {
                base: pid_base,
                offset: pid,
            }),
        ),
    ] = events[..]
    else {
        return Err(layout_error("process start failure event"));
    };
    if id_base != process || pid_base != process {
        return Err(layout_error(
            "the start failure event reports another object than the one linked",
        ));
    }
    Ok((links, pid, trustlet_id))
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

    /// Key instructions of SkpsInitializeProcess, 10.0.26100.9457: the
    /// start-failure event's arguments and the list insertion, with the
    /// `lea`s of the event and the list head placed to target the returned
    /// `(code, list, event)` addresses.
    fn initialize(event_args: &str) -> (Vec<u8>, u64, u64) {
        initialize_with(event_args, "cd 29")
    }

    /// The event's `mov r9, [rdi+0x1a0]`, in `initialize`'s `event_args`.
    const IDENTITY: &str = "4c 8b 8f a0 01 00 00";

    /// `guard` follows the list-head check's `mov ecx, 3` on the path the
    /// check's `je` skips.
    fn initialize_with(identity: &str, guard: &str) -> (Vec<u8>, u64, u64) {
        let ip = 0x1400a4000;
        let before_event = [
            "48 8b 7d d0",    // mov rdi, [rbp-0x30]
            "48 8b cf",       // mov rcx, rdi
            "e8 00 00 00 00", // call (clobbers volatile registers)
            "8b 47 38",       // mov eax, [rdi+0x38]
        ]
        .concat();
        let event = ip + bytes(&before_event).len() as u64 + 7;
        let prefix = [
            before_event.as_str(),
            "48 8d 15 00 00 00 00", // lea rdx, [rip+0] = IumProcessStartFailed
            identity,               // mov r9, [rdi+0x1a0]
            "89 5c 24 28",          // mov [rsp+0x28], ebx
            "89 44 24 20",          // mov [rsp+0x20], eax
            "e8 00 00 00 00",       // call McTemplateK0xqq_EtwWriteTransfer
            "48 8b 15 b2 f0 08 00", // mov rdx, [rip+...]
        ]
        .concat();
        let list = ip + bytes(&prefix).len() as u64 + 7;
        let code = [
            prefix,
            "4c 8d 05 00 00 00 00".to_string(), // lea r8, [rip+0] = SkpsProcessList
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
        (bytes(&code), list, event)
    }

    #[test]
    fn process_offsets_match_the_examined_build() {
        let (code, list, event) = initialize(IDENTITY);
        assert_eq!(
            process_offsets(&code, 0x1400a4000, list, event).unwrap(),
            (0xe8, 0x38, 0x1a0)
        );
        // Another list head is not SkpsProcessList, another event not the
        // start-failure report.
        assert!(process_offsets(&code, 0x1400a4000, list + 8, event).is_err());
        assert!(process_offsets(&code, 0x1400a4000, list, event + 8).is_err());
    }

    #[test]
    fn branch_joins_keep_only_values_both_paths_agree_on() {
        // Without the fast-fail, `mov ecx, 3` falls through into the list
        // insertion, so rcx no longer holds the entry address there.
        let (code, list, event) = initialize_with(IDENTITY, "90 90");
        assert!(process_offsets(&code, 0x1400a4000, list, event).is_err());
    }

    #[test]
    fn an_event_about_another_object_is_rejected() {
        // mov r9, [rsi+0x1a0]: not the object linked onto the list.
        let (code, list, event) = initialize("4c 8b 8e a0 01 00 00");
        assert!(process_offsets(&code, 0x1400a4000, list, event).is_err());
    }

    // SkpsReadPolicyMetadata, 10.0.26100.9457: the process argument moved to
    // rbx, another field read, then the identity read, compared, and filled.
    const POLICY: &str = "48 8b d9 48 8b 8b a0 00 00 00 e8 00 00 00 00 \
                          4c 8b 83 a0 01 00 00 48 89 83 a0 01 00 00 c3";

    #[test]
    fn policy_reads_follow_the_process_argument() {
        // rbx holds the argument after `mov rbx, rcx`; the call clobbers rcx
        // but not rbx.
        assert_eq!(
            policy_process_reads(&bytes(POLICY), 0x1400a8feb),
            [0xa0, 0x1a0]
        );
        // 10.0.19041 compares the identity in place instead of loading it.
        let compared = "48 8b d9 e8 00 00 00 00 48 83 bb f0 00 00 00 00 \
                        48 3b 83 f0 00 00 00 c3";
        assert_eq!(
            policy_process_reads(&bytes(compared), 0x14002df4f),
            [0xf0, 0xf0]
        );
    }

    #[test]
    fn derived_layout_requires_both_identity_sites_to_agree() {
        let (code, list, event) = initialize(IDENTITY);
        let select = bytes(SELECT);
        let policy = bytes(POLICY);
        let derive = |select: &[u8], policy: &[u8]| {
            TrustletLayout::derive(
                (select, 0x1400e75e0),
                (&code, 0x1400a4000),
                (policy, 0x1400a8feb),
                list,
                event,
            )
        };
        assert_eq!(
            derive(&select, &policy).unwrap(),
            TrustletLayout {
                links: 0xe8,
                pid: 0x38,
                dtb: 0x40,
                trustlet_id: 0x1a0,
            }
        );
        let elsewhere = bytes(&POLICY.replace("a0 01 00 00", "a8 01 00 00"));
        assert!(derive(&select, &elsewhere).is_err());
        // A root at the PID's offset overlaps it.
        let overlapping = bytes(&SELECT.replace("4c8b4140", "4c8b4138"));
        assert!(derive(&overlapping, &policy).is_err());
    }
}
