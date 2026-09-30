//! Where the Windows hypervisor keeps the guest general-purpose registers of
//! a VM exit. A VMCS holds RIP and RSP but no other general-purpose
//! register: on an exit they are still in the CPU, and the hypervisor's exit
//! entry point (the eVMCS `host_rip`, running on `host_rsp`) saves them
//! itself. Where it saves them is a detail of the hypervisor build, so it is
//! read off the entry code rather than kept as offsets: the code is followed
//! symbolically from `host_rsp` until it first branches, and the layout is
//! accepted only when every guest register ends up, once, in one block that
//! nothing written after it may have overwritten.

use std::collections::HashMap;

use iced_x86::{
    Code, Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, Mnemonic,
    OpAccess, OpKind, Register,
};

use crate::error::{Error, Result};

/// The general-purpose registers other than RSP, which a VMCS does hold.
pub const EXIT_GPRS: [&str; 15] = [
    "rax", "rcx", "rdx", "rbx", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14",
    "r15",
];

const EXIT_GPR_REGISTERS: [Register; 15] = [
    Register::RAX,
    Register::RCX,
    Register::RDX,
    Register::RBX,
    Register::RBP,
    Register::RSI,
    Register::RDI,
    Register::R8,
    Register::R9,
    Register::R10,
    Register::R11,
    Register::R12,
    Register::R13,
    Register::R14,
    Register::R15,
];

/// Bytes of entry code followed. Entry stubs save the registers within a few
/// dozen instructions; past this the code is doing something else.
pub const ENTRY_CODE_BYTES: usize = 0x200;
const MAX_INSTRUCTIONS: usize = 96;

/// An address, as the entry code reaches it from `host_rsp`: start at
/// `host_rsp`, for each of `loads` add it and read the qword there, then add
/// `offset`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Path {
    loads: Vec<i64>,
    offset: i64,
}

impl Path {
    fn plus(&self, displacement: i64) -> Self {
        Self {
            loads: self.loads.clone(),
            offset: self.offset.wrapping_add(displacement),
        }
    }

    /// The qword stored at this address, as a path of its own.
    fn loaded(&self) -> Self {
        let mut loads = self.loads.clone();
        loads.push(self.offset);
        Self { loads, offset: 0 }
    }
}

/// What a register holds while the entry code runs.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Value {
    /// The guest's value of this register, from the exit.
    Guest(usize),
    /// An address the code computed from `host_rsp`.
    Address(Path),
}

/// Where a memory access goes. Memory reached different ways (through
/// different loads from `host_rsp`, or at a fixed address) is taken to be
/// different memory: the code cannot tell, and the walk does not guess.
enum Target {
    /// An address reached from `host_rsp`.
    Path(Path),
    /// A fixed address: absolute, RIP-relative (the image's own data), or
    /// FS- or GS-relative with no base register (the processor's).
    Fixed,
    /// Through a register the walk does not know as an address, or with an
    /// index: anywhere.
    Unknown,
}

/// Where the entry code saved the guest registers: one block, reached from
/// `host_rsp` through `block_loads` (as in the module docs), and each
/// register's offset in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitRegisterLayout {
    pub block_loads: Vec<i64>,
    /// Offsets in the block, in [`EXIT_GPRS`] order.
    pub offsets: [i64; 15],
    /// The first instruction after the last store into the block. A vCPU
    /// between `host_rip` and this has not saved this exit's registers yet.
    pub stores_end: u64,
}

impl ExitRegisterLayout {
    /// The saved registers of the exit that `host_rsp` belongs to, reading
    /// qwords through `read` (the hypervisor's address space).
    pub fn read(
        &self,
        host_rsp: u64,
        mut read: impl FnMut(u64) -> Option<u64>,
    ) -> Option<HashMap<&'static str, u64>> {
        let mut block = host_rsp;
        for load in &self.block_loads {
            block = read(block.wrapping_add_signed(*load))?;
        }
        EXIT_GPRS
            .iter()
            .zip(self.offsets)
            .map(|(name, offset)| Some((*name, read(block.wrapping_add_signed(offset))?)))
            .collect()
    }
}

fn layout_error(detail: impl std::fmt::Display) -> Error {
    Error::SavedVtlState(format!("VM-exit entry code: {detail}"))
}

impl super::Guest {
    /// Where the exit entry code at `host_rip` saves the guest's registers,
    /// read off its code (`read_code` fills a buffer from `host_rip` in the
    /// hypervisor's address space) the first time an entry point is seen,
    /// and remembered for the boot, as a failure is.
    pub fn exit_register_layout(
        &self,
        host_rip: u64,
        read_code: impl FnOnce(&mut [u8]) -> Result<()>,
    ) -> std::result::Result<ExitRegisterLayout, String> {
        let mut layouts = self
            .exit_register_layouts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(layout) = layouts.get(&host_rip) {
            return layout.clone();
        }
        let mut code = vec![0u8; ENTRY_CODE_BYTES];
        let layout = read_code(&mut code)
            .and_then(|()| derive(&code, host_rip))
            .map_err(|error| error.to_string());
        layouts.insert(host_rip, layout.clone());
        layout
    }
}

/// What the entry code at `ip` (its bytes are `code`) does with the guest's
/// registers, followed until its first branch, call, or return.
pub fn derive(code: &[u8], ip: u64) -> Result<ExitRegisterLayout> {
    let mut walk = Walk::new();
    let mut info = InstructionInfoFactory::new();
    let mut decoder = Decoder::with_ip(64, code, ip, DecoderOptions::NONE);
    let mut instruction = Instruction::default();
    let mut followed = 0;
    while decoder.can_decode() && followed < MAX_INSTRUCTIONS {
        decoder.decode_out(&mut instruction);
        if instruction.code() == Code::INVALID || instruction.flow_control() != FlowControl::Next {
            break;
        }
        walk.step(&instruction, &mut info);
        followed += 1;
    }
    walk.layout()
}

struct Walk {
    registers: HashMap<Register, Value>,
    /// Addresses that hold a guest register, and the end of the store that
    /// put it there.
    memory: HashMap<Path, (usize, u64)>,
}

impl Walk {
    fn new() -> Self {
        let mut registers: HashMap<Register, Value> = EXIT_GPR_REGISTERS
            .iter()
            .enumerate()
            .map(|(index, register)| (*register, Value::Guest(index)))
            .collect();
        registers.insert(
            Register::RSP,
            Value::Address(Path {
                loads: Vec::new(),
                offset: 0,
            }),
        );
        Self {
            registers,
            memory: HashMap::new(),
        }
    }

    fn address_in(&self, register: Register) -> Option<Path> {
        match self.registers.get(&register) {
            Some(Value::Address(path)) => Some(path.clone()),
            _ => None,
        }
    }

    /// Where `segment:[base + index + displacement]` is.
    fn target(
        &self,
        base: Register,
        index: Register,
        segment: Register,
        displacement: u64,
    ) -> Target {
        if index != Register::None {
            return Target::Unknown;
        }
        if matches!(base, Register::None | Register::RIP) {
            return Target::Fixed;
        }
        match self.address_in(base) {
            Some(path) if !matches!(segment, Register::FS | Register::GS) => {
                Target::Path(path.plus(displacement as i64))
            }
            _ => Target::Unknown,
        }
    }

    /// Where `instruction`'s memory operand is.
    fn memory_target(&self, instruction: &Instruction) -> Target {
        self.target(
            instruction.memory_base(),
            instruction.memory_index(),
            instruction.segment_prefix(),
            instruction.memory_displacement64(),
        )
    }

    /// The address of `instruction`'s memory operand, when it is reached
    /// from `host_rsp`.
    fn memory_address(&self, instruction: &Instruction) -> Option<Path> {
        match self.memory_target(instruction) {
            Target::Path(path) => Some(path),
            Target::Fixed | Target::Unknown => None,
        }
    }

    /// Forget the saved registers a write of `size` bytes to `target` may
    /// overwrite: those it overlaps, or every one when where it writes, or
    /// how much, is not known.
    fn clobber(&mut self, target: &Target, size: usize) {
        match target {
            Target::Path(address) if size != 0 => self.overwrite(address, size),
            Target::Fixed => {}
            Target::Path(_) | Target::Unknown => self.memory.clear(),
        }
    }

    /// Forget the saved registers that `size` bytes at `address` overlap.
    fn overwrite(&mut self, address: &Path, size: usize) {
        self.memory.retain(|slot, _| {
            let distance = slot.offset.wrapping_sub(address.offset);
            slot.loads != address.loads || distance <= -8 || distance >= size as i64
        });
    }

    /// Store the qword in `register` at `address`: remembered only when it
    /// is a guest register.
    fn store(&mut self, address: Path, register: Register, end: u64) {
        self.overwrite(&address, 8);
        if register.is_gpr64()
            && let Some(Value::Guest(index)) = self.registers.get(&register)
        {
            let index = *index;
            self.memory.insert(address, (index, end));
        }
    }

    fn load(&mut self, register: Register, address: Option<Path>) {
        let value = address.map(|address| match self.memory.get(&address) {
            Some((index, _)) => Value::Guest(*index),
            None => Value::Address(address.loaded()),
        });
        self.set(register, value);
    }

    fn set(&mut self, register: Register, value: Option<Value>) {
        match value {
            Some(value) => self.registers.insert(register.full_register(), value),
            None => self.registers.remove(&register.full_register()),
        };
    }

    fn step(&mut self, instruction: &Instruction, info: &mut InstructionInfoFactory) {
        let end = instruction.next_ip();
        let op = |index| instruction.op_kind(index);
        let register = |index| instruction.op_register(index);
        let size = instruction.memory_size().size();
        let qword = size == 8;
        match instruction.mnemonic() {
            Mnemonic::Mov if op(0) == OpKind::Memory && op(1) == OpKind::Register => {
                match self.memory_target(instruction) {
                    Target::Path(address) if qword => self.store(address, register(1), end),
                    target => self.clobber(&target, size),
                }
                return;
            }
            Mnemonic::Mov if op(0) == OpKind::Register && register(0).is_gpr64() => {
                let value = match op(1) {
                    OpKind::Memory if qword => {
                        let address = self.memory_address(instruction);
                        self.load(register(0), address);
                        return;
                    }
                    OpKind::Register if register(1).is_gpr64() => {
                        self.registers.get(&register(1)).cloned()
                    }
                    _ => None,
                };
                self.set(register(0), value);
                return;
            }
            Mnemonic::Lea if register(0).is_gpr64() => {
                let address = self.memory_address(instruction);
                self.set(register(0), address.map(Value::Address));
                return;
            }
            Mnemonic::Push if op(0) == OpKind::Register && register(0).is_gpr64() => {
                if let Some(top) = self.address_in(Register::RSP).map(|rsp| rsp.plus(-8)) {
                    self.store(top.clone(), register(0), end);
                    self.set(Register::RSP, Some(Value::Address(top)));
                    return;
                }
            }
            Mnemonic::Pop if op(0) == OpKind::Register && register(0).is_gpr64() => {
                if let Some(top) = self.address_in(Register::RSP) {
                    self.load(register(0), Some(top.clone()));
                    self.set(Register::RSP, Some(Value::Address(top.plus(8))));
                    return;
                }
            }
            Mnemonic::Sub | Mnemonic::Add
                if op(0) == OpKind::Register
                    && register(0).is_gpr64()
                    && matches!(op(1), OpKind::Immediate8to64 | OpKind::Immediate32to64) =>
            {
                let amount = instruction.immediate(1) as i64;
                let amount = if instruction.mnemonic() == Mnemonic::Sub {
                    amount.wrapping_neg()
                } else {
                    amount
                };
                let moved = self
                    .address_in(register(0))
                    .map(|address| address.plus(amount));
                self.set(register(0), moved.map(Value::Address));
                return;
            }
            _ => {}
        }
        self.invalidate(instruction, info);
    }

    /// Anything else: the memory it may write, explicitly or not (a push,
    /// a string store), is clobbered, and every register it writes becomes
    /// unknown.
    fn invalidate(&mut self, instruction: &Instruction, info: &mut InstructionInfoFactory) {
        let info = info.info(instruction);
        for used in info.used_memory() {
            if !matches!(
                used.access(),
                OpAccess::Read | OpAccess::CondRead | OpAccess::NoMemAccess
            ) {
                let target = self.target(
                    used.base(),
                    used.index(),
                    used.segment(),
                    used.displacement(),
                );
                self.clobber(&target, used.memory_size().size());
            }
        }
        for used in info.used_registers() {
            if matches!(
                used.access(),
                OpAccess::Write
                    | OpAccess::CondWrite
                    | OpAccess::ReadWrite
                    | OpAccess::ReadCondWrite
            ) {
                self.registers.remove(&used.register().full_register());
            }
        }
    }

    /// The block every guest register was saved into: all fifteen, each
    /// once, behind one chain of loads from `host_rsp`. A register that also
    /// passed through another place (a stack slot it was parked in) is
    /// fine; two blocks that both hold all of them are not.
    fn layout(&self) -> Result<ExitRegisterLayout> {
        let mut blocks: HashMap<&Vec<i64>, Vec<(usize, i64, u64)>> = HashMap::new();
        for (path, (index, end)) in &self.memory {
            blocks
                .entry(&path.loads)
                .or_default()
                .push((*index, path.offset, *end));
        }
        let mut complete = blocks.into_iter().filter_map(|(loads, slots)| {
            let mut offsets = [None; 15];
            for (index, offset, _) in &slots {
                if offsets[*index].replace(*offset).is_some() {
                    return None;
                }
            }
            if offsets.iter().any(Option::is_none) {
                return None;
            }
            let stores_end = slots.iter().map(|(_, _, end)| *end).max().unwrap_or(0);
            Some(ExitRegisterLayout {
                block_loads: loads.clone(),
                offsets: offsets.map(|offset| offset.unwrap_or_default()),
                stores_end,
            })
        });
        match (complete.next(), complete.next()) {
            (Some(layout), None) => Ok(layout),
            (None, _) => Err(layout_error(
                "not every general-purpose register is saved in one block before the first branch",
            )),
            (Some(_), Some(_)) => Err(layout_error(
                "more than one block holds every general-purpose register",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IP: u64 = 0xffff_f837_bc9a_843d;

    /// `hvix64` 10.0.26100 (Windows 11 26200), from `host_rip`: parks rcx
    /// on the stack, loads the block through `[[rsp+0x20]]`, stores every
    /// register in encoding order, then moves the parked rcx in.
    fn entry_26100() -> (Vec<u8>, u64) {
        let stores: &[&[u8]] = &[
            &[0xc7, 0x44, 0x24, 0x30, 0, 0, 0, 0], // mov dword [rsp+0x30], 0
            &[0x48, 0x89, 0x4c, 0x24, 0x28],       // mov [rsp+0x28], rcx
            &[0x48, 0x8b, 0x4c, 0x24, 0x20],       // mov rcx, [rsp+0x20]
            &[0x48, 0x8b, 0x09],                   // mov rcx, [rcx]
            &[0x48, 0x89, 0x01],                   // mov [rcx], rax
            &[0x48, 0x89, 0x51, 0x10],             // mov [rcx+0x10], rdx
            &[0x48, 0x89, 0x59, 0x18],             // mov [rcx+0x18], rbx
            &[0x48, 0x89, 0x69, 0x28],             // mov [rcx+0x28], rbp
            &[0x48, 0x89, 0x71, 0x30],             // mov [rcx+0x30], rsi
            &[0x48, 0x89, 0x79, 0x38],             // mov [rcx+0x38], rdi
            &[0x4c, 0x89, 0x41, 0x40],             // mov [rcx+0x40], r8
            &[0x4c, 0x89, 0x49, 0x48],
            &[0x4c, 0x89, 0x51, 0x50],
            &[0x4c, 0x89, 0x59, 0x58],
            &[0x4c, 0x89, 0x61, 0x60],
            &[0x4c, 0x89, 0x69, 0x68],
            &[0x4c, 0x89, 0x71, 0x70],
            &[0x4c, 0x89, 0x79, 0x78],       // mov [rcx+0x78], r15
            &[0x48, 0x8b, 0x44, 0x24, 0x28], // mov rax, [rsp+0x28]
            &[0x48, 0x89, 0x41, 0x08],       // mov [rcx+8], rax
        ];
        let tail: &[&[u8]] = &[
            &[0x48, 0x8d, 0x41, 0x70],                      // lea rax, [rcx+0x70]
            &[0x0f, 0x29, 0x40, 0x10],                      // movaps [rax+0x10], xmm0
            &[0x48, 0x8b, 0xe9],                            // mov rbp, rcx
            &[0x48, 0x8b, 0x4c, 0x24, 0x20],                // mov rcx, [rsp+0x20]
            &[0x33, 0xdb],                                  // xor ebx, ebx
            &[0x48, 0x89, 0x5c, 0x24, 0x28],                // mov [rsp+0x28], rbx
            &[0x65, 0x80, 0x24, 0x25, 0x85, 0, 0, 0, 0xf9], // and byte [gs:0x85], 0xf9
            &[0xe8, 0x71, 0xd3, 0xff, 0xff],                // call
            &[0x48, 0x89, 0x41, 0x08],                      // (after the call: not followed)
        ];
        let stored: Vec<u8> = stores.concat();
        let end = IP + stored.len() as u64;
        ([stored, tail.concat()].concat(), end)
    }

    #[test]
    fn follows_the_block_through_host_rsp_and_the_parked_register() {
        let (code, end) = entry_26100();
        let layout = derive(&code, IP).unwrap();
        assert_eq!(layout.block_loads, vec![0x20, 0]);
        assert_eq!(
            layout.offsets,
            [
                0, 8, 0x10, 0x18, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70, 0x78
            ]
        );
        assert_eq!(layout.stores_end, end);
    }

    #[test]
    fn a_stub_that_pushes_saves_below_host_rsp() {
        // push r15 ... push rax, in reverse encoding order, then call.
        let mut code = Vec::new();
        for register in (0..16u8).rev().filter(|register| *register != 4) {
            if register >= 8 {
                code.push(0x41);
            }
            code.push(0x50 + (register & 7));
        }
        code.extend([0xe8, 0, 0, 0, 0]);
        let layout = derive(&code, IP).unwrap();
        assert!(layout.block_loads.is_empty());
        // rax was pushed last, so it is lowest; r15 first, at -8.
        assert_eq!(layout.offsets[0], -120);
        assert_eq!(layout.offsets[14], -8);
    }

    #[test]
    fn a_register_left_unsaved_before_the_first_call_refuses_the_layout() {
        let (code, _) = entry_26100();
        // Cut the stores short of r15 and call instead.
        let cut = code
            .windows(4)
            .position(|window| window == [0x4c, 0x89, 0x79, 0x78])
            .unwrap();
        let code = [&code[..cut], &[0xe8, 0, 0, 0, 0][..]].concat();
        assert!(derive(&code, IP).is_err());
    }

    #[test]
    fn a_register_overwritten_before_it_is_saved_is_not_the_guests() {
        let (code, _) = entry_26100();
        // xor edx, edx ahead of everything: the rdx stored later is zero.
        let code = [&[0x31, 0xd2][..], &code].concat();
        assert!(derive(&code, IP - 2).is_err());
    }

    #[test]
    fn a_write_that_may_overwrite_a_saved_register_refuses_the_layout() {
        let (code, _) = entry_26100();
        // Just after the stores, ahead of `lea rax, [rcx+0x70]`.
        let after_stores = code
            .windows(3)
            .position(|window| window == [0x48, 0x8d, 0x41])
            .unwrap();
        let writes: [&[u8]; 3] = [
            &[0x48, 0x89, 0x13],             // mov [rbx], rdx: anywhere
            &[0xc7, 0x41, 0x7c, 0, 0, 0, 0], // mov dword [rcx+0x7c], 0: half of r15
            &[0x48, 0xab],                   // stosq: [rdi], anywhere
        ];
        for write in writes {
            let code = [&code[..after_stores], write, &code[after_stores..]].concat();
            assert!(derive(&code, IP).is_err(), "{write:02x?}");
        }
    }

    #[test]
    fn reads_the_block_through_the_loads() {
        let (code, _) = entry_26100();
        let layout = derive(&code, IP).unwrap();
        let host_rsp = 0xffff_e700_0020_5fc0;
        let holder = 0xffff_e800_0026_cf10;
        let block = 0xffff_e700_0020_7080;
        let registers = layout
            .read(host_rsp, |address| match address {
                a if a == host_rsp + 0x20 => Some(holder),
                a if a == holder => Some(block),
                a if (block..block + 0x80).contains(&a) => Some(a - block),
                _ => None,
            })
            .unwrap();
        assert_eq!(registers["rax"], 0);
        assert_eq!(registers["rcx"], 8);
        assert_eq!(registers["rbp"], 0x28);
        assert_eq!(registers["r15"], 0x78);
        assert!(layout.read(host_rsp, |_| None).is_none());
    }

    /// The RVAs a `hvix64` image writes to VMCS host RIP (encoding 0x6C16):
    /// for each `vmwrite`, the field register's last write must be that
    /// constant and the value register's a RIP-relative `lea`, whose target
    /// is an entry point. Nothing about the entry code itself is assumed.
    fn host_rip_writes(pe: pelite::pe64::PeFile<'_>) -> Vec<u32> {
        use pelite::pe64::Pe;
        const HOST_RIP: u64 = 0x6c16;
        const WINDOW: usize = 24;
        let base = pe.optional_header().ImageBase;
        let mut entries = Vec::new();
        for section in pe.section_headers() {
            if section.Characteristics & 0x2000_0000 == 0 {
                continue;
            }
            let Ok(bytes) = pe.get_section_bytes(section) else {
                continue;
            };
            let ip = base + u64::from(section.VirtualAddress);
            let mut decoder = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE);
            let mut recent: std::collections::VecDeque<Instruction> = Default::default();
            for instruction in &mut decoder {
                if instruction.mnemonic() == Mnemonic::Vmwrite
                    && instruction.op0_kind() == OpKind::Register
                    && instruction.op1_kind() == OpKind::Register
                {
                    let last_write = |register: Register| {
                        recent.iter().rev().find(|earlier| {
                            earlier.op0_kind() == OpKind::Register
                                && earlier.op0_register().full_register()
                                    == register.full_register()
                        })
                    };
                    let field = last_write(instruction.op0_register()).filter(|earlier| {
                        earlier.mnemonic() == Mnemonic::Mov
                            && earlier.op1_kind() != OpKind::Register
                            && earlier.op1_kind() != OpKind::Memory
                            && earlier.immediate(1) == HOST_RIP
                    });
                    let value = last_write(instruction.op1_register()).filter(|earlier| {
                        earlier.mnemonic() == Mnemonic::Lea && earlier.is_ip_rel_memory_operand()
                    });
                    if let (Some(_), Some(lea)) = (field, value) {
                        let rva = u32::try_from(lea.ip_rel_memory_address() - base).unwrap();
                        if !entries.contains(&rva) {
                            entries.push(rva);
                        }
                    }
                }
                if recent.len() == WINDOW {
                    recent.pop_front();
                }
                recent.push_back(instruction);
            }
        }
        entries
    }

    /// The layout of real `hvix64` builds, which are not redistributable:
    /// `NTOSEYE_HVIX64_IMAGES` lists image paths, one per line, such as
    /// those `tools/fetch_hvix64.py` downloads. Builds have
    /// a fast-path entry that saves only volatile registers elsewhere, which
    /// must be refused; every entry that is accepted must agree with the
    /// others of its image, and each image must have one. `cargo test --lib
    /// exit_registers -- --ignored --nocapture` prints them.
    #[test]
    #[ignore = "needs hvix64 images named by NTOSEYE_HVIX64_IMAGES"]
    fn derives_the_layout_of_real_builds() {
        use pelite::pe64::{Pe, PeFile};
        let images = std::env::var("NTOSEYE_HVIX64_IMAGES").expect("NTOSEYE_HVIX64_IMAGES");
        let mut failures = Vec::new();
        for path in images
            .lines()
            .map(str::trim)
            .filter(|path| !path.is_empty())
        {
            let data = std::fs::read(path).unwrap();
            let pe = PeFile::from_bytes(&data).unwrap();
            let base = pe.optional_header().ImageBase;
            let mut accepted: Vec<ExitRegisterLayout> = Vec::new();
            for rva in host_rip_writes(pe) {
                let code = pe.derva_slice::<u8>(rva, ENTRY_CODE_BYTES).unwrap();
                match derive(code, base + u64::from(rva)) {
                    Ok(layout) => {
                        println!(
                            "{path} {rva:#x}: block {:x?}, offsets {:x?}, stores end +{:#x}",
                            layout.block_loads,
                            layout.offsets,
                            layout.stores_end - base - u64::from(rva)
                        );
                        accepted.push(layout);
                    }
                    Err(error) => println!("{path} {rva:#x}: refused: {error}"),
                }
            }
            if accepted.is_empty() {
                failures.push(format!(
                    "{path}: no entry point saves the registers in one block"
                ));
            } else if accepted.iter().any(|layout| {
                layout.block_loads != accepted[0].block_loads
                    || layout.offsets != accepted[0].offsets
            }) {
                failures.push(format!("{path}: entry points disagree on the block"));
            }
        }
        assert!(failures.is_empty(), "{failures:#?}");
    }
}
