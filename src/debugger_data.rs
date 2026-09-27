use crate::dmp::structs::{DbgKdDebugDataHeader64, KdDebuggerData64};
use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind, Register};
use std::collections::HashSet;
use std::fmt;
use std::mem::{offset_of, size_of};

use crate::backend::MemoryOps;
use crate::bytes::{get_u64, read_u32};
use crate::error::{Error, Result};
use crate::types::{Arch, VirtAddr};

const KDBG_OWNER_TAG: u32 = 0x4742_444b;
const KDBG_HEADER_SIZE: usize = size_of::<DbgKdDebugDataHeader64>();
const KDBG_OWNER_TAG_OFFSET: usize = offset_of!(DbgKdDebugDataHeader64, owner_tag);
const KDBG_REMOTE_SIZE_OFFSET: usize = offset_of!(DbgKdDebugDataHeader64, size);
const KDBG_MAX_REMOTE_SIZE: usize = 0x4000;
const KDBG_LIST_LIMIT: usize = 64;

// `KDDEBUGGER_DATA64` is an append-only debugger wire/container ABI. Derive
// offsets from the SDK-sourced `#[repr(C)]` definition in `crate::dmp::structs`
// rather than maintaining a second numeric copy here.
const KERN_BASE_OFFSET: usize = offset_of!(KdDebuggerData64, kern_base);
const PS_LOADED_MODULE_LIST_OFFSET: usize = offset_of!(KdDebuggerData64, ps_loaded_module_list);
const PS_ACTIVE_PROCESS_HEAD_OFFSET: usize = offset_of!(KdDebuggerData64, ps_active_process_head);
const PSP_CID_TABLE_OFFSET: usize = offset_of!(KdDebuggerData64, psp_cid_table);
const MM_NUMBER_OF_PHYSICAL_PAGES_OFFSET: usize =
    offset_of!(KdDebuggerData64, mm_number_of_physical_pages);
const MM_MAXIMUM_NONPAGED_POOL_IN_BYTES_OFFSET: usize =
    offset_of!(KdDebuggerData64, mm_maximum_non_paged_pool_in_bytes);
const MM_PAGE_SIZE_OFFSET: usize = offset_of!(KdDebuggerData64, mm_page_size);
const MM_SIZE_OF_PAGED_POOL_IN_BYTES_OFFSET: usize =
    offset_of!(KdDebuggerData64, mm_size_of_paged_pool_in_bytes);
const MM_TOTAL_COMMIT_LIMIT_OFFSET: usize = offset_of!(KdDebuggerData64, mm_total_commit_limit);
const MM_TOTAL_COMMITTED_PAGES_OFFSET: usize =
    offset_of!(KdDebuggerData64, mm_total_committed_pages);
const MM_AVAILABLE_PAGES_OFFSET: usize = offset_of!(KdDebuggerData64, mm_available_pages);
const MM_RESIDENT_AVAILABLE_PAGES_OFFSET: usize =
    offset_of!(KdDebuggerData64, mm_resident_available_pages);
const KNOWN_PREFIX_SIZE: usize = MM_RESIDENT_AVAILABLE_PAGES_OFFSET + 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataSource {
    KdVersion,
    KernelSymbol,
    DumpHeader,
    KernelCode,
}

impl fmt::Display for MetadataSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::KdVersion => "KD GetVersion",
            Self::KernelSymbol => "kernel symbol",
            Self::DumpHeader => "dump header",
            Self::KernelCode => "kernel getter code",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetadataValue<T> {
    pub value: T,
    pub source: MetadataSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebuggerDataCandidate {
    pub address: VirtAddr,
    pub source: MetadataSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebuggerDataBlock {
    pub address: VirtAddr,
    pub source: MetadataSource,
    pub remote_size: u32,
    bytes: Vec<u8>,
}

impl DebuggerDataBlock {
    pub fn kern_base(&self) -> Option<MetadataValue<VirtAddr>> {
        self.u64_at(KERN_BASE_OFFSET)
            .filter(|value| *value != 0)
            .map(VirtAddr)
            .map(|value| self.sourced(value))
    }

    pub fn ps_loaded_module_list(&self) -> Option<MetadataValue<VirtAddr>> {
        self.pointer_at(PS_LOADED_MODULE_LIST_OFFSET)
    }

    pub fn ps_active_process_head(&self) -> Option<MetadataValue<VirtAddr>> {
        self.pointer_at(PS_ACTIVE_PROCESS_HEAD_OFFSET)
    }

    pub fn psp_cid_table(&self) -> Option<MetadataValue<VirtAddr>> {
        self.pointer_at(PSP_CID_TABLE_OFFSET)
    }

    pub fn mm_number_of_physical_pages_address(&self) -> Option<MetadataValue<VirtAddr>> {
        self.pointer_at(MM_NUMBER_OF_PHYSICAL_PAGES_OFFSET)
    }

    pub fn mm_maximum_nonpaged_pool_in_bytes_address(&self) -> Option<MetadataValue<VirtAddr>> {
        self.pointer_at(MM_MAXIMUM_NONPAGED_POOL_IN_BYTES_OFFSET)
    }

    pub fn mm_page_size(&self) -> Option<MetadataValue<u64>> {
        self.value_at(MM_PAGE_SIZE_OFFSET)
    }

    pub fn mm_size_of_paged_pool_in_bytes_address(&self) -> Option<MetadataValue<VirtAddr>> {
        self.pointer_at(MM_SIZE_OF_PAGED_POOL_IN_BYTES_OFFSET)
    }

    pub fn mm_total_commit_limit_address(&self) -> Option<MetadataValue<VirtAddr>> {
        self.pointer_at(MM_TOTAL_COMMIT_LIMIT_OFFSET)
    }

    pub fn mm_total_committed_pages_address(&self) -> Option<MetadataValue<VirtAddr>> {
        self.pointer_at(MM_TOTAL_COMMITTED_PAGES_OFFSET)
    }

    pub fn mm_available_pages_address(&self) -> Option<MetadataValue<VirtAddr>> {
        self.pointer_at(MM_AVAILABLE_PAGES_OFFSET)
    }

    pub fn mm_resident_available_pages_address(&self) -> Option<MetadataValue<VirtAddr>> {
        self.pointer_at(MM_RESIDENT_AVAILABLE_PAGES_OFFSET)
    }

    fn pointer_at(&self, offset: usize) -> Option<MetadataValue<VirtAddr>> {
        self.u64_at(offset)
            .filter(|value| *value != 0)
            .map(VirtAddr)
            .map(|value| self.sourced(value))
    }

    fn value_at(&self, offset: usize) -> Option<MetadataValue<u64>> {
        self.u64_at(offset).map(|value| self.sourced(value))
    }

    fn sourced<T>(&self, value: T) -> MetadataValue<T> {
        MetadataValue {
            value,
            source: self.source,
        }
    }

    fn u64_at(&self, offset: usize) -> Option<u64> {
        get_u64(&self.bytes, offset)
    }
}

pub fn locate_debugger_data_block<M: MemoryOps<VirtAddr>>(
    memory: &M,
    candidates: impl IntoIterator<Item = DebuggerDataCandidate>,
    expected_kernel_base: Option<VirtAddr>,
) -> Option<DebuggerDataBlock> {
    for candidate in candidates {
        if let Some(block) = parse_debugger_data_block(memory, candidate, expected_kernel_base) {
            return Some(block);
        }
        if let Some(block) = walk_debugger_data_list(memory, candidate, expected_kernel_base) {
            return Some(block);
        }
    }
    None
}

fn parse_debugger_data_block<M: MemoryOps<VirtAddr>>(
    memory: &M,
    candidate: DebuggerDataCandidate,
    expected_kernel_base: Option<VirtAddr>,
) -> Option<DebuggerDataBlock> {
    let mut header = [0u8; KDBG_HEADER_SIZE];
    memory.read_bytes(candidate.address, &mut header).ok()?;
    if read_u32(&header, KDBG_OWNER_TAG_OFFSET) != KDBG_OWNER_TAG {
        return None;
    }
    let remote_size = read_u32(&header, KDBG_REMOTE_SIZE_OFFSET);
    let remote_size_usize = usize::try_from(remote_size).ok()?;
    if !(KDBG_HEADER_SIZE..=KDBG_MAX_REMOTE_SIZE).contains(&remote_size_usize) {
        return None;
    }

    let mut bytes = vec![0u8; remote_size_usize.min(KNOWN_PREFIX_SIZE)];
    memory.read_bytes(candidate.address, &mut bytes).ok()?;
    let block = DebuggerDataBlock {
        address: candidate.address,
        source: candidate.source,
        remote_size,
        bytes,
    };
    if expected_kernel_base.is_some_and(|expected| {
        block
            .kern_base()
            .is_none_or(|actual| actual.value != expected)
    }) {
        return None;
    }
    Some(block)
}

fn walk_debugger_data_list<M: MemoryOps<VirtAddr>>(
    memory: &M,
    candidate: DebuggerDataCandidate,
    expected_kernel_base: Option<VirtAddr>,
) -> Option<DebuggerDataBlock> {
    let mut current = read_pointer(memory, candidate.address)?;
    let mut seen = HashSet::new();
    for _ in 0..KDBG_LIST_LIMIT {
        if current.is_zero() || current == candidate.address || !seen.insert(current.0) {
            break;
        }
        let entry = DebuggerDataCandidate {
            address: current,
            source: candidate.source,
        };
        if let Some(block) = parse_debugger_data_block(memory, entry, expected_kernel_base) {
            return Some(block);
        }
        current = read_pointer(memory, current)?;
    }
    None
}

fn read_pointer<M: MemoryOps<VirtAddr>>(memory: &M, address: VirtAddr) -> Option<VirtAddr> {
    let mut bytes = [0u8; 8];
    memory.read_bytes(address, &mut bytes).ok()?;
    Some(VirtAddr(u64::from_le_bytes(bytes)))
}

/// Most bytes of a getter evaluated, and instructions run.
const MAX_GETTER_BYTES: usize = 128;
const MAX_GETTER_INSTRUCTIONS: usize = 24;

/// Evaluate a deliberately small, straight-line subset of a memory-manager
/// getter (`MmGetAvailablePages`, ...) compiled for `arch`, which returns a
/// counter of the partition its first argument selects. The argument is 0,
/// the system partition, and the pointer chain must pass through
/// `expected_system_partition`. Unknown instructions or control flow are
/// rejected rather than guessing a counter location.
pub fn read_counter_from_getter<M: MemoryOps<VirtAddr>>(
    memory: &M,
    arch: Arch,
    address: VirtAddr,
    expected_system_partition: VirtAddr,
) -> Result<MetadataValue<u64>> {
    match arch {
        Arch::Amd64 => read_counter_from_x64_getter(memory, address, expected_system_partition),
        Arch::Arm64 => read_counter_from_a64_getter(memory, address, expected_system_partition),
    }
}

/// The counter a getter returned, once it followed the validated chain: at
/// least the partition table, the partition, and the counter loaded, the
/// partition being the system one.
fn getter_result(
    address: VirtAddr,
    value: Option<u64>,
    memory_loads: usize,
    saw_system_partition: bool,
) -> Result<MetadataValue<u64>> {
    let value = value.ok_or_else(|| {
        Error::DebugInfo(format!(
            "memory getter {address:#x} returned without producing its result register"
        ))
    })?;
    if memory_loads < 3 || !saw_system_partition {
        return Err(Error::DebugInfo(format!(
            "memory getter {address:#x} did not follow the validated system-partition pointer chain"
        )));
    }
    Ok(MetadataValue {
        value,
        source: MetadataSource::KernelCode,
    })
}

fn read_counter_from_x64_getter<M: MemoryOps<VirtAddr>>(
    memory: &M,
    address: VirtAddr,
    expected_system_partition: VirtAddr,
) -> Result<MetadataValue<u64>> {
    let mut code = [0u8; MAX_GETTER_BYTES];
    memory.read_bytes(address, &mut code)?;
    let mut decoder = Decoder::with_ip(64, &code, address.0, DecoderOptions::NONE);
    // The exported getters index the partition table with CX. Slot zero is
    // accepted only when it resolves to the independently symbolized
    // MiSystemPartition object.
    let mut registers = [None, Some(0), None];
    let mut memory_loads = 0usize;
    let mut saw_system_partition = false;

    for _ in 0..MAX_GETTER_INSTRUCTIONS {
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            break;
        }
        match instruction.mnemonic() {
            Mnemonic::Mov => {
                let destination = instruction.op0_register();
                let (_, destination_width) = register_slot(destination).ok_or_else(|| {
                    unsupported_getter_instruction(address, &instruction.to_string())
                })?;
                let value = match instruction.op1_kind() {
                    OpKind::Register => read_register(&registers, instruction.op1_register())
                        .ok_or_else(|| {
                            unsupported_getter_instruction(address, &instruction.to_string())
                        })?,
                    OpKind::Memory => {
                        let effective =
                            effective_address(&instruction, &registers).ok_or_else(|| {
                                unsupported_getter_instruction(address, &instruction.to_string())
                            })?;
                        memory_loads += 1;
                        let value = read_unsigned(memory, effective, destination_width)?;
                        saw_system_partition |= value == expected_system_partition.0;
                        value
                    }
                    _ => {
                        return Err(unsupported_getter_instruction(
                            address,
                            &instruction.to_string(),
                        ));
                    }
                };
                write_register(&mut registers, destination, value).ok_or_else(|| {
                    unsupported_getter_instruction(address, &instruction.to_string())
                })?;
            }
            Mnemonic::Movzx if instruction.op1_kind() == OpKind::Register => {
                let source = instruction.op1_register();
                let value = read_register(&registers, source).ok_or_else(|| {
                    unsupported_getter_instruction(address, &instruction.to_string())
                })?;
                write_register(&mut registers, instruction.op0_register(), value).ok_or_else(
                    || unsupported_getter_instruction(address, &instruction.to_string()),
                )?;
            }
            Mnemonic::Nop => {}
            Mnemonic::Ret => {
                return getter_result(address, registers[0], memory_loads, saw_system_partition);
            }
            _ => {
                return Err(unsupported_getter_instruction(
                    address,
                    &instruction.to_string(),
                ));
            }
        }
    }

    Err(Error::DebugInfo(format!(
        "memory getter {address:#x} has no return within the bounded straight-line prefix"
    )))
}

/// [`read_counter_from_x64_getter`] for an ARM64 kernel's getters: `adrp`
/// and `add` to `MiState`, loads through the partition table (`ldr`,
/// `ldar`, with an immediate, register, or shifted-register offset), the
/// partition index taken with `ubfx`, and `mov` of an offset.
fn read_counter_from_a64_getter<M: MemoryOps<VirtAddr>>(
    memory: &M,
    address: VirtAddr,
    expected_system_partition: VirtAddr,
) -> Result<MetadataValue<u64>> {
    use bad64::{Imm, Op, Operand, Shift};

    let mut code = [0u8; MAX_GETTER_BYTES];
    memory.read_bytes(address, &mut code)?;
    // x0..x30, and slot 31 the zero register. x0 is the partition index.
    let mut registers = [None; 32];
    registers[0] = Some(0);
    registers[31] = Some(0);
    let mut memory_loads = 0usize;
    let mut saw_system_partition = false;
    let immediate = |imm: &Imm| match *imm {
        Imm::Signed(value) => value as u64,
        Imm::Unsigned(value) => value,
    };

    for (index, word) in code
        .as_chunks::<4>()
        .0
        .iter()
        .take(MAX_GETTER_INSTRUCTIONS)
        .enumerate()
    {
        let pc = address.0 + 4 * index as u64;
        let Ok(instruction) = bad64::decode(u32::from_le_bytes(*word), pc) else {
            break;
        };
        let unsupported = || unsupported_getter_instruction(address, &instruction.to_string());
        let read = |registers: &[Option<u64>; 32], operand: &Operand| -> Option<u64> {
            match operand {
                Operand::Reg { reg, arrspec: None } => {
                    let (slot, width) = a64_register(*reg)?;
                    Some(registers[slot]? & width_mask(width))
                }
                Operand::Imm32 { imm, shift } | Operand::Imm64 { imm, shift } => match shift {
                    None => Some(immediate(imm)),
                    Some(Shift::LSL(amount)) => immediate(imm).checked_shl(*amount),
                    Some(_) => None,
                },
                Operand::Label(imm) => Some(immediate(imm)),
                _ => None,
            }
        };
        let operands = instruction.operands();
        let destination = match operands.first() {
            Some(Operand::Reg { reg, arrspec: None }) => a64_register(*reg),
            _ => None,
        };
        let value = match instruction.op() {
            Op::RET => {
                return getter_result(address, registers[0], memory_loads, saw_system_partition);
            }
            Op::NOP => continue,
            Op::ADRP | Op::MOV => operands.get(1).and_then(|source| read(&registers, source)),
            Op::ADD => match operands {
                [_, left, right] => read(&registers, left)
                    .zip(read(&registers, right))
                    .map(|(left, right)| left.wrapping_add(right)),
                _ => None,
            },
            Op::UBFX => match operands {
                [_, source, lsb, width] => read(&registers, source)
                    .zip(read(&registers, lsb))
                    .zip(read(&registers, width))
                    .and_then(|((source, lsb), width)| {
                        Some(source.checked_shr(u32::try_from(lsb).ok()?)? & width_mask_bits(width))
                    }),
                _ => None,
            },
            Op::LDR | Op::LDAR => {
                let effective = match operands.get(1) {
                    Some(Operand::MemReg(base)) => {
                        a64_register(*base).and_then(|(slot, _)| registers[slot])
                    }
                    Some(Operand::MemOffset {
                        reg,
                        offset,
                        mul_vl: false,
                        arrspec: None,
                    }) => a64_register(*reg)
                        .and_then(|(slot, _)| registers[slot])
                        .map(|base| base.wrapping_add(immediate(offset))),
                    Some(Operand::MemExt {
                        regs: [base, index],
                        shift: None | Some(Shift::LSL(_)),
                        arrspec: None,
                    }) => {
                        let shift = match operands.get(1) {
                            Some(Operand::MemExt {
                                shift: Some(Shift::LSL(amount)),
                                ..
                            }) => *amount,
                            _ => 0,
                        };
                        let base = a64_register(*base).and_then(|(slot, _)| registers[slot]);
                        let index = a64_register(*index).and_then(|(slot, _)| registers[slot]);
                        base.zip(index).and_then(|(base, index)| {
                            Some(base.wrapping_add(index.checked_shl(shift)?))
                        })
                    }
                    _ => None,
                };
                match (effective, destination) {
                    (Some(effective), Some((_, width))) => {
                        memory_loads += 1;
                        let value = read_unsigned(memory, VirtAddr(effective), width)?;
                        saw_system_partition |= value == expected_system_partition.0;
                        Some(value)
                    }
                    _ => None,
                }
            }
            _ => None,
        };
        let (Some(value), Some((slot, width))) = (value, destination) else {
            return Err(unsupported());
        };
        // A write to a W register zero-extends; the zero register discards.
        if slot != 31 {
            registers[slot] = Some(value & width_mask(width));
        }
    }

    Err(Error::DebugInfo(format!(
        "memory getter {address:#x} has no return within the bounded straight-line prefix"
    )))
}

/// An A64 general-purpose register's number (31 for the zero register) and
/// width in bytes; `None` for any other register (sp, SIMD).
fn a64_register(register: bad64::Reg) -> Option<(usize, usize)> {
    use bad64::Reg;
    let number = register as u32;
    if (Reg::X0 as u32..=Reg::X30 as u32).contains(&number) {
        return Some(((number - Reg::X0 as u32) as usize, 8));
    }
    if (Reg::W0 as u32..=Reg::W30 as u32).contains(&number) {
        return Some(((number - Reg::W0 as u32) as usize, 4));
    }
    match register {
        Reg::XZR => Some((31, 8)),
        Reg::WZR => Some((31, 4)),
        _ => None,
    }
}

fn width_mask(width: usize) -> u64 {
    width_mask_bits(width as u64 * 8)
}

fn width_mask_bits(bits: u64) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1 << bits) - 1
    }
}

fn effective_address(
    instruction: &iced_x86::Instruction,
    registers: &[Option<u64>; 3],
) -> Option<VirtAddr> {
    if instruction.is_ip_rel_memory_operand() {
        return Some(VirtAddr(instruction.ip_rel_memory_address()));
    }
    let base = match instruction.memory_base() {
        Register::None => 0,
        register => read_register(registers, register)?,
    };
    let index = match instruction.memory_index() {
        Register::None => 0,
        register => read_register(registers, register)?
            .checked_mul(u64::from(instruction.memory_index_scale()))?,
    };
    Some(VirtAddr(
        base.wrapping_add(index)
            .wrapping_add(instruction.memory_displacement64()),
    ))
}

fn read_unsigned<M: MemoryOps<VirtAddr>>(
    memory: &M,
    address: VirtAddr,
    width: usize,
) -> Result<u64> {
    let mut bytes = [0u8; 8];
    memory.read_bytes(address, &mut bytes[..width])?;
    Ok(u64::from_le_bytes(bytes))
}

fn register_slot(register: Register) -> Option<(usize, usize)> {
    match register {
        Register::RAX => Some((0, 8)),
        Register::EAX => Some((0, 4)),
        Register::AX => Some((0, 2)),
        Register::AL => Some((0, 1)),
        Register::RCX => Some((1, 8)),
        Register::ECX => Some((1, 4)),
        Register::CX => Some((1, 2)),
        Register::CL => Some((1, 1)),
        Register::RDX => Some((2, 8)),
        Register::EDX => Some((2, 4)),
        Register::DX => Some((2, 2)),
        Register::DL => Some((2, 1)),
        _ => None,
    }
}

fn read_register(registers: &[Option<u64>; 3], register: Register) -> Option<u64> {
    let (slot, width) = register_slot(register)?;
    let value = registers[slot]?;
    Some(match width {
        1 => value & 0xff,
        2 => value & 0xffff,
        4 => value & 0xffff_ffff,
        8 => value,
        _ => unreachable!(),
    })
}

fn write_register(registers: &mut [Option<u64>; 3], register: Register, value: u64) -> Option<()> {
    let (slot, width) = register_slot(register)?;
    // x86 semantics: 8/16-bit writes keep the register's upper bits, 32-bit
    // writes zero-extend.
    let previous = registers[slot].unwrap_or(0);
    registers[slot] = Some(match width {
        1 => (previous & !0xff) | (value & 0xff),
        2 => (previous & !0xffff) | (value & 0xffff),
        4 => value & 0xffff_ffff,
        8 => value,
        _ => unreachable!(),
    });
    Some(())
}

fn unsupported_getter_instruction(address: VirtAddr, instruction: &str) -> Error {
    Error::DebugInfo(format!(
        "memory getter {address:#x} contains unsupported instruction `{instruction}`"
    ))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::error::{Error, Result};

    struct TestMemory {
        bytes: HashMap<u64, u8>,
    }

    impl TestMemory {
        fn with_regions(regions: &[(u64, Vec<u8>)]) -> Self {
            let mut bytes = HashMap::new();
            for (base, region) in regions {
                for (offset, byte) in region.iter().enumerate() {
                    bytes.insert(base + offset as u64, *byte);
                }
            }
            Self { bytes }
        }
    }

    impl MemoryOps<VirtAddr> for TestMemory {
        fn read_bytes(&self, addr: VirtAddr, buf: &mut [u8]) -> Result<()> {
            for (offset, byte) in buf.iter_mut().enumerate() {
                *byte = *self
                    .bytes
                    .get(&(addr.0 + offset as u64))
                    .ok_or_else(|| Error::BadVirtualAddress(addr))?;
            }
            Ok(())
        }

        fn write_bytes(&self, _addr: VirtAddr, _buf: &[u8]) -> Result<()> {
            unreachable!()
        }
    }

    fn block(size: usize, kernel_base: u64) -> Vec<u8> {
        let mut bytes = vec![0u8; size];
        bytes[KDBG_OWNER_TAG_OFFSET..KDBG_OWNER_TAG_OFFSET + 4]
            .copy_from_slice(&KDBG_OWNER_TAG.to_le_bytes());
        bytes[KDBG_REMOTE_SIZE_OFFSET..KDBG_REMOTE_SIZE_OFFSET + 4]
            .copy_from_slice(&(size as u32).to_le_bytes());
        bytes[KERN_BASE_OFFSET..KERN_BASE_OFFSET + 8].copy_from_slice(&kernel_base.to_le_bytes());
        bytes
    }

    #[test]
    fn parses_only_fields_present_in_remote_size() {
        let mut bytes = block(MM_TOTAL_COMMIT_LIMIT_OFFSET + 8, 0xffff_f800_0000_0000);
        bytes[MM_NUMBER_OF_PHYSICAL_PAGES_OFFSET..MM_NUMBER_OF_PHYSICAL_PAGES_OFFSET + 8]
            .copy_from_slice(&0x1234u64.to_le_bytes());
        bytes[MM_TOTAL_COMMIT_LIMIT_OFFSET..MM_TOTAL_COMMIT_LIMIT_OFFSET + 8]
            .copy_from_slice(&0x5678u64.to_le_bytes());
        let memory = TestMemory::with_regions(&[(0x1000, bytes)]);

        let parsed = locate_debugger_data_block(
            &memory,
            [DebuggerDataCandidate {
                address: VirtAddr(0x1000),
                source: MetadataSource::KernelSymbol,
            }],
            Some(VirtAddr(0xffff_f800_0000_0000)),
        )
        .unwrap();

        assert_eq!(
            parsed.remote_size as usize,
            MM_TOTAL_COMMIT_LIMIT_OFFSET + 8
        );
        assert_eq!(
            parsed.mm_number_of_physical_pages_address().unwrap().value,
            VirtAddr(0x1234)
        );
        assert_eq!(
            parsed.mm_total_commit_limit_address().unwrap().value,
            VirtAddr(0x5678)
        );
        assert!(parsed.mm_total_committed_pages_address().is_none());
    }

    #[test]
    fn follows_a_list_head_and_rejects_wrong_kernel() {
        let head = 0x1000u64;
        let first = 0x2000u64;
        let mut head_bytes = vec![0u8; 8];
        head_bytes.copy_from_slice(&first.to_le_bytes());
        let mut bytes = block(KNOWN_PREFIX_SIZE, 0xffff_f800_1234_0000);
        bytes[..8].copy_from_slice(&head.to_le_bytes());
        let memory = TestMemory::with_regions(&[(head, head_bytes), (first, bytes)]);
        let candidate = DebuggerDataCandidate {
            address: VirtAddr(head),
            source: MetadataSource::KdVersion,
        };

        assert!(
            locate_debugger_data_block(&memory, [candidate], Some(VirtAddr(0xffff_f800_0000_0000)))
                .is_none()
        );
        assert_eq!(
            locate_debugger_data_block(&memory, [candidate], Some(VirtAddr(0xffff_f800_1234_0000)))
                .unwrap()
                .address,
            VirtAddr(first)
        );
    }

    #[test]
    fn rejects_invalid_owner_and_unbounded_size() {
        let invalid_owner = vec![0u8; KDBG_HEADER_SIZE];
        let mut invalid_size = vec![0u8; KDBG_HEADER_SIZE];
        invalid_size[KDBG_OWNER_TAG_OFFSET..KDBG_OWNER_TAG_OFFSET + 4]
            .copy_from_slice(&KDBG_OWNER_TAG.to_le_bytes());
        invalid_size[KDBG_REMOTE_SIZE_OFFSET..KDBG_REMOTE_SIZE_OFFSET + 4]
            .copy_from_slice(&0x4001u32.to_le_bytes());
        let memory = TestMemory::with_regions(&[(0x1000, invalid_owner), (0x2000, invalid_size)]);

        for address in [0x1000, 0x2000] {
            assert!(
                locate_debugger_data_block(
                    &memory,
                    [DebuggerDataCandidate {
                        address: VirtAddr(address),
                        source: MetadataSource::DumpHeader,
                    }],
                    None
                )
                .is_none()
            );
        }
    }

    #[test]
    fn evaluates_supported_partition_getter_chain() {
        let mut code = vec![0u8; 128];
        let instructions = [
            0x48, 0x8b, 0x05, 0xf9, 0x0f, 0x00, 0x00, // mov rax,[rip+0xff9]
            0x0f, 0xb7, 0xd1, // movzx edx,cx
            0x48, 0x8b, 0x04, 0xd0, // mov rax,[rax+rdx*8]
            0x48, 0x8b, 0x80, 0x50, 0x00, 0x00, 0x00, // mov rax,[rax+0x50]
            0xc3, // ret
        ];
        code[..instructions.len()].copy_from_slice(&instructions);
        let memory = TestMemory::with_regions(&[
            (0x1000, code),
            (0x2000, 0x4000u64.to_le_bytes().to_vec()),
            (0x4000, 0x5000u64.to_le_bytes().to_vec()),
            (0x5050, 0x1234u64.to_le_bytes().to_vec()),
        ]);

        let counter =
            read_counter_from_getter(&memory, Arch::Amd64, VirtAddr(0x1000), VirtAddr(0x5000))
                .unwrap();
        assert_eq!(counter.value, 0x1234);
        assert_eq!(counter.source, MetadataSource::KernelCode);
    }

    #[test]
    fn rejects_getter_control_flow() {
        let mut code = vec![0u8; 128];
        code[..5].copy_from_slice(&[0xe9, 0, 0, 0, 0]);
        let memory = TestMemory::with_regions(&[(0x1000, code)]);

        assert!(
            read_counter_from_getter(&memory, Arch::Amd64, VirtAddr(0x1000), VirtAddr(0x5000))
                .unwrap_err()
                .to_string()
                .contains("unsupported instruction")
        );
    }

    /// ARM64 Windows 11 22631's `MmGetTotalCommittedPages`: `adrp`/`add` to
    /// `MiState`, the partition table at +0x1fc8 indexed by the argument's
    /// low 16 bits, then an acquire load at +0x4668 of the partition.
    #[test]
    fn evaluates_an_arm64_partition_getter() {
        const GETTER: u64 = 0xffff_f803_3efb_8bf0;
        const MI_STATE: u64 = 0xffff_f803_3f83_c980;
        const TABLE: u64 = 0xffff_b182_0000_1000;
        const PARTITION: u64 = 0xffff_f803_3f84_2180;
        let words: [u32; 9] = [
            0x9000_4428, // adrp x8, MiState page
            0x9126_0108, // add x8, x8, #0x980
            0xf94f_e509, // ldr x9, [x8, #0x1fc8]
            0xd340_3c0a, // ubfx x10, x0, #0, #16
            0xd288_cd08, // mov x8, #0x4668
            0xf86a_792a, // ldr x10, [x9, x10, lsl #3]
            0x8b08_0148, // add x8, x10, x8
            0xc8df_fd00, // ldar x0, [x8]
            0xd65f_03c0, // ret
        ];
        let mut code = vec![0u8; 128];
        for (index, word) in words.iter().enumerate() {
            code[4 * index..4 * index + 4].copy_from_slice(&word.to_le_bytes());
        }
        let memory = TestMemory::with_regions(&[
            (GETTER, code),
            (MI_STATE + 0x1fc8, TABLE.to_le_bytes().to_vec()),
            (TABLE, PARTITION.to_le_bytes().to_vec()),
            (PARTITION + 0x4668, 369_837u64.to_le_bytes().to_vec()),
        ]);

        let counter =
            read_counter_from_getter(&memory, Arch::Arm64, VirtAddr(GETTER), VirtAddr(PARTITION))
                .unwrap();
        assert_eq!(counter.value, 369_837);
        // A chain that never reaches the system partition is refused.
        let elsewhere = VirtAddr(0xffff_f803_3f84_0000);
        assert!(
            read_counter_from_getter(&memory, Arch::Arm64, VirtAddr(GETTER), elsewhere).is_err()
        );
    }
}
