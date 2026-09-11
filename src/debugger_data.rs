use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind, Register};
use kdmp_parser::structs::{DbgKdDebugDataHeader64, KdDebuggerData64};
use std::collections::HashSet;
use std::fmt;
use std::mem::{offset_of, size_of};

use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::types::VirtAddr;

const KDBG_OWNER_TAG: u32 = 0x4742_444b;
const KDBG_HEADER_SIZE: usize = size_of::<DbgKdDebugDataHeader64>();
const KDBG_OWNER_TAG_OFFSET: usize = offset_of!(DbgKdDebugDataHeader64, owner_tag);
const KDBG_REMOTE_SIZE_OFFSET: usize = offset_of!(DbgKdDebugDataHeader64, size);
const KDBG_MAX_REMOTE_SIZE: usize = 0x4000;
const KDBG_LIST_LIMIT: usize = 64;

// `KDDEBUGGER_DATA64` is an append-only debugger wire/container ABI. Derive
// offsets from kdmp-parser's SDK-sourced `#[repr(C)]` definition rather than
// maintaining a second numeric copy here.
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
        let bytes = self.bytes.get(offset..offset.checked_add(8)?)?;
        Some(u64::from_le_bytes(bytes.try_into().ok()?))
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
    if read_u32(&header, KDBG_OWNER_TAG_OFFSET)? != KDBG_OWNER_TAG {
        return None;
    }
    let remote_size = read_u32(&header, KDBG_REMOTE_SIZE_OFFSET)?;
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

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}

/// Evaluate a deliberately small, straight-line subset of an x64 memory-manager
/// getter. Unknown instructions or control flow are rejected rather than
/// guessing a counter location.
pub fn read_counter_from_getter<M: MemoryOps<VirtAddr>>(
    memory: &M,
    address: VirtAddr,
    expected_system_partition: VirtAddr,
) -> Result<MetadataValue<u64>> {
    const MAX_GETTER_BYTES: usize = 128;
    const MAX_INSTRUCTIONS: usize = 24;

    let mut code = [0u8; MAX_GETTER_BYTES];
    memory.read_bytes(address, &mut code)?;
    let mut decoder = Decoder::with_ip(64, &code, address.0, DecoderOptions::NONE);
    // The exported getters index the partition table with CX. Slot zero is
    // accepted only when it resolves to the independently symbolized
    // MiSystemPartition object.
    let mut registers = [None, Some(0), None];
    let mut memory_loads = 0usize;
    let mut saw_system_partition = false;

    for _ in 0..MAX_INSTRUCTIONS {
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
                let value = registers[0].ok_or_else(|| {
                    Error::DebugInfo(format!(
                        "memory getter {address:#x} returned without producing RAX"
                    ))
                })?;
                if memory_loads < 3 || !saw_system_partition {
                    return Err(Error::DebugInfo(format!(
                        "memory getter {address:#x} did not follow the validated system-partition pointer chain"
                    )));
                }
                return Ok(MetadataValue {
                    value,
                    source: MetadataSource::KernelCode,
                });
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
            read_counter_from_getter(&memory, VirtAddr(0x1000), VirtAddr(0x5000)).unwrap();
        assert_eq!(counter.value, 0x1234);
        assert_eq!(counter.source, MetadataSource::KernelCode);
    }

    #[test]
    fn rejects_getter_control_flow() {
        let mut code = vec![0u8; 128];
        code[..5].copy_from_slice(&[0xe9, 0, 0, 0, 0]);
        let memory = TestMemory::with_regions(&[(0x1000, code)]);

        assert!(
            read_counter_from_getter(&memory, VirtAddr(0x1000), VirtAddr(0x5000))
                .unwrap_err()
                .to_string()
                .contains("unsupported instruction")
        );
    }
}
