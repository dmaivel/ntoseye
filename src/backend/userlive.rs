//! The memory of a live user-mode target: one process's address space behind
//! a process server, read and written by virtual address through the server's
//! own debug-memory calls.

use crate::base::error::{Error, Result};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// Windows `MEMORY_BASIC_INFORMATION` on a 64-bit target, as `VirtualQuery`
/// fills it: `{ PVOID BaseAddress; PVOID AllocationBase; DWORD
/// AllocationProtect; WORD PartitionId; SIZE_T RegionSize; DWORD State; DWORD
/// Protect; DWORD Type; }`. The two named holes are the structure's own
/// padding, which `#[repr(C)]` otherwise leaves unnamed; naming them is what
/// lets the bytes be read back as the structure itself.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, Immutable, KnownLayout)]
pub struct MemoryBasicInformation {
    pub base_address: u64,
    pub allocation_base: u64,
    pub allocation_protect: u32,
    pub partition_id: u16,
    /// The hole before the eight-byte-aligned `RegionSize`.
    pub reserved0: [u8; 2],
    pub region_size: u64,
    pub state: u32,
    pub protect: u32,
    /// `MEM_*` (`MEM_IMAGE`, `MEM_MAPPED`, `MEM_PRIVATE`).
    pub kind: u32,
    /// The structure's tail padding.
    pub reserved1: [u8; 4],
}

const _: () =
    assert!(core::mem::size_of::<MemoryBasicInformation>() == MemoryBasicInformation::SIZE);

impl MemoryBasicInformation {
    /// Bytes of the 64-bit structure.
    pub const SIZE: usize = 48;

    /// Read the bytes `VirtualQuery` filled. The bytes come from another
    /// process, so they are copied out rather than viewed in place: a
    /// `Vec<u8>` carries no alignment promise.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Self::read_from_bytes(bytes).map_err(|_| {
            Error::DebugInfo(format!(
                "VirtualQuery filled {} bytes, {} expected",
                bytes.len(),
                Self::SIZE
            ))
        })
    }
}

/// A live process's memory, as a process server serves it: by virtual
/// address, since the target is one process with one address space.
pub trait UserLiveMemory: Send + Sync {
    /// Read `buf` at `address` in `process`. A short read is an error.
    fn read(&self, process: u64, address: u64, buf: &mut [u8]) -> Result<()>;

    /// Write `buf` at `address` in `process`. A short write is an error.
    fn write(&self, process: u64, address: u64, buf: &[u8]) -> Result<()>;

    /// What `VirtualQuery` reports for `address` in `process`.
    fn query(&self, process: u64, address: u64) -> Result<MemoryBasicInformation>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bytes are the x64 `MEMORY_BASIC_INFORMATION`, read at the offsets
    /// the structure defines: `PartitionId` at 0x14, then `RegionSize` at
    /// 0x18 because of its eight-byte alignment.
    #[test]
    fn a_memory_basic_information_is_read_at_its_windows_offsets() {
        let mut bytes = [0u8; MemoryBasicInformation::SIZE];
        bytes[0..8].copy_from_slice(&0x1000_0000u64.to_le_bytes());
        bytes[8..16].copy_from_slice(&0x0fff_0000u64.to_le_bytes());
        bytes[16..20].copy_from_slice(&0x04u32.to_le_bytes());
        bytes[20..22].copy_from_slice(&7u16.to_le_bytes());
        bytes[24..32].copy_from_slice(&0x4200u64.to_le_bytes());
        bytes[32..36].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[36..40].copy_from_slice(&0x20u32.to_le_bytes());
        bytes[40..44].copy_from_slice(&0x100_0000u32.to_le_bytes());

        let info = MemoryBasicInformation::decode(&bytes).expect("48 bytes");
        assert_eq!(info.base_address, 0x1000_0000);
        assert_eq!(info.allocation_base, 0x0fff_0000);
        assert_eq!(info.allocation_protect, 4);
        assert_eq!(info.partition_id, 7);
        assert_eq!(info.region_size, 0x4200);
        assert_eq!(info.state, 0x1000);
        assert_eq!(info.protect, 0x20);
        assert_eq!(info.kind, 0x100_0000);
    }

    /// A 32-bit server fills `MEMORY_BASIC_INFORMATION32` (28 bytes), which
    /// this client refuses rather than misreading at the 64-bit offsets.
    #[test]
    fn a_short_query_answer_is_refused() {
        assert!(MemoryBasicInformation::decode(&[0u8; 28]).is_err());
        assert!(MemoryBasicInformation::decode(&[]).is_err());
    }
}
