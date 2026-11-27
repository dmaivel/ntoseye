//! The memory of a live user-mode target: one process's address space behind
//! a process server, read and written by virtual address through the server's
//! own debug-memory calls.

use crate::base::error::{Error, Result};

/// `MEMORY_BASIC_INFORMATION` as `VirtualQuery` reports it for an address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtualQuery {
    pub base: u64,
    pub size: u64,
    pub allocation_base: u64,
    pub allocation_protect: u32,
    pub state: u32,
    pub protect: u32,
    /// `MEM_*` (`MEM_IMAGE`, `MEM_MAPPED`, `MEM_PRIVATE`).
    pub kind: u32,
}

impl VirtualQuery {
    /// Bytes in the 64-bit `MEMORY_BASIC_INFORMATION` this decodes.
    pub const SIZE: usize = 48;

    /// Decode the first [`Self::SIZE`] bytes of what `VirtualQuery` filled.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < Self::SIZE {
            return Err(Error::DebugInfo(format!(
                "VirtualQuery filled {} bytes, {} expected",
                bytes.len(),
                Self::SIZE
            )));
        }
        let u32_at = |at: usize| {
            u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
        };
        let u64_at = |at: usize| {
            let mut value = [0u8; 8];
            value.copy_from_slice(&bytes[at..at + 8]);
            u64::from_le_bytes(value)
        };
        Ok(Self {
            base: u64_at(0),
            allocation_base: u64_at(8),
            allocation_protect: u32_at(16),
            size: u64_at(24),
            state: u32_at(32),
            protect: u32_at(36),
            kind: u32_at(40),
        })
    }

    /// The end of the region (exclusive).
    pub fn end(&self) -> u64 {
        self.base.saturating_add(self.size)
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
    fn query(&self, process: u64, address: u64) -> Result<VirtualQuery>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_memory_basic_information_decodes_its_region_and_protection() {
        let mut bytes = [0u8; VirtualQuery::SIZE];
        bytes[0..8].copy_from_slice(&0x1000_0000u64.to_le_bytes());
        bytes[8..16].copy_from_slice(&0x0fff_0000u64.to_le_bytes());
        bytes[16..20].copy_from_slice(&0x04u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&0x4200u64.to_le_bytes());
        bytes[32..36].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[36..40].copy_from_slice(&0x20u32.to_le_bytes());
        bytes[40..44].copy_from_slice(&0x100_0000u32.to_le_bytes());
        assert_eq!(
            VirtualQuery::decode(&bytes).unwrap(),
            VirtualQuery {
                base: 0x1000_0000,
                size: 0x4200,
                allocation_base: 0x0fff_0000,
                allocation_protect: 4,
                state: 0x1000,
                protect: 0x20,
                kind: 0x100_0000,
            }
        );
        assert_eq!(VirtualQuery::decode(&bytes).unwrap().end(), 0x1000_4200);
        assert!(VirtualQuery::decode(&bytes[..24]).is_err());
    }
}
