//! The backend-neutral interface for a live user-mode target: one process's
//! address space read and written by virtual address, its thread id format,
//! and the shared live process metadata updated by the backend as threads
//! arrive and exit.

use std::sync::{Arc, Mutex, PoisonError};

use zerocopy::{FromBytes, Immutable, KnownLayout};

use crate::base::error::{Error, Result};

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

/// The backend thread id of live thread `tid`: its id in hex, as WinDbg names
/// a user-mode thread.
pub fn backend_thread_id(tid: u32) -> String {
    format!("{tid:x}")
}

/// Parse a backend thread id produced by [`backend_thread_id`].
pub fn parse_backend_thread_id(id: &str) -> Option<u32> {
    u32::from_str_radix(id, 16).ok()
}

/// One thread of a live user-mode process, free of any backend-private handle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveUserThread {
    pub tid: u32,
    /// The thread's `_TEB`, when the backend names it.
    pub teb: Option<u64>,
    /// The address the thread's function starts at, when the backend says.
    pub start_address: Option<u64>,
    /// The thread's description (`SetThreadDescription`), when it has one.
    pub name: Option<String>,
}

/// Live process metadata shared between a user-mode backend and the Windows
/// model above it, so thread creation and exit stay visible to inspection
/// commands without copying or exposing backend handles.
#[derive(Clone, Debug, Default)]
pub struct LiveProcessInfo {
    pub pid: u32,
    /// The process's `_PEB`, when the backend names it.
    pub peb: Option<u64>,
    /// The image the process was created from, which is its only module until
    /// its loader fills the lists.
    pub image_base: Option<u64>,
    /// The file name of the command line this session created, if one was.
    pub image_hint: Option<String>,
    pub threads: Vec<LiveUserThread>,
}

impl LiveProcessInfo {
    /// The thread `tid` names.
    pub fn thread_by_id(&self, tid: u32) -> Option<&LiveUserThread> {
        self.threads.iter().find(|thread| thread.tid == tid)
    }

    /// The thread a backend id names (see [`backend_thread_id`]).
    pub fn thread_by_backend_id(&self, backend_id: &str) -> Option<&LiveUserThread> {
        self.thread_by_id(parse_backend_thread_id(backend_id)?)
    }

    /// The index of the thread a backend id names in the process's thread
    /// list, which is the number `~` selects it by.
    pub fn thread_index_by_backend_id(&self, backend_id: &str) -> Option<usize> {
        let tid = parse_backend_thread_id(backend_id)?;
        self.threads.iter().position(|thread| thread.tid == tid)
    }
}

/// Shared handle to [`LiveProcessInfo`] owned by the backend and read by the
/// target model.
#[derive(Clone, Debug, Default)]
pub struct LiveProcessState {
    inner: Arc<Mutex<LiveProcessInfo>>,
}

impl LiveProcessState {
    pub fn new(info: LiveProcessInfo) -> Self {
        Self {
            inner: Arc::new(Mutex::new(info)),
        }
    }

    pub fn snapshot(&self) -> LiveProcessInfo {
        self.with(Clone::clone)
    }

    pub fn with<R>(&self, f: impl FnOnce(&LiveProcessInfo) -> R) -> R {
        let guard = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        f(&guard)
    }

    pub fn update<R>(&self, f: impl FnOnce(&mut LiveProcessInfo) -> R) -> R {
        let mut guard = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        f(&mut guard)
    }
}

/// A live process's memory, as a user-mode backend serves it: by virtual
/// address, since the target is one process with one address space.
pub trait UserLiveMemory: Send + Sync {
    /// Read `buf` at `address`. A short read is an error.
    fn read(&self, address: u64, buf: &mut [u8]) -> Result<()>;

    /// Write `buf` at `address`. A short write is an error.
    fn write(&self, address: u64, buf: &[u8]) -> Result<()>;

    /// What `VirtualQuery` reports for `address`.
    fn query(&self, address: u64) -> Result<MemoryBasicInformation>;
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

    #[test]
    fn thread_ids_round_trip_in_hex() {
        assert_eq!(backend_thread_id(0x1a2c), "1a2c");
        assert_eq!(parse_backend_thread_id("1a2c"), Some(0x1a2c));
        assert_eq!(parse_backend_thread_id("not-hex"), None);
    }
}
