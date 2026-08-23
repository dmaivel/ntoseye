use std::sync::Arc;

use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes};

use crate::error::Result;

pub trait MemoryOps<A> {
    fn read_bytes(&self, addr: A, buf: &mut [u8]) -> Result<()>;

    #[allow(dead_code)]
    fn write_bytes(&self, addr: A, buf: &[u8]) -> Result<()>;

    fn read<T: Copy + FromZeros + FromBytes + IntoBytes>(&self, addr: A) -> Result<T> {
        let mut obj = T::new_zeroed();

        let slice = obj.as_mut_bytes();
        self.read_bytes(addr, slice)?;

        Ok(obj)
    }

    #[allow(dead_code)]
    fn write<T: Copy + IntoBytes + Immutable>(&self, addr: A, val: &T) -> Result<()> {
        let slice = val.as_bytes();
        self.write_bytes(addr, slice)
    }
}

/// Lets a shared `Arc<B>` stand in anywhere a memory backend `B` is expected,
/// so owners such as `WinObject` can share physical memory without changing
/// every reader signature.
impl<A, B: MemoryOps<A>> MemoryOps<A> for Arc<B> {
    fn read_bytes(&self, addr: A, buf: &mut [u8]) -> Result<()> {
        (**self).read_bytes(addr, buf)
    }

    fn write_bytes(&self, addr: A, buf: &[u8]) -> Result<()> {
        (**self).write_bytes(addr, buf)
    }
}
