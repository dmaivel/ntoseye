//! The kernel's DbgPrint buffer: the ring `KdLogDbgPrint` copies every
//! debug print into, whether or not a debugger listens, and which WinDbg's
//! `!dbgprint` shows. A backend without KD's debug-print stream reads guest
//! debug output from it.

use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::target::Target;
use crate::types::VirtAddr;

/// Larger than any buffer `KdPrintBufferSize` can name, so a corrupt size is
/// refused rather than read.
const MAX_RING_SIZE: usize = 16 << 20;

/// Where the writer is: how many times it wrapped to the buffer's start,
/// and the offset it writes at next. Bytes before it are written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrintCursor {
    pub rollovers: u32,
    pub offset: usize,
}

/// The ring's location and where its writer is.
#[derive(Clone, Copy, Debug)]
pub struct PrintPosition {
    pub buffer: VirtAddr,
    pub size: usize,
    pub cursor: PrintCursor,
}

/// What was written to the ring after a cursor.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PrintsSince {
    pub bytes: Vec<u8>,
    /// More was written than the ring holds, so the oldest of it is gone.
    pub lost: bool,
}

/// The bytes of a ring of `buffer.len()` bytes written between `from` and
/// `to`, oldest first. A writer that wrapped more than once since `from`
/// overwrote some of it: the whole ring is returned, marked lost. A writer
/// behind `from` started again (the target rebooted): everything it wrote
/// since is new.
pub fn prints_between(buffer: &[u8], from: PrintCursor, to: PrintCursor) -> PrintsSince {
    let size = buffer.len();
    let to_offset = to.offset.min(size);
    let from_offset = from.offset.min(size);
    let span = |start: usize, end: usize| buffer[start..end].to_vec();
    let behind = to.rollovers < from.rollovers
        || (to.rollovers == from.rollovers && to_offset < from_offset);
    let bytes = if behind {
        if to.rollovers == 0 {
            span(0, to_offset)
        } else {
            return PrintsSince {
                bytes: chronological(buffer, to),
                lost: true,
            };
        }
    } else if to.rollovers == from.rollovers {
        span(from_offset, to_offset)
    } else if to.rollovers == from.rollovers + 1 && to_offset <= from_offset {
        let mut bytes = span(from_offset, size);
        bytes.extend_from_slice(&buffer[..to_offset]);
        bytes
    } else {
        return PrintsSince {
            bytes: chronological(buffer, to),
            lost: true,
        };
    };
    PrintsSince { bytes, lost: false }
}

/// The ring's bytes oldest first, with the writer at `cursor`: before its
/// first wrap only the start up to the writer is written.
pub fn chronological(buffer: &[u8], cursor: PrintCursor) -> Vec<u8> {
    let offset = cursor.offset.min(buffer.len());
    if cursor.rollovers == 0 {
        return buffer[..offset].to_vec();
    }
    let mut bytes = buffer[offset..].to_vec();
    bytes.extend_from_slice(&buffer[..offset]);
    bytes
}

impl Target {
    /// Where the kernel's DbgPrint ring is and where its writer is. The
    /// writer's offset and wrap count are read twice around each other, so a
    /// running target that wraps meanwhile is read again.
    pub fn kernel_print_position(&self) -> Result<PrintPosition> {
        let guest = self.guest()?;
        let nt = &guest.ntoskrnl;
        let buffer = VirtAddr(nt.symbol("KdPrintCircularBuffer")?.read::<u64>()?);
        let size = nt.symbol("KdPrintBufferSize")?.read::<u32>()? as usize;
        if buffer.is_zero() || size == 0 || size > MAX_RING_SIZE {
            return Err(Error::DebugInfo(format!(
                "the kernel's DbgPrint buffer is not set up (KdPrintCircularBuffer {:#x}, \
                 KdPrintBufferSize {size:#x})",
                buffer.0
            )));
        }
        let writer = nt.symbol("KdPrintWritePointer")?;
        let rollovers = nt.symbol("KdPrintRolloverCount")?;
        for _ in 0..3 {
            let before = rollovers.read::<u32>()?;
            let write = writer.read::<u64>()?;
            if rollovers.read::<u32>()? != before {
                continue;
            }
            let offset = write
                .checked_sub(buffer.0)
                .and_then(|offset| usize::try_from(offset).ok())
                .filter(|offset| *offset <= size)
                .ok_or_else(|| {
                    Error::DebugInfo(format!(
                        "the DbgPrint writer {write:#x} is outside its buffer {:#x}+{size:#x}",
                        buffer.0
                    ))
                })?;
            return Ok(PrintPosition {
                buffer,
                size,
                cursor: PrintCursor {
                    rollovers: before,
                    offset,
                },
            });
        }
        Err(Error::DebugInfo(
            "the DbgPrint buffer kept wrapping while it was read".into(),
        ))
    }

    /// The bytes of the kernel's DbgPrint ring at `position`, as stored.
    pub fn kernel_print_buffer(&self, position: &PrintPosition) -> Result<Vec<u8>> {
        let mut bytes = vec![0u8; position.size];
        self.kernel_address_space()
            .read_bytes(position.buffer, &mut bytes)?;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::{PrintCursor, PrintsSince, chronological, prints_between};

    fn at(rollovers: u32, offset: usize) -> PrintCursor {
        PrintCursor { rollovers, offset }
    }

    fn since(buffer: &[u8], from: PrintCursor, to: PrintCursor) -> (String, bool) {
        let PrintsSince { bytes, lost } = prints_between(buffer, from, to);
        (String::from_utf8(bytes).unwrap(), lost)
    }

    /// New prints are the bytes between the cursors, across one wrap; a
    /// writer that lapped the reader returns the whole ring as lost, and a
    /// writer that started over (a reboot) returns what it wrote since.
    #[test]
    fn prints_between_cursors_follow_the_writer_around_the_ring() {
        let ring = b"0123456789";
        assert_eq!(since(ring, at(0, 2), at(0, 5)), ("234".into(), false));
        assert_eq!(since(ring, at(0, 5), at(0, 5)), (String::new(), false));
        assert_eq!(since(ring, at(3, 8), at(4, 2)), ("8901".into(), false));
        assert_eq!(since(ring, at(3, 8), at(4, 9)), ("9012345678".into(), true));
        assert_eq!(since(ring, at(1, 4), at(3, 4)), ("4567890123".into(), true));
        assert_eq!(since(ring, at(2, 7), at(0, 3)), ("012".into(), false));
        assert_eq!(since(ring, at(2, 7), at(1, 3)), ("3456789012".into(), true));
    }

    /// Before its first wrap, only the bytes up to the writer are written.
    #[test]
    fn chronological_starts_after_the_writer_once_it_wrapped() {
        assert_eq!(chronological(b"0123456789", at(0, 4)), b"0123");
        assert_eq!(chronological(b"0123456789", at(1, 4)), b"4567890123");
    }
}
