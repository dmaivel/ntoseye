//! Replace a destination file atomically where the platform allows it.
//!
//! Symbol caches, breakpoint journals and dump writers all stage a new file
//! next to the real one and publish it only once it is complete, so a reader
//! never observes a half-written file. `fs::rename` gives that for free on
//! Unix; on Windows it fails when the destination exists, so `MoveFileExW`
//! with `MOVEFILE_REPLACE_EXISTING` is needed instead.

use std::io;
use std::path::Path;

#[cfg(unix)]
pub fn replace(from: &Path, to: &Path) -> io::Result<()> {
    std::fs::rename(from, to)
}

#[cfg(windows)]
pub fn replace(from: &Path, to: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_REPLACE_EXISTING, MoveFileExW};

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    let (from, to) = (wide(from), wide(to));
    // SAFETY: both buffers are NUL-terminated and outlive the call.
    if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), MOVEFILE_REPLACE_EXISTING) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
