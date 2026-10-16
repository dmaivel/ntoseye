//! Read-only remote file access (`vFile`): module images from the symbol
//! cache and the generated `/proc/<pid>/maps`.

use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;

use gdbstub::target::ext::host_io::{
    FsKind, HostIo, HostIoClose, HostIoCloseOps, HostIoErrno, HostIoError, HostIoFstat,
    HostIoFstatOps, HostIoOpen, HostIoOpenFlags, HostIoOpenMode, HostIoOpenOps, HostIoPread,
    HostIoPreadOps, HostIoResult, HostIoSetfs, HostIoSetfsOps, HostIoStat,
};

use super::GdbTarget;

/// Whether a remote path names a process's memory map, `/proc/<pid>/maps`.
fn is_proc_maps(path: &str) -> bool {
    path.strip_prefix("/proc/")
        .and_then(|rest| rest.strip_suffix("/maps"))
        .is_some_and(|pid| {
            pid == "self" || (!pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()))
        })
}

/// A file served through `vFile`: a module image from the symbol cache, or
/// text generated when it was opened.
pub(super) enum OpenFile {
    Image(File),
    Generated(Vec<u8>),
}

impl OpenFile {
    /// Zero bytes at and past the end: IDA sizes a file by probing one-byte
    /// reads for where they stop.
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        match self {
            Self::Image(file) => file.read_at(buf, offset),
            Self::Generated(bytes) => {
                let rest = usize::try_from(offset)
                    .ok()
                    .and_then(|start| bytes.get(start..))
                    .unwrap_or_default();
                let len = rest.len().min(buf.len());
                buf[..len].copy_from_slice(&rest[..len]);
                Ok(len)
            }
        }
    }

    fn len(&self) -> io::Result<u64> {
        match self {
            Self::Image(file) => Ok(file.metadata()?.len()),
            Self::Generated(bytes) => Ok(bytes.len() as u64),
        }
    }
}

impl GdbTarget<'_> {
    /// Hold `file` open for the client under a new descriptor.
    fn add_file(&mut self, file: OpenFile) -> u32 {
        let fd = self.next_fd;
        self.next_fd += 1;
        self.files.insert(fd, file);
        fd
    }
}

/// Remote file access, read-only: a client opening a path gets the PE file
/// of the loaded module with that file name, from the symbol cache. An image
/// not cached yet is downloaded in the background and the open fails until it
/// arrives. IDA started with `-rgdb@host:port ntoskrnl.exe` loads its input
/// this way, and gdb fetches the reported program file the same way, so either
/// gets the exact build that is running without copying anything. The one
/// other path served is `/proc/<pid>/maps`, generated from the module list,
/// which is where Binary Ninja's GDB adapter reads modules from.
impl HostIo for GdbTarget<'_> {
    fn support_open(&mut self) -> Option<HostIoOpenOps<'_, Self>> {
        Some(self)
    }

    fn support_close(&mut self) -> Option<HostIoCloseOps<'_, Self>> {
        Some(self)
    }

    fn support_pread(&mut self) -> Option<HostIoPreadOps<'_, Self>> {
        Some(self)
    }

    fn support_fstat(&mut self) -> Option<HostIoFstatOps<'_, Self>> {
        Some(self)
    }

    fn support_setfs(&mut self) -> Option<HostIoSetfsOps<'_, Self>> {
        Some(self)
    }
}

impl HostIoOpen for GdbTarget<'_> {
    fn open(
        &mut self,
        filename: &[u8],
        flags: HostIoOpenFlags,
        _mode: HostIoOpenMode,
    ) -> HostIoResult<u32, Self> {
        let writes = HostIoOpenFlags::O_WRONLY
            | HostIoOpenFlags::O_RDWR
            | HostIoOpenFlags::O_APPEND
            | HostIoOpenFlags::O_CREAT
            | HostIoOpenFlags::O_TRUNC;
        if flags.intersects(writes) {
            return Err(HostIoError::Errno(HostIoErrno::EROFS));
        }
        let path = String::from_utf8_lossy(filename);
        if is_proc_maps(&path) {
            let maps = self.current_proc_maps();
            return Ok(self.add_file(OpenFile::Generated(maps)));
        }
        // Clients send whatever path they hold: a host path, a guest path,
        // or a bare name. The file name is what identifies the module.
        let name = path.rsplit(['/', '\\']).next().unwrap_or(&path);
        // Never download here: the client is waiting on this reply with a
        // short timeout, and a late reply knocks every later one out of step.
        let image = match self.session.target.module_image_or_fetch_later(name) {
            Ok(Some(image)) => image,
            Ok(None) => {
                eprintln!(
                    "ntoseye-gdbserver: {name} is being downloaded; it can be opened once that \
                     finishes"
                );
                return Err(HostIoError::Errno(HostIoErrno::ENOENT));
            }
            Err(error) => {
                eprintln!("ntoseye-gdbserver: cannot serve {path}: {error}");
                return Err(HostIoError::Errno(HostIoErrno::ENOENT));
            }
        };
        let file = File::open(&image)?;
        Ok(self.add_file(OpenFile::Image(file)))
    }
}

impl HostIoClose for GdbTarget<'_> {
    fn close(&mut self, fd: u32) -> HostIoResult<(), Self> {
        self.files
            .remove(&fd)
            .map(drop)
            .ok_or(HostIoError::Errno(HostIoErrno::EBADF))
    }
}

impl HostIoPread for GdbTarget<'_> {
    fn pread(
        &mut self,
        fd: u32,
        count: usize,
        offset: u64,
        buf: &mut [u8],
    ) -> HostIoResult<usize, Self> {
        let file = self
            .files
            .get(&fd)
            .ok_or(HostIoError::Errno(HostIoErrno::EBADF))?;
        let len = count.min(buf.len());
        Ok(file.read_at(&mut buf[..len], offset)?)
    }
}

impl HostIoFstat for GdbTarget<'_> {
    fn fstat(&mut self, fd: u32) -> HostIoResult<HostIoStat, Self> {
        let file = self
            .files
            .get(&fd)
            .ok_or(HostIoError::Errno(HostIoErrno::EBADF))?;
        let size = file.len()?;
        Ok(HostIoStat {
            st_dev: 0,
            st_ino: 0,
            st_mode: HostIoOpenMode::S_IFREG
                | HostIoOpenMode::S_IRUSR
                | HostIoOpenMode::S_IRGRP
                | HostIoOpenMode::S_IROTH,
            st_nlink: 1,
            st_uid: 0,
            st_gid: 0,
            st_rdev: 0,
            st_size: size,
            st_blksize: 4096,
            st_blocks: size.div_ceil(512),
            st_atime: 0,
            st_mtime: 0,
            st_ctime: 0,
        })
    }
}

/// There is one filesystem: the module images. gdb selects it by process
/// before opening the program file.
impl HostIoSetfs for GdbTarget<'_> {
    fn setfs(&mut self, _fs: FsKind) -> HostIoResult<(), Self> {
        Ok(())
    }
}
