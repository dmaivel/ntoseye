//! Read-only remote file access (`vFile`): module images from the symbol
//! cache and the generated `/proc/<pid>/maps`.
//!
//! A client opening a path gets the PE file of the loaded module with that
//! file name, from the symbol cache. An image not cached yet is downloaded
//! in the background and the open fails until it arrives. IDA started with
//! `-rgdb@host:port ntoskrnl.exe` loads its input this way, and gdb fetches
//! the reported program file the same way, so either gets the exact build
//! that is running without copying anything. The one other path served is
//! `/proc/<pid>/maps`, generated from the module list, which is where
//! Binary Ninja's GDB adapter reads modules from.

use std::fs::File;
use std::io;
use std::path::PathBuf;

use gdb_remote::reply::{FileReply, FileStat, errno};
use gdb_remote::request::{FileRequest, open_flags};

use crate::base::error::Error;

use super::{PACKET_SIZE, Server};

/// Read at an absolute offset without moving the file's own cursor.
#[cfg(unix)]
pub(super) fn read_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    use std::os::unix::fs::FileExt;

    file.read_at(buf, offset)
}

/// Read at an absolute offset without moving the file's own cursor.
#[cfg(windows)]
pub(super) fn read_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    use std::os::windows::fs::FileExt;

    file.seek_read(buf, offset)
}

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
            Self::Image(file) => read_at(file, buf, offset),
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

    /// A read-only regular file of its size.
    fn stat(&self) -> io::Result<FileStat> {
        let size = self.len()?;
        Ok(FileStat {
            mode: FileStat::REGULAR
                | FileStat::OWNER_READ
                | FileStat::GROUP_READ
                | FileStat::OTHERS_READ,
            links: 1,
            size,
            block_size: 4096,
            blocks: size.div_ceil(512),
            ..FileStat::default()
        })
    }
}

/// A `vFile` reply: `result`, or the error number of a failure.
fn reply(result: Result<i64, u64>) -> FileReply {
    match result {
        Ok(result) => FileReply {
            result,
            errno: None,
            attachment: None,
        },
        Err(errno) => FileReply {
            result: -1,
            errno: Some(errno),
            attachment: None,
        },
    }
}

/// The protocol's error number for a host I/O error.
fn io_errno(error: &io::Error) -> u64 {
    match error.kind() {
        io::ErrorKind::NotFound => errno::ENOENT,
        io::ErrorKind::PermissionDenied => errno::EACCES,
        io::ErrorKind::Interrupted => errno::EINTR,
        _ => errno::EUNKNOWN,
    }
}

impl Server<'_> {
    /// Answer a `vFile` request. Writes are refused: the files are the
    /// symbol cache's.
    pub(super) fn file(&mut self, request: FileRequest) -> FileReply {
        match request {
            FileRequest::Open { path, flags, .. } => {
                let writes = open_flags::O_WRONLY
                    | open_flags::O_RDWR
                    | open_flags::O_APPEND
                    | open_flags::O_CREAT
                    | open_flags::O_TRUNC;
                if flags & writes != 0 {
                    return reply(Err(errno::EROFS));
                }
                let opened = self.open_file(&path).and_then(|file| {
                    let fd = self.next_fd;
                    self.next_fd += 1;
                    self.files.insert(fd, file);
                    i64::try_from(fd).map_err(|_| errno::EMFILE)
                });
                reply(opened)
            }
            FileRequest::Close { fd } => {
                reply(self.files.remove(&fd).map(|_| 0).ok_or(errno::EBADF))
            }
            FileRequest::Pread { fd, count, offset } => {
                let Some(file) = self.files.get(&fd) else {
                    return reply(Err(errno::EBADF));
                };
                let count =
                    usize::try_from(count).map_or(PACKET_SIZE, |count| count.min(PACKET_SIZE));
                let mut data = vec![0u8; count];
                match file.read_at(&mut data, offset) {
                    Ok(read) => {
                        data.truncate(read);
                        FileReply {
                            result: i64::try_from(read).unwrap_or(i64::MAX),
                            errno: None,
                            attachment: Some(data),
                        }
                    }
                    Err(error) => reply(Err(io_errno(&error))),
                }
            }
            FileRequest::Fstat { fd } => match self.files.get(&fd) {
                Some(file) => stat_reply(file.stat()),
                None => reply(Err(errno::EBADF)),
            },
            // Every path served is a regular file.
            FileRequest::Stat { path } | FileRequest::Lstat { path } => {
                match self.open_file(&path) {
                    Ok(file) => stat_reply(file.stat()),
                    Err(errno) => reply(Err(errno)),
                }
            }
            FileRequest::Readlink { path } => match self.open_file(&path) {
                Ok(_) => reply(Err(errno::EINVAL)),
                Err(errno) => reply(Err(errno)),
            },
            // There is one filesystem: the module images. gdb selects it
            // by process before opening the program file.
            FileRequest::Setfs { .. } => reply(Ok(0)),
            FileRequest::Pwrite { .. } | FileRequest::Unlink { .. } => reply(Err(errno::EROFS)),
        }
    }

    /// The file at `path`: the generated memory map, or the image of the
    /// loaded module with the path's file name; else the error number.
    fn open_file(&mut self, path: &[u8]) -> Result<OpenFile, u64> {
        let path = String::from_utf8_lossy(path);
        if is_proc_maps(&path) {
            return Ok(OpenFile::Generated(self.current_proc_maps()));
        }
        let image = self.module_image(&path).ok_or(errno::ENOENT)?;
        File::open(&image)
            .map(OpenFile::Image)
            .map_err(|error| io_errno(&error))
    }

    /// The cached image of the module `path` names by its file name.
    /// Clients send whatever path they hold: a host path, a guest path, or
    /// a bare name. Never downloads: the client is waiting on this reply
    /// with a short timeout, and a late reply knocks every later one out of
    /// step.
    fn module_image(&self, path: &str) -> Option<PathBuf> {
        let name = path.rsplit(['/', '\\']).next().unwrap_or(path);
        match self.session.target.module_image_or_fetch_later(name) {
            Ok(Some(image)) => Some(image),
            Ok(None) => {
                eprintln!(
                    "ntoseye-gdbserver: {name} is being downloaded; it can be opened once that \
                     finishes"
                );
                None
            }
            // No loaded module has the name: the expected answer to gdb's
            // probes for separate debug files, one per module, so not
            // worth a line.
            Err(Error::InvalidArgument(_)) => None,
            Err(error) => {
                eprintln!("ntoseye-gdbserver: cannot serve {path}: {error}");
                None
            }
        }
    }
}

/// An `fstat`, `stat` or `lstat` reply.
fn stat_reply(stat: io::Result<FileStat>) -> FileReply {
    match stat {
        Ok(stat) => {
            let mut attachment = Vec::with_capacity(FileStat::SIZE);
            stat.write(&mut attachment);
            FileReply {
                result: i64::try_from(FileStat::SIZE).unwrap_or(i64::MAX),
                errno: None,
                attachment: Some(attachment),
            }
        }
        Err(error) => reply(Err(io_errno(&error))),
    }
}
