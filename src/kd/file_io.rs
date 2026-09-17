//! Host-served target file I/O through the `.kdfiles` driver replacement map.
//!
//! `nt!MmLoadSystemImage` requests driver images through
//! [`PACKET_TYPE_KD_FILE_IO`]. Mapped names are served from host files;
//! unmapped names return `STATUS_UNSUCCESSFUL` so the target uses its disk copy.
//!
//! The wire layout from `windbgkd.h` is little-endian with the union at offset 8.
//!
//! ```text
//! ULONG  ApiNumber                  @  0
//! ULONG  Status                     @  4
//! union {                           @  8   (ULONG64 ReserveSpace[7] => 56 bytes)
//!   DBGKD_CREATE_FILE {
//!     ULONG   DesiredAccess         @  8
//!     ULONG   FileAttributes        @ 12
//!     ULONG   ShareAccess           @ 16
//!     ULONG   CreateDisposition     @ 20
//!     ULONG   CreateOptions         @ 24
//!     /* 4 bytes padding            @ 28 */
//!     ULONG64 Handle                @ 32
//!     ULONG64 Length                @ 40
//!   }
//!   DBGKD_READ_FILE / DBGKD_WRITE_FILE {
//!     ULONG64 Handle                @  8
//!     ULONG64 Offset                @ 16
//!     ULONG   Length                @ 24
//!   }
//!   DBGKD_CLOSE_FILE { ULONG64 Handle @ 8 }
//! }
//! ```
//!
//! Total 64 bytes ([`DBGKD_FILE_IO_HEADER_SIZE`]). For `CreateFile` the target
//! appends the UTF-16LE file name after the header; for `ReadFile` the debugger
//! appends the data it read to its reply.

use std::collections::HashMap;
use std::fs::{File, read_to_string};
use std::io::{ErrorKind, Read, Result as IoResult, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex, MutexGuard};

use crate::diagnostics::eprint_note;
use crate::error::{Error, Result};
use crate::kd::framing::{KdFraming, PACKET_MAX_SIZE, PACKET_TYPE_KD_FILE_IO};
use crate::kd::wire::{read_u32, read_u64, write_u32, write_u64};

use super::{
    DBGKD_CLOSE_FILE_API, DBGKD_CREATE_FILE_API, DBGKD_FILE_IO_HEADER_SIZE, DBGKD_READ_FILE_API,
    DBGKD_WRITE_FILE_API, STATUS_UNSUCCESSFUL,
};

const STATUS_SUCCESS: u32 = 0x0000_0000;
const STATUS_INVALID_HANDLE: u32 = 0xc000_0008;
const STATUS_ACCESS_DENIED: u32 = 0xc000_0022;

/// Largest `ReadFile` payload that still fits one KD packet.
const MAX_READ_CHUNK: usize = PACKET_MAX_SIZE - DBGKD_FILE_IO_HEADER_SIZE;

/// Limit host resources if the target leaves files open.
const MAX_OPEN_FILES: usize = 64;

/// One `target name -> host file` mapping.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KdFileMapping {
    /// Match key as written by the user, preserved for display.
    pub target: String,
    /// Host file served for a match.
    pub host: PathBuf,
}

impl KdFileMapping {
    /// Match a target path case-insensitively with normalized separators.
    /// Partial paths must match on a `\`-delimited suffix boundary.
    fn matches(&self, requested: &str) -> bool {
        let key = normalize(&self.target);
        let requested = normalize(requested);
        if key.is_empty() {
            return false;
        }
        if key == requested {
            return true;
        }
        if !key.contains('\\') {
            return base_name(&requested) == key;
        }
        requested
            .strip_suffix(&key)
            .is_some_and(|prefix| prefix.ends_with('\\'))
    }
}

fn normalize(path: &str) -> String {
    path.trim()
        .trim_end_matches('\0')
        .replace('/', "\\")
        .to_ascii_lowercase()
}

fn base_name(normalized: &str) -> &str {
    match normalized.rsplit_once('\\') {
        Some((_, name)) => name,
        None => normalized,
    }
}

/// File-serving counters displayed by `.kdfiles`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KdFileStats {
    pub opened: u64,
    pub refused: u64,
    pub bytes_read: u64,
}

struct OpenFile {
    mapping: KdFileMapping,
    file: File,
    len: u64,
}

#[derive(Default)]
struct Inner {
    mappings: Vec<KdFileMapping>,
    open: HashMap<u64, OpenFile>,
    next_handle: u64,
    stats: KdFileStats,
}

/// Driver replacement map shared by the background pump and foreground
/// manipulate-reply wait. KD permits one session per process.
pub struct KdFileMap {
    inner: Mutex<Inner>,
}

/// The process-wide driver replacement map.
pub fn kd_files() -> &'static KdFileMap {
    static MAP: LazyLock<KdFileMap> = LazyLock::new(KdFileMap::new);
    &MAP
}

impl KdFileMap {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                next_handle: 1,
                ..Inner::default()
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn mappings(&self) -> Vec<KdFileMapping> {
        self.lock().mappings.clone()
    }

    pub fn stats(&self) -> KdFileStats {
        self.lock().stats
    }

    /// Replace the map without closing handles still owned by the target.
    pub fn set(&self, mappings: Vec<KdFileMapping>) {
        let mut inner = self.lock();
        inner.mappings = mappings;
        inner.stats = KdFileStats::default();
    }

    pub fn clear(&self) {
        self.set(Vec::new());
    }

    /// Add one mapping, replacing any existing entry with the same target.
    ///
    /// Open the host file to report access errors before the target requests it.
    pub fn add(&self, target: &str, host: &Path) -> Result<KdFileMapping> {
        let target = target.trim();
        if target.is_empty() {
            return Err(Error::DebugInfo("target file name is empty".into()));
        }
        let host = host
            .canonicalize()
            .map_err(|err| Error::DebugInfo(format!("cannot serve {}: {err}", host.display())))?;
        if !host.is_file() {
            return Err(Error::DebugInfo(format!(
                "cannot serve {}: not a regular file",
                host.display()
            )));
        }
        File::open(&host)
            .map_err(|err| Error::DebugInfo(format!("cannot read {}: {err}", host.display())))?;
        let mapping = KdFileMapping {
            target: target.to_string(),
            host,
        };
        let mut inner = self.lock();
        let key = normalize(target);
        inner
            .mappings
            .retain(|entry| normalize(&entry.target) != key);
        inner.mappings.push(mapping.clone());
        inner.stats = KdFileStats::default();
        Ok(mapping)
    }

    pub fn remove(&self, target: &str) -> bool {
        let key = normalize(target);
        let mut inner = self.lock();
        let before = inner.mappings.len();
        inner
            .mappings
            .retain(|entry| normalize(&entry.target) != key);
        inner.mappings.len() != before
    }

    fn find(&self, requested: &str) -> Option<KdFileMapping> {
        self.lock()
            .mappings
            .iter()
            .find(|mapping| mapping.matches(requested))
            .cloned()
    }

    fn open(&self, requested: &str) -> Option<(u64, u64, KdFileMapping)> {
        let mapping = self.find(requested)?;
        let file = match File::open(&mapping.host) {
            Ok(file) => file,
            Err(err) => {
                kd_trace!(
                    "kd: kdfiles: {} matched {} but cannot be opened: {err}",
                    requested,
                    mapping.host.display()
                );
                self.lock().stats.refused += 1;
                return None;
            }
        };
        let len = match file.metadata() {
            Ok(metadata) => metadata.len(),
            Err(err) => {
                kd_trace!("kd: kdfiles: cannot stat {}: {err}", mapping.host.display());
                self.lock().stats.refused += 1;
                return None;
            }
        };
        let mut inner = self.lock();
        if inner.open.len() >= MAX_OPEN_FILES {
            kd_trace!("kd: kdfiles: refusing open, {MAX_OPEN_FILES} handles already outstanding");
            inner.stats.refused += 1;
            return None;
        }
        let handle = inner.next_handle;
        inner.next_handle = inner.next_handle.wrapping_add(1).max(1);
        inner.open.insert(
            handle,
            OpenFile {
                mapping: mapping.clone(),
                file,
                len,
            },
        );
        inner.stats.opened += 1;
        Some((handle, len, mapping))
    }

    /// Read from an open handle. Returns the bytes read, or `None` for an
    /// unknown handle.
    fn read(&self, handle: u64, offset: u64, length: usize) -> Option<Vec<u8>> {
        let mut inner = self.lock();
        let open = inner.open.get_mut(&handle)?;
        if offset >= open.len {
            return Some(Vec::new());
        }
        let available = (open.len - offset) as usize;
        let want = length.min(MAX_READ_CHUNK).min(available);
        let mut buf = vec![0u8; want];
        let read = match open
            .file
            .seek(SeekFrom::Start(offset))
            .and_then(|_| read_full(&mut open.file, &mut buf))
        {
            Ok(read) => read,
            Err(err) => {
                kd_trace!(
                    "kd: kdfiles: read {} at {offset:#x} failed: {err}",
                    open.mapping.host.display()
                );
                return Some(Vec::new());
            }
        };
        buf.truncate(read);
        inner.stats.bytes_read += read as u64;
        Some(buf)
    }

    fn close(&self, handle: u64) -> bool {
        self.lock().open.remove(&handle).is_some()
    }

    /// Forget every open handle when the connection is replaced.
    /// Target handles do not survive a reboot or reconnect.
    pub fn reset_handles(&self) {
        self.lock().open.clear();
    }
}

impl Default for KdFileMap {
    fn default() -> Self {
        Self::new()
    }
}

/// `Read::read_exact` that tolerates a short final read instead of erroring.
fn read_full(file: &mut File, buf: &mut [u8]) -> IoResult<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
    Ok(filled)
}

/// A decoded `DBGKD_FILE_IO` request.
#[derive(Debug, PartialEq, Eq)]
pub enum FileIoRequest {
    Create {
        name: String,
        desired_access: u32,
        create_disposition: u32,
    },
    Read {
        handle: u64,
        offset: u64,
        length: u32,
    },
    Write {
        handle: u64,
        offset: u64,
        length: u32,
    },
    Close {
        handle: u64,
    },
    Unknown {
        api: u32,
    },
}

/// A `DBGKD_FILE_IO` reply containing a fixed 64-byte header and trailing data.
#[derive(Debug, PartialEq, Eq)]
pub struct FileIoReply {
    pub header: [u8; DBGKD_FILE_IO_HEADER_SIZE],
    pub data: Vec<u8>,
}

impl FileIoReply {
    fn new(api: u32, status: u32) -> Self {
        let mut header = [0u8; DBGKD_FILE_IO_HEADER_SIZE];
        write_u32(&mut header, 0, api);
        write_u32(&mut header, 4, status);
        Self {
            header,
            data: Vec::new(),
        }
    }

    pub fn status(&self) -> u32 {
        read_u32(&self.header, 4)
    }

    fn into_payload(self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(self.header.len() + self.data.len());
        payload.extend_from_slice(&self.header);
        payload.extend_from_slice(&self.data);
        payload
    }
}

pub fn parse_file_io(payload: &[u8]) -> Result<FileIoRequest> {
    if payload.len() < DBGKD_FILE_IO_HEADER_SIZE {
        return Err(Error::Kd(format!(
            "KD file I/O payload too short: {} bytes",
            payload.len()
        )));
    }
    let api = read_u32(payload, 0);
    Ok(match api {
        DBGKD_CREATE_FILE_API => {
            // The name follows the header as UTF-16LE. `Length` carries its
            // byte count; trust it only when it fits, since the trailing bytes
            // are authoritative and older targets have left it zero.
            let tail = &payload[DBGKD_FILE_IO_HEADER_SIZE..];
            let declared = read_u64(payload, 40) as usize;
            let name_bytes = if declared > 0 && declared <= tail.len() {
                &tail[..declared]
            } else {
                tail
            };
            FileIoRequest::Create {
                name: decode_utf16le(name_bytes),
                desired_access: read_u32(payload, 8),
                create_disposition: read_u32(payload, 20),
            }
        }
        DBGKD_READ_FILE_API => FileIoRequest::Read {
            handle: read_u64(payload, 8),
            offset: read_u64(payload, 16),
            length: read_u32(payload, 24),
        },
        DBGKD_WRITE_FILE_API => FileIoRequest::Write {
            handle: read_u64(payload, 8),
            offset: read_u64(payload, 16),
            length: read_u32(payload, 24),
        },
        DBGKD_CLOSE_FILE_API => FileIoRequest::Close {
            handle: read_u64(payload, 8),
        },
        api => FileIoRequest::Unknown { api },
    })
}

fn decode_utf16le(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .take_while(|unit| *unit != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

/// Answer one file I/O request from the map.
pub fn serve_file_io(map: &KdFileMap, request: &FileIoRequest) -> FileIoReply {
    match request {
        FileIoRequest::Create {
            name,
            desired_access,
            create_disposition,
        } => match map.open(name) {
            Some((handle, len, mapping)) => {
                let mut reply = FileIoReply::new(DBGKD_CREATE_FILE_API, STATUS_SUCCESS);
                write_u64(&mut reply.header, 32, handle);
                write_u64(&mut reply.header, 40, len);
                kd_trace!(
                    "kd: kdfiles: serving {} as {} ({len} bytes, handle {handle:#x}, access {desired_access:#x}, disposition {create_disposition:#x})",
                    mapping.host.display(),
                    name
                );
                eprint_note(format!(
                    "kdfiles: target opened {name} -> {} ({len} bytes)",
                    mapping.host.display()
                ));
                reply
            }
            None => {
                kd_trace!("kd: kdfiles: no mapping for {name}, target will use its own copy");
                FileIoReply::new(DBGKD_CREATE_FILE_API, STATUS_UNSUCCESSFUL)
            }
        },
        FileIoRequest::Read {
            handle,
            offset,
            length,
        } => match map.read(*handle, *offset, *length as usize) {
            Some(data) => {
                let mut reply = FileIoReply::new(DBGKD_READ_FILE_API, STATUS_SUCCESS);
                write_u32(&mut reply.header, 24, data.len() as u32);
                kd_trace!(
                    "kd: kdfiles: read handle {handle:#x} offset {offset:#x} want {length} -> {} bytes",
                    data.len()
                );
                reply.data = data;
                reply
            }
            None => {
                kd_trace!("kd: kdfiles: read for unknown handle {handle:#x}");
                FileIoReply::new(DBGKD_READ_FILE_API, STATUS_INVALID_HANDLE)
            }
        },
        // Target file access is read-only.
        FileIoRequest::Write { handle, length, .. } => {
            kd_trace!("kd: kdfiles: refusing {length}-byte write to handle {handle:#x}");
            FileIoReply::new(DBGKD_WRITE_FILE_API, STATUS_ACCESS_DENIED)
        }
        FileIoRequest::Close { handle } => {
            let known = map.close(*handle);
            kd_trace!("kd: kdfiles: close handle {handle:#x} (known: {known})");
            FileIoReply::new(
                DBGKD_CLOSE_FILE_API,
                if known {
                    STATUS_SUCCESS
                } else {
                    STATUS_INVALID_HANDLE
                },
            )
        }
        FileIoRequest::Unknown { api } => {
            kd_trace!("kd: kdfiles: unsupported file I/O api {api:#x}");
            FileIoReply::new(*api, STATUS_UNSUCCESSFUL)
        }
    }
}

/// Service one `PACKET_TYPE_KD_FILE_IO` packet against the process-wide map.
///
/// Refuse malformed requests without dropping the connection so the target
/// receives a reply.
///
/// The caller's read timeout must cover a full-packet ACK, which takes about
/// 350ms for 4000 bytes at 115200 baud. Premature retransmission desynchronizes framing.
pub fn handle_file_io<T: Read + Write>(framing: &mut KdFraming<T>, payload: &[u8]) -> Result<()> {
    let reply = match parse_file_io(payload) {
        Ok(request) => serve_file_io(kd_files(), &request),
        Err(err) => {
            kd_trace!("kd: kdfiles: {err}");
            let api = if payload.len() >= 4 {
                read_u32(payload, 0)
            } else {
                0
            };
            FileIoReply::new(api, STATUS_UNSUCCESSFUL)
        }
    };
    framing.send_data(PACKET_TYPE_KD_FILE_IO, &reply.into_payload())
}

/// Parse a WinDbg driver-replacement map file.
///
/// Each record contains three lines.
///
/// ```text
/// map
/// \SystemRoot\system32\drivers\mydriver.sys
/// /home/me/build/mydriver.sys
/// ```
///
/// Blank lines and `;` / `//` comments are ignored. Relative host paths resolve
/// against the map file's directory.
pub fn parse_map_file(contents: &str, base: Option<&Path>) -> Result<Vec<KdFileMapping>> {
    let mut mappings = Vec::new();
    let mut pending: Option<String> = None;
    let mut expect_record = false;
    for (index, raw) in contents.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with("//") {
            continue;
        }
        let number = index + 1;
        if line.eq_ignore_ascii_case("map") {
            if let Some(target) = pending.take() {
                return Err(Error::DebugInfo(format!(
                    "line {number}: `map` record for {target} has no host path"
                )));
            }
            expect_record = true;
            continue;
        }
        if !expect_record {
            return Err(Error::DebugInfo(format!(
                "line {number}: expected `map` before `{line}`"
            )));
        }
        match pending.take() {
            None => pending = Some(line.to_string()),
            Some(target) => {
                let host = match base {
                    Some(base) if Path::new(line).is_relative() => base.join(line),
                    _ => PathBuf::from(line),
                };
                mappings.push(KdFileMapping { target, host });
                expect_record = false;
            }
        }
    }
    if let Some(target) = pending {
        return Err(Error::DebugInfo(format!(
            "unterminated `map` record for {target}: host path missing"
        )));
    }
    if expect_record {
        return Err(Error::DebugInfo(
            "trailing `map` with no target or host path".into(),
        ));
    }
    Ok(mappings)
}

/// Load a map file and validate every host path before installing it.
pub fn load_map_file(path: &Path) -> Result<Vec<KdFileMapping>> {
    let contents = read_to_string(path)
        .map_err(|err| Error::DebugInfo(format!("cannot read {}: {err}", path.display())))?;
    let mappings = parse_map_file(&contents, path.parent())?;
    if mappings.is_empty() {
        return Err(Error::DebugInfo(format!(
            "{} contains no `map` records",
            path.display()
        )));
    }
    let mut resolved = Vec::with_capacity(mappings.len());
    for mapping in mappings {
        let host = mapping.host.canonicalize().map_err(|err| {
            Error::DebugInfo(format!(
                "cannot serve {} for {}: {err}",
                mapping.host.display(),
                mapping.target
            ))
        })?;
        if !host.is_file() {
            return Err(Error::DebugInfo(format!(
                "cannot serve {} for {}: not a regular file",
                host.display(),
                mapping.target
            )));
        }
        resolved.push(KdFileMapping {
            target: mapping.target,
            host,
        });
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use std::env::temp_dir;
    use std::fs::create_dir_all;
    use std::process::id;

    use super::*;

    fn temp_file(name: &str, contents: &[u8]) -> PathBuf {
        let dir = temp_dir().join(format!("ntoseye-kdfiles-{}", id()));
        create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        let mut file = File::create(&path).unwrap();
        file.write_all(contents).unwrap();
        path
    }

    fn create_payload(name: &str) -> Vec<u8> {
        let mut payload = vec![0u8; DBGKD_FILE_IO_HEADER_SIZE];
        write_u32(&mut payload, 0, DBGKD_CREATE_FILE_API);
        let encoded: Vec<u8> = name
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect();
        write_u64(&mut payload, 40, encoded.len() as u64);
        payload.extend_from_slice(&encoded);
        payload
    }

    fn read_payload(handle: u64, offset: u64, length: u32) -> Vec<u8> {
        let mut payload = vec![0u8; DBGKD_FILE_IO_HEADER_SIZE];
        write_u32(&mut payload, 0, DBGKD_READ_FILE_API);
        write_u64(&mut payload, 8, handle);
        write_u64(&mut payload, 16, offset);
        write_u32(&mut payload, 24, length);
        payload
    }

    #[test]
    fn bare_name_mapping_matches_any_target_directory() {
        let mapping = KdFileMapping {
            target: "PdbProbe.sys".into(),
            host: PathBuf::from("/tmp/PdbProbe.sys"),
        };
        assert!(mapping.matches("\\SystemRoot\\System32\\drivers\\pdbprobe.sys"));
        assert!(mapping.matches("\\??\\C:\\Windows\\System32\\drivers\\PdbProbe.sys"));
        assert!(mapping.matches("pdbprobe.sys"));
        assert!(!mapping.matches("\\SystemRoot\\System32\\drivers\\other.sys"));
        assert!(!mapping.matches("\\SystemRoot\\System32\\drivers\\xpdbprobe.sys"));
    }

    #[test]
    fn partial_path_mapping_matches_only_on_a_separator_boundary() {
        let mapping = KdFileMapping {
            target: "drivers\\probe.sys".into(),
            host: PathBuf::from("/tmp/probe.sys"),
        };
        assert!(mapping.matches("\\SystemRoot\\System32\\drivers\\probe.sys"));
        assert!(!mapping.matches("\\SystemRoot\\System32\\mydrivers\\probe.sys"));
    }

    #[test]
    fn create_read_close_serves_host_file_contents() {
        let body: Vec<u8> = (0u8..=255).collect();
        let path = temp_file("serve.sys", &body);
        let map = KdFileMap::new();
        map.add("serve.sys", &path).unwrap();

        let create = parse_file_io(&create_payload(
            "\\SystemRoot\\System32\\drivers\\serve.sys",
        ))
        .unwrap();
        let reply = serve_file_io(&map, &create);
        assert_eq!(reply.status(), STATUS_SUCCESS);
        let handle = read_u64(&reply.header, 32);
        assert_eq!(read_u64(&reply.header, 40), body.len() as u64);

        let read = parse_file_io(&read_payload(handle, 16, 32)).unwrap();
        let reply = serve_file_io(&map, &read);
        assert_eq!(reply.status(), STATUS_SUCCESS);
        assert_eq!(read_u32(&reply.header, 24), 32);
        assert_eq!(reply.data, body[16..48]);

        let close = parse_file_io(&{
            let mut payload = vec![0u8; DBGKD_FILE_IO_HEADER_SIZE];
            write_u32(&mut payload, 0, DBGKD_CLOSE_FILE_API);
            write_u64(&mut payload, 8, handle);
            payload
        })
        .unwrap();
        assert_eq!(serve_file_io(&map, &close).status(), STATUS_SUCCESS);

        let read = parse_file_io(&read_payload(handle, 0, 8)).unwrap();
        assert_eq!(serve_file_io(&map, &read).status(), STATUS_INVALID_HANDLE);
    }

    #[test]
    fn read_past_end_of_file_returns_empty_success() {
        let path = temp_file("short.sys", b"abcd");
        let map = KdFileMap::new();
        map.add("short.sys", &path).unwrap();
        let create = parse_file_io(&create_payload("short.sys")).unwrap();
        let handle = read_u64(&serve_file_io(&map, &create).header, 32);

        let reply = serve_file_io(&map, &parse_file_io(&read_payload(handle, 2, 64)).unwrap());
        assert_eq!(reply.status(), STATUS_SUCCESS);
        assert_eq!(reply.data, b"cd");

        let reply = serve_file_io(&map, &parse_file_io(&read_payload(handle, 4, 64)).unwrap());
        assert_eq!(reply.status(), STATUS_SUCCESS);
        assert!(reply.data.is_empty());
    }

    #[test]
    fn read_is_bounded_to_one_kd_packet() {
        let body = vec![0x41u8; MAX_READ_CHUNK * 2];
        let path = temp_file("big.sys", &body);
        let map = KdFileMap::new();
        map.add("big.sys", &path).unwrap();
        let create = parse_file_io(&create_payload("big.sys")).unwrap();
        let handle = read_u64(&serve_file_io(&map, &create).header, 32);

        let reply = serve_file_io(
            &map,
            &parse_file_io(&read_payload(handle, 0, u32::MAX)).unwrap(),
        );
        assert_eq!(reply.data.len(), MAX_READ_CHUNK);
        assert!(reply.header.len() + reply.data.len() <= PACKET_MAX_SIZE);
    }

    #[test]
    fn unmapped_name_is_refused_so_the_target_uses_its_own_copy() {
        let map = KdFileMap::new();
        let create = parse_file_io(&create_payload(
            "\\SystemRoot\\System32\\drivers\\unmapped.sys",
        ))
        .unwrap();
        assert_eq!(serve_file_io(&map, &create).status(), STATUS_UNSUCCESSFUL);
    }

    #[test]
    fn writes_are_denied() {
        let map = KdFileMap::new();
        let mut payload = vec![0u8; DBGKD_FILE_IO_HEADER_SIZE];
        write_u32(&mut payload, 0, DBGKD_WRITE_FILE_API);
        write_u64(&mut payload, 8, 1);
        write_u32(&mut payload, 24, 4);
        payload.extend_from_slice(b"oops");
        let request = parse_file_io(&payload).unwrap();
        assert_eq!(serve_file_io(&map, &request).status(), STATUS_ACCESS_DENIED);
    }

    #[test]
    fn create_name_is_read_from_trailing_bytes_when_length_is_absent() {
        let mut payload = create_payload("probe.sys");
        write_u64(&mut payload, 40, 0);
        match parse_file_io(&payload).unwrap() {
            FileIoRequest::Create { name, .. } => assert_eq!(name, "probe.sys"),
            other => panic!("expected create, got {other:?}"),
        }
    }

    #[test]
    fn short_payload_is_rejected_rather_than_panicking() {
        assert!(parse_file_io(&[0u8; 8]).is_err());
    }

    #[test]
    fn map_file_records_resolve_relative_host_paths() {
        let mappings = parse_map_file(
            "; comment\nmap\n\\SystemRoot\\system32\\drivers\\a.sys\nbuild/a.sys\n\nmap\nb.sys\n/abs/b.sys\n",
            Some(Path::new("/maps")),
        )
        .unwrap();
        assert_eq!(
            mappings,
            vec![
                KdFileMapping {
                    target: "\\SystemRoot\\system32\\drivers\\a.sys".into(),
                    host: PathBuf::from("/maps/build/a.sys"),
                },
                KdFileMapping {
                    target: "b.sys".into(),
                    host: PathBuf::from("/abs/b.sys"),
                },
            ]
        );
    }

    #[test]
    fn map_file_without_map_keyword_is_an_error() {
        assert!(parse_map_file("a.sys\n/tmp/a.sys\n", None).is_err());
    }

    #[test]
    fn map_file_with_incomplete_record_is_an_error() {
        assert!(parse_map_file("map\na.sys\n", None).is_err());
        assert!(parse_map_file("map\n", None).is_err());
    }

    #[test]
    fn adding_the_same_target_replaces_the_previous_host() {
        let first = temp_file("dup-one.sys", b"one");
        let second = temp_file("dup-two.sys", b"two");
        let map = KdFileMap::new();
        map.add("dup.sys", &first).unwrap();
        map.add("dup.sys", &second).unwrap();
        let mappings = map.mappings();
        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].host, second.canonicalize().unwrap());
    }

    #[test]
    fn adding_a_missing_host_file_fails_immediately() {
        let map = KdFileMap::new();
        assert!(map.add("x.sys", Path::new("/nonexistent/x.sys")).is_err());
        assert!(map.mappings().is_empty());
    }
}
