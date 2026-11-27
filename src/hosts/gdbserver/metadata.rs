//! What the server publishes about the target: the target description,
//! thread, library, and memory-map transfers, the program (the kernel, or
//! a user-mode minidump's main image), and what lldb asks of a target and
//! its memory.

use std::fmt::Write as _;
use std::fs::File;

use gdb_remote::lldb::{KeyValues, MemoryRegion, Permissions};
use gdb_remote::reply::{Offsets, XferChunk};
use gdb_remote::request::XferRead;
use gdb_remote::xfer::{Bases, Libraries, Library, MemoryKind, MemoryMap, Region, Thread, Threads};
use pelite::PeView;

use crate::arch::Arch;
use crate::backend::dbg_backend::{thread_kind, thread_label};
use crate::base::error::{Error, Result};
use crate::nt::guest::ModuleInfo;
use crate::nt::pe::{HeaderPage, image_base};
use crate::session::VcpuInfo;

use super::Server;
use super::host_io::read_at;

impl Server<'_> {
    /// Answer a `qXfer` read: `None` for an object the server does not
    /// publish, which the client gets the empty reply for. Only `osdata`
    /// takes an annex besides the target description's, and only the
    /// tables it has, so the snapshots stay one per document.
    pub(super) fn xfer(&mut self, read: &XferRead<'_>) -> Option<Result<XferChunk>> {
        let document = match (read.object, read.annex) {
            ("features", "target.xml") => {
                let description = self.layout.target_xml().as_bytes();
                return Some(Ok(XferChunk::window(description, read.offset, read.length)));
            }
            ("features", annex) => {
                return Some(Err(Error::InvalidArgument(format!(
                    "no target description document {annex}"
                ))));
            }
            ("threads" | "libraries" | "memory-map", annex) if !annex.is_empty() => {
                return Some(Err(Error::InvalidArgument(format!(
                    "{} takes no annex, not {annex}",
                    read.object
                ))));
            }
            ("exec-file", _) => match self.program_name() {
                Some(name) => remote_path(&name).into_bytes(),
                None => {
                    return Some(Err(Error::DebugInfo(
                        "this user-mode minidump names no program".into(),
                    )));
                }
            },
            ("threads" | "libraries" | "memory-map" | "osdata", annex) => {
                let key = (read.object.to_string(), annex.to_string());
                if read.offset == 0 || !self.snapshots.contains_key(&key) {
                    let document = match self.document(read.object, annex) {
                        Ok(document) => document,
                        Err(error) => return Some(Err(error)),
                    };
                    self.snapshots.insert(key.clone(), document);
                }
                let snapshot = &self.snapshots[&key];
                return Some(Ok(XferChunk::window(snapshot, read.offset, read.length)));
            }
            _ => return None,
        };
        Some(Ok(XferChunk::window(&document, read.offset, read.length)))
    }

    /// A fresh copy of an object a client reads in pieces, which the
    /// server snapshots at its first piece.
    pub(super) fn document(&mut self, object: &str, annex: &str) -> Result<Vec<u8>> {
        let mut xml = String::new();
        match object {
            "threads" => self.thread_list().write(&mut xml),
            "libraries" => {
                let modules = self.published_modules();
                let modules = modules
                    .iter()
                    .map(|module| (module.name.as_str(), module.base_address.0));
                library_list(self.arch, modules).write(&mut xml);
            }
            "memory-map" => memory_map(&self.layout_spans()).write(&mut xml),
            _ => self.osdata(annex)?.write(&mut xml),
        }
        Ok(xml.into_bytes())
    }

    /// The images published as libraries: kernel modules, plus the current
    /// process's modules once `.process` selects one; a user-mode
    /// minidump's own modules.
    fn published_modules(&self) -> Vec<ModuleInfo> {
        let target = &self.session.target;
        if let Some(modules) = target.user_modules() {
            return modules.to_vec();
        }
        let mut modules = target.kernel_modules().unwrap_or_default();
        if target.attached_process().is_some() {
            modules.extend(target.modules().unwrap_or_default());
        }
        modules
    }

    /// The published images as the address space clients are shown it.
    fn layout_spans(&self) -> Vec<Span> {
        let modules = self.published_modules();
        address_layout(self.arch, &image_spans(&modules))
    }

    /// The thread list, naming each vCPU by what it runs; `core` is the
    /// processor number.
    fn thread_list(&mut self) -> Threads {
        let names: Vec<String> = match self.session.vcpus() {
            Ok(vcpus) => vcpus.iter().map(VcpuInfo::label).collect(),
            Err(_) => {
                self.sync_threads();
                self.threads
                    .iter()
                    .map(|id| format!("{} {}", thread_kind(id), thread_label(id)))
                    .collect()
            }
        };
        Threads {
            threads: names
                .into_iter()
                .enumerate()
                .map(|(index, name)| Thread {
                    id: self.thread_id(index),
                    core: u64::try_from(index).ok(),
                    name: Some(name),
                    handle: None,
                    extra: None,
                })
                .collect(),
        }
    }

    /// `/proc/<pid>/maps` as Binary Ninja's GDB adapter reads it.
    pub(super) fn current_proc_maps(&self) -> Vec<u8> {
        proc_maps(&self.layout_spans()).into_bytes()
    }

    /// lldb's `qMemoryRegionInfo`: the region of the memory map `address`
    /// is in, or the unmapped stretch around it, which has no permissions.
    /// What a mapped region allows is not known, so it says all of it; an
    /// image's region is named by its path.
    pub(super) fn memory_region(&self, address: u64) -> MemoryRegion {
        let spans = self.layout_spans();
        if let Some(span) = spans
            .iter()
            .find(|span| (span.start..span.end).contains(&address))
        {
            return MemoryRegion {
                start: span.start,
                size: span.end - span.start,
                permissions: Some(Permissions {
                    read: true,
                    write: true,
                    execute: true,
                }),
                name: span
                    .image
                    .as_deref()
                    .map(|name| remote_path(name).into_bytes()),
            };
        }
        let start = spans
            .iter()
            .map(|span| span.end)
            .filter(|&end| end <= address)
            .max()
            .unwrap_or(0);
        // To the next region, or to the end of the address space (2^64,
        // which the size reaches by wrapping).
        let end = spans
            .iter()
            .map(|span| span.start)
            .filter(|&start| start > address)
            .min()
            .unwrap_or(0);
        MemoryRegion {
            start,
            size: end.wrapping_sub(start),
            permissions: None,
            name: None,
        }
    }

    /// lldb's `qHostInfo` (`ptrsize` decimal) or `qProcessInfo`
    /// (`ptrsize` hexadecimal, and the process id): a Windows target.
    pub(super) fn target_info(&self, process: bool) -> KeyValues {
        let triple: &[u8] = match self.arch {
            Arch::Amd64 => b"x86_64-pc-windows-msvc",
            Arch::Arm64 => b"aarch64-pc-windows-msvc",
        };
        let mut info = KeyValues::default();
        if process {
            info.push("pid", &format!("{:x}", self.pid));
        }
        info.push_hex("triple", triple);
        info.push("ostype", "windows");
        info.push("vendor", "pc");
        info.push("endian", "little");
        info.push("ptrsize", "8");
        info
    }

    /// The image published as the program: the kernel, or a user-mode
    /// minidump's main image, which its module list names first.
    fn program(&self) -> Option<ModuleInfo> {
        let target = &self.session.target;
        if let Some(modules) = target.user_modules() {
            return modules.first().cloned();
        }
        let base = target.kernel_base()?;
        target
            .kernel_modules()
            .ok()?
            .into_iter()
            .find(|module| module.base_address == base)
    }

    /// The program's file name. A kernel whose module list is unreadable is
    /// still `ntoskrnl.exe`; a user-mode minidump with no modules has none.
    fn program_name(&self) -> Option<String> {
        match self.program() {
            Some(module) => Some(module.name),
            None if self.session.target.user_dump().is_some() => None,
            None => Some("ntoskrnl.exe".to_string()),
        }
    }

    /// How far the program sits from its preferred base, so gdb relocates
    /// a file it loaded itself (`file ntoskrnl.exe`, or the image Ghidra
    /// launches gdb with) onto the target. Zero, which gdb takes as "not
    /// relocated", while the image is not in the symbol cache.
    pub(super) fn offsets(&self) -> Offsets {
        let slide = self.program_slide().unwrap_or(0);
        Offsets::Sections {
            text: slide,
            data: slide,
            bss: Some(slide),
        }
    }

    /// The program's loaded base minus the preferred base in its PE file.
    /// The file is the only source: the loader rewrites `ImageBase` in the
    /// mapped headers to the address it relocated the image to.
    fn program_slide(&self) -> Option<u64> {
        let program = self.program()?;
        let image = self
            .session
            .target
            .module_image_or_fetch_later(&program.name)
            .ok()??;
        let mut headers = HeaderPage::zeroed();
        let file = File::open(image).ok()?;
        let read = read_at(&file, &mut headers[..], 0).ok()?;
        let view = PeView::from_bytes(&headers[..read]).ok()?;
        Some(program.base_address.0.wrapping_sub(image_base(&view)))
    }
}

/// One stretch of the address space as clients are shown it: RAM between
/// module images, or one image with its file name.
#[derive(Debug, PartialEq, Eq)]
struct Span {
    start: u64,
    end: u64,
    image: Option<String>,
}

/// The user and kernel halves of the canonical address space, cut around
/// the published module images (`base`, `size`, file name), in address
/// order. A client shows memory only inside its map, and reads of unmapped
/// pages within it simply fail, so the halves are all it needs. The kernel
/// half stops a page short of the top so its end fits in 64 bits. Empty
/// stretches are left out: a zero-length region is malformed to IDA.
fn address_layout(arch: Arch, images: &[(u64, u64, &str)]) -> Vec<Span> {
    let (user_len, kernel_start) = arch.paging().canonical_halves();
    let kernel_end = 0u64.wrapping_sub(0x1000);
    let mut images: Vec<(u64, u64, &str)> = images
        .iter()
        .filter(|(_, size, _)| *size != 0)
        .map(|&(base, size, name)| (base, base.saturating_add(size), name))
        .collect();
    images.sort_unstable();

    let mut spans = Vec::new();
    let ram = |spans: &mut Vec<Span>, start: u64, end: u64| {
        if end > start {
            spans.push(Span {
                start,
                end,
                image: None,
            });
        }
    };
    for (start, end) in [(0, user_len), (kernel_start, kernel_end)] {
        let mut cursor = start;
        for &(base, image_end, name) in &images {
            if image_end <= cursor || base >= end {
                continue;
            }
            ram(&mut spans, cursor, base.min(end));
            spans.push(Span {
                start: base.max(cursor),
                end: image_end.min(end),
                image: Some(name.to_string()),
            });
            cursor = cursor.max(image_end);
        }
        ram(&mut spans, cursor, end);
    }
    spans
}

/// The memory map, one region per stretch. gdb reads only inside the map,
/// so the images must be in it. They are their own regions because IDA
/// lays out a module's segments first and drops every map region that
/// overlaps one: a region spanning a whole half would take the kernel with
/// it.
fn memory_map(layout: &[Span]) -> MemoryMap {
    MemoryMap {
        regions: layout
            .iter()
            .map(|span| Region {
                kind: MemoryKind::Ram,
                start: span.start,
                length: span.end - span.start,
            })
            .collect(),
    }
}

/// The library list of `modules` (file name, image base). Each name is
/// rooted ([`remote_path`]). For AMD64 a segment address is the image base
/// plus 0x1000, the first section's address, which is how gdb reads it for
/// PE images and what IDA subtracts before rebasing; for ARM64 IDA takes
/// the address as the image base.
fn library_list<'m>(arch: Arch, modules: impl IntoIterator<Item = (&'m str, u64)>) -> Libraries {
    let bias = match arch {
        Arch::Amd64 => 0x1000,
        Arch::Arm64 => 0,
    };
    Libraries {
        libraries: modules
            .into_iter()
            .map(|(name, base)| Library {
                name: remote_path(name),
                bases: Bases::Segments(vec![base.wrapping_add(bias)]),
            })
            .collect(),
    }
}

/// The layout in Linux `/proc/<pid>/maps` form, the only place Binary
/// Ninja's GDB adapter looks for modules and memory regions. An image is a
/// line whose path is `/` and its file name, which is how the adapter names
/// the module and matches it to the open database by base name; RAM is a line
/// with no path.
fn proc_maps(layout: &[Span]) -> String {
    let mut maps = String::new();
    for span in layout {
        let perms = if span.image.is_some() { "r-xp" } else { "rw-p" };
        let _ = write!(
            maps,
            "{:x}-{:x} {perms} 00000000 00:00 0",
            span.start, span.end
        );
        if let Some(name) = &span.image {
            let _ = write!(maps, " {}", remote_path(name));
        }
        maps.push('\n');
    }
    maps
}

/// The `(base, size, file name)` of each module, for [`address_layout`].
fn image_spans(modules: &[ModuleInfo]) -> Vec<(u64, u64, &str)> {
    modules
        .iter()
        .map(|module| {
            (
                module.base_address.0,
                u64::from(module.size),
                module.name.as_str(),
            )
        })
        .collect()
}

/// The path a module's image is reported under: its file name at the root.
/// gdb fetches a file through the server (`target:`) only when its path is
/// absolute, and looks for a bare name on the host instead. The server serves
/// any path by its file name, and clients match modules by base name, so no
/// directory is needed.
fn remote_path(name: &str) -> String {
    format!("/{name}")
}

#[cfg(test)]
mod tests {
    use gdb_remote::xfer::{Bases, Libraries, MemoryMap};

    use super::{address_layout, library_list, memory_map, proc_maps};
    use crate::arch::Arch;

    /// IDA subtracts 0x1000 from an x86 library's segment address before
    /// rebasing (gdb's PE convention) and takes ARM64's as the image base. A
    /// wrong bias rebases every module one page off. gdb fetches a library
    /// through the server only under an absolute path.
    #[test]
    fn library_segment_addresses_follow_the_pe_convention_per_arch() {
        let modules = [
            ("ntoskrnl.exe", 0xffff_f800_0000_0000u64),
            ("a&b.sys", 0x1000),
        ];
        let read = |arch| {
            let mut xml = String::new();
            library_list(arch, modules).write(&mut xml);
            Libraries::parse(&xml)
                .unwrap()
                .libraries
                .into_iter()
                .map(|library| (library.name, library.bases))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            read(Arch::Amd64),
            [
                (
                    "/ntoskrnl.exe".to_string(),
                    Bases::Segments(vec![0xffff_f800_0000_1000])
                ),
                ("/a&b.sys".to_string(), Bases::Segments(vec![0x2000])),
            ]
        );
        assert_eq!(
            read(Arch::Arm64)[0].1,
            Bases::Segments(vec![0xffff_f800_0000_0000])
        );
    }

    fn regions(images: &[(u64, u64, &str)]) -> Vec<(u64, u64)> {
        let mut xml = String::new();
        memory_map(&address_layout(Arch::Amd64, images)).write(&mut xml);
        MemoryMap::parse(&xml)
            .unwrap()
            .regions
            .into_iter()
            .map(|region| (region.start, region.length))
            .collect()
    }

    /// gdb reads only inside the map, so it must cover both halves, images
    /// included. IDA lays out module segments first and drops any map region
    /// overlapping one, so each image must be a region of its own, and IDA
    /// rejects zero-length or 64-bit-overflowing regions.
    #[test]
    fn memory_map_covers_the_halves_with_each_image_its_own_region() {
        let nt = (0xffff_f800_0000_0000u64, 0x100_0000u64);
        // Adjacent to nt, so no zero-length gap may appear between them.
        let hal = (nt.0 + nt.1, 0x1000);
        let user_dll = (0x7ff8_0000_0000u64, 0x2000);
        let images = [
            (hal.0, hal.1, "hal.dll"),
            (user_dll.0, user_dll.1, "ntdll.dll"),
            (nt.0, nt.1, "ntoskrnl.exe"),
        ];
        let regions = regions(&images);

        assert_eq!(
            regions,
            [
                (0, user_dll.0),
                user_dll,
                (
                    user_dll.0 + user_dll.1,
                    0x8000_0000_0000 - (user_dll.0 + user_dll.1)
                ),
                (0xffff_8000_0000_0000, nt.0 - 0xffff_8000_0000_0000),
                nt,
                hal,
                (hal.0 + hal.1, 0xffff_ffff_ffff_f000 - (hal.0 + hal.1)),
            ]
        );
        for (start, length) in regions {
            assert!(length > 0 && start.checked_add(length).is_some());
        }
    }

    /// Binary Ninja's GDB adapter takes modules only from `/proc/<pid>/maps`:
    /// a line ending in a `/`-rooted path is a module, named by that path, and
    /// the open database is matched to it by base name to find where to rebase.
    /// Every image must appear once at its exact range, and RAM must not look
    /// like a module.
    #[test]
    fn proc_maps_names_each_image_at_its_range() {
        let images = [
            (0xffff_f800_0000_0000u64, 0x100_0000u64, "ntoskrnl.exe"),
            (0xffff_f800_0100_0000, 0x1000, "hal.dll"),
        ];
        let maps = proc_maps(&address_layout(Arch::Amd64, &images));

        let mut modules = Vec::new();
        for line in maps.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let (start, end) = fields[0].split_once('-').unwrap();
            let start = u64::from_str_radix(start, 16).unwrap();
            let end = u64::from_str_radix(end, 16).unwrap();
            assert!(end > start, "{line}");
            assert_eq!(fields[2..5], ["00000000", "00:00", "0"], "{line}");
            match fields.get(5) {
                Some(path) => modules.push((start, end, *path)),
                None => assert_eq!(fields[1], "rw-p", "{line}"),
            }
        }
        assert_eq!(
            modules,
            [
                (
                    0xffff_f800_0000_0000,
                    0xffff_f800_0100_0000,
                    "/ntoskrnl.exe"
                ),
                (0xffff_f800_0100_0000, 0xffff_f800_0100_1000, "/hal.dll"),
            ]
        );
    }
}
