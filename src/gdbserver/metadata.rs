//! What the server publishes about the target: the target description,
//! thread, library, and memory-map transfers, and the kernel as the program.

use std::fmt::Write as _;
use std::fs::File;
use std::os::unix::fs::FileExt;

use gdbstub::common::Pid;
use gdbstub::target::ext::exec_file::ExecFile;
use gdbstub::target::ext::libraries::Libraries;
use gdbstub::target::ext::memory_map::MemoryMap;
use gdbstub::target::ext::section_offsets::{Offsets, SectionOffsets};
use gdbstub::target::ext::target_description_xml_override::TargetDescriptionXmlOverride;
use gdbstub::target::{TargetError, TargetResult};
use pelite::PeView;

use crate::guest::ModuleInfo;
use crate::pe::{HeaderPage, image_base};
use crate::session::VcpuInfo;
use crate::types::Arch;

use super::GdbTarget;
use super::connection::{xfer_reply, xfer_window};

impl GdbTarget<'_> {
    /// The images published as libraries: kernel modules, plus the current
    /// process's modules once `.process` selects one.
    fn published_modules(&self) -> Vec<ModuleInfo> {
        let target = &self.session.target;
        let mut modules = target.kernel_modules().unwrap_or_default();
        if target.attached_process().is_some() {
            modules.extend(target.modules().unwrap_or_default());
        }
        modules
    }

    fn libraries_xml(&self) -> Vec<u8> {
        let modules = self.published_modules();
        let entries = modules
            .iter()
            .map(|module| (module.name.as_str(), module.base_address.0));
        library_list_xml(self.arch, entries).into_bytes()
    }

    fn current_memory_map(&self) -> Vec<u8> {
        let modules = self.published_modules();
        let images = image_spans(&modules);
        memory_map_xml(&address_layout(self.arch, &images)).into_bytes()
    }

    pub(super) fn current_proc_maps(&self) -> Vec<u8> {
        let modules = self.published_modules();
        let images = image_spans(&modules);
        proc_maps(&address_layout(self.arch, &images)).into_bytes()
    }

    /// Answer `qXfer:threads:read` for `window` (`offset,length`), naming each
    /// vCPU by what it runs. A read starting at zero takes a new snapshot.
    pub(super) fn threads_xfer(&mut self, window: &[u8], multiprocess: bool) -> Vec<u8> {
        let Some((offset, length)) = xfer_window(window) else {
            return b"E00".to_vec();
        };
        if offset == 0 {
            let names = match self.session.vcpus() {
                Ok(vcpus) => vcpus.iter().map(VcpuInfo::label).collect(),
                Err(_) => {
                    self.sync_threads();
                    self.threads.clone()
                }
            };
            self.thread_list =
                thread_list_xml(names.iter().map(String::as_str), multiprocess).into_bytes();
        }
        xfer_reply(&self.thread_list, offset, length)
    }

    fn kernel_image_name(&self) -> String {
        let target = &self.session.target;
        target
            .kernel_base()
            .and_then(|base| {
                target
                    .kernel_modules()
                    .ok()?
                    .into_iter()
                    .find(|module| module.base_address == base)
            })
            .map(|module| module.name)
            .unwrap_or_else(|| "ntoskrnl.exe".to_string())
    }

    /// The live kernel base minus the preferred base in the kernel's PE file.
    /// The file is the only source: the loader rewrites `ImageBase` in the
    /// mapped headers to the address it relocated the image to.
    fn kernel_slide(&self) -> Option<u64> {
        let target = &self.session.target;
        let base = target.kernel_base()?;
        let image = target
            .module_image_or_fetch_later(&self.kernel_image_name())
            .ok()??;
        let mut headers = HeaderPage::zeroed();
        let read = File::open(image).ok()?.read_at(&mut headers[..], 0).ok()?;
        let view = PeView::from_bytes(&headers[..read]).ok()?;
        Some(base.0.wrapping_sub(image_base(&view)))
    }
}

/// `<threads>` for a thread-list transfer; `core` is the processor number.
/// Ids must match the stop replies: `p1.<tid>` once the client negotiated
/// multiprocess (gdb, lldb), plain hex otherwise, which is also the only
/// form IDA parses.
fn thread_list_xml<'n>(names: impl IntoIterator<Item = &'n str>, multiprocess: bool) -> String {
    let mut xml = String::from("<?xml version=\"1.0\"?>\n<threads>\n");
    // gdbstub reports every thread under pid 1 without extended mode.
    let pid = if multiprocess { "p1." } else { "" };
    for (index, name) in names.into_iter().enumerate() {
        let _ = writeln!(
            xml,
            "<thread id=\"{pid}{:x}\" core=\"{index}\" name=\"{}\"/>",
            index + 1,
            xml_escape(name)
        );
    }
    xml.push_str("</threads>\n");
    xml
}

/// One stretch of the address space as clients are shown it: RAM between
/// module images, or one image with its file name.
#[derive(Debug, PartialEq, Eq)]
struct Span<'m> {
    start: u64,
    end: u64,
    image: Option<&'m str>,
}

/// The user and kernel halves of the canonical address space, cut around
/// the published module images (`base`, `size`, file name), in address
/// order. A client shows memory only inside its map, and reads of unmapped
/// pages within it simply fail, so the halves are all it needs. The kernel
/// half stops a page short of the top so its end fits in 64 bits. Empty
/// stretches are left out: a zero-length region is malformed to IDA.
fn address_layout<'m>(arch: Arch, images: &[(u64, u64, &'m str)]) -> Vec<Span<'m>> {
    let (user_len, kernel_start) = match arch {
        Arch::Amd64 => (0x0000_8000_0000_0000u64, 0xFFFF_8000_0000_0000u64),
        Arch::Arm64 => (0x0001_0000_0000_0000, 0xFFFF_0000_0000_0000),
    };
    let kernel_end = 0u64.wrapping_sub(0x1000);
    let mut images: Vec<(u64, u64, &str)> = images
        .iter()
        .filter(|(_, size, _)| *size != 0)
        .map(|&(base, size, name)| (base, base.saturating_add(size), name))
        .collect();
    images.sort_unstable();

    let mut spans = Vec::new();
    let ram = |spans: &mut Vec<Span<'m>>, start: u64, end: u64| {
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
                image: Some(name),
            });
            cursor = cursor.max(image_end);
        }
        ram(&mut spans, cursor, end);
    }
    spans
}

/// The memory-map XML, one region per stretch. gdb reads only inside the
/// map, so the images must be in it. They are their own regions because IDA
/// lays out a module's segments first and drops every map region that
/// overlaps one: a region spanning a whole half would take the kernel with it.
fn memory_map_xml(layout: &[Span<'_>]) -> String {
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n\
         <!DOCTYPE memory-map PUBLIC \"+//IDN gnu.org//DTD GDB Memory Map V1.0//EN\" \
         \"http://sourceware.org/gdb/gdb-memory-map.dtd\">\n\
         <memory-map>\n",
    );
    for span in layout {
        let _ = writeln!(
            xml,
            "<memory type=\"ram\" start=\"{:#x}\" length=\"{:#x}\"/>",
            span.start,
            span.end - span.start
        );
    }
    xml.push_str("</memory-map>\n");
    xml
}

/// The layout in Linux `/proc/<pid>/maps` form, the only place Binary
/// Ninja's GDB adapter looks for modules and memory regions. An image is a
/// line whose path is `/` and its file name, which is how the adapter names
/// the module and matches it to the open database by base name; RAM is a line
/// with no path.
fn proc_maps(layout: &[Span<'_>]) -> String {
    let mut maps = String::new();
    for span in layout {
        let perms = if span.image.is_some() { "r-xp" } else { "rw-p" };
        let _ = write!(
            maps,
            "{:x}-{:x} {perms} 00000000 00:00 0",
            span.start, span.end
        );
        if let Some(name) = span.image {
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

/// A Windows-style library list. Each name is rooted ([`remote_path`]). For
/// AMD64 a segment address is the image base plus 0x1000, the first section's
/// address, which is how gdb reads it for PE images and what IDA subtracts
/// before rebasing; for ARM64 IDA takes the address as the image base.
fn library_list_xml<'m>(arch: Arch, modules: impl IntoIterator<Item = (&'m str, u64)>) -> String {
    let bias = match arch {
        Arch::Amd64 => 0x1000,
        Arch::Arm64 => 0,
    };
    let mut xml = String::from("<?xml version=\"1.0\"?>\n<library-list>\n");
    for (name, base) in modules {
        let _ = writeln!(
            xml,
            "<library name=\"{}\"><segment address=\"{:#x}\"/></library>",
            xml_escape(&remote_path(name)),
            base.wrapping_add(bias)
        );
    }
    xml.push_str("</library-list>\n");
    xml
}

/// The path a module's image is reported under: its file name at the root.
/// gdb fetches a file through the server (`target:`) only when its path is
/// absolute, and looks for a bare name on the host instead. The server serves
/// any path by its file name, and clients match modules by base name, so no
/// directory is needed.
fn remote_path(name: &str) -> String {
    format!("/{name}")
}

fn xml_escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            c => escaped.push(c),
        }
    }
    escaped
}

/// Copy the window `[offset, offset + length)` of `data` into `buf`, as a
/// `qXfer` read wants it. Zero means the object ended.
fn copy_window(data: &[u8], offset: u64, length: usize, buf: &mut [u8]) -> usize {
    let Some(rest) = usize::try_from(offset)
        .ok()
        .and_then(|start| data.get(start..))
    else {
        return 0;
    };
    let len = rest.len().min(length).min(buf.len());
    buf[..len].copy_from_slice(&rest[..len]);
    len
}

impl TargetDescriptionXmlOverride for GdbTarget<'_> {
    fn target_description_xml(
        &self,
        annex: &[u8],
        offset: u64,
        length: usize,
        buf: &mut [u8],
    ) -> TargetResult<usize, Self> {
        if annex != b"target.xml" {
            return Err(TargetError::NonFatal);
        }
        Ok(copy_window(
            self.layout.target_xml().as_bytes(),
            offset,
            length,
            buf,
        ))
    }
}

impl MemoryMap for GdbTarget<'_> {
    fn memory_map_xml(
        &self,
        offset: u64,
        length: usize,
        buf: &mut [u8],
    ) -> TargetResult<usize, Self> {
        let mut snapshot = self.memory_map.borrow_mut();
        if offset == 0 {
            *snapshot = self.current_memory_map();
        }
        Ok(copy_window(&snapshot, offset, length, buf))
    }
}

impl Libraries for GdbTarget<'_> {
    fn get_libraries(
        &self,
        offset: u64,
        length: usize,
        buf: &mut [u8],
    ) -> TargetResult<usize, Self> {
        let mut snapshot = self.libraries.borrow_mut();
        if offset == 0 {
            *snapshot = self.libraries_xml();
        }
        Ok(copy_window(&snapshot, offset, length, buf))
    }
}

/// The kernel image is the "program": a client that opened `ntoskrnl.exe`
/// matches it by name and rebases its database to the live kernel, and gdb
/// fetches it from the server when it has no file of its own.
impl ExecFile for GdbTarget<'_> {
    fn get_exec_file(
        &self,
        _pid: Option<Pid>,
        offset: u64,
        length: usize,
        buf: &mut [u8],
    ) -> TargetResult<usize, Self> {
        Ok(copy_window(
            remote_path(&self.kernel_image_name()).as_bytes(),
            offset,
            length,
            buf,
        ))
    }
}

/// How far the program (the kernel image) sits from its preferred base, so
/// gdb relocates a kernel file it loaded itself (`file ntoskrnl.exe`, or the
/// image Ghidra launches gdb with) onto the live kernel. Zero, which gdb takes
/// as "not relocated", while the image is not in the symbol cache.
impl SectionOffsets for GdbTarget<'_> {
    fn get_section_offsets(&mut self) -> std::result::Result<Offsets<u64>, Self::Error> {
        let slide = self.kernel_slide().unwrap_or(0);
        Ok(Offsets::Sections {
            text: slide,
            data: slide,
            bss: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{address_layout, library_list_xml, memory_map_xml, proc_maps};
    use crate::types::Arch;

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
        let amd64 = library_list_xml(Arch::Amd64, modules);
        assert!(amd64.contains(
            "<library name=\"/ntoskrnl.exe\"><segment address=\"0xfffff80000001000\"/></library>"
        ));
        assert!(amd64.contains("name=\"/a&amp;b.sys\""));

        let arm64 = library_list_xml(Arch::Arm64, modules);
        assert!(arm64.contains("<segment address=\"0xfffff80000000000\"/>"));
    }

    fn regions(xml: &str) -> Vec<(u64, u64)> {
        xml.split("<memory ")
            .skip(1)
            .map(|region| {
                let field = |key: &str| {
                    let start = region.find(&format!("{key}=\"0x")).unwrap() + key.len() + 4;
                    let end = start + region[start..].find('"').unwrap();
                    u64::from_str_radix(&region[start..end], 16).unwrap()
                };
                (field("start"), field("length"))
            })
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
        let xml = memory_map_xml(&address_layout(Arch::Amd64, &images));
        let regions = regions(&xml);

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
