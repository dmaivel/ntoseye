//! A walk's reads: the stack page cache, the module image cache (in-memory
//! or on-disk), and the fallback scan for return addresses.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use pelite::pe64::{Pe, PeView, image::IMAGE_SCN_MEM_EXECUTE};

use super::{CachedModule, OwnedModule, StackTracer, ThreadTraceContext};
use crate::{
    backend::MemoryOps,
    error::{Error, Result},
    guest::{Image, ModuleInfo, PeImage, pe_headers_end, read_pe_image},
    memory::{AddressSpace, PAGE_SIZE},
    symbols::ImageFetch,
    target::Target,
    types::VirtAddr,
};

const STACK_SCAN_BYTES: usize = 0x1000;

impl<'a> StackTracer<'a> {
    pub(super) fn new(debugger: &'a Target, trace: &'a ThreadTraceContext) -> Self {
        Self {
            trace,
            phys: &debugger.phys,
            symbols: &debugger.symbols,
            memory: debugger.address_space(trace.active_dtb),
            modules: HashMap::new(),
            stack_pages: RefCell::new(HashMap::new()),
            kernel: debugger.guest.as_ref().map(|guest| &guest.ntoskrnl),
        }
    }

    /// A stack slot, from the per-trace page cache.
    pub(super) fn stack_u64(&self, address: u64) -> Result<u64> {
        let mut bytes = [0u8; 8];
        let mut done = 0usize;
        while done < bytes.len() {
            let at = address
                .checked_add(done as u64)
                .ok_or(Error::BadVirtualAddress(VirtAddr(address)))?;
            let page = at & !(PAGE_SIZE as u64 - 1);
            let offset = (at - page) as usize;
            let take = (bytes.len() - done).min(PAGE_SIZE - offset);
            let mut pages = self.stack_pages.borrow_mut();
            let cached = pages.entry(page).or_insert_with(|| {
                let mut buf = vec![0u8; PAGE_SIZE];
                self.memory
                    .read_bytes(VirtAddr(page), &mut buf)
                    .ok()
                    .map(|()| buf.into_boxed_slice())
            });
            let Some(data) = cached else {
                return Err(Error::BadVirtualAddress(VirtAddr(at)));
            };
            bytes[done..done + take].copy_from_slice(&data[offset..offset + take]);
            done += take;
        }
        Ok(u64::from_le_bytes(bytes))
    }

    pub(super) fn scan_stack(
        &mut self,
        start_rsp: u64,
        seen: &HashSet<u64>,
        limit: usize,
    ) -> Vec<(u64, u64)> {
        let mut frames = Vec::new();
        let mut failures = 0usize;

        if limit == 0 {
            return frames;
        }

        for slot in 0..(STACK_SCAN_BYTES / 8) {
            if frames.len() >= limit {
                break;
            }
            if failures >= 32 {
                break;
            }

            let sp = start_rsp.saturating_add((slot * 8) as u64);
            let potential_ip = match self.stack_u64(sp) {
                Ok(addr) => {
                    failures = 0;
                    addr
                }
                Err(_) => {
                    failures += 1;
                    continue;
                }
            };

            if seen.contains(&potential_ip) || !self.is_executable_address(potential_ip) {
                continue;
            }

            frames.push((sp, potential_ip));
        }

        frames
    }

    pub(super) fn is_executable_address(&mut self, address: u64) -> bool {
        let Some(module) = self.module_containing(address) else {
            return false;
        };

        let rva = (address - module.info.base_address.0) as u32;
        module
            .executable_ranges
            .iter()
            .any(|(start, end)| rva >= *start && rva < *end)
    }

    pub(super) fn module_containing(&mut self, address: u64) -> Option<&CachedModule> {
        let module = self.trace.module_for_address(address)?;

        self.ensure_module_loaded(&module)?;
        self.modules.get(&(module.dtb, module.info.base_address.0))
    }

    /// A cheap clone of the cached image handle for the module containing
    /// `address` (the module must already be loaded).
    pub(super) fn module_image(&self, address: u64) -> Option<Arc<PeImage>> {
        let module = self.trace.module_for_address(address)?;
        self.modules
            .get(&(module.dtb, module.info.base_address.0))
            .map(|cached| cached.image.clone())
    }

    /// Replace a module's holed in-memory image with the complete on-disk one,
    /// downloading it if needed. Returns whether the cache now holds a complete
    /// image. No-op (false) when the image is already complete or the on-disk
    /// fetch fails (non-Microsoft module, offline); the caller then degrades to
    /// a stack scan.
    pub(super) fn upgrade_module_image(&mut self, address: u64) -> bool {
        let Some(module) = self.trace.module_for_address(address) else {
            return false;
        };
        let key = (module.dtb, module.info.base_address.0);

        let disk = {
            let Some(cached) = self.modules.get(&key) else {
                return false;
            };
            if cached.image.is_complete() {
                return false;
            }
            self.on_disk_image(&cached.image, &module.info, ImageFetch::Download)
        };
        let Some(disk) = disk else {
            return false;
        };

        unwind_trace!(
            "unwind: recovered on-disk image for {} (in-memory unwind data paged out)",
            module.info.short_name
        );
        let executable_ranges = executable_ranges(&disk);
        self.modules.insert(
            key,
            CachedModule {
                info: module.info.clone(),
                image: disk,
                executable_ranges,
            },
        );
        true
    }

    fn ensure_module_loaded(&mut self, module: &OwnedModule) -> Option<()> {
        let key = (module.dtb, module.info.base_address.0);
        if self.modules.contains_key(&key) {
            return Some(());
        }

        let kernel_image = self
            .kernel
            .filter(|kernel| {
                kernel.base_address == module.info.base_address && kernel.dtb() == module.dtb
            })
            .and_then(Image::image);
        let image = match kernel_image {
            Some(image) => image,
            None => {
                let (phys, dtb) = (Arc::clone(self.phys), module.dtb);
                match read_pe_image(module.info.base_address, move |address, buf| {
                    AddressSpace::new(&phys, dtb).read_bytes(address, buf)
                }) {
                    Ok(img) => Arc::new(img),
                    Err(_) => {
                        // Triage dumps don't contain PE headers; download the PE from
                        // the symbol server using the driver list's metadata.
                        let tds = module.info.time_date_stamp?;
                        unwind_trace!(
                            "unwind: in-memory PE unreadable for {}, downloading via timestamp",
                            module.info.short_name
                        );
                        self.symbols
                            .module_image_on_disk(
                                &module.info.name,
                                tds,
                                module.info.size,
                                ImageFetch::Download,
                            )
                            .ok()?
                    }
                }
            }
        };
        let image = match self.cached_on_disk_image(&image, &module.info) {
            Some(disk) if !image.is_complete() => {
                unwind_trace!(
                    "unwind: using cached on-disk image for {}",
                    module.info.short_name
                );
                disk
            }
            _ => image,
        };
        let executable_ranges = executable_ranges(&image);

        self.modules.insert(
            key,
            CachedModule {
                info: module.info.clone(),
                image,
                executable_ranges,
            },
        );

        Some(())
    }

    /// The module's on-disk image when the image cache already holds it: its
    /// unwind tables are the guest's, relocation-free, and cost no reads
    /// from the target. The file must open with the headers the guest
    /// mapped; a mismatch keeps the guest image. Nothing is downloaded here.
    fn cached_on_disk_image(&self, image: &PeImage, info: &ModuleInfo) -> Option<Arc<PeImage>> {
        let disk = self.on_disk_image(image, info, ImageFetch::CacheOnly)?;
        let headers_end = pe_headers_end(image.headers())?;
        headers_match_relocated(
            disk.headers().get(..headers_end)?,
            image.headers().get(..headers_end)?,
        )
        .then_some(disk)
    }

    /// The module's complete on-disk PE image, matched by the in-memory
    /// header's TimeDateStamp + SizeOfImage and downloaded if needed when
    /// `fetch` allows. A recovering caller re-resolves against it to decide
    /// whether it actually recovered anything.
    fn on_disk_image(
        &self,
        image: &PeImage,
        info: &ModuleInfo,
        fetch: ImageFetch,
    ) -> Option<Arc<PeImage>> {
        let view = PeView::from_bytes(image.headers()).ok()?;
        self.symbols
            .module_image_on_disk(
                &info.name,
                view.file_header().TimeDateStamp,
                view.optional_header().SizeOfImage,
                fetch,
            )
            .ok()
    }
}

/// The `[start, end)` RVA ranges of a module's executable sections (used to
/// validate scan candidates).
fn executable_ranges(image: &PeImage) -> Vec<(u32, u32)> {
    let Ok(view) = PeView::from_bytes(image.headers()) else {
        return Vec::new();
    };
    view.section_headers()
        .iter()
        .filter_map(|section| {
            if section.Characteristics & IMAGE_SCN_MEM_EXECUTE == 0 {
                return None;
            }
            let size = section.VirtualSize.max(section.SizeOfRawData);
            if size == 0 {
                return None;
            }
            Some((
                section.VirtualAddress,
                section.VirtualAddress.saturating_add(size),
            ))
        })
        .collect()
}

/// Whether `disk` is the file `mapped` was loaded from: the headers agree
/// except in `OptionalHeader.ImageBase`, which the loader rewrites to the
/// address it relocated the image to.
fn headers_match_relocated(disk: &[u8], mapped: &[u8]) -> bool {
    if disk.len() != mapped.len() || disk.len() < 0x40 {
        return false;
    }
    let e_lfanew = u32::from_le_bytes(disk[0x3c..0x40].try_into().unwrap()) as usize;
    let optional = e_lfanew + 24;
    let Some(magic) = disk.get(optional..optional + 2) else {
        return false;
    };
    let image_base = match u16::from_le_bytes([magic[0], magic[1]]) {
        0x20b => optional + 24..optional + 32,
        0x10b => optional + 28..optional + 32,
        _ => return false,
    };
    if image_base.end > disk.len() {
        return false;
    }
    disk[..image_base.start] == mapped[..image_base.start]
        && disk[image_base.end..] == mapped[image_base.end..]
}
