//! A walk's reads: the stack page cache, the module image cache (in-memory
//! or on-disk), and the fallback scan for return addresses.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use pelite::pe64::{Pe, PeView};

use super::{
    CachedModule, FrameMemory, FrameRegisters, OwnedModule, StackPage, StackTracer,
    ThreadTraceContext, frame_registers_from_saved, unwinder,
};
use crate::nt::trapframe::decode_ktrap_frame_for_thread;
use crate::{
    base::{
        error::{Error, Result},
        memory::{MemoryOps, PAGE_SIZE, Residency, read_page_chunks},
        types::{CodeMachine, VirtAddr},
    },
    nt::{
        guest::{Image, ModuleInfo},
        pe::{self, CodeLayout, PeImage},
        symbols::ImageFetch,
        target::{Target, TargetKind},
    },
};

const STACK_SCAN_BYTES: usize = 0x1000;

impl<'a> StackTracer<'a> {
    pub(super) fn new(debugger: &'a Target, trace: &'a ThreadTraceContext) -> Self {
        Self {
            target: debugger,
            trace,
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
        self.stack_bytes(address, &mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    /// A pointer-sized stack slot, as wide as the traced space's
    /// architecture's pointers.
    fn stack_pointer(&self, address: u64) -> Result<u64> {
        let arch = self.memory.arch();
        let mut bytes = [0u8; 8];
        let bytes = &mut bytes[..arch.pointer_size() as usize];
        self.stack_bytes(address, bytes)?;
        Ok(arch.decode_pointer(bytes).0)
    }

    /// `bytes.len()` bytes of stack at `address`, from the per-trace page
    /// cache.
    fn stack_bytes(&self, address: u64, bytes: &mut [u8]) -> Result<()> {
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
                let (bytes, valid) = read_page_chunks(VirtAddr(page), PAGE_SIZE, |at, buf| {
                    self.memory.read_bytes(at, buf)
                })
                .ok()?;
                if !valid.contains(&true) {
                    return None;
                }
                Some(StackPage {
                    bytes: bytes.into_boxed_slice(),
                    valid: valid.contains(&false).then(|| valid.into_boxed_slice()),
                })
            });
            let Some(data) = cached.as_ref().filter(|data| {
                data.valid
                    .as_ref()
                    .is_none_or(|valid| valid[offset..offset + take].iter().all(|byte| *byte))
            }) else {
                return Err(Error::BadVirtualAddress(VirtAddr(at)));
            };
            bytes[done..done + take].copy_from_slice(&data.bytes[offset..offset + take]);
            done += take;
        }
        Ok(())
    }

    pub(super) fn scan_stack(
        &mut self,
        start_rsp: u64,
        seen: &HashSet<u64>,
        limit: usize,
    ) -> Vec<(u64, u64)> {
        let mut frames = Vec::new();
        // A stale copy of a return address (a spill slot, a frame since
        // popped) is no second frame: each address is listed once.
        let mut found = HashSet::new();
        let mut failures = 0usize;

        if limit == 0 {
            return frames;
        }

        let slot_size = self.memory.arch().pointer_size() as usize;
        for slot in 0..(STACK_SCAN_BYTES / slot_size) {
            if frames.len() >= limit {
                break;
            }
            if failures >= 32 {
                break;
            }

            let sp = start_rsp.saturating_add((slot * slot_size) as u64);
            let potential_ip = match self.stack_pointer(sp) {
                Ok(addr) => {
                    failures = 0;
                    addr
                }
                Err(_) => {
                    failures += 1;
                    continue;
                }
            };

            if seen.contains(&potential_ip)
                || found.contains(&potential_ip)
                || !self.is_executable_address(potential_ip)
            {
                continue;
            }
            // On a root none of NT's (the hypervisor's), NT's modules are not
            // mapped: an NT address on its stack is a guest's value, and only
            // its own image holds return addresses.
            if let Some(image) = self.trace.foreign_image.as_ref()
                && !(image.base_address.0..image.base_address.0 + u64::from(image.size))
                    .contains(&potential_ip)
            {
                continue;
            }

            found.insert(potential_ip);
            frames.push((sp, potential_ip));
        }

        frames
    }

    pub(super) fn is_executable_address(&mut self, address: u64) -> bool {
        let Some(module) = self.module_containing(address) else {
            // Code no module holds is executable where a dynamic function
            // table describes it.
            return self.dynamic_function(address).is_some();
        };

        let rva = (address - module.info.base_address.0) as u32;
        module
            .executable_ranges
            .iter()
            .any(|(start, end)| rva >= *start && rva < *end)
    }

    /// Whether a return address the unwind found is code: by
    /// [`Self::is_executable_address`], or, outside every module of a
    /// kernel target, in a page the tables map executable. JIT-compiled code
    /// is there, and .NET Framework's has no tables to read: an in-process
    /// callback gives its unwind data. The stack scan keeps to the strict
    /// test, which needs no page walk for each slot it reads.
    pub(super) fn is_return_address(&mut self, address: u64) -> bool {
        if self.is_executable_address(address) {
            return true;
        }
        self.target.kind() == TargetKind::Kernel
            && self.module_containing(address).is_none()
            && matches!(
                self.memory.virt_to_phys(VirtAddr(address)),
                Ok(Some(page)) if page.residency == Residency::Mapped && !page.nx
            )
    }

    pub(super) fn module_containing(&mut self, address: u64) -> Option<&CachedModule> {
        let module = self.trace.module_for_address(address)?;

        self.ensure_module_loaded(&module)?;
        self.modules.get(&(module.dtb, module.info.base_address.0))
    }

    /// Cheap clones of the cached image handle for the module containing
    /// `address`, and of its code layout (the module must already be
    /// loaded).
    pub(super) fn module_code(
        &self,
        address: u64,
    ) -> Option<(Arc<PeImage>, Option<Arc<CodeLayout>>)> {
        let module = self.trace.module_for_address(address)?;
        self.modules
            .get(&(module.dtb, module.info.base_address.0))
            .map(|cached| (cached.image.clone(), cached.layout.clone()))
    }

    /// Whether `context` is at a Windows hypervisor VM-exit entry, where its
    /// stack begins.
    pub fn at_hypervisor_stack_base(&self, context: &FrameRegisters) -> bool {
        let (Some(symbols), Some(image)) = (&self.trace.hypervisor, &self.trace.foreign_image)
        else {
            return false;
        };
        context
            .pc
            .checked_sub(image.base_address.0)
            .and_then(|rva| u32::try_from(rva).ok())
            .is_some_and(|rva| symbols.in_exit_entry(rva))
    }

    /// The instruction set of the code at `address`, which picks the
    /// unwinder for its frame.
    pub(super) fn code_machine_at(&mut self, address: u64) -> CodeMachine {
        unwinder(self.target.arch()).code_machine_at(self, address)
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
        // The foreign image's file was looked for when it was loaded, and no
        // server has one (see `ensure_module_loaded`).
        if self.is_foreign_image(&module.info) {
            return false;
        }
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
        self.modules
            .insert(key, CachedModule::new(module.info.clone(), disk));
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
                // A session-space driver (win32k) is not mapped in the
                // kernel's address space, its module's, but is in the
                // traced thread's process's.
                match self
                    .target
                    .mapped_pe_image(module.dtb, module.info.base_address)
                    .or_else(|error| {
                        if self.trace.active_dtb == module.dtb {
                            return Err(error);
                        }
                        self.target
                            .mapped_pe_image(self.trace.active_dtb, module.info.base_address)
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
        let disk = if self.is_foreign_image(&module.info) {
            // The Windows hypervisor's loader is not NT's, so its header
            // may differ from the file's in more than `ImageBase`; the key
            // the file is found by comes from the mapped header.
            self.on_disk_image(&image, &module.info, ImageFetch::Local)
        } else {
            self.cached_on_disk_image(&image, &module.info)
        };
        let image = match disk {
            Some(disk) if !image.is_complete() => {
                unwind_trace!(
                    "unwind: using cached on-disk image for {}",
                    module.info.short_name
                );
                disk
            }
            _ => image,
        };
        self.modules
            .insert(key, CachedModule::new(module.info.clone(), image));

        Some(())
    }

    /// The module's on-disk image when the image cache already holds it: its
    /// unwind tables are the guest's, relocation-free, and cost no reads
    /// from the target. The file must open with the headers the guest
    /// mapped; a mismatch keeps the guest image. Nothing is downloaded here.
    fn cached_on_disk_image(&self, image: &PeImage, info: &ModuleInfo) -> Option<Arc<PeImage>> {
        self.symbols
            .module_image_matching(&info.name, image.headers(), ImageFetch::CacheOnly)
    }

    /// Whether `info` is the trace's foreign image (the Windows
    /// hypervisor's), which no symbol server has.
    pub fn is_foreign_image(&self, info: &ModuleInfo) -> bool {
        self.trace
            .foreign_image
            .as_ref()
            .is_some_and(|image| image.base_address == info.base_address)
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

impl CachedModule {
    fn new(info: ModuleInfo, image: Arc<PeImage>) -> Self {
        Self {
            info,
            executable_ranges: executable_ranges(&image),
            layout: image.code_layout().map(Arc::new),
            image,
        }
    }
}

/// The `[start, end)` RVA ranges of a module's executable sections (used to
/// validate scan candidates).
fn executable_ranges(image: &PeImage) -> Vec<(u32, u32)> {
    PeView::from_bytes(image.headers())
        .map_or_else(|_| Vec::new(), |view| pe::executable_ranges(&view))
}

impl FrameMemory for StackTracer<'_> {
    fn stack_u64(&self, address: u64) -> Option<u64> {
        StackTracer::stack_u64(self, address).ok()
    }

    fn trap_frame(&self, address: u64) -> Option<FrameRegisters> {
        let saved =
            decode_ktrap_frame_for_thread(self.target, self.trace.active_dtb, VirtAddr(address))
                .ok()?;
        frame_registers_from_saved(&saved)
    }
}
