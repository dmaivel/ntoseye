//! Guest memory read and written through KD requests while the target is
//! halted, and the per-halt line caches that make a serial link usable.

use std::collections::HashMap;
use std::hash::Hash;

use crate::bytes;
use crate::error::{Error, Result};
use crate::memory::PAGE_SIZE;
use crate::types::{Arch, Dtb, PhysAddr, VirtAddr};

use super::registers::KSPECIAL_REGISTERS_CR3_OFFSET;
use super::{KD_REQUEST_TIMEOUT, KdBackend, api, with_framing_read_timeout};

pub(super) const KD_REMOTE_MEMORY_CHUNK: usize = 0x800;
/// Unit of [`LineCache`]. A serial link pays per byte (a QEMU UART
/// exits the guest for each one: about 2 ms per request plus 5 us per
/// byte), so a line is sized to pay for itself after a few field reads
/// rather than to fill a request.
pub(super) const KD_VIRTUAL_LINE: usize = 0x200;
/// Lines a [`LineCache`] holds before starting over; 16 MiB of guest
/// memory, past what one halt's commands read short of an image scan.
const LINE_CACHE_LIMIT: usize = 32768;

/// Memory read through the target, remembered in `KD_VIRTUAL_LINE`-aligned
/// lines while it is halted. Nothing but this debugger changes guest memory
/// during a halt, so a line stays valid until the target runs or the
/// debugger writes. Virtual lines are keyed by the processor that resolved
/// them as well (user space follows that processor's root); page-table
/// lines by physical address.
pub(super) struct LineCache<K> {
    lines: HashMap<K, Vec<u8>>,
}

impl<K: Eq + Hash> Default for LineCache<K> {
    fn default() -> Self {
        Self {
            lines: HashMap::new(),
        }
    }
}

impl<K: Eq + Hash> LineCache<K> {
    fn get(&self, key: K) -> Option<&[u8]> {
        self.lines.get(&key).map(Vec::as_slice)
    }

    fn insert(&mut self, key: K, data: Vec<u8>) {
        if self.lines.len() >= LINE_CACHE_LIMIT {
            self.lines.clear();
        }
        self.lines.insert(key, data);
    }

    pub(super) fn clear(&mut self) {
        self.lines.clear();
    }
}

impl KdBackend {
    fn require_remote_memory_stopped(&self) -> Result<()> {
        if self.link.is_running() {
            return Err(Error::TargetRunning(self.running_reason));
        }
        self.require_no_pending_write_breakpoint()
    }

    pub(super) fn read_physical_bytes(&mut self, addr: PhysAddr, buf: &mut [u8]) -> Result<()> {
        self.require_remote_memory_stopped()?;
        let processor = self.current_processor;
        let mut completed = 0usize;
        while completed < buf.len() {
            let chunk_addr = addr
                .checked_add(completed as u64)
                .ok_or_else(|| Error::Kd("physical-memory read address overflow".into()))?;
            let requested = (buf.len() - completed).min(KD_REMOTE_MEMORY_CHUNK);
            let data =
                match with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
                    api::read_physical_memory(framing, processor, chunk_addr, requested as u32)
                }) {
                    Ok(data) => data,
                    Err(Error::KdStatus { .. }) => {
                        return Err(Error::BadPhysicalAddress(chunk_addr));
                    }
                    Err(error) => return Err(error),
                };
            kd_trace!(
                "kd: remote physical read {chunk_addr:#x}+{requested:#x} -> {:#x} {:02x?}",
                data.len(),
                &data[..data.len().min(8)]
            );
            let end = completed + data.len();
            buf[completed..end].copy_from_slice(&data);
            completed = end;
        }
        Ok(())
    }

    /// Page-table entries for the host page walk, a line of them per
    /// request: a walk of adjacent pages shares its upper-level entries and
    /// its run of PTEs, so the four reads a page costs become closer to one.
    pub(super) fn read_page_table_bytes(&mut self, addr: PhysAddr, buf: &mut [u8]) -> Result<()> {
        self.require_remote_memory_stopped()?;
        let processor = self.current_processor;
        let mut completed = 0usize;
        while completed < buf.len() {
            let chunk_addr = addr
                .checked_add(completed as u64)
                .ok_or_else(|| Error::Kd("physical-memory read address overflow".into()))?;
            let line = chunk_addr & !(KD_VIRTUAL_LINE as u64 - 1);
            let offset = (chunk_addr - line) as usize;
            if self.table_lines.get(line).is_none() {
                let data = match with_framing_read_timeout(
                    self.framing()?,
                    KD_REQUEST_TIMEOUT,
                    |framing| {
                        api::read_physical_memory(framing, processor, line, KD_VIRTUAL_LINE as u32)
                    },
                ) {
                    Ok(data) => data,
                    Err(Error::KdStatus { .. }) => {
                        return Err(Error::BadPhysicalAddress(chunk_addr));
                    }
                    Err(error) => return Err(error),
                };
                kd_trace!(
                    "kd: remote table read {line:#x}+{KD_VIRTUAL_LINE:#x} -> {:#x}",
                    data.len()
                );
                self.table_lines.insert(line, data);
            }
            let data = self.table_lines.get(line).expect("line was just inserted");
            let available = data.len().saturating_sub(offset);
            if available == 0 {
                return Err(Error::BadPhysicalAddress(chunk_addr));
            }
            let end = completed + available.min(buf.len() - completed);
            buf[completed..end].copy_from_slice(&data[offset..offset + end - completed]);
            completed = end;
        }
        Ok(())
    }

    pub(super) fn write_physical_bytes(&mut self, addr: PhysAddr, buf: &[u8]) -> Result<()> {
        self.require_remote_memory_stopped()?;
        // The write may land in a page table.
        self.translations.clear();
        self.virtual_lines.clear();
        self.table_lines.clear();
        let processor = self.current_processor;
        let mut completed = 0usize;
        while completed < buf.len() {
            let chunk_addr = addr
                .checked_add(completed as u64)
                .ok_or_else(|| Error::Kd("physical-memory write address overflow".into()))?;
            let requested = (buf.len() - completed).min(KD_REMOTE_MEMORY_CHUNK);
            let written =
                with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
                    api::write_physical_memory(
                        framing,
                        processor,
                        chunk_addr,
                        &buf[completed..completed + requested],
                    )
                })? as usize;
            completed += written;
        }
        Ok(())
    }

    /// `DbgKdReadVirtualMemoryApi` resolves through the current processor's
    /// page tables: kernel space, which every root maps alike, and user
    /// space under the root that processor is running on. Both take one
    /// request per line where the host walk costs four page-table reads per
    /// page first. User space under any other root keeps the walk: the API
    /// has no address-space selector.
    pub(super) fn read_virtual_direct(
        &mut self,
        addr: VirtAddr,
        root: Dtb,
        buf: &mut [u8],
    ) -> Option<Result<()>> {
        if !self.virtual_api_serves(addr, root) {
            return None;
        }
        Some(self.read_virtual_bytes(addr, buf))
    }

    /// Whether `DbgKd{Read,Write}VirtualMemoryApi` resolves `addr` in the
    /// `root` address space. Kernel space is the same under every root, save
    /// session space, which the API resolves in the halted processor's
    /// session (as WinDbg does); user space only under the root the serving
    /// processor is running on.
    fn virtual_api_serves(&mut self, addr: VirtAddr, root: Dtb) -> bool {
        let kernel_space = match self.arch {
            Arch::Amd64 => addr.0 >> 63 != 0,
            Arch::Arm64 => addr.0 & (1 << 55) != 0,
        };
        kernel_space || self.serving_processor_runs_on(root)
    }

    /// Whether `root` is the page-table root the *serving* processor is
    /// running on.
    ///
    /// The serving processor is the one that broke in, not the one the user
    /// selected with `~Ns`: KD services every request on the processor that
    /// entered the debugger, and the packet's `Processor` field selects a
    /// register file, not an address space. Comparing the selected
    /// processor's CR3 would authorize a user-space request that the target
    /// then resolves in a different process.
    ///
    /// AMD64 only: CR3 sits in the special registers cached per halt, while
    /// the ARM64 user root (TTBR0) would cost a request of its own to learn.
    fn serving_processor_runs_on(&mut self, root: Dtb) -> bool {
        if self.arch != Arch::Amd64 || self.require_remote_memory_stopped().is_err() {
            return false;
        }
        let processor = self.last_stop_processor;
        if self.registers.special(processor).is_none() {
            let Ok(special) = self.read_special_registers_uncached(processor) else {
                return false;
            };
            self.registers.set_special(processor, special);
        }
        let Some(special) = self.registers.special(processor) else {
            return false;
        };
        let cr3 = bytes::read_u64(special, KSPECIAL_REGISTERS_CR3_OFFSET);
        let mask = self.arch.dtb_page_mask();
        cr3 & mask == root & mask
    }

    /// The write twin of [`Self::read_virtual_direct`], eligible in exactly
    /// the same address spaces.
    ///
    /// `DbgKdWriteVirtualMemoryApi` is serviced by the guest's own
    /// debug-memory path, which resolves the address through the target's own
    /// page tables and refuses a page it will not write. Writing the frame
    /// instead, through a host mapping or `DbgKdWritePhysicalMemory`, reaches
    /// whatever is mapped and reports nothing: a frame the guest reclaims
    /// afterwards carries the edit to whatever lands there next.
    ///
    /// Neither preserves write protection or copy-on-write. `KdpWriteVirtual`
    /// reaches `MmDbgCopyMemory` with `MMDBG_COPY_UNSAFE`, whose
    /// `MiDbgWriteCheck` makes the PTE writable for the duration instead of
    /// taking the fault that would copy a shared page; the CoW-capable path
    /// next to it requires IRQL <= APC_LEVEL, which the debugger, running
    /// with every other processor frozen, can never satisfy. So a breakpoint
    /// in a shared image page is seen by every process mapping that page,
    /// however it was written.
    pub(super) fn write_virtual_direct(
        &mut self,
        addr: VirtAddr,
        root: Dtb,
        buf: &[u8],
    ) -> Option<Result<()>> {
        if !self.virtual_api_serves(addr, root) {
            return None;
        }
        Some(self.write_virtual_bytes(addr, buf))
    }

    pub(super) fn write_virtual_bytes(&mut self, addr: VirtAddr, buf: &[u8]) -> Result<()> {
        self.require_remote_memory_stopped()?;
        // The write may land in a page table.
        self.translations.clear();
        self.virtual_lines.clear();
        self.table_lines.clear();
        let processor = self.current_processor;
        let mut completed = 0usize;
        while completed < buf.len() {
            let chunk_addr = addr
                .0
                .checked_add(completed as u64)
                .ok_or_else(|| Error::Kd("virtual-memory write address overflow".into()))?;
            let to_page_end = PAGE_SIZE - (chunk_addr as usize & (PAGE_SIZE - 1));
            let requested = (buf.len() - completed)
                .min(KD_REMOTE_MEMORY_CHUNK)
                .min(to_page_end);
            let written =
                match with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
                    api::write_virtual_memory(
                        framing,
                        processor,
                        chunk_addr,
                        &buf[completed..completed + requested],
                    )
                }) {
                    Ok(written) => written as usize,
                    // The target refuses a page it will not write: unmapped,
                    // or protected in a way a physical poke would have
                    // silently defeated.
                    Err(Error::KdStatus { .. }) if completed > 0 => {
                        return Err(Error::PartialWrite(completed));
                    }
                    Err(Error::KdStatus { .. }) => {
                        return Err(Error::BadVirtualAddress(VirtAddr(chunk_addr)));
                    }
                    Err(error) => return Err(error),
                };
            if written == 0 {
                return Err(Error::PartialWrite(completed));
            }
            kd_trace!(
                "kd: remote virtual write {chunk_addr:#x}+{written:#x} {:02x?}",
                &buf[completed..completed + written.min(8)]
            );
            completed += written;
        }
        Ok(())
    }

    /// A miss reads from the start of its line to the end of the request,
    /// rounded up to lines and capped at a chunk and a page: the fields of a
    /// structure cost one request between them, and a large read costs the
    /// same chunks it always did. Lines never cross a page, and a page is
    /// mapped or not as a whole, so a refused fill is exactly the hole a
    /// page walk reports. A reply shorter than the fill is the transport's
    /// limit, not a hole: its whole lines are kept and the rest asked for
    /// again.
    pub(super) fn read_virtual_bytes(&mut self, addr: VirtAddr, buf: &mut [u8]) -> Result<()> {
        self.require_remote_memory_stopped()?;
        let processor = self.current_processor;
        let request_end = addr
            .0
            .checked_add(buf.len() as u64)
            .ok_or_else(|| Error::Kd("virtual-memory read address overflow".into()))?;
        let mut completed = 0usize;
        while completed < buf.len() {
            let chunk_addr = addr.0 + completed as u64;
            let line = chunk_addr & !(KD_VIRTUAL_LINE as u64 - 1);
            let offset = (chunk_addr - line) as usize;
            let refused = |completed: usize| {
                if completed > 0 {
                    Error::PartialRead(completed)
                } else {
                    Error::BadVirtualAddress(VirtAddr(chunk_addr))
                }
            };
            if self.virtual_lines.get((processor, line)).is_none() {
                let wanted = request_end.next_multiple_of(KD_VIRTUAL_LINE as u64) - line;
                let to_page_end = PAGE_SIZE as u64 - (line & (PAGE_SIZE as u64 - 1));
                let fill = wanted.min(self.virtual_fill_cap as u64).min(to_page_end) as usize;
                let data = match with_framing_read_timeout(
                    self.framing()?,
                    KD_REQUEST_TIMEOUT,
                    |framing| api::read_virtual_memory(framing, processor, line, fill as u32),
                ) {
                    Ok(data) => data,
                    Err(Error::KdStatus { .. }) => return Err(refused(completed)),
                    Err(error) => return Err(error),
                };
                kd_trace!(
                    "kd: remote virtual read {line:#x}+{fill:#x} -> {:#x}",
                    data.len()
                );
                let whole = data.len() / KD_VIRTUAL_LINE * KD_VIRTUAL_LINE;
                if whole == 0 {
                    return Err(refused(completed));
                }
                if data.len() < fill {
                    self.virtual_fill_cap = whole;
                }
                for (index, piece) in data[..whole].chunks(KD_VIRTUAL_LINE).enumerate() {
                    self.virtual_lines.insert(
                        (processor, line + (index * KD_VIRTUAL_LINE) as u64),
                        piece.to_vec(),
                    );
                }
            }
            let data = self
                .virtual_lines
                .get((processor, line))
                .expect("line was just inserted");
            let end = completed + (data.len() - offset).min(buf.len() - completed);
            buf[completed..end].copy_from_slice(&data[offset..offset + end - completed]);
            completed = end;
        }
        Ok(())
    }
}
