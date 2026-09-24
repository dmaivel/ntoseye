//! The synchronized handles a connected backend is split into, so the
//! debugger facade and guest memory share one KD transport.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use crate::backend::MemoryOps;
use crate::dbg_backend::{
    BackendCapability, ContinueDisposition, DebugBackend, DebugOutputPage, HwBreakpointAccess,
    StopEvent, TrapState,
};
use crate::debugger_data::DebuggerDataCandidate;
use crate::error::Result;
use crate::gdb::RegisterMap;
use crate::memory::TranslationCache;
use crate::phys::PhysMem;
use crate::types::{Dtb, KernelLocation, PhysAddr, VirtAddr};

use super::{KdBackend, KdBackendHandle, KdMemory};

impl KdBackendHandle {
    fn lock(&self) -> MutexGuard<'_, KdBackend> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl KdMemory {
    fn lock(&self) -> MutexGuard<'_, KdBackend> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl MemoryOps<PhysAddr> for KdMemory {
    fn read_bytes(&self, addr: PhysAddr, buf: &mut [u8]) -> Result<()> {
        self.lock().read_physical_bytes(addr, buf)
    }

    fn write_bytes(&self, addr: PhysAddr, buf: &[u8]) -> Result<()> {
        self.lock().write_physical_bytes(addr, buf)
    }

    fn read_virtual_direct(&self, addr: VirtAddr, root: Dtb, buf: &mut [u8]) -> Option<Result<()>> {
        self.lock().read_virtual_direct(addr, root, buf)
    }

    fn write_virtual_direct(&self, addr: VirtAddr, root: Dtb, buf: &[u8]) -> Option<Result<()>> {
        self.lock().write_virtual_direct(addr, root, buf)
    }

    fn can_mediate_writes(&self) -> bool {
        !self.lock().link.is_running()
    }

    fn translation_cache(&self) -> Option<&TranslationCache> {
        Some(&self.translations)
    }

    fn read_page_table_bytes(&self, addr: PhysAddr, buf: &mut [u8]) -> Result<()> {
        self.lock().read_page_table_bytes(addr, buf)
    }
}

impl KdBackend {
    /// Convert a connected KD backend into synchronized debugger and memory
    /// handles after target hints have been collected. The memory handle
    /// serves every source: it is the whole memory source for `kd`, and the
    /// write path for `host`.
    pub fn into_remote_memory(self) -> (KdBackendHandle, KdMemory) {
        let register_map = self.register_map.clone();
        let backend_name = self.backend_name;
        let translations = Arc::clone(&self.translations);
        let inner = Arc::new(Mutex::new(self));
        (
            KdBackendHandle {
                inner: Arc::clone(&inner),
                register_map,
                backend_name,
            },
            KdMemory {
                inner,
                translations,
            },
        )
    }
}

impl DebugBackend for KdBackendHandle {
    fn register_map(&self) -> &RegisterMap {
        &self.register_map
    }
    fn registers_are_context(&self) -> bool {
        true
    }

    fn revalidate_host_memory(&mut self, phys: &PhysMem) -> Result<()> {
        let mut backend = self.lock();
        let hints = backend.target_hints()?;
        backend.validate_host_memory(phys, hints)
    }

    fn name(&self) -> &'static str {
        self.backend_name
    }

    fn set_kernel_dtb(&mut self, dtb: u64) {
        self.lock().set_kernel_dtb(dtb);
    }

    fn read_registers(&mut self) -> Result<Vec<u8>> {
        self.lock().read_registers()
    }

    fn stop_trap_state(&mut self) -> Option<TrapState> {
        self.lock().stop_trap_state()
    }

    fn surface_next_break_at(&mut self, address: Option<u64>) {
        self.lock().surface_next_break_at(address);
    }

    fn write_registers(&mut self, data: &[u8]) -> Result<()> {
        self.lock().write_registers(data)
    }

    fn set_breakpoint(&mut self, addr: u64) -> Result<()> {
        self.lock().set_breakpoint(addr)
    }

    fn remove_breakpoint(&mut self, addr: u64) -> Result<()> {
        self.lock().remove_breakpoint(addr)
    }

    fn supports_watchpoints(&self) -> bool {
        self.lock().supports_watchpoints()
    }

    fn hardware_breakpoint_slots(&self) -> u8 {
        self.lock().hardware_breakpoint_slots()
    }

    fn hardware_slot_range(&self, access: HwBreakpointAccess) -> std::ops::Range<u8> {
        self.lock().hardware_slot_range(access)
    }

    fn set_hardware_breakpoint(
        &mut self,
        slot: u8,
        addr: u64,
        access: HwBreakpointAccess,
        len: u8,
    ) -> Result<()> {
        self.lock().set_hardware_breakpoint(slot, addr, access, len)
    }

    fn clear_hardware_breakpoint(&mut self, slot: u8) -> Result<()> {
        self.lock().clear_hardware_breakpoint(slot)
    }

    fn supports_user_mode_breakpoints(&self) -> bool {
        self.lock().supports_user_mode_breakpoints()
    }

    fn supports_msr(&self) -> bool {
        self.lock().supports_msr()
    }

    fn read_msr(&mut self, processor: u16, msr: u32) -> Result<u64> {
        self.lock().read_msr(processor, msr)
    }

    fn write_msr(&mut self, processor: u16, msr: u32, value: u64) -> Result<()> {
        self.lock().write_msr(processor, msr, value)
    }

    fn supports_target_control(&self) -> bool {
        self.lock().supports_target_control()
    }

    fn supports_target_file_io(&self) -> bool {
        self.lock().supports_target_file_io()
    }

    fn reboot_target(&mut self) -> Result<()> {
        self.lock().reboot_target()
    }

    fn cause_bugcheck(&mut self) -> Result<()> {
        self.lock().cause_bugcheck()
    }

    fn optional_capabilities(&self) -> Vec<BackendCapability> {
        self.lock().optional_capabilities()
    }

    fn read_debug_output(&self, since_seq: u64) -> DebugOutputPage {
        self.lock().read_debug_output(since_seq)
    }

    fn take_notices(&mut self) -> Vec<String> {
        self.lock().take_notices()
    }

    fn note_breakpoint_installed(&mut self, addr: u64) {
        self.lock().note_breakpoint_installed(addr);
    }

    fn note_breakpoint_uninstalled(&mut self, addr: u64) {
        self.lock().note_breakpoint_uninstalled(addr);
    }

    fn note_target_rediscovery_pending(&mut self) {
        self.lock().note_target_rediscovery_pending();
    }

    fn note_target_rediscovery_complete(&mut self) {
        self.lock().note_target_rediscovery_complete();
    }

    fn target_manages_breakpoint_sites(&self) -> bool {
        self.lock().target_manages_breakpoint_sites()
    }

    fn sites_dropped_by_stop(&self) -> Vec<u64> {
        self.lock().sites_dropped_by_stop()
    }

    fn target_kernel_location(&mut self) -> Result<Option<KernelLocation>> {
        self.lock().target_kernel_location()
    }

    fn target_debugger_data_hint(&mut self) -> Result<Option<DebuggerDataCandidate>> {
        self.lock().target_debugger_data_hint()
    }

    fn continue_execution(&mut self) -> Result<()> {
        self.lock().continue_execution()
    }

    fn continue_execution_with_disposition(
        &mut self,
        disposition: ContinueDisposition,
    ) -> Result<()> {
        self.lock().continue_execution_with_disposition(disposition)
    }

    fn step(&mut self) -> Result<()> {
        self.lock().step()
    }

    fn interrupt(&mut self) -> Result<StopEvent> {
        self.lock().interrupt()
    }

    fn wait_for_stop(&mut self) -> Result<StopEvent> {
        self.lock().wait_for_stop()
    }

    fn try_wait_for_stop(&mut self, timeout: Duration) -> Result<Option<StopEvent>> {
        self.lock().try_wait_for_stop(timeout)
    }

    fn thread_list(&mut self) -> Result<Vec<String>> {
        self.lock().thread_list()
    }

    fn set_current_thread(&mut self, thread_id: &str) -> Result<()> {
        self.lock().set_current_thread(thread_id)
    }

    fn stopped_thread_id(&mut self) -> Result<String> {
        self.lock().stopped_thread_id()
    }

    fn is_running(&self) -> bool {
        self.lock().is_running()
    }

    fn has_pending_stop(&self) -> bool {
        self.lock().has_pending_stop()
    }

    fn prepare_for_exit(&mut self, leave_running: bool) -> Result<()> {
        self.lock().prepare_for_exit(leave_running)
    }
}
