//! A recording [`DebugBackend`] stub shared by the breakpoint tests.

use std::time::Duration;

use crate::dbg_backend::{DebugBackend, StopEvent};
use crate::error::{Error, Result};
use crate::gdb::RegisterMap;

/// Backend stub that records which DR slots `clear_hardware_breakpoint`
/// releases; every other operation is out of scope for these tests.
pub(super) struct SlotRecorder {
    register_map: RegisterMap,
    pub(super) cleared: Vec<u8>,
    /// Address the target refuses a breakpoint at, like a driver's
    /// discarded `INIT` section.
    refused: Option<u64>,
    pub(super) installed: Vec<u64>,
}

impl SlotRecorder {
    pub(super) fn new() -> Self {
        Self {
            register_map: RegisterMap::default(),
            cleared: Vec::new(),
            refused: None,
            installed: Vec::new(),
        }
    }

    pub(super) fn accepting() -> Self {
        Self::refusing(u64::MAX)
    }

    pub(super) fn refusing(address: u64) -> Self {
        Self {
            refused: Some(address),
            ..Self::new()
        }
    }
}

impl DebugBackend for SlotRecorder {
    fn register_map(&self) -> &RegisterMap {
        &self.register_map
    }
    /// Host-patched (user-space) sites are refused outright without this,
    /// so the recorder has to look like a live backend that can patch
    /// guest memory.
    fn supports_user_mode_breakpoints(&self) -> bool {
        true
    }
    fn read_registers(&mut self) -> Result<Vec<u8>> {
        Err(Error::NotSupported)
    }
    fn write_registers(&mut self, _data: &[u8]) -> Result<()> {
        Err(Error::NotSupported)
    }
    fn set_breakpoint(&mut self, addr: u64) -> Result<()> {
        if self.refused == Some(addr) {
            return Err(Error::Kd("kernel returned NTSTATUS 0xc0000001".into()));
        }
        if self.refused.is_none() {
            return Err(Error::NotSupported);
        }
        self.installed.push(addr);
        Ok(())
    }
    fn remove_breakpoint(&mut self, _addr: u64) -> Result<()> {
        Err(Error::NotSupported)
    }
    fn clear_hardware_breakpoint(&mut self, slot: u8) -> Result<()> {
        self.cleared.push(slot);
        Ok(())
    }
    fn continue_execution(&mut self) -> Result<()> {
        Err(Error::NotSupported)
    }
    fn step(&mut self) -> Result<()> {
        Err(Error::NotSupported)
    }
    fn interrupt(&mut self) -> Result<StopEvent> {
        Err(Error::NotSupported)
    }
    fn wait_for_stop(&mut self) -> Result<StopEvent> {
        Err(Error::NotSupported)
    }
    fn try_wait_for_stop(&mut self, _timeout: Duration) -> Result<Option<StopEvent>> {
        Ok(None)
    }
    fn thread_list(&mut self) -> Result<Vec<String>> {
        Err(Error::NotSupported)
    }
    fn set_current_thread(&mut self, _thread_id: &str) -> Result<()> {
        Err(Error::NotSupported)
    }
    fn stopped_thread_id(&mut self) -> Result<String> {
        Err(Error::NotSupported)
    }
    fn is_running(&self) -> bool {
        false
    }
}
