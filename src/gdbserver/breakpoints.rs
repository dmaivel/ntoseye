//! Software breakpoints, hardware breakpoints, and watchpoints the client
//! plants, each backed by a session breakpoint.

use gdbstub::target::ext::breakpoints::{
    Breakpoints, HwBreakpoint, HwBreakpointOps, HwWatchpoint, HwWatchpointOps, SwBreakpoint,
    SwBreakpointOps, WatchKind,
};
use gdbstub::target::{TargetError, TargetResult};

use crate::dbg_backend::{HwBreakpointAccess, WatchpointAccess};
use crate::error::Error;
use crate::gdb::BreakpointConfig;
use crate::types::VirtAddr;

use super::{GdbTarget, Planted, PlantedKind};

impl GdbTarget<'_> {
    /// Plant a client breakpoint, halting a running target for the edit.
    fn plant(&mut self, kind: PlantedKind, address: u64) -> TargetResult<bool, Self> {
        if self
            .planted
            .iter()
            .any(|planted| planted.kind == kind && planted.address == address)
        {
            return Ok(true);
        }
        let config = BreakpointConfig::default();
        let added = self.session.with_target_halted(|session| match kind {
            PlantedKind::Software => session.add_breakpoint(VirtAddr(address), None, config),
            PlantedKind::Hardware => session.breakpoints.add_hardware_configured(
                session.backend.as_mut(),
                &session.target,
                VirtAddr(address),
                HwBreakpointAccess::Execute,
                1,
                None,
                config,
            ),
            PlantedKind::Watch { len, kind } => {
                let len = u8::try_from(len).map_err(|_| {
                    Error::InvalidArgument(format!("watch length {len} is too large"))
                })?;
                // x86 has no read-only data watch; a read watch also traps
                // writes, as the DAP server's does.
                let access = match kind {
                    WatchKind::Write => WatchpointAccess::Write,
                    WatchKind::Read | WatchKind::ReadWrite => WatchpointAccess::ReadWrite,
                };
                session.add_watchpoint(VirtAddr(address), access, len, None, config)
            }
        });
        match added {
            Ok(id) => {
                self.planted.push(Planted { kind, address, id });
                Ok(true)
            }
            Err(error) => {
                eprintln!("ntoseye-gdbserver: breakpoint at {address:#x} refused: {error}");
                Err(TargetError::NonFatal)
            }
        }
    }

    fn unplant(&mut self, kind: PlantedKind, address: u64) -> TargetResult<bool, Self> {
        let Some(index) = self
            .planted
            .iter()
            .position(|planted| planted.kind == kind && planted.address == address)
        else {
            return Ok(false);
        };
        let id = self.planted.remove(index).id;
        let removed = self
            .session
            .with_target_halted(|session| session.remove_breakpoint(id));
        if let Err(error) = removed {
            eprintln!("ntoseye-gdbserver: removing breakpoint at {address:#x} failed: {error}");
            return Err(TargetError::NonFatal);
        }
        Ok(true)
    }
}

impl Breakpoints for GdbTarget<'_> {
    fn support_sw_breakpoint(&mut self) -> Option<SwBreakpointOps<'_, Self>> {
        Some(self)
    }

    fn support_hw_breakpoint(&mut self) -> Option<HwBreakpointOps<'_, Self>> {
        Some(self)
    }

    fn support_hw_watchpoint(&mut self) -> Option<HwWatchpointOps<'_, Self>> {
        Some(self)
    }
}

impl SwBreakpoint for GdbTarget<'_> {
    fn add_sw_breakpoint(&mut self, addr: u64, _kind: usize) -> TargetResult<bool, Self> {
        self.plant(PlantedKind::Software, addr)
    }

    fn remove_sw_breakpoint(&mut self, addr: u64, _kind: usize) -> TargetResult<bool, Self> {
        self.unplant(PlantedKind::Software, addr)
    }
}

impl HwBreakpoint for GdbTarget<'_> {
    fn add_hw_breakpoint(&mut self, addr: u64, _kind: usize) -> TargetResult<bool, Self> {
        self.plant(PlantedKind::Hardware, addr)
    }

    fn remove_hw_breakpoint(&mut self, addr: u64, _kind: usize) -> TargetResult<bool, Self> {
        self.unplant(PlantedKind::Hardware, addr)
    }
}

impl HwWatchpoint for GdbTarget<'_> {
    fn add_hw_watchpoint(
        &mut self,
        addr: u64,
        len: u64,
        kind: WatchKind,
    ) -> TargetResult<bool, Self> {
        self.plant(PlantedKind::Watch { len, kind }, addr)
    }

    fn remove_hw_watchpoint(
        &mut self,
        addr: u64,
        len: u64,
        kind: WatchKind,
    ) -> TargetResult<bool, Self> {
        self.unplant(PlantedKind::Watch { len, kind }, addr)
    }
}
