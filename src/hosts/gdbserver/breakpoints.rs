//! Software breakpoints, hardware breakpoints, and watchpoints the client
//! plants (`Z`) and removes (`z`), each backed by a session breakpoint.

use gdb_remote::request::{Breakpoint, BreakpointType};

use crate::arch::HwBreakpointAccess;
use crate::backend::dbg_backend::{DebugCapability, WatchpointAccess};
use crate::base::error::{Error, Result};
use crate::base::memory::{NonResident, Place};
use crate::base::types::VirtAddr;
use crate::nt::breakpoints::BreakpointConfig;

use super::{Planted, Server};

impl Server<'_> {
    /// Plant a client breakpoint, halting a running target for the edit.
    /// Planting one the client already has succeeds without a second.
    pub(super) fn plant(&mut self, breakpoint: &Breakpoint<'_>) -> Result<()> {
        let Breakpoint {
            ty: kind,
            address,
            kind: len,
            ..
        } = *breakpoint;
        if self
            .planted
            .iter()
            .any(|planted| planted.kind == kind && planted.address == address && planted.len == len)
        {
            return Ok(());
        }
        // A backend that plants no software breakpoints (a dump) refuses
        // the request itself, which says more than the page does.
        let plants = [
            DebugCapability::KernelBreakpoints,
            DebugCapability::UserModeBreakpoints,
        ]
        .into_iter()
        .any(|capability| self.session.backend.supports(capability));
        if kind == BreakpointType::Software && plants && self.never_code(address) {
            return Err(Error::Breakpoint(format!(
                "no code can be at {address:#x} (its page is unmapped or demand-zero), so a \
                 breakpoint there could never hit"
            )));
        }
        let config = BreakpointConfig::default();
        let id = self.session.with_target_halted(|session| match kind {
            BreakpointType::Software => session.add_breakpoint(VirtAddr(address), None, config),
            BreakpointType::Hardware => session.add_hardware_breakpoint(
                VirtAddr(address),
                HwBreakpointAccess::Execute,
                1,
                None,
                config,
            ),
            BreakpointType::WriteWatch
            | BreakpointType::ReadWatch
            | BreakpointType::AccessWatch => {
                let len = u8::try_from(len).map_err(|_| {
                    Error::InvalidArgument(format!("watch length {len} is too large"))
                })?;
                // x86 has no read-only data watch; a read watch also traps
                // writes, as the DAP server's does.
                let access = match kind {
                    BreakpointType::WriteWatch => WatchpointAccess::Write,
                    _ => WatchpointAccess::ReadWrite,
                };
                session.add_watchpoint(VirtAddr(address), access, len, None, config)
            }
        })?;
        let serial = self
            .session
            .breakpoints
            .listed(id)
            .map_or(0, |bp| bp.serial);
        self.planted.push(Planted {
            kind,
            address,
            len,
            id,
            serial,
        });
        Ok(())
    }

    /// Remove a client breakpoint, halting a running target for the edit.
    pub(super) fn unplant(&mut self, breakpoint: &Breakpoint<'_>) -> Result<()> {
        let Some(index) = self.planted.iter().position(|planted| {
            planted.kind == breakpoint.ty
                && planted.address == breakpoint.address
                && planted.len == breakpoint.kind
        }) else {
            return Err(Error::Breakpoint(format!(
                "no breakpoint of the client's at {:#x}",
                breakpoint.address
            )));
        };
        let Planted { id, serial, .. } = self.planted[index];
        // Cleared through `monitor` already, possibly with the id reused
        // since by a breakpoint the client does not own.
        if self.session.breakpoints.live(id, serial).is_none() {
            self.planted.remove(index);
            return Ok(());
        }
        let removed = self
            .session
            .with_target_halted(|session| session.remove_breakpoint(id));
        match removed {
            Ok(()) | Err(Error::BPNotFound(_)) => {
                self.planted.remove(index);
                Ok(())
            }
            // The site is still installed: keep owning it, so its hits stay
            // the client's and a detach retries the removal.
            Err(error) => Err(error),
        }
    }

    /// Whether no code will ever be at `address`: nothing maps its page,
    /// or the page is demand-zero, which reads as zeros once touched. The
    /// session accepts a breakpoint on a page that is not in memory, which
    /// the target writes when the page arrives (paged-out kernel code); a
    /// driver's discarded `INIT` section is left demand-zero (seen over KD
    /// on Windows 11 26200), its code gone, and the client must hear that
    /// its breakpoint cannot hit.
    fn never_code(&self, address: u64) -> bool {
        let target = &self.session.target;
        let address = VirtAddr(address);
        let dtb = if target.arch().paging().is_kernel_address(address) {
            target.kernel_dtb()
        } else {
            target.current_dtb()
        };
        matches!(
            target.non_resident(dtb, address),
            Some(NonResident {
                place: Place::Unmapped | Place::DemandZero,
                ..
            })
        )
    }
}
