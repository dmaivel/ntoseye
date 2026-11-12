//! Software breakpoints written through the target's `KdpBreakpointTable`,
//! including installs whose reply is still pending and table entries
//! stranded by earlier sessions.

use std::collections::HashSet;

use crate::arch::Arch;
use crate::backend::kd::framing::KdFraming;
use crate::base::error::{Error, Result};
use crate::base::notice::Notice;
use crate::base::types::VirtAddr;

use super::transport::KdTransport;
use super::{
    KD_REQUEST_TIMEOUT, KdBackend, STATUS_UNSUCCESSFUL, api, is_temporary_io_error,
    with_framing_read_timeout, with_framing_read_timeout_raw,
};

#[derive(Debug, Clone, Copy)]
pub(super) struct PendingWriteBreakpoint {
    pub(super) addr: u64,
    pub(super) processor: u16,
}

/// Entries in the target's `KdpBreakpointTable`. A fixed global in every
/// Windows kernel (`BREAKPOINT_TABLE_SIZE`), and the ceiling on how many
/// software breakpoints any debugger can have installed at once.
pub(super) const KD_BREAKPOINT_TABLE_SIZE: u32 = 32;

/// Whether the instruction at `pc` is the KD breakpoint instruction
/// ([`Arch::breakpoint_instruction`]), read through the target so it
/// reflects what will execute on resume.
///
/// An unreadable PC answers `false`. The only thing this answer is used for is
/// deciding whether to step the PC past a byte, and guessing wrong in that
/// direction costs a repeated stop, where guessing wrong in the other resumes
/// the guest inside an instruction.
pub(super) fn breakpoint_instruction_at(
    framing: &mut KdFraming<KdTransport>,
    arch: Arch,
    processor: u16,
    pc: u64,
) -> bool {
    let expected = arch.breakpoint_instruction();
    match with_framing_read_timeout(framing, KD_REQUEST_TIMEOUT, |framing| {
        api::read_virtual_memory(framing, processor, pc, expected.len() as u32)
    }) {
        Ok(bytes) => bytes == expected,
        Err(_) => false,
    }
}

/// The table entries earlier sessions left, as this session found them.
#[derive(Debug, Default)]
pub struct StrandedEntries {
    /// Handles whose entry was released: the slot was freed, and is ours
    /// to fill since.
    pub released: HashSet<u32>,
    /// Handles whose entry the target kept. Its restore puts the code the
    /// entry saved back only where it finds the breakpoint instruction the
    /// entry wrote, and only into a resident page; otherwise it keeps the
    /// entry, marked as owing that restore: a site an earlier session wrote
    /// over, or a breakpoint left in a page since paged out or unloaded.
    /// Asking again is no use. The entry stays until a page fault in its
    /// page lets the target finish the restore, the guest reboots, or a
    /// breakpoint is installed at its address, which the target answers
    /// with this entry (see [`KdBackend::replant_held_entry`]).
    pub held: HashSet<u32>,
}

/// What one pass of [`restore_unowned_breakpoint_handles`] did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Reclaim {
    /// Entries released.
    pub released: usize,
    /// Entries the target kept.
    pub held: usize,
}

/// Release every entry in the target's breakpoint table whose handle is
/// neither `owned` nor already in `stranded`, recording each in `stranded`
/// as released or held.
///
/// Handles are table indices plus one and only one debugger may be attached at
/// a time, so every handle we do not hold belongs to a session that is gone and
/// is ours to release. Releasing one restores the byte the entry displaced,
/// which is the only correct way to get a guest past an `int3` we cannot
/// account for. An empty slot refuses the handle. The target accepts the
/// handle of an entry it keeps too (see [`StrandedEntries::held`]), so a
/// handle it accepts is asked for once more: the slot it freed refuses.
pub(super) fn restore_unowned_breakpoint_handles(
    framing: &mut KdFraming<KdTransport>,
    processor: u16,
    owned: &HashSet<u32>,
    stranded: &mut StrandedEntries,
) -> Result<Reclaim> {
    let mut reclaim = Reclaim::default();
    let mut restore = |handle| {
        with_framing_read_timeout(framing, KD_REQUEST_TIMEOUT, |framing| {
            api::restore_breakpoint(framing, processor, handle)
        })
    };
    for handle in 1..=KD_BREAKPOINT_TABLE_SIZE {
        if owned.contains(&handle)
            || stranded.released.contains(&handle)
            || stranded.held.contains(&handle)
        {
            continue;
        }
        let answer = match restore(handle) {
            Ok(()) => restore(handle),
            // An empty slot refuses the handle; that is the common answer.
            Err(Error::KdStatus { .. }) => continue,
            Err(error) => Err(error),
        };
        match answer {
            Err(Error::KdStatus { .. }) => {
                kd_trace!("kd: reclaim: released handle {handle}");
                stranded.released.insert(handle);
                reclaim.released += 1;
            }
            Ok(()) => {
                kd_trace!("kd: reclaim: the target keeps handle {handle}");
                stranded.held.insert(handle);
                reclaim.held += 1;
            }
            // Once something was reclaimed the caller can act on it, and the
            // transport trouble resurfaces on its next request. Before that,
            // an empty reclaim would read as a full table, so the error is
            // the honest answer.
            Err(error) => {
                kd_trace!("kd: reclaim: handle {handle} failed: {error}");
                if reclaim == Reclaim::default() {
                    return Err(error);
                }
                break;
            }
        }
    }
    Ok(reclaim)
}

/// Word a reclaim for the operator. A stranded entry is invisible to them
/// but costs a breakpoint slot, and one the target keeps goes on costing it.
pub(super) fn reclaimed_breakpoints_notice(reclaim: Reclaim) -> Option<Notice> {
    let entries = |count: usize| {
        format!(
            "{count} breakpoint table entr{}",
            if count == 1 { "y" } else { "ies" }
        )
    };
    let released = format!(
        "released {} stranded by an earlier session",
        entries(reclaim.released)
    );
    let held = format!(
        "{} an earlier session left could not be released: the target could not put back the \
         code {} displaced, and keeps {} until it can",
        entries(reclaim.held),
        if reclaim.held == 1 { "it" } else { "they" },
        if reclaim.held == 1 { "it" } else { "them" },
    );
    match (reclaim.released, reclaim.held) {
        (0, 0) => None,
        (_, 0) => Some(Notice::info(released)),
        (0, _) => Some(Notice::warning(held)),
        _ => Some(Notice::warning(format!("{released}; {held}"))),
    }
}

impl KdBackend {
    fn pending_write_breakpoint_error(pending: PendingWriteBreakpoint) -> Error {
        Error::Kd(format!(
            "breakpoint install at {:#x} is pending; retry the same bp command before issuing other KD commands",
            pending.addr
        ))
    }

    pub(super) fn require_no_pending_write_breakpoint(&self) -> Result<()> {
        match self.pending_write_breakpoint {
            Some(pending) => Err(Self::pending_write_breakpoint_error(pending)),
            None => Ok(()),
        }
    }

    fn complete_pending_write_breakpoint(&mut self, addr: u64) -> Result<bool> {
        let Some(pending) = self.pending_write_breakpoint else {
            return Ok(false);
        };
        if pending.addr != addr {
            return Err(Self::pending_write_breakpoint_error(pending));
        }

        kd_trace!(
            "kd: breakpoint: waiting for late WriteBreakPoint reply at {:#x}",
            pending.addr
        );
        let result = with_framing_read_timeout_raw(
            self.framing_unchecked()?,
            KD_REQUEST_TIMEOUT,
            |framing| api::recv_write_breakpoint_reply(framing, pending.processor, pending.addr),
        );
        match result {
            Ok(handle) => {
                kd_trace!(
                    "kd: breakpoint: completed late WriteBreakPoint at {:#x} handle={}",
                    pending.addr,
                    handle
                );
                self.pending_write_breakpoint = None;
                let handle = self.replant_held_entry(pending.addr, pending.processor, handle)?;
                self.bp_handles.insert(pending.addr, handle);
                self.dropped_bp_addresses.remove(&pending.addr);
                self.managed_bp_addresses.insert(pending.addr);
                Ok(true)
            }
            Err(Error::Io(e)) if is_temporary_io_error(e.kind()) => Err(Error::Kd(format!(
                "KD request timed out after {}s; breakpoint install is still pending",
                KD_REQUEST_TIMEOUT.as_secs()
            ))),
            Err(err) => {
                self.pending_write_breakpoint = None;
                Err(err)
            }
        }
    }

    /// Reclaim breakpoint slots stranded by an earlier debugger session, then
    /// retry the install once.
    ///
    /// `KdpAddBreakpoint` answers `STATUS_UNSUCCESSFUL` in exactly two cases a
    /// debugger can hit: the address already has an entry in the target's
    /// 32-slot `KdpBreakpointTable`, or every slot is taken. Both mean the same
    /// thing in practice, because only the debugger holding a handle can
    /// release one and a session killed mid-flight takes its handles with it -
    /// so a fresh session can be locked out of an address it never touched,
    /// until the guest reboots.
    ///
    /// Handles are table indices plus one and only one debugger may be attached
    /// at a time, so every handle we do not own belongs to a dead session and is
    /// ours to release. Releasing one cannot corrupt the guest: before writing
    /// an entry's saved byte back, `KdpLowWriteContent` checks the site still
    /// holds the breakpoint instruction. When that write-back cannot happen,
    /// as for a breakpoint in a driver's discarded `INIT` section, the target
    /// reports success but keeps the entry, marked suspended: the address is
    /// installable again, though the slot itself only frees on reboot.
    fn write_breakpoint_after_reclaim(&mut self, addr: u64, processor: u16) -> Result<u32> {
        let reclaimed = self.reclaim_stranded_breakpoints(processor)?;
        self.notices.extend(reclaimed_breakpoints_notice(reclaimed));
        if reclaimed.released == 0 {
            return Err(self.breakpoint_table_error(addr));
        }
        match self.write_breakpoint(addr, processor) {
            Ok(handle) => Ok(handle),
            Err(Error::KdStatus { ntstatus, api })
                if ntstatus == STATUS_UNSUCCESSFUL && api == api::DBGKD_WRITE_BREAKPOINT =>
            {
                Err(self.breakpoint_table_error(addr))
            }
            Err(error) => Err(error),
        }
    }

    /// Release every table handle this session does not own (see
    /// [`restore_unowned_breakpoint_handles`]).
    fn reclaim_stranded_breakpoints(&mut self, processor: u16) -> Result<Reclaim> {
        let owned: HashSet<u32> = self.bp_handles.values().copied().collect();
        let framing = self.link.framing(self.running_reason)?;
        restore_unowned_breakpoint_handles(framing, processor, &owned, &mut self.stranded)
    }

    /// Ask the target for a breakpoint at `addr`. A reply that does not come
    /// in time leaves the install pending: the target may still have added
    /// the entry, and its late reply, which only a retry of the same install
    /// takes (see [`Self::complete_pending_write_breakpoint`]), names it.
    fn write_breakpoint(&mut self, addr: u64, processor: u16) -> Result<u32> {
        let result =
            with_framing_read_timeout_raw(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
                api::write_breakpoint(framing, processor, addr)
            });
        if let Err(Error::Io(e)) = &result
            && is_temporary_io_error(e.kind())
        {
            self.pending_write_breakpoint = Some(PendingWriteBreakpoint { addr, processor });
            return Err(Error::Kd(format!(
                "KD request timed out after {}s; breakpoint install is pending, retry the same bp command to complete it",
                KD_REQUEST_TIMEOUT.as_secs()
            )));
        }
        result
    }

    /// Name the cause the raw NTSTATUS hides. WinDbg reports this as
    /// `Win32 error 0n998`, "invalid access to memory location", which sends
    /// people hunting a memory-access problem that does not exist. Every
    /// entry may hold this session's own sites, which only clearing some
    /// frees; otherwise the rest are strays an earlier session left where
    /// the target cannot restore them.
    fn breakpoint_table_error(&self, addr: u64) -> Error {
        let owned = self.bp_handles.len();
        let cause = if owned >= KD_BREAKPOINT_TABLE_SIZE as usize {
            "this session's breakpoints and traps hold them all; clear some with bc".to_string()
        } else {
            format!(
                "this session holds {owned}, and an earlier session stranded the rest in pages \
                 the target can no longer write back, which only clear when the guest reboots"
            )
        };
        Error::BreakpointTableFull(format!(
            "target refused a breakpoint at {addr:#x}: all {KD_BREAKPOINT_TABLE_SIZE} entries in \
             its breakpoint table are taken; {cause}"
        ))
    }

    pub(super) fn install_breakpoint(&mut self, addr: u64) -> Result<()> {
        if self.complete_pending_write_breakpoint(addr)? {
            return Ok(());
        }

        // The target patches the site itself; every line read from here on
        // must see it.
        self.virtual_lines.clear();
        let processor = self.current_processor;
        let handle = match self.write_breakpoint(addr, processor) {
            Ok(handle) => handle,
            Err(Error::KdStatus { ntstatus, api })
                if ntstatus == STATUS_UNSUCCESSFUL && api == api::DBGKD_WRITE_BREAKPOINT =>
            {
                self.write_breakpoint_after_reclaim(addr, processor)?
            }
            Err(err) => return Err(err),
        };
        let handle = self.replant_held_entry(addr, processor, handle)?;
        kd_trace!("kd: write_breakpoint: {addr:#x} -> handle {handle}");
        self.bp_handles.insert(addr, handle);
        self.dropped_bp_addresses.remove(&addr);
        self.managed_bp_addresses.insert(addr);
        Ok(())
    }

    /// The target answered an install at `addr` with `handle`. When that is
    /// an entry an earlier session left and the target kept (see
    /// [`StrandedEntries::held`]), the install wrote nothing: for an entry
    /// still owing its restore at the same address, `KdpAddBreakpoint`
    /// drops the debt and hands the entry back, taking the breakpoint
    /// instruction it once wrote to be in place, so the breakpoint would
    /// never hit. Release the entry the only way the target allows, by
    /// giving its restore the instruction it looks for, put back the code
    /// that was there if the copy the entry saved differs, and install
    /// afresh. Any other handle is returned as it is.
    ///
    /// Whatever the target answered with is an entry at `addr` now, no
    /// longer the one held: the held entry was handed back, or it had freed
    /// itself (a page fault let its restore finish) and its slot went to
    /// this install. So the handle leaves [`StrandedEntries::held`] either
    /// way. When the replant fails, the entry is left to the next reclaim,
    /// which releases it or finds it kept again; a handle still counted as
    /// held would be skipped, and every install at `addr` refused.
    fn replant_held_entry(&mut self, addr: u64, processor: u16, handle: u32) -> Result<u32> {
        if !self.stranded.held.remove(&handle) {
            return Ok(handle);
        }
        kd_trace!("kd: write_breakpoint: {addr:#x} got kept handle {handle}; replanting");
        self.release_held_entry(addr, processor, handle)
    }

    fn release_held_entry(&mut self, addr: u64, processor: u16, handle: u32) -> Result<u32> {
        let instruction = self.arch.breakpoint_instruction();
        let mut code = vec![0u8; instruction.len()];
        self.read_virtual_bytes(VirtAddr(addr), &mut code)?;
        if code == instruction {
            return Ok(handle);
        }
        if let Err(error) = self.restore_held_entry(addr, processor, handle, &code) {
            // The site may hold the instruction written for the restore, or
            // the entry's stale copy the restore wrote: put back the code
            // that was there, so that the next release of the entry finds
            // no breakpoint and leaves the code alone.
            self.virtual_lines.clear();
            let _ = self.write_virtual_bytes(VirtAddr(addr), &code);
            return Err(error);
        }
        self.write_breakpoint(addr, processor)
    }

    /// Release the held entry `handle` at `addr`, whose site holds `code`,
    /// leaving `code` there.
    fn restore_held_entry(
        &mut self,
        addr: u64,
        processor: u16,
        handle: u32,
        code: &[u8],
    ) -> Result<()> {
        let instruction = self.arch.breakpoint_instruction();
        self.write_virtual_bytes(VirtAddr(addr), instruction)?;
        with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
            api::restore_breakpoint(framing, processor, handle)
        })?;
        // The restore wrote the code the entry saved.
        self.virtual_lines.clear();
        self.stranded.released.insert(handle);
        let mut restored = vec![0u8; code.len()];
        self.read_virtual_bytes(VirtAddr(addr), &mut restored)?;
        if restored != code {
            self.write_virtual_bytes(VirtAddr(addr), code)?;
        }
        Ok(())
    }

    pub(super) fn uninstall_breakpoint(&mut self, addr: u64) -> Result<()> {
        // A report already deleted the entry and wrote the byte back; its
        // handle may name someone else's entry by now.
        if self.dropped_bp_addresses.remove(&addr) {
            kd_trace!("kd: breakpoint at {addr:#x} was dropped by a report; nothing to restore");
            self.managed_bp_addresses.remove(&addr);
            self.retired_bp_addresses.insert(addr);
            return Ok(());
        }
        let handle = *self
            .bp_handles
            .get(&addr)
            .ok_or_else(|| Error::Kd(format!("no breakpoint tracked at {addr:#x}")))?;
        self.virtual_lines.clear();
        let processor = self.current_processor;
        let result = with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
            api::restore_breakpoint(framing, processor, handle)
        });
        match result {
            Ok(()) => {}
            Err(Error::KdStatus { ntstatus, api })
                if ntstatus == STATUS_UNSUCCESSFUL && api == api::DBGKD_RESTORE_BREAKPOINT =>
            {
                // The target refuses a handle whose table entry it has
                // already reclaimed, which is what a stop does to every
                // entry it suspends. That is only the harmless answer if the
                // site is clean: forgetting an address that still holds the
                // breakpoint instruction leaves an `int3` no one claims, and
                // the next resume steps the program counter past it and into
                // the middle of the instruction it displaced. Keep the
                // handle so a retry (and exit) can still release the entry.
                let arch = self.arch;
                if breakpoint_instruction_at(
                    self.link.framing(self.running_reason)?,
                    arch,
                    processor,
                    addr,
                ) {
                    return Err(Error::Kd(format!(
                        "target refused to release the breakpoint at {addr:#x} (handle {handle}) \
                         and the site still holds a breakpoint instruction"
                    )));
                }
                kd_trace!(
                    "kd: restore breakpoint handle {handle} at {addr:#x} was already consumed"
                );
            }
            // Transport failure: the site may still be patched, so keep
            // tracking it (a retry restores it; a hit there is still ours).
            Err(e) => return Err(e),
        }
        self.bp_handles.remove(&addr);
        self.managed_bp_addresses.remove(&addr);
        self.retired_bp_addresses.insert(addr);
        Ok(())
    }
}
