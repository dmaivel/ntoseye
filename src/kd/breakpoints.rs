//! Software breakpoints written through the target's `KdpBreakpointTable`,
//! including installs whose reply is still pending and table entries
//! stranded by earlier sessions.

use std::collections::HashSet;

use crate::error::{Error, Result};
use crate::kd::framing::KdFraming;
use crate::types::Arch;

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

/// Whether the instruction at `pc` is the KD breakpoint instruction (`int3`
/// on AMD64, `BRK #0xF000` on ARM64), read through the target so it reflects
/// what will execute on resume.
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
    const INT3: [u8; 1] = [0xcc];
    const BRK_F000: [u8; 4] = 0xD43E_0000u32.to_le_bytes();
    let expected: &[u8] = match arch {
        Arch::Amd64 => &INT3,
        Arch::Arm64 => &BRK_F000,
    };
    match with_framing_read_timeout(framing, KD_REQUEST_TIMEOUT, |framing| {
        api::read_virtual_memory(framing, processor, pc, expected.len() as u32)
    }) {
        Ok(bytes) => bytes == expected,
        Err(_) => false,
    }
}

/// Release every entry in the target's breakpoint table whose handle is in
/// neither `owned` nor `released`, reporting how many the target accepted and
/// adding those to `released`.
///
/// Handles are table indices plus one and only one debugger may be attached at
/// a time, so every handle we do not hold belongs to a session that is gone and
/// is ours to release. Releasing one restores the byte the entry displaced,
/// which is the only correct way to get a guest past an `int3` we cannot
/// account for. An empty slot refuses the handle. An entry whose page is not
/// resident (a breakpoint left in an unloaded driver) is accepted every time
/// but only marked expired: the kernel keeps it until the page returns, so a
/// released handle is never asked about again.
pub(super) fn restore_unowned_breakpoint_handles(
    framing: &mut KdFraming<KdTransport>,
    processor: u16,
    owned: &HashSet<u32>,
    released: &mut HashSet<u32>,
) -> usize {
    let mut reclaimed = 0;
    for handle in 1..=KD_BREAKPOINT_TABLE_SIZE {
        if owned.contains(&handle) || released.contains(&handle) {
            continue;
        }
        match with_framing_read_timeout(framing, KD_REQUEST_TIMEOUT, |framing| {
            api::restore_breakpoint(framing, processor, handle)
        }) {
            Ok(()) => {
                kd_trace!("kd: reclaim: released handle {handle}");
                released.insert(handle);
                reclaimed += 1;
            }
            // An empty slot refuses the handle; that is the common answer.
            Err(Error::KdStatus { .. }) => {}
            // Transport trouble will resurface on whatever the caller does
            // next, with a better error than a reclaim failure could give.
            Err(error) => {
                kd_trace!("kd: reclaim: handle {handle} failed: {error}");
                break;
            }
        }
    }
    reclaimed
}

/// Word reclaimed table entries for the operator. A stranded entry is
/// invisible to them but costs a breakpoint slot for the rest of the boot.
pub(super) fn reclaimed_breakpoints_notice(reclaimed: usize) -> Option<String> {
    (reclaimed != 0).then(|| {
        format!(
            "released {reclaimed} breakpoint table entr{} stranded by an earlier session",
            if reclaimed == 1 { "y" } else { "ies" }
        )
    })
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
            |framing| api::recv_write_breakpoint_reply(framing, pending.processor),
        );
        match result {
            Ok(handle) => {
                kd_trace!(
                    "kd: breakpoint: completed late WriteBreakPoint at {:#x} handle={}",
                    pending.addr,
                    handle
                );
                self.pending_write_breakpoint = None;
                self.bp_handles.insert(pending.addr, handle);
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
        let reclaimed = self.reclaim_stranded_breakpoints(processor);
        if reclaimed == 0 {
            return Err(Self::breakpoint_table_error(addr));
        }
        self.notices.extend(reclaimed_breakpoints_notice(reclaimed));
        match with_framing_read_timeout_raw(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
            api::write_breakpoint(framing, processor, addr)
        }) {
            Ok(handle) => Ok(handle),
            Err(Error::KdStatus { ntstatus, api })
                if ntstatus == STATUS_UNSUCCESSFUL && api == api::DBGKD_WRITE_BREAKPOINT =>
            {
                Err(Self::breakpoint_table_error(addr))
            }
            Err(error) => Err(error),
        }
    }

    /// Release every table handle this session does not own, reporting how many
    /// the target accepted. A handle for a free slot is refused, so the count is
    /// the number of entries actually recovered.
    fn reclaim_stranded_breakpoints(&mut self, processor: u16) -> usize {
        let owned: HashSet<u32> = self.bp_handles.values().copied().collect();
        let Ok(framing) = self.link.framing(self.running_reason) else {
            return 0;
        };
        restore_unowned_breakpoint_handles(framing, processor, &owned, &mut self.released_handles)
    }

    /// Name the cause the raw NTSTATUS hides. WinDbg reports this as
    /// `Win32 error 0n998`, "invalid access to memory location", which sends
    /// people hunting a memory-access problem that does not exist.
    fn breakpoint_table_error(addr: u64) -> Error {
        Error::Kd(format!(
            "target refused a breakpoint at {addr:#x}: all {KD_BREAKPOINT_TABLE_SIZE} entries in \
             its breakpoint table are taken; entries an earlier session stranded in a page the \
             target can no longer write back only clear when the guest reboots"
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
        let result =
            with_framing_read_timeout_raw(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
                api::write_breakpoint(framing, processor, addr)
            });
        let handle = match result {
            Ok(handle) => handle,
            Err(Error::Io(e)) if is_temporary_io_error(e.kind()) => {
                self.pending_write_breakpoint = Some(PendingWriteBreakpoint { addr, processor });
                return Err(Error::Kd(format!(
                    "KD request timed out after {}s; breakpoint install is pending, retry the same bp command to complete it",
                    KD_REQUEST_TIMEOUT.as_secs()
                )));
            }
            Err(Error::KdStatus { ntstatus, api })
                if ntstatus == STATUS_UNSUCCESSFUL && api == api::DBGKD_WRITE_BREAKPOINT =>
            {
                self.write_breakpoint_after_reclaim(addr, processor)?
            }
            Err(err) => return Err(err),
        };
        kd_trace!("kd: write_breakpoint: {addr:#x} -> handle {handle}");
        self.bp_handles.insert(addr, handle);
        self.managed_bp_addresses.insert(addr);
        Ok(())
    }

    pub(super) fn uninstall_breakpoint(&mut self, addr: u64) -> Result<()> {
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
        Ok(())
    }
}
