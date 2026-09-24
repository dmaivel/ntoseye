//! RSP threads as vCPUs, and the register and memory access a client
//! performs through them.

use std::num::NonZeroUsize;

use gdbstub::common::Tid;
use gdbstub::target::ext::base::multithread::{MultiThreadBase, MultiThreadResumeOps};
use gdbstub::target::ext::base::single_register_access::{
    SingleRegisterAccess, SingleRegisterAccessOps,
};
use gdbstub::target::{TargetError, TargetResult};
use libc::EFAULT;

use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::session::Session;
use crate::types::VirtAddr;

use super::layout::Layout;
use super::{GdbTarget, WireRegId, WireRegisters};

impl GdbTarget<'_> {
    pub(super) fn sync_threads(&mut self) {
        self.threads = match self.session.backend.thread_list() {
            Ok(threads) if !threads.is_empty() => threads,
            _ => vec![self.session.current_thread.clone()],
        };
    }

    fn tid_of(&self, backend_id: &str) -> Tid {
        let index = self
            .threads
            .iter()
            .position(|id| id == backend_id)
            .unwrap_or(0);
        NonZeroUsize::new(index + 1).expect("index + 1 is never zero")
    }

    pub(super) fn current_tid(&self) -> Tid {
        self.tid_of(&self.session.current_thread)
    }

    /// Make `tid` the vCPU register reads and steps apply to.
    pub(super) fn select(&mut self, tid: Tid) -> Result<()> {
        if self.threads.is_empty() {
            self.sync_threads();
        }
        let id = self
            .threads
            .get(tid.get() - 1)
            .cloned()
            .ok_or_else(|| Error::InvalidArgument(format!("no thread {tid}")))?;
        if self.session.current_thread != id {
            self.session.set_current_thread(&id)?;
        }
        Ok(())
    }

    /// Run `access` against `tid`'s registers, then give ntoseye's current
    /// vCPU back. A client reads every thread's registers to list them, and
    /// `monitor` commands must keep acting on the stopped vCPU (or the one
    /// chosen with `monitor ~<n>s`) regardless.
    fn with_thread<T>(
        &mut self,
        tid: Tid,
        access: impl FnOnce(&mut Session, &Layout) -> Result<T>,
    ) -> Result<T> {
        let previous = self.session.current_thread.clone();
        self.select(tid)?;
        let result = access(self.session, &self.layout);
        if self.session.current_thread != previous {
            self.session.set_current_thread(&previous)?;
        }
        result
    }
}

/// A session failure the client can recover from: it gets an error reply and
/// the connection stays up.
fn nonfatal<T>(result: Result<T>) -> std::result::Result<T, TargetError<Error>> {
    result.map_err(|_| TargetError::NonFatal)
}

impl MultiThreadBase for GdbTarget<'_> {
    fn read_registers(&mut self, regs: &mut WireRegisters, tid: Tid) -> TargetResult<(), Self> {
        regs.0 = nonfatal(self.with_thread(tid, |session, layout| {
            let file = session.read_registers()?;
            Ok(layout.encode(&session.register_map, &file))
        }))?;
        Ok(())
    }

    fn write_registers(&mut self, regs: &WireRegisters, tid: Tid) -> TargetResult<(), Self> {
        let wire: Vec<u8> = regs.0.iter().map(|byte| byte.unwrap_or(0)).collect();
        nonfatal(self.with_thread(tid, |session, layout| {
            session.patch_registers(|map, file| layout.decode(map, file, &wire))
        }))
    }

    fn support_single_register_access(&mut self) -> Option<SingleRegisterAccessOps<'_, Tid, Self>> {
        Some(self)
    }

    fn read_addrs(
        &mut self,
        start_addr: u64,
        data: &mut [u8],
        _tid: Tid,
    ) -> TargetResult<usize, Self> {
        // Memory follows the inspection context (`monitor .process`), not
        // the thread: kernel space is the same on every vCPU.
        match self.session.read_masked_partial(VirtAddr(start_addr), data) {
            0 if !data.is_empty() => Err(TargetError::Errno(EFAULT as u8)),
            read => Ok(read),
        }
    }

    fn write_addrs(&mut self, start_addr: u64, data: &[u8], _tid: Tid) -> TargetResult<(), Self> {
        let written = self
            .session
            .target
            .context_memory()
            .write_bytes(VirtAddr(start_addr), data);
        written.map_err(|_| TargetError::Errno(EFAULT as u8))
    }

    fn list_active_threads(
        &mut self,
        thread_is_active: &mut dyn FnMut(Tid),
    ) -> std::result::Result<(), Self::Error> {
        if self.threads.is_empty() {
            self.sync_threads();
        }
        // The stopped vCPU first: a client's `?` reports the first thread.
        let current = self.current_tid();
        thread_is_active(current);
        for index in 0..self.threads.len() {
            let tid = NonZeroUsize::new(index + 1).expect("index + 1 is never zero");
            if tid != current {
                thread_is_active(tid);
            }
        }
        Ok(())
    }

    fn support_resume(&mut self) -> Option<MultiThreadResumeOps<'_, Self>> {
        Some(self)
    }
}

impl SingleRegisterAccess<Tid> for GdbTarget<'_> {
    fn read_register(
        &mut self,
        tid: Tid,
        reg_id: WireRegId,
        buf: &mut [u8],
    ) -> TargetResult<usize, Self> {
        let value = nonfatal(self.with_thread(tid, |session, layout| {
            let file = session.read_registers()?;
            layout
                .encode_one(reg_id.0, &session.register_map, &file)
                .ok_or(Error::NotSupported)
        }))?;
        let slot = buf.get_mut(..value.len()).ok_or(TargetError::NonFatal)?;
        slot.copy_from_slice(&value);
        Ok(value.len())
    }

    fn write_register(
        &mut self,
        tid: Tid,
        reg_id: WireRegId,
        val: &[u8],
    ) -> TargetResult<(), Self> {
        nonfatal(self.with_thread(tid, |session, layout| {
            session.patch_registers(|map, file| layout.decode_one(reg_id.0, map, file, val))
        }))
    }
}
