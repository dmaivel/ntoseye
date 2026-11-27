//! RSP threads as vCPUs, and the register and memory access a client
//! performs through them.

use std::num::NonZeroU64;

use gdb_remote::thread::{Id, ThreadId};

use crate::base::error::{Error, Result};
use crate::base::types::VirtAddr;
use crate::nt::target::MemoryKind;
use crate::session::Session;

use super::layout::Layout;
use super::{PACKET_SIZE, Server};

/// The most memory one read returns: its hex fills the packet size the
/// server advertises.
pub(super) const MEMORY_CHUNK: usize = PACKET_SIZE / 2;

impl Server<'_> {
    pub(super) fn sync_threads(&mut self) {
        self.threads = match self.session.backend.thread_list() {
            Ok(threads) if !threads.is_empty() => threads,
            _ => vec![self.session.current_thread.clone()],
        };
    }

    /// The index of the thread with backend id `backend_id`; the first
    /// when there is none.
    pub(super) fn index_of(&self, backend_id: &str) -> usize {
        self.threads
            .iter()
            .position(|id| id == backend_id)
            .unwrap_or(0)
    }

    /// The index of the stopped vCPU (or the one `monitor ~<n>s` chose).
    pub(super) fn current_index(&self) -> usize {
        self.index_of(&self.session.current_thread)
    }

    /// The thread id of the thread at `index`: RSP thread `index + 1`,
    /// in the process thread ids carry once the client negotiated
    /// `multiprocess+` (gdb, lldb); plain otherwise, the only form IDA reads.
    pub(super) fn thread_id(&self, index: usize) -> ThreadId {
        let number = |n: u64| NonZeroU64::new(n).map_or(Id::Any, Id::Is);
        ThreadId {
            process: self.multiprocess.then(|| number(self.pid)),
            thread: number(u64::try_from(index).map_or(0, |index| index + 1)),
        }
    }

    /// The thread index `id` names: `Some(None)` for `-1` or `0`, which
    /// name none in particular; `None` for a thread that does not exist or
    /// a process other than the one threads carry.
    pub(super) fn resolve(&self, id: ThreadId) -> Option<Option<usize>> {
        if let Some(Id::Is(process)) = id.process
            && process.get() != self.pid
        {
            return None;
        }
        match id.thread {
            Id::All | Id::Any => Some(None),
            Id::Is(thread) => {
                let index = usize::try_from(thread.get()).ok()?.checked_sub(1)?;
                (index < self.threads.len()).then_some(Some(index))
            }
        }
    }

    /// Make the thread at `index` the vCPU register reads and steps apply to.
    pub(super) fn select(&mut self, index: usize) -> Result<()> {
        if self.threads.is_empty() {
            self.sync_threads();
        }
        let id = self
            .threads
            .get(index)
            .cloned()
            .ok_or_else(|| Error::InvalidArgument(format!("no thread {}", index + 1)))?;
        if self.session.current_thread != id {
            self.session.set_current_thread(&id)?;
        }
        Ok(())
    }

    /// Run `access` against the registers of the thread at `index`, then
    /// give ntoseye's current vCPU back. A client reads every thread's
    /// registers to list them, and `monitor` commands must keep acting on
    /// the stopped vCPU (or the one chosen with `monitor ~<n>s`) regardless.
    fn with_thread<T>(
        &mut self,
        index: usize,
        access: impl FnOnce(&mut Session, &Layout) -> Result<T>,
    ) -> Result<T> {
        let previous = self.session.current_thread.clone();
        self.select(index)?;
        let result = access(self.session, &self.layout);
        if self.session.current_thread != previous {
            self.session.set_current_thread(&previous)?;
        }
        result
    }

    /// The thread `g`, `G`, `p` and `P` act on.
    fn general_index(&self) -> usize {
        self.general_thread.unwrap_or_else(|| self.current_index())
    }

    /// Every register of the `Hg` thread, in `g` order. A register the
    /// thread's context lacks is unavailable (`None`, sent as `xx`): all of
    /// them for a processor a dump saved no context for.
    pub(super) fn read_registers(&mut self) -> Result<Vec<Option<u8>>> {
        let index = self.general_index();
        self.with_thread(index, |session, layout| {
            Ok(match session.read_registers() {
                Ok(file) => {
                    let known = |name: &str| recorded(session, &file, name);
                    layout.encode(&session.register_map, &file, known)
                }
                Err(_) => layout.unavailable(),
            })
        })
    }

    /// One register of the `Hg` thread, by its number in the target
    /// description; `None` when there is no such register.
    pub(super) fn read_register(&mut self, regnum: u64) -> Result<Option<Vec<Option<u8>>>> {
        let index = self.general_index();
        let Ok(regnum) = usize::try_from(regnum) else {
            return Ok(None);
        };
        self.with_thread(index, |session, layout| {
            Ok(match session.read_registers() {
                Ok(file) => {
                    let known = |name: &str| recorded(session, &file, name);
                    layout.encode_one(regnum, &session.register_map, &file, known)
                }
                Err(_) => layout.unavailable_one(regnum),
            })
        })
    }

    pub(super) fn write_registers(&mut self, wire: &[u8]) -> Result<()> {
        let index = self.general_index();
        self.with_thread(index, |session, layout| {
            session.patch_registers(|map, file| layout.decode(map, file, wire))
        })
    }

    pub(super) fn write_register(&mut self, regnum: u64, value: &[u8]) -> Result<()> {
        let index = self.general_index();
        let regnum = usize::try_from(regnum)
            .map_err(|_| Error::InvalidArgument(format!("no register number {regnum}")))?;
        self.with_thread(index, |session, layout| {
            session.patch_registers(|map, file| layout.decode_one(regnum, map, file, value))
        })
    }

    /// Up to `length` bytes at `address`, as many as can be read from its
    /// start, at most [`MEMORY_CHUNK`]; `None` when not even the first byte
    /// can. Memory follows the inspection context (`monitor .process`), not
    /// the thread: kernel space is the same on every vCPU.
    pub(super) fn read_memory(&mut self, address: u64, length: u64) -> Option<Vec<u8>> {
        let length =
            usize::try_from(length).map_or(MEMORY_CHUNK, |length| length.min(MEMORY_CHUNK));
        let mut data = vec![0u8; length];
        let read = self
            .session
            .read_masked_partial(VirtAddr(address), &mut data);
        if read == 0 && length > 0 {
            return None;
        }
        data.truncate(read);
        Some(data)
    }

    pub(super) fn write_memory(&mut self, address: u64, data: &[u8]) -> Result<()> {
        self.session
            .write_memory(MemoryKind::Virtual, address, data)
    }
}

/// Whether `file`, the selected thread's registers, records `name`: on a
/// user-mode minidump only what its `CONTEXT` flags mark present, so an
/// unrecorded register reads as unavailable, not zero, as `r` leaves it out.
fn recorded(session: &Session, file: &[u8], name: &str) -> bool {
    session
        .target
        .user_dump_arch()
        .is_none_or(|arch| arch.context_records(file, name))
}
