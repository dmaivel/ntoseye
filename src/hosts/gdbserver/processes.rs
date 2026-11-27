//! Windows processes as GDB processes: the process list (`info os
//! processes`), and attaching to one (`attach PID` in extended mode),
//! which selects it as the inspection context as `monitor .process /i`
//! does. The threads stay the vCPUs; their ids carry the attached process.

use gdb_remote::xfer::{Item, Osdata};

use crate::base::error::{Error, Result};

use super::{KERNEL_PID, Server, halt_for_client};

/// The `osdata` tables the server publishes, with what `info os` shows for
/// each: type, description, title.
const TABLES: [(&str, &str, &str); 1] = [("processes", "Listing of all processes", "Processes")];

impl Server<'_> {
    /// The `osdata` table `annex` names: the list of tables for the empty
    /// annex, as gdbserver gives it. The process list is read with the
    /// target halted (a client in extended mode lists processes after it
    /// detached, when the guest runs), and a guest halted for it runs on.
    pub(super) fn osdata(&mut self, annex: &str) -> Result<Osdata> {
        let column = |name: &str, value: String| (name.to_string(), value);
        let items = match annex {
            "" => TABLES
                .iter()
                .map(|&(kind, description, title)| Item {
                    columns: vec![
                        column("Type", kind.to_string()),
                        column("Description", description.to_string()),
                        column("Title", title.to_string()),
                    ],
                })
                .collect(),
            "processes" => self
                .session
                .with_target_halted(|session| session.target.matching_processes(None))?
                .into_iter()
                .map(|process| Item {
                    columns: vec![
                        column("pid", process.pid.to_string()),
                        column("command", process.name),
                    ],
                })
                .collect(),
            _ => {
                return Err(Error::InvalidArgument(format!(
                    "no operating system data of type {annex}"
                )));
            }
        };
        Ok(Osdata {
            kind: if annex.is_empty() { "types" } else { annex }.to_string(),
            items,
        })
    }

    /// `vAttach`: halt the target, if it runs, and make process `pid` the
    /// inspection context until the client detaches. The stop reply that
    /// answers it, and every thread id after, carries `pid`. Attaching to
    /// [`KERNEL_PID`] returns to the kernel's context. The process's module
    /// symbols are not loaded up front, as `.process /i` loads them: over
    /// KD that takes most of a minute, and gdb gives up on a reply after
    /// six seconds. They load as stacks reach them.
    pub(super) fn attach(&mut self, pid: u64) -> Result<Vec<u8>> {
        // The process list reads guest memory, which a running guest (one
        // the client detached from in extended mode) does not give.
        halt_for_client(self.session);
        let process = if pid == KERNEL_PID {
            None
        } else {
            let processes = self.session.target.matching_processes(None)?;
            Some(
                processes
                    .into_iter()
                    .find(|process| process.pid == pid)
                    .ok_or(Error::ProcessNotFound(pid))?,
            )
        };
        self.in_repl(|state| {
            state.leave_vtl1();
            match process {
                Some(process) => state.ctx.target.enter_process_scope(process),
                None => state.ctx.target.detach(),
            }
            state.caches.refresh_symbol_context(&state.ctx.target);
            state.clear_selected_frame();
        });
        self.pid = pid;
        self.last_stop = None;
        Ok(self.halt_reply())
    }

    /// The client is done with its process (`D` in extended mode, `vKill`):
    /// remove its breakpoints and return to the kernel's context. The
    /// connection stays. Whether every breakpoint is gone.
    pub(super) fn forget_process(&mut self) -> bool {
        let removed = self.remove_planted();
        if self.pid != KERNEL_PID {
            self.in_repl(|state| {
                state.ctx.target.detach();
                state.caches.refresh_symbol_context(&state.ctx.target);
                state.clear_selected_frame();
            });
        }
        self.pid = KERNEL_PID;
        self.last_stop = None;
        removed
    }

    /// `qGetTIBAddr`: on a user-mode minidump, the thread's TEB, from
    /// which gdb finds where the program is loaded. A kernel target
    /// answers nothing: a vCPU's thread has a TEB only in user mode, and
    /// gdb would take that process's image base for the kernel's.
    pub(super) fn tib_address(&mut self, index: usize) -> Option<Result<u64>> {
        self.session.target.user_dump_info()?;
        let previous = self.session.current_thread.clone();
        let teb = self.select(index).map(|()| {
            self.session
                .target
                .builtin_variable_value("teb")
                .filter(|&teb| teb != 0)
        });
        if let Err(error) = self.session.set_current_thread(&previous) {
            return Some(Err(error));
        }
        Some(teb.and_then(|teb| {
            teb.ok_or_else(|| Error::DebugInfo("the dump records no TEB for this thread".into()))
        }))
    }
}
