//! How much processor time each thread of a process has used (`!runaway`):
//! user and kernel time, and how long ago each started. A kernel target
//! counts them in clock ticks in each `KTHREAD`; a user-mode minidump's
//! thread-info stream records them in 100 ns units.

use ntoseye_macros::record;

use crate::base::error::{Error, Result};
use crate::base::memory::MemoryOps;
use crate::nt::kuser_shared::KuserSharedData;
use crate::nt::target::{KTHREAD_STATE_TERMINATED, Target, ThreadInfo};

/// FILETIME (100 ns units since 1601) at the Unix epoch.
const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;
/// 100 ns units in a second.
const FILETIME_SECOND: u64 = 10_000_000;

/// The times of one thread, in 100 ns units.
#[record]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadTime {
    pub tid: u64,
    /// Its place in a user-mode minidump's thread list (`~` numbers), `None`
    /// on a kernel target.
    pub index: Option<usize>,
    pub user_time: Option<u64>,
    pub kernel_time: Option<u64>,
    /// How long ago it started, at the time of the target: now on a live
    /// one, when the dump was written on a dump. Until it exited, for one
    /// that has.
    pub elapsed: Option<u64>,
}

/// A kernel thread's times (see [`Target::kernel_thread_times_of`]).
#[derive(Debug, Clone, Copy, Default)]
pub struct KernelThreadTimes {
    pub create_time: Option<u64>,
    pub exit_time: Option<u64>,
    pub kernel_time: Option<u64>,
    pub user_time: Option<u64>,
}

/// The processor times of a process's threads (`!runaway`).
#[record]
#[derive(Debug, Clone)]
pub struct ThreadTimes {
    /// The process's image name.
    pub process: Option<String>,
    pub pid: Option<u64>,
    pub threads: Vec<ThreadTime>,
}

impl Target {
    /// The processor times of the threads of the current process: the one
    /// .process selected, else the owner of the current thread; on a
    /// user-mode minidump, its one process.
    pub fn thread_times(&self) -> Result<ThreadTimes> {
        match self.user_dump_info() {
            Some(info) => {
                // MINIDUMP_HEADER.TimeDateStamp is in seconds since 1970.
                let written =
                    FILETIME_UNIX_EPOCH + u64::from(info.time_date_stamp) * FILETIME_SECOND;
                let threads = info
                    .threads
                    .iter()
                    .enumerate()
                    .map(|(index, thread)| {
                        let times = thread.times.as_ref();
                        ThreadTime {
                            tid: u64::from(thread.tid),
                            index: Some(index),
                            user_time: times.map(|times| times.user_time),
                            kernel_time: times.map(|times| times.kernel_time),
                            elapsed: times.and_then(|times| {
                                let end = if times.exit_time != 0 {
                                    times.exit_time
                                } else {
                                    written
                                };
                                end.checked_sub(times.create_time)
                            }),
                        }
                    })
                    .collect();
                let process = info.process();
                Ok(ThreadTimes {
                    process: process.name,
                    pid: process.pid.map(u64::from),
                    threads,
                })
            }
            None => self.kernel_thread_times(),
        }
    }

    fn kernel_thread_times(&self) -> Result<ThreadTimes> {
        let process = self.selected_process_info()?;
        let now = KuserSharedData::new(self).system_time();
        let threads = self.enumerate_threads_for_process_info(&process)?;
        let times = self.kernel_thread_times_of(&threads)?;
        let threads = threads
            .iter()
            .zip(times)
            .map(|(thread, times)| ThreadTime {
                tid: thread.tid.unwrap_or(0),
                index: None,
                user_time: times.user_time,
                kernel_time: times.kernel_time,
                elapsed: times
                    .create_time
                    .zip(times.exit_time.or(now))
                    .and_then(|(created, ended)| ended.checked_sub(created)),
            })
            .collect::<Vec<_>>();
        if threads.is_empty() {
            return Err(Error::DebugInfo(format!(
                "{} (PID {}) has no threads",
                process.name, process.pid
            )));
        }
        Ok(ThreadTimes {
            process: Some(process.name),
            pid: Some(process.pid),
            threads,
        })
    }

    /// The times of each of `threads` on a kernel target: when it started
    /// (`ETHREAD.CreateTime`) and, once it has exited, ended
    /// (`ETHREAD.ExitTime`, which shares its storage with fields a live
    /// thread uses), as FILETIMEs; and its CPU time, its `KTHREAD` tick
    /// counts times `KeMaximumIncrement`, in 100 ns units.
    pub fn kernel_thread_times_of(&self, threads: &[ThreadInfo]) -> Result<Vec<KernelThreadTimes>> {
        let guest = self.guest()?;
        // A clock tick, in 100 ns units.
        let tick = u64::from(guest.ntoskrnl.symbol("KeMaximumIncrement")?.read::<u32>()?);
        let ethread = guest.ntoskrnl.types().layout("_ETHREAD")?;
        let memory = self.kernel_address_space();
        let field = |thread: &ThreadInfo, name: &str| {
            ethread
                .field_offset(name)
                .ok()
                .and_then(|offset| memory.read::<u64>(thread.ethread + offset).ok())
                .filter(|&value| value != 0)
        };
        Ok(threads
            .iter()
            .map(|thread| {
                let detail = self.thread_detail(thread.clone(), None);
                KernelThreadTimes {
                    create_time: field(thread, "CreateTime"),
                    exit_time: (thread.state == Some(KTHREAD_STATE_TERMINATED))
                        .then(|| field(thread, "ExitTime"))
                        .flatten(),
                    kernel_time: detail.kernel_time.map(|ticks| ticks * tick),
                    user_time: detail.user_time.map(|ticks| ticks * tick),
                }
            })
            .collect())
    }
}
