//! Threads and stack frames: the vCPU list, stack walks, and installing
//! the frame a request names as the session's inspection context.

use std::mem::replace;
use std::result;

use serde_json::{Value, json};

use crate::target::SelectedFrame;

use super::{FrameRef, Handled, RunState, Server, arg_i64, source_value};

/// Frames cached per stop; stackTrace paging slices this walk.
const STACK_FRAME_LIMIT: usize = 256;

impl Server {
    /// Rebuild the vCPU list, announcing additions and removals so a client's
    /// thread view survives a reboot changing the processor count.
    pub(super) fn sync_threads(&mut self) {
        let Some(session) = self.session.as_mut() else {
            return;
        };
        let ids: Vec<String> = match session.vcpus() {
            Ok(vcpus) => vcpus.into_iter().map(|vcpu| vcpu.id).collect(),
            Err(_) => vec![session.current_thread.clone()],
        };
        self.set_threads(ids);
    }

    /// Install the vCPU list, announcing additions and removals.
    fn set_threads(&mut self, ids: Vec<String>) {
        if ids == self.threads {
            return;
        }
        let previous = replace(&mut self.threads, ids);
        for index in previous.len()..self.threads.len() {
            self.send_event(
                "thread",
                json!({"reason": "started", "threadId": index as i64 + 1}),
            );
        }
        for index in (self.threads.len()..previous.len()).rev() {
            self.send_event(
                "thread",
                json!({"reason": "exited", "threadId": index as i64 + 1}),
            );
        }
    }

    pub(super) fn select_thread(&mut self, thread: i64) -> result::Result<(), String> {
        // Report a missing target before a missing thread: without a session
        // the thread table is empty for that reason, not because the client
        // named a stale id.
        self.session()?;
        if self.threads.is_empty() {
            self.sync_threads();
        }
        let Some(backend_id) = self.backend_thread_id(thread) else {
            return Err(format!("unknown thread id {thread}"));
        };
        let session = self.session()?;
        if session.current_thread == backend_id {
            return Ok(());
        }
        session
            .set_current_thread(&backend_id)
            .map_err(|error| error.to_string())
    }

    fn backend_thread_id(&self, thread: i64) -> Option<String> {
        usize::try_from(thread)
            .ok()
            .and_then(|index| index.checked_sub(1))
            .and_then(|index| self.threads.get(index))
            .cloned()
    }

    pub(super) fn dap_thread_id(&self, backend_id: &str) -> i64 {
        self.threads
            .iter()
            .position(|id| id == backend_id)
            .map(|index| index as i64 + 1)
            .unwrap_or(1)
    }

    pub(super) fn on_threads(&mut self) -> Handled {
        if matches!(self.state, RunState::Running) {
            // vCPU contexts can only be read while halted; report the last
            // known set so the client's thread view does not empty out.
            let threads = self
                .threads
                .iter()
                .enumerate()
                .map(|(index, id)| json!({"id": index as i64 + 1, "name": format!("{id} (running)")}))
                .collect::<Vec<_>>();
            return Ok(Some(json!({"threads": threads})));
        }
        let session = self.session()?;
        let vcpus = session.vcpus().map_err(|error| error.to_string())?;
        self.set_threads(vcpus.iter().map(|vcpu| vcpu.id.clone()).collect());
        let threads = vcpus
            .iter()
            .enumerate()
            .map(|(index, vcpu)| json!({"id": index as i64 + 1, "name": vcpu.label()}))
            .collect::<Vec<_>>();
        Ok(Some(json!({"threads": threads})))
    }

    pub(super) fn on_stack_trace(&mut self, args: &Value) -> Handled {
        let thread = arg_i64(args, "threadId").unwrap_or(1);
        self.select_thread(thread)?;
        // Clients walk every stopped thread before asking for scopes, so a
        // thread already walked in this stop keeps the handles it was given.
        if !self.frames.iter().any(|frame| frame.thread == thread) {
            self.build_frames(thread)?;
        }

        let start = arg_i64(args, "startFrame").unwrap_or(0).max(0) as usize;
        let levels = arg_i64(args, "levels").unwrap_or(0).max(0) as usize;
        let own: Vec<usize> = self
            .frames
            .iter()
            .enumerate()
            .filter(|(_, frame)| frame.thread == thread)
            .map(|(handle, _)| handle)
            .collect();
        let total = own.len();
        let end = if levels == 0 {
            total
        } else {
            (start + levels).min(total)
        };
        let mut frames = Vec::new();
        for handle in own.iter().skip(start).take(end.saturating_sub(start)) {
            frames.push(self.frame_value(*handle));
        }
        Ok(Some(json!({"stackFrames": frames, "totalFrames": total})))
    }

    /// Walk the selected thread's stack and publish one handle per frame.
    fn build_frames(&mut self, thread: i64) -> result::Result<(), String> {
        let session = self.session()?;
        // Goes through the session so a Windows thread selected in the console
        // (`.thread`) is the stack the client sees, instead of whatever the
        // vCPU is running.
        let (recovered, seed) = session
            .recovered_backtrace(STACK_FRAME_LIMIT)
            .map_err(|error| error.to_string())?;
        for (index, frame) in recovered.frames.iter().enumerate() {
            self.frames.push(FrameRef {
                thread,
                index,
                ip: frame.frame.ip,
                sp: frame.frame.sp,
                symbol: frame.frame.symbol.clone(),
                source_location: frame.frame.source_location.clone(),
                frame_base: frame.frame_base,
                registers: frame.registers.clone(),
                seed_registers: seed.clone(),
                dtb: recovered.dtb,
            });
        }
        Ok(())
    }

    pub(super) fn frame_value(&mut self, handle: usize) -> Value {
        let frame = &self.frames[handle];
        let ip = frame.ip;
        let mut value = json!({
            "id": handle as i64 + 1,
            "name": frame.symbol,
            "line": 0,
            "column": 0,
            "instructionPointerReference": format!("{ip:#x}"),
        });
        if let Some(location) = &frame.source_location {
            value["line"] = json!(self.to_client_line(location.line as i64));
            value["column"] = json!(
                location
                    .column
                    .map(|column| self.to_client_column(column as i64))
                    .unwrap_or(0)
            );
            value["source"] = source_value(location);
        }
        value
    }

    pub(super) fn frame_handle(&self, args: &Value, key: &str) -> result::Result<usize, String> {
        let id = arg_i64(args, key).ok_or_else(|| format!("missing {key}"))?;
        usize::try_from(id)
            .ok()
            .and_then(|id| id.checked_sub(1))
            .filter(|handle| *handle < self.frames.len())
            .ok_or_else(|| format!("stale frame id {id}; re-request the stack trace"))
    }

    /// Select the requested frame, or keep the current frame if none was supplied.
    /// Reject stale frame ids.
    pub(super) fn select_named_frame(
        &mut self,
        args: &Value,
        key: &str,
    ) -> result::Result<(), String> {
        if args.get(key).is_none() {
            return Ok(());
        }
        let handle = self.frame_handle(args, key)?;
        self.select_frame(handle)
    }

    /// Re-read the live register file into a frame-0 handle, so the frame
    /// context this adapter installs for locals and expressions matches the
    /// target after a write (`setVariable`, or `r rax=...` in the console).
    /// Caller frames keep their recovered snapshot, and so does a parked
    /// Windows thread, whose `read_registers` is refused.
    pub(super) fn refresh_live_frame(&mut self, handle: usize) {
        if self.frames[handle].index != 0 {
            return;
        }
        let Some(session) = self.session.as_mut() else {
            return;
        };
        let Ok(registers) = session.read_registers() else {
            return;
        };
        let values = session.register_map.to_hashmap(&registers);
        self.frames[handle].registers = values.clone();
        self.frames[handle].seed_registers = values;
    }

    /// Install the recovered register context for a frame in the session, the
    /// same way `.frame N` does, so locals and expressions resolve against the
    /// frame the client selected. Its thread also becomes the backend's
    /// current context, because handles outlive the client's last stack walk.
    pub(super) fn select_frame(&mut self, handle: usize) -> result::Result<(), String> {
        self.select_thread(self.frames[handle].thread)?;
        self.refresh_live_frame(handle);
        // The walk was seeded from the vCPU unless a parked Windows thread
        // supplied its saved context.
        let seed_live = self
            .session
            .as_ref()
            .is_some_and(|session| session.parked_windows_thread().is_none());
        let frame = &self.frames[handle];
        let selected = SelectedFrame {
            index: frame.index,
            ip: frame.ip,
            sp: frame.sp,
            frame_base: frame.frame_base,
            registers: frame.registers.clone(),
            seed_registers: frame.seed_registers.clone(),
            seed_live,
            dtb: Some(frame.dtb),
        };
        if let Some(session) = self.session.as_mut() {
            session.select_frame(selected);
        }
        Ok(())
    }
}
