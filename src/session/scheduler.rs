//! Scheduler inspection that needs the session's stack walker: running
//! processors with their short stacks, per-thread APC queues, and the
//! all-threads stack listing.

use std::sync::atomic::Ordering;

use crate::dbg_backend::processor_index_from_backend_thread_id;
use crate::error::{Error, Result};
use crate::session::Session;
use crate::target::sched::{
    ApcDetail, ApcLayout, ApcListDetail, ApcSelector, ApcThread, MAX_LIST_ENTRIES, RunningDetail,
    StackThreadDetail, StacksDetail, available, frame_details, select_threads, thread_summary,
    unavailable, walk_list_nodes,
};
use crate::target::{DiagnosticValue, ListTermination, ThreadInfo};
use crate::types::VirtAddr;
use crate::unwind::{ThreadTraceContext, resolve_thread_trace_context};

const MAX_RUNNING_STACK_FRAMES: usize = 8;
const MAX_STACK_FRAMES_LEVEL_1: usize = 32;
const MAX_STACK_FRAMES_LEVEL_2: usize = 64;
const APC_THREAD_DISPLAY_LIMIT: usize = 16_384;

impl Session {
    /// Decode running processor metadata and, when requested, append a bounded
    /// short stack for each current thread using the session's stack walker.
    /// KPRC/KPCR, current/next/idle pointers, thread metadata, and stack reads
    /// are independent diagnostics, so one processor's missing field does not
    /// discard its other rows.
    pub fn inspect_running(
        &self,
        include_idle: bool,
        include_stacks: bool,
    ) -> Result<RunningDetail> {
        let mut detail = self.target.running_data(include_idle)?;
        if include_stacks {
            for processor in &mut detail.processors {
                let stack = match &processor.current_thread {
                    DiagnosticValue::Available(Some(thread)) => {
                        match self.target.thread_info_from_ethread(thread.ethread) {
                            Ok(thread_info) => match self
                                .backtrace_thread(&thread_info, MAX_RUNNING_STACK_FRAMES)
                            {
                                Ok(trace) => available(frame_details(trace.stacktrace.frames)),
                                Err(error) => unavailable(error.to_string()),
                            },
                            Err(error) => unavailable(error.to_string()),
                        }
                    }
                    DiagnosticValue::Available(None) => unavailable("current thread is null"),
                    DiagnosticValue::Unavailable(error) => unavailable(error.clone()),
                };
                processor.short_stack = Some(stack);
            }
        }
        Ok(detail)
    }

    fn select_apc_threads(&self, selector: ApcSelector) -> Result<(ApcSelector, Vec<ThreadInfo>)> {
        match selector {
            ApcSelector::CurrentThread => {
                let thread = if let Some(thread) = self.target.windows_thread_selection.as_ref() {
                    thread.clone()
                } else {
                    let processor = processor_index_from_backend_thread_id(&self.current_thread)
                        .ok_or_else(|| {
                            Error::DebugInfo("current Windows thread is unavailable".to_string())
                        })?;
                    self.target
                        .current_windows_thread_for_processor(processor)?
                };
                Ok((selector, vec![thread]))
            }
            selector => Ok(select_threads(selector, self.target.enumerate_threads()?)),
        }
    }

    fn decode_apc(
        &self,
        apc: VirtAddr,
        layout: &ApcLayout,
        trace: &ThreadTraceContext,
    ) -> ApcDetail {
        let kernel = self
            .target
            .pointer_field("_KAPC", apc, layout.kernel_routine);
        let normal = self
            .target
            .pointer_field("_KAPC", apc, layout.normal_routine);
        ApcDetail {
            address: apc,
            kernel_routine_symbol: self.target.pointer_symbol(&kernel, trace),
            kernel_routine: kernel,
            normal_routine_symbol: self.target.pointer_symbol(&normal, trace),
            normal_routine: normal,
        }
    }

    /// Decode kernel and user APC queues for the selected/current thread, one
    /// thread, one PID/EPROCESS, or all threads.  APC list walks are bounded and
    /// preserve their per-list termination; layout failure is retained in
    /// `layout_error` while thread metadata still remains usable.
    pub fn inspect_apcs(&self, selector: ApcSelector) -> Result<ApcListDetail> {
        let (selector, threads) = self.select_apc_threads(selector)?;
        let layout = self.target.apc_layout();
        let layout_error = layout.as_ref().err().map(ToString::to_string);
        let trace = resolve_thread_trace_context(&self.target, self.target.kernel_dtb());
        let selected_count = threads.len();
        let mut detail_threads = Vec::new();
        let mut total = 0usize;
        let mut truncated = false;
        for thread in threads.into_iter().take(APC_THREAD_DISPLAY_LIMIT) {
            let summary = thread_summary(&thread);
            let (mut kernel_entries, mut user_entries) = (Vec::new(), Vec::new());
            let (mut kernel_termination, mut user_termination) =
                (ListTermination::Head, ListTermination::Head);
            let mut state_error = None;
            if let Ok(layout) = &layout {
                let state_base = if layout.state_is_pointer {
                    match self
                        .target
                        .guest()
                        .and_then(|guest| {
                            guest.ntoskrnl.types().struct_at("_KTHREAD", thread.kthread)
                        })
                        .and_then(|cursor| cursor.read_field::<VirtAddr>("ApcState"))
                    {
                        Ok(address) if !address.is_zero() => Some(address),
                        Ok(_) => {
                            state_error = Some("ApcState is null".to_string());
                            None
                        }
                        Err(error) => {
                            state_error = Some(error.to_string());
                            None
                        }
                    }
                } else {
                    Some(thread.kthread + layout.state_offset)
                };
                if let Some(state_base) = state_base {
                    for (index, entries, termination) in [
                        (0usize, &mut kernel_entries, &mut kernel_termination),
                        (1usize, &mut user_entries, &mut user_termination),
                    ] {
                        if total >= MAX_LIST_ENTRIES {
                            truncated = true;
                            break;
                        }
                        let head =
                            state_base + layout.heads_offset + index as u64 * layout.head_stride;
                        let remaining = MAX_LIST_ENTRIES - total;
                        let (nodes, stop) = walk_list_nodes(&self.target, head, remaining);
                        *termination = stop;
                        for node in nodes {
                            let apc = layout
                                .link_offset
                                .map(|offset| node - offset)
                                .unwrap_or(node);
                            entries.push(self.decode_apc(apc, layout, &trace));
                            total += 1;
                            if total >= MAX_LIST_ENTRIES {
                                truncated = true;
                                break;
                            }
                        }
                    }
                }
            }
            detail_threads.push(ApcThread {
                thread: summary,
                kernel: kernel_entries,
                user: user_entries,
                kernel_termination,
                user_termination,
                state_error,
            });
            if truncated {
                break;
            }
        }
        if selected_count > APC_THREAD_DISPLAY_LIMIT {
            truncated = true;
        }
        Ok(ApcListDetail {
            selector,
            threads: detail_threads,
            total,
            truncated,
            layout_error,
        })
    }

    /// Enumerate every Windows thread (including active vCPU threads absent
    /// from the process walk), resolve its bounded stack, and apply the optional
    /// case-insensitive process/symbol filter before returning structured rows.
    /// Each top symbol/stack read is independently diagnostic; unreadable
    /// thread metadata remains visible with its unavailable field.
    pub fn inspect_stacks(&mut self, level: u8, filter: Option<&str>) -> Result<StacksDetail> {
        let level = level.min(2);
        let filter = filter.map(|value| value.to_ascii_lowercase());
        let (threads, active_vcpus) = self.windows_threads()?;
        let scanned_threads = threads.len();
        let frame_limit = match level {
            1 => MAX_STACK_FRAMES_LEVEL_1,
            2 => MAX_STACK_FRAMES_LEVEL_2,
            _ => 1,
        };
        let mut interrupted = false;
        let mut details = Vec::new();
        for thread in threads {
            if interrupted || self.target.interrupt.swap(false, Ordering::SeqCst) {
                interrupted = true;
                break;
            }
            let stack = self.backtrace_thread(&thread, frame_limit);
            let (frames, truncated, error, top_symbol) = match stack {
                Ok(trace) => {
                    let frames = frame_details(trace.stacktrace.frames);
                    let top = frames.first().map(|frame| frame.symbol.clone());
                    (frames, trace.stacktrace.truncated, None, available(top))
                }
                Err(error) => {
                    let message = error.to_string();
                    (Vec::new(), 0, Some(message.clone()), unavailable(message))
                }
            };
            let process = thread
                .process_name
                .as_deref()
                .unwrap_or("<unknown>")
                .to_ascii_lowercase();
            let symbol_match = filter.as_deref().is_none_or(|needle| {
                top_symbol_contains(&top_symbol, needle)
                    || frames
                        .iter()
                        .any(|frame| frame.symbol.to_ascii_lowercase().contains(needle))
            });
            let process_match = filter
                .as_deref()
                .is_none_or(|needle| process.contains(needle));
            if !symbol_match && !process_match {
                continue;
            }
            details.push(StackThreadDetail {
                thread: thread_summary(&thread),
                active_vcpu: active_vcpus.get(&thread.ethread.0).cloned(),
                top_symbol,
                frames,
                truncated,
                error,
            });
        }
        Ok(StacksDetail {
            level,
            filter,
            scanned_threads,
            displayed_threads: details.len(),
            interrupted,
            threads: details,
        })
    }
}

fn top_symbol_contains(value: &DiagnosticValue<Option<String>>, needle: &str) -> bool {
    matches!(
        value,
        DiagnosticValue::Available(Some(symbol)) if symbol.to_ascii_lowercase().contains(needle)
    )
}
