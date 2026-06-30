use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::Result;
use crate::gdb::RegisterMap;
use crate::target::Target;
use crate::types::VirtAddr;

/// One captured line of guest debug output (DbgPrint / kernel printf), with the
/// host wall-clock time it completed and a monotonic sequence number used as the
/// read cursor.
#[derive(Clone, Debug)]
pub struct DebugLine {
    pub seq: u64,
    pub timestamp_ms: u64,
    pub text: String,
}

/// A window of debug lines returned by [`DebugBackend::read_debug_output`].
/// `next_seq` is the cursor to pass on the next call to resume after the last
/// returned line; `dropped` is set when `since_seq` predated the retained window
/// (the bounded ring evicted lines the caller had not yet read).
#[derive(Clone, Debug, Default)]
pub struct DebugOutputPage {
    pub lines: Vec<DebugLine>,
    pub next_seq: u64,
    pub dropped: bool,
}

/// Thread-safe, bounded, line-oriented ring buffer of guest debug output.
///
/// Guest DbgPrint arrives as arbitrary byte chunks serviced from two threads
/// (the foreground KD loop and the background pump that owns the socket while
/// the VM runs), so this is a cheap cloneable shared handle. Text is accumulated
/// and split on `\n`; each completed line is timestamped and assigned a
/// monotonic `seq`. Reads are snapshot+cursor and never drain, so independent
/// consumers (the REPL's live terminal stream, an MCP poller, a Python script)
/// can each track their own position.
#[derive(Clone)]
pub struct DebugLog {
    inner: Arc<Mutex<DebugLogInner>>,
}

struct DebugLogInner {
    lines: VecDeque<DebugLine>,
    /// Bytes received since the last newline; a line is emitted only once
    /// terminated, mirroring how a terminal line-buffers the same stream.
    partial: String,
    next_seq: u64,
    capacity: usize,
}

impl DebugLog {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(DebugLogInner {
                lines: VecDeque::new(),
                partial: String::new(),
                next_seq: 0,
                capacity: capacity.max(1),
            })),
        }
    }

    /// Append a raw chunk of debug output, splitting it into timestamped lines.
    /// Invalid UTF-8 is replaced lossily so the ring always holds valid text.
    pub fn record(&self, bytes: &[u8]) {
        let text = String::from_utf8_lossy(bytes);
        let now = now_ms();
        let mut inner = self.inner.lock().unwrap();
        inner.push_text(&text, now);
    }

    /// Lines with `seq >= since_seq`, plus the cursor to resume after them.
    pub fn read_since(&self, since_seq: u64) -> DebugOutputPage {
        let inner = self.inner.lock().unwrap();
        let dropped = inner
            .lines
            .front()
            .is_some_and(|first| since_seq < first.seq);
        let lines = inner
            .lines
            .iter()
            .filter(|line| line.seq >= since_seq)
            .cloned()
            .collect();
        DebugOutputPage {
            lines,
            next_seq: inner.next_seq,
            dropped,
        }
    }
}

impl DebugLogInner {
    fn push_text(&mut self, text: &str, now_ms: u64) {
        for ch in text.chars() {
            if ch == '\n' {
                let mut line = std::mem::take(&mut self.partial);
                // Normalize CRLF so Windows prints don't leave a trailing CR
                if line.ends_with('\r') {
                    line.pop();
                }
                self.push_line(line, now_ms);
            } else {
                self.partial.push(ch);
            }
        }
    }

    fn push_line(&mut self, text: String, now_ms: u64) {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.lines.push_back(DebugLine {
            seq,
            timestamp_ms: now_ms,
            text,
        });
        while self.lines.len() > self.capacity {
            self.lines.pop_front();
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BugcheckInfo {
    pub code: u32,
    pub parameters: [u64; 4],
    pub driver: Option<String>,
}

/// Backend-neutral stop event
pub struct StopEvent {
    /// Backend execution-context id, if the stop packet provided one
    pub thread_id: Option<String>,
    /// Backend exception/status code, when the stop packet carries one
    pub exception_code: Option<u32>,
    /// Program counter reported by the stop packet, when available
    pub program_counter: Option<u64>,
    /// Set when the stop was surfaced because the guest is processing a
    /// bugcheck (KD load-symbols teardown caught by the backend)
    pub is_bugcheck: bool,
    /// Structured bugcheck details decoded from KD debug output, when the
    /// target provided them before the stop packet
    pub bugcheck: Option<BugcheckInfo>,
    /// Set when the transport observed the target reset its KD packet stream,
    /// which usually means the guest rebooted and debugger state must be rebuilt.
    pub target_reloaded: bool,
    /// Kernel/module base reported by the stop packet, when available.
    pub target_kernel_base_hint: Option<VirtAddr>,
    /// Set when this stop was caused by a debugger-generated assist break-in
    /// during a target refresh/reconnect sequence, rather than by a user break
    /// or target exception.
    pub assisted_breakin: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DebugCapability {
    MemoryIntrospection,
    ExecutionControl,
    InterruptTarget,
    SingleStep,
    ReadRegisters,
    WriteRegisters,
    ThreadList,
    ThreadSelection,
    KernelBreakpoints,
    UserModeBreakpoints,
    TargetReloadDetection,
    KernelBaseHint,
    BugcheckDetection,
    BugcheckDetails,
    DebugOutput,
}

impl DebugCapability {
    pub fn label(self) -> &'static str {
        match self {
            Self::MemoryIntrospection => "memory introspection",
            Self::ExecutionControl => "execution control",
            Self::InterruptTarget => "target interrupt",
            Self::SingleStep => "single step",
            Self::ReadRegisters => "register read",
            Self::WriteRegisters => "register write",
            Self::ThreadList => "context enumeration",
            Self::ThreadSelection => "context selection",
            Self::KernelBreakpoints => "kernel breakpoints",
            Self::UserModeBreakpoints => "usermode breakpoints",
            Self::TargetReloadDetection => "target reload detection",
            Self::KernelBaseHint => "kernel base hint",
            Self::BugcheckDetection => "bugcheck stop detection",
            Self::BugcheckDetails => "bugcheck details",
            Self::DebugOutput => "debug output",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackendCapability {
    pub capability: DebugCapability,
    pub supported: bool,
}

impl BackendCapability {
    pub fn supported(capability: DebugCapability) -> Self {
        Self {
            capability,
            supported: true,
        }
    }

    pub fn unsupported(capability: DebugCapability) -> Self {
        Self {
            capability,
            supported: false,
        }
    }
}

/// Debug transport abstraction; memory access stays on `/dev/kvm`
pub trait DebugBackend {
    fn register_map(&self) -> &RegisterMap;

    fn read_registers(&mut self) -> Result<Vec<u8>>;
    fn write_registers(&mut self, data: &[u8]) -> Result<()>;

    fn set_breakpoint(&mut self, addr: u64) -> Result<()>;
    fn remove_breakpoint(&mut self, addr: u64) -> Result<()>;

    fn supports_user_mode_breakpoints(&self) -> bool {
        false
    }

    fn optional_capabilities(&self) -> Vec<BackendCapability> {
        vec![
            BackendCapability {
                capability: DebugCapability::UserModeBreakpoints,
                supported: self.supports_user_mode_breakpoints(),
            },
            BackendCapability::unsupported(DebugCapability::TargetReloadDetection),
            BackendCapability::unsupported(DebugCapability::KernelBaseHint),
            BackendCapability::unsupported(DebugCapability::BugcheckDetection),
            BackendCapability::unsupported(DebugCapability::BugcheckDetails),
            BackendCapability::unsupported(DebugCapability::DebugOutput),
        ]
    }

    fn capabilities(&self) -> Vec<BackendCapability> {
        let mut capabilities = vec![
            BackendCapability::supported(DebugCapability::MemoryIntrospection),
            BackendCapability::supported(DebugCapability::ExecutionControl),
            BackendCapability::supported(DebugCapability::InterruptTarget),
            BackendCapability::supported(DebugCapability::SingleStep),
            BackendCapability::supported(DebugCapability::ReadRegisters),
            BackendCapability::supported(DebugCapability::WriteRegisters),
            BackendCapability::supported(DebugCapability::ThreadList),
            BackendCapability::supported(DebugCapability::ThreadSelection),
            BackendCapability::supported(DebugCapability::KernelBreakpoints),
        ];
        capabilities.extend(self.optional_capabilities());
        capabilities
    }

    /// Notify the backend about a breakpoint patched outside `set_breakpoint`
    fn note_breakpoint_installed(&mut self, _addr: u64) {}
    fn note_breakpoint_uninstalled(&mut self, _addr: u64) {}

    /// Called once after the [`Target`] is constructed, giving the backend a
    /// chance to read guest state that requires symbol resolution. DmpBackend
    /// uses this to extract per-CPU registers from the PRCB ContextFrame.
    fn initialize_from_target(&mut self, _target: &Target) {}

    /// Notify the backend about guest rediscovery progress after a transport
    /// reload. Backends can use this to tune reconnect assistance while booting.
    fn note_target_rediscovery_pending(&mut self) {}
    fn note_target_rediscovery_complete(&mut self) {}

    /// Best-effort kernel base reported by the transport after a target reload.
    /// KD provides this via GetVersion; transports without a native answer return
    /// None and let the KVM-side guest scanner discover the kernel normally.
    fn target_kernel_base_hint(&mut self) -> Result<Option<VirtAddr>> {
        Ok(None)
    }

    fn continue_execution(&mut self) -> Result<()>;
    fn step(&mut self) -> Result<()>;
    fn interrupt(&mut self) -> Result<StopEvent>;

    /// Block until the target stops
    fn wait_for_stop(&mut self) -> Result<StopEvent>;

    /// Poll for a stop
    fn try_wait_for_stop(&mut self, timeout: Duration) -> Result<Option<StopEvent>>;

    fn thread_list(&mut self) -> Result<Vec<String>>;
    fn set_current_thread(&mut self, thread_id: &str) -> Result<()>;

    /// Return the currently stopped execution context
    fn stopped_thread_id(&mut self) -> Result<String>;

    fn is_running(&self) -> bool;

    /// Whether a stop has been caught but not yet drained by the foreground (e.g.
    /// the background servicer reported a stop into its channel and exited, but no
    /// `wait_for_stop`/`interrupt` has consumed it). In that window `is_running()`
    /// is still its last `continue` value, stale, so the VM is actually halted
    /// even though `is_running()` says true. A read-only "where am I" surface uses
    /// this to report the truth without consuming the stop. Default `false`:
    /// backends that stop synchronously have no such window.
    fn has_pending_stop(&self) -> bool {
        false
    }

    /// Best-effort target cleanup before the frontend exits.
    ///
    /// `leave_running` means the frontend wants the guest executing after exit.
    /// Backends with background servicing threads can override this to make
    /// teardown explicit instead of relying on `Drop` timing.
    fn prepare_for_exit(&mut self, leave_running: bool) -> Result<()> {
        if leave_running && !self.is_running() {
            self.continue_execution()?;
        }
        Ok(())
    }

    /// Read captured guest debug output (DbgPrint) at or after `since_seq`.
    /// Default empty: only transports with a native debug-print stream (KD)
    /// capture anything; see [`DebugCapability::DebugOutput`].
    fn read_debug_output(&self, _since_seq: u64) -> DebugOutputPage {
        DebugOutputPage::default()
    }

    /// Return (and clear) whether a kernel module/driver loaded or unloaded since
    /// the last call, used to invalidate module-dependent caches (driver
    /// completions). Default `false`: backends without a load event rely instead
    /// on the per-stop module-list diff.
    fn take_modules_changed(&mut self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_log_splits_lines_and_strips_crlf() {
        let log = DebugLog::new(16);
        // Arrives in two chunks, the second completing a line split across them
        log.record(b"DriverEntry failed\r\nhello ");
        log.record(b"world\n");
        let page = log.read_since(0);
        let texts: Vec<&str> = page.lines.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(texts, vec!["DriverEntry failed", "hello world"]);
        assert_eq!(page.next_seq, 2);
        assert!(!page.dropped);
    }

    #[test]
    fn debug_log_buffers_unterminated_partial() {
        let log = DebugLog::new(16);
        log.record(b"no newline yet");
        assert!(log.read_since(0).lines.is_empty());
        log.record(b"\n");
        assert_eq!(log.read_since(0).lines.len(), 1);
    }

    #[test]
    fn debug_log_cursor_returns_only_new_lines() {
        let log = DebugLog::new(16);
        log.record(b"one\ntwo\n");
        let first = log.read_since(0);
        assert_eq!(first.lines.len(), 2);
        log.record(b"three\n");
        let next = log.read_since(first.next_seq);
        let texts: Vec<&str> = next.lines.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(texts, vec!["three"]);
        assert_eq!(next.next_seq, 3);
    }

    #[test]
    fn debug_log_evicts_oldest_and_flags_dropped() {
        let log = DebugLog::new(2);
        log.record(b"a\nb\nc\n");
        let page = log.read_since(0);
        // Only the last two retained; seq 0 ("a") was evicted
        let texts: Vec<&str> = page.lines.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(texts, vec!["b", "c"]);
        // A reader still holding the evicted cursor learns it fell behind
        assert!(page.dropped);
        // A reader caught up to the retained window does not
        assert!(!log.read_since(1).dropped);
    }
}
