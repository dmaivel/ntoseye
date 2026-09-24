//! Attaching to a KD target over KDCOM or KDNET, and querying the identity
//! (architecture, kernel page-table root, kernel base) a session builds on.

use std::collections::{HashMap, HashSet};
use std::os::unix::net::UnixStream;
use std::sync::Arc;

use crate::backend::MemoryOps;
use crate::bytes;
use crate::dbg_backend::DebugLog;
use crate::debugger_data::{DebuggerDataCandidate, MetadataSource};
use crate::error::{Error, Result};
use crate::kd::framing::KdFraming;
use crate::memory::{AddressSpace, TranslationCache};
use crate::types::{Arch, Dtb, PhysAddr, VirtAddr};

use super::breakpoints::{
    breakpoint_instruction_at, reclaimed_breakpoints_notice, restore_unowned_breakpoint_handles,
};
use super::halt::HaltRegisters;
use super::kdnet::KdNetStream;
use super::memory::{KD_REMOTE_MEMORY_CHUNK, LineCache};
use super::registers::{ARM64_WINDBG_TTBR1_EL1, KSPECIAL_REGISTERS_CR3_OFFSET};
use super::transport::KdTransport;
use super::{
    DBG_KD_EXCEPTION_STATE_CHANGE, DEBUG_LOG_CAPACITY, KD_REQUEST_TIMEOUT, KdBackend,
    KdTargetHints, Link, STATUS_BREAKPOINT, api, context, context_arm64, is_initial_resync_error,
    kd_initial_timeout, kd_socket_connect_error, poll_for_initial_break, probe_initial_request,
    with_framing_read_timeout,
};

/// [`KdBackend::running_reason`] when the operator picked `--memory-source kd`.
pub(super) const MEMORY_OVER_KD_CHOSEN: &str = "Guest memory is read over KD on this session, and KD only \
     answers while the target is halted (--memory-source auto reads host memory live).";
/// [`KdBackend::running_reason`] when `auto` found no usable host memory.
const MEMORY_OVER_KD_FALLBACK: &str = "Guest memory is read over KD on this session (host memory \
     was unavailable at connect), and KD only answers while the target is halted.";

pub(super) fn detect_arch(machine_type: u16) -> Result<Arch> {
    match Arch::from_machine_type(machine_type) {
        Some(arch) => Ok(arch),
        None => {
            let name = match machine_type {
                0x014c => "I386",
                _ => "unknown",
            };
            Err(Error::UnsupportedArchitecture(format!(
                "{name} KD target (machine {machine_type:#06x})"
            )))
        }
    }
}

pub(super) fn normalize_kernel_dtb(arch: Arch, register_value: u64) -> Dtb {
    register_value & arch.dtb_page_mask()
}

impl KdBackend {
    /// Connect to a KDCOM serial pipe and stop at the initial state-change.
    /// Connection progress (the wait for a target can run for a minute) is
    /// reported one line at a time through `progress`.
    pub fn connect(socket_path: &str, progress: &mut dyn FnMut(&str)) -> Result<Self> {
        progress(&format!("kd: using KDCOM backend on {socket_path}"));
        let stream = UnixStream::connect(socket_path)
            .map_err(|err| kd_socket_connect_error(socket_path, err))?;
        Self::connect_transport(
            KdTransport::Serial(stream),
            "kd: serial connected; waiting for Windows KD target",
            "kd",
            progress,
        )
    }

    /// Listen for a KDNET target and stop at the initial state-change.
    pub fn connect_net(
        listen_addr: &str,
        key: &str,
        progress: &mut dyn FnMut(&str),
    ) -> Result<Self> {
        progress(&format!("kdnet: listening on {listen_addr}"));
        let stream = KdNetStream::bind(listen_addr, key)?;
        Self::connect_transport(
            KdTransport::Network(stream),
            "kdnet: listener ready; waiting for Windows KDNET target",
            "kdnet",
            progress,
        )
    }

    fn connect_transport(
        transport: KdTransport,
        waiting_message: &str,
        backend_name: &'static str,
        progress: &mut dyn FnMut(&str),
    ) -> Result<Self> {
        let network_generation = transport.network_session_generation();
        let mut framing = KdFraming::new(transport);
        if let Some(generation) = network_generation {
            framing.use_kdnet_packet_ids(generation);
        }
        let initial_timeout = kd_initial_timeout()?;

        progress(&format!(
            "{waiting_message} (timeout {}s)",
            initial_timeout.as_secs()
        ));

        // A waiting kernel retransmits state-change; otherwise break in.
        let mut initial_stop = poll_for_initial_break(&mut framing, initial_timeout, progress)?;
        let version = match probe_initial_request(&mut framing, initial_stop.processor) {
            Ok(version) => version,
            Err(err) => {
                if !is_initial_resync_error(&err) {
                    return Err(err);
                }
                kd_trace!("kd: initial request probe failed ({err}); resetting KD packet stream");
                framing.send_reset()?;
                initial_stop = poll_for_initial_break(&mut framing, initial_timeout, progress)?;
                probe_initial_request(&mut framing, initial_stop.processor)?
            }
        };
        let arch = detect_arch(version.machine_type)?;
        let register_map = match arch {
            Arch::Amd64 => context::build_register_map(),
            Arch::Arm64 => context_arm64::build_register_map(),
        };
        // The first state-change often arrives with KD's SYNC bit set. That is
        // the baseline connection, not a target reload for the REPL to surface.
        framing.take_peer_reset_seen();
        kd_trace!(
            "kd: initial state-change received: p{}/{}, exc={:#x}, rip={:#x}",
            initial_stop.processor + 1,
            initial_stop.number_processors,
            initial_stop.exception_code,
            initial_stop.program_counter
        );

        // A second handle on the same transport lets the foreground send an
        // unframed break-in byte while the pump owns `framing` for reading.
        let breakin_clone = framing.transport_mut().try_clone()?;

        // Only one debugger is attached at a time, so every entry already in
        // the target's breakpoint table was left by a session that is gone:
        // its `int3` is still displacing a byte of guest code and its slot is
        // held until the guest reboots. Release them before anything reads
        // guest memory or resumes, so no later decision has to reason about an
        // `int3` nobody can account for.
        let mut released_handles = HashSet::new();
        if let Some(notice) = reclaimed_breakpoints_notice(restore_unowned_breakpoint_handles(
            &mut framing,
            initial_stop.processor,
            &HashSet::new(),
            &mut released_handles,
        )) {
            progress(&notice);
        }

        // A target left waiting on a debugger that died mid-breakpoint reports
        // its stop again to us, at the breakpoint's address. The kernel has
        // dropped that table entry and its `int3` by the time the RESET
        // handshake completes, so the byte at PC tells the two cases apart: a
        // hard-coded break (`cc`, a break-in site to remember) or a stale
        // breakpoint hit (resume in place; never treat that address as a
        // break-in, or later real hits there would be absorbed as noise).
        let mut stopped_on_stale_breakpoint = false;
        if initial_stop.exception_code == STATUS_BREAKPOINT {
            stopped_on_stale_breakpoint = !breakpoint_instruction_at(
                &mut framing,
                arch,
                initial_stop.processor,
                initial_stop.program_counter,
            );
            if stopped_on_stale_breakpoint {
                kd_trace!(
                    "kd: initial stop at {:#x} was a stale breakpoint; resuming in place",
                    initial_stop.program_counter
                );
            }
        }

        let mut breakin_addresses = HashSet::new();
        let initial_breakin = initial_stop.new_state == DBG_KD_EXCEPTION_STATE_CHANGE
            && initial_stop.exception_code == STATUS_BREAKPOINT
            && !stopped_on_stale_breakpoint;
        if initial_breakin {
            breakin_addresses.insert(initial_stop.program_counter);
        }

        Ok(Self {
            link: Link::Halted(framing),
            breakin_clone,
            backend_name,
            register_map,
            arch,
            kernel_dtb_override: 0,
            processor_count: initial_stop.number_processors.max(1),
            current_processor: initial_stop.processor,
            last_stop_processor: initial_stop.processor,
            last_exception_code: initial_stop.exception_code,
            last_rip: initial_stop.program_counter,
            bp_handles: HashMap::new(),
            managed_bp_addresses: HashSet::new(),
            breakin_addresses,
            late_breakin: !initial_breakin,
            pending_write_breakpoint: None,
            reconnect_assist_after_continue: None,
            registers: HaltRegisters::default(),
            stop_was_managed_breakpoint: false,
            surface_break_at: None,
            special_registers_unsupported: false,
            efer_cache: HashMap::new(),
            virtual_lines: LineCache::default(),
            table_lines: LineCache::default(),
            virtual_fill_cap: KD_REMOTE_MEMORY_CHUNK,
            exit_prepared: false,
            debug_log: DebugLog::new(DEBUG_LOG_CAPACITY),
            translations: Arc::new(TranslationCache::default()),
            notices: Vec::new(),
            released_handles,
            running_reason: MEMORY_OVER_KD_CHOSEN,
        })
    }

    /// Record that `--memory-source auto` fell back to KD memory, so the
    /// refusal a running target answers with does not suggest a setting the
    /// operator is already on.
    pub fn note_host_memory_unavailable(&mut self) {
        self.running_reason = MEMORY_OVER_KD_FALLBACK;
    }

    /// Query the target identity needed by both host-memory validation and
    /// target-mediated KD memory.
    pub fn target_hints(&mut self) -> Result<KdTargetHints> {
        let processor = self.current_processor;
        let version = with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
            api::get_version(framing, processor)
        })?;
        let register_value = match self.arch {
            Arch::Amd64 => {
                let special = self.read_special_registers_uncached(processor)?;
                bytes::read_u64(&special, KSPECIAL_REGISTERS_CR3_OFFSET)
            }
            Arch::Arm64 => {
                with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
                    api::read_machine_specific_register(framing, processor, ARM64_WINDBG_TTBR1_EL1)
                })?
            }
        };
        let kernel_dtb = normalize_kernel_dtb(self.arch, register_value);
        if kernel_dtb == 0 || version.kern_base == 0 || version.ps_loaded_module_list == 0 {
            return Err(Error::Kd(format!(
                "KD target did not expose usable discovery hints (dtb={kernel_dtb:#x}, base={:#x}, psmods={:#x})",
                version.kern_base, version.ps_loaded_module_list
            )));
        }
        self.kernel_dtb_override = kernel_dtb;
        kd_trace!(
            "kd: memory hints: dtb={kernel_dtb:#x} base={:#x} psmods={:#x} arch={:?}",
            version.kern_base,
            version.ps_loaded_module_list,
            self.arch
        );
        Ok(KdTargetHints {
            kernel_dtb,
            kernel_base: VirtAddr(version.kern_base),
            ps_loaded_module_list: VirtAddr(version.ps_loaded_module_list),
            arch: self.arch,
        })
    }

    /// Reject a local VM mapping unless it is demonstrably the KD target.
    ///
    /// The PE header checks static identity; the loaded-module-list links add a
    /// dynamic per-boot identity so an unrelated local VM running the same
    /// Windows build cannot be selected accidentally.
    pub fn validate_host_memory<P: MemoryOps<PhysAddr>>(
        &mut self,
        phys: &P,
        hints: KdTargetHints,
    ) -> Result<()> {
        let local = AddressSpace::for_arch(phys, hints.kernel_dtb, hints.kernel_dtb, hints.arch);
        for (address, len, label) in [
            (hints.kernel_base, 64usize, "kernel PE header"),
            (hints.ps_loaded_module_list, 16usize, "loaded-module list"),
        ] {
            let mut local_bytes = vec![0u8; len];
            local.read_bytes(address, &mut local_bytes)?;
            let processor = self.current_processor;
            let remote_bytes =
                with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
                    api::read_virtual_memory(framing, processor, address.0, len as u32)
                })?;
            if remote_bytes != local_bytes {
                return Err(Error::Kd(format!(
                    "host VM memory does not match KD target ({label} differs)"
                )));
            }
        }
        Ok(())
    }

    pub(super) fn debugger_data_hint(&mut self) -> Result<Option<DebuggerDataCandidate>> {
        let processor = self.current_processor;
        with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
            api::get_version(framing, processor).map(|version| {
                (version.flags & api::DBGKD_VERS_FLAG_DATA != 0 && version.debugger_data_list != 0)
                    .then_some(DebuggerDataCandidate {
                        address: VirtAddr(version.debugger_data_list),
                        source: MetadataSource::KdVersion,
                    })
            })
        })
    }
}
