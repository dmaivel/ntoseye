//! Register access on the halted processors: the `CONTEXT`, the
//! `KSPECIAL_REGISTERS` control space and MSRs, cached per halt.

use super::machine::machine;
use crate::arch::{Arch, arm64};
use crate::backend::dbg_backend::ThreadLayout;
use crate::base::bytes;
use crate::base::error::{Error, Result};
use crate::base::types::VirtAddr;

use super::{KD_REQUEST_TIMEOUT, KdBackend, api, trace_enabled, with_framing_read_timeout};

/// The control-space selector for `KSPECIAL_REGISTERS`, on both
/// architectures.
pub const CONTROL_SPACE_KSPECIAL: u64 = 2;
/// The control-space selector for a processor's KPCR pointer, which the
/// target reads from its processor block for the processor a request names.
const CONTROL_SPACE_KPCR: u64 = 0;
pub const MSR_EFER: u32 = 0xC000_0080;

/// Windows KD encoding of `TTBR1_EL1`: op0=3, op1=0, CRn=2, CRm=0, op2=1.
pub const ARM64_WINDBG_TTBR1_EL1: u32 = 0x0003_0201;
/// Windows KD encodings of ARM64 system registers (op0/op1/CRn/CRm/op2).
pub const ARM64_WINDBG_TTBR0_EL1: u32 = 0x0003_0200;
pub const ARM64_WINDBG_ESR_EL1: u32 = 0x0003_0520;
pub const ARM64_WINDBG_FAR_EL1: u32 = 0x0003_0600;
/// `TPIDR_EL1`: op0=3, op1=0, CRn=13, CRm=0, op2=4. Windows keeps the
/// processor's KPCR there, with flags in the low bits.
const ARM64_WINDBG_TPIDR_EL1: u32 = 0x0003_0d04;

/// Where Windows keeps an ARM64 thread's `x18`, which the `CONTEXT` KD
/// returns does not carry.
pub(super) trait Arm64X18Source {
    /// The processor's KPCR: `TPIDR_EL1` with its flag bits (the low 12)
    /// cleared, as every exception entry loads `x18`.
    fn kpcr(&mut self) -> Option<u64>;
    /// The pointer at `address` in kernel memory.
    fn read_pointer(&mut self, address: u64) -> Option<u64>;
}

/// The `x18` of an ARM64 `context`, when it has to be recovered: in kernel
/// mode the processor's KPCR, which an exception taken there reloads
/// without saving, so KD returns whatever the frame's slot held (0, or
/// another pointer); in user mode the current thread's TEB, which KD
/// returns as 0 (the trap frame saves it, the `CONTEXT` leaves it out).
/// `None` for a user-mode `x18` KD did return, or when `source` cannot
/// answer.
pub(super) fn arm64_x18(
    context: &[u8],
    thread_layout: Option<ThreadLayout>,
    source: &mut impl Arm64X18Source,
) -> Option<u64> {
    let cpsr = bytes::read_u32(context, arm64::OFFSET_CPSR);
    let x18_at = arm64::OFFSET_X0 + 18 * 8;
    let x18 = u64::from_le_bytes(context.get(x18_at..x18_at + 8)?.try_into().ok()?);
    // CPSR.M[3:2] is the exception level the context was taken at.
    match (cpsr >> 2) & 3 {
        1 => source.kpcr().filter(|kpcr| *kpcr != 0),
        0 if x18 == 0 => {
            let path = thread_layout?;
            let kpcr = source.kpcr().filter(|kpcr| *kpcr != 0)?;
            let thread = source.read_pointer(kpcr.wrapping_add(path.current_thread))?;
            source
                .read_pointer(thread.wrapping_add(path.teb))
                .filter(|teb| *teb != 0)
        }
        _ => None,
    }
}

/// The bytes of `special`, a processor's `KSPECIAL_REGISTERS`, KD's
/// control space must return for every register the layout names.
pub fn check_special_size(arch: Arch, special: &[u8]) -> Result<()> {
    let expected = arch.special_register_map().extent();
    if special.len() < expected {
        return Err(Error::Kd(format!(
            "{} KSPECIAL_REGISTERS buffer too short: {} bytes, expected at least {expected}",
            arch.label(),
            special.len(),
        )));
    }
    Ok(())
}

/// Copy `special`, a processor's `KSPECIAL_REGISTERS`, into the register
/// buffer `ctx`, a `CONTEXT` it grows to the architecture's buffer.
pub fn special_into_context(arch: Arch, ctx: &mut Vec<u8>, special: &[u8]) -> Result<()> {
    check_special_size(arch, special)?;
    ctx.resize(arch.register_buffer_size(), 0);
    arch.register_map()
        .copy_from(ctx, arch.special_register_map(), special);
    Ok(())
}

/// Copy into `special` the registers it shares with the `CONTEXT` in `ctx`
/// (the debug registers), which KD restores from `KSPECIAL_REGISTERS`
/// rather than from the `CONTEXT`.
pub fn context_into_special(arch: Arch, special: &mut [u8], ctx: &[u8]) -> Result<()> {
    check_special_size(arch, special)?;
    let context = context_payload(arch, ctx)?;
    arch.special_register_map()
        .copy_from(special, arch.register_map(), context);
    Ok(())
}

/// The `CONTEXT` at the start of the register buffer `data`.
pub fn context_payload(arch: Arch, data: &[u8]) -> Result<&[u8]> {
    data.get(..arch.context_size()).ok_or_else(|| {
        Error::Kd(format!(
            "{} CONTEXT buffer too short: {} bytes, expected {}",
            arch.label(),
            data.len(),
            arch.context_size()
        ))
    })
}

impl Arm64X18Source for KdBackend {
    fn kpcr(&mut self) -> Option<u64> {
        self.processor_kpcr(self.current_processor)
    }

    fn read_pointer(&mut self, address: u64) -> Option<u64> {
        let mut bytes = [0u8; 8];
        self.read_virtual_bytes(VirtAddr(address), &mut bytes)
            .inspect_err(|error| kd_trace!("kd: ARM64 TEB lookup read failed: {error}"))
            .ok()?;
        Some(u64::from_le_bytes(bytes))
    }
}

impl KdBackend {
    /// `processor`'s KPCR. On the processor that stopped the target it is
    /// `TPIDR_EL1` with its flag bits (the low 12) cleared; the target reads
    /// system registers only there, so any other processor's comes from
    /// control space.
    pub(super) fn processor_kpcr(&mut self, processor: u16) -> Option<u64> {
        let kpcr = if processor == self.last_stop_processor {
            self.read_msr_value(processor, ARM64_WINDBG_TPIDR_EL1)
                .inspect_err(|error| kd_trace!("kd: ARM64 TPIDR_EL1 read unavailable: {error}"))
                .ok()
                .map(|value| value & !0xfff)
        } else {
            with_framing_read_timeout(self.framing().ok()?, KD_REQUEST_TIMEOUT, |framing| {
                api::read_control_space(framing, processor, CONTROL_SPACE_KPCR, 8)
            })
            .inspect_err(|error| kd_trace!("kd: p{} KPCR read unavailable: {error}", processor + 1))
            .ok()
            .and_then(|bytes| Some(u64::from_le_bytes(bytes.get(..8)?.try_into().ok()?)))
        };
        kpcr.filter(|kpcr| *kpcr != 0)
    }

    /// The page-table root of the address space `processor`'s current
    /// thread runs in, read from its process (see [`ThreadLayout`]).
    pub(super) fn processor_process_root(&mut self, processor: u16) -> Option<u64> {
        let layout = self.thread_layout?;
        let kpcr = self.processor_kpcr(processor)?;
        let thread = self.read_pointer(kpcr.wrapping_add(layout.current_thread))?;
        let process = self.read_pointer(thread.wrapping_add(layout.process))?;
        self.read_pointer(process.wrapping_add(layout.directory_table_base))
    }

    pub(super) fn read_special_registers_uncached(&mut self, processor: u16) -> Result<Vec<u8>> {
        let size = self.arch.special_register_map().extent() as u32;
        with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
            api::read_control_space(framing, processor, CONTROL_SPACE_KSPECIAL, size)
        })
    }

    pub(super) fn read_msr_value(&mut self, processor: u16, msr: u32) -> Result<u64> {
        with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
            api::read_machine_specific_register(framing, processor, msr)
        })
    }

    pub(super) fn validate_processor(&self, processor: u16) -> Result<()> {
        if processor >= self.processor_count.max(1) {
            return Err(Error::Kd(format!(
                "processor {} is out of range (target reports {} processor(s))",
                processor + 1,
                self.processor_count.max(1)
            )));
        }
        Ok(())
    }

    pub(super) fn write_special_registers(&mut self, special: Vec<u8>) -> Result<()> {
        let processor = self.current_processor;
        let expected_size = self.arch.special_register_map().extent();
        let actual = with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
            api::write_control_space(framing, processor, CONTROL_SPACE_KSPECIAL, &special)
        })?;
        if actual as usize != special.len() {
            return Err(Error::Kd(format!(
                "short KSPECIAL_REGISTERS write on processor {}: wrote {} of {} bytes (requested layout size {})",
                processor + 1,
                actual,
                special.len(),
                expected_size,
            )));
        }
        // The CONTEXT and the stop's report the halt holds were read with
        // the special registers before this write (the debug registers among
        // them), so they go; the new special registers are what was written.
        self.registers.invalidate(processor);
        self.registers.set_special(processor, special);
        Ok(())
    }

    pub fn read_special_registers(&mut self) -> Result<&[u8]> {
        let processor = self.current_processor;
        if self.registers.special(processor).is_none() {
            let data = self.read_special_registers_uncached(processor)?;
            self.registers.set_special(processor, data);
        }
        self.registers
            .special(processor)
            .ok_or_else(|| Error::Kd("special-register cache lookup failed".into()))
    }

    /// System register `msr` of the selected processor, or 0 when KD will
    /// not read it.
    pub fn system_register_or_zero(&mut self, msr: u32, name: &str) -> u64 {
        self.read_msr_value(self.current_processor, msr)
            .inspect_err(|error| kd_trace!("kd: {name} read unavailable: {error}"))
            .unwrap_or(0)
    }

    /// Fill the register buffer's slots past the `CONTEXT` in `ctx`, from
    /// the special registers and the system registers KD reads one by one.
    fn append_control_registers(&mut self, ctx: &mut Vec<u8>) -> Result<()> {
        machine(self.arch).append_registers(self, ctx)
    }

    /// The selected processor's register context, memoized for the halt.
    ///
    /// A full `CONTEXT` is a request/reply exchange plus the control-register
    /// and EFER reads layered on top, and one stop asks for it repeatedly: the
    /// `int3` rewind, the stop classification, the step-over and the trap-flag
    /// cleanup all want the same bytes. Nothing but this debugger can change
    /// them while the target is halted, so the fetch happens once and is
    /// invalidated on resume and after a write, along with the rest of the
    /// processor's halt state. See [`HaltRegisters`](super::halt::HaltRegisters).
    pub(super) fn read_register_context(&mut self) -> Result<Vec<u8>> {
        if let Some(cached) = self.registers.context(self.current_processor) {
            return Ok(cached.to_vec());
        }
        kd_trace!(
            "kd: read_registers: GetContext on p{}",
            self.current_processor + 1
        );
        let processor = self.current_processor;
        let context_flags = self.arch.context_flags().all;
        let mut ctx = with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
            api::get_context(framing, processor, context_flags)
        })?;
        kd_trace!("kd: read_registers: got {} context bytes", ctx.len());
        context_payload(self.arch, &ctx)?;
        self.append_control_registers(&mut ctx)?;
        kd_trace!("kd: read_registers: extended to {} bytes", ctx.len());
        if trace_enabled() {
            let cr3 = self.register_map.read_u64("cr3", &ctx).unwrap_or(0);
            let pc = self
                .register_map
                .read_u64(self.arch.pc_register(), &ctx)
                .unwrap_or(0);
            let sp = self
                .register_map
                .read_u64(self.arch.sp_register(), &ctx)
                .unwrap_or(0);
            kd_trace!("kd: read_registers: cr3={cr3:#x} pc={pc:#x} sp={sp:#x}");
        }
        self.registers.set_context(processor, ctx.clone());
        Ok(ctx)
    }

    pub(super) fn write_register_context(&mut self, data: &[u8]) -> Result<()> {
        let processor = self.current_processor;
        // Everything the host holds about this processor described the state
        // before the write, the stop's report of TF and DR6 included.
        self.registers.invalidate(processor);
        let context = context_payload(self.arch, data)?;
        let flags = self.arch.context_flags().all;
        with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
            api::set_context(framing, processor, flags, context)
        })?;

        // KD restores the hardware-breakpoint state from KSPECIAL_REGISTERS,
        // not from the CONTEXT's copy of the debug registers. Keep both views
        // coherent so DR6 clearing and DR7 (or BCR/WCR) updates survive the
        // continue.
        let Some(mut special) = machine(self.arch).special_registers_to_mirror(self, processor)?
        else {
            return Ok(());
        };
        context_into_special(self.arch, &mut special, data)?;
        self.write_special_registers(special)
    }

    pub(super) fn write_msr_value(&mut self, processor: u16, msr: u32, value: u64) -> Result<()> {
        with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
            api::write_machine_specific_register(framing, processor, msr, value)
        })?;
        // The register buffer the halt holds shows system registers read
        // from MSRs (EFER; TTBR0, ESR and FAR on ARM64).
        self.registers.invalidate(processor);
        if msr == MSR_EFER {
            self.efer_cache.insert(processor, value);
        }
        Ok(())
    }
}
