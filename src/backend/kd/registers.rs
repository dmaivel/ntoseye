//! Register access on the halted processors: the `CONTEXT`, the
//! `KSPECIAL_REGISTERS` control space and MSRs, cached per halt.

use crate::arch::{Arch, arm64};
use crate::backend::dbg_backend::TebPath;
use crate::base::bytes;
use crate::base::error::{Error, Result};
use crate::base::types::VirtAddr;

use super::{
    KD_REQUEST_TIMEOUT, KdBackend, STATUS_SINGLE_STEP, api, trace_enabled,
    with_framing_read_timeout,
};

/// The control-space selector for `KSPECIAL_REGISTERS`, on both
/// architectures (0 returns a KPCR pointer).
pub const CONTROL_SPACE_KSPECIAL: u64 = 2;
const MSR_EFER: u32 = 0xC000_0080;

/// Windows KD encoding of `TTBR1_EL1`: op0=3, op1=0, CRn=2, CRm=0, op2=1.
pub(super) const ARM64_WINDBG_TTBR1_EL1: u32 = 0x0003_0201;
/// Windows KD encodings of ARM64 system registers (op0/op1/CRn/CRm/op2).
const ARM64_WINDBG_TTBR0_EL1: u32 = 0x0003_0200;
const ARM64_WINDBG_ESR_EL1: u32 = 0x0003_0520;
const ARM64_WINDBG_FAR_EL1: u32 = 0x0003_0600;
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
    teb_path: Option<TebPath>,
    source: &mut impl Arm64X18Source,
) -> Option<u64> {
    let cpsr = bytes::read_u32(context, arm64::OFFSET_CPSR);
    let x18_at = arm64::OFFSET_X0 + 18 * 8;
    let x18 = u64::from_le_bytes(context.get(x18_at..x18_at + 8)?.try_into().ok()?);
    // CPSR.M[3:2] is the exception level the context was taken at.
    match (cpsr >> 2) & 3 {
        1 => source.kpcr().filter(|kpcr| *kpcr != 0),
        0 if x18 == 0 => {
            let path = teb_path?;
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
fn check_special_size(arch: Arch, special: &[u8]) -> Result<()> {
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
        self.read_msr_value(self.current_processor, ARM64_WINDBG_TPIDR_EL1)
            .inspect_err(|error| kd_trace!("kd: ARM64 TPIDR_EL1 read unavailable: {error}"))
            .ok()
            .map(|value| value & !0xfff)
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
        self.registers.set_special(processor, special);
        Ok(())
    }

    fn read_special_registers(&mut self) -> Result<&[u8]> {
        let processor = self.current_processor;
        if self.registers.special(processor).is_none() {
            let data = self.read_special_registers_uncached(processor)?;
            self.registers.set_special(processor, data);
        }
        self.registers
            .special(processor)
            .ok_or_else(|| Error::Kd("special-register cache lookup failed".into()))
    }

    /// Prefer the kernel debug-register copies; fall back to GetContext if unavailable.
    fn arm64_special_registers(&mut self) -> Option<&[u8]> {
        if self.special_registers_unsupported {
            return None;
        }
        if let Err(error) = self.read_special_registers().map(|_| ()) {
            kd_trace!("kd: ARM64 KSPECIAL_REGISTERS unavailable: {error}");
            self.special_registers_unsupported = true;
            return None;
        }
        self.registers
            .special(self.current_processor)
            .filter(|special| check_special_size(Arch::Arm64, special).is_ok())
    }

    /// System register `msr` of the selected processor, or 0 when KD will
    /// not read it.
    fn system_register_or_zero(&mut self, msr: u32, name: &str) -> u64 {
        self.read_msr_value(self.current_processor, msr)
            .inspect_err(|error| kd_trace!("kd: {name} read unavailable: {error}"))
            .unwrap_or(0)
    }

    /// Fill the register buffer's slots past the `CONTEXT` in `ctx`, from
    /// the special registers and the system registers KD reads one by one.
    fn append_control_registers(&mut self, ctx: &mut Vec<u8>) -> Result<()> {
        let arch = self.arch;
        let map = arch.register_map();
        match arch {
            Arch::Amd64 => {
                let processor = self.current_processor;
                let special = self.read_special_registers()?;
                special_into_context(arch, ctx, special)?;
                let efer = self.efer_cache.get(&processor).copied().or_else(|| {
                    match self.read_msr_value(processor, MSR_EFER) {
                        Ok(value) => {
                            self.efer_cache.insert(processor, value);
                            Some(value)
                        }
                        Err(error) => {
                            kd_trace!("kd: EFER read unavailable: {error}");
                            None
                        }
                    }
                });
                if let Some(efer) = efer {
                    map.write_u64("efer", ctx, efer)?;
                }
            }
            Arch::Arm64 => {
                let ttbr0 = self.system_register_or_zero(ARM64_WINDBG_TTBR0_EL1, "ARM64 TTBR0_EL1")
                    & arch.dtb_page_mask();
                // A single step reports its syndrome and fault address.
                let fault = (self.last_exception_code == STATUS_SINGLE_STEP).then(|| {
                    (
                        self.system_register_or_zero(ARM64_WINDBG_ESR_EL1, "ARM64 ESR_EL1"),
                        self.system_register_or_zero(ARM64_WINDBG_FAR_EL1, "ARM64 FAR_EL1"),
                    )
                });
                if let Some(x18) = arm64_x18(ctx, self.teb_path, self) {
                    map.write_u64("x18", ctx, x18)?;
                }
                ctx.resize(arch.register_buffer_size(), 0);
                map.write_u64(arch.kernel_dtb_register(), ctx, self.kernel_dtb_override)?;
                map.write_u64("ttbr0", ctx, ttbr0)?;
                if let Some((esr, far)) = fault {
                    map.write_u64("esr", ctx, esr)?;
                    map.write_u64("far", ctx, far)?;
                }
                if let Some(special) = self.arm64_special_registers() {
                    special_into_context(arch, ctx, special)?;
                }
            }
        }
        Ok(())
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
        with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
            api::set_context_chunked(framing, processor, context)
        })?;

        // KD restores the hardware-breakpoint state from KSPECIAL_REGISTERS,
        // not from the CONTEXT's copy of the debug registers. Keep both views
        // coherent so DR6 clearing and DR7 (or BCR/WCR) updates survive the
        // continue.
        let mut special = match self.arch {
            Arch::Amd64 => self.read_special_registers_uncached(processor)?,
            // The SetContext above already carried the debug registers, so
            // a target that refuses control space must not fail an applied
            // write.
            Arch::Arm64 => {
                if self.special_registers_unsupported {
                    return Ok(());
                }
                match self.read_special_registers_uncached(processor) {
                    Ok(special) => special,
                    Err(error) => {
                        kd_trace!("kd: ARM64 KSPECIAL_REGISTERS mirror skipped: {error}");
                        self.special_registers_unsupported = true;
                        return Ok(());
                    }
                }
            }
        };
        context_into_special(self.arch, &mut special, data)?;
        self.write_special_registers(special)
    }

    pub(super) fn write_msr_value(&mut self, processor: u16, msr: u32, value: u64) -> Result<()> {
        with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
            api::write_machine_specific_register(framing, processor, msr, value)
        })?;
        if msr == MSR_EFER {
            self.efer_cache.insert(processor, value);
        }
        Ok(())
    }
}
