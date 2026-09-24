//! Register access on the halted processors: the `CONTEXT`, the
//! `KSPECIAL_REGISTERS` control space and MSRs, cached per halt.

use crate::bytes;
use crate::error::{Error, Result};
use crate::types::Arch;

use super::{
    KD_REQUEST_TIMEOUT, KdBackend, STATUS_SINGLE_STEP, api, context, context_arm64, hwbp,
    trace_enabled, with_framing_read_timeout,
};

pub(super) const AMD64_DEBUG_CONTROL_SPACE_KSPECIAL: u64 = 2;
/// Control-space bases are selectors: 0 returns a KPCR pointer, 2 selects
/// `KARM64_SPECIAL_REGISTERS` (160 bytes in the public WoA definition).
const ARM64_DEBUG_CONTROL_SPACE_KSPECIAL: u64 = 2;

pub(super) const KSPECIAL_REGISTERS_CR0_OFFSET: usize = 0x00;
pub(super) const KSPECIAL_REGISTERS_CR2_OFFSET: usize = 0x08;
pub(super) const KSPECIAL_REGISTERS_CR3_OFFSET: usize = 0x10;
pub(super) const KSPECIAL_REGISTERS_CR4_OFFSET: usize = 0x18;
pub(super) const KSPECIAL_REGISTERS_DR0_OFFSET: usize = 0x20;
const KSPECIAL_REGISTERS_DR1_OFFSET: usize = 0x28;
const KSPECIAL_REGISTERS_DR2_OFFSET: usize = 0x30;
const KSPECIAL_REGISTERS_DR3_OFFSET: usize = 0x38;
pub(super) const KSPECIAL_REGISTERS_DR6_OFFSET: usize = 0x40;
pub(super) const KSPECIAL_REGISTERS_DR7_OFFSET: usize = 0x48;
// KDESCRIPTOR has Pad[3], Limit, and Base, so its Base is eight bytes into
// the descriptor even though the descriptor itself starts at these offsets.
pub(super) const KSPECIAL_REGISTERS_GDTR_OFFSET: usize = 0x50;
pub(super) const KSPECIAL_REGISTERS_IDTR_OFFSET: usize = 0x60;
pub(super) const KSPECIAL_REGISTERS_TR_OFFSET: usize = 0x70;
pub(super) const KSPECIAL_REGISTERS_LDTR_OFFSET: usize = 0x72;
pub(super) const KSPECIAL_REGISTERS_CR8_OFFSET: usize = 0xA0;
pub(super) const KSPECIAL_REGISTERS_MIN_SIZE: usize = KSPECIAL_REGISTERS_CR8_OFFSET + 8;
pub(super) const ARM64_KSPECIAL_REGISTERS_BVR0_OFFSET: usize = 0x28;
pub(super) const ARM64_KSPECIAL_REGISTERS_BCR0_OFFSET: usize = 0x68;
pub(super) const ARM64_KSPECIAL_REGISTERS_WVR0_OFFSET: usize = 0x88;
pub(super) const ARM64_KSPECIAL_REGISTERS_WCR0_OFFSET: usize = 0x98;
pub(super) const ARM64_KSPECIAL_REGISTERS_MIN_SIZE: usize = 0xA0;
const MSR_EFER: u32 = 0xC000_0080;

/// Windows KD encoding of `TTBR1_EL1`: op0=3, op1=0, CRn=2, CRm=0, op2=1.
pub(super) const ARM64_WINDBG_TTBR1_EL1: u32 = 0x0003_0201;
/// Windows KD encodings of ARM64 system registers (op0/op1/CRn/CRm/op2).
const ARM64_WINDBG_TTBR0_EL1: u32 = 0x0003_0200;
const ARM64_WINDBG_ESR_EL1: u32 = 0x0003_0520;
const ARM64_WINDBG_FAR_EL1: u32 = 0x0003_0600;

const ARM64_DEBUG_REGISTER_OFFSETS: &[(usize, usize, usize, usize)] = &[
    (
        ARM64_KSPECIAL_REGISTERS_BVR0_OFFSET,
        context_arm64::OFFSET_BVR0,
        8,
        hwbp::ARM64_MAX_BREAKPOINTS as usize,
    ),
    (
        ARM64_KSPECIAL_REGISTERS_BCR0_OFFSET,
        context_arm64::OFFSET_BCR0,
        4,
        hwbp::ARM64_MAX_BREAKPOINTS as usize,
    ),
    (
        ARM64_KSPECIAL_REGISTERS_WVR0_OFFSET,
        context_arm64::OFFSET_WVR0,
        8,
        hwbp::ARM64_MAX_WATCHPOINTS as usize,
    ),
    (
        ARM64_KSPECIAL_REGISTERS_WCR0_OFFSET,
        context_arm64::OFFSET_WCR0,
        4,
        hwbp::ARM64_MAX_WATCHPOINTS as usize,
    ),
];

fn kspecial_control_space(arch: Arch) -> (u64, usize) {
    match arch {
        Arch::Amd64 => (
            AMD64_DEBUG_CONTROL_SPACE_KSPECIAL,
            KSPECIAL_REGISTERS_MIN_SIZE,
        ),
        Arch::Arm64 => (
            ARM64_DEBUG_CONTROL_SPACE_KSPECIAL,
            ARM64_KSPECIAL_REGISTERS_MIN_SIZE,
        ),
    }
}

pub(super) fn append_control_registers_from_special(
    ctx: &mut Vec<u8>,
    special: &[u8],
) -> Result<()> {
    if special.len() < KSPECIAL_REGISTERS_MIN_SIZE {
        return Err(Error::Kd(format!(
            "KSPECIAL_REGISTERS buffer too short: {} bytes, expected at least {}",
            special.len(),
            KSPECIAL_REGISTERS_MIN_SIZE
        )));
    }

    ctx.resize(context::REGISTER_BUFFER_SIZE, 0);

    let copy_reg = |ctx: &mut [u8], ctx_offset: usize, special_offset: usize| {
        ctx[ctx_offset..ctx_offset + 8]
            .copy_from_slice(&special[special_offset..special_offset + 8]);
    };
    copy_reg(ctx, context::OFFSET_CR0, KSPECIAL_REGISTERS_CR0_OFFSET);
    copy_reg(ctx, context::OFFSET_CR2, KSPECIAL_REGISTERS_CR2_OFFSET);
    copy_reg(ctx, context::OFFSET_CR3, KSPECIAL_REGISTERS_CR3_OFFSET);
    copy_reg(ctx, context::OFFSET_CR4, KSPECIAL_REGISTERS_CR4_OFFSET);
    copy_reg(ctx, context::OFFSET_DR0, KSPECIAL_REGISTERS_DR0_OFFSET);
    copy_reg(ctx, context::OFFSET_DR1, KSPECIAL_REGISTERS_DR1_OFFSET);
    copy_reg(ctx, context::OFFSET_DR2, KSPECIAL_REGISTERS_DR2_OFFSET);
    copy_reg(ctx, context::OFFSET_DR3, KSPECIAL_REGISTERS_DR3_OFFSET);
    copy_reg(ctx, context::OFFSET_DR6, KSPECIAL_REGISTERS_DR6_OFFSET);
    copy_reg(ctx, context::OFFSET_DR7, KSPECIAL_REGISTERS_DR7_OFFSET);
    copy_reg(ctx, context::OFFSET_CR8, KSPECIAL_REGISTERS_CR8_OFFSET);
    // KDESCRIPTOR layout is Pad[3] (6 bytes), Limit (2 bytes), Base (8
    // bytes). The register map stores each value in a synthetic 8-byte slot;
    // only the descriptor's meaningful bytes are copied for the limits.
    ctx[context::OFFSET_GDTR_LIMIT..context::OFFSET_GDTR_LIMIT + 2].copy_from_slice(
        &special[KSPECIAL_REGISTERS_GDTR_OFFSET + 6..KSPECIAL_REGISTERS_GDTR_OFFSET + 8],
    );
    copy_reg(
        ctx,
        context::OFFSET_GDTR_BASE,
        KSPECIAL_REGISTERS_GDTR_OFFSET + 8,
    );
    ctx[context::OFFSET_IDTR_LIMIT..context::OFFSET_IDTR_LIMIT + 2].copy_from_slice(
        &special[KSPECIAL_REGISTERS_IDTR_OFFSET + 6..KSPECIAL_REGISTERS_IDTR_OFFSET + 8],
    );
    copy_reg(
        ctx,
        context::OFFSET_IDTR_BASE,
        KSPECIAL_REGISTERS_IDTR_OFFSET + 8,
    );
    ctx[context::OFFSET_TR..context::OFFSET_TR + 2]
        .copy_from_slice(&special[KSPECIAL_REGISTERS_TR_OFFSET..KSPECIAL_REGISTERS_TR_OFFSET + 2]);
    ctx[context::OFFSET_LDTR..context::OFFSET_LDTR + 2].copy_from_slice(
        &special[KSPECIAL_REGISTERS_LDTR_OFFSET..KSPECIAL_REGISTERS_LDTR_OFFSET + 2],
    );
    Ok(())
}

pub(super) fn update_special_debug_registers_from_context(
    special: &mut [u8],
    ctx: &[u8],
) -> Result<()> {
    if special.len() < KSPECIAL_REGISTERS_MIN_SIZE {
        return Err(Error::Kd(format!(
            "KSPECIAL_REGISTERS buffer too short: {} bytes, expected at least {}",
            special.len(),
            KSPECIAL_REGISTERS_MIN_SIZE
        )));
    }
    context_payload(ctx)?;

    for (ctx_offset, special_offset) in [
        (context::OFFSET_DR0, KSPECIAL_REGISTERS_DR0_OFFSET),
        (context::OFFSET_DR1, KSPECIAL_REGISTERS_DR1_OFFSET),
        (context::OFFSET_DR2, KSPECIAL_REGISTERS_DR2_OFFSET),
        (context::OFFSET_DR3, KSPECIAL_REGISTERS_DR3_OFFSET),
        (context::OFFSET_DR6, KSPECIAL_REGISTERS_DR6_OFFSET),
        (context::OFFSET_DR7, KSPECIAL_REGISTERS_DR7_OFFSET),
    ] {
        special[special_offset..special_offset + 8]
            .copy_from_slice(&ctx[ctx_offset..ctx_offset + 8]);
    }
    Ok(())
}

pub(super) fn update_arm64_debug_registers_from_context(
    special: &mut [u8],
    ctx: &[u8],
) -> Result<()> {
    if special.len() < ARM64_KSPECIAL_REGISTERS_MIN_SIZE {
        return Err(Error::Kd(format!(
            "ARM64 KSPECIAL_REGISTERS buffer too short: {} bytes, expected at least {}",
            special.len(),
            ARM64_KSPECIAL_REGISTERS_MIN_SIZE
        )));
    }
    if ctx.len() < context_arm64::CONTEXT_SIZE {
        return Err(Error::Kd(format!(
            "ARM64 CONTEXT buffer too short: {} bytes, expected {}",
            ctx.len(),
            context_arm64::CONTEXT_SIZE
        )));
    }
    copy_arm64_debug_registers(special, ctx, false);
    Ok(())
}

fn copy_arm64_debug_registers(dst: &mut [u8], src: &[u8], to_context: bool) {
    for &(special_base, context_base, width, count) in ARM64_DEBUG_REGISTER_OFFSETS {
        let (dst_base, src_base) = if to_context {
            (context_base, special_base)
        } else {
            (special_base, context_base)
        };
        for index in 0..count {
            let dst_offset = dst_base + index * width;
            let src_offset = src_base + index * width;
            dst[dst_offset..dst_offset + width]
                .copy_from_slice(&src[src_offset..src_offset + width]);
        }
    }
}

pub(super) fn context_payload(data: &[u8]) -> Result<&[u8]> {
    if data.len() < context::CONTEXT_SIZE {
        return Err(Error::Kd(format!(
            "CONTEXT buffer too short: {} bytes, expected {}",
            data.len(),
            context::CONTEXT_SIZE
        )));
    }
    Ok(&data[..context::CONTEXT_SIZE])
}

impl KdBackend {
    fn context_flags(&self) -> u32 {
        match self.arch {
            Arch::Amd64 => context::CONTEXT_ALL,
            Arch::Arm64 => context_arm64::CONTEXT_ALL,
        }
    }

    pub(super) fn read_special_registers_uncached(&mut self, processor: u16) -> Result<Vec<u8>> {
        let (base, size) = kspecial_control_space(self.arch);
        with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
            api::read_control_space(framing, processor, base, size as u32)
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
        let (base, expected_size) = kspecial_control_space(self.arch);
        let actual = with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
            api::write_control_space(framing, processor, base, &special)
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
            .filter(|special| special.len() >= ARM64_KSPECIAL_REGISTERS_MIN_SIZE)
    }

    fn append_control_registers(&mut self, ctx: &mut Vec<u8>) -> Result<()> {
        match self.arch {
            Arch::Amd64 => {
                let special = self.read_special_registers()?;
                append_control_registers_from_special(ctx, special)
            }
            Arch::Arm64 => {
                if ctx.len() < context_arm64::CONTEXT_SIZE {
                    return Err(Error::Kd(format!(
                        "ARM64 CONTEXT buffer too short: {} bytes, expected {}",
                        ctx.len(),
                        context_arm64::CONTEXT_SIZE
                    )));
                }
                let ttbr0 =
                    match self.read_msr_value(self.current_processor, ARM64_WINDBG_TTBR0_EL1) {
                        Ok(value) => value & Arch::Arm64.dtb_page_mask(),
                        Err(error) => {
                            kd_trace!("kd: ARM64 TTBR0_EL1 read unavailable: {error}");
                            0
                        }
                    };
                let (esr, far) = if self.last_exception_code == STATUS_SINGLE_STEP {
                    let esr =
                        match self.read_msr_value(self.current_processor, ARM64_WINDBG_ESR_EL1) {
                            Ok(value) => value,
                            Err(error) => {
                                kd_trace!("kd: ARM64 ESR_EL1 read unavailable: {error}");
                                0
                            }
                        };
                    let far =
                        match self.read_msr_value(self.current_processor, ARM64_WINDBG_FAR_EL1) {
                            Ok(value) => value,
                            Err(error) => {
                                kd_trace!("kd: ARM64 FAR_EL1 read unavailable: {error}");
                                0
                            }
                        };
                    (esr, far)
                } else {
                    (0, 0)
                };
                let kernel_dtb = self.kernel_dtb_override;
                ctx.resize(context_arm64::REGISTER_BUFFER_SIZE, 0);
                ctx[context_arm64::OFFSET_CR3..context_arm64::OFFSET_CR3 + 8]
                    .copy_from_slice(&kernel_dtb.to_le_bytes());
                ctx[context_arm64::OFFSET_TTBR0..context_arm64::OFFSET_TTBR0 + 8]
                    .copy_from_slice(&ttbr0.to_le_bytes());
                if let Some(special) = self.arm64_special_registers() {
                    copy_arm64_debug_registers(ctx, special, true);
                }
                if self.last_exception_code == STATUS_SINGLE_STEP {
                    ctx[context_arm64::OFFSET_ESR..context_arm64::OFFSET_ESR + 8]
                        .copy_from_slice(&esr.to_le_bytes());
                    ctx[context_arm64::OFFSET_FAR..context_arm64::OFFSET_FAR + 8]
                        .copy_from_slice(&far.to_le_bytes());
                }
                Ok(())
            }
        }
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
        let context_flags = self.context_flags();
        let mut ctx = with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
            api::get_context(framing, processor, context_flags)
        })?;
        kd_trace!("kd: read_registers: got {} context bytes", ctx.len());
        self.append_control_registers(&mut ctx)?;
        if self.arch == Arch::Amd64 {
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
                bytes::write_u64(&mut ctx, context::OFFSET_EFER, efer);
            }
        }
        kd_trace!("kd: read_registers: extended to {} bytes", ctx.len());
        if trace_enabled() {
            let cr3 = self.register_map.read_u64("cr3", &ctx).unwrap_or(0);
            let pc = self.register_map.read_u64("pc", &ctx).unwrap_or(0);
            let sp = self.register_map.read_u64("sp", &ctx).unwrap_or(0);
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
        match self.arch {
            Arch::Amd64 => {
                let context = context_payload(data)?;
                with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
                    api::set_context_chunked(framing, processor, context)
                })?;

                // KD restores hardware-breakpoint state from KSPECIAL_REGISTERS,
                // not the CONTEXT debug-register fields. Keep both views
                // coherent so DR6 clearing and DR7 updates survive ContinueApi2.
                let mut special = self.read_special_registers_uncached(self.current_processor)?;
                update_special_debug_registers_from_context(&mut special, data)?;
                self.write_special_registers(special)
            }
            Arch::Arm64 => {
                if data.len() < context_arm64::CONTEXT_SIZE {
                    return Err(Error::Kd(format!(
                        "ARM64 CONTEXT buffer too short: {} bytes, expected {}",
                        data.len(),
                        context_arm64::CONTEXT_SIZE
                    )));
                }
                with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
                    api::set_context_chunked(
                        framing,
                        processor,
                        &data[..context_arm64::CONTEXT_SIZE],
                    )
                })?;
                // ARM64 hardware state is authoritative in KSPECIAL_REGISTERS,
                // while CONTEXT exposes the same BVR/BCR and WVR/WCR fields.
                // Keep both views coherent when a full context is written. The
                // SetContext above already carried those fields, so a target
                // that refuses control space must not fail an applied write.
                if self.special_registers_unsupported {
                    return Ok(());
                }
                let mut special = match self.read_special_registers_uncached(processor) {
                    Ok(special) => special,
                    Err(error) => {
                        kd_trace!("kd: ARM64 KSPECIAL_REGISTERS mirror skipped: {error}");
                        self.special_registers_unsupported = true;
                        return Ok(());
                    }
                };
                update_arm64_debug_registers_from_context(&mut special, data)?;
                self.write_special_registers(special)
            }
        }
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
