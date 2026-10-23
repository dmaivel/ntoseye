//! What stepping a frame of Windows code to its caller needs, whatever the
//! architecture: the registers a walk tracks, what one step concludes, and
//! the reads an unwinder makes, of a function's unwind data and of the
//! stack. Each architecture's unwind formats, which the Windows ABI defines
//! per architecture, are in its own `unwind` module.

use std::borrow::Cow;
use std::sync::LazyLock;

use ntoseye_macros::record;

use super::amd64::unwind::Amd64UnwindInfo;
use super::arm64::unwind::{Arm64PackedUnwind, Arm64XdataUnwind};
use super::{Arch, amd64, arm64};

static UNWIND_TRACE: LazyLock<bool> =
    LazyLock::new(|| std::env::var_os("NTOSEYE_UNWIND_TRACE").is_some());

/// Whether per-frame unwinder diagnostics are on (`NTOSEYE_UNWIND_TRACE`):
/// which branch each step takes, so an early bail-out (no function entry,
/// bad codes, a failed read) can be told apart from a genuine leaf pop.
pub fn unwind_trace_enabled() -> bool {
    *UNWIND_TRACE
}

macro_rules! unwind_trace {
    ($($arg:tt)*) => {
        if $crate::arch::unwind::unwind_trace_enabled() {
            eprintln!($($arg)*);
        }
    };
}

/// Register slots a walk tracks: the most any architecture numbers.
pub const REGISTER_SLOTS: usize = {
    let amd64 = amd64::ENCODED_REGISTERS.len();
    let arm64 = arm64::ENCODED_REGISTERS.len();
    if amd64 > arm64 { amd64 } else { arm64 }
};

/// A frame's registers during a walk. `regs` is indexed by architectural
/// number, in [`super::Architecture::encoded_registers`] order: x64
/// encoding order or ARM64 x0–x30.
#[derive(Clone, Debug)]
pub struct FrameRegisters {
    /// The architecture whose registers these are, which numbers `regs`.
    pub arch: Arch,
    pub pc: u64,
    pub sp: u64,
    /// The integer registers by the architecture's encoding.
    pub regs: [Option<u64>; REGISTER_SLOTS],
    /// `pc` is a return address rather than where the frame was stopped or
    /// interrupted.
    pub after_call: bool,
    /// The hardware-pushed machine frame the last unwind step crossed to
    /// reach this frame (AMD64 `UWOP_PUSH_MACHFRAME`): this frame was
    /// interrupted there rather than called.
    pub machine_frame: Option<u64>,
}

impl FrameRegisters {
    pub fn new(arch: Arch, pc: u64, sp: u64) -> Self {
        Self {
            arch,
            pc,
            sp,
            regs: [None; REGISTER_SLOTS],
            after_call: false,
            machine_frame: None,
        }
    }

    /// The context of a stopped frame whose registers `lookup` answers by
    /// name, a register it lacks under its own name taken by its other one
    /// (ARM64's `x29` as `fp`).
    pub fn from_lookup(arch: Arch, lookup: impl Fn(&str) -> Option<u64>) -> Self {
        let mut context = Self::new(
            arch,
            lookup(arch.pc_register()).unwrap_or(0),
            lookup(arch.sp_register()).unwrap_or(0),
        );
        for (slot, name) in context.regs.iter_mut().zip(arch.encoded_registers()) {
            *slot = lookup(name).or_else(|| lookup(arch.other_register_name(name)?));
        }
        context
    }

    /// Every register the context knows, under each name a host may ask for
    /// it by.
    pub fn named_values(&self) -> Vec<(&'static str, u64)> {
        let arch = self.arch;
        let mut values = Vec::new();
        let mut others = Vec::new();
        for (register, name) in arch.encoded_registers().iter().enumerate() {
            let Some(value) = self.get(register as u8) else {
                continue;
            };
            values.push((*name, value));
            if let Some(other) = arch.other_register_name(name) {
                others.push((other, value));
            }
        }
        values.extend(others);
        values.extend([(arch.pc_register(), self.pc), (arch.sp_register(), self.sp)]);
        values
    }

    /// An integer register by its encoding number; the stack pointer's
    /// number, where the encoding has one, is `sp`.
    pub fn get(&self, register: u8) -> Option<u64> {
        if Some(register) == self.arch.encoded_sp() {
            return Some(self.sp);
        }
        self.regs.get(register as usize).copied().flatten()
    }

    pub fn set(&mut self, register: u8, value: u64) {
        if Some(register) == self.arch.encoded_sp() {
            self.sp = value;
        }
        if let Some(slot) = self.regs.get_mut(register as usize) {
            *slot = Some(value);
        }
    }
}

/// Outcome of unwinding one frame to its caller.
pub enum Unwound {
    /// Could not unwind further; the caller falls back to a stack scan.
    Stop,
    /// Advanced to the caller. `stack_switch` is set when we crossed a hardware
    /// trap/interrupt frame, where sp may move to a different stack (e.g. an IST
    /// or the idle stack) and so need not be greater than the previous sp.
    Frame { stack_switch: bool },
    /// Advanced to the caller by analyzing its function's prolog: a frame of
    /// code whose unwind data is not mapped.
    Prolog,
}

/// The bytes of an image's unwind data, at offsets from its base.
pub trait UnwindBytes {
    fn read(&self, offset: usize, len: usize) -> Option<Cow<'_, [u8]>>;
}

/// What an unwind reads besides the unwind data: the stack being walked.
pub trait FrameMemory {
    /// The pointer-sized value on the stack at `address`.
    fn stack_u64(&self, address: u64) -> Option<u64>;

    /// The registers the kernel saved in the `KTRAP_FRAME` at `address`,
    /// whose layout the Windows build gives.
    fn trap_frame(&self, address: u64) -> Option<FrameRegisters>;
}

/// An entry's decoded unwind data, by form.
#[record]
#[derive(Debug, Clone)]
pub enum Unwind {
    Amd64(Amd64UnwindInfo),
    Packed(Arm64PackedUnwind),
    Xdata(Arm64XdataUnwind),
}

/// The exception or termination handler of an unwind info.
#[record]
#[derive(Debug, Clone)]
pub struct UnwindHandler {
    #[record(hex)]
    pub address: u64,
    pub symbol: String,
    /// The start address of the language-specific data of the handler.
    #[record(hex)]
    pub data: u64,
}

impl UnwindHandler {
    /// The handler at `rva` of the image at `base`, its data at `data_rva`.
    pub fn new(base: u64, rva: u32, data_rva: u32, symbol: impl Fn(u64) -> String) -> Self {
        let address = base.wrapping_add(u64::from(rva));
        Self {
            address,
            symbol: symbol(address),
            data: base.wrapping_add(u64::from(data_rva)),
        }
    }
}
