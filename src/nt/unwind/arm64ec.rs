//! Emulated x64 frames on ARM64 (ARM64EC).
//!
//! In an x64 process on ARM64 Windows, x64 code (the program's own, run by
//! the emulator) and ARM64EC code (the system DLLs, compiled for ARM64 but to
//! the x64 calling convention) call each other on one stack. ARM64EC code
//! keeps each x64 register in a fixed ARM64 one, so a frame of either kind
//! unwinds from the same registers: x64 code by its x64 unwind data, ARM64EC
//! code by its ARM64 unwind data.
//!
//! Neither kind of call leaves an emulator frame to cross. x64 code calling
//! ARM64EC code enters it through an entry thunk with the x64 return address
//! popped into lr, so unwinding the thunk returns into the x64 caller.
//! ARM64EC code calling x64 code goes through an exit thunk whose call the
//! emulator turns into an x64 call, pushing the thunk's return address, so
//! unwinding the x64 callee returns into the thunk.

use super::{AMD64_VOLATILE, REGISTER_SLOTS, RegisterContext, StackTracer, Unwound};

/// The ARM64 register each x64 register lives in during ARM64EC code, by
/// x64 unwind number (rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8–r15). rsp
/// is sp, which the walk keeps as `rsp` on either machine.
const X64_IN_ARM64: [Option<usize>; 16] = [
    Some(8),
    Some(0),
    Some(1),
    Some(27),
    None,
    Some(29),
    Some(25),
    Some(26),
    Some(2),
    Some(3),
    Some(4),
    Some(5),
    Some(19),
    Some(20),
    Some(21),
    Some(22),
];

/// ARM64 registers a call clobbers (x0–x17), and lr, which an x64 frame
/// neither saves nor restores.
fn clobbered_by_x64_frame(arm64: usize) -> bool {
    arm64 < 18 || arm64 == 30
}

impl StackTracer<'_> {
    /// Unwind an x64 frame of an ARM64 thread, whose registers are in their
    /// ARM64EC homes.
    pub fn unwind_once_emulated_amd64(&mut self, context: &mut RegisterContext) -> Unwound {
        let mut x64 = RegisterContext {
            rip: context.rip,
            rsp: context.rsp,
            regs: [None; REGISTER_SLOTS],
            after_call: context.after_call,
            machine_frame: None,
        };
        for (register, home) in X64_IN_ARM64.iter().enumerate() {
            if let Some(home) = home {
                x64.regs[register] = context.regs[*home];
            }
        }
        let unwound = self.unwind_once_amd64(&mut x64);
        let Unwound::Frame { stack_switch } = unwound else {
            return unwound;
        };
        for index in 0..REGISTER_SLOTS {
            if clobbered_by_x64_frame(index) {
                context.regs[index] = None;
            }
        }
        for (register, home) in X64_IN_ARM64.iter().enumerate() {
            if let Some(home) = home
                && !AMD64_VOLATILE.contains(&register)
            {
                context.regs[*home] = x64.regs[register];
            }
        }
        context.rip = x64.rip;
        context.rsp = x64.rsp;
        // A popped return address: the caller, x64 or an exit thunk, is
        // suspended in its call.
        context.after_call = !stack_switch;
        unwound
    }
}
