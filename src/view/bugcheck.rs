//! Bugcheck [`View`] builders and the fault context they carry:
//! decoded trap frames and exception records.

use super::shape::{Hex, shapes, unions};
use crate::bugchecks::{self, BugcheckAnalysis};
use crate::session;
use crate::trapframe::{KtrapFrame, KtrapFrameData};
use crate::triage_report::exception_code_name;

shapes! {
    /// A decoded bugcheck (BSOD) with the code, the four parameters, and the
    /// faulting instruction if ntoseye identified it.
    Bugcheck {
        /// The bugcheck code.
        code: u32,
        /// The code as zero-padded hex text (`0x0000000a`).
        code_hex: String,
        /// The symbolic name (`IRQL_NOT_LESS_OR_EQUAL`).
        name: String,
        /// What the bugcheck means. `None` if the code has no description.
        description: Option<String>,
        /// The responsible driver, from the dump record or from the fault site.
        driver: Option<String>,
        /// Where ntoseye found the data if it was not in its usual place (a
        /// pointer in `nt!KiBugCheckData` to the real slots). Usually `None`.
        source: Option<String>,
        /// The four bugcheck parameters, each with its meaning for this code.
        args: Vec<BugcheckArgument>,
        /// The faulting instruction. `None` if ntoseye did not identify one.
        fault: Option<BugcheckFault>,
        /// The trap frames that the parameters point to.
        trap_frames: Vec<BugcheckTrapFrame>,
    }

    /// One bugcheck parameter and what it means for the code.
    BugcheckArgument {
        /// The parameter's position, 1 to 4.
        index: usize,
        value: Hex,
        /// What this parameter holds for the bugcheck code. Empty if the code
        /// has no documented meaning for this parameter.
        description: String,
    }

    /// The instruction a bugcheck faulted at.
    BugcheckFault {
        /// The faulting instruction pointer.
        ip: Hex,
        /// The symbol at `ip`.
        symbol: String,
        /// The driver that contains `ip`. `None` if `ip` is not in a loaded
        /// driver.
        driver: Option<String>,
    }

    /// The x64 registers that a `_KTRAP_FRAME` saved. A register is `None` if
    /// the entry that built the frame does not write it. The nonvolatile
    /// registers r12-r15 are in the `_KEXCEPTION_FRAME`, so this type does
    /// not include them.
    Amd64TrapFrame {
        /// The entry that built the frame: `interrupt`, `exception`,
        /// `system call`, or `Zw call`. `None` if the entry is unknown, and
        /// then only the machine frame and rbp are reliable.
        kind: Option<&'static str>,
        rax: Option<Hex>,
        rbx: Option<Hex>,
        rcx: Option<Hex>,
        rdx: Option<Hex>,
        rsi: Option<Hex>,
        rdi: Option<Hex>,
        rbp: Hex,
        rsp: Hex,
        r8: Option<Hex>,
        r9: Option<Hex>,
        r10: Option<Hex>,
        r11: Option<Hex>,
        rip: Hex,
        cs: Hex<u16>,
        ss: Option<Hex>,
        eflags: Hex<u32>,
        /// The exception error code, which is stale for a vector that has no
        /// error code.
        error_code: Option<Hex>,
        /// The mode that the trap came from: 0 for kernel, 1 for user.
        previous_mode: u8,
        /// The IRQL before the trap, which only interrupts record.
        previous_irql: Option<u8>,
    }

    /// The ARM64 registers that a `_KTRAP_FRAME` saved. The frame holds
    /// x0-x18, fp (x29), and lr (x30), so x19-x28 are `None`.
    Arm64TrapFrame {
        x0: Option<Hex>,
        x1: Option<Hex>,
        x2: Option<Hex>,
        x3: Option<Hex>,
        x4: Option<Hex>,
        x5: Option<Hex>,
        x6: Option<Hex>,
        x7: Option<Hex>,
        x8: Option<Hex>,
        x9: Option<Hex>,
        x10: Option<Hex>,
        x11: Option<Hex>,
        x12: Option<Hex>,
        x13: Option<Hex>,
        x14: Option<Hex>,
        x15: Option<Hex>,
        x16: Option<Hex>,
        x17: Option<Hex>,
        x18: Option<Hex>,
        x19: Option<Hex>,
        x20: Option<Hex>,
        x21: Option<Hex>,
        x22: Option<Hex>,
        x23: Option<Hex>,
        x24: Option<Hex>,
        x25: Option<Hex>,
        x26: Option<Hex>,
        x27: Option<Hex>,
        x28: Option<Hex>,
        x29: Option<Hex>,
        x30: Option<Hex>,
        fp: Hex,
        lr: Hex,
        sp: Hex,
        pc: Hex,
        cpsr: Option<Hex>,
        esr: Option<Hex>,
        /// The faulting data address (FAR).
        fault_address: Option<Hex>,
        /// The mode that the trap came from: 0 for kernel, 1 for user.
        previous_mode: Option<u8>,
        /// The IRQL before the trap.
        previous_irql: Option<u8>,
        /// Breakpoint control registers.
        bcr: Vec<Option<Hex>>,
        /// Breakpoint value registers.
        bvr: Vec<Option<Hex>>,
        /// Watchpoint control registers.
        wcr: Vec<Option<Hex>>,
        /// Watchpoint value registers.
        wvr: Vec<Option<Hex>>,
    }

    /// A decoded `EXCEPTION_RECORD64` (`.exr`).
    ExceptionRecord {
        /// The address that ntoseye read the record from. `None` for the
        /// record of the current event, which ntoseye builds from the stop
        /// without reading it from memory.
        record_address: Option<Hex>,
        /// The exception code (NTSTATUS).
        code: Hex<u32>,
        /// The code's symbolic name.
        code_name: String,
        flags: Hex<u32>,
        /// The address of a nested `EXCEPTION_RECORD`, or 0.
        nested: Hex,
        /// Where the exception occurred.
        exception_address: Hex,
        /// The exception's `ExceptionInformation` parameters.
        parameters: Vec<Hex>,
    }

    /// A decoded `_KTRAP_FRAME` (`.trap`).
    TrapFrame {
        /// The address that ntoseye read the frame from.
        address: Hex,
        /// The symbol at the interrupted instruction.
        rip_symbol: Option<String>,
        /// The saved registers, by architecture.
        frame: KtrapFrameRegisters,
    }

    /// A trap frame that a bugcheck parameter points to, with its decoded
    /// registers or the reason that decoding failed.
    BugcheckTrapFrame {
        /// The address that ntoseye read the frame from.
        address: Hex,
        /// The symbol at the interrupted instruction.
        rip_symbol: Option<String>,
        /// The saved registers. `None` if decoding failed.
        frame: Option<KtrapFrameRegisters>,
        /// The reason that decoding failed. `None` if decoding succeeded.
        error: Option<String>,
    }
}

unions! {
    /// A `_KTRAP_FRAME`'s registers, as the frame's architecture names them.
    KtrapFrameRegisters {
        Amd64(Amd64TrapFrame),
        Arm64(Box<Arm64TrapFrame>),
    }
}

/// A decoded bugcheck (BSOD): code/name/description, its four parameters, and the
/// faulting instruction when one was identified.
pub fn bugcheck(a: &BugcheckAnalysis) -> Bugcheck {
    Bugcheck {
        code: a.code,
        code_hex: format!("{:#010x}", a.code),
        name: a.name.clone(),
        description: a.description.clone(),
        driver: a.driver.clone(),
        source: a.source.clone(),
        args: a
            .args
            .iter()
            .enumerate()
            .map(|(i, arg)| BugcheckArgument {
                index: i + 1,
                value: arg.value,
                description: arg.description.clone(),
            })
            .collect(),
        fault: a.fault.as_ref().map(|f| BugcheckFault {
            ip: f.ip,
            symbol: f.symbol.clone(),
            driver: f.driver.clone(),
        }),
        trap_frames: a.trap_frames.iter().map(bugcheck_trap_frame).collect(),
    }
}

fn ktrap_frame_registers(frame: &KtrapFrame) -> KtrapFrameRegisters {
    match &frame.data {
        KtrapFrameData::Amd64(frame) => KtrapFrameRegisters::Amd64(Amd64TrapFrame {
            kind: frame.kind.map(|kind| kind.as_str()),
            rax: frame.rax,
            rbx: frame.rbx,
            rcx: frame.rcx,
            rdx: frame.rdx,
            rsi: frame.rsi,
            rdi: frame.rdi,
            rbp: frame.rbp,
            rsp: frame.rsp,
            r8: frame.r8,
            r9: frame.r9,
            r10: frame.r10,
            r11: frame.r11,
            rip: frame.rip,
            cs: frame.cs,
            ss: frame.ss.map(u64::from),
            eflags: frame.eflags,
            error_code: frame.error_code,
            previous_mode: frame.previous_mode,
            previous_irql: frame.previous_irql,
        }),
        KtrapFrameData::Arm64(frame) => {
            let x = |index: usize| match index {
                0..=18 => Some(frame.x[index]),
                29 => Some(frame.fp),
                30 => Some(frame.lr),
                _ => None,
            };
            let registers =
                |values: &[Option<u64>]| values.to_vec();
            KtrapFrameRegisters::Arm64(Box::new(Arm64TrapFrame {
                x0: x(0),
                x1: x(1),
                x2: x(2),
                x3: x(3),
                x4: x(4),
                x5: x(5),
                x6: x(6),
                x7: x(7),
                x8: x(8),
                x9: x(9),
                x10: x(10),
                x11: x(11),
                x12: x(12),
                x13: x(13),
                x14: x(14),
                x15: x(15),
                x16: x(16),
                x17: x(17),
                x18: x(18),
                x19: x(19),
                x20: x(20),
                x21: x(21),
                x22: x(22),
                x23: x(23),
                x24: x(24),
                x25: x(25),
                x26: x(26),
                x27: x(27),
                x28: x(28),
                x29: x(29),
                x30: x(30),
                fp: frame.fp,
                lr: frame.lr,
                sp: frame.sp,
                pc: frame.pc,
                cpsr: frame.cpsr,
                esr: frame.esr,
                fault_address: frame.fault_address,
                previous_mode: frame.previous_mode,
                previous_irql: frame.previous_irql,
                bcr: registers(&frame.bcr),
                bvr: registers(&frame.bvr),
                wcr: registers(&frame.wcr),
                wvr: registers(&frame.wvr),
            }))
        }
    }
}

/// A decoded `EXCEPTION_RECORD64` (`.exr`). `record_address` is where the
/// record was read from; `None` for the current event's record, which is
/// reconstructed from the stop rather than read from guest memory.
pub fn exception_record(record_address: Option<u64>, record: &session::ExceptionRecord) -> ExceptionRecord {
    ExceptionRecord {
        record_address,
        code: record.code,
        code_name: exception_code_name(record.code).to_string(),
        flags: record.flags,
        nested: record.nested,
        exception_address: record.address,
        parameters: record.parameters.to_vec(),
    }
}

/// A decoded `_KTRAP_FRAME` shared by structured host APIs.
pub fn trap_frame(frame: &KtrapFrame, rip_symbol: Option<String>) -> TrapFrame {
    TrapFrame {
        address: frame.address,
        rip_symbol,
        frame: ktrap_frame_registers(frame),
    }
}

/// A trap frame carried by a bugcheck parameter: its address, the symbol at
/// the interrupted `rip`, and either the decoded `_KTRAP_FRAME` registers or
/// the reason decoding failed.
pub fn bugcheck_trap_frame(tf: &bugchecks::BugcheckTrapFrame) -> BugcheckTrapFrame {
    BugcheckTrapFrame {
        address: tf.address,
        rip_symbol: tf.rip_symbol.clone(),
        frame: tf.frame.as_ref().map(ktrap_frame_registers),
        error: tf.error.clone(),
    }
}

#[cfg(all(test, feature = "mcp"))]
mod tests {
    use super::bugcheck_trap_frame;
    use crate::bugchecks::BugcheckTrapFrame;
    use crate::view::to_json;

    #[test]
    fn bugcheck_trap_frame_exposes_decode_failure() {
        let view = bugcheck_trap_frame(&BugcheckTrapFrame {
            address: 0xffff_8000_1234_5000,
            frame: None,
            rip_symbol: None,
            error: Some("type `_KTRAP_FRAME` not found".to_string()),
        })
        .into_view();
        let json = to_json(&view);
        assert!(json["frame"].is_null());
        assert_eq!(json["error"], "type `_KTRAP_FRAME` not found");
    }
}
