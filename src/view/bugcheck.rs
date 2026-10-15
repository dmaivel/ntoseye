//! Bugcheck [`View`] builders and the fault context they carry:
//! decoded trap frames and exception records.

use ntoseye_macros::record;

use crate::bugchecks::{self, BugcheckAnalysis};
use crate::session;
use crate::trapframe::{KtrapFrame, KtrapFrameData};
use crate::triage_report::exception_code_name;

/// A decoded bugcheck (BSOD) with the code, the four parameters, and the
/// faulting instruction if ntoseye identified it.
#[record]
pub struct Bugcheck {
    /// The bugcheck code.
    pub code: u32,
    /// The code as zero-padded hex text (`0x0000000a`).
    pub code_hex: String,
    /// The symbolic name (`IRQL_NOT_LESS_OR_EQUAL`).
    pub name: String,
    /// What the bugcheck means. `None` if the code has no description.
    pub description: Option<String>,
    /// The responsible driver, from the dump record or from the fault site.
    pub driver: Option<String>,
    /// Where ntoseye found the data if it was not in its usual place (a
    /// pointer in `nt!KiBugCheckData` to the real slots). Usually `None`.
    pub source: Option<String>,
    /// The four bugcheck parameters, each with its meaning for this code.
    pub args: Vec<BugcheckArgument>,
    /// The faulting instruction. `None` if ntoseye did not identify one.
    pub fault: Option<BugcheckFault>,
    /// The trap frames that the parameters point to.
    pub trap_frames: Vec<BugcheckTrapFrame>,
}

/// One bugcheck parameter and what it means for the code.
#[record]
pub struct BugcheckArgument {
    /// The parameter's position, 1 to 4.
    pub index: usize,
    #[record(hex)]
    pub value: u64,
    /// What this parameter holds for the bugcheck code. Empty if the code
    /// has no documented meaning for this parameter.
    pub description: String,
}

/// The instruction a bugcheck faulted at.
#[record]
pub struct BugcheckFault {
    /// The faulting instruction pointer.
    #[record(hex)]
    pub ip: u64,
    /// The symbol at `ip`.
    pub symbol: String,
    /// The driver that contains `ip`. `None` if `ip` is not in a loaded
    /// driver.
    pub driver: Option<String>,
}

/// The x64 registers that a `_KTRAP_FRAME` saved. A register is `None` if
/// the entry that built the frame does not write it. The nonvolatile
/// registers r12-r15 are in the `_KEXCEPTION_FRAME`, so this type does
/// not include them.
#[record]
pub struct Amd64TrapFrame {
    /// The entry that built the frame: `interrupt`, `exception`,
    /// `system call`, or `Zw call`. `None` if the entry is unknown, and
    /// then only the machine frame and rbp are reliable.
    pub kind: Option<&'static str>,
    #[record(hex)]
    pub rax: Option<u64>,
    #[record(hex)]
    pub rbx: Option<u64>,
    #[record(hex)]
    pub rcx: Option<u64>,
    #[record(hex)]
    pub rdx: Option<u64>,
    #[record(hex)]
    pub rsi: Option<u64>,
    #[record(hex)]
    pub rdi: Option<u64>,
    #[record(hex)]
    pub rbp: u64,
    #[record(hex)]
    pub rsp: u64,
    #[record(hex)]
    pub r8: Option<u64>,
    #[record(hex)]
    pub r9: Option<u64>,
    #[record(hex)]
    pub r10: Option<u64>,
    #[record(hex)]
    pub r11: Option<u64>,
    #[record(hex)]
    pub rip: u64,
    #[record(hex)]
    pub cs: u16,
    #[record(hex)]
    pub ss: Option<u64>,
    #[record(hex)]
    pub eflags: u32,
    /// The exception error code, which is stale for a vector that has no
    /// error code.
    #[record(hex)]
    pub error_code: Option<u64>,
    /// The mode that the trap came from: 0 for kernel, 1 for user.
    pub previous_mode: u8,
    /// The IRQL before the trap, which only interrupts record.
    pub previous_irql: Option<u8>,
}

/// The ARM64 registers that a `_KTRAP_FRAME` saved. The frame holds
/// x0-x18, fp (x29), and lr (x30), so x19-x28 are `None`.
#[record]
pub struct Arm64TrapFrame {
    #[record(hex)]
    pub x0: Option<u64>,
    #[record(hex)]
    pub x1: Option<u64>,
    #[record(hex)]
    pub x2: Option<u64>,
    #[record(hex)]
    pub x3: Option<u64>,
    #[record(hex)]
    pub x4: Option<u64>,
    #[record(hex)]
    pub x5: Option<u64>,
    #[record(hex)]
    pub x6: Option<u64>,
    #[record(hex)]
    pub x7: Option<u64>,
    #[record(hex)]
    pub x8: Option<u64>,
    #[record(hex)]
    pub x9: Option<u64>,
    #[record(hex)]
    pub x10: Option<u64>,
    #[record(hex)]
    pub x11: Option<u64>,
    #[record(hex)]
    pub x12: Option<u64>,
    #[record(hex)]
    pub x13: Option<u64>,
    #[record(hex)]
    pub x14: Option<u64>,
    #[record(hex)]
    pub x15: Option<u64>,
    #[record(hex)]
    pub x16: Option<u64>,
    #[record(hex)]
    pub x17: Option<u64>,
    #[record(hex)]
    pub x18: Option<u64>,
    #[record(hex)]
    pub x19: Option<u64>,
    #[record(hex)]
    pub x20: Option<u64>,
    #[record(hex)]
    pub x21: Option<u64>,
    #[record(hex)]
    pub x22: Option<u64>,
    #[record(hex)]
    pub x23: Option<u64>,
    #[record(hex)]
    pub x24: Option<u64>,
    #[record(hex)]
    pub x25: Option<u64>,
    #[record(hex)]
    pub x26: Option<u64>,
    #[record(hex)]
    pub x27: Option<u64>,
    #[record(hex)]
    pub x28: Option<u64>,
    #[record(hex)]
    pub x29: Option<u64>,
    #[record(hex)]
    pub x30: Option<u64>,
    #[record(hex)]
    pub fp: u64,
    #[record(hex)]
    pub lr: u64,
    #[record(hex)]
    pub sp: u64,
    #[record(hex)]
    pub pc: u64,
    #[record(hex)]
    pub cpsr: Option<u64>,
    #[record(hex)]
    pub esr: Option<u64>,
    /// The faulting data address (FAR).
    #[record(hex)]
    pub fault_address: Option<u64>,
    /// The mode that the trap came from: 0 for kernel, 1 for user.
    pub previous_mode: Option<u8>,
    /// The IRQL before the trap.
    pub previous_irql: Option<u8>,
    /// Breakpoint control registers.
    #[record(hex)]
    pub bcr: Vec<Option<u64>>,
    /// Breakpoint value registers.
    #[record(hex)]
    pub bvr: Vec<Option<u64>>,
    /// Watchpoint control registers.
    #[record(hex)]
    pub wcr: Vec<Option<u64>>,
    /// Watchpoint value registers.
    #[record(hex)]
    pub wvr: Vec<Option<u64>>,
}

/// A decoded `EXCEPTION_RECORD64` (`.exr`).
#[record]
pub struct ExceptionRecord {
    /// The address that ntoseye read the record from. `None` for the
    /// record of the current event, which ntoseye builds from the stop
    /// without reading it from memory.
    #[record(hex)]
    pub record_address: Option<u64>,
    /// The exception code (NTSTATUS).
    #[record(hex)]
    pub code: u32,
    /// The code's symbolic name.
    pub code_name: String,
    #[record(hex)]
    pub flags: u32,
    /// The address of a nested `EXCEPTION_RECORD`, or 0.
    #[record(hex)]
    pub nested: u64,
    /// Where the exception occurred.
    #[record(hex)]
    pub exception_address: u64,
    /// The exception's `ExceptionInformation` parameters.
    #[record(hex)]
    pub parameters: Vec<u64>,
}

/// A decoded `_KTRAP_FRAME` (`.trap`).
#[record]
pub struct TrapFrame {
    /// The address that ntoseye read the frame from.
    #[record(hex)]
    pub address: u64,
    /// The symbol at the interrupted instruction.
    pub rip_symbol: Option<String>,
    /// The saved registers, by architecture.
    pub frame: KtrapFrameRegisters,
}

/// A trap frame that a bugcheck parameter points to, with its decoded
/// registers or the reason that decoding failed.
#[record]
pub struct BugcheckTrapFrame {
    /// The address that ntoseye read the frame from.
    #[record(hex)]
    pub address: u64,
    /// The symbol at the interrupted instruction.
    pub rip_symbol: Option<String>,
    /// The saved registers. `None` if decoding failed.
    pub frame: Option<KtrapFrameRegisters>,
    /// The reason that decoding failed. `None` if decoding succeeded.
    pub error: Option<String>,
}

/// A `_KTRAP_FRAME`'s registers, as the frame's architecture names them.
#[record]
pub enum KtrapFrameRegisters {
    Amd64(Amd64TrapFrame),
    Arm64(Box<Arm64TrapFrame>),
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
            let registers = |values: &[Option<u64>]| values.to_vec();
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
pub fn exception_record(
    record_address: Option<u64>,
    record: &session::ExceptionRecord,
) -> ExceptionRecord {
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
