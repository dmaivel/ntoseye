//! Bugcheck [`View`] builders and the trap frames they carry.

use ntoseye_macros::record;

use crate::bugchecks::{self, BugcheckAnalysis};
use crate::trapframe::KtrapFrameData;

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
    pub frame: Option<KtrapFrameData>,
    /// The reason that decoding failed. `None` if decoding succeeded.
    pub error: Option<String>,
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

/// A trap frame carried by a bugcheck parameter: its address, the symbol at
/// the interrupted `rip`, and either the decoded `_KTRAP_FRAME` registers or
/// the reason decoding failed.
pub fn bugcheck_trap_frame(tf: &bugchecks::BugcheckTrapFrame) -> BugcheckTrapFrame {
    BugcheckTrapFrame {
        address: tf.address,
        rip_symbol: tf.rip_symbol.clone(),
        frame: tf.frame.as_ref().map(|frame| frame.data.clone()),
        error: tf.error.clone(),
    }
}
