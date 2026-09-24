//! Bugcheck [`View`] builders and the fault context they carry:
//! decoded trap frames and exception records.

use super::View;
use crate::bugchecks::{BugcheckAnalysis, BugcheckTrapFrame};
use crate::session::ExceptionRecord;
use crate::trapframe::{KtrapFrame, KtrapFrameData};
use crate::triage_report::exception_code_name;

/// A decoded bugcheck (BSOD): code/name/description, its four parameters, and the
/// faulting instruction when one was identified.
pub fn bugcheck(a: &BugcheckAnalysis) -> View {
    let args = a
        .args
        .iter()
        .enumerate()
        .map(|(i, arg)| {
            View::Object(vec![
                ("index", View::Num((i + 1) as u64)),
                ("value", View::Hex(arg.value)),
                ("description", View::Str(arg.description.clone())),
            ])
        })
        .collect();
    let fault = a.fault.as_ref().map_or(View::Null, |f| {
        View::Object(vec![
            ("ip", View::Hex(f.ip)),
            ("symbol", View::Str(f.symbol.clone())),
            ("driver", View::OptStr(f.driver.clone())),
        ])
    });
    let trap_frames = a.trap_frames.iter().map(bugcheck_trap_frame).collect();
    View::Object(vec![
        ("code", View::Num(a.code as u64)),
        ("code_hex", View::Str(format!("{:#010x}", a.code))),
        ("name", View::Str(a.name.clone())),
        ("description", View::OptStr(a.description.clone())),
        ("driver", View::OptStr(a.driver.clone())),
        ("source", View::OptStr(a.source.clone())),
        ("args", View::List(args)),
        ("fault", fault),
        ("trap_frames", View::List(trap_frames)),
    ])
}

fn ktrap_frame_registers(frame: &KtrapFrame) -> View {
    match &frame.data {
        KtrapFrameData::Amd64(frame) => View::Object(vec![
            ("rax", View::Hex(frame.rax)),
            ("rbx", View::Hex(frame.rbx)),
            ("rcx", View::Hex(frame.rcx)),
            ("rdx", View::Hex(frame.rdx)),
            ("rsi", View::Hex(frame.rsi)),
            ("rdi", View::Hex(frame.rdi)),
            ("rbp", View::Hex(frame.rbp)),
            ("rsp", View::Hex(frame.rsp)),
            ("r8", View::Hex(frame.r8)),
            ("r9", View::Hex(frame.r9)),
            ("r10", View::Hex(frame.r10)),
            ("r11", View::Hex(frame.r11)),
            ("rip", View::Hex(frame.rip)),
            ("cs", View::Hex(frame.cs as u64)),
            ("ss", View::Hex(frame.ss as u64)),
            ("eflags", View::Hex(frame.eflags as u64)),
            ("error_code", View::Hex(frame.error_code)),
            ("previous_mode", View::Num(frame.previous_mode as u64)),
            ("previous_irql", View::Num(frame.previous_irql as u64)),
        ]),
        KtrapFrameData::Arm64(frame) => {
            const X_NAMES: [&str; 31] = [
                "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12",
                "x13", "x14", "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24",
                "x25", "x26", "x27", "x28", "x29", "x30",
            ];
            let mut fields = Vec::with_capacity(31 + 9);
            for (index, name) in X_NAMES.iter().enumerate() {
                let value = match index {
                    0..=18 => Some(frame.x[index]),
                    29 => Some(frame.fp),
                    30 => Some(frame.lr),
                    _ => None,
                };
                fields.push((*name, value.map_or(View::Null, View::Hex)));
            }
            fields.extend([
                ("fp", View::Hex(frame.fp)),
                ("lr", View::Hex(frame.lr)),
                ("sp", View::Hex(frame.sp)),
                ("pc", View::Hex(frame.pc)),
                ("cpsr", View::OptHex(frame.cpsr)),
                ("esr", View::OptHex(frame.esr)),
                ("fault_address", View::OptHex(frame.fault_address)),
                (
                    "previous_mode",
                    View::OptNum(frame.previous_mode.map(u64::from)),
                ),
                (
                    "previous_irql",
                    View::OptNum(frame.previous_irql.map(u64::from)),
                ),
            ]);
            let registers = |values: &[Option<u64>]| {
                View::List(values.iter().copied().map(View::OptHex).collect())
            };
            fields.extend([
                ("bcr", registers(&frame.bcr)),
                ("bvr", registers(&frame.bvr)),
                ("wcr", registers(&frame.wcr)),
                ("wvr", registers(&frame.wvr)),
            ]);
            View::Object(fields)
        }
    }
}

/// A decoded `EXCEPTION_RECORD64` (`.exr`). `record_address` is where the
/// record was read from; `None` for the current event's record, which is
/// reconstructed from the stop rather than read from guest memory.
pub fn exception_record(record_address: Option<u64>, record: &ExceptionRecord) -> View {
    View::Object(vec![
        ("record_address", View::OptHex(record_address)),
        ("code", View::Hex(u64::from(record.code))),
        (
            "code_name",
            View::Str(exception_code_name(record.code).to_string()),
        ),
        ("flags", View::Hex(u64::from(record.flags))),
        ("nested", View::Hex(record.nested)),
        ("exception_address", View::Hex(record.address)),
        (
            "parameters",
            View::List(record.parameters.iter().copied().map(View::Hex).collect()),
        ),
    ])
}

/// A decoded `_KTRAP_FRAME` shared by structured host APIs.
pub fn trap_frame(frame: &KtrapFrame, rip_symbol: Option<String>) -> View {
    View::Object(vec![
        ("address", View::Hex(frame.address)),
        ("rip_symbol", View::OptStr(rip_symbol)),
        ("frame", ktrap_frame_registers(frame)),
    ])
}

/// A trap frame carried by a bugcheck parameter: its address, the symbol at
/// the interrupted `rip`, and either the decoded `_KTRAP_FRAME` registers or
/// the reason decoding failed.
pub fn bugcheck_trap_frame(tf: &BugcheckTrapFrame) -> View {
    View::Object(vec![
        ("address", View::Hex(tf.address)),
        ("rip_symbol", View::OptStr(tf.rip_symbol.clone())),
        (
            "frame",
            tf.frame.as_ref().map_or(View::Null, ktrap_frame_registers),
        ),
        ("error", View::OptStr(tf.error.clone())),
    ])
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
        });
        let json = to_json(&view);
        assert!(json["frame"].is_null());
        assert_eq!(json["error"], "type `_KTRAP_FRAME` not found");
    }
}
