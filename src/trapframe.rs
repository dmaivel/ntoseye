//! x64 and ARM64 `_KTRAP_FRAME` decoding.
//!
//! Windows builds a `_KTRAP_FRAME` on every kernel-mode trap (interrupt,
//! exception, syscall); several bugchecks carry a pointer to one in their
//! parameters. The layout is taken from the PDB rather than hardcoded, so
//! decoding tracks whatever build the guest is running.

use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::layout::{FieldInfo, TypeInfo, le_uint};
use crate::target::{Arm64SavedRegisters, SavedThreadRegisters, Target};
use crate::types::{Arch, Dtb, VirtAddr};
use std::sync::Arc;

pub const KTRAP_FRAME_TYPE: &str = "_KTRAP_FRAME";
pub const KSWITCH_FRAME_TYPE: &str = "_KSWITCH_FRAME";

/// A decoded ARM64 `_KTRAP_FRAME` as described by the target PDB. ARM64 saves
/// X0-X18 in the trap frame and keeps the control/debug state alongside the
/// return context. Optional fields absent from a particular build are `None`
/// rather than being filled from a guessed fixed offset.
#[derive(Clone, Debug)]
pub struct Arm64TrapFrame {
    pub x: [u64; 19],
    pub lr: u64,
    pub fp: u64,
    pub pc: u64,
    pub sp: u64,
    pub cpsr: Option<u64>,
    pub esr: Option<u64>,
    pub fault_address: Option<u64>,
    pub bcr: [Option<u64>; 8],
    pub bvr: [Option<u64>; 8],
    pub wcr: [Option<u64>; 2],
    pub wvr: [Option<u64>; 2],
    pub previous_mode: Option<u8>,
    pub previous_irql: Option<u8>,
}

/// Which kind of entry built an x64 `_KTRAP_FRAME` (its `ExceptionActive`),
/// which decides the registers it holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrapKind {
    Interrupt,
    Exception,
    SystemCall,
}

impl TrapKind {
    fn from_exception_active(value: u64) -> Option<Self> {
        match value {
            0 => Some(Self::Interrupt),
            1 => Some(Self::Exception),
            2 => Some(Self::SystemCall),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Interrupt => "interrupt",
            Self::Exception => "exception",
            Self::SystemCall => "system call",
        }
    }
}

/// The x64 state saved by a `_KTRAP_FRAME`. The nonvolatile r12-r15 live in
/// the accompanying `_KEXCEPTION_FRAME`, not the trap frame.
///
/// What a frame holds depends on the entry that built it, `kind`: every
/// entry saves the volatile registers and rbp, but only a system call saves
/// rbx, rsi, and rdi, and it stores r10 in the r11 slot (`syscall` keeps the
/// flags in r11) and writes no error code; only interrupt dispatch keeps the
/// previous IRQL. A register
/// the entry does not save is `None` rather than whatever the slot held.
#[derive(Clone, Debug)]
pub struct Amd64TrapFrame {
    /// `None` when the PDB has no `ExceptionActive` or it holds an unknown
    /// value; then only the registers every entry saves are trusted.
    pub kind: Option<TrapKind>,
    pub rax: u64,
    pub rbx: Option<u64>,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: Option<u64>,
    pub rdi: Option<u64>,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: Option<u64>,
    pub rip: u64,
    pub cs: u16,
    pub ss: u16,
    pub eflags: u32,
    /// Hardware error code pushed by the CPU for faults that carry one
    /// (page fault, GP fault, ...); otherwise whatever the trap handler wrote.
    /// `None` for a system call, whose entry writes none.
    pub error_code: Option<u64>,
    /// `KPROCESSOR_MODE` the trap came from (0 = kernel, 1 = user), from the
    /// saved `cs` as Windows reads it: the `PreviousMode` field is set only
    /// by a system call.
    pub previous_mode: u8,
    pub previous_irql: Option<u8>,
}

#[derive(Clone, Debug)]
pub enum KtrapFrameData {
    Amd64(Amd64TrapFrame),
    Arm64(Box<Arm64TrapFrame>),
}

/// A decoded `_KTRAP_FRAME` with architecture-specific register names.
#[derive(Clone, Debug)]
pub struct KtrapFrame {
    /// Guest-virtual address the frame was decoded from.
    pub address: u64,
    pub data: KtrapFrameData,
}

impl KtrapFrame {
    pub fn is_arm64(&self) -> bool {
        matches!(&self.data, KtrapFrameData::Arm64(_))
    }

    pub fn instruction_pointer(&self) -> u64 {
        match &self.data {
            KtrapFrameData::Amd64(frame) => frame.rip,
            KtrapFrameData::Arm64(frame) => frame.pc,
        }
    }

    pub fn stack_pointer(&self) -> u64 {
        match &self.data {
            KtrapFrameData::Amd64(frame) => frame.rsp,
            KtrapFrameData::Arm64(frame) => frame.sp,
        }
    }

    pub fn amd64(&self) -> Option<&Amd64TrapFrame> {
        match &self.data {
            KtrapFrameData::Amd64(frame) => Some(frame),
            KtrapFrameData::Arm64(_) => None,
        }
    }

    pub fn arm64(&self) -> Option<&Arm64TrapFrame> {
        match &self.data {
            KtrapFrameData::Amd64(_) => None,
            KtrapFrameData::Arm64(frame) => Some(frame),
        }
    }
}

impl KtrapFrame {
    /// Decode a frame at `address` out of `buf` (which must cover the whole
    /// struct) using the PDB-described `layout`.
    pub fn decode(layout: &TypeInfo, address: u64, buf: &[u8]) -> Result<Self> {
        let field = |name: &str| field_uint(buf, name, layout.field(name)?);
        if layout.fields.contains_key("Pc") && !layout.fields.contains_key("Rip") {
            return Self::decode_arm64(layout, address, buf);
        }
        let kind = field("ExceptionActive")
            .ok()
            .and_then(TrapKind::from_exception_active);
        let system_call = kind == Some(TrapKind::SystemCall);
        let saved_if = |saved: bool, name: &str| -> Result<Option<u64>> {
            saved.then(|| field(name)).transpose()
        };
        let cs = field("SegCs")? as u16;
        Ok(Self {
            address,
            data: KtrapFrameData::Amd64(Amd64TrapFrame {
                kind,
                rax: field("Rax")?,
                rbx: saved_if(system_call, "Rbx")?,
                rcx: field("Rcx")?,
                rdx: field("Rdx")?,
                rsi: saved_if(system_call, "Rsi")?,
                rdi: saved_if(system_call, "Rdi")?,
                rbp: field("Rbp")?,
                rsp: field("Rsp")?,
                r8: field("R8")?,
                r9: field("R9")?,
                r10: field("R10")?,
                r11: saved_if(!system_call, "R11")?,
                rip: field("Rip")?,
                cs,
                ss: field("SegSs")? as u16,
                eflags: field("EFlags")? as u32,
                error_code: saved_if(!system_call, "ErrorCode")?,
                previous_mode: (cs & 1) as u8,
                previous_irql: saved_if(kind == Some(TrapKind::Interrupt), "PreviousIrql")?
                    .map(|irql| irql as u8),
            }),
        })
    }

    fn decode_arm64(layout: &TypeInfo, address: u64, buf: &[u8]) -> Result<Self> {
        let field = |names: &[&str]| -> Result<u64> {
            let (name, info) = names
                .iter()
                .find_map(|&name| Some((name, layout.fields.get(name)?)))
                .ok_or_else(|| Error::FieldNotFound(names[0].to_string()))?;
            field_uint(buf, name, info)
        };
        let array_field = |name: &str, index: usize, element_size: usize| -> Result<u64> {
            let offset = (layout.field(name)?.offset as usize)
                .checked_add(index.saturating_mul(element_size))
                .ok_or_else(|| Error::FieldNotFound(name.to_string()))?;
            buffer_uint(buf, name, offset, element_size)
        };
        let mut x = [0u64; 19];
        for (index, value) in x.iter_mut().enumerate() {
            *value = array_field("X", index, 8)?;
        }
        let bcr = std::array::from_fn(|index| array_field("Bcr", index, 4).ok());
        let bvr = std::array::from_fn(|index| array_field("Bvr", index, 8).ok());
        let wcr = std::array::from_fn(|index| array_field("Wcr", index, 4).ok());
        let wvr = std::array::from_fn(|index| array_field("Wvr", index, 8).ok());
        let pc = field(&["Pc"])?;
        let sp = field(&["Sp"])?;
        let fp = field(&["Fp"])?;
        let lr = field(&["Lr"])?;
        let cpsr = field(&["Spsr", "Cpsr"]).ok();
        let esr = field(&["Esr"]).ok();
        let fault_address = field(&["FaultAddress", "Far"]).ok();
        let previous_mode = field(&["PreviousMode"]).ok().map(|mode| mode as u8);
        let previous_irql = field(&["PreviousIrql"]).ok().map(|irql| irql as u8);
        Ok(Self {
            address,
            data: KtrapFrameData::Arm64(Box::new(Arm64TrapFrame {
                x,
                lr,
                fp,
                pc,
                sp,
                cpsr,
                esr,
                fault_address,
                bcr,
                bvr,
                wcr,
                wvr,
                previous_mode,
                previous_irql,
            })),
        })
    }
}

/// The little-endian integer `field` occupies in `buf`, read at no more than
/// eight bytes of its PDB width.
fn field_uint(buf: &[u8], name: &str, field: &FieldInfo) -> Result<u64> {
    buffer_uint(
        buf,
        name,
        field.offset as usize,
        (field.size as usize).min(8),
    )
}

/// The little-endian integer at `buf[offset..offset + size]`; an empty or
/// out-of-bounds span means the frame does not hold field `name`.
fn buffer_uint(buf: &[u8], name: &str, offset: usize, size: usize) -> Result<u64> {
    offset
        .checked_add(size)
        .filter(|_| size != 0)
        .and_then(|end| buf.get(offset..end))
        .map(le_uint)
        .ok_or_else(|| Error::FieldNotFound(name.to_string()))
}

impl From<&KtrapFrame> for SavedThreadRegisters {
    fn from(frame: &KtrapFrame) -> Self {
        match &frame.data {
            KtrapFrameData::Amd64(frame) => Self {
                rip: Some(frame.rip),
                rsp: Some(frame.rsp),
                rax: Some(frame.rax),
                rcx: Some(frame.rcx),
                rdx: Some(frame.rdx),
                rbx: frame.rbx,
                rbp: Some(frame.rbp),
                rsi: frame.rsi,
                rdi: frame.rdi,
                r8: Some(frame.r8),
                r9: Some(frame.r9),
                r10: Some(frame.r10),
                r11: frame.r11,
                // These registers live in a KEXCEPTION_FRAME, not KTRAP_FRAME.
                r12: None,
                r13: None,
                r14: None,
                r15: None,
                rflags: Some(u64::from(frame.eflags)),
                arm64: None,
            },
            KtrapFrameData::Arm64(frame) => {
                let mut x = [None; 31];
                for (index, value) in frame.x.iter().copied().enumerate() {
                    x[index] = Some(value);
                }
                x[29] = Some(frame.fp);
                x[30] = Some(frame.lr);
                Self {
                    arm64: Some(Arm64SavedRegisters {
                        x,
                        sp: Some(frame.sp),
                        pc: Some(frame.pc),
                        cpsr: frame.cpsr,
                        fp: Some(frame.fp),
                        lr: Some(frame.lr),
                    }),
                    ..Self::default()
                }
            }
        }
    }
}

fn read_frame_bytes(
    debugger: &Target,
    dtb: Dtb,
    type_name: &str,
    address: VirtAddr,
) -> Result<(Arc<TypeInfo>, Vec<u8>)> {
    let layout = debugger
        .symbols
        .find_type_across_modules(dtb, type_name)
        .ok_or_else(|| Error::StructNotFound(type_name.to_string()))?;
    let mut buf = vec![0u8; layout.size];
    debugger.address_space(dtb).read_bytes(address, &mut buf)?;
    Ok((layout, buf))
}

pub fn decode_ktrap_frame_for_thread(
    debugger: &Target,
    dtb: Dtb,
    addr: VirtAddr,
) -> Result<SavedThreadRegisters> {
    let (layout, buf) = read_frame_bytes(debugger, dtb, KTRAP_FRAME_TYPE, addr)?;
    let frame = KtrapFrame::decode(&layout, addr.0, &buf)?;
    Ok(SavedThreadRegisters::from(&frame))
}

fn decode_kswitch_frame(
    layout: &TypeInfo,
    address: VirtAddr,
    buf: &[u8],
) -> Result<SavedThreadRegisters> {
    let field = |name: &str| -> Result<(u64, u32)> {
        let field = layout.field(name)?;
        Ok((field_uint(buf, name, field)?, field.offset))
    };
    let optional = |name: &str| field(name).ok().map(|(value, _)| value);
    let (rip, return_offset) = field("Return")?;
    let rsp = address
        .0
        .checked_add(u64::from(return_offset))
        .and_then(|value| value.checked_add(8))
        .ok_or_else(|| Error::DebugInfo("KSWITCH_FRAME stack pointer overflow".into()))?;

    Ok(SavedThreadRegisters {
        rip: Some(rip),
        rsp: Some(rsp),
        // Only fields explicitly described by this build's PDB are exposed.
        rbx: optional("Rbx"),
        rbp: optional("Rbp"),
        rsi: optional("Rsi"),
        rdi: optional("Rdi"),
        r12: optional("R12"),
        r13: optional("R13"),
        r14: optional("R14"),
        r15: optional("R15"),
        ..SavedThreadRegisters::default()
    })
}

pub fn decode_kswitch_frame_seed(
    debugger: &Target,
    dtb: Dtb,
    address: VirtAddr,
) -> Result<SavedThreadRegisters> {
    if debugger.arch() == Arch::Arm64 {
        return Err(Error::DebugInfo(
            "ARM64 _KSWITCH_FRAME layout is not verified; use a PDB-described KTRAP_FRAME".into(),
        ));
    }
    let layout = debugger
        .symbols
        .find_type_across_modules(dtb, KSWITCH_FRAME_TYPE)
        .ok_or_else(|| Error::StructNotFound(KSWITCH_FRAME_TYPE.to_string()))?;
    let mut buf = vec![0u8; layout.size];
    debugger.address_space(dtb).read_bytes(address, &mut buf)?;
    decode_kswitch_frame(&layout, address, &buf)
}

/// Read and decode an `_KTRAP_FRAME` at a kernel address. Fails when the
/// type is not in the loaded symbols or the memory is unreadable.
pub fn read_ktrap_frame(debugger: &Target, addr: VirtAddr) -> Result<KtrapFrame> {
    let dtb = debugger.current_dtb();
    let (layout, buf) = read_frame_bytes(debugger, dtb, KTRAP_FRAME_TYPE, addr)?;
    KtrapFrame::decode(&layout, addr.0, &buf)
}

/// The `_KTRAP_FRAME` a Windows trap handler built around the machine frame
/// at `machine_frame`, the hardware-pushed tail a stack walk crossed
/// ([`crate::unwind::StackFrame::machine_frame`]), when its saved `Rip` is
/// `interrupted`, where the walk resumed: a machine frame that ends no trap
/// frame is not misread as one. AMD64 only.
pub fn ktrap_frame_at_machine_frame(
    debugger: &Target,
    machine_frame: u64,
    interrupted: u64,
) -> Option<KtrapFrame> {
    if debugger.arch() != Arch::Amd64 {
        return None;
    }
    let layout = debugger
        .symbols
        .find_type_across_modules(debugger.kernel_dtb(), KTRAP_FRAME_TYPE)?;
    let rip = layout.field("Rip").ok()?.offset;
    let address = machine_frame.checked_sub(u64::from(rip))?;
    let frame = read_ktrap_frame(debugger, VirtAddr(address)).ok()?;
    (frame.instruction_pointer() == interrupted).then_some(frame)
}

/// Read an explicitly addressed trap frame, or the current Windows thread's
/// saved `KTHREAD.TrapFrame` when `addr` is `None`.
pub fn read_ktrap_frame_at_or_current(
    debugger: &Target,
    addr: Option<VirtAddr>,
) -> Result<KtrapFrame> {
    let addr = match addr {
        Some(addr) => addr,
        None => debugger
            .current_thread_pseudo_register("trapframe")
            .map(VirtAddr)
            .ok_or_else(|| {
                Error::DebugInfo(
                    "current thread has no saved trap frame (or no Windows thread context)".into(),
                )
            })?,
    };
    read_ktrap_frame(debugger, addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::{FieldInfo, ParsedType};
    use std::collections::HashMap;

    /// A miniature `_KTRAP_FRAME` layout: enough fields, PDB-shaped, with the
    /// sub-8-byte sizes the real type uses for segments/flags/mode/irql.
    fn test_layout() -> TypeInfo {
        let mut fields = HashMap::new();
        let mut add = |name: &str, offset: u32, size: u64| {
            fields.insert(
                name.to_string(),
                FieldInfo {
                    offset,
                    size,
                    type_data: ParsedType::Primitive("test".into()),
                },
            );
        };
        add("PreviousMode", 0x00, 1);
        add("PreviousIrql", 0x01, 1);
        add("ExceptionActive", 0x02, 1);
        add("Rax", 0x08, 8);
        add("Rcx", 0x10, 8);
        add("Rdx", 0x18, 8);
        add("R8", 0x20, 8);
        add("R9", 0x28, 8);
        add("R10", 0x30, 8);
        add("R11", 0x38, 8);
        add("Rbx", 0x40, 8);
        add("Rdi", 0x48, 8);
        add("Rsi", 0x50, 8);
        add("Rbp", 0x58, 8);
        add("ErrorCode", 0x60, 8);
        add("Rip", 0x68, 8);
        add("SegCs", 0x70, 2);
        add("EFlags", 0x74, 4);
        add("Rsp", 0x78, 8);
        add("SegSs", 0x80, 2);
        TypeInfo {
            name: KTRAP_FRAME_TYPE.to_string(),
            pointer_size: 8,
            size: 0x88,
            fields,
        }
    }

    #[test]
    fn decodes_fields_at_pdb_offsets() {
        let layout = test_layout();
        let mut buf = vec![0u8; layout.size];
        buf[0x02] = 0; // ExceptionActive: an interrupt
        buf[0x01] = 2; // PreviousIrql
        buf[0x08..0x10].copy_from_slice(&0x1111u64.to_le_bytes()); // Rax
        buf[0x60..0x68].copy_from_slice(&0x2u64.to_le_bytes()); // ErrorCode
        buf[0x68..0x70].copy_from_slice(&0xffff_f800_1234_5678u64.to_le_bytes()); // Rip
        buf[0x70..0x72].copy_from_slice(&0x10u16.to_le_bytes()); // SegCs
        buf[0x74..0x78].copy_from_slice(&0x0004_0246u32.to_le_bytes()); // EFlags
        buf[0x78..0x80].copy_from_slice(&0xffff_b001_0000_0000u64.to_le_bytes()); // Rsp
        buf[0x80..0x82].copy_from_slice(&0x18u16.to_le_bytes()); // SegSs

        let frame = KtrapFrame::decode(&layout, 0xffff_b000_dead_0000, &buf).unwrap();
        assert_eq!(frame.address, 0xffff_b000_dead_0000);
        let amd64 = frame.amd64().unwrap();
        assert_eq!(amd64.rax, 0x1111);
        assert_eq!(amd64.rip, 0xffff_f800_1234_5678);
        assert_eq!(amd64.rsp, 0xffff_b001_0000_0000);
        assert_eq!(amd64.cs, 0x10);
        assert_eq!(amd64.ss, 0x18);
        assert_eq!(amd64.eflags, 0x0004_0246);
        assert_eq!(amd64.error_code, Some(2));
        assert_eq!(amd64.previous_irql, Some(2));
    }

    /// Only the entry that built a frame decides what it holds: a register
    /// that entry does not save must read as unknown, not as the stale slot.
    #[test]
    fn a_trap_frame_holds_only_what_its_entry_saved() {
        let layout = test_layout();
        let decode = |exception_active: Option<u8>, cs: u16| {
            let mut layout = layout.clone();
            let mut buf = vec![0u8; layout.size];
            match exception_active {
                Some(value) => buf[0x02] = value,
                None => {
                    layout.fields.remove("ExceptionActive");
                }
            }
            buf[0x00] = 1; // PreviousMode: stale unless a system call wrote it
            buf[0x01] = 0x50; // PreviousIrql
            buf[0x38..0x40].copy_from_slice(&0x1b1bu64.to_le_bytes()); // R11
            buf[0x40..0x48].copy_from_slice(&0xb0b0u64.to_le_bytes()); // Rbx
            buf[0x48..0x50].copy_from_slice(&0xd1d1u64.to_le_bytes()); // Rdi
            buf[0x50..0x58].copy_from_slice(&0x5151u64.to_le_bytes()); // Rsi
            buf[0x70..0x72].copy_from_slice(&cs.to_le_bytes());
            KtrapFrame::decode(&layout, 0, &buf)
                .unwrap()
                .amd64()
                .unwrap()
                .clone()
        };

        let interrupt = decode(Some(0), 0x10);
        assert_eq!(interrupt.kind, Some(TrapKind::Interrupt));
        assert_eq!(
            (interrupt.rbx, interrupt.rsi, interrupt.rdi),
            (None, None, None)
        );
        assert_eq!(interrupt.r11, Some(0x1b1b));
        assert_eq!(interrupt.previous_irql, Some(0x50));
        assert_eq!(interrupt.previous_mode, 0, "from cs, not the stale field");

        let exception = decode(Some(1), 0x10);
        assert_eq!(exception.kind, Some(TrapKind::Exception));
        assert_eq!(
            (exception.rbx, exception.rsi, exception.rdi),
            (None, None, None)
        );
        assert_eq!(exception.r11, Some(0x1b1b));
        assert_eq!(exception.previous_irql, None);

        let system_call = decode(Some(2), 0x33);
        assert_eq!(system_call.kind, Some(TrapKind::SystemCall));
        assert_eq!(
            (system_call.rbx, system_call.rsi, system_call.rdi),
            (Some(0xb0b0), Some(0x5151), Some(0xd1d1))
        );
        assert_eq!(system_call.r11, None, "the slot holds r10");
        assert_eq!(system_call.error_code, None);
        assert_eq!(system_call.previous_irql, None);
        assert_eq!(system_call.previous_mode, 1);

        let unknown = decode(None, 0x10);
        assert_eq!(unknown.kind, None);
        assert_eq!((unknown.rbx, unknown.rsi, unknown.rdi), (None, None, None));
        assert_eq!(unknown.r11, Some(0x1b1b));
        assert_eq!(unknown.previous_irql, None);
    }

    #[test]
    fn decodes_arm64_fields_from_named_arrays() {
        let mut fields = HashMap::new();
        let mut add = |name: &str, offset: u32, size: u64| {
            fields.insert(
                name.to_string(),
                FieldInfo {
                    offset,
                    size,
                    type_data: ParsedType::Primitive("test".into()),
                },
            );
        };
        add("PreviousMode", 0x00, 1);
        add("PreviousIrql", 0x01, 1);
        add("X", 0x08, 19 * 8);
        add("Lr", 0xa0, 8);
        add("Fp", 0xa8, 8);
        add("Pc", 0xb0, 8);
        add("Sp", 0xb8, 8);
        add("Spsr", 0xc0, 4);
        add("Esr", 0xc4, 4);
        add("FaultAddress", 0xc8, 8);
        add("Bcr", 0xd0, 8 * 4);
        add("Bvr", 0xf0, 8 * 8);
        add("Wcr", 0x130, 2 * 4);
        add("Wvr", 0x138, 2 * 8);
        let layout = TypeInfo {
            name: KTRAP_FRAME_TYPE.to_string(),
            pointer_size: 8,
            size: 0x148,
            fields,
        };
        let mut buf = vec![0u8; layout.size];
        buf[0x08..0x10].copy_from_slice(&0x1122u64.to_le_bytes());
        buf[0x08 + 18 * 8..0x10 + 18 * 8].copy_from_slice(&0x3344u64.to_le_bytes());
        buf[0xa0..0xa8].copy_from_slice(&0x5566u64.to_le_bytes());
        buf[0xa8..0xb0].copy_from_slice(&0x7788u64.to_le_bytes());
        buf[0xb0..0xb8].copy_from_slice(&0xffff_0000_0000_1000u64.to_le_bytes());
        buf[0xb8..0xc0].copy_from_slice(&0xffff_0000_1234_5000u64.to_le_bytes());
        buf[0xc0..0xc4].copy_from_slice(&0x6000_03c5u32.to_le_bytes());
        buf[0xc4..0xc8].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        buf[0xc8..0xd0].copy_from_slice(&0x4000u64.to_le_bytes());

        let frame = KtrapFrame::decode(&layout, 0xffff_0000_ffff_0000, &buf).unwrap();
        let arm = frame.arm64().unwrap();
        assert_eq!(arm.x[0], 0x1122);
        assert_eq!(arm.x[18], 0x3344);
        assert_eq!(arm.lr, 0x5566);
        assert_eq!(arm.fp, 0x7788);
        assert_eq!(arm.pc, 0xffff_0000_0000_1000);
        assert_eq!(arm.sp, 0xffff_0000_1234_5000);
        assert_eq!(arm.cpsr, Some(0x6000_03c5));
        assert_eq!(arm.esr, Some(0x1234_5678));
        assert_eq!(arm.fault_address, Some(0x4000));
        assert_eq!(frame.instruction_pointer(), arm.pc);
        assert_eq!(frame.stack_pointer(), arm.sp);

        let registers = SavedThreadRegisters::from(&frame);
        assert_eq!(registers.get("pc"), Some(arm.pc));
        assert_eq!(registers.get("sp"), Some(arm.sp));
        assert_eq!(registers.get("x0"), Some(arm.x[0]));
        assert_eq!(registers.get("x18"), Some(arm.x[18]));
        assert_eq!(registers.get("fp"), Some(arm.fp));
        assert_eq!(registers.get("lr"), Some(arm.lr));
        assert_eq!(registers.get("cpsr"), arm.cpsr);
    }

    #[test]
    fn missing_field_is_an_error_not_a_zero() {
        let mut layout = test_layout();
        layout.fields.remove("Rip");
        let buf = vec![0u8; layout.size];
        assert!(matches!(
            KtrapFrame::decode(&layout, 0, &buf),
            Err(Error::FieldNotFound(name)) if name == "Rip"
        ));
    }

    #[test]
    fn absent_arm64_optional_fields_are_unavailable_not_zero() {
        let mut fields = HashMap::new();
        for (name, offset, size) in [
            ("X", 0x00, 19 * 8),
            ("Lr", 0x98, 8),
            ("Fp", 0xa0, 8),
            ("Pc", 0xa8, 8),
            ("Sp", 0xb0, 8),
            ("Bcr", 0xb8, 8 * 4),
        ] {
            fields.insert(
                name.to_string(),
                FieldInfo {
                    offset,
                    size,
                    type_data: ParsedType::Primitive("test".into()),
                },
            );
        }
        // The frame buffer ends before the last four Bcr slots.
        let layout = TypeInfo {
            name: KTRAP_FRAME_TYPE.to_string(),
            pointer_size: 8,
            size: 0xc8,
            fields,
        };
        let mut buf = vec![0u8; layout.size];
        buf[0xb8..0xbc].copy_from_slice(&0x1e5u32.to_le_bytes());

        let frame = KtrapFrame::decode(&layout, 0, &buf).unwrap();
        let arm = frame.arm64().unwrap();
        assert_eq!(arm.cpsr, None);
        assert_eq!(arm.esr, None);
        assert_eq!(arm.fault_address, None);
        assert_eq!(arm.previous_mode, None);
        assert_eq!(arm.previous_irql, None);
        assert_eq!(arm.bcr[0], Some(0x1e5));
        assert_eq!(arm.bcr[3], Some(0));
        assert_eq!(arm.bcr[4], None);
        assert_eq!(arm.wvr, [None; 2]);
        assert_eq!(SavedThreadRegisters::from(&frame).get("cpsr"), None);
    }

    #[test]
    fn short_buffer_is_an_error() {
        let layout = test_layout();
        let buf = vec![0u8; 0x70];
        assert!(KtrapFrame::decode(&layout, 0, &buf).is_err());
    }

    #[test]
    fn trap_frame_conversion_reports_unsaved_nonvolatile_registers() {
        let layout = test_layout();
        let mut buf = vec![0u8; layout.size];
        buf[0x02] = 2; // ExceptionActive: a system call, which saves rbx
        buf[0x40..0x48].copy_from_slice(&0x44u64.to_le_bytes());
        buf[0x58..0x60].copy_from_slice(&0x55u64.to_le_bytes());
        buf[0x68..0x70].copy_from_slice(&0xffff_f800_0000_1000u64.to_le_bytes());
        buf[0x78..0x80].copy_from_slice(&0xffff_a000_0000_2000u64.to_le_bytes());

        let frame = KtrapFrame::decode(&layout, 0xffff_a000_0000_1800, &buf).unwrap();
        let registers = SavedThreadRegisters::from(&frame);
        assert_eq!(registers.rip, Some(0xffff_f800_0000_1000));
        assert_eq!(registers.rsp, Some(0xffff_a000_0000_2000));
        assert_eq!(registers.rbx, Some(0x44));
        assert_eq!(registers.rbp, Some(0x55));
        assert_eq!(registers.r12, None);
        assert_eq!(registers.r13, None);
        assert_eq!(registers.r14, None);
        assert_eq!(registers.r15, None);
    }

    #[test]
    fn switch_frame_seed_uses_only_pdb_described_fields() {
        let mut fields = HashMap::new();
        fields.insert(
            "Rbp".to_string(),
            FieldInfo {
                offset: 0x30,
                size: 8,
                type_data: ParsedType::Primitive("test".into()),
            },
        );
        fields.insert(
            "Return".to_string(),
            FieldInfo {
                offset: 0x38,
                size: 8,
                type_data: ParsedType::Primitive("test".into()),
            },
        );
        let layout = TypeInfo {
            name: KSWITCH_FRAME_TYPE.to_string(),
            pointer_size: 8,
            size: 0x40,
            fields,
        };
        let mut buf = vec![0u8; layout.size];
        buf[0x30..0x38].copy_from_slice(&0x1234u64.to_le_bytes());
        buf[0x38..0x40].copy_from_slice(&0xffff_f800_0000_3000u64.to_le_bytes());

        let registers =
            decode_kswitch_frame(&layout, VirtAddr(0xffff_a000_0000_1000), &buf).unwrap();
        assert_eq!(registers.rip, Some(0xffff_f800_0000_3000));
        assert_eq!(registers.rsp, Some(0xffff_a000_0000_1040));
        assert_eq!(registers.rbp, Some(0x1234));
        assert_eq!(registers.rbx, None);
        assert_eq!(registers.rax, None);
    }

    #[test]
    fn switch_frame_without_return_is_explicitly_unusable() {
        let layout = TypeInfo {
            name: KSWITCH_FRAME_TYPE.to_string(),
            pointer_size: 8,
            size: 8,
            fields: HashMap::new(),
        };
        assert!(matches!(
            decode_kswitch_frame(&layout, VirtAddr(0x1000), &[0; 8]),
            Err(Error::FieldNotFound(name)) if name == "Return"
        ));
    }
}
