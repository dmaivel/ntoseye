//! The register file and target description the server presents.
//!
//! The wire layout follows the architecture and uses GDB's standard feature
//! and register names, so a client recognizes it without special casing. Each
//! wire register is filled from the session's register map by name. A
//! register gdb requires that the transport does not carry (KD has no x87
//! state, for instance) is reported unavailable instead of as zero; an
//! optional one it does not carry is left out of the layout.

use std::fmt::Write as _;

use crate::error::{Error, Result};
use crate::gdb::registers::RegisterMap;
use crate::types::Arch;

struct WireRegister {
    name: String,
    bytes: usize,
    ty: &'static str,
    feature: &'static str,
    /// Outside the features gdb requires: left out of the description when
    /// the transport does not carry it.
    optional: bool,
}

pub struct Layout {
    registers: Vec<WireRegister>,
    target_xml: String,
}

impl Layout {
    /// The layout for `arch` over a transport whose registers `map` names.
    pub fn new(arch: Arch, map: &RegisterMap) -> Self {
        let (architecture, mut registers) = match arch {
            Arch::Amd64 => ("i386:x86-64", amd64()),
            Arch::Arm64 => ("aarch64", arm64()),
        };
        registers.retain(|register| !register.optional || map.info(&register.name).is_some());
        let target_xml = target_xml(architecture, &registers);
        Self {
            registers,
            target_xml,
        }
    }

    pub fn target_xml(&self) -> &str {
        &self.target_xml
    }

    /// The register file in `g` order. Bytes of a register the transport does
    /// not carry are `None`, which the protocol sends as `xx`.
    pub fn encode(&self, map: &RegisterMap, file: &[u8]) -> Vec<Option<u8>> {
        let mut wire = Vec::new();
        for register in &self.registers {
            encode_into(register, map, file, &mut wire);
        }
        wire
    }

    /// One register by its position in the target description, or `None`
    /// when there is no such register or the transport does not carry it.
    pub fn encode_one(&self, regnum: usize, map: &RegisterMap, file: &[u8]) -> Option<Vec<u8>> {
        let register = self.registers.get(regnum)?;
        let mut wire = Vec::with_capacity(register.bytes);
        encode_into(register, map, file, &mut wire);
        wire.into_iter().collect()
    }

    /// Apply a full `G` payload to the register file. Registers the transport
    /// does not carry are skipped.
    pub fn decode(&self, map: &RegisterMap, file: &mut [u8], wire: &[u8]) -> Result<()> {
        let expected: usize = self.registers.iter().map(|register| register.bytes).sum();
        if wire.len() != expected {
            return Err(Error::InvalidArgument(format!(
                "register payload is {} bytes; the target description has {expected}",
                wire.len()
            )));
        }
        let mut offset = 0;
        for register in &self.registers {
            decode_into(register, map, file, &wire[offset..offset + register.bytes]);
            offset += register.bytes;
        }
        Ok(())
    }

    /// Apply one `P` value. Refused when the transport does not carry the
    /// register, so the client is not told a write it cannot see took effect.
    pub fn decode_one(
        &self,
        regnum: usize,
        map: &RegisterMap,
        file: &mut [u8],
        value: &[u8],
    ) -> Result<()> {
        let register = self
            .registers
            .get(regnum)
            .ok_or_else(|| Error::InvalidArgument(format!("no register number {regnum}")))?;
        if value.len() != register.bytes {
            return Err(Error::InvalidArgument(format!(
                "{} takes {} bytes, not {}",
                register.name,
                register.bytes,
                value.len()
            )));
        }
        if !decode_into(register, map, file, value) {
            return Err(Error::RegisterNotFound(register.name.clone()));
        }
        Ok(())
    }
}

/// The bytes of `register` inside the transport's register file.
fn source_range(
    register: &WireRegister,
    map: &RegisterMap,
    file_len: usize,
) -> Option<(usize, usize)> {
    let info = map.info(&register.name)?;
    let len = info.size.min(register.bytes);
    (info.offset + len <= file_len).then_some((info.offset, len))
}

/// Append `register` to `wire`: its bytes zero-extended to the wire width, or
/// all `None` when the transport does not carry it.
fn encode_into(
    register: &WireRegister,
    map: &RegisterMap,
    file: &[u8],
    wire: &mut Vec<Option<u8>>,
) {
    match source_range(register, map, file.len()) {
        Some((offset, len)) => {
            wire.extend(file[offset..offset + len].iter().copied().map(Some));
            wire.extend(std::iter::repeat_n(Some(0), register.bytes - len));
        }
        None => wire.extend(std::iter::repeat_n(None, register.bytes)),
    }
}

/// Write `value` (the wire width) into the register file, truncated to the
/// transport's width. Returns whether the transport carries the register.
fn decode_into(register: &WireRegister, map: &RegisterMap, file: &mut [u8], value: &[u8]) -> bool {
    match source_range(register, map, file.len()) {
        Some((offset, len)) => {
            file[offset..offset + len].copy_from_slice(&value[..len]);
            true
        }
        None => false,
    }
}

fn target_xml(architecture: &str, registers: &[WireRegister]) -> String {
    let mut xml = format!(
        "<?xml version=\"1.0\"?>\n<!DOCTYPE target SYSTEM \"gdb-target.dtd\">\n\
         <target version=\"1.0\">\n<architecture>{architecture}</architecture>\n"
    );
    let mut open: Option<&str> = None;
    for register in registers {
        if open != Some(register.feature) {
            if open.is_some() {
                xml.push_str("</feature>\n");
            }
            let _ = writeln!(xml, "<feature name=\"{}\">", register.feature);
            open = Some(register.feature);
        }
        let _ = writeln!(
            xml,
            "<reg name=\"{}\" bitsize=\"{}\" type=\"{}\"/>",
            register.name,
            register.bytes * 8,
            register.ty
        );
    }
    if open.is_some() {
        xml.push_str("</feature>\n");
    }
    xml.push_str("</target>\n");
    xml
}

fn push(
    registers: &mut Vec<WireRegister>,
    feature: &'static str,
    ty: &'static str,
    bits: usize,
    names: impl IntoIterator<Item = String>,
) {
    registers.extend(names.into_iter().map(|name| WireRegister {
        name,
        bytes: bits / 8,
        ty,
        feature,
        optional: false,
    }));
}

/// Mark every register added since `from` optional.
fn optional(registers: &mut [WireRegister], from: usize) {
    for register in &mut registers[from..] {
        register.optional = true;
    }
}

fn named<'a>(names: &'a [&'a str]) -> impl Iterator<Item = String> + 'a {
    names.iter().map(|name| name.to_string())
}

/// GDB's `i386:x86-64` core, SSE, and segment-base features, plus the control
/// and debug registers a kernel debugger reads. The names follow QEMU's
/// target description, which is also what ntoseye's own GDB client expects.
/// The segment bases and the system registers are optional: a transport may
/// lack them (KD has no segment bases, QEMU's stub no debug registers), and
/// gdb files them in its `general` group, which clients read on every stop
/// and Ghidra's gdb agent abandons at the first unavailable value.
fn amd64() -> Vec<WireRegister> {
    const CORE: &str = "org.gnu.gdb.i386.core";
    let mut registers = Vec::new();
    push(
        &mut registers,
        CORE,
        "int64",
        64,
        named(&["rax", "rbx", "rcx", "rdx", "rsi", "rdi"]),
    );
    push(&mut registers, CORE, "data_ptr", 64, named(&["rbp", "rsp"]));
    push(
        &mut registers,
        CORE,
        "int64",
        64,
        (8..16).map(|i| format!("r{i}")),
    );
    push(&mut registers, CORE, "code_ptr", 64, named(&["rip"]));
    push(
        &mut registers,
        CORE,
        "int32",
        32,
        named(&["eflags", "cs", "ss", "ds", "es", "fs", "gs"]),
    );
    push(
        &mut registers,
        CORE,
        "i387_ext",
        80,
        (0..8).map(|i| format!("st{i}")),
    );
    push(
        &mut registers,
        CORE,
        "int32",
        32,
        named(&[
            "fctrl", "fstat", "ftag", "fiseg", "fioff", "foseg", "fooff", "fop",
        ]),
    );
    const SSE: &str = "org.gnu.gdb.i386.sse";
    push(
        &mut registers,
        SSE,
        "uint128",
        128,
        (0..16).map(|i| format!("xmm{i}")),
    );
    push(&mut registers, SSE, "int32", 32, named(&["mxcsr"]));
    let first_optional = registers.len();
    push(
        &mut registers,
        "org.gnu.gdb.i386.segments",
        "data_ptr",
        64,
        named(&["fs_base", "gs_base"]),
    );
    push(
        &mut registers,
        "org.ntoseye.x86.system",
        "int64",
        64,
        named(&[
            "k_gs_base",
            "cr0",
            "cr2",
            "cr3",
            "cr4",
            "cr8",
            "efer",
            "dr0",
            "dr1",
            "dr2",
            "dr3",
            "dr6",
            "dr7",
        ]),
    );
    optional(&mut registers, first_optional);
    registers
}

/// GDB's AArch64 core and FP/SIMD features.
fn arm64() -> Vec<WireRegister> {
    const CORE: &str = "org.gnu.gdb.aarch64.core";
    const FPU: &str = "org.gnu.gdb.aarch64.fpu";
    let mut registers = Vec::new();
    push(
        &mut registers,
        CORE,
        "int64",
        64,
        (0..31).map(|i| format!("x{i}")),
    );
    push(&mut registers, CORE, "data_ptr", 64, named(&["sp"]));
    push(&mut registers, CORE, "code_ptr", 64, named(&["pc"]));
    push(&mut registers, CORE, "int32", 32, named(&["cpsr"]));
    push(
        &mut registers,
        FPU,
        "uint128",
        128,
        (0..32).map(|i| format!("v{i}")),
    );
    push(&mut registers, FPU, "int32", 32, named(&["fpsr", "fpcr"]));
    registers
}

#[cfg(test)]
mod tests {
    use super::Layout;
    use crate::kd::context::{REGISTER_BUFFER_SIZE, build_register_map};
    use crate::types::Arch;

    /// Byte offset of a register on the wire: its position in the AMD64
    /// description (rax..r15, rip, eflags, six segments, eight x87 stack
    /// registers, eight x87 control registers, sixteen xmm, mxcsr, ...).
    fn wire_offset(name: &str) -> usize {
        let widths: &[(&str, usize)] = &[
            ("rax", 8),
            ("rbx", 8),
            ("rcx", 8),
            ("rdx", 8),
            ("rsi", 8),
            ("rdi", 8),
            ("rbp", 8),
            ("rsp", 8),
            ("r8", 8),
            ("r9", 8),
            ("r10", 8),
            ("r11", 8),
            ("r12", 8),
            ("r13", 8),
            ("r14", 8),
            ("r15", 8),
            ("rip", 8),
            ("eflags", 4),
            ("cs", 4),
            ("ss", 4),
            ("ds", 4),
            ("es", 4),
            ("fs", 4),
            ("gs", 4),
        ];
        let mut offset = 0;
        for (register, width) in widths {
            if *register == name {
                return offset;
            }
            offset += width;
        }
        panic!("{name} is not in the core feature prefix");
    }

    /// KD carries no x87 state and 2-byte selectors. The wire must still put
    /// every register at gdb's fixed offset, widen the selectors, and mark the
    /// x87 registers unavailable rather than zero, or a client reads garbage
    /// into every register after the first mismatch.
    #[test]
    fn kd_register_file_encodes_at_gdb_offsets() {
        let map = build_register_map();
        let mut file = vec![0u8; REGISTER_BUFFER_SIZE];
        map.write_u64("rip", &mut file, 0xffff_f800_1234_5678)
            .unwrap();
        map.write_u64("cs", &mut file, 0x10).unwrap();
        map.write_u64("xmm0l", &mut file, 0x1122_3344_5566_7788)
            .unwrap();

        let layout = Layout::new(Arch::Amd64, &map);
        let wire = layout.encode(&map, &file);

        let rip = wire_offset("rip");
        let rip_bytes: Vec<u8> = wire[rip..rip + 8].iter().map(|b| b.unwrap()).collect();
        assert_eq!(
            u64::from_le_bytes(rip_bytes.try_into().unwrap()),
            0xffff_f800_1234_5678
        );

        let cs = wire_offset("cs");
        assert_eq!(&wire[cs..cs + 4], &[Some(0x10), Some(0), Some(0), Some(0)]);

        let st0 = wire_offset("gs") + 4;
        assert!(
            wire[st0..st0 + 10].iter().all(Option::is_none),
            "st0 is unavailable over KD"
        );

        // Eight 10-byte x87 stack registers and eight 4-byte control registers.
        let xmm0 = st0 + 8 * 10 + 8 * 4;
        assert_eq!(wire[xmm0], Some(0x88));
    }

    /// A `G` write must land in the transport's register file at the transport's
    /// offsets and widths, skipping what the transport lacks.
    #[test]
    fn register_payload_round_trips_through_the_kd_file() {
        let map = build_register_map();
        let mut file = vec![0u8; REGISTER_BUFFER_SIZE];
        map.write_u64("rsp", &mut file, 0xffff_8000_0000_1000)
            .unwrap();
        let layout = Layout::new(Arch::Amd64, &map);

        let mut wire: Vec<u8> = layout
            .encode(&map, &file)
            .into_iter()
            .map(|byte| byte.unwrap_or(0xAA))
            .collect();
        let rip = wire_offset("rip");
        wire[rip..rip + 8].copy_from_slice(&0xffff_f800_0000_4000u64.to_le_bytes());
        layout.decode(&map, &mut file, &wire).unwrap();

        assert_eq!(map.read_u64("rip", &file).unwrap(), 0xffff_f800_0000_4000);
        assert_eq!(map.read_u64("rsp", &file).unwrap(), 0xffff_8000_0000_1000);
        assert!(layout.decode(&map, &mut file, &wire[1..]).is_err());
    }

    /// gdb files the segment bases and system registers under `general`, which
    /// clients read on every stop; Ghidra's gdb agent gives up at the first
    /// unavailable one. So an optional register the transport lacks (KD has no
    /// segment bases) must not be described at all, while a required one (x87)
    /// stays and reads as unavailable.
    #[test]
    fn optional_registers_the_transport_lacks_are_not_described() {
        let map = build_register_map();
        let xml = Layout::new(Arch::Amd64, &map).target_xml().to_string();
        for absent in ["\"fs_base\"", "\"gs_base\"", "\"k_gs_base\""] {
            assert!(!xml.contains(absent), "{absent} described");
        }
        for present in ["\"dr7\"", "\"cr3\"", "\"st0\"", "\"rip\""] {
            assert!(xml.contains(present), "{present} missing");
        }
    }
}
