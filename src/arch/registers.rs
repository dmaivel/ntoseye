//! Register files as byte buffers: the layout every transport describes its
//! `read_registers` buffer with, and the second names an architecture's
//! registers answer to ([`Architecture::register_synonyms`]).
//!
//! [`Architecture::register_synonyms`]: super::Architecture::register_synonyms

use std::collections::HashMap;
use std::result;

use super::Arch;
use crate::base::error::{Error, Result};

/// Give every pair of `synonyms` both its names in `registers`: the name it
/// lacks reads the same bytes as the one it carries. Fails with the shown
/// name of a pair it carries neither name of.
pub fn push_synonyms(
    registers: &mut Vec<RegisterInfo>,
    synonyms: &[(&'static str, &'static str)],
) -> result::Result<(), &'static str> {
    for &(shown, other) in synonyms {
        let carried = |name: &str| registers.iter().find(|reg| reg.name == name).cloned();
        let (register, missing) = match (carried(shown), carried(other)) {
            (Some(_), Some(_)) => continue,
            (Some(register), None) => (register, other),
            (None, Some(register)) => (register, shown),
            (None, None) => return Err(shown),
        };
        registers.push(RegisterInfo {
            name: missing.to_string(),
            ..register
        });
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct RegisterInfo {
    pub name: String,
    pub offset: usize,
    pub size: usize,
    /// The transport's number for the register. A GDB stub orders its
    /// `g`/`G` packet by it, not by where its target XML happens to list
    /// the register.
    pub regnum: usize,
}

#[derive(Debug, Default, Clone)]
pub struct RegisterMap {
    by_name: HashMap<String, RegisterInfo>,
    ordered: Vec<RegisterInfo>,
}

impl RegisterMap {
    /// Construct a `RegisterMap` from an explicit list of registers. Each
    /// register's `offset`/`size` is interpreted as an index into whatever
    /// byte buffer the backend hands back from `read_registers`. Used by
    /// backends (like KD) that build their register layout from a fixed
    /// struct rather than parsing a target description.
    pub fn from_registers(registers: Vec<RegisterInfo>) -> Self {
        let mut map = RegisterMap::default();
        for reg in registers {
            map.by_name.insert(reg.name.clone(), reg.clone());
            map.ordered.push(reg);
        }
        map.add_vector_halves();
        map
    }

    /// A map of `(name, offset, size)` fields, numbered in order: a
    /// structure's layout.
    pub fn from_layout<N: Into<String>>(
        fields: impl IntoIterator<Item = (N, usize, usize)>,
    ) -> Self {
        Self::from_registers(
            fields
                .into_iter()
                .enumerate()
                .map(|(regnum, (name, offset, size))| RegisterInfo {
                    name: name.into(),
                    offset,
                    size,
                    regnum,
                })
                .collect(),
        )
    }

    /// Bytes from the layout's start to the end of its last register.
    pub fn extent(&self) -> usize {
        self.ordered
            .iter()
            .map(|register| register.offset + register.size)
            .max()
            .unwrap_or(0)
    }

    /// Copy into `data`, laid out as this map, the registers `source_data`,
    /// laid out as `source`, holds, matching them by name. A register past
    /// the end of `data`, or missing from `source` or past the end of
    /// `source_data`, keeps its bytes; a narrower source value is
    /// zero-extended.
    pub fn copy_from(&self, data: &mut [u8], source: &RegisterMap, source_data: &[u8]) {
        for register in &self.ordered {
            let end = register.offset + register.size;
            if end > data.len() {
                continue;
            }
            if let Ok(value) = source.read_u128(&register.name, source_data) {
                data[register.offset..end].copy_from_slice(&value.to_le_bytes()[..register.size]);
            }
        }
    }

    /// Name each 128-bit register's 64-bit halves `{name}l` / `{name}h`
    /// (as KD's AMD64 map spells `xmm0l`/`xmm0h`), unless the map already
    /// defines them. They are lookups into the same bytes, not wire registers.
    fn add_vector_halves(&mut self) {
        let vectors: Vec<RegisterInfo> = self
            .ordered
            .iter()
            .filter(|reg| reg.size == 16)
            .cloned()
            .collect();
        for reg in vectors {
            for (suffix, offset) in [("l", reg.offset), ("h", reg.offset + 8)] {
                let name = format!("{}{suffix}", reg.name);
                self.by_name.entry(name.clone()).or_insert(RegisterInfo {
                    name,
                    offset,
                    size: 8,
                    regnum: reg.regnum,
                });
            }
        }
    }

    /// The register `name`, if it fits the 64-bit accessors.
    fn scalar(&self, name: &str) -> Result<&RegisterInfo> {
        let info = self
            .by_name
            .get(name)
            .ok_or_else(|| Error::RegisterNotFound(name.to_string()))?;
        if info.size > 8 {
            return Err(Error::RegisterTooWide(name.to_string()));
        }
        Ok(info)
    }

    pub fn read_u64<S>(&self, name: S, data: &[u8]) -> Result<u64>
    where
        S: Into<String> + AsRef<str>,
    {
        let info = self.scalar(name.as_ref())?;
        if info.offset + info.size > data.len() {
            return Err(Error::BufferNotEnough);
        }
        let slice = &data[info.offset..info.offset + info.size];

        let mut buf = [0u8; 8];
        let copy_len = slice.len().min(8);
        buf[..copy_len].copy_from_slice(&slice[..copy_len]);
        Ok(u64::from_le_bytes(buf))
    }

    /// Read a register whose wire representation is at most 128 bits.
    /// Smaller registers are zero-extended in the same little-endian order as
    /// [`Self::read_u64`]. This is used for the AMD64 XMM/FltSave and ARM64 V
    /// registers exposed by KD's CONTEXT packet.
    pub fn read_u128<S>(&self, name: S, data: &[u8]) -> Result<u128>
    where
        S: Into<String> + AsRef<str>,
    {
        let info = self
            .by_name
            .get(name.as_ref())
            .ok_or(Error::RegisterNotFound(name.into()))?;
        if info.size > 16 {
            return Err(Error::RegisterTooWide(info.name.clone()));
        }
        if info.offset + info.size > data.len() {
            return Err(Error::BufferNotEnough);
        }
        let slice = &data[info.offset..info.offset + info.size];

        let mut buf = [0u8; 16];
        buf[..slice.len()].copy_from_slice(slice);
        Ok(u128::from_le_bytes(buf))
    }

    pub fn write_u64<S>(&self, name: S, data: &mut [u8], value: u64) -> Result<()>
    where
        S: Into<String> + AsRef<str>,
    {
        let info = self.scalar(name.as_ref())?;
        if info.offset + info.size > data.len() {
            return Err(Error::BufferNotEnough);
        }
        let bytes = value.to_le_bytes();
        let copy_len = info.size.min(bytes.len());
        data[info.offset..info.offset + copy_len].copy_from_slice(&bytes[..copy_len]);
        Ok(())
    }

    /// Every register that fits 64 bits, by name. A 128-bit register appears
    /// as its `{name}l` / `{name}h` halves, never as a truncated whole; see
    /// [`wide_values`](Self::wide_values) for full-width values.
    pub fn to_hashmap(&self, data: &[u8]) -> HashMap<String, u64> {
        let mut values = HashMap::with_capacity(self.ordered.len());
        let mut insert = |name: String, offset: usize, size: usize| {
            if let Some(bytes) = data.get(offset..offset + size) {
                let mut buf = [0u8; 8];
                buf[..size].copy_from_slice(bytes);
                values.insert(name, u64::from_le_bytes(buf));
            }
        };
        for reg in &self.ordered {
            match reg.size {
                0..=8 => insert(reg.name.clone(), reg.offset, reg.size),
                16 => {
                    insert(format!("{}l", reg.name), reg.offset, 8);
                    insert(format!("{}h", reg.name), reg.offset + 8, 8);
                }
                _ => {}
            }
        }
        values
    }

    /// Registers wider than 64 bits and at most 128, at full width, in wire
    /// order (AMD64 `xmmN`, ARM64 `vN`).
    pub fn wide_values(&self, data: &[u8]) -> Vec<(String, u128)> {
        self.ordered
            .iter()
            .filter(|reg| (9..=16).contains(&reg.size))
            .filter_map(|reg| Some((reg.name.clone(), self.read_u128(&reg.name, data).ok()?)))
            .collect()
    }

    /// A sparse register context (`.cxr`, `.trap`, a saved VTL state) named
    /// the way [`Self::to_hashmap`] names it, so an alias also yields the
    /// register it aliases (ARM64 `fp` gives `x29`). Only registers whose
    /// every byte `values` supplies are kept: a register the context lacks
    /// stays unknown instead of reading zero. Names the map does not carry
    /// are dropped.
    pub fn supplied_values(&self, values: &HashMap<String, u64>) -> HashMap<String, u64> {
        let size = self
            .by_name
            .values()
            .map(|reg| reg.offset + reg.size)
            .max()
            .unwrap_or(0);
        let mut data = vec![0u8; size];
        let mut supplied = vec![false; size];
        for (name, value) in values {
            let Ok(info) = self.scalar(name) else {
                continue;
            };
            let range = info.offset..info.offset + info.size;
            if self.write_u64(name.as_str(), &mut data, *value).is_ok() {
                supplied[range].fill(true);
            }
        }
        self.to_hashmap(&data)
            .into_iter()
            .filter(|(name, _)| {
                self.by_name.get(name).is_some_and(|reg| {
                    reg.size > 0
                        && supplied[reg.offset..reg.offset + reg.size]
                            .iter()
                            .all(|b| *b)
                })
            })
            .collect()
    }

    pub fn names(&self) -> Vec<String> {
        self.ordered.iter().map(|reg| reg.name.clone()).collect()
    }

    /// Every register in wire order.
    pub fn registers(&self) -> &[RegisterInfo] {
        &self.ordered
    }

    /// Whether the target description carries this register. Callers use it
    /// to tell "the transport exposes no such state" from "the register read
    /// zero".
    pub fn contains(&self, name: &str) -> bool {
        self.by_name.contains_key(name)
    }

    /// Where `name` lives in the register file, if the transport carries it.
    pub fn info(&self, name: &str) -> Option<&RegisterInfo> {
        self.by_name.get(name)
    }
}

/// One processor's registers: its architecture's register buffer, the
/// `CONTEXT` record then the synthetic slots behind it.
#[derive(Debug, Clone)]
pub struct RegisterFile {
    arch: Arch,
    bytes: Vec<u8>,
}

impl RegisterFile {
    /// The registers a raw `CONTEXT` record holds.
    pub fn from_context(arch: Arch, record: &[u8]) -> Self {
        Self {
            arch,
            bytes: arch.register_buffer(record),
        }
    }

    /// A processor with no registers recorded: every one reads zero.
    pub fn empty(arch: Arch) -> Self {
        Self::from_context(arch, &[])
    }

    pub fn arch(&self) -> Arch {
        self.arch
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The register `name`, when the architecture has one.
    pub fn read(&self, name: &str) -> Option<u64> {
        self.arch.register_map().read_u64(name, &self.bytes).ok()
    }

    pub fn instruction_pointer(&self) -> u64 {
        self.read(self.arch.pc_register()).unwrap_or(0)
    }

    pub fn stack_pointer(&self) -> u64 {
        self.read(self.arch.sp_register()).unwrap_or(0)
    }

    /// The buffer with the kernel page-table root set to `dtb`, as a
    /// backend serves it.
    pub fn with_kernel_dtb(&self, dtb: u64) -> Vec<u8> {
        let mut bytes = self.bytes.clone();
        self.arch
            .register_map()
            .write_u64(self.arch.kernel_dtb_register(), &mut bytes, dtb)
            .expect("every register buffer has a kernel page-table root slot");
        bytes
    }
}

/// Whether `name` is `prefix` followed by a number: `xmm3` for `xmm`.
pub fn numbered(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix)
        .and_then(|rest| rest.chars().next())
        .is_some_and(|ch| ch.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::{RegisterInfo, RegisterMap};
    use crate::base::error::Error;

    /// A map of `(name, size)` registers packed back to back, as a
    /// transport lays out its register buffer.
    fn packed(registers: &[(&str, usize)]) -> RegisterMap {
        let mut offset = 0;
        RegisterMap::from_registers(
            registers
                .iter()
                .enumerate()
                .map(|(regnum, (name, size))| {
                    let reg = RegisterInfo {
                        name: name.to_string(),
                        offset,
                        size: *size,
                        regnum,
                    };
                    offset += size;
                    reg
                })
                .collect(),
        )
    }

    #[test]
    fn writes_general_instruction_and_flags_registers_without_spilling() {
        let map = packed(&[("rax", 8), ("rip", 8), ("eflags", 4), ("cs", 2)]);
        let mut regs = vec![0xa5; 22];

        map.write_u64("rax", &mut regs, 1).unwrap();
        map.write_u64("rip", &mut regs, 0xffff_f800_1234_5678)
            .unwrap();
        map.write_u64("eflags", &mut regs, 0x202).unwrap();

        assert_eq!(map.read_u64("rax", &regs).unwrap(), 1);
        assert_eq!(map.read_u64("rip", &regs).unwrap(), 0xffff_f800_1234_5678);
        assert_eq!(map.read_u64("eflags", &regs).unwrap(), 0x202);
        assert_eq!(&regs[20..22], &[0xa5, 0xa5]);
        assert!(matches!(
            map.write_u64("readonly_or_unknown", &mut regs, 0),
            Err(Error::RegisterNotFound(name)) if name == "readonly_or_unknown"
        ));
    }

    #[test]
    fn reads_128_bit_registers_without_truncation() {
        let map = packed(&[("xmm0", 16)]);
        let value = 0x0011_2233_4455_6677_8899_aabb_ccdd_eeffu128;
        assert_eq!(map.read_u128("xmm0", &value.to_le_bytes()).unwrap(), value);
    }

    #[test]
    fn read_u128_rejects_a_256_bit_register() {
        let map = packed(&[("ymm0", 32)]);

        assert!(matches!(
            map.read_u128("ymm0", &[0x5a; 32]),
            Err(Error::RegisterTooWide(name)) if name == "ymm0"
        ));
    }

    /// A 128-bit register never reaches the 64-bit views truncated: they see
    /// its halves, and the whole is only available at full width.
    #[test]
    fn vector_registers_split_into_halves_for_scalar_views() {
        let map = packed(&[("x0", 8), ("v0", 16)]);
        let v0 = 0x0011_2233_4455_6677_8899_aabb_ccdd_eeffu128;
        let mut regs = 7u64.to_le_bytes().to_vec();
        regs.extend_from_slice(&v0.to_le_bytes());

        let scalars = map.to_hashmap(&regs);
        assert_eq!(scalars.get("x0"), Some(&7));
        assert_eq!(scalars.get("v0l"), Some(&0x8899_aabb_ccdd_eeff));
        assert_eq!(scalars.get("v0h"), Some(&0x0011_2233_4455_6677));
        assert!(!scalars.contains_key("v0"));
        assert_eq!(map.wide_values(&regs), [("v0".to_string(), v0)]);
        assert!(matches!(
            map.read_u64("v0", &regs),
            Err(Error::RegisterTooWide(name)) if name == "v0"
        ));

        map.write_u64("v0h", &mut regs, 0xdead_beef).unwrap();
        assert_eq!(
            map.read_u128("v0", &regs).unwrap(),
            (0xdead_beef << 64) | 0x8899_aabb_ccdd_eeff
        );
        assert!(matches!(
            map.write_u64("v0", &mut regs, 0),
            Err(Error::RegisterTooWide(_))
        ));
    }
}
