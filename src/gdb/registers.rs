use std::collections::HashMap;
use std::result;

use crate::error::{Error, Result};

/// ARM64 names the rest of the debugger reads, each paired with the
/// architectural register it aliases. Shared code spells the program
/// counter and stack pointer the x64 way; `fp`, `lr` and `pstate` are the
/// ABI names users type.
const ARM64_ALIASES: [(&str, &str); 5] = [
    ("rip", "pc"),
    ("rsp", "sp"),
    ("fp", "x29"),
    ("lr", "x30"),
    ("pstate", "cpsr"),
];

/// Append every ARM64 alias to `registers`, each reading the same bytes as
/// the register it names. Fails with the architectural name `registers`
/// does not carry.
pub fn push_arm64_aliases(registers: &mut Vec<RegisterInfo>) -> result::Result<(), &'static str> {
    for (alias, canonical) in ARM64_ALIASES {
        let register = registers
            .iter()
            .find(|reg| reg.name == canonical)
            .ok_or(canonical)?
            .clone();
        registers.push(RegisterInfo {
            name: alias.to_string(),
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
    /// Position in the stub's `g`/`G` packet, which is ordered by regnum,
    /// not by where the target XML happens to list the register.
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
    /// [`read_u64`]. This is used for the AMD64 XMM/FltSave and ARM64 V
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

    /// The `<architecture>` a target description declares, such as
    /// `i386:x86-64` or `aarch64`. This is the stub's own statement of what
    /// it is, which beats guessing from register names.
    pub fn target_architecture(xml: &str) -> Option<&str> {
        let start = xml.find("<architecture>")? + "<architecture>".len();
        let rest = &xml[start..];
        Some(rest[..rest.find("</architecture>")?].trim())
    }

    pub fn parse_target_xml(xml: &str) -> Result<Self> {
        let mut map = RegisterMap::default();
        let mut next_regnum = 0usize;
        let mut registers = Vec::new();

        let xml = Self::strip_xml_comments(xml);

        let mut cursor = 0;
        while let Some(start_offset) = xml[cursor..].find("<reg") {
            let start = cursor + start_offset;
            let rest = &xml[start + 4..];
            if !matches!(rest.as_bytes().first(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
                cursor = start + 4;
                continue;
            }

            let Some(end_offset) = xml[start..].find('>') else {
                break;
            };

            let end = start + end_offset + 1;
            let element = &xml[start..end];
            let name = Self::extract_attr(element, "name");
            let bitsize = Self::extract_attr(element, "bitsize");
            let explicit_regnum = Self::extract_attr(element, "regnum");

            let explicit_regnum = explicit_regnum
                .map(|value| {
                    value.parse::<usize>().map_err(|_| {
                        Error::Rsp(format!("invalid register regnum '{value}' in target XML"))
                    })
                })
                .transpose()?;
            let size_bits = bitsize
                .map(|value| {
                    let size = value.parse::<usize>().map_err(|_| {
                        Error::Rsp(format!("invalid register bitsize '{value}' in target XML"))
                    })?;
                    if size == 0 || size % 8 != 0 {
                        return Err(Error::Rsp(format!(
                            "invalid register bitsize '{value}' in target XML"
                        )));
                    }
                    Ok(size)
                })
                .transpose()?;

            if let Some(name) = name {
                let size_bits = size_bits.ok_or_else(|| {
                    Error::Rsp(format!("register '{name}' has no bitsize in target XML"))
                })?;
                let size_bytes = size_bits / 8;
                let regnum = explicit_regnum.unwrap_or(next_regnum);
                next_regnum = regnum.checked_add(1).ok_or_else(|| {
                    Error::Rsp("register regnum overflows in target XML".to_string())
                })?;
                registers.push(RegisterInfo {
                    name: name.to_string(),
                    offset: 0,
                    size: size_bytes,
                    regnum,
                });
            }

            cursor = end;
        }

        // The g packet packs registers in ascending regnum; the XML may list
        // them in any order (and skip numbers).
        registers.sort_by_key(|reg| reg.regnum);
        let mut offset = 0usize;
        for mut reg in registers {
            reg.offset = offset;
            offset = offset
                .checked_add(reg.size)
                .ok_or_else(|| Error::Rsp("register offsets overflow in target XML".to_string()))?;
            map.by_name.insert(reg.name.clone(), reg.clone());
            map.ordered.push(reg);
        }
        map.add_vector_halves();
        Ok(map)
    }

    fn strip_xml_comments(xml: &str) -> String {
        let mut result = xml.to_string();
        while let Some(start) = result.find("<!--") {
            if let Some(end_offset) = result[start..].find("-->") {
                let end = start + end_offset + 3; // +3 for "-->"
                result = format!("{}{}", &result[..start], &result[end..]);
            } else {
                break;
            }
        }
        result
    }

    pub fn extract_attr<'a>(element: &'a str, attr: &str) -> Option<&'a str> {
        let pattern = format!("{}=\"", attr);
        let start = element.find(&pattern)?;
        let value_start = start + pattern.len();
        let rest = &element[value_start..];
        let end = rest.find('"')?;
        Some(&rest[..end])
    }
}

#[cfg(test)]
mod tests {
    use super::RegisterMap;
    use crate::error::Error;

    #[test]
    fn parses_target_xml_without_line_based_reg_tags() {
        let xml = r#"
            <target>
              <feature name="org.gnu.gdb.i386.core">
                <reg
                    name="rax"
                    bitsize="64"
                    regnum="0"/>
                <reg name="rip" bitsize="64"/>
              </feature>
            </target>
        "#;

        let map = RegisterMap::parse_target_xml(xml).unwrap();
        let regs = map.to_hashmap(&[1u8; 16]);

        assert_eq!(
            map.read_u64("rax", &[1u8; 16]).unwrap(),
            0x0101_0101_0101_0101
        );
        assert_eq!(regs.get("rip"), Some(&0x0101_0101_0101_0101));
    }

    #[test]
    fn malformed_bitsize_is_rejected() {
        let xml = r#"<target><feature name="core">
            <reg name="broken" bitsize="not-a-width"/>
            <reg name="rax" bitsize="8"/>
        </feature></target>"#;
        assert!(matches!(
            RegisterMap::parse_target_xml(xml),
            Err(Error::Rsp(_))
        ));
    }

    #[test]
    fn malformed_explicit_regnum_is_rejected() {
        let xml = r#"<target><feature name="core">
            <reg name="rax" bitsize="64" regnum="not-a-number"/>
        </feature></target>"#;

        assert!(matches!(
            RegisterMap::parse_target_xml(xml),
            Err(Error::Rsp(_))
        ));
    }

    #[test]
    fn target_register_offsets_reject_overflow() {
        let bitsize = (usize::MAX / 8 * 8).to_string();
        let mut xml = String::from("<target><feature name=\"core\">");
        for index in 0..9 {
            xml.push_str(&format!("<reg name=\"r{index}\" bitsize=\"{bitsize}\"/>"));
        }
        xml.push_str("</feature></target>");

        assert!(matches!(
            RegisterMap::parse_target_xml(&xml),
            Err(Error::Rsp(_))
        ));
    }

    #[test]
    fn writes_general_instruction_and_flags_registers_without_spilling() {
        let xml = r#"
            <target><feature name="core">
              <reg name="rax" bitsize="64"/>
              <reg name="rip" bitsize="64"/>
              <reg name="eflags" bitsize="32"/>
              <reg name="cs" bitsize="16"/>
            </feature></target>
        "#;
        let map = RegisterMap::parse_target_xml(xml).unwrap();
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
    fn reads_the_declared_architecture_from_a_target_description() {
        assert_eq!(
            RegisterMap::target_architecture(
                "<target><architecture>aarch64</architecture>\
                 <xi:include href=\"aarch64-core.xml\"/></target>"
            ),
            Some("aarch64")
        );
        assert_eq!(
            RegisterMap::target_architecture(
                "<target><architecture>i386:x86-64</architecture></target>"
            ),
            Some("i386:x86-64")
        );
        assert_eq!(RegisterMap::target_architecture("<target></target>"), None);
    }

    #[test]
    fn reads_128_bit_registers_without_truncation() {
        let xml = r#"<target><feature name="core">
            <reg name="xmm0" bitsize="128"/>
        </feature></target>"#;
        let map = RegisterMap::parse_target_xml(xml).unwrap();
        let value = 0x0011_2233_4455_6677_8899_aabb_ccdd_eeffu128;
        assert_eq!(map.read_u128("xmm0", &value.to_le_bytes()).unwrap(), value);
    }

    #[test]
    fn read_u128_rejects_a_256_bit_register() {
        let xml = r#"<target><feature name="core">
            <reg name="ymm0" bitsize="256"/>
        </feature></target>"#;
        let map = RegisterMap::parse_target_xml(xml).unwrap();

        assert!(matches!(
            map.read_u128("ymm0", &[0x5a; 32]),
            Err(Error::RegisterTooWide(name)) if name == "ymm0"
        ));
    }

    /// A 128-bit register never reaches the 64-bit views truncated: they see
    /// its halves, and the whole is only available at full width.
    #[test]
    fn vector_registers_split_into_halves_for_scalar_views() {
        let xml = r#"<target><feature name="core">
            <reg name="x0" bitsize="64"/>
            <reg name="v0" bitsize="128"/>
        </feature></target>"#;
        let map = RegisterMap::parse_target_xml(xml).unwrap();
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
