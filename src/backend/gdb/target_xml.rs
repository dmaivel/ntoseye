//! The GDB stub's target description (`qXfer:features:read`): the XML that
//! names the stub's architecture and lays out its `g`/`G` register packet.

use crate::arch::{RegisterInfo, RegisterMap};
use crate::base::error::{Error, Result};

/// The `<architecture>` a target description declares, such as
/// `i386:x86-64` or `aarch64`. This is the stub's own statement of what
/// it is, which beats guessing from register names.
pub fn target_architecture(xml: &str) -> Option<&str> {
    let start = xml.find("<architecture>")? + "<architecture>".len();
    let rest = &xml[start..];
    Some(rest[..rest.find("</architecture>")?].trim())
}

/// The register map a target description lays out: each `<reg>` at its
/// regnum's place in the `g` packet, which packs registers in ascending
/// regnum whatever order the XML lists them in.
pub fn parse_target_xml(xml: &str) -> Result<RegisterMap> {
    let mut next_regnum = 0usize;
    let mut registers = Vec::new();

    let xml = strip_xml_comments(xml);

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
        let name = extract_attr(element, "name");
        let bitsize = extract_attr(element, "bitsize");
        let explicit_regnum = extract_attr(element, "regnum");

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
            next_regnum = regnum
                .checked_add(1)
                .ok_or_else(|| Error::Rsp("register regnum overflows in target XML".to_string()))?;
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
    for reg in &mut registers {
        reg.offset = offset;
        offset = offset
            .checked_add(reg.size)
            .ok_or_else(|| Error::Rsp("register offsets overflow in target XML".to_string()))?;
    }
    Ok(RegisterMap::from_registers(registers))
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

/// The value of `attr="..."` in one XML element, unescaped as written.
pub fn extract_attr<'a>(element: &'a str, attr: &str) -> Option<&'a str> {
    let pattern = format!("{}=\"", attr);
    let start = element.find(&pattern)?;
    let value_start = start + pattern.len();
    let rest = &element[value_start..];
    let end = rest.find('"')?;
    Some(&rest[..end])
}

#[cfg(test)]
mod tests {
    use super::{parse_target_xml, target_architecture};
    use crate::base::error::Error;

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

        let map = parse_target_xml(xml).unwrap();
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
        assert!(matches!(parse_target_xml(xml), Err(Error::Rsp(_))));
    }

    #[test]
    fn malformed_explicit_regnum_is_rejected() {
        let xml = r#"<target><feature name="core">
            <reg name="rax" bitsize="64" regnum="not-a-number"/>
        </feature></target>"#;

        assert!(matches!(parse_target_xml(xml), Err(Error::Rsp(_))));
    }

    #[test]
    fn target_register_offsets_reject_overflow() {
        let bitsize = (usize::MAX / 8 * 8).to_string();
        let mut xml = String::from("<target><feature name=\"core\">");
        for index in 0..9 {
            xml.push_str(&format!("<reg name=\"r{index}\" bitsize=\"{bitsize}\"/>"));
        }
        xml.push_str("</feature></target>");

        assert!(matches!(parse_target_xml(&xml), Err(Error::Rsp(_))));
    }

    /// Registers are packed in regnum order, so a register listed first
    /// with a later regnum still lands behind the ones numbered before it,
    /// and one without a regnum takes the number after the one listed
    /// before it.
    #[test]
    fn registers_are_packed_in_regnum_order() {
        let xml = r#"<target><feature name="core">
            <reg name="rip" bitsize="64" regnum="1"/>
            <reg name="eflags" bitsize="32"/>
            <reg name="rax" bitsize="64" regnum="0"/>
        </feature></target>"#;
        let map = parse_target_xml(xml).unwrap();

        let offsets: Vec<_> = map
            .registers()
            .iter()
            .map(|reg| (reg.name.as_str(), reg.offset, reg.regnum))
            .collect();
        assert_eq!(offsets, [("rax", 0, 0), ("rip", 8, 1), ("eflags", 16, 2)]);
    }

    #[test]
    fn reads_the_declared_architecture_from_a_target_description() {
        assert_eq!(
            target_architecture(
                "<target><architecture>aarch64</architecture>\
                 <xi:include href=\"aarch64-core.xml\"/></target>"
            ),
            Some("aarch64")
        );
        assert_eq!(
            target_architecture("<target><architecture>i386:x86-64</architecture></target>"),
            Some("i386:x86-64")
        );
        assert_eq!(target_architecture("<target></target>"), None);
    }
}
