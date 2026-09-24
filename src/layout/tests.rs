use super::*;

fn bit(pos: u8) -> FieldInfo {
    FieldInfo {
        offset: 0,
        size: 1,
        type_data: ParsedType::Bitfield {
            underlying: Box::new(ParsedType::Primitive("UCHAR".to_string())),
            pos,
            len: 1,
        },
    }
}

#[test]
fn bitfields_sort_by_position_and_fields_resolve_case_insensitively() {
    assert_eq!(unqualified_type_name("nt!_EPROCESS"), "_EPROCESS");

    // PDB reports both bitfields at offset 0, so only the bit position
    // orders them; `dt` prints the low bit first even when its name sorts
    // last.
    let info = TypeInfo {
        name: "_NODE".to_string(),
        pointer_size: 8,
        size: 1,
        fields: [("Alpha".to_string(), bit(7)), ("Zeta".to_string(), bit(0))]
            .into_iter()
            .collect(),
    };
    let order: Vec<_> = info
        .fields_in_order()
        .into_iter()
        .map(|(name, _)| name.as_str())
        .collect();
    assert_eq!(order, ["Zeta", "Alpha"]);

    assert_eq!(
        find_field(&info, "alpha").map(|(name, _)| name.as_str()),
        Some("Alpha")
    );
}

#[test]
fn bitfield_extraction_covers_the_whole_word() {
    let raw = 0x8000_0000_0000_0005;
    assert_eq!(bitfield_value(raw, 0, 3), 0b101);
    assert_eq!(bitfield_value(raw, 63, 1), 1);
    assert_eq!(bitfield_value(raw, 0, 64), raw);
    assert_eq!(bitfield_value(raw, 0, 0), 0);
    assert_eq!(bitfield_value(raw, 64, 1), 0);
}

#[test]
fn wide_text_pairs_surrogates_and_stops_at_nul_only_when_terminated() {
    // "a", U+1F600 as a surrogate pair, NUL, "b".
    let bytes: Vec<u8> = [0x61u16, 0xd83d, 0xde00, 0, 0x62]
        .into_iter()
        .flat_map(u16::to_le_bytes)
        .collect();
    assert_eq!(utf16le_nul_terminated(&bytes), "a\u{1f600}");
    assert_eq!(utf16le_lossy(&bytes), "a\u{1f600}\0b");
}
