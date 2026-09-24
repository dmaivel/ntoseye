use super::*;

#[test]
fn bitfields_sort_by_position_and_fields_resolve_case_insensitively() {
    assert_eq!(unqualified_type_name("nt!_EPROCESS"), "_EPROCESS");

    // PDB reports both bitfields at offset 0, so only the bit position
    // orders them; `dt` prints the low bit first.
    let low = FieldInfo {
        offset: 0,
        size: 1,
        type_data: ParsedType::Bitfield {
            underlying: Box::new(ParsedType::Primitive("UCHAR".to_string())),
            pos: 7,
            len: 1,
        },
    };
    let high = FieldInfo {
        offset: 0,
        size: 1,
        type_data: ParsedType::Bitfield {
            underlying: Box::new(ParsedType::Primitive("UCHAR".to_string())),
            pos: 0,
            len: 1,
        },
    };
    assert!(field_sort_key(&high) < field_sort_key(&low));

    let mut fields = HashMap::new();
    fields.insert("Value".to_string(), low);
    let info = TypeInfo {
        name: "_NODE".to_string(),
        pointer_size: 8,
        size: 1,
        fields,
    };
    assert_eq!(
        find_field(&info, "value").map(|(name, _)| name.as_str()),
        Some("Value")
    );
}
