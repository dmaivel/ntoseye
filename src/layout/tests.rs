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

#[test]
fn unnamed_aggregates_are_keyed_by_field_list_and_shown_by_pdb_name() {
    // A named type keeps its name, `#` and all; only an unnamed one with
    // its own field list (not a forward reference) gets the index.
    assert_eq!(aggregate_key("_IRP", Some(0x1124)), "_IRP");
    assert_eq!(aggregate_key("_A#B", Some(0x1124)), "_A#B");
    assert_eq!(
        aggregate_key("<unnamed-tag>", Some(0x1124)),
        "<unnamed-tag>#1124"
    );
    assert_eq!(aggregate_key("<unnamed-tag>", None), "<unnamed-tag>");

    // Shown without the index or the module that scopes the lookup, for
    // the kernel's keys and a 32-bit module's alike.
    for key in [
        "<unnamed-tag>#1124",
        "nt!<unnamed-tag>#1124",
        "ntdll32!<unnamed-tag>#1a2",
    ] {
        assert_eq!(aggregate_display_name(key), "<unnamed-tag>");
    }
    assert_eq!(aggregate_display_name("_A#B"), "_A#B");
    assert_eq!(aggregate_display_name("ntdll32!_PEB"), "ntdll32!_PEB");
}

/// `dx` writes the C names WinDbg does, verified against kd.exe on a
/// Windows 11 26200 kernel dump: primitives, a structure without its
/// module, pointers, arrays, and function pointers with their convention.
#[test]
fn windbg_type_names_follow_dx() {
    let primitive = |name: &str| ParsedType::Primitive(name.to_string());
    let pointer = |inner: ParsedType| ParsedType::Pointer(Box::new(inner));
    let array = |inner: ParsedType, count| ParsedType::Array(Box::new(inner), count);
    let named = |name: &str| ParsedType::Struct(name.to_string());

    for (pdb, windbg) in [
        ("CHAR", "char"),
        ("UCHAR", "unsigned char"),
        ("WCHAR", "wchar_t"),
        ("SHORT", "short"),
        ("USHORT", "unsigned short"),
        ("INT", "int"),
        ("UINT", "unsigned int"),
        ("LONG", "long"),
        ("ULONG", "unsigned long"),
        ("LONGLONG", "__int64"),
        ("ULONGLONG", "unsigned __int64"),
        ("void", "void"),
        ("bool", "bool"),
    ] {
        assert_eq!(windbg_type_name(&primitive(pdb)), windbg, "{pdb}");
    }
    assert_eq!(windbg_type_name(&named("nt!_EPROCESS")), "_EPROCESS");
    assert_eq!(
        windbg_type_name(&named("nt!<unnamed-tag>#1124")),
        "<unnamed-tag>"
    );
    assert_eq!(windbg_type_name(&pointer(primitive("void"))), "void *");
    assert_eq!(
        windbg_type_name(&pointer(pointer(named("_EPROCESS")))),
        "_EPROCESS * *"
    );
    assert_eq!(
        windbg_type_name(&array(primitive("UCHAR"), 15)),
        "unsigned char [15]"
    );
    assert_eq!(
        windbg_type_name(&array(array(primitive("ULONG"), 256), 2)),
        "unsigned long [2][256]"
    );
    assert_eq!(
        windbg_type_name(&array(pointer(named("_KAPC_STATE")), 2)),
        "_KAPC_STATE * [2]"
    );
    assert_eq!(
        windbg_type_name(&pointer(array(primitive("UCHAR"), 15))),
        "unsigned char (*)[15]"
    );
    let dispatch = ParsedType::Function(
        Box::new(primitive("LONG")),
        vec![pointer(named("_DEVICE_OBJECT")), pointer(named("_IRP"))],
    );
    assert_eq!(
        windbg_type_name(&pointer(dispatch.clone())),
        "long (__cdecl*)(_DEVICE_OBJECT *,_IRP *)"
    );
    assert_eq!(
        windbg_type_name(&dispatch),
        "long __cdecl(_DEVICE_OBJECT *,_IRP *)"
    );
    assert_eq!(
        windbg_type_name(&array(pointer(dispatch), 28)),
        "long (__cdecl* [28])(_DEVICE_OBJECT *,_IRP *)"
    );
    let bits = ParsedType::Bitfield {
        underlying: Box::new(primitive("ULONG")),
        pos: 3,
        len: 2,
    };
    assert_eq!(windbg_type_name(&bits), "unsigned long");
}
