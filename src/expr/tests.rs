use super::*;
use crate::layout::{FieldInfo, TypeInfo};
use crate::session::session_over_memory;
use std::collections::HashMap;

#[test]
fn test_subregisters_read_their_parent_without_fabricating_storage() {
    let mut session = session_over_memory(0x1000, &[0; 8]);
    session.target.registers = Some(HashMap::from([
        ("rcx".into(), 0xfeed00000000001b),
        ("rax".into(), 0x1234),
    ]));
    assert_eq!(session.target.register_value("ecx"), Some(27));
    assert_eq!(session.target.register_value("ah"), Some(0x12));
    let value = ExprValue::Register {
        value: VirtAddr(session.target.register_value("ecx").unwrap()),
        type_data: ParsedType::Primitive("ULONG".into()),
        byte_size: Some(4),
        name: "ecx".into(),
    };
    assert_eq!(value.scalar(&session.target).unwrap().0, 27);
    assert!(value.address().is_err());
    session.target.registers = Some(HashMap::from([("ecx".into(), 27)]));
    assert_eq!(session.target.register_value("rcx"), None);
}

#[test]
fn test_typed_reads_preserve_width_and_address_of_does_not_read_memory() {
    let bytes = [0x78, 0x56, 0x34, 0x12, 0xaa, 0xbb, 0xcc, 0xdd];
    let session = session_over_memory(0x1000, &bytes);
    let target = &session.target;
    assert_eq!(
        Expr::eval("*((dword*)0x1000)", target).unwrap().0,
        0x12345678
    );
    assert_eq!(
        Expr::eval("poi((dword*)0x1000)", target).unwrap().0,
        0xddccbbaa12345678
    );
    assert_eq!(
        Expr::eval("*(&((dword*)0x1000)[0])", target).unwrap().0,
        0x12345678
    );
    assert_eq!(
        Expr::eval("&((dword*)0x2000)[3]", target).unwrap().0,
        0x200c
    );
    assert!(Expr::eval("((dword*)0x2000)[3]", target).is_err());
}

#[test]
fn test_typed_pointer_indirection_loads_each_pointer_slot() {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&0x1008u64.to_le_bytes());
    bytes[8..12].copy_from_slice(&0xdeadbeefu32.to_le_bytes());
    bytes[12..].copy_from_slice(&0xffffffffu32.to_le_bytes());
    let session = session_over_memory(0x1000, &bytes);
    assert_eq!(
        Expr::eval("**((dword**)0x1000)", &session.target)
            .unwrap()
            .0,
        0xdeadbeef
    );
}

#[test]
fn test_pointer_fields_use_the_pdb_declared_width() {
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&0x12345678u32.to_le_bytes());
    bytes[4..].copy_from_slice(&0xdeadbeefu32.to_le_bytes());
    let session = session_over_memory(0x1000, &bytes);
    let dtb = session.target.current_dtb();
    session.target.symbols.set_kernel(Some(1), dtb);
    session.target.symbols.inject_module_for_test(
        2,
        vec![TypeInfo {
            name: "_WOW64_POINTER_TEST".to_string(),
            size: 4,
            pointer_size: 4,
            fields: [(
                "Pointer".to_string(),
                FieldInfo {
                    offset: 0,
                    size: 4,
                    type_data: ParsedType::Pointer(Box::new(ParsedType::Primitive(
                        "UCHAR".to_string(),
                    ))),
                },
            )]
            .into_iter()
            .collect(),
        }],
        &[],
    );
    session
        .target
        .symbols
        .register_module_for_test(2, "ntdll32", dtb);
    let expression = Expr::FieldAccess(
        Box::new(Expr::Cast(
            Box::new(Expr::Literal(VirtAddr(0x1000))),
            ExprType::Pointer(Box::new(ExprType::Struct(
                "_WOW64_POINTER_TEST".to_string(),
            ))),
        )),
        "Pointer".to_string(),
    );

    assert_eq!(expression.resolve(&session.target).unwrap().0, 0x12345678);
}

#[test]
fn test_module_qualified_pointer_casts_resolve_the_type_in_that_module() {
    let mut bytes = [0u8; 8];
    bytes[4..].copy_from_slice(&0x2au32.to_le_bytes());
    let session = session_over_memory(0x1000, &bytes);
    let dtb = session.target.current_dtb();
    session.target.symbols.inject_module_for_test(
        2,
        vec![TypeInfo {
            name: "_NODE".to_string(),
            size: 8,
            pointer_size: 8,
            fields: [(
                "Value".to_string(),
                FieldInfo {
                    offset: 4,
                    size: 4,
                    type_data: ParsedType::Primitive("ULONG".to_string()),
                },
            )]
            .into_iter()
            .collect(),
        }],
        &[],
    );
    session
        .target
        .symbols
        .register_module_for_test(2, "driver", dtb);

    assert_eq!(
        Expr::eval("((driver!_NODE*)0x1000)->Value", &session.target)
            .unwrap()
            .0,
        0x2a
    );
    // A parenthesized qualified name without `*` stays a symbol, not a cast.
    assert!(matches!(
        Expr::parse("(driver!Routine)+8"),
        Ok(Expr::Binary(_, ExprBinaryOp::Add, _))
    ));
}

#[test]
fn test_bitfields_read_only_the_declared_storage_and_have_no_address() {
    let session = session_over_memory(0x1000, &[0b10110100]);
    let field = ExprValue::Memory {
        address: VirtAddr(0x1000),
        type_data: ParsedType::Bitfield {
            underlying: Box::new(ParsedType::Primitive("UCHAR".into())),
            pos: 2,
            len: 3,
        },
        byte_size: Some(1),
    };
    assert_eq!(field.scalar(&session.target).unwrap().0, 5);
    assert!(field.address().is_err());
}

fn lit(value: u64) -> Box<Expr> {
    Box::new(Expr::Literal(VirtAddr(value)))
}

fn add(lhs: Box<Expr>, rhs: Box<Expr>) -> Expr {
    Expr::Binary(lhs, ExprBinaryOp::Add, rhs)
}

#[test]
fn test_parse_symbol() {
    let expr = Expr::parse("PsInitialSystemProcess").unwrap();
    assert_eq!(expr, Expr::Symbol("PsInitialSystemProcess".to_string()));
}

#[test]
fn test_parse_literal() {
    let expr = Expr::parse("0xfffff80123456789").unwrap();
    assert_eq!(expr, Expr::Literal(VirtAddr(0xfffff80123456789)));
}

#[test]
fn test_parse_hex_literal_with_addition() {
    let expr = Expr::parse("0xffffa304cb692040 + 584").unwrap();
    assert_eq!(expr, add(lit(0xffffa304cb692040), lit(584)));
}

#[test]
fn test_parse_decimal_literal_with_addition() {
    let expr = Expr::parse("1000 + 24").unwrap();
    assert_eq!(expr, add(lit(1000), lit(24)));
}

#[test]
fn test_parse_bare_hex_stays_symbol_until_resolution() {
    let expr = Expr::parse("fffff80123456789").unwrap();
    assert_eq!(expr, Expr::Symbol("fffff80123456789".to_string()));
}

#[test]
fn test_parse_bare_decimal_stays_decimal_literal() {
    let expr = Expr::parse("1000").unwrap();
    assert_eq!(expr, Expr::Literal(VirtAddr(1000)));
}

#[test]
fn test_parse_with_hexadecimal_default_radix() {
    assert_eq!(
        Expr::parse_with_radix("1000 + 10", NumberRadix::Hexadecimal).unwrap(),
        add(lit(0x1000), lit(0x10))
    );
    assert_eq!(
        Expr::parse_with_radix("123abc", NumberRadix::Hexadecimal).unwrap(),
        Expr::Literal(VirtAddr(0x123abc))
    );
}

#[test]
fn test_explicit_decimal_overrides_default_radix() {
    assert_eq!(
        Expr::parse_with_radix("0n1000 + 0n10", NumberRadix::Hexadecimal).unwrap(),
        add(lit(1000), lit(10))
    );
}

#[test]
fn test_bare_hex_literal_fallback_requires_hex_letter() {
    assert_eq!(
        Expr::parse_bare_hex_literal("fffff80123456789"),
        Some(0xfffff80123456789)
    );
    assert_eq!(Expr::parse_bare_hex_literal("DEADBEEF"), Some(0xdeadbeef));
    assert_eq!(Expr::parse_bare_hex_literal("1000"), None);
    assert_eq!(Expr::parse_bare_hex_literal("nt!KeBugCheck"), None);
}

#[test]
fn test_parse_deref() {
    let expr = Expr::parse("*PsInitialSystemProcess").unwrap();
    assert_eq!(
        expr,
        Expr::Deref(Box::new(Expr::Symbol("PsInitialSystemProcess".to_string())))
    );
}

#[test]
fn test_parse_addition() {
    let expr = Expr::parse("PsInitialSystemProcess + 0x20").unwrap();
    assert_eq!(
        expr,
        add(
            Box::new(Expr::Symbol("PsInitialSystemProcess".to_string())),
            lit(0x20)
        )
    );
}

#[test]
fn test_parse_parentheses() {
    let expr = Expr::parse("(PsInitialSystemProcess + 0x20)").unwrap();
    assert_eq!(
        expr,
        add(
            Box::new(Expr::Symbol("PsInitialSystemProcess".to_string())),
            lit(0x20)
        )
    );
}

#[test]
fn test_parse_deref_binds_before_addition() {
    let expr = Expr::parse("*PsInitialSystemProcess + 8").unwrap();
    assert_eq!(
        expr,
        add(
            Box::new(Expr::Deref(Box::new(Expr::Symbol(
                "PsInitialSystemProcess".to_string()
            )))),
            lit(8)
        )
    );
}

#[test]
fn test_parse_field_access() {
    let expr = Expr::parse("PsInitialSystemProcess->Token").unwrap();
    assert_eq!(
        expr,
        Expr::FieldAccess(
            Box::new(Expr::Symbol("PsInitialSystemProcess".to_string())),
            "Token".to_string()
        )
    );
}

#[test]
fn test_parse_cast_primitive() {
    let expr = Expr::parse("(dword)0x12345678").unwrap();
    assert_eq!(
        expr,
        Expr::Cast(
            Box::new(Expr::Literal(VirtAddr(0x12345678))),
            ExprType::Dword
        )
    );
}

#[test]
fn test_parse_cast_struct() {
    let expr = Expr::parse("(EPROCESS)PsInitialSystemProcess").unwrap();
    assert_eq!(
        expr,
        Expr::Cast(
            Box::new(Expr::Symbol("PsInitialSystemProcess".to_string())),
            ExprType::Struct("EPROCESS".to_string())
        )
    );
}

#[test]
fn test_parse_cast_pointer() {
    let expr = Expr::parse("(EPROCESS*)addr").unwrap();
    assert_eq!(
        expr,
        Expr::Cast(
            Box::new(Expr::Symbol("addr".to_string())),
            ExprType::Pointer(Box::new(ExprType::Struct("EPROCESS".to_string())))
        )
    );
}

#[test]
fn test_parse_deref_with_cast() {
    let expr = Expr::parse("*(dword)addr").unwrap();
    assert_eq!(
        expr,
        Expr::Deref(Box::new(Expr::Cast(
            Box::new(Expr::Symbol("addr".to_string())),
            ExprType::Dword
        )))
    );
}

#[test]
fn test_parse_cast_with_arithmetic() {
    let expr = Expr::parse("(qword)(addr + 0x10)").unwrap();
    assert_eq!(
        expr,
        Expr::Cast(
            Box::new(add(Box::new(Expr::Symbol("addr".to_string())), lit(0x10))),
            ExprType::Qword
        )
    );
}

#[test]
fn test_parse_grouped_deref() {
    let expr = Expr::parse("*(PsInitialSystemProcess + 0x10)").unwrap();
    assert_eq!(
        expr,
        Expr::Deref(Box::new(add(
            Box::new(Expr::Symbol("PsInitialSystemProcess".to_string())),
            lit(0x10)
        )))
    );
}

#[test]
fn test_parse_index() {
    assert_eq!(
        Expr::parse("addr[3]").unwrap(),
        Expr::Index(Box::new(Expr::Symbol("addr".to_string())), 3)
    );
    assert_eq!(
        Expr::parse("addr[0x10]").unwrap(),
        Expr::Index(Box::new(Expr::Symbol("addr".to_string())), 0x10)
    );
}

#[test]
fn test_parse_register_sigils_are_interchangeable() {
    for text in ["$rax", "@rax", "@$rax"] {
        assert_eq!(
            Expr::parse(text).unwrap(),
            Expr::Register("rax".to_string()),
            "{text}"
        );
    }
}

#[test]
fn test_parse_register_with_arithmetic() {
    let expr = Expr::parse("$rsp+0x10").unwrap();
    assert_eq!(
        expr,
        add(Box::new(Expr::Register("rsp".to_string())), lit(0x10))
    );
}

#[test]
fn test_parse_deref_register() {
    let expr = Expr::parse("*$rsp").unwrap();
    assert_eq!(
        expr,
        Expr::Deref(Box::new(Expr::Register("rsp".to_string())))
    );
}

#[test]
fn test_parse_poi_with_symbol_offset() {
    let expr = Expr::parse("poi(x) + offset").unwrap();
    assert_eq!(
        expr,
        add(
            Box::new(Expr::Read(8, Box::new(Expr::Symbol("x".to_string())))),
            Box::new(Expr::Symbol("offset".to_string()))
        )
    );
}

#[test]
fn test_parse_template_symbol_names_and_comparisons() {
    assert_eq!(
        Expr::parse("nt!ST_STORE<SM_TRAITS>::StStart").unwrap(),
        Expr::Symbol("nt!ST_STORE<SM_TRAITS>::StStart".to_string())
    );
    assert_eq!(
        Expr::parse("ST_STORE<SM_TRAITS>::StStart").unwrap(),
        Expr::Symbol("ST_STORE<SM_TRAITS>::StStart".to_string())
    );
    assert_eq!(
        Expr::parse("index < 0n10").unwrap(),
        Expr::Binary(
            Box::new(Expr::Symbol("index".to_string())),
            ExprBinaryOp::Less,
            Box::new(Expr::Literal(VirtAddr(10)))
        )
    );
    // No `::` after the closing bracket, so this is two comparisons rather
    // than a name, and chaining them is rejected.
    assert!(Expr::parse("index<0n10>0n2").is_err());
}

#[test]
fn test_parse_masm_width_reads() {
    for (text, width) in [
        ("by(x)", 1u8),
        ("wo(x)", 2),
        ("dwo(x)", 4),
        ("qwo(x)", 8),
        ("poi(x)", 8),
    ] {
        assert_eq!(
            Expr::parse(text).unwrap(),
            Expr::Read(width, Box::new(Expr::Symbol("x".to_string()))),
            "{text}"
        );
    }
    // A symbol that merely starts with an operator name is still a symbol.
    assert_eq!(
        Expr::parse("bytes_written").unwrap(),
        Expr::Symbol("bytes_written".to_string())
    );
}

#[test]
fn test_parse_boolean_precedence_and_module_symbols() {
    let expr = Expr::parse("nt!Flag == 1 || $rbx == 2 && !$rcx").unwrap();
    assert_eq!(
        expr,
        Expr::Binary(
            Box::new(Expr::Binary(
                Box::new(Expr::Symbol("nt!Flag".to_string())),
                ExprBinaryOp::Equal,
                lit(1),
            )),
            ExprBinaryOp::LogicalOr,
            Box::new(Expr::Binary(
                Box::new(Expr::Binary(
                    Box::new(Expr::Register("rbx".to_string())),
                    ExprBinaryOp::Equal,
                    lit(2),
                )),
                ExprBinaryOp::LogicalAnd,
                Box::new(Expr::Unary(
                    ExprUnaryOp::LogicalNot,
                    Box::new(Expr::Register("rcx".to_string())),
                )),
            )),
        )
    );
}

#[test]
fn test_parse_not_equal_without_spaces_after_module_symbol() {
    let expr = Expr::parse("nt!Flag!=0").unwrap();
    assert_eq!(
        expr,
        Expr::Binary(
            Box::new(Expr::Symbol("nt!Flag".to_string())),
            ExprBinaryOp::NotEqual,
            lit(0),
        )
    );
}

#[test]
fn test_parse_grouped_boolean_and_bitwise_expression() {
    let expr = Expr::parse("($rax & 0xff) == 0x42 && ($rdx >> 4) != 0").unwrap();
    let mask = Expr::Binary(
        Box::new(Expr::Register("rax".to_string())),
        ExprBinaryOp::BitwiseAnd,
        lit(0xff),
    );
    let shift = Expr::Binary(
        Box::new(Expr::Register("rdx".to_string())),
        ExprBinaryOp::ShiftRight,
        lit(4),
    );
    assert_eq!(
        expr,
        Expr::Binary(
            Box::new(Expr::Binary(Box::new(mask), ExprBinaryOp::Equal, lit(0x42))),
            ExprBinaryOp::LogicalAnd,
            Box::new(Expr::Binary(
                Box::new(shift),
                ExprBinaryOp::NotEqual,
                lit(0)
            )),
        )
    );
}

#[test]
fn test_parse_rejects_chained_relational_comparison() {
    let err = Expr::parse_detailed("0 < $rax < 10").unwrap_err();
    assert!(
        err.label
            .contains("chained relational comparisons are ambiguous")
    );
}

#[test]
fn test_parse_rejects_chained_equality_comparison() {
    let err = Expr::parse_detailed("$rax == 1 == $rbx").unwrap_err();
    assert!(
        err.label
            .contains("chained equality comparisons are ambiguous")
    );
}

#[test]
fn test_parse_error_labels_register_name() {
    let err = Expr::parse_detailed("rax + @").unwrap_err();
    assert_eq!(err.span, 6..7);
    assert_eq!(err.label, "expected register name after '@'");
}

#[test]
fn test_parse_error_labels_missing_poi_operand() {
    let err = Expr::parse_detailed("poi(rax + )").unwrap_err();
    assert_eq!(err.span, 10..11);
    assert_eq!(err.label, "expected expression");
}

#[test]
fn test_parse_explicit_source_local_escape() {
    assert_eq!(
        Expr::parse("$!request").unwrap(),
        Expr::Local("request".to_string())
    );
}

#[test]
fn test_parse_dot_members_and_qualified_module_extension() {
    assert_eq!(
        Expr::parse("request.IoStatus.Status").unwrap(),
        Expr::MemberAccess(
            Box::new(Expr::MemberAccess(
                Box::new(Expr::Symbol("request".to_string())),
                "IoStatus".to_string(),
            )),
            "Status".to_string(),
        )
    );
    assert_eq!(
        Expr::parse("driver.sys!Worker").unwrap(),
        Expr::Symbol("driver.sys!Worker".to_string())
    );
}

#[test]
fn test_parse_postfix_binds_before_prefix_deref() {
    assert_eq!(
        Expr::parse("*ptr->field").unwrap(),
        Expr::Deref(Box::new(Expr::FieldAccess(
            Box::new(Expr::Symbol("ptr".to_string())),
            "field".to_string(),
        )))
    );
}

#[test]
fn test_parse_address_of_grouped_pointer_member() {
    assert_eq!(
        Expr::parse("&((TYPE*)addr)->field").unwrap(),
        Expr::Address(Box::new(Expr::FieldAccess(
            Box::new(Expr::Cast(
                Box::new(Expr::Symbol("addr".to_string())),
                ExprType::Pointer(Box::new(ExprType::Struct("TYPE".to_string()))),
            )),
            "field".to_string(),
        )))
    );
}
