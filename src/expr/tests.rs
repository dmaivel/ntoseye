use super::*;

fn lit(value: u64) -> Box<Expr> {
    Box::new(Expr::Literal(VirtAddr(value)))
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
    assert_eq!(expr, Expr::Add(lit(0xffffa304cb692040), lit(584)));
}

#[test]
fn test_parse_decimal_literal_with_addition() {
    let expr = Expr::parse("1000 + 24").unwrap();
    assert_eq!(expr, Expr::Add(lit(1000), lit(24)));
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
        Expr::Add(lit(0x1000), lit(0x10))
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
        Expr::Add(lit(1000), lit(10))
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
        Expr::Add(
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
        Expr::Add(
            Box::new(Expr::Symbol("PsInitialSystemProcess".to_string())),
            lit(0x20)
        )
    );
}

#[test]
fn test_parse_complex() {
    let expr = Expr::parse("*PsInitialSystemProcess + 8").unwrap();
    assert_eq!(
        expr,
        Expr::Add(
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
fn test_parse_cast_with_field_access() {
    let expr = Expr::parse("(EPROCESS)PsInitialSystemProcess->Token").unwrap();
    assert_eq!(
        expr,
        Expr::FieldAccess(
            Box::new(Expr::Cast(
                Box::new(Expr::Symbol("PsInitialSystemProcess".to_string())),
                ExprType::Struct("EPROCESS".to_string())
            )),
            "Token".to_string()
        )
    );
}

#[test]
fn test_parse_nested_field_access() {
    let expr = Expr::parse("(EPROCESS)PsInitialSystemProcess->Token->Value").unwrap();
    if let Expr::FieldAccess(inner, field2) = &expr {
        assert_eq!(field2, "Value");
        if let Expr::FieldAccess(inner2, field1) = inner.as_ref() {
            assert_eq!(field1, "Token");
            if let Expr::Cast(_, expr_type) = inner2.as_ref() {
                assert!(matches!(expr_type, ExprType::Struct(name) if name == "EPROCESS"));
            } else {
                panic!("Expected Cast");
            }
        } else {
            panic!("Expected FieldAccess");
        }
    } else {
        panic!("Expected FieldAccess");
    }
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
            Box::new(Expr::Add(
                Box::new(Expr::Symbol("addr".to_string())),
                lit(0x10)
            )),
            ExprType::Qword
        )
    );
}

#[test]
fn test_parse_cast_pointer_with_literal_and_field() {
    let expr = Expr::parse("(EPROCESS*)(0xffffe70c61240080)->Token").unwrap();
    if let Expr::FieldAccess(inner, field) = &expr {
        assert_eq!(field, "Token");
        if let Expr::Cast(inner2, expr_type) = inner.as_ref() {
            if let ExprType::Pointer(inner_type) = expr_type {
                if let ExprType::Struct(name) = inner_type.as_ref() {
                    assert_eq!(name, "EPROCESS");
                } else {
                    panic!("Expected Struct");
                }
            } else {
                panic!("Expected Pointer");
            }
            if let Expr::Literal(addr) = inner2.as_ref() {
                assert_eq!(addr.0, 0xffffe70c61240080);
            } else {
                panic!("Expected Literal, got {:?}", inner2);
            }
        } else {
            panic!("Expected Cast, got {:?}", inner);
        }
    } else {
        panic!("Expected FieldAccess, got {:?}", expr);
    }
}

#[test]
fn test_parse_cast_struct_with_literal_and_field() {
    let expr = Expr::parse("(EPROCESS)(0xffffe70c61240080)->Token").unwrap();
    if let Expr::FieldAccess(inner, field) = &expr {
        assert_eq!(field, "Token");
        if let Expr::Cast(inner2, expr_type) = inner.as_ref() {
            if let ExprType::Struct(name) = expr_type {
                assert_eq!(name, "EPROCESS");
            } else {
                panic!("Expected Struct");
            }
            if let Expr::Literal(addr) = inner2.as_ref() {
                assert_eq!(addr.0, 0xffffe70c61240080);
            } else {
                panic!("Expected Literal, got {:?}", inner2);
            }
        } else {
            panic!("Expected Cast, got {:?}", inner);
        }
    } else {
        panic!("Expected FieldAccess, got {:?}", expr);
    }
}

#[test]
fn test_parse_grouped_deref() {
    let expr = Expr::parse("*(PsInitialSystemProcess + 0x10)").unwrap();
    assert_eq!(
        expr,
        Expr::Deref(Box::new(Expr::Add(
            Box::new(Expr::Symbol("PsInitialSystemProcess".to_string())),
            lit(0x10)
        )))
    );
}

#[test]
fn test_parse_grouped_deref_with_field() {
    let expr = Expr::parse("(_EPROCESS)(*PsInitialSystemProcess)->Token").unwrap();
    if let Expr::FieldAccess(inner, field) = &expr {
        assert_eq!(field, "Token");
        if let Expr::Cast(inner2, _) = inner.as_ref() {
            assert!(matches!(inner2.as_ref(), Expr::Deref(_)));
        } else {
            panic!("Expected Cast, got {:?}", inner);
        }
    } else {
        panic!("Expected FieldAccess, got {:?}", expr);
    }
}

#[test]
fn test_parse_index() {
    let expr = Expr::parse("addr[3]").unwrap();
    assert_eq!(
        expr,
        Expr::Index(Box::new(Expr::Symbol("addr".to_string())), 3)
    );
}

#[test]
fn test_parse_index_hex() {
    let expr = Expr::parse("addr[0x10]").unwrap();
    assert_eq!(
        expr,
        Expr::Index(Box::new(Expr::Symbol("addr".to_string())), 0x10)
    );
}

#[test]
fn test_parse_field_then_index() {
    let expr = Expr::parse("(EPROCESS)addr->field[2]").unwrap();
    if let Expr::Index(inner, index) = &expr {
        assert_eq!(*index, 2);
        assert!(matches!(inner.as_ref(), Expr::FieldAccess(_, _)));
    } else {
        panic!("Expected Index, got {:?}", expr);
    }
}

#[test]
fn test_parse_register() {
    let expr = Expr::parse("$rax").unwrap();
    assert_eq!(expr, Expr::Register("rax".to_string()));
}

#[test]
fn test_parse_register_with_arithmetic() {
    let expr = Expr::parse("$rsp+0x10").unwrap();
    assert_eq!(
        expr,
        Expr::Add(Box::new(Expr::Register("rsp".to_string())), lit(0x10))
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
fn test_parse_adds_subexpressions() {
    let expr = Expr::parse("rax + rbx").unwrap();
    assert_eq!(
        expr,
        Expr::Add(
            Box::new(Expr::Symbol("rax".to_string())),
            Box::new(Expr::Symbol("rbx".to_string()))
        )
    );
}

#[test]
fn test_parse_poi_with_symbol_offset() {
    let expr = Expr::parse("poi(x) + offset").unwrap();
    assert_eq!(
        expr,
        Expr::Add(
            Box::new(Expr::Deref(Box::new(Expr::Symbol("x".to_string())))),
            Box::new(Expr::Symbol("offset".to_string()))
        )
    );
}

#[test]
fn test_parse_at_register() {
    let expr = Expr::parse("@rip").unwrap();
    assert_eq!(expr, Expr::Register("rip".to_string()));
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
    assert!(matches!(expr, Expr::Binary(_, ExprBinaryOp::LogicalAnd, _)));
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
fn test_parse_error_render_includes_caret_and_label() {
    let err = Expr::parse_detailed("rax + @").unwrap_err();
    let rendered = err.render("rax + @");
    assert!(rendered.contains("rax + @"));
    assert!(rendered.contains("^"));
    assert!(rendered.contains("expected register name after '@'"));
}
