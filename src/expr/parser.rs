//! The MASM expression grammar: winnow parsers from operator precedence
//! down to literals, symbols, and casts, and their positioned parse errors.

use super::{
    Expr, ExprBinaryOp, ExprParseError, ExprType, ExprUnaryOp, NumberRadix, StringOp,
    parse_number_literal_text,
};
use crate::error::Result;
use crate::types::VirtAddr;
use std::result;
use winnow::Parser;
use winnow::combinator::{alt, not, peek};
use winnow::error::{ErrMode, ModalResult, ParserError};
use winnow::stream::{LocatingSlice, Location, Stateful, Stream};
use winnow::token::{literal, one_of, take_till, take_while};

impl Expr {
    fn is_type_name(s: &str) -> bool {
        fn is_identifier(s: &str) -> bool {
            s.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
                && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        let mut s = s.trim();
        let mut pointer = false;
        while let Some(stripped) = s.strip_suffix('*') {
            s = stripped.trim_end();
            pointer = true;
        }
        match s.split_once('!') {
            // `(nt!Symbol)` is a parenthesized symbol, so a module-qualified
            // type is only taken as a cast when it is a pointer type.
            Some((module, name)) => pointer && is_identifier(module) && is_identifier(name),
            None => is_identifier(s),
        }
    }

    fn parse_type(type_str: &str) -> Result<ExprType> {
        let type_str = type_str.trim();

        if let Some(stripped) = type_str.strip_suffix('*') {
            let inner_type = Self::parse_type(stripped.trim_end())?;
            return Ok(ExprType::Pointer(Box::new(inner_type)));
        }

        match type_str.to_lowercase().as_str() {
            "byte" | "u8" | "uchar" | "char" | "boolean" | "uint8_t" | "int8_t" => {
                Ok(ExprType::Byte)
            }
            "word" | "u16" | "ushort" | "short" | "wchar" | "uint16_t" | "int16_t" => {
                Ok(ExprType::Word)
            }
            "dword" | "u32" | "ulong" | "long" | "uint" | "int" | "uint32_t" | "int32_t" => {
                Ok(ExprType::Dword)
            }
            "qword" | "u64" | "dword64" | "ulong64" | "longlong" | "ulonglong" | "pvoid"
            | "size_t" | "uint64_t" | "int64_t" | "usize" => Ok(ExprType::Qword),
            _ => Ok(ExprType::Struct(type_str.to_string())),
        }
    }
}

type ExprInput<'a> = Stateful<LocatingSlice<&'a str>, NumberRadix>;

type ParseResult<T> = ModalResult<T, ExprParseError>;

impl<'a> ParserError<ExprInput<'a>> for ExprParseError {
    type Inner = Self;

    fn from_input(input: &ExprInput<'a>) -> Self {
        error_at(input, "expected expression")
    }

    fn into_inner(self) -> result::Result<Self::Inner, Self> {
        Ok(self)
    }

    fn or(self, other: Self) -> Self {
        if other.span.start >= self.span.start {
            other
        } else {
            self
        }
    }
}

enum Suffix {
    Field(String),
    Member(String),
    Index(u64),
}

fn parse_left_associative<'a, Op>(
    input: &mut ExprInput<'a>,
    operand: fn(&mut ExprInput<'a>) -> ParseResult<Expr>,
    tail: fn(&mut ExprInput<'a>) -> ParseResult<(Op, Expr)>,
    combine: fn(Expr, Op, Expr) -> Expr,
) -> ParseResult<Expr> {
    let mut expr = operand(input)?;
    loop {
        let checkpoint = input.checkpoint();
        match tail(input) {
            Ok((op, rhs)) => expr = combine(expr, op, rhs),
            Err(ErrMode::Backtrack(_)) => {
                input.reset(&checkpoint);
                return Ok(expr);
            }
            Err(error) => return Err(error),
        }
    }
}

fn parse_non_chained_binary<'a>(
    input: &mut ExprInput<'a>,
    operand: fn(&mut ExprInput<'a>) -> ParseResult<Expr>,
    tail: fn(&mut ExprInput<'a>) -> ParseResult<(ExprBinaryOp, Expr)>,
    chained_error: &'static str,
) -> ParseResult<Expr> {
    let lhs = operand(input)?;
    let checkpoint = input.checkpoint();
    let (op, rhs) = match tail(input) {
        Ok(term) => term,
        Err(ErrMode::Backtrack(_)) => {
            input.reset(&checkpoint);
            return Ok(lhs);
        }
        Err(error) => return Err(error),
    };
    let expr = Expr::Binary(Box::new(lhs), op, Box::new(rhs));

    let checkpoint = input.checkpoint();
    match tail(input) {
        Ok(_) => Err(ErrMode::Cut(error_at(input, chained_error))),
        Err(ErrMode::Backtrack(_)) => {
            input.reset(&checkpoint);
            Ok(expr)
        }
        Err(error) => Err(error),
    }
}

fn combine_binary(lhs: Expr, op: ExprBinaryOp, rhs: Expr) -> Expr {
    Expr::Binary(Box::new(lhs), op, Box::new(rhs))
}

pub(super) fn parse_logical_or(input: &mut ExprInput<'_>) -> ParseResult<Expr> {
    parse_left_associative(
        input,
        parse_logical_and,
        parse_logical_or_tail,
        combine_binary,
    )
}

fn parse_logical_or_tail(input: &mut ExprInput<'_>) -> ParseResult<(ExprBinaryOp, Expr)> {
    ws0.parse_next(input)?;
    literal("||").parse_next(input)?;
    let rhs = parse_logical_and.parse_next(input).map_err(ErrMode::cut)?;
    Ok((ExprBinaryOp::LogicalOr, rhs))
}

fn parse_logical_and(input: &mut ExprInput<'_>) -> ParseResult<Expr> {
    parse_left_associative(
        input,
        parse_bitwise_or,
        parse_logical_and_tail,
        combine_binary,
    )
}

fn parse_logical_and_tail(input: &mut ExprInput<'_>) -> ParseResult<(ExprBinaryOp, Expr)> {
    ws0.parse_next(input)?;
    literal("&&").parse_next(input)?;
    let rhs = parse_bitwise_or.parse_next(input).map_err(ErrMode::cut)?;
    Ok((ExprBinaryOp::LogicalAnd, rhs))
}

fn parse_bitwise_or(input: &mut ExprInput<'_>) -> ParseResult<Expr> {
    parse_left_associative(
        input,
        parse_bitwise_xor,
        parse_bitwise_or_tail,
        combine_binary,
    )
}

fn parse_bitwise_or_tail(input: &mut ExprInput<'_>) -> ParseResult<(ExprBinaryOp, Expr)> {
    ws0.parse_next(input)?;
    alt((
        (literal("|"), not(literal("|"))).void(),
        parse_word_operator(&[("or", ExprBinaryOp::BitwiseOr)]).void(),
    ))
    .parse_next(input)?;
    let rhs = parse_bitwise_xor.parse_next(input).map_err(ErrMode::cut)?;
    Ok((ExprBinaryOp::BitwiseOr, rhs))
}

fn parse_bitwise_xor(input: &mut ExprInput<'_>) -> ParseResult<Expr> {
    parse_left_associative(
        input,
        parse_bitwise_and,
        parse_bitwise_xor_tail,
        combine_binary,
    )
}

fn parse_bitwise_xor_tail(input: &mut ExprInput<'_>) -> ParseResult<(ExprBinaryOp, Expr)> {
    ws0.parse_next(input)?;
    alt((
        literal("^").void(),
        parse_word_operator(&[("xor", ExprBinaryOp::BitwiseXor)]).void(),
    ))
    .parse_next(input)?;
    let rhs = parse_bitwise_and.parse_next(input).map_err(ErrMode::cut)?;
    Ok((ExprBinaryOp::BitwiseXor, rhs))
}

fn parse_bitwise_and(input: &mut ExprInput<'_>) -> ParseResult<Expr> {
    parse_left_associative(
        input,
        parse_equality,
        parse_bitwise_and_tail,
        combine_binary,
    )
}

fn parse_bitwise_and_tail(input: &mut ExprInput<'_>) -> ParseResult<(ExprBinaryOp, Expr)> {
    ws0.parse_next(input)?;
    alt((
        (literal("&"), not(literal("&"))).void(),
        parse_word_operator(&[("and", ExprBinaryOp::BitwiseAnd)]).void(),
    ))
    .parse_next(input)?;
    let rhs = parse_equality.parse_next(input).map_err(ErrMode::cut)?;
    Ok((ExprBinaryOp::BitwiseAnd, rhs))
}

fn parse_equality(input: &mut ExprInput<'_>) -> ParseResult<Expr> {
    parse_non_chained_binary(
        input,
        parse_relational,
        parse_equality_tail,
        "chained equality comparisons are ambiguous; join comparisons with '&&'",
    )
}

fn parse_equality_tail(input: &mut ExprInput<'_>) -> ParseResult<(ExprBinaryOp, Expr)> {
    ws0.parse_next(input)?;
    let op = alt((
        literal("==").value(ExprBinaryOp::Equal),
        literal("!=").value(ExprBinaryOp::NotEqual),
        // MASM spells equality with one `=` as readily as two. There are no
        // assignments inside an expression, so this cannot be mistaken.
        literal("=").value(ExprBinaryOp::Equal),
    ))
    .parse_next(input)?;
    let rhs = parse_relational.parse_next(input).map_err(ErrMode::cut)?;
    Ok((op, rhs))
}

fn parse_relational(input: &mut ExprInput<'_>) -> ParseResult<Expr> {
    parse_non_chained_binary(
        input,
        parse_shift,
        parse_relational_tail,
        "chained relational comparisons are ambiguous; join comparisons with '&&'",
    )
}

fn parse_relational_tail(input: &mut ExprInput<'_>) -> ParseResult<(ExprBinaryOp, Expr)> {
    ws0.parse_next(input)?;
    let op = alt((
        literal("<=").value(ExprBinaryOp::LessEqual),
        literal(">=").value(ExprBinaryOp::GreaterEqual),
        literal("<").value(ExprBinaryOp::Less),
        literal(">").value(ExprBinaryOp::Greater),
    ))
    .parse_next(input)?;
    let rhs = parse_shift.parse_next(input).map_err(ErrMode::cut)?;
    Ok((op, rhs))
}

fn parse_shift(input: &mut ExprInput<'_>) -> ParseResult<Expr> {
    parse_left_associative(input, parse_additive, parse_shift_tail, combine_binary)
}

fn parse_shift_tail(input: &mut ExprInput<'_>) -> ParseResult<(ExprBinaryOp, Expr)> {
    ws0.parse_next(input)?;
    let op = alt((
        literal("<<").value(ExprBinaryOp::ShiftLeft),
        literal(">>>").value(ExprBinaryOp::ShiftRightArithmetic),
        literal(">>").value(ExprBinaryOp::ShiftRight),
    ))
    .parse_next(input)?;
    let rhs = parse_additive.parse_next(input).map_err(ErrMode::cut)?;
    Ok((op, rhs))
}

fn parse_additive(input: &mut ExprInput<'_>) -> ParseResult<Expr> {
    parse_left_associative(
        input,
        parse_multiplicative,
        parse_additive_tail,
        combine_binary,
    )
}

fn parse_additive_tail(input: &mut ExprInput<'_>) -> ParseResult<(ExprBinaryOp, Expr)> {
    ws0.parse_next(input)?;
    let op = alt((
        literal("+").value(ExprBinaryOp::Add),
        literal("-").value(ExprBinaryOp::Sub),
    ))
    .parse_next(input)?;
    let rhs = parse_multiplicative
        .parse_next(input)
        .map_err(ErrMode::cut)?;
    Ok((op, rhs))
}

/// `*`, `/`, and `mod`/`%` bind tighter than `+` and `-`, as they do in MASM
/// and in C. A `*` only reaches here after an operand; in prefix position it
/// is still a dereference.
fn parse_multiplicative(input: &mut ExprInput<'_>) -> ParseResult<Expr> {
    parse_left_associative(
        input,
        parse_prefix,
        parse_multiplicative_tail,
        combine_binary,
    )
}

fn parse_multiplicative_tail(input: &mut ExprInput<'_>) -> ParseResult<(ExprBinaryOp, Expr)> {
    ws0.parse_next(input)?;
    let op = alt((
        literal("*").value(ExprBinaryOp::Multiply),
        literal("/").value(ExprBinaryOp::Divide),
        literal("%").value(ExprBinaryOp::Modulo),
        parse_word_operator(&[("mod", ExprBinaryOp::Modulo)]),
    ))
    .parse_next(input)?;
    let rhs = parse_prefix.parse_next(input).map_err(ErrMode::cut)?;
    Ok((op, rhs))
}

/// Match one of MASM's spelled-out operators (`and`, `or`, `xor`, `mod`).
/// A word only counts when the following character cannot continue a symbol,
/// so `andy` and `order` stay symbols.
fn parse_word_operator<T: Copy>(
    words: &'static [(&'static str, T)],
) -> impl FnMut(&mut ExprInput<'_>) -> ParseResult<T> {
    move |input| {
        let checkpoint = input.checkpoint();
        let token = take_while(1.., |ch: char| ch.is_ascii_alphabetic()).parse_next(input)?;
        let matched = words
            .iter()
            .find(|(word, _)| token.eq_ignore_ascii_case(word))
            .map(|(_, op)| *op);
        let continues = input.as_ref().starts_with(symbol_char);
        match matched {
            Some(op) if !continues => Ok(op),
            _ => {
                input.reset(&checkpoint);
                Err(ErrMode::Backtrack(error_at(input, "expected an operator")))
            }
        }
    }
}

fn parse_postfix(input: &mut ExprInput<'_>) -> ParseResult<Expr> {
    let mut expr = alt((
        parse_read,
        parse_range_valid,
        parse_image_entry,
        parse_string_op,
        parse_atom,
    ))
    .parse_next(input)?;
    loop {
        let checkpoint = input.checkpoint();
        match alt((parse_field_suffix, parse_index_suffix)).parse_next(input) {
            Ok(Suffix::Field(field)) => expr = Expr::FieldAccess(Box::new(expr), field),
            Ok(Suffix::Member(field)) => expr = Expr::MemberAccess(Box::new(expr), field),
            Ok(Suffix::Index(index)) => expr = Expr::Index(Box::new(expr), index),
            Err(ErrMode::Backtrack(_)) => {
                input.reset(&checkpoint);
                return Ok(expr);
            }
            Err(error) => return Err(error),
        }
    }
}

fn parse_field_suffix(input: &mut ExprInput<'_>) -> ParseResult<Suffix> {
    ws0.parse_next(input)?;
    let indirect = alt((literal("->").value(true), literal(".").value(false))).parse_next(input)?;
    ws0.parse_next(input)?;
    let field = parse_field_name
        .parse_next(input)
        .map_err(|_| ErrMode::Cut(error_at(input, "expected field name after member operator")))?;
    Ok(if indirect {
        Suffix::Field(field.to_string())
    } else {
        Suffix::Member(field.to_string())
    })
}

fn parse_index_suffix(input: &mut ExprInput<'_>) -> ParseResult<Suffix> {
    ws0.parse_next(input)?;
    one_of('[').parse_next(input)?;
    ws0.parse_next(input)?;
    let index = parse_number_literal(input, "expected numeric index")?;
    ws0.parse_next(input)?;
    expect_char(input, ']', "expected ']'")?;
    Ok(Suffix::Index(index))
}

fn parse_prefix(input: &mut ExprInput<'_>) -> ParseResult<Expr> {
    ws0.parse_next(input)?;

    alt((
        parse_address_prefix,
        parse_unary_prefix,
        parse_unary_plus,
        parse_deref_prefix,
        parse_cast,
        parse_postfix,
    ))
    .parse_next(input)
}

fn parse_address_prefix(input: &mut ExprInput<'_>) -> ParseResult<Expr> {
    one_of('&').parse_next(input)?;
    let inner = parse_prefix.parse_next(input).map_err(ErrMode::cut)?;
    Ok(Expr::Address(Box::new(inner)))
}

fn parse_unary_prefix(input: &mut ExprInput<'_>) -> ParseResult<Expr> {
    let op = alt((
        literal("!").value(ExprUnaryOp::LogicalNot),
        literal("~").value(ExprUnaryOp::BitwiseNot),
        literal("-").value(ExprUnaryOp::Negate),
        // MASM's spelled-out unary operators. `not` mirrors `!`, and
        // `hi`/`low` extract a 16-bit half.
        parse_word_operator(&[
            ("not", ExprUnaryOp::LogicalNot),
            ("hi", ExprUnaryOp::HighWord),
            ("low", ExprUnaryOp::LowWord),
        ]),
    ))
    .parse_next(input)?;
    let inner = parse_prefix.parse_next(input).map_err(ErrMode::cut)?;
    Ok(Expr::Unary(op, Box::new(inner)))
}

/// `+expr` is MASM's unary plus: accepted and discarded.
fn parse_unary_plus(input: &mut ExprInput<'_>) -> ParseResult<Expr> {
    one_of('+').parse_next(input)?;
    parse_prefix.parse_next(input).map_err(ErrMode::cut)
}

fn parse_deref_prefix(input: &mut ExprInput<'_>) -> ParseResult<Expr> {
    one_of('*').parse_next(input)?;
    let inner = parse_prefix.parse_next(input).map_err(ErrMode::cut)?;
    Ok(Expr::Deref(Box::new(inner)))
}

/// WinDbg's MASM memory operators. Each reads a fixed width and, unlike `*`
/// on a typed pointer, never applies a source type to the result.
fn parse_read(input: &mut ExprInput<'_>) -> ParseResult<Expr> {
    let (width, physical) = alt((
        alt((
            literal("poi").value((8u8, false)),
            literal("qwo").value((8u8, false)),
            literal("dwo").value((4u8, false)),
            literal("wo").value((2u8, false)),
            literal("by").value((1u8, false)),
        )),
        alt((
            literal("$ppoi").value((8u8, true)),
            literal("$pqwo").value((8u8, true)),
            literal("$pdwo").value((4u8, true)),
            literal("$pwo").value((2u8, true)),
            literal("$pby").value((1u8, true)),
        )),
    ))
    .parse_next(input)?;
    ws0.parse_next(input)?;
    one_of('(').parse_next(input)?;
    ws0.parse_next(input)?;
    let inner = parse_logical_or.parse_next(input).map_err(ErrMode::cut)?;
    ws0.parse_next(input)?;
    expect_char(input, ')', "expected ')' after memory read expression")?;
    Ok(if physical {
        Expr::ReadPhysical(width, Box::new(inner))
    } else {
        Expr::Read(width, Box::new(inner))
    })
}

/// `$scmp`, `$sicmp`, `$spat` accept two quoted literals, not expressions.
fn parse_string_op(input: &mut ExprInput<'_>) -> ParseResult<Expr> {
    let op = alt((
        literal("$scmp").value(StringOp::Compare),
        literal("$sicmp").value(StringOp::CompareIgnoreCase),
        literal("$spat").value(StringOp::Match),
    ))
    .parse_next(input)?;
    ws0.parse_next(input)?;
    one_of('(').parse_next(input)?;
    ws0.parse_next(input)?;
    let left = parse_string_literal(input)?;
    ws0.parse_next(input)?;
    expect_char(input, ',', "expected ',' between string operands")?;
    ws0.parse_next(input)?;
    let right = parse_string_literal(input)?;
    ws0.parse_next(input)?;
    expect_char(input, ')', "expected ')' after string operands")?;
    Ok(Expr::StringOp(op, left, right))
}

fn parse_string_literal(input: &mut ExprInput<'_>) -> ParseResult<String> {
    expect_char(input, '"', "expected a quoted string")?;
    let text = take_till(0.., '"')
        .parse_next(input)
        .map_err(|_: ErrMode<ExprParseError>| {
            ErrMode::Cut(error_at(input, "unterminated string"))
        })?;
    expect_char(input, '"', "expected a closing '\"'")?;
    Ok(text.to_string())
}

/// `$iment(base)`: MASM's image entry point lookup.
fn parse_image_entry(input: &mut ExprInput<'_>) -> ParseResult<Expr> {
    literal("$iment").parse_next(input)?;
    ws0.parse_next(input)?;
    one_of('(').parse_next(input)?;
    ws0.parse_next(input)?;
    let base = parse_logical_or.parse_next(input).map_err(ErrMode::cut)?;
    ws0.parse_next(input)?;
    expect_char(input, ')', "expected ')' after $iment base")?;
    Ok(Expr::ImageEntry(Box::new(base)))
}

/// `$vvalid(address, length)`: MASM's memory-validity test.
fn parse_range_valid(input: &mut ExprInput<'_>) -> ParseResult<Expr> {
    literal("$vvalid").parse_next(input)?;
    ws0.parse_next(input)?;
    one_of('(').parse_next(input)?;
    ws0.parse_next(input)?;
    let address = parse_logical_or.parse_next(input).map_err(ErrMode::cut)?;
    ws0.parse_next(input)?;
    expect_char(input, ',', "expected ',' after $vvalid address")?;
    ws0.parse_next(input)?;
    let length = parse_logical_or.parse_next(input).map_err(ErrMode::cut)?;
    ws0.parse_next(input)?;
    expect_char(input, ')', "expected ')' after $vvalid length")?;
    Ok(Expr::RangeValid(Box::new(address), Box::new(length)))
}

fn parse_cast(input: &mut ExprInput<'_>) -> ParseResult<Expr> {
    let expr_type = parse_cast_type.parse_next(input)?;
    ws0.parse_next(input)?;
    peek(parse_operand_start).parse_next(input)?;
    let base = parse_prefix.parse_next(input).map_err(ErrMode::cut)?;
    Ok(Expr::Cast(Box::new(base), expr_type))
}

fn parse_cast_type(input: &mut ExprInput<'_>) -> ParseResult<ExprType> {
    one_of('(').parse_next(input)?;
    ws0.parse_next(input)?;
    let span = take_till(1.., ')').parse_next(input)?;
    let type_str = span.trim();
    if !Expr::is_type_name(type_str) {
        return Err(ErrMode::Backtrack(error_at(input, "expected expression")));
    }
    let expr_type = Expr::parse_type(type_str)
        .map_err(|_| ErrMode::Cut(error_at(input, "invalid cast type")))?;
    expect_char(input, ')', "expected ')'")?;
    Ok(expr_type)
}

fn parse_atom(input: &mut ExprInput<'_>) -> ParseResult<Expr> {
    alt((
        parse_group,
        parse_masm_scope,
        parse_local_escape,
        parse_register,
        parse_literal_expr,
        parse_symbol_expr,
    ))
    .parse_next(input)
}

/// `@@masm( ... )` names this evaluator explicitly, so a pasted expression
/// that spells out its evaluator still works. `@@( ... )` and `@@c++( ... )`
/// select WinDbg's C++ evaluator, whose pointer arithmetic scales by the
/// pointee size; accepting them here would answer a different question, so
/// they are left to fail.
fn parse_masm_scope(input: &mut ExprInput<'_>) -> ParseResult<Expr> {
    // C++ evaluator scopes use different pointer arithmetic; reject them explicitly.
    for scope in ["@@c++(", "@@("] {
        if input.as_ref().starts_with(scope) {
            return Err(ErrMode::Cut(error_at(
                input,
                "WinDbg's C++ evaluator is not available: it scales pointer arithmetic by the \
                 pointee size and this evaluator does not; use `@@masm( ... )` or drop the prefix",
            )));
        }
    }
    literal("@@masm(").parse_next(input)?;
    ws0.parse_next(input)?;
    let expr = parse_logical_or.parse_next(input).map_err(ErrMode::cut)?;
    ws0.parse_next(input)?;
    expect_char(input, ')', "expected ')' after @@masm expression")?;
    Ok(expr)
}

fn parse_group(input: &mut ExprInput<'_>) -> ParseResult<Expr> {
    one_of('(').parse_next(input)?;
    ws0.parse_next(input)?;
    let expr = parse_logical_or.parse_next(input).map_err(ErrMode::cut)?;
    ws0.parse_next(input)?;
    expect_char(input, ')', "expected ')'")?;
    Ok(expr)
}

fn parse_local_escape(input: &mut ExprInput<'_>) -> ParseResult<Expr> {
    literal("$!").parse_next(input)?;
    let name = parse_local_name
        .parse_next(input)
        .map_err(|_| ErrMode::Cut(error_at(input, "expected source local name after '$!'")))?;
    Ok(Expr::Local(name.to_string()))
}

fn parse_register(input: &mut ExprInput<'_>) -> ParseResult<Expr> {
    let (sigil, span) = one_of(['$', '@']).with_span().parse_next(input)?;
    // WinDbg documents `@$name` for pseudo-registers: the `@` says "this is a
    // register, do not search the symbol table". Both halves are optional
    // there, so accept the combination as the same name.
    let sigil = if sigil == '@' && input.as_ref().starts_with('$') {
        one_of('$').parse_next(input)?
    } else {
        sigil
    };
    let name = parse_register_name.parse_next(input).map_err(|_| {
        ErrMode::Cut(ExprParseError::new(
            span,
            format!("expected register name after '{sigil}'"),
        ))
    })?;
    Ok(Expr::Register(name.to_string()))
}

fn parse_literal_expr(input: &mut ExprInput<'_>) -> ParseResult<Expr> {
    peek(one_of('0'..='9')).parse_next(input)?;
    let value = parse_number_literal(input, "expected numeric literal").map_err(ErrMode::cut)?;
    Ok(Expr::Literal(VirtAddr(value)))
}

fn parse_symbol_expr(input: &mut ExprInput<'_>) -> ParseResult<Expr> {
    let symbol = parse_symbol_name
        .parse_next(input)
        .map_err(|_| ErrMode::Backtrack(error_at(input, "expected expression")))?;
    Ok(Expr::Symbol(symbol.to_string()))
}

fn parse_number_literal(input: &mut ExprInput<'_>, label: &'static str) -> ParseResult<u64> {
    let (token, span) = parse_number_token
        .with_span()
        .parse_next(input)
        .map_err(|_| ErrMode::Backtrack(error_at(input, label)))?;

    parse_number_literal_text(token, input.state)
        .map_err(|label| ErrMode::Cut(ExprParseError::new(span, label)))
}

fn parse_operand_start(input: &mut ExprInput<'_>) -> ParseResult<()> {
    ws0.parse_next(input)?;
    alt((
        one_of(['(', '*', '&', '!', '~', '$', '@']).void(),
        one_of('0'..='9').void(),
        take_while(1.., symbol_char).void(),
    ))
    .parse_next(input)
}

fn parse_register_name<'a>(input: &mut ExprInput<'a>) -> ParseResult<&'a str> {
    take_while(1.., |c: char| c.is_ascii_alphanumeric() || c == '_').parse_next(input)
}

fn parse_local_name<'a>(input: &mut ExprInput<'a>) -> ParseResult<&'a str> {
    take_while(1.., |c: char| {
        c.is_ascii_alphanumeric() || c == '_' || c == '$'
    })
    .parse_next(input)
}

fn parse_field_name<'a>(input: &mut ExprInput<'a>) -> ParseResult<&'a str> {
    take_while(1.., |c: char| {
        !is_expr_boundary(c) && c != ']' && c != '!' && c != '.'
    })
    .parse_next(input)
}

fn parse_symbol_name<'a>(input: &mut ExprInput<'a>) -> ParseResult<&'a str> {
    let remaining = *input.as_ref();
    let mut end = 0;
    let mut chars = remaining.char_indices();
    while let Some((offset, ch)) = chars.next() {
        // A C++ template argument list is part of the name, not a pair of
        // comparisons: real kernel symbols look like
        // `nt!ST_STORE<SM_TRAITS>::StStart`. Only a balanced list whose `>`
        // is followed by `::` counts, so `index<10` in a breakpoint
        // condition stays a comparison.
        if ch == '<'
            && end > 0
            && let Some(len) = template_argument_len(&remaining[offset..])
        {
            for _ in 1..remaining[offset..offset + len].chars().count() {
                chars.next();
            }
            end = offset + len;
            continue;
        }
        let module_extension_dot = ch == '.'
            && remaining[offset + ch.len_utf8()..]
                .find('!')
                .is_some_and(|bang| {
                    remaining[offset + ch.len_utf8()..offset + ch.len_utf8() + bang]
                        .chars()
                        .all(|candidate| !is_expr_boundary(candidate) && candidate != ']')
                });
        if !symbol_char(ch)
            || (ch == '!' && remaining[offset..].starts_with("!="))
            || (ch == '.' && !module_extension_dot)
        {
            break;
        }
        end = offset + ch.len_utf8();
    }
    if end == 0 {
        return Err(ErrMode::Backtrack(error_at(input, "expected symbol")));
    }
    Ok(input.next_slice(end))
}

/// Byte length of the `<...>` template argument list starting at `text`, when
/// it is balanced, contains no whitespace, and is followed by `::`. Anything
/// else is a comparison operator and belongs to the expression.
fn template_argument_len(text: &str) -> Option<usize> {
    let mut depth = 0usize;
    for (offset, ch) in text.char_indices() {
        match ch {
            '<' => depth += 1,
            '>' => {
                depth -= 1;
                if depth == 0 {
                    let end = offset + ch.len_utf8();
                    return text[end..].starts_with("::").then_some(end);
                }
            }
            ch if ch.is_whitespace() => return None,
            _ => {}
        }
    }
    None
}

fn parse_number_token<'a>(input: &mut ExprInput<'a>) -> ParseResult<&'a str> {
    take_while(1.., |c: char| !is_expr_boundary(c) && c != ']' && c != '!').parse_next(input)
}

pub(super) fn ws0(input: &mut ExprInput<'_>) -> ParseResult<()> {
    take_while(0.., char::is_whitespace)
        .void()
        .parse_next(input)
}

fn expect_char(input: &mut ExprInput<'_>, expected: char, label: &'static str) -> ParseResult<()> {
    let parsed: ParseResult<char> = one_of(expected).parse_next(input);
    parsed
        .map(|_| ())
        .map_err(|_| ErrMode::Cut(error_at(input, label)))
}

pub(super) fn error_at(input: &ExprInput<'_>, label: impl Into<String>) -> ExprParseError {
    let start = input.current_token_start();
    let end = input
        .peek_token()
        .map(|ch| start + ch.len_utf8())
        .unwrap_or(start + 1);
    ExprParseError::new(start..end, label)
}

pub(super) fn unwrap_parse_error(err: ErrMode<ExprParseError>) -> ExprParseError {
    match err {
        ErrMode::Backtrack(err) | ErrMode::Cut(err) => err,
        ErrMode::Incomplete(_) => ExprParseError::new(0..1, "incomplete expression"),
    }
}

fn symbol_char(ch: char) -> bool {
    !is_expr_boundary(ch) && ch != ']'
}

fn is_expr_boundary(ch: char) -> bool {
    ch.is_whitespace()
        || matches!(
            ch,
            '(' | ')'
                | '['
                | ','
                | '+'
                | '-'
                | '*'
                | '/'
                | '%'
                | '='
                | '<'
                | '>'
                | '&'
                | '|'
                | '^'
                | '~'
        )
}
