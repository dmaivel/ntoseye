use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::symbols::{ParsedType, SymbolStore};
use crate::target::Target;
use crate::types::{Dtb, VirtAddr};
use crate::ui;
use owo_colors::OwoColorize;
use std::ops::Range;
use winnow::Parser;
use winnow::combinator::{alt, not, peek};
use winnow::error::{ErrMode, ModalResult, ParserError};
use winnow::stream::{LocatingSlice, Location, Stateful, Stream};
use winnow::token::{literal, one_of, take_till, take_while};

#[derive(Debug, Clone, PartialEq)]
pub enum ExprType {
    /// primitive types
    Byte,
    Word,
    Dword,
    Qword,
    /// struct/union type by name
    Struct(String),
    /// pointer to a type
    Pointer(Box<ExprType>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExprUnaryOp {
    LogicalNot,
    BitwiseNot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExprBinaryOp {
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
    LogicalAnd,
    LogicalOr,
    BitwiseAnd,
    BitwiseXor,
    BitwiseOr,
    ShiftLeft,
    ShiftRight,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumberRadix {
    Octal,
    Decimal,
    Hexadecimal,
}

impl NumberRadix {
    pub const fn value(self) -> u32 {
        match self {
            Self::Octal => 8,
            Self::Decimal => 10,
            Self::Hexadecimal => 16,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Literal(VirtAddr),
    Symbol(String),
    /// `$rax`, `$rip`, etc
    Register(String),
    /// `*expr`
    Deref(Box<Expr>),
    /// `expr->field`
    FieldAccess(Box<Expr>, String),
    /// `expr[index]`
    Index(Box<Expr>, u64),
    Add(Box<Expr>, Box<Expr>),
    Sub(Box<Expr>, Box<Expr>),
    Unary(ExprUnaryOp, Box<Expr>),
    Binary(Box<Expr>, ExprBinaryOp, Box<Expr>),
    /// `(TYPE)expr` or `(TYPE*)expr`
    Cast(Box<Expr>, ExprType),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExprParseError {
    pub span: Range<usize>,
    pub label: String,
}

impl ExprParseError {
    fn new(span: Range<usize>, label: impl Into<String>) -> Self {
        Self {
            span,
            label: label.into(),
        }
    }

    pub fn render(&self, input: &str) -> String {
        let start = self.span.start.min(input.len());
        let end = self.span.end.min(input.len()).max(start + 1);
        let caret_width = end.saturating_sub(start).max(1);
        format!(
            "{}\n{}{} {}",
            input,
            " ".repeat(start),
            "^".repeat(caret_width).red(),
            ui::muted(&self.label)
        )
    }
}

impl Expr {
    pub fn eval(input: &str, context: &Target) -> Result<VirtAddr> {
        Self::eval_with_radix(input, context, NumberRadix::Decimal)
    }

    pub fn eval_with_radix(input: &str, context: &Target, radix: NumberRadix) -> Result<VirtAddr> {
        Self::parse_with_radix(input, radix)?.resolve(context)
    }

    pub fn parse(input: &str) -> Result<Self> {
        Self::parse_with_radix(input, NumberRadix::Decimal)
    }

    pub fn parse_with_radix(input: &str, radix: NumberRadix) -> Result<Self> {
        Self::parse_detailed_with_radix(input, radix)
            .map_err(|err| Error::InvalidExpression(err.render(input)))
    }

    pub fn parse_detailed(input: &str) -> std::result::Result<Self, ExprParseError> {
        Self::parse_detailed_with_radix(input, NumberRadix::Decimal)
    }

    pub fn parse_detailed_with_radix(
        input: &str,
        radix: NumberRadix,
    ) -> std::result::Result<Self, ExprParseError> {
        let mut input = Stateful {
            input: LocatingSlice::new(input),
            state: radix,
        };
        let expr = parse_logical_or
            .parse_next(&mut input)
            .map_err(unwrap_parse_error)?;
        ws0.parse_next(&mut input).map_err(unwrap_parse_error)?;
        if input.peek_token().is_some() {
            return Err(error_at(&input, "expected end of expression"));
        }
        Ok(expr)
    }

    fn is_type_name(s: &str) -> bool {
        let s = s.trim().trim_end_matches('*').trim();
        !s.is_empty()
            && s.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
            && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    }

    fn parse_type(type_str: &str) -> Result<ExprType> {
        let type_str = type_str.trim();

        if let Some(stripped) = type_str.strip_suffix('*') {
            let inner_type = Self::parse_type(stripped)?;
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

    pub fn resolve(&self, context: &Target) -> Result<VirtAddr> {
        match self {
            Expr::Literal(addr) => Ok(*addr),

            Expr::Symbol(name) => {
                if let Some(addr) = context
                    .symbols
                    .find_symbol_across_modules(context.current_dtb(), name)?
                {
                    return Ok(addr);
                }
                if let Some(value) = Self::parse_bare_hex_literal(name) {
                    return Ok(VirtAddr(value));
                }
                // A bare `rip`/`rsp` resolves as a register when no symbol matches.
                if let Some(value) = context.register_value(name) {
                    return Ok(VirtAddr(value));
                }
                if let Some(value) = context.builtin_variable_value(name) {
                    return Ok(VirtAddr(value));
                }
                // WinDbg: a bare module name is its base (`? nt`, `u nt+0x1000`).
                if let Some(base) = context
                    .symbols
                    .module_base_by_name(context.current_dtb(), name)
                {
                    return Ok(base);
                }
                Err(Error::SymbolNotFound(name.clone()))
            }

            Expr::Register(name) => {
                // $<digits> -> a volatile result slot ($0..$N) from the most
                // recent result-producing command (search, ev, ...)
                if !name.is_empty() && name.chars().all(|c| c.is_ascii_digit()) {
                    let idx: usize = name.parse().map_err(|_| {
                        Error::InvalidExpression(format!("invalid result index ${name}"))
                    })?;
                    return context
                        .results
                        .get(idx)
                        .copied()
                        .map(VirtAddr)
                        .ok_or_else(|| {
                            Error::InvalidExpression(format!(
                                "no result ${name} ({} available)",
                                context.results.len()
                            ))
                        });
                }

                // a register (predefined) wins over a user variable of the same name
                if let Some(value) = context.register_value(name) {
                    return Ok(VirtAddr(value));
                }

                // a user-defined convenience variable ($name = ...); explicit
                // assignment wins over a builtin of the same name
                if let Some(var) = context.user_vars.get(name) {
                    return Ok(VirtAddr(var.value));
                }

                if let Some(value) = context.builtin_variable_value(name) {
                    return Ok(VirtAddr(value));
                }

                // unknown: if registers are simply unavailable (VM running) the
                // name may well be a register, so surface that hint
                if context.registers.is_none() {
                    return Err(Error::InvalidExpression(
                        "registers unavailable while VM is running".into(),
                    ));
                }
                Err(Error::RegisterNotFound(name.clone()))
            }

            Expr::Deref(inner) => {
                let addr = inner.resolve(context)?;
                let memory = context.context_memory();
                // `*(dword)x` / `*(dword*)x` read a dword; an uncast deref is
                // pointer-sized.
                let val = match Self::deref_width(inner, context) {
                    1 => u64::from(memory.read::<u8>(addr)?),
                    2 => u64::from(memory.read::<u16>(addr)?),
                    4 => u64::from(memory.read::<u32>(addr)?),
                    _ => memory.read::<u64>(addr)?,
                };
                Ok(VirtAddr(val))
            }

            Expr::FieldAccess(base, field_name) => {
                let base_addr = base.resolve(context)?;

                let base_type_name = base
                    .resolve_type(&context.symbols, context.current_dtb())
                    .ok_or_else(|| {
                        Error::InvalidExpression(
                            "field access requires explicit cast: e.g., (TYPE)expr->field".into(),
                        )
                    })?;

                let type_info = context
                    .symbols
                    .find_type_across_modules(context.current_dtb(), &base_type_name)
                    .ok_or_else(|| Error::StructNotFound(base_type_name))?;

                let offset = type_info
                    .field_offset(field_name)
                    .map_err(|_| Error::FieldNotFound(field_name.clone()))?;
                Ok(base_addr + offset)
            }

            Expr::Index(base, index) => {
                let base_addr = base.resolve(context)?;
                let elem_size = Self::resolve_element_size(base, context);
                Ok(base_addr + index.wrapping_mul(elem_size))
            }

            Expr::Add(lhs, rhs) => {
                let base = lhs.resolve(context)?;
                let value = rhs.resolve(context)?;
                Ok(base + value.0)
            }

            Expr::Sub(lhs, rhs) => {
                let base = lhs.resolve(context)?;
                let value = rhs.resolve(context)?;
                Ok(base - value.0)
            }

            Expr::Unary(op, inner) => {
                let value = inner.resolve(context)?.0;
                Ok(VirtAddr(match op {
                    ExprUnaryOp::LogicalNot => u64::from(value == 0),
                    ExprUnaryOp::BitwiseNot => !value,
                }))
            }

            Expr::Binary(lhs, op, rhs) => {
                let left = lhs.resolve(context)?.0;
                match op {
                    ExprBinaryOp::LogicalAnd if left == 0 => Ok(VirtAddr(0)),
                    ExprBinaryOp::LogicalOr if left != 0 => Ok(VirtAddr(1)),
                    _ => {
                        let right = rhs.resolve(context)?.0;
                        let value = match op {
                            ExprBinaryOp::Equal => u64::from(left == right),
                            ExprBinaryOp::NotEqual => u64::from(left != right),
                            ExprBinaryOp::Less => u64::from(left < right),
                            ExprBinaryOp::LessEqual => u64::from(left <= right),
                            ExprBinaryOp::Greater => u64::from(left > right),
                            ExprBinaryOp::GreaterEqual => u64::from(left >= right),
                            ExprBinaryOp::LogicalAnd | ExprBinaryOp::LogicalOr => {
                                u64::from(right != 0)
                            }
                            ExprBinaryOp::BitwiseAnd => left & right,
                            ExprBinaryOp::BitwiseXor => left ^ right,
                            ExprBinaryOp::BitwiseOr => left | right,
                            ExprBinaryOp::ShiftLeft => left.wrapping_shl(right as u32),
                            ExprBinaryOp::ShiftRight => left.wrapping_shr(right as u32),
                        };
                        Ok(VirtAddr(value))
                    }
                }
            }

            Expr::Cast(expr, _) => expr.resolve(context),
        }
    }

    pub fn resolve_type(&self, symbols: &SymbolStore, dtb: Dtb) -> Option<String> {
        match self {
            Expr::Cast(_, expr_type) => Some(Self::expr_type_to_name(expr_type)),
            Expr::FieldAccess(base, field_name) => {
                let base_type_name = base.resolve_type(symbols, dtb)?;
                let type_info = symbols.find_type_across_modules(dtb, &base_type_name)?;
                let field_info = type_info.fields.get(field_name)?;
                Self::struct_type_name(&field_info.type_data)
            }
            _ => None,
        }
    }

    /// Return field names matching a prefix for the type this expression resolves to.
    pub fn complete_fields(&self, symbols: &SymbolStore, dtb: Dtb, prefix: &str) -> Vec<String> {
        let type_name = match self.resolve_type(symbols, dtb) {
            Some(name) => name,
            None => return vec![],
        };
        let type_info = match symbols.find_type_across_modules(dtb, &type_name) {
            Some(info) => info,
            None => return vec![],
        };
        let mut fields: Vec<String> = type_info
            .fields
            .keys()
            .filter(|f| f.starts_with(prefix))
            .cloned()
            .collect();
        fields.sort();
        fields
    }

    /// determine the element size in bytes for array indexing
    /// uses type info from casts (e.g. `(dword*)addr[3]` -> 4 bytes per element)
    fn resolve_element_size(expr: &Expr, context: &Target) -> u64 {
        match expr {
            // `((dword*)p)[i]` strides by the pointee, `((dword)p)[i]` by the
            // cast width.
            Expr::Cast(_, ExprType::Pointer(pointee)) => Self::expr_type_size(pointee, context),
            Expr::Cast(_, expr_type) => Self::expr_type_size(expr_type, context),
            _ => 1,
        }
    }

    /// Bytes a `*expr` reads: the primitive width of a cast on `expr` (through
    /// one pointer level), else pointer-sized.
    fn deref_width(expr: &Expr, context: &Target) -> u64 {
        match expr {
            Expr::Cast(_, ExprType::Pointer(pointee)) => {
                Self::expr_type_size(pointee, context).min(8)
            }
            Expr::Cast(_, ty @ (ExprType::Byte | ExprType::Word | ExprType::Dword)) => {
                Self::expr_type_size(ty, context)
            }
            _ => 8,
        }
    }

    /// falls back to 1 if no type info is available
    fn expr_type_size(expr_type: &ExprType, context: &Target) -> u64 {
        match expr_type {
            ExprType::Byte => 1,
            ExprType::Word => 2,
            ExprType::Dword => 4,
            ExprType::Qword => 8,
            ExprType::Pointer(_) => 8,
            ExprType::Struct(name) => {
                let lookup = if name.starts_with('_') {
                    name.clone()
                } else {
                    format!("_{name}")
                };
                context
                    .symbols
                    .find_type_across_modules(context.current_dtb(), &lookup)
                    .map(|t| t.size as u64)
                    .unwrap_or(1)
            }
        }
    }

    fn expr_type_to_name(expr_type: &ExprType) -> String {
        match expr_type {
            ExprType::Byte => "byte".to_string(),
            ExprType::Word => "word".to_string(),
            ExprType::Dword => "dword".to_string(),
            ExprType::Qword => "qword".to_string(),
            ExprType::Struct(name) => {
                if name.starts_with('_') {
                    name.clone()
                } else {
                    format!("_{name}")
                }
            }
            ExprType::Pointer(inner) => Self::expr_type_to_name(inner),
        }
    }

    fn struct_type_name(type_data: &ParsedType) -> Option<String> {
        match type_data {
            ParsedType::Struct(name) | ParsedType::Union(name) => Some(name.clone()),
            ParsedType::Pointer(inner) => Self::struct_type_name(inner),
            ParsedType::Array(inner, _) => Self::struct_type_name(inner),
            _ => None,
        }
    }

    fn parse_bare_hex_literal(s: &str) -> Option<u64> {
        let s = s.trim();
        let has_hex_letter = s
            .chars()
            .any(|ch| ch.is_ascii_hexdigit() && ch.is_ascii_alphabetic());
        if !has_hex_letter || !s.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return None;
        }
        u64::from_str_radix(s, 16).ok()
    }
}

type ExprInput<'a> = Stateful<LocatingSlice<&'a str>, NumberRadix>;
type ParseResult<T> = ModalResult<T, ExprParseError>;

impl<'a> ParserError<ExprInput<'a>> for ExprParseError {
    type Inner = Self;

    fn from_input(input: &ExprInput<'a>) -> Self {
        error_at(input, "expected expression")
    }

    fn into_inner(self) -> std::result::Result<Self::Inner, Self> {
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

#[derive(Clone, Copy)]
enum AdditiveOp {
    Add,
    Sub,
}

enum Suffix {
    Field(String),
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

fn parse_logical_or(input: &mut ExprInput<'_>) -> ParseResult<Expr> {
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
    literal("|").parse_next(input)?;
    not(literal("|")).parse_next(input)?;
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
    literal("^").parse_next(input)?;
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
    literal("&").parse_next(input)?;
    not(literal("&")).parse_next(input)?;
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
        literal(">>").value(ExprBinaryOp::ShiftRight),
    ))
    .parse_next(input)?;
    let rhs = parse_additive.parse_next(input).map_err(ErrMode::cut)?;
    Ok((op, rhs))
}

fn parse_additive(input: &mut ExprInput<'_>) -> ParseResult<Expr> {
    parse_left_associative(
        input,
        parse_postfix,
        parse_additive_tail,
        |lhs, op, rhs| match op {
            AdditiveOp::Add => Expr::Add(Box::new(lhs), Box::new(rhs)),
            AdditiveOp::Sub => Expr::Sub(Box::new(lhs), Box::new(rhs)),
        },
    )
}

fn parse_additive_tail(input: &mut ExprInput<'_>) -> ParseResult<(AdditiveOp, Expr)> {
    ws0.parse_next(input)?;
    let op = alt((
        literal("+").value(AdditiveOp::Add),
        literal("-").value(AdditiveOp::Sub),
    ))
    .parse_next(input)?;
    let rhs = parse_postfix.parse_next(input).map_err(ErrMode::cut)?;
    Ok((op, rhs))
}

fn parse_postfix(input: &mut ExprInput<'_>) -> ParseResult<Expr> {
    let mut expr = parse_prefix.parse_next(input)?;
    loop {
        let checkpoint = input.checkpoint();
        match alt((parse_field_suffix, parse_index_suffix)).parse_next(input) {
            Ok(Suffix::Field(field)) => expr = Expr::FieldAccess(Box::new(expr), field),
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
    literal("->").parse_next(input)?;
    ws0.parse_next(input)?;
    let field = parse_field_name
        .parse_next(input)
        .map_err(|_| ErrMode::Cut(error_at(input, "expected field name after '->'")))?;
    Ok(Suffix::Field(field.to_string()))
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
        parse_unary_prefix,
        parse_deref_prefix,
        parse_poi,
        parse_cast,
        parse_atom,
    ))
    .parse_next(input)
}

fn parse_unary_prefix(input: &mut ExprInput<'_>) -> ParseResult<Expr> {
    let op = alt((
        literal("!").value(ExprUnaryOp::LogicalNot),
        literal("~").value(ExprUnaryOp::BitwiseNot),
    ))
    .parse_next(input)?;
    let inner = parse_prefix.parse_next(input).map_err(ErrMode::cut)?;
    Ok(Expr::Unary(op, Box::new(inner)))
}

fn parse_deref_prefix(input: &mut ExprInput<'_>) -> ParseResult<Expr> {
    one_of('*').parse_next(input)?;
    let inner = parse_prefix.parse_next(input).map_err(ErrMode::cut)?;
    Ok(Expr::Deref(Box::new(inner)))
}

fn parse_poi(input: &mut ExprInput<'_>) -> ParseResult<Expr> {
    literal("poi").parse_next(input)?;
    ws0.parse_next(input)?;
    one_of('(').parse_next(input)?;
    ws0.parse_next(input)?;
    let inner = parse_logical_or.parse_next(input).map_err(ErrMode::cut)?;
    ws0.parse_next(input)?;
    expect_char(input, ')', "expected ')' after poi expression")?;
    Ok(Expr::Deref(Box::new(inner)))
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
        parse_register,
        parse_literal_expr,
        parse_symbol_expr,
    ))
    .parse_next(input)
}

fn parse_group(input: &mut ExprInput<'_>) -> ParseResult<Expr> {
    one_of('(').parse_next(input)?;
    ws0.parse_next(input)?;
    let expr = parse_logical_or.parse_next(input).map_err(ErrMode::cut)?;
    ws0.parse_next(input)?;
    expect_char(input, ')', "expected ')'")?;
    Ok(expr)
}

fn parse_register(input: &mut ExprInput<'_>) -> ParseResult<Expr> {
    let (sigil, span) = one_of(['$', '@']).with_span().parse_next(input)?;
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

    if token.starts_with("0x") || token.starts_with("0X") {
        return u64::from_str_radix(&token[2..], 16)
            .map_err(|_| ErrMode::Cut(ExprParseError::new(span, "invalid hex literal")));
    }
    if token.starts_with("0b") || token.starts_with("0B") {
        return u64::from_str_radix(&token[2..], 2)
            .map_err(|_| ErrMode::Cut(ExprParseError::new(span, "invalid binary literal")));
    }
    if token.starts_with("0n") || token.starts_with("0N") {
        return token[2..]
            .parse::<u64>()
            .map_err(|_| ErrMode::Cut(ExprParseError::new(span, "invalid decimal literal")));
    }
    u64::from_str_radix(token, input.state.value())
        .map_err(|_| ErrMode::Cut(ExprParseError::new(span, "invalid numeric literal")))
}

fn parse_operand_start(input: &mut ExprInput<'_>) -> ParseResult<()> {
    ws0.parse_next(input)?;
    alt((
        one_of(['(', '*', '!', '~', '$', '@']).void(),
        one_of('0'..='9').void(),
        take_while(1.., symbol_char).void(),
    ))
    .parse_next(input)
}

fn parse_register_name<'a>(input: &mut ExprInput<'a>) -> ParseResult<&'a str> {
    take_while(1.., |c: char| c.is_ascii_alphanumeric() || c == '_').parse_next(input)
}

fn parse_field_name<'a>(input: &mut ExprInput<'a>) -> ParseResult<&'a str> {
    take_while(1.., |c: char| !is_expr_boundary(c) && c != ']' && c != '!').parse_next(input)
}

fn parse_symbol_name<'a>(input: &mut ExprInput<'a>) -> ParseResult<&'a str> {
    let remaining = *input.as_ref();
    let mut end = 0;
    for (offset, ch) in remaining.char_indices() {
        if !symbol_char(ch) || (ch == '!' && remaining[offset..].starts_with("!=")) {
            break;
        }
        end = offset + ch.len_utf8();
    }
    if end == 0 {
        return Err(ErrMode::Backtrack(error_at(input, "expected symbol")));
    }
    Ok(input.next_slice(end))
}

fn parse_number_token<'a>(input: &mut ExprInput<'a>) -> ParseResult<&'a str> {
    take_while(1.., |c: char| !is_expr_boundary(c) && c != ']' && c != '!').parse_next(input)
}

fn ws0(input: &mut ExprInput<'_>) -> ParseResult<()> {
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

fn error_at(input: &ExprInput<'_>, label: impl Into<String>) -> ExprParseError {
    let start = input.current_token_start();
    let end = input
        .peek_token()
        .map(|ch| start + ch.len_utf8())
        .unwrap_or(start + 1);
    ExprParseError::new(start..end, label)
}

fn unwrap_parse_error(err: ErrMode<ExprParseError>) -> ExprParseError {
    match err {
        ErrMode::Backtrack(err) | ErrMode::Cut(err) => err,
        ErrMode::Incomplete(_) => ExprParseError::new(0..1, "incomplete expression"),
    }
}

fn symbol_char(ch: char) -> bool {
    !is_expr_boundary(ch) && ch != '*' && ch != ']'
}

fn is_expr_boundary(ch: char) -> bool {
    ch.is_whitespace()
        || matches!(
            ch,
            '(' | ')' | '[' | '+' | '-' | '=' | '<' | '>' | '&' | '|' | '^' | '~'
        )
}

#[cfg(test)]
mod tests;
