use crate::error::{Error, Result};
use crate::layout::ParsedType;
use crate::target::Target;
use crate::types::VirtAddr;
use std::borrow::Cow;
use std::ops::Range;
use std::result;
use winnow::Parser;
use winnow::stream::{LocatingSlice, Stateful, Stream};

mod eval;
mod parser;

use parser::{error_at, parse_logical_or, unwrap_parse_error, ws0};

#[derive(Debug, Clone, PartialEq)]
pub enum ExprType {
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
    /// `-expr`. MASM computes in ULONG64, so this wraps.
    Negate,
    /// `hi expr`: the high 16 bits of the low 32.
    HighWord,
    /// `low expr`: the low 16 bits.
    LowWord,
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
    /// `>>>`: sign-preserving right shift.
    ShiftRightArithmetic,
    /// `+`. MASM computes in ULONG64, so this wraps.
    Add,
    /// `-`. Wraps like [`ExprBinaryOp::Add`]; no pointee scaling.
    Sub,
    Multiply,
    Divide,
    Modulo,
}

/// MASM's string operators. Their operands are quoted literals, so they are
/// kept apart from the numeric operator tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringOp {
    /// `$scmp`: `strcmp`, so -1, 0, or 1.
    Compare,
    /// `$sicmp`: `stricmp`.
    CompareIgnoreCase,
    /// `$spat`: case-insensitive wildcard match, 1 or 0.
    Match,
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
    /// A source local selected explicitly with `$!name`.
    Local(String),
    /// `$rax`, `$rip`, etc
    Register(String),
    /// `*expr`
    Deref(Box<Expr>),
    /// A raw memory read of a fixed width in bytes, ignoring any source type:
    /// `by` (1), `wo` (2), `dwo` (4), `qwo` and `poi` (8).
    Read(u8, Box<Expr>),
    /// The same read against physical memory: `$pby`, `$pwo`, `$pdwo`,
    /// `$pqwo`, `$ppoi`.
    ReadPhysical(u8, Box<Expr>),
    /// `$vvalid(address, length)`: 1 when every byte of the range reads.
    RangeValid(Box<Expr>, Box<Expr>),
    /// `$iment(base)`: the entry point recorded in a loaded image's PE header.
    ImageEntry(Box<Expr>),
    /// `$scmp`, `$sicmp`, and `$spat`: MASM's string operators, whose
    /// operands are literals rather than expressions.
    StringOp(StringOp, String, String),
    /// `&expr`, the storage address of an addressable value.
    Address(Box<Expr>),
    /// `expr->field`, which requires a pointer rather than an aggregate.
    FieldAccess(Box<Expr>, String),
    /// `expr.field`, which requires an aggregate object rather than a pointer.
    MemberAccess(Box<Expr>, String),
    /// `expr[index]`
    Index(Box<Expr>, u64),
    Unary(ExprUnaryOp, Box<Expr>),
    Binary(Box<Expr>, ExprBinaryOp, Box<Expr>),
    /// `(TYPE)expr` or `(TYPE*)expr`
    Cast(Box<Expr>, ExprType),
}

/// A value produced by expression evaluation.
///
/// Raw expressions intentionally remain address/u64 oriented. Typed values
/// retain their source type and storage class so callers can choose between a
/// numeric read (`scalar`) and an aggregate expansion (`address` + `type_data`)
/// without evaluating the expression twice.
#[derive(Debug, Clone, PartialEq)]
pub enum ExprValue {
    /// An untyped value.  `address` is set only for storage-like raw symbols
    /// and module bases; literals, registers, convenience variables, and poi
    /// results are deliberately not addressable.
    Raw {
        value: VirtAddr,
        address: Option<VirtAddr>,
    },
    /// A typed value stored in target memory.
    Memory {
        address: VirtAddr,
        type_data: ParsedType,
        byte_size: Option<u64>,
    },
    /// A typed value held in a register. Aggregates may be represented here
    /// for DAP, but cannot be converted to a scalar or storage address.
    Register {
        value: VirtAddr,
        type_data: ParsedType,
        byte_size: Option<u64>,
        name: String,
    },
    /// A typed value with no storage (for example, a pointer cast).
    Immediate {
        value: VirtAddr,
        type_data: ParsedType,
        byte_size: Option<u64>,
    },
    /// A binding exists but DIA/PDB did not provide a usable value location.
    Unavailable {
        type_data: Option<ParsedType>,
        byte_size: Option<u64>,
        reason: String,
    },
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

    /// The input with a caret line under the offending span. Plain text: it
    /// travels inside [`Error::InvalidExpression`] to every host, including
    /// Python exception messages.
    pub fn render(&self, input: &str) -> String {
        let start = self.span.start.min(input.len());
        let end = self.span.end.min(input.len()).max(start + 1);
        let caret_width = end.saturating_sub(start).max(1);
        format!(
            "{input}\n{}{} {}",
            " ".repeat(start),
            "^".repeat(caret_width),
            self.label
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

    pub fn parse_detailed(input: &str) -> result::Result<Self, ExprParseError> {
        Self::parse_detailed_with_radix(input, NumberRadix::Decimal)
    }

    pub fn parse_detailed_with_radix(
        input: &str,
        radix: NumberRadix,
    ) -> result::Result<Self, ExprParseError> {
        // A lone `.` conflicts with member access; report the replacement syntax.
        if input.trim() == "." {
            return Err(ExprParseError::new(
                0..input.len(),
                "'.' is the member operator here, not WinDbg's shorthand for the current \
                 instruction; use `$ip`",
            ));
        }
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
}

/// Parse a MASM numeric literal, returning the label of the failure it is not.
///
/// `0x` hexadecimal, `0n` decimal, `0t` octal, and `0y` binary (`0b` stays
/// accepted as a synonym for `0y`) each override `radix`, as does a trailing
/// `h`; everything else reads in `radix`. Every command that takes a bare
/// number goes through this, so the prefixes mean the same thing in an
/// expression and in an option argument like `bp /p`.
pub fn parse_number_literal_text(
    token: &str,
    radix: NumberRadix,
) -> result::Result<u64, &'static str> {
    // A token carrying WinDbg's address separator is hexadecimal whatever the
    // session radix is: the separator only ever appears in a 64-bit address,
    // which the debugger always prints in hex.
    let separated = token.contains('`');
    let token = strip_digit_separators(token);
    let token = token.as_ref();
    if token.is_empty() {
        return Err("invalid numeric literal");
    }

    // A prefix with no digits reads as zero, as the reference spells out:
    // `0x` == `0`.
    for (prefix, prefix_radix, label) in [
        ("0x", 16u32, "invalid hex literal"),
        ("0n", 10, "invalid decimal literal"),
        ("0t", 8, "invalid octal literal"),
        ("0y", 2, "invalid binary literal"),
        ("0b", 2, "invalid binary literal"),
    ] {
        let Some(digits) = strip_prefix_ignore_case(token, prefix) else {
            continue;
        };
        if digits.is_empty() {
            return Ok(0);
        }
        return u64::from_str_radix(digits, prefix_radix).map_err(|_| label);
    }
    // A trailing `h` is MASM's other spelling of a hexadecimal literal:
    // `4ab3h` == `0x4ab3`.
    if let Some(digits) = token
        .strip_suffix('h')
        .or_else(|| token.strip_suffix('H'))
        .filter(|digits| !digits.is_empty())
    {
        return u64::from_str_radix(digits, 16).map_err(|_| "invalid hex literal");
    }
    let radix = if separated { 16 } else { radix.value() };
    u64::from_str_radix(token, radix).map_err(|_| "invalid numeric literal")
}

fn strip_prefix_ignore_case<'a>(token: &'a str, prefix: &str) -> Option<&'a str> {
    let candidate = token.get(..prefix.len())?;
    candidate
        .eq_ignore_ascii_case(prefix)
        .then(|| &token[prefix.len()..])
}

/// Remove WinDbg's `` ` `` address separator, borrowing separator-free input.
fn strip_digit_separators(token: &str) -> Cow<'_, str> {
    if token.contains('`') {
        Cow::Owned(token.replace('`', ""))
    } else {
        Cow::Borrowed(token)
    }
}

#[cfg(test)]
mod tests;
