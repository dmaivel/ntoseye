use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::symbols::{
    LocalVariableLocation, ParsedType, ProcedureLocal, SymbolStore, TypeInfo, glob_matches,
};
use crate::target::Target;
use crate::types::{Dtb, VirtAddr};
use std::borrow::Cow;
use std::cmp::Ordering;
use std::ops::Range;
use std::result;
use std::sync::Arc;
use winnow::Parser;
use winnow::combinator::{alt, not, peek};
use winnow::error::{ErrMode, ModalResult, ParserError};
use winnow::stream::{LocatingSlice, Location, Stateful, Stream};
use winnow::token::{literal, one_of, take_till, take_while};

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

    fn is_type_name(s: &str) -> bool {
        let mut s = s.trim();
        while let Some(stripped) = s.strip_suffix('*') {
            s = stripped.trim_end();
        }
        !s.is_empty()
            && s.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
            && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
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

    /// Resolve an expression to a value that retains its type and storage
    /// class. Numeric consumers should call [`ExprValue::scalar`], while
    /// aggregate consumers can use [`ExprValue::address`] and
    /// [`ExprValue::type_data`] without evaluating the expression again.
    pub fn evaluate(&self, context: &Target) -> Result<ExprValue> {
        match self {
            Expr::Literal(value) => Ok(ExprValue::Raw {
                value: *value,
                address: None,
            }),
            Expr::Symbol(name) => Self::evaluate_symbol(name, context),
            Expr::Local(name) => Self::evaluate_local(name, context),
            Expr::Register(name) => Self::evaluate_register(name, context),
            Expr::Deref(inner) => Self::evaluate_deref(inner, context),
            Expr::Read(width, inner) => Self::evaluate_read(*width, inner, context),
            Expr::ReadPhysical(width, inner) => {
                Self::evaluate_physical_read(*width, inner, context)
            }
            Expr::RangeValid(address, length) => {
                let address = address.evaluate(context)?.scalar(context)?;
                let length = length.evaluate(context)?.scalar(context)?.0;
                Ok(ExprValue::Raw {
                    value: VirtAddr(u64::from(Self::range_is_readable(address, length, context))),
                    address: None,
                })
            }
            Expr::ImageEntry(base) => {
                let base = base.evaluate(context)?.scalar(context)?;
                Ok(ExprValue::Raw {
                    value: Self::image_entry_point(base, context)?,
                    address: None,
                })
            }
            Expr::StringOp(op, left, right) => {
                let value = match op {
                    StringOp::Compare => Self::ordering_value(left.as_str().cmp(right.as_str())),
                    StringOp::CompareIgnoreCase => Self::ordering_value(
                        left.to_ascii_lowercase().cmp(&right.to_ascii_lowercase()),
                    ),
                    StringOp::Match => u64::from(glob_matches(right, left, true)),
                };
                Ok(ExprValue::Raw {
                    value: VirtAddr(value),
                    address: None,
                })
            }
            Expr::Address(inner) => {
                let value = inner.evaluate(context)?;
                let address = value.address()?;
                if let Some(type_data) = value.type_data().cloned() {
                    Ok(ExprValue::Immediate {
                        value: address,
                        type_data: ParsedType::Pointer(Box::new(type_data)),
                        byte_size: Some(8),
                    })
                } else {
                    Ok(ExprValue::Raw {
                        value: address,
                        address: None,
                    })
                }
            }
            Expr::FieldAccess(base, field_name) => {
                Self::evaluate_field(base, field_name, true, context)
            }
            Expr::MemberAccess(base, field_name) => {
                Self::evaluate_field(base, field_name, false, context)
            }
            Expr::Index(base, index) => Self::evaluate_index(base, *index, context),
            Expr::Unary(op, inner) => {
                // WinDbg uses `!name` for symbols; here `!` negates.
                // Reject ambiguous names instead of silently choosing an interpretation.
                if matches!(op, ExprUnaryOp::LogicalNot)
                    && let Expr::Symbol(name) = inner.as_ref()
                    && !name.contains('!')
                {
                    return Err(Error::InvalidExpression(format!(
                        "'!{name}' is ambiguous: WinDbg reads a leading '!' as a symbol \
                         qualifier. Write 'not {name}' or '!({name})' to negate, or \
                         'module!{name}' for the symbol"
                    )));
                }
                let value = inner.evaluate(context)?.scalar(context)?.0;
                let value = match op {
                    ExprUnaryOp::LogicalNot => u64::from(value == 0),
                    ExprUnaryOp::BitwiseNot => !value,
                    ExprUnaryOp::Negate => value.wrapping_neg(),
                    ExprUnaryOp::HighWord => (value >> 16) & 0xffff,
                    ExprUnaryOp::LowWord => value & 0xffff,
                };
                Ok(ExprValue::Raw {
                    value: VirtAddr(value),
                    address: None,
                })
            }
            Expr::Binary(lhs, op, rhs) => {
                let left = lhs.evaluate(context)?.scalar(context)?.0;
                match op {
                    ExprBinaryOp::LogicalAnd if left == 0 => Ok(ExprValue::Raw {
                        value: VirtAddr(0),
                        address: None,
                    }),
                    ExprBinaryOp::LogicalOr if left != 0 => Ok(ExprValue::Raw {
                        value: VirtAddr(1),
                        address: None,
                    }),
                    _ => {
                        let right = rhs.evaluate(context)?.scalar(context)?.0;
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
                            ExprBinaryOp::ShiftRightArithmetic => {
                                ((left as i64).wrapping_shr(right as u32)) as u64
                            }
                            ExprBinaryOp::Add => left.wrapping_add(right),
                            ExprBinaryOp::Sub => left.wrapping_sub(right),
                            ExprBinaryOp::Multiply => left.wrapping_mul(right),
                            ExprBinaryOp::Divide | ExprBinaryOp::Modulo if right == 0 => {
                                return Err(Error::InvalidExpression("division by zero".into()));
                            }
                            ExprBinaryOp::Divide => left / right,
                            ExprBinaryOp::Modulo => left % right,
                        };
                        Ok(ExprValue::Raw {
                            value: VirtAddr(value),
                            address: None,
                        })
                    }
                }
            }
            Expr::Cast(expr, expr_type) => Self::evaluate_cast(expr, expr_type, context),
        }
    }

    fn evaluate_symbol(name: &str, context: &Target) -> Result<ExprValue> {
        // A qualified name is always a module symbol. In particular, a module
        // called `driver.sys` must not be split into a source member access.
        if name.contains('!') {
            let value = context
                .symbols
                .find_symbol_across_modules(context.current_dtb(), name)?
                .ok_or_else(|| Error::SymbolNotFound(name.to_string()))?;
            return Ok(ExprValue::Raw {
                value,
                address: Some(value),
            });
        }

        // WinDbg resolves an unqualified name by scope: the innermost source
        // binding wins, and the outer namespaces are consulted only when no
        // local matches. `module!name`, `@reg`, and `0x...` name the outer
        // interpretations explicitly; `$!name` asserts the local.
        if let Some(local) = Self::find_local_in_scope(name, context)? {
            return Self::materialize_local(local, context);
        }
        if let Some(value) = context
            .symbols
            .find_symbol_across_modules(context.current_dtb(), name)?
        {
            return Ok(ExprValue::Raw {
                value,
                address: Some(value),
            });
        }
        if let Some(value) = Self::parse_bare_hex_literal(name).map(VirtAddr) {
            return Ok(ExprValue::Raw {
                value,
                address: None,
            });
        }
        if let Some(value) = context.register_value(name).map(VirtAddr) {
            return Ok(ExprValue::Raw {
                value,
                address: None,
            });
        }
        if let Some(value) = context.builtin_variable_value(name).map(VirtAddr) {
            return Ok(ExprValue::Raw {
                value,
                address: None,
            });
        }
        if let Some(value) = context
            .symbols
            .module_base_by_name(context.current_dtb(), name)
        {
            return Ok(ExprValue::Raw {
                value,
                address: Some(value),
            });
        }
        Err(Error::SymbolNotFound(name.to_string()))
    }

    fn evaluate_register(name: &str, context: &Target) -> Result<ExprValue> {
        // `$<digits>` names a volatile result slot, not a CPU register.
        if !name.is_empty() && name.chars().all(|ch| ch.is_ascii_digit()) {
            let idx: usize = name
                .parse()
                .map_err(|_| Error::InvalidExpression(format!("invalid result index ${name}")))?;
            let value = context
                .results
                .get(idx)
                .copied()
                .map(VirtAddr)
                .ok_or_else(|| {
                    Error::InvalidExpression(format!(
                        "no result ${name} ({} available)",
                        context.results.len()
                    ))
                })?;
            return Ok(ExprValue::Raw {
                value,
                address: None,
            });
        }

        if let Some(value) = context.register_value(name) {
            return Ok(ExprValue::Raw {
                value: VirtAddr(value),
                address: None,
            });
        }
        if let Some(var) = context.user_vars.get(name) {
            return Ok(ExprValue::Raw {
                value: VirtAddr(var.value),
                address: None,
            });
        }
        match context.builtin_variable(name) {
            Some(Some(value)) => {
                return Ok(ExprValue::Raw {
                    value: VirtAddr(value),
                    address: None,
                });
            }
            // Distinguish unavailable state from an unknown register name.
            Some(None) => {
                return Err(Error::InvalidExpression(format!(
                    "'${name}' is not available here: the pseudo-register exists, but the state \
                     behind it is unknown at this stop"
                )));
            }
            None => {}
        }
        // `$exentry` is the PE entry point of the process context's executable.
        // The image base is target state, but decoding the header is this
        // evaluator's job, so the two halves meet here rather than in `Target`.
        if name.eq_ignore_ascii_case("exentry")
            && let Some(base) = context.builtin_variable_value("imagebase")
        {
            return Ok(ExprValue::Raw {
                value: Self::image_entry_point(VirtAddr(base), context)?,
                address: None,
            });
        }
        // Breakpoint addresses belong to the host; direct users to its listing.
        if let Some(index) = name.strip_prefix("bp")
            && !index.is_empty()
            && index.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(Error::InvalidExpression(format!(
                "'${name}' is not available: breakpoint state belongs to the debugger, not the \
                 evaluator; use `bl` to list breakpoints and their addresses"
            )));
        }
        if context.registers.is_none() {
            return Err(Error::InvalidExpression(
                "registers unavailable while VM is running".into(),
            ));
        }
        Err(Error::RegisterNotFound(name.to_string()))
    }

    fn evaluate_local(name: &str, context: &Target) -> Result<ExprValue> {
        let local = Self::find_local(name, context)?.ok_or_else(|| {
            Error::InvalidExpression(format!("source local '{name}' is not in scope"))
        })?;
        Self::materialize_local(local, context)
    }

    fn active_locals(context: &Target) -> Result<Option<Arc<Vec<ProcedureLocal>>>> {
        let address = context
            .selected_frame
            .as_ref()
            .map(|frame| frame.ip)
            .or_else(|| context.register_value("rip"))
            .or_else(|| context.register_value("pc"));
        let Some(address) = address else {
            return Ok(None);
        };
        context.procedure_locals(VirtAddr(address))
    }

    /// Locals of the selected frame, for resolving a bare identifier. A frame
    /// without private symbols, or a PDB whose local scopes cannot be read,
    /// must not stop an otherwise resolvable symbol from resolving, so a scan
    /// failure reads as "no local of that name".
    fn find_local_in_scope(name: &str, context: &Target) -> Result<Option<ProcedureLocal>> {
        match Self::active_locals(context) {
            Ok(Some(locals)) => Self::pick_local(&locals, name),
            Ok(None) | Err(_) => Ok(None),
        }
    }

    fn find_local(name: &str, context: &Target) -> Result<Option<ProcedureLocal>> {
        let Some(locals) = Self::active_locals(context)? else {
            return Ok(None);
        };
        Self::pick_local(&locals, name)
    }

    fn pick_local(locals: &[ProcedureLocal], name: &str) -> Result<Option<ProcedureLocal>> {
        let mut matches = locals.iter().filter(|local| local.name == name);
        let Some(first) = matches.next() else {
            return Ok(None);
        };
        if matches.next().is_some() {
            return Err(Error::InvalidExpression(format!(
                "source local '{name}' is ambiguous; debug metadata did not identify an innermost binding"
            )));
        }
        Ok(Some(first.clone()))
    }

    fn materialize_local(local: ProcedureLocal, context: &Target) -> Result<ExprValue> {
        let type_data = local.type_data.clone();
        let byte_size = local.byte_size;
        match &local.location {
            LocalVariableLocation::Register { register } => {
                let Some(value) = context.register_value(register) else {
                    return Ok(ExprValue::Unavailable {
                        type_data: Some(type_data.clone()),
                        byte_size,
                        reason: format!("register {register} is unavailable"),
                    });
                };
                Ok(ExprValue::Register {
                    value: VirtAddr(value),
                    type_data,
                    byte_size,
                    name: register.clone(),
                })
            }
            LocalVariableLocation::RegisterRelative { .. }
            | LocalVariableLocation::FrameRelative { .. } => {
                let Some(address) = context.procedure_local_address(&local).map(VirtAddr) else {
                    return Ok(ExprValue::Unavailable {
                        type_data: Some(type_data.clone()),
                        byte_size,
                        reason: "local storage address is unavailable".into(),
                    });
                };
                Ok(ExprValue::Memory {
                    address,
                    type_data,
                    byte_size,
                })
            }
            LocalVariableLocation::Unavailable { reason } => Ok(ExprValue::Unavailable {
                type_data: Some(type_data),
                byte_size,
                reason: reason.clone(),
            }),
        }
    }

    fn evaluate_read(width: u8, inner: &Expr, context: &Target) -> Result<ExprValue> {
        let address = inner.evaluate(context)?.scalar(context)?;
        let value = Self::read_integer(&context.context_memory(), address, u64::from(width))?;
        Ok(ExprValue::Raw {
            value: VirtAddr(value),
            address: None,
        })
    }

    /// MASM's `$p*` operators take a physical address, bypassing the page
    /// tables the virtual reads walk.
    fn evaluate_physical_read(width: u8, inner: &Expr, context: &Target) -> Result<ExprValue> {
        let address = inner.evaluate(context)?.scalar(context)?;
        let mut bytes = [0u8; 8];
        let width = usize::from(width);
        context.phys.read_bytes(address.0, &mut bytes[..width])?;
        Ok(ExprValue::Raw {
            value: VirtAddr(u64::from_le_bytes(bytes)),
            address: None,
        })
    }

    /// Whether every byte of `address..address+length` reads. Walked in
    /// chunks so a caller-supplied length cannot drive a large allocation,
    /// and stopped at the first unreadable chunk.
    fn range_is_readable(address: VirtAddr, length: u64, context: &Target) -> bool {
        if length == 0 {
            return true;
        }
        let memory = context.context_memory();
        let mut buffer = [0u8; 256];
        let mut offset = 0u64;
        while offset < length {
            let chunk = (length - offset).min(buffer.len() as u64) as usize;
            let Some(start) = address.0.checked_add(offset) else {
                return false;
            };
            if memory
                .read_bytes(VirtAddr(start), &mut buffer[..chunk])
                .is_err()
            {
                return false;
            }
            offset += chunk as u64;
        }
        true
    }

    fn evaluate_deref(inner: &Expr, context: &Target) -> Result<ExprValue> {
        let value = inner.evaluate(context)?;
        let scalar = value.scalar(context)?;

        if let Some(ParsedType::Pointer(pointee)) = value.type_data() {
            let byte_size = Self::parsed_type_size(pointee, None, context).ok();
            return Ok(ExprValue::Memory {
                address: scalar,
                type_data: (**pointee).clone(),
                byte_size,
            });
        }

        if value.type_data().is_some() {
            return Err(Error::InvalidExpression(
                "typed dereference requires a pointer; use *((TYPE*)address) or poi(address)"
                    .into(),
            ));
        }

        let read = context.context_memory().read::<u64>(scalar)?;
        Ok(ExprValue::Raw {
            value: VirtAddr(read),
            address: None,
        })
    }

    fn evaluate_field(
        base: &Expr,
        field_name: &str,
        indirect: bool,
        context: &Target,
    ) -> Result<ExprValue> {
        let value = base.evaluate(context)?;
        let (address, type_data) = match &value {
            ExprValue::Memory {
                address, type_data, ..
            } => match (indirect, type_data) {
                (true, ParsedType::Pointer(pointee)) => {
                    (value.scalar(context)?, (**pointee).clone())
                }
                (true, _) => {
                    return Err(Error::InvalidExpression(
                        "pointer member access requires a typed pointer".into(),
                    ));
                }
                (false, ParsedType::Pointer(_)) => {
                    return Err(Error::InvalidExpression(
                        "aggregate member access requires a typed aggregate; use -> for pointers"
                            .into(),
                    ));
                }
                (false, _) => (*address, type_data.clone()),
            },
            ExprValue::Immediate {
                type_data: ParsedType::Pointer(pointee),
                ..
            }
            | ExprValue::Register {
                type_data: ParsedType::Pointer(pointee),
                ..
            } if indirect => (value.scalar(context)?, (**pointee).clone()),
            ExprValue::Immediate { .. } | ExprValue::Register { .. } => {
                return Err(Error::InvalidExpression(
                    "aggregate member access requires a memory-resident object".into(),
                ));
            }
            ExprValue::Unavailable { .. } => return Ok(value),
            _ => {
                return Err(Error::InvalidExpression(
                    if indirect {
                        "pointer member access requires a typed pointer; cast an address as (TYPE*)address"
                    } else {
                        "aggregate member access requires a typed aggregate"
                    }
                    .into(),
                ));
            }
        };
        Self::project_field(address, &type_data, field_name, context)
    }

    /// `strcmp`'s three-valued result, with MASM's ULONG64 spelling of -1.
    fn ordering_value(ordering: Ordering) -> u64 {
        match ordering {
            Ordering::Less => u64::MAX,
            Ordering::Equal => 0,
            Ordering::Greater => 1,
        }
    }

    /// The entry point of the image mapped at `base`, read out of its PE
    /// header the way WinDbg's `$iment` does. `AddressOfEntryPoint` sits at
    /// the same offset in PE32 and PE32+, so one path covers both.
    fn image_entry_point(base: VirtAddr, context: &Target) -> Result<VirtAddr> {
        let memory = context.context_memory();
        let not_an_image = || Error::InvalidExpression(format!("no PE image at {:#x}", base.0));
        if memory.read::<u16>(base)? != 0x5a4d {
            return Err(not_an_image());
        }
        let lfanew = u64::from(memory.read::<u32>(base + 0x3cu64)?);
        if lfanew == 0 || lfanew > 0x1000 {
            return Err(not_an_image());
        }
        let headers = base + lfanew;
        if memory.read::<u32>(headers)? != 0x0000_4550 {
            return Err(not_an_image());
        }
        let entry = u64::from(memory.read::<u32>(headers + 0x28u64)?);
        // A DLL without an entry point records zero; WinDbg reports the
        // header value rather than inventing an address.
        Ok(if entry == 0 {
            VirtAddr(0)
        } else {
            base + entry
        })
    }

    /// Resolve `field_name` against an aggregate at `address`.
    fn project_field(
        address: VirtAddr,
        type_data: &ParsedType,
        field_name: &str,
        context: &Target,
    ) -> Result<ExprValue> {
        let type_name = match type_data {
            ParsedType::Struct(name) | ParsedType::Union(name) => name,
            _ => {
                return Err(Error::InvalidExpression(
                    "field access requires a typed aggregate; cast an address as (TYPE*)address"
                        .into(),
                ));
            }
        };
        let type_info = Self::find_type(context, type_name)
            .ok_or_else(|| Error::StructNotFound(type_name.clone()))?;
        let field = type_info
            .fields
            .get(field_name)
            .ok_or_else(|| Error::FieldNotFound(field_name.to_string()))?;
        let byte_size = if field.size == 0 {
            Self::parsed_type_size(&field.type_data, None, context).ok()
        } else {
            Some(field.size)
        };
        Ok(ExprValue::Memory {
            address: address + u64::from(field.offset),
            type_data: field.type_data.clone(),
            byte_size,
        })
    }

    fn evaluate_index(base: &Expr, index: u64, context: &Target) -> Result<ExprValue> {
        let value = base.evaluate(context)?;
        match &value {
            ExprValue::Memory {
                address,
                type_data: ParsedType::Array(inner, count),
                byte_size,
            } => {
                let element_size =
                    Self::array_element_size(inner.as_ref(), *byte_size, *count, context)?;
                Ok(ExprValue::Memory {
                    address: *address + index.wrapping_mul(element_size),
                    type_data: (**inner).clone(),
                    byte_size: Some(element_size),
                })
            }
            ExprValue::Memory {
                type_data: ParsedType::Pointer(inner),
                ..
            }
            | ExprValue::Immediate {
                type_data: ParsedType::Pointer(inner),
                ..
            }
            | ExprValue::Register {
                type_data: ParsedType::Pointer(inner),
                ..
            } => {
                let address = value.scalar(context)?;
                let element_size = Self::parsed_type_size(inner.as_ref(), None, context)?;
                Ok(ExprValue::Memory {
                    address: address + index.wrapping_mul(element_size),
                    type_data: (**inner).clone(),
                    byte_size: Some(element_size),
                })
            }
            ExprValue::Raw { value, address } => Ok(ExprValue::Raw {
                value: VirtAddr(value.0.wrapping_add(index)),
                address: (*address).map(|base| VirtAddr(base.0.wrapping_add(index))),
            }),
            ExprValue::Unavailable { .. } => Ok(value),
            _ => Err(Error::InvalidExpression(
                "indexing requires a typed pointer or array".into(),
            )),
        }
    }

    fn evaluate_cast(expr: &Expr, expr_type: &ExprType, context: &Target) -> Result<ExprValue> {
        if matches!(expr_type, ExprType::Struct(_)) {
            return Err(Error::InvalidExpression(
                "aggregate address casts are no longer supported; use (TYPE*)address for a pointer cast"
                    .into(),
            ));
        }
        let value = expr.evaluate(context)?.scalar(context)?;
        let type_data = Self::expr_type_to_parsed(expr_type);
        let width = Self::expr_type_size_exact(expr_type, context)?;
        Ok(ExprValue::Immediate {
            value: VirtAddr(Self::mask_value(value.0, width)),
            type_data,
            byte_size: Some(width),
        })
    }

    fn find_type(context: &Target, name: &str) -> Option<Arc<TypeInfo>> {
        if let Some(type_info) = context
            .symbols
            .find_type_across_modules(context.current_dtb(), name)
        {
            return Some(type_info);
        }
        if name.starts_with('_') {
            return None;
        }
        context
            .symbols
            .find_type_across_modules(context.current_dtb(), &format!("_{name}"))
    }

    fn expr_type_to_parsed(expr_type: &ExprType) -> ParsedType {
        match expr_type {
            ExprType::Byte => ParsedType::Primitive("UCHAR".into()),
            ExprType::Word => ParsedType::Primitive("USHORT".into()),
            ExprType::Dword => ParsedType::Primitive("ULONG".into()),
            ExprType::Qword => ParsedType::Primitive("ULONGLONG".into()),
            ExprType::Struct(name) => ParsedType::Struct(name.clone()),
            ExprType::Pointer(inner) => {
                ParsedType::Pointer(Box::new(Self::expr_type_to_parsed(inner)))
            }
        }
    }

    fn expr_type_size_exact(expr_type: &ExprType, context: &Target) -> Result<u64> {
        match expr_type {
            ExprType::Byte => Ok(1),
            ExprType::Word => Ok(2),
            ExprType::Dword => Ok(4),
            ExprType::Qword | ExprType::Pointer(_) => Ok(8),
            ExprType::Struct(name) => Self::find_type(context, name)
                .map(|info| info.size as u64)
                .filter(|size| *size != 0)
                .ok_or_else(|| Error::StructNotFound(name.clone())),
        }
    }

    fn scalar_width(type_data: &ParsedType, declared_size: Option<u64>) -> Result<u64> {
        let width = match type_data {
            ParsedType::Primitive(name) => {
                if Self::primitive_size(name).is_none() {
                    return Err(Error::InvalidExpression(format!(
                        "unsupported or unknown scalar type: {name}"
                    )));
                }
                declared_size.or_else(|| Self::primitive_size(name))
            }
            ParsedType::Enum(name) => declared_size.or_else(|| Self::primitive_size(name)),
            ParsedType::Pointer(_) => Some(8),
            ParsedType::Bitfield { underlying, .. } => {
                Some(Self::scalar_width(underlying, declared_size)?)
            }
            ParsedType::Struct(name) | ParsedType::Union(name) => {
                return Err(Error::InvalidExpression(format!(
                    "aggregate type {name} has no scalar value; use &expr for its address or dt to expand it"
                )));
            }
            ParsedType::Array(_, _) => {
                return Err(Error::InvalidExpression(
                    "array has no scalar value; use &expr for its address or expr[n] for an element"
                        .into(),
                ));
            }
            ParsedType::Function(_, _) => {
                return Err(Error::InvalidExpression(
                    "function type has no scalar value".into(),
                ));
            }
            ParsedType::Unknown => {
                return Err(Error::InvalidExpression(
                    "unsupported or unknown expression type".into(),
                ));
            }
        }
        .ok_or_else(|| Error::InvalidExpression("unknown scalar width".into()))?;
        if !(1..=8).contains(&width) {
            return Err(Error::InvalidExpression(format!(
                "scalar width {width} is unsupported"
            )));
        }
        Ok(width)
    }

    fn read_integer(
        memory: &impl MemoryOps<VirtAddr>,
        address: VirtAddr,
        width: u64,
    ) -> Result<u64> {
        let width = usize::try_from(width)
            .ok()
            .filter(|width| (1..=8).contains(width))
            .ok_or_else(|| Error::InvalidExpression("invalid integer width".into()))?;
        let mut bytes = [0u8; 8];
        memory.read_bytes(address, &mut bytes[..width])?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn parsed_type_size(
        type_data: &ParsedType,
        declared_size: Option<u64>,
        context: &Target,
    ) -> Result<u64> {
        match type_data {
            ParsedType::Primitive(name) => declared_size
                .or_else(|| Self::primitive_size(name))
                .ok_or_else(|| {
                    Error::InvalidExpression(format!("unsupported or unknown type width: {name}"))
                }),
            ParsedType::Struct(name) | ParsedType::Union(name) => Self::find_type(context, name)
                .map(|info| info.size as u64)
                .filter(|size| *size != 0)
                .or(declared_size.filter(|size| *size != 0))
                .ok_or_else(|| Error::StructNotFound(name.clone())),
            ParsedType::Enum(name) => declared_size
                .filter(|size| *size != 0)
                .ok_or_else(|| Error::InvalidExpression(format!("unknown enum width: {name}"))),
            ParsedType::Pointer(_) => Ok(8),
            ParsedType::Array(inner, count) => {
                let element = Self::parsed_type_size(inner, None, context)?;
                element
                    .checked_mul(u64::from(*count))
                    .ok_or_else(|| Error::InvalidExpression("array type size overflows u64".into()))
            }
            ParsedType::Bitfield { underlying, .. } => {
                Self::parsed_type_size(underlying, declared_size, context)
            }
            ParsedType::Function(_, _) | ParsedType::Unknown => Err(Error::InvalidExpression(
                "unsupported or unknown expression type".into(),
            )),
        }
    }

    fn array_element_size(
        inner: &ParsedType,
        total_size: Option<u64>,
        count: u32,
        context: &Target,
    ) -> Result<u64> {
        if count == 0 {
            return Err(Error::InvalidExpression(
                "array has unknown element count".into(),
            ));
        }
        if let Some(total_size) = total_size
            && total_size != 0
            && total_size % u64::from(count) == 0
        {
            return Ok(total_size / u64::from(count));
        }
        Self::parsed_type_size(inner, None, context)
    }

    fn primitive_size(name: &str) -> Option<u64> {
        match name.to_ascii_lowercase().as_str() {
            "char" | "schar" | "uchar" | "u8" | "i8" | "int8_t" | "uint8_t" | "bool" | "bool8"
            | "boolean" => Some(1),
            "wchar" | "wchar_t" | "char16_t" | "short" | "ushort" | "short int"
            | "unsigned short" | "i16" | "u16" | "int16_t" | "uint16_t" => Some(2),
            "long" | "ulong" | "int" | "uint" | "i32" | "u32" | "int32_t" | "uint32_t"
            | "bool32" => Some(4),
            "longlong" | "ulonglong" | "long long" | "unsigned long long" | "i64" | "u64"
            | "int64_t" | "uint64_t" | "qword" | "size_t" | "usize" => Some(8),
            _ => None,
        }
    }

    fn mask_value(value: u64, byte_size: u64) -> u64 {
        if byte_size >= 8 {
            value
        } else if byte_size == 0 {
            0
        } else {
            value & ((1u64 << (byte_size * 8)) - 1)
        }
    }

    fn decode_scalar(value: u64, type_data: &ParsedType, width: u64) -> Result<u64> {
        let value = Self::mask_value(value, width);
        let ParsedType::Bitfield { pos, len, .. } = type_data else {
            return Ok(value);
        };
        let bits = u32::from(*pos) + u32::from(*len);
        if *len == 0 || u64::from(bits) > width * 8 {
            return Err(Error::InvalidExpression(
                "invalid bitfield position or width".into(),
            ));
        }
        let mask = if *len >= 64 {
            u64::MAX
        } else {
            (1u64 << *len) - 1
        };
        Ok((value >> *pos) & mask)
    }

    /// The numeric entry point every address-oriented consumer reaches (REPL
    /// commands, breakpoints, SDKs, and Python), via [`Expr::eval`].
    pub fn resolve(&self, context: &Target) -> Result<VirtAddr> {
        self.evaluate(context)?.scalar(context)
    }

    pub fn resolve_type(&self, symbols: &SymbolStore, dtb: Dtb) -> Option<String> {
        match self {
            Expr::Cast(_, expr_type) => Some(Self::expr_type_to_name(expr_type)),
            Expr::Address(inner)
            | Expr::Deref(inner)
            | Expr::Read(_, inner)
            | Expr::ReadPhysical(_, inner) => inner.resolve_type(symbols, dtb),
            Expr::Index(base, _) => base.resolve_type(symbols, dtb),
            Expr::FieldAccess(base, field_name) | Expr::MemberAccess(base, field_name) => {
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
        let s = strip_digit_separators(s.trim());
        let s = s.as_ref();
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

impl ExprValue {
    /// Convert this value to an unsigned scalar. Typed memory values are read
    /// at their declared width; aggregate values intentionally fail instead
    /// of degrading to their storage address.
    pub fn scalar(&self, context: &Target) -> Result<VirtAddr> {
        match self {
            ExprValue::Raw { value, .. } => Ok(*value),
            ExprValue::Immediate {
                value,
                type_data,
                byte_size,
            }
            | ExprValue::Register {
                value,
                type_data,
                byte_size,
                ..
            } => {
                let width = Expr::scalar_width(type_data, *byte_size)?;
                Ok(VirtAddr(Expr::decode_scalar(value.0, type_data, width)?))
            }
            ExprValue::Memory {
                address,
                type_data,
                byte_size,
            } => {
                let memory = context.context_memory();
                let width = Expr::scalar_width(type_data, *byte_size)?;
                let raw = Expr::read_integer(&memory, *address, width)?;
                Ok(VirtAddr(Expr::decode_scalar(raw, type_data, width)?))
            }
            ExprValue::Unavailable { reason, .. } => Err(Error::InvalidExpression(format!(
                "value unavailable: {reason}"
            ))),
        }
    }

    /// Return the storage address of an addressable value. Registers,
    /// immediates, poi results, and bitfields have no independently usable
    /// storage address in the expression model.
    pub fn address(&self) -> Result<VirtAddr> {
        match self {
            ExprValue::Raw {
                address: Some(address),
                ..
            } => Ok(*address),
            ExprValue::Memory {
                address, type_data, ..
            } => {
                if matches!(type_data, ParsedType::Bitfield { .. }) {
                    return Err(Error::InvalidExpression(
                        "bitfield has no independently addressable storage".into(),
                    ));
                }
                if matches!(type_data, ParsedType::Unknown | ParsedType::Function(_, _))
                    || matches!(type_data, ParsedType::Primitive(name) if Expr::primitive_size(name).is_none())
                {
                    return Err(Error::InvalidExpression(
                        "unsupported or unknown typed value has no usable storage address".into(),
                    ));
                }
                Ok(*address)
            }
            ExprValue::Raw { address: None, .. } => Err(Error::InvalidExpression(
                "value has no storage address".into(),
            )),
            ExprValue::Register { name, .. } => Err(Error::InvalidExpression(format!(
                "register {name} has no storage address"
            ))),
            ExprValue::Immediate { .. } => Err(Error::InvalidExpression(
                "immediate value has no storage address".into(),
            )),
            ExprValue::Unavailable { reason, .. } => Err(Error::InvalidExpression(format!(
                "value unavailable: {reason}"
            ))),
        }
    }

    pub fn type_data(&self) -> Option<&ParsedType> {
        match self {
            ExprValue::Memory { type_data, .. }
            | ExprValue::Register { type_data, .. }
            | ExprValue::Immediate { type_data, .. } => Some(type_data),
            ExprValue::Unavailable { type_data, .. } => type_data.as_ref(),
            ExprValue::Raw { .. } => None,
        }
    }

    pub fn byte_size(&self) -> Option<u64> {
        match self {
            ExprValue::Memory { byte_size, .. }
            | ExprValue::Register { byte_size, .. }
            | ExprValue::Immediate { byte_size, .. }
            | ExprValue::Unavailable { byte_size, .. } => *byte_size,
            ExprValue::Raw { .. } => None,
        }
    }
}

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

#[cfg(test)]
mod tests;
