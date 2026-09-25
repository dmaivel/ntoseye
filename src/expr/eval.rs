//! Target-aware evaluation: resolving an [`Expr`] against memory, registers,
//! symbols, and source locals, and projecting typed values through fields,
//! indices, and casts.

use super::{
    Expr, ExprBinaryOp, ExprType, ExprUnaryOp, ExprValue, StringOp, strip_digit_separators,
};
use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::layout::{ParsedType, TypeInfo, bitfield_value, primitive_size};
use crate::symbols::{LocalVariableLocation, ProcedureLocal, SymbolStore, glob_matches};
use crate::target::Target;
use crate::types::{Dtb, VirtAddr};
use std::cmp::Ordering;
use std::sync::Arc;

impl Expr {
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
        if context.in_secure_scope() {
            return Err(Error::InvalidExpression(
                "registers belong to the VTL0 context; use .vtl 0 first".into(),
            ));
        }
        if context.registers.is_none() {
            return Err(Error::InvalidExpression(
                "registers unavailable while VM is running".into(),
            ));
        }
        // A 128-bit register reaches the scalar file only as its halves.
        if context.register_value(&format!("{name}l")).is_some()
            && context.register_value(&format!("{name}h")).is_some()
        {
            return Err(Error::RegisterTooWide(name.to_string()));
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
        let field = type_info.field(field_name)?;
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
                if primitive_size(name).is_none() {
                    return Err(Error::InvalidExpression(format!(
                        "unsupported or unknown scalar type: {name}"
                    )));
                }
                declared_size.or_else(|| primitive_size(name))
            }
            ParsedType::Enum(name) => declared_size.or_else(|| primitive_size(name)),
            ParsedType::Pointer(_) => Some(declared_size.filter(|size| *size != 0).unwrap_or(8)),
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
                .or_else(|| primitive_size(name))
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
            ParsedType::Pointer(_) => Ok(declared_size.filter(|size| *size != 0).unwrap_or(8)),
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
        Ok(bitfield_value(value, *pos, *len))
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

    pub(super) fn parse_bare_hex_literal(s: &str) -> Option<u64> {
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
                    || matches!(type_data, ParsedType::Primitive(name) if primitive_size(name).is_none())
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
