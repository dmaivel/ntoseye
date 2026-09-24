//! Data breakpoints: resolving the storage and width a variable row or
//! expression names, and installing watchpoints on it.

use std::result;

use serde_json::{Value, json};

use crate::dbg_backend::{DebugCapability, WatchpointAccess, validate_hw_breakpoint};
use crate::expr::{Expr, ExprType, ExprValue};
use crate::layout::{ParsedType, find_field};
use crate::repl::supports_capability;
use crate::session::Session;
use crate::typeview::TypeView;

use super::breakpoints::{Install, OwnedSet, breakpoint_config};
use super::evaluate::direct_register_expression;
use super::variables::{VARIABLES_BASE, element_index};
use super::{Handled, Server, VarRef, arg_i64, arg_str, parse_address};

impl Server {
    pub(super) fn on_data_breakpoint_info(&mut self, args: &Value) -> Handled {
        let name = arg_str(args, "name").ok_or_else(|| "missing name".to_string())?;
        let watchpoints = {
            let session = self.session()?;
            let capabilities = session.capabilities();
            supports_capability(&capabilities, DebugCapability::Watchpoints)
        };
        if !watchpoints {
            return Ok(Some(json!({
                "dataId": Value::Null,
                "description": "this backend does not support data watchpoints",
            })));
        }

        // A free-form `name` is evaluated in the frame the client names, the
        // way `evaluate` does: a local in an outer frame otherwise resolves
        // against whichever frame happens to be selected.
        self.select_named_frame(args, "frameId")?;
        // From the variables view the client passes the owning scope; anything
        // else is treated as an expression naming an address.
        let resolved = match arg_i64(args, "variablesReference") {
            Some(reference) if reference >= VARIABLES_BASE => self.data_target(reference, &name),
            _ => self.data_expression_target(&name),
        };
        let (address, size) = match resolved {
            Ok(resolved) => resolved,
            Err(message) => {
                return Ok(Some(json!({
                    "dataId": Value::Null,
                    "description": message,
                })));
            }
        };
        let len = watch_length(size);
        if let Err(error) = validate_hw_breakpoint(WatchpointAccess::Write.into(), len, address) {
            return Ok(Some(json!({
                "dataId": Value::Null,
                "description": error.to_string(),
            })));
        }
        Ok(Some(json!({
            "dataId": format!("{address:#x}:{len}"),
            "description": format!("{len} byte(s) at {address:#x}"),
            "accessTypes": ["write", "readWrite"],
            "canPersist": false,
        })))
    }

    /// Resolve a free-form watch expression once through the typed evaluator.
    /// Typed memory values watch their storage; raw address/u64 expressions
    /// retain the old numeric-address behavior. Registers and non-pointer
    /// typed immediate values are rejected because neither has writable
    /// storage.
    pub(super) fn data_expression_target(
        &mut self,
        expression: &str,
    ) -> result::Result<(u64, usize), String> {
        let (expr, value) = self.parse_and_evaluate(expression)?;
        let session = self.session()?;
        match value.address() {
            Ok(address) => expression_watch_size(&value, session).map(|size| (address.0, size)),
            Err(_error) if direct_register_expression(&expr, &session.target) => {
                Err("registers cannot be watched; watch the memory they point at".to_string())
            }
            // A typed pointer rvalue has no storage address of its own, but
            // its scalar is an explicit pointee address a client can watch.
            Err(error) => match value.type_data() {
                Some(ParsedType::Pointer(pointee)) => {
                    let size = TypeView::new(session).parsed_type_size(pointee);
                    if size == 0 {
                        return Err("typed pointer has unknown pointee size".to_string());
                    }
                    value
                        .scalar(&session.target)
                        .map(|address| (address.0, size))
                        .map_err(|error| error.to_string())
                }
                Some(_) => Err(error.to_string()),
                None => {
                    let address = value
                        .scalar(&session.target)
                        .map_err(|error| error.to_string())?;
                    let size = expression_watch_size(&value, session)?;
                    Ok((address.0, size))
                }
            },
        }
    }

    /// Resolve the storage address and width to watch from the variable the
    /// client asked about. Register-held values and bitfields intentionally
    /// have no independently watchable address.
    fn data_target(&mut self, reference: i64, name: &str) -> result::Result<(u64, usize), String> {
        let index = self.var_index(reference)?;
        match self.vars[index].clone() {
            VarRef::Locals(handle) => {
                self.select_frame(handle)?;
                // The explicit local namespace avoids accidentally selecting
                // a same-named module symbol when a scope row is watched.
                let expression = Expr::Local(name.to_string());
                let session = self.session()?;
                let value = expression
                    .evaluate(&session.target)
                    .map_err(|error| error.to_string())?;
                let address = value.address().map_err(|error| error.to_string())?;
                let size = expression_watch_size(&value, session)?;
                Ok((address.0, size))
            }
            VarRef::Registers(_) => {
                Err("registers cannot be watched; watch the memory they point at".into())
            }
            VarRef::Fields {
                type_name, address, ..
            } => {
                let field_name = {
                    let session = self.session()?;
                    let view = TypeView::new(session);
                    let type_info = view.lookup_type(&type_name).ok_or_else(|| {
                        format!("type '{type_name}' is not in the loaded symbols")
                    })?;
                    find_field(type_info.as_ref(), name)
                        .map(|(field_name, _)| field_name.clone())
                        .ok_or_else(|| format!("no field named '{name}' in {type_name}"))?
                };
                let expression = Expr::FieldAccess(
                    Box::new(Expr::Cast(
                        Box::new(Expr::Literal(address)),
                        ExprType::Pointer(Box::new(ExprType::Struct(type_name))),
                    )),
                    field_name,
                );
                self.data_value_target(&expression)
            }
            VarRef::Elements {
                count,
                element_size,
                address,
                element: element_type,
                ..
            } => {
                let index = element_index(name)?;
                if index >= count {
                    Err(format!(
                        "element {index} is past the end of a [{count}] array"
                    ))
                } else if matches!(&element_type, ParsedType::Bitfield { .. }) {
                    Err("bitfields have no independently addressable storage".to_string())
                } else if element_size == 0 {
                    Err("array element has no storage size".to_string())
                } else {
                    let offset = u64::from(index) * element_size as u64;
                    Ok((address.0.wrapping_add(offset), element_size))
                }
            }
        }
    }

    /// Resolve typed storage and width; reject registers, bitfields, and immediates.
    fn data_value_target(&mut self, expression: &Expr) -> result::Result<(u64, usize), String> {
        let value = {
            let session = self.session()?;
            expression
                .evaluate(&session.target)
                .map_err(|error| error.to_string())?
        };
        let session = self.session()?;
        let address = value.address().map_err(|error| error.to_string())?;
        let size = expression_watch_size(&value, session)?;
        Ok((address.0, size))
    }

    pub(super) fn on_set_data_breakpoints(&mut self, args: &Value) -> Handled {
        let requested = args
            .get("breakpoints")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let plan = requested
            .iter()
            .map(|entry| {
                let (address, len) = arg_str(entry, "dataId")
                    .ok_or_else(|| "breakpoint without a dataId".to_string())
                    .and_then(|id| parse_data_id(&id))?;
                let access = match arg_str(entry, "accessType").as_deref() {
                    Some("read") | Some("readWrite") => WatchpointAccess::ReadWrite,
                    _ => WatchpointAccess::Write,
                };
                let config = breakpoint_config(entry)?;
                Ok(Install::Watch {
                    address,
                    access,
                    len,
                    config,
                })
            })
            .collect();
        self.replace_owned_set(OwnedSet::Data, plan)
    }
}

/// Use the declared width or loaded layout. Untyped addresses default to eight bytes.
fn expression_watch_size(value: &ExprValue, session: &Session) -> result::Result<usize, String> {
    if let Some(size) = value
        .byte_size()
        .and_then(|size| usize::try_from(size).ok())
        .filter(|size| *size != 0)
    {
        return Ok(size);
    }
    if let Some(type_data) = value.type_data() {
        let size = TypeView::new(session).parsed_type_size(type_data);
        if size != 0 {
            return Ok(size);
        }
        return Err(format!(
            "typed value '{type_data}' has unknown storage size"
        ));
    }
    Ok(8)
}

/// Round a variable's size down to a legal debug-register watch width.
fn watch_length(size: usize) -> u8 {
    match size {
        0 | 1 => 1,
        2 | 3 => 2,
        4..=7 => 4,
        _ => 8,
    }
}

fn parse_data_id(id: &str) -> result::Result<(u64, u8), String> {
    let (address, len) = id
        .split_once(':')
        .ok_or_else(|| format!("malformed dataId '{id}'"))?;
    let address = parse_address(address)?;
    let len = len
        .parse::<u8>()
        .map_err(|_| format!("malformed dataId '{id}'"))?;
    Ok((address, len))
}

#[cfg(test)]
mod tests {
    use super::{parse_data_id, watch_length};

    #[test]
    fn data_ids_round_trip_through_the_client() {
        let (address, len) = parse_data_id("0x1000:4").unwrap();
        assert_eq!((address, len), (0x1000, 4));
        assert!(parse_data_id("0x1000").is_err());
        assert!(parse_data_id("0x1000:x").is_err());
    }

    #[test]
    fn watch_widths_round_down_to_legal_debug_register_sizes() {
        assert_eq!(watch_length(0), 1);
        assert_eq!(watch_length(3), 2);
        assert_eq!(watch_length(6), 4);
        assert_eq!(watch_length(16), 8);
    }
}
