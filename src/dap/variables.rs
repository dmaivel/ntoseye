//! Scopes and variables: the reference table, the rows each reference opens
//! into, and `setVariable` writes back into the guest.

use std::result;

use serde_json::{Value, json};

use crate::backend::MemoryOps;
use crate::layout::{FieldInfo, ParsedType, find_field};
use crate::symbols::{LocalVariableLocation, ProcedureLocal};
use crate::types::{Dtb, VirtAddr};
use crate::typeview::{Expand, FieldView, TypeView};

use super::{Handled, NO_TARGET, Server, VarRef, arg_i64, arg_str};

/// `variablesReference` values start here so they can never collide with a
/// frame id (both are plain integers in the protocol).
pub(super) const VARIABLES_BASE: i64 = 1 << 20;
/// Maximum array elements decoded per variables request.
const MAX_VARIABLE_PAGE: usize = 1024;

impl Server {
    pub(super) fn on_scopes(&mut self, args: &Value) -> Handled {
        let handle = self.frame_handle(args, "frameId")?;
        let locals = self.var_ref(VarRef::Locals(handle));
        let registers = self.var_ref(VarRef::Registers(handle));
        Ok(Some(json!({"scopes": [
            {
                "name": "Locals",
                "presentationHint": "locals",
                "variablesReference": locals,
                "expensive": false,
            },
            {
                "name": "Registers",
                "presentationHint": "registers",
                "variablesReference": registers,
                "expensive": false,
            }
        ]})))
    }

    pub(super) fn var_ref(&mut self, reference: VarRef) -> i64 {
        if let Some(existing) = self.var_refs.get(&reference) {
            return *existing;
        }
        self.vars.push(reference.clone());
        let id = VARIABLES_BASE + self.vars.len() as i64 - 1;
        self.var_refs.insert(reference, id);
        id
    }

    /// Resolve a client-supplied `variablesReference` into a live table slot.
    /// References are cleared at every stop, so a stale one is an error rather
    /// than a silent read of whatever now occupies that slot.
    pub(super) fn var_index(&self, reference: i64) -> result::Result<usize, String> {
        reference
            .checked_sub(VARIABLES_BASE)
            .and_then(|index| usize::try_from(index).ok())
            .filter(|index| *index < self.vars.len())
            .ok_or_else(|| format!("stale variablesReference {reference}"))
    }

    pub(super) fn on_variables(&mut self, args: &Value) -> Handled {
        let reference = arg_i64(args, "variablesReference")
            .ok_or_else(|| "missing variablesReference".to_string())?;
        let index = self.var_index(reference)?;
        // Respect both the requested child kind and the array paging window.
        let filter = arg_str(args, "filter").unwrap_or_default();
        let start = arg_i64(args, "start").unwrap_or(0).max(0) as usize;
        let requested = arg_i64(args, "count").unwrap_or(0).max(0) as usize;
        match self.vars[index].clone() {
            VarRef::Registers(handle) if filter != "indexed" => {
                let rows = self.register_variables(handle)?;
                Self::page_rows(rows, start, requested)
            }
            VarRef::Locals(handle) if filter != "indexed" => {
                let rows = self.local_variables(handle)?;
                Self::page_rows(rows, start, requested)
            }
            VarRef::Fields {
                type_name,
                address,
                dtb,
            } if filter != "indexed" => {
                let rows = self.field_variables(&type_name, address, dtb)?;
                Self::page_rows(rows, start, requested)
            }
            VarRef::Elements {
                element,
                count,
                element_size,
                address,
                dtb,
            } if filter != "named" => {
                let window = match requested {
                    0 => MAX_VARIABLE_PAGE,
                    requested => requested.min(MAX_VARIABLE_PAGE),
                };
                self.element_variables(&element, count, element_size, address, dtb, start, window)
            }
            _ => Ok(Some(json!({"variables": []}))),
        }
    }

    /// Apply a client's `start`/`count` window to rows already produced.
    ///
    /// Array elements are windowed at the source, because reading a million of
    /// them to return ten would be the cost that paging exists to avoid. Named
    /// children are bounded by a type's field count, so slicing them here
    /// keeps one window rule for every reference kind.
    fn page_rows(body: Option<Value>, start: usize, count: usize) -> Handled {
        if start == 0 && count == 0 {
            return Ok(body);
        }
        let Some(mut body) = body else {
            return Ok(None);
        };
        let Some(rows) = body["variables"].as_array() else {
            return Ok(Some(body));
        };
        let windowed: Vec<Value> = match count {
            0 => rows.iter().skip(start).cloned().collect(),
            count => rows.iter().skip(start).take(count).cloned().collect(),
        };
        body["variables"] = Value::Array(windowed);
        Ok(Some(body))
    }

    fn register_variables(&mut self, handle: usize) -> Handled {
        self.select_frame(handle)?;
        let frame = &self.frames[handle];
        let session = self.session.as_mut().ok_or(NO_TARGET)?;
        // Frame 0 is the live register file, so read it rather than the
        // snapshot taken when the stack was walked: a write (`setVariable`, or
        // `r rax=...` in the console) then shows up immediately. Caller frames
        // keep their recovered snapshot, which is all unwind metadata
        // justifies, and so does a parked Windows thread, which has no live
        // file at all.
        let live_context = frame.index == 0 && session.parked_windows_thread().is_none();
        let live = live_context
            .then(|| session.read_registers().ok())
            .flatten();
        let map = &session.register_map;
        let mut variables = Vec::new();
        for register in map.registers() {
            let name = register.name.as_str();
            let value = match (&live, register.size) {
                (Some(file), 0..=8) => map.read_u64(name, file).ok().map(|v| format!("{v:#018x}")),
                (Some(file), 9..=16) => {
                    map.read_u128(name, file).ok().map(|v| format!("{v:#034x}"))
                }
                (Some(_), _) => None,
                (None, _) => frame.registers.get(name).map(|v| format!("{v:#018x}")),
            };
            let Some(value) = value else {
                continue;
            };
            variables.push(json!({
                "name": name,
                "value": value,
                "variablesReference": 0,
                "presentationHint": {"kind": "data", "attributes": ["rawString"]},
            }));
        }
        Ok(Some(json!({"variables": variables})))
    }

    pub(super) fn local_variables(&mut self, handle: usize) -> Handled {
        let ip = self.frames[handle].ip;
        let dtb = self.frames[handle].dtb;
        self.select_frame(handle)?;
        let views = {
            let session = self.session()?;
            let locals = session
                .target
                .symbols
                .procedure_locals(dtb, VirtAddr(ip))
                .map_err(|error| error.to_string())?;
            let Some(locals) = locals else {
                return Ok(Some(json!({"variables": []})));
            };
            let view = TypeView::in_address_space(session, dtb);
            locals
                .iter()
                .map(|local| {
                    let address = session.target.procedure_local_address(local).map(VirtAddr);
                    // Decode memory locals as fields, including aggregates.
                    let (value, expand) = match address {
                        Some(address) => {
                            let field = FieldInfo {
                                offset: 0,
                                size: local.byte_size.unwrap_or_default(),
                                type_data: local.type_data.clone(),
                            };
                            let (text, raw) = view.value_and_raw(address, &field);
                            (text, view.expand_for(&local.type_data, Some(address), raw))
                        }
                        None => {
                            let value = session
                                .target
                                .resolve_procedure_local_value(VirtAddr(ip), local);
                            let expand = view.expand_for(&local.type_data, None, value);
                            (local_value_text(local, value, expand.as_ref()), expand)
                        }
                    };
                    let field = FieldView {
                        name: local.name.clone(),
                        type_name: local.type_name.clone(),
                        address,
                        value,
                        expand,
                    };
                    (field, local.is_parameter)
                })
                .collect::<Vec<_>>()
        };
        let variables = self.variable_rows(views, dtb);
        Ok(Some(json!({"variables": variables})))
    }

    /// Open a struct or union: one row per field, each with the value `dt`
    /// would print and a reference of its own when it is expandable in turn.
    pub(super) fn field_variables(
        &mut self,
        type_name: &str,
        address: VirtAddr,
        dtb: Dtb,
    ) -> Handled {
        let views = {
            let session = self.session()?;
            let view = TypeView::in_address_space(session, dtb);
            let type_info = view
                .lookup_type(type_name)
                .ok_or_else(|| format!("type '{type_name}' is not in the loaded symbols"))?;
            view.fields(type_info.as_ref(), address)
                .into_iter()
                .map(|field| (field, false))
                .collect::<Vec<_>>()
        };
        let variables = self.variable_rows(views, dtb);
        Ok(Some(json!({"variables": variables})))
    }

    /// Open a bounded array. Only the shared element bound is materialized; a
    /// larger array is read past that point through the console (`dt -a`, `dq`).
    fn element_variables(
        &mut self,
        element: &ParsedType,
        count: u32,
        element_size: usize,
        address: VirtAddr,
        dtb: Dtb,
        start: usize,
        window: usize,
    ) -> Handled {
        let views = {
            let session = self.session()?;
            let view = TypeView::in_address_space(session, dtb);
            view.elements_from(address, element, count, element_size, start, window)
                .into_iter()
                .map(|field| (field, false))
                .collect::<Vec<_>>()
        };
        let variables = self.variable_rows(views, dtb);
        Ok(Some(json!({"variables": variables})))
    }

    /// Turn neutral field views into `variables` rows, allocating a reference
    /// for every row the client may open, in the address space `dtb` the
    /// views were read in. An aggregate has no scalar text, so it is labeled
    /// by what opening it yields.
    fn variable_rows(&mut self, views: Vec<(FieldView, bool)>, dtb: Dtb) -> Vec<Value> {
        let mut variables = Vec::with_capacity(views.len());
        for (field, parameter) in views {
            let value = if field.value.is_empty() {
                match &field.expand {
                    Some(Expand::Fields { .. }) => "{...}".to_string(),
                    Some(Expand::Elements { count, .. }) => format!("[{count}]"),
                    None => String::new(),
                }
            } else {
                field.value
            };
            let indexed = match &field.expand {
                Some(Expand::Elements { count, .. }) => Some(*count),
                _ => None,
            };
            let reference = match field.expand {
                Some(expand) => self.var_ref(VarRef::aggregate(expand, dtb)),
                None => 0,
            };
            let mut variable = json!({
                "name": field.name,
                "type": field.type_name,
                "value": value,
                "variablesReference": reference,
                "presentationHint": {
                    "kind": if parameter { "property" } else { "data" },
                },
            });
            if let Some(address) = field.address {
                variable["memoryReference"] = json!(format!("{:#x}", address.0));
            }
            if let Some(count) = indexed {
                variable["indexedVariables"] = json!(count);
            }
            variables.push(variable);
        }
        variables
    }

    pub(super) fn on_set_variable(&mut self, args: &Value) -> Handled {
        let reference = arg_i64(args, "variablesReference")
            .ok_or_else(|| "missing variablesReference".to_string())?;
        let name = arg_str(args, "name").ok_or_else(|| "missing name".to_string())?;
        let expression = arg_str(args, "value").ok_or_else(|| "missing value".to_string())?;
        let index = self.var_index(reference)?;
        let target = self.vars[index].clone();
        // A scope row's value expression (`index + 1`, `@rcx`) means what it
        // means in that row's frame, not in whichever frame the previous
        // request installed. Aggregates address the guest directly.
        if let VarRef::Locals(handle) | VarRef::Registers(handle) = target {
            self.select_frame(handle)?;
        }
        let value = self.evaluate_expression(&expression)?;
        match target {
            VarRef::Registers(handle) => {
                if self.frames[handle].index != 0 {
                    return Err(
                        "caller-frame registers are recovered from unwind metadata and are not writable"
                            .to_string(),
                    );
                }
                let session = self.session()?;
                if session.parked_windows_thread().is_some() {
                    return Err(
                        "a parked Windows thread's registers are recovered from its saved context \
                         and are not writable; select a vCPU with `.thread` first"
                            .to_string(),
                    );
                }
                session
                    .write_register(&name, value)
                    .map_err(|error| error.to_string())?;
                self.refresh_live_frame(handle);
                Ok(Some(json!({"value": format!("{value:#018x}")})))
            }
            VarRef::Locals(handle) => {
                let ip = self.frames[handle].ip;
                let dtb = self.frames[handle].dtb;
                let live_frame = self.frames[handle].index == 0;
                let session = self.session()?;
                let locals = session
                    .target
                    .symbols
                    .procedure_locals(dtb, VirtAddr(ip))
                    .map_err(|error| error.to_string())?
                    .unwrap_or_default();
                let local = locals
                    .iter()
                    .find(|local| local.name == name)
                    .ok_or_else(|| format!("no local named '{name}' in scope"))?;
                let size = local
                    .byte_size
                    .and_then(|size| usize::try_from(size).ok())
                    .filter(|size| *size > 0 && *size <= 8)
                    .ok_or_else(|| {
                        format!("'{name}' is not a scalar this adapter can write in place")
                    })?;
                match &local.location {
                    LocalVariableLocation::Register { register } => {
                        if !live_frame {
                            return Err(format!(
                                "'{name}' lives in a register recovered from unwind metadata for a \
                                 caller frame; writing it would change the live register instead"
                            ));
                        }
                        let register = register.clone();
                        session
                            .write_register(&register, value)
                            .map_err(|error| error.to_string())?;
                    }
                    _ => {
                        let address = session
                            .target
                            .procedure_local_address(local)
                            .ok_or_else(|| format!("'{name}' has no resolvable address"))?;
                        let bytes = value.to_le_bytes();
                        session
                            .target
                            .address_space(dtb)
                            .write_bytes(VirtAddr(address), &bytes[..size])
                            .map_err(|error| error.to_string())?;
                    }
                }
                // A register-held local shares storage with the frame's
                // register cache, which `select_frame` reinstalls on the next
                // request; re-read it so the pane does not show the old value.
                self.refresh_live_frame(handle);
                let session = self.session()?;
                let refreshed = session
                    .target
                    .symbols
                    .procedure_locals(dtb, VirtAddr(ip))
                    .ok()
                    .flatten()
                    .unwrap_or_default();
                let view = TypeView::in_address_space(session, dtb);
                let text = refreshed
                    .iter()
                    .find(|local| local.name == name)
                    .map(|local| {
                        // Read the written local back the way the variables
                        // view renders it, so the response and the next
                        // refresh cannot disagree.
                        match session.target.procedure_local_address(local).map(VirtAddr) {
                            Some(address) => {
                                let field = FieldInfo {
                                    offset: 0,
                                    size: local.byte_size.unwrap_or_default(),
                                    type_data: local.type_data.clone(),
                                };
                                view.value_text(address, &field)
                            }
                            None => {
                                let value = session
                                    .target
                                    .resolve_procedure_local_value(VirtAddr(ip), local);
                                let expand = view.expand_for(&local.type_data, None, value);
                                local_value_text(local, value, expand.as_ref())
                            }
                        }
                    })
                    .unwrap_or_else(|| format!("{value:#x}"));
                Ok(Some(json!({"value": text})))
            }
            VarRef::Fields {
                type_name,
                address,
                dtb,
            } => {
                let (field_address, size, field) = {
                    let session = self.session()?;
                    let view = TypeView::in_address_space(session, dtb);
                    let type_info = view.lookup_type(&type_name).ok_or_else(|| {
                        format!("type '{type_name}' is not in the loaded symbols")
                    })?;
                    let (field_name, field) = find_field(type_info.as_ref(), &name)
                        .ok_or_else(|| format!("no field named '{name}' in {type_name}"))?;
                    if let ParsedType::Bitfield { .. } = field.type_data {
                        return Err(format!(
                            "'{field_name}' is a bitfield; set it with 'eb'/'ed' on the containing \
                             value in the console"
                        ));
                    }
                    let size = view.field_size(field);
                    if !(1..=8).contains(&size) {
                        return Err(format!(
                            "'{field_name}' is {size} bytes; write it with 'eb' in the console"
                        ));
                    }
                    let field_address = address + u64::from(field.offset);
                    (field_address, size, field.clone())
                };
                self.write_scalar(dtb, field_address, size, value)?;
                let session = self.session()?;
                let view = TypeView::in_address_space(session, dtb);
                Ok(Some(
                    json!({"value": view.value_text(field_address, &field)}),
                ))
            }
            VarRef::Elements {
                element,
                count,
                element_size,
                address,
                dtb,
            } => {
                let index = element_index(&name)?;
                if index >= count {
                    return Err(format!(
                        "element {index} is past the end of a [{count}] array"
                    ));
                }
                if !(1..=8).contains(&element_size) {
                    return Err(format!(
                        "elements are {element_size} bytes; write them with 'eb' in the console"
                    ));
                }
                let element_address =
                    address + u64::from(index) * u64::try_from(element_size).unwrap_or(1);
                self.write_scalar(dtb, element_address, element_size, value)?;
                let field = FieldInfo {
                    offset: 0,
                    size: element_size as u64,
                    type_data: element,
                };
                let session = self.session()?;
                let view = TypeView::in_address_space(session, dtb);
                Ok(Some(
                    json!({"value": view.value_text(element_address, &field)}),
                ))
            }
        }
    }

    /// Write `size` little-endian bytes into the guest in the address space
    /// `dtb`. The caller has already bounded `size` to a scalar width.
    fn write_scalar(
        &mut self,
        dtb: Dtb,
        address: VirtAddr,
        size: usize,
        value: u64,
    ) -> result::Result<(), String> {
        let bytes = value.to_le_bytes();
        self.session()?
            .target
            .address_space(dtb)
            .write_bytes(address, &bytes[..size])
            .map_err(|error| error.to_string())
    }
}

/// Render a local's value, or the reason it has none. A caller frame keeps
/// only the registers unwind metadata justifies, so "unavailable" is a real
/// answer rather than a failure.
fn local_value_text(local: &ProcedureLocal, value: Option<u64>, expand: Option<&Expand>) -> String {
    if let Some(value) = value {
        return match local.byte_size {
            Some(size) if size <= 8 => format!("{value:#x} ({value})"),
            _ => format!("{value:#x}"),
        };
    }
    // An aggregate has no scalar value to be missing, so it is not unavailable:
    // the caller labels it by what expanding it yields.
    if expand.is_some() {
        return String::new();
    }
    match &local.location {
        LocalVariableLocation::Unavailable { reason } => format!("<unavailable: {reason}>"),
        LocalVariableLocation::Register { register } => {
            format!("<in {register}, unavailable in this context>")
        }
        location => format!("<at {}, unreadable>", location.describe()),
    }
}

/// The index in an array child's name (`[3]`), which is how a client names an
/// element back to the adapter.
pub(super) fn element_index(name: &str) -> result::Result<u32, String> {
    name.trim()
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .and_then(|index| index.parse().ok())
        .ok_or_else(|| format!("'{name}' is not an array element"))
}
