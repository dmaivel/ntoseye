//! Symbol, source-line, local-variable, and type-layout [`View`](super::View)
//! builders.

use super::View;
use crate::layout::TypeInfo;
use crate::symbols::{
    LocalVariableLocation, ProcedureLocal, SourceLocation, SymbolCandidate, SymbolVisibility,
    format_symbol_with_offset,
};
use crate::target::{SymbolSearchMatch, Target};
use crate::types::VirtAddr;

/// A struct's field layout, sorted by offset.
pub fn type_layout(name: &str, info: &TypeInfo) -> View {
    let fields = info
        .fields_in_order()
        .into_iter()
        .map(|(field_name, field)| {
            View::Object(vec![
                ("name", View::Str(field_name.clone())),
                ("offset", View::Num(field.offset.into())),
                ("size", View::Num(field.size)),
                ("type", View::Str(field.type_data.to_string())),
            ])
        })
        .collect();
    View::Object(vec![
        ("name", View::Str(name.to_string())),
        ("size", View::Num(info.size as u64)),
        ("fields", View::List(fields)),
    ])
}

pub fn symbol_candidate(candidate: &SymbolCandidate) -> View {
    View::Object(vec![
        ("module", View::Str(candidate.module.clone())),
        ("address", View::Hex(candidate.address.0)),
        (
            "visibility",
            View::Str(
                match candidate.visibility {
                    SymbolVisibility::Public => "public",
                    SymbolVisibility::Private => "private",
                }
                .to_string(),
            ),
        ),
        ("compiland", View::OptStr(candidate.compiland.clone())),
    ])
}

pub fn symbol_search_match(symbol: &SymbolSearchMatch) -> View {
    View::Object(vec![
        ("name", View::Str(symbol.name.clone())),
        (
            "address",
            View::OptHex(symbol.address.map(|address| address.0)),
        ),
        ("module", View::OptStr(symbol.module.clone())),
    ])
}

pub fn nearest_symbol(address: VirtAddr, symbol: Option<(String, String, u32)>) -> View {
    let (formatted, module, name, offset) = match symbol {
        Some((module, name, offset)) => (
            View::Str(format_symbol_with_offset(&module, &name, offset)),
            View::Str(module),
            View::Str(name),
            View::Num(offset.into()),
        ),
        None => (View::Null, View::Null, View::Null, View::Null),
    };
    View::Object(vec![
        ("address", View::Hex(address.0)),
        ("symbol", formatted),
        ("module", module),
        ("name", name),
        ("offset", offset),
    ])
}

pub fn source_location(location: &SourceLocation) -> View {
    View::Object(vec![
        ("file", View::Str(location.file.clone())),
        ("line", View::Num(location.line.into())),
        ("column", View::OptNum(location.column.map(u64::from))),
        (
            "local_path",
            View::OptStr(
                location
                    .local_path
                    .as_ref()
                    .map(|path| path.display().to_string()),
            ),
        ),
        ("local_exists", View::Bool(location.local_exists)),
    ])
}

fn local_location(location: &LocalVariableLocation) -> View {
    let (kind, register, offset, reason) = match location {
        LocalVariableLocation::Register { register } => {
            ("register", Some(register.clone()), None, None)
        }
        LocalVariableLocation::RegisterRelative { register, offset } => (
            "register_relative",
            Some(register.clone()),
            Some(i64::from(*offset)),
            None,
        ),
        LocalVariableLocation::FrameRelative { offset } => {
            ("frame_relative", None, Some(i64::from(*offset)), None)
        }
        LocalVariableLocation::Unavailable { reason } => {
            ("unavailable", None, None, Some(reason.clone()))
        }
    };
    View::Object(vec![
        ("kind", View::Str(kind.to_string())),
        ("register", View::OptStr(register)),
        ("offset", offset.map(View::Int).unwrap_or(View::Null)),
        ("reason", View::OptStr(reason)),
    ])
}

pub fn procedure_local(target: &Target, address: VirtAddr, local: &ProcedureLocal) -> View {
    let View::Object(mut fields) = procedure_local_layout(local) else {
        unreachable!("a local's layout is an object");
    };
    fields.push((
        "value",
        View::OptHex(target.resolve_procedure_local_value(address, local)),
    ));
    View::Object(fields)
}

/// A PDB local or parameter's layout, without evaluating it.
pub fn procedure_local_layout(local: &ProcedureLocal) -> View {
    View::Object(vec![
        ("name", View::Str(local.name.clone())),
        ("type_name", View::Str(local.type_name.clone())),
        ("byte_size", View::OptNum(local.byte_size)),
        ("parameter", View::Bool(local.is_parameter)),
        ("location", local_location(&local.location)),
    ])
}
