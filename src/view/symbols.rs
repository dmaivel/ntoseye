//! Symbol, source-line, local-variable, and type-layout [`View`]
//! builders.

use super::shape::shapes;
use crate::layout::{FieldInfo, TypeInfo};
use crate::symbols::{self, SymbolVisibility};
use crate::target;
use crate::types::VirtAddr;

shapes! {
    /// The field layout of a struct or union (`dt`).
    TypeLayout {
        /// The PDB type name.
        name: String,
        /// The size in bytes.
        size: usize,
        /// The fields, sorted by offset.
        fields: Vec<Field>,
    }

    /// The PDB layout of a field, with its name, byte offset, byte size, and type spelling.
    Field {
        name: String,
        /// The byte offset in the containing type.
        offset: u32,
        /// The size in bytes.
        size: u64,
        /// The PDB type spelling.
        r#type: String,
    }

    /// One definition that a symbol name resolves to.
    SymbolCandidate {
        module: String,
        address: VirtAddr,
        /// `public` or `private`.
        visibility: &'static str,
        /// The compiland that defines a private symbol.
        compiland: Option<String>,
    }

    /// A symbol that a name search matched.
    SymbolSearchMatch {
        name: String,
        /// `None` if the match does not resolve to a unique address.
        address: Option<VirtAddr>,
        module: Option<String>,
    }

    /// The symbol nearest below an address (`ln`, `Symbols.nearest()`).
    Symbol {
        /// The module that contains the symbol.
        module: String,
        /// The symbol name.
        name: String,
        /// The address of the symbol.
        address: VirtAddr,
        /// The distance in bytes from the symbol to the queried address.
        offset: u32;

        /// `module!name+0xoffset`.
        fn __str__(slf: &pyo3::Bound<'_, Self>) -> pyo3::PyResult<String> {
            use pyo3::types::PyAnyMethods;
            let record = slf.as_super().get();
            let py = slf.py();
            Ok(symbols::format_symbol_with_offset(
                &record.field(py, "module")?.extract::<String>()?,
                &record.field(py, "name")?.extract::<String>()?,
                record.field(py, "offset")?.extract()?,
            ))
        }
    }

    /// PDB source metadata for an address.
    SourceLocation {
        /// The source file as the PDB records it.
        file: String,
        line: u32,
        /// `None` if the PDB records no column.
        column: Option<u32>,
        /// The local file that the source path maps it to. `None` if no mapping
        /// applies.
        local_path: Option<String>,
        /// `found`, `missing`, or `differs`. `found` means that the file is
        /// there and, if the PDB records a checksum, that it is the compiled
        /// file. `differs` means that the file is there but its checksum does
        /// not match the compiled file. `None` if `local_path` is `None`.
        local_state: Option<&'static str>,
    }

    /// The location of a local variable.
    LocalVariableLocation {
        /// `register`, `register_relative`, `frame_relative`, or
        /// `unavailable`.
        kind: &'static str,
        /// The register, for `register` and `register_relative`.
        register: Option<String>,
        /// The signed displacement, for `register_relative` and
        /// `frame_relative`.
        offset: Option<i64>,
        /// The reason that the location is unknown, for `unavailable`.
        reason: Option<String>,
    }

    /// A PDB local or parameter.
    ProcedureLocal {
        name: String,
        /// The PDB type spelling.
        type_name: String,
        /// `None` if the size of the type is unknown.
        byte_size: Option<u64>,
        /// True for a parameter, False for a local.
        parameter: bool,
        location: LocalVariableLocation,
    }
}

/// One field's layout.
pub fn type_field(name: &str, field: &FieldInfo) -> Field {
    Field {
        name: name.to_string(),
        offset: field.offset,
        size: field.size,
        r#type: field.type_data.to_string(),
    }
}

/// A struct's field layout, sorted by offset.
pub fn type_layout(name: &str, info: &TypeInfo) -> TypeLayout {
    TypeLayout {
        name: name.to_string(),
        size: info.size,
        fields: info
            .fields_in_order()
            .into_iter()
            .map(|(name, field)| type_field(name, field))
            .collect(),
    }
}

pub fn symbol_candidate(candidate: &symbols::SymbolCandidate) -> SymbolCandidate {
    SymbolCandidate {
        module: candidate.module.clone(),
        address: candidate.address,
        visibility: match candidate.visibility {
            SymbolVisibility::Public => "public",
            SymbolVisibility::Private => "private",
        },
        compiland: candidate.compiland.clone(),
    }
}

pub fn symbol_search_match(symbol: &target::SymbolSearchMatch) -> SymbolSearchMatch {
    SymbolSearchMatch {
        name: symbol.name.clone(),
        address: symbol.address,
        module: symbol.module.clone(),
    }
}

/// The symbol `offset` bytes below `address`.
pub fn symbol(address: VirtAddr, module: String, name: String, offset: u32) -> Symbol {
    Symbol {
        module,
        name,
        address: VirtAddr(address.0.saturating_sub(u64::from(offset))),
        offset,
    }
}

pub fn source_location(location: &symbols::SourceLocation) -> SourceLocation {
    SourceLocation {
        file: location.file.clone(),
        line: location.line,
        column: location.column,
        local_path: location
            .local
            .as_ref()
            .map(|local| local.path.display().to_string()),
        local_state: location.local.as_ref().map(|local| match local.state {
            symbols::LocalSourceState::Found => "found",
            symbols::LocalSourceState::Missing => "missing",
            symbols::LocalSourceState::Differs => "differs",
        }),
    }
}

fn local_location(location: &symbols::LocalVariableLocation) -> LocalVariableLocation {
    let (kind, register, offset, reason) = match location {
        symbols::LocalVariableLocation::Register { register } => {
            ("register", Some(register.clone()), None, None)
        }
        symbols::LocalVariableLocation::RegisterRelative { register, offset } => (
            "register_relative",
            Some(register.clone()),
            Some(i64::from(*offset)),
            None,
        ),
        symbols::LocalVariableLocation::FrameRelative { offset } => {
            ("frame_relative", None, Some(i64::from(*offset)), None)
        }
        symbols::LocalVariableLocation::Unavailable { reason } => {
            ("unavailable", None, None, Some(reason.clone()))
        }
    };
    LocalVariableLocation {
        kind,
        register,
        offset,
        reason,
    }
}

/// A PDB local or parameter's layout.
pub fn procedure_local(local: &symbols::ProcedureLocal) -> ProcedureLocal {
    ProcedureLocal {
        name: local.name.clone(),
        type_name: local.type_name.clone(),
        byte_size: local.byte_size,
        parameter: local.is_parameter,
        location: local_location(&local.location),
    }
}
