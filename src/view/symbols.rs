//! Symbol, source-line, local-variable, and type-layout [`View`]
//! builders.

use ntoseye_macros::record;

use crate::layout::FieldInfo;
use crate::symbols::{self, SymbolVisibility};
use crate::target;
use crate::types::VirtAddr;

/// The PDB layout of a field, with its name, byte offset, byte size, and type spelling.
#[record]
pub struct Field {
    pub name: String,
    /// The byte offset in the containing type.
    pub offset: u32,
    /// The size in bytes.
    pub size: u64,
    /// The PDB type spelling.
    pub r#type: String,
}

/// One definition that a symbol name resolves to.
#[record]
pub struct SymbolCandidate {
    pub module: String,
    pub address: VirtAddr,
    /// `public` or `private`.
    pub visibility: &'static str,
    /// The compiland that defines a private symbol.
    pub compiland: Option<String>,
}

/// A symbol that a name search matched.
#[record]
pub struct SymbolSearchMatch {
    pub name: String,
    /// `None` if the match does not resolve to a unique address.
    pub address: Option<VirtAddr>,
    pub module: Option<String>,
}

/// The symbol nearest below an address (`ln`, `Symbols.nearest()`).
#[record(impl)]
pub struct Symbol {
    /// The module that contains the symbol.
    pub module: String,
    /// The symbol name.
    pub name: String,
    /// The address of the symbol.
    pub address: VirtAddr,
    /// The distance in bytes from the symbol to the queried address.
    pub offset: u32,
}

#[record]
impl Symbol {
    /// `module!name+0xoffset`.
    #[record(python)]
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
#[record]
pub struct SourceLocation {
    /// The source file as the PDB records it.
    pub file: String,
    pub line: u32,
    /// `None` if the PDB records no column.
    pub column: Option<u32>,
    /// The local file that the source path maps it to. `None` if no mapping
    /// applies.
    pub local_path: Option<String>,
    /// `found`, `missing`, or `differs`. `found` means that the file is
    /// there and, if the PDB records a checksum, that it is the compiled
    /// file. `differs` means that the file is there but its checksum does
    /// not match the compiled file. `None` if `local_path` is `None`.
    pub local_state: Option<&'static str>,
}

/// The location of a local variable.
#[record]
pub struct LocalVariableLocation {
    /// `register`, `register_relative`, `frame_relative`, or
    /// `unavailable`.
    pub kind: &'static str,
    /// The register, for `register` and `register_relative`.
    pub register: Option<String>,
    /// The signed displacement, for `register_relative` and
    /// `frame_relative`.
    pub offset: Option<i64>,
    /// The reason that the location is unknown, for `unavailable`.
    pub reason: Option<String>,
}

/// A PDB local or parameter.
#[record]
pub struct ProcedureLocal {
    pub name: String,
    /// The PDB type spelling.
    pub type_name: String,
    /// `None` if the size of the type is unknown.
    pub byte_size: Option<u64>,
    /// True for a parameter, False for a local.
    pub parameter: bool,
    pub location: LocalVariableLocation,
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
