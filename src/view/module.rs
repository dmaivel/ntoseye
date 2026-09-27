//! Loaded-module [`View`] builders: module identity and symbol
//! load status.

use super::{View, diagnostic};
use crate::guest::{ModuleInfo, ModuleSymbolLoadReport};
use crate::pe::headers::{
    CodeView, DebugRecord, FileHeader, ImportDescriptor, ImportName, OptionalHeader, SectionHeader,
    debug_type_name, dll_characteristics, file_characteristics, machine_name,
    section_characteristics, subsystem_name,
};
use crate::pe::{ExportDirectory, ImageExports};
use crate::symbols::ModuleSymbolStatus;
use crate::target::image::ImageHeadersDetail;
use crate::target::{DiagnosticValue, Target};
use crate::types::Dtb;

pub fn module(module: &ModuleInfo) -> View {
    let mut fields = vec![
        ("name", View::Str(module.name.clone())),
        ("short_name", View::Str(module.short_name.clone())),
        ("path", View::OptStr(module.path.clone())),
        ("base", View::Hex(module.base_address.0)),
        ("end", View::Hex(module.end_address().0)),
        ("size", View::Num(module.size.into())),
    ];
    if let Some(timestamp) = module.time_date_stamp {
        fields.push(("time_date_stamp", View::Hex(timestamp.into())));
    }
    if let Some(checksum) = module.checksum {
        fields.push(("checksum", View::Hex(checksum.into())));
    }
    if let Some(version) = &module.file_version {
        fields.push(("file_version", View::Str(version.clone())));
    }
    if let Some(version) = &module.product_version {
        fields.push(("product_version", View::Str(version.clone())));
    }
    View::Object(fields)
}

/// The outcome of a symbol reload: how many modules loaded, lacked a PDB,
/// were skipped, or failed, plus the first diagnostics (bounded).
pub fn module_symbol_report(report: &ModuleSymbolLoadReport) -> View {
    View::Object(vec![
        ("total", View::Num(report.total as u64)),
        ("loaded", View::Num(report.loaded as u64)),
        ("unloaded", View::Num(report.unloaded as u64)),
        ("no_pdb", View::Num(report.no_pdb as u64)),
        ("skipped", View::Num(report.skipped as u64)),
        ("failed", View::Num(report.failed as u64)),
        (
            "diagnostic_count",
            View::Num(report.diagnostic_count as u64),
        ),
        (
            "diagnostics",
            View::List(
                report
                    .diagnostics
                    .iter()
                    .map(|diagnostic| {
                        View::Object(vec![
                            ("module", View::Str(diagnostic.module.clone())),
                            ("phase", View::Str(diagnostic.phase.to_string())),
                            ("compiland", View::OptStr(diagnostic.compiland.clone())),
                            ("message", View::Str(diagnostic.message.clone())),
                        ])
                    })
                    .collect(),
            ),
        ),
    ])
}

/// A module's symbol status and PDB identity (`lmv`).
pub fn module_symbols(target: &Target, info: &ModuleInfo, dtb: Dtb) -> View {
    let status = target.symbols.module_symbol_status(dtb, info.base_address);
    let identity = target.symbols.module_pdb_identity(dtb, info.base_address);
    let source = target.symbols.module_symbol_source(dtb, info.base_address);
    let status_name = match (&status, &identity) {
        (Some(status), _) => status.label().to_string(),
        (None, Some(_)) => "loaded".to_string(),
        (None, None) => "unknown".to_string(),
    };
    let failed = match &status {
        Some(ModuleSymbolStatus::Failed(error)) => Some(error.clone()),
        _ => None,
    };
    View::Object(vec![
        ("status", View::Str(status_name)),
        (
            "source",
            View::OptStr(source.as_ref().map(|source| source.label().to_string())),
        ),
        (
            "pdb_guid",
            View::OptStr(
                identity
                    .as_ref()
                    .map(|identity| format!("{:032X}", identity.guid)),
            ),
        ),
        (
            "pdb_age",
            View::OptNum(identity.map(|identity| u64::from(identity.age))),
        ),
        ("error", View::OptStr(failed)),
    ])
}

fn flag_list(names: Vec<String>) -> View {
    View::List(names.into_iter().map(View::Str).collect())
}

fn version((major, minor): (u16, u16)) -> View {
    View::Str(format!("{major}.{minor}"))
}

fn file_header(file: &FileHeader) -> View {
    View::Object(vec![
        ("machine", View::Hex(file.machine.into())),
        ("machine_name", View::Str(machine_name(file.machine).into())),
        (
            "number_of_sections",
            View::Num(file.number_of_sections.into()),
        ),
        ("time_date_stamp", View::Hex(file.time_date_stamp.into())),
        (
            "pointer_to_symbol_table",
            View::Hex(file.pointer_to_symbol_table.into()),
        ),
        (
            "number_of_symbols",
            View::Num(file.number_of_symbols.into()),
        ),
        (
            "size_of_optional_header",
            View::Hex(file.size_of_optional_header.into()),
        ),
        ("characteristics", View::Hex(file.characteristics.into())),
        (
            "characteristics_names",
            flag_list(file_characteristics(file.characteristics)),
        ),
    ])
}

fn optional_header(optional: &OptionalHeader, base: u64) -> View {
    View::Object(vec![
        ("magic", View::Hex(optional.magic.into())),
        (
            "linker_version",
            View::Str(format!(
                "{}.{}",
                optional.linker_version.0, optional.linker_version.1
            )),
        ),
        ("size_of_code", View::Hex(optional.size_of_code.into())),
        (
            "size_of_initialized_data",
            View::Hex(optional.size_of_initialized_data.into()),
        ),
        (
            "size_of_uninitialized_data",
            View::Hex(optional.size_of_uninitialized_data.into()),
        ),
        (
            "entry_point_rva",
            View::Hex(optional.address_of_entry_point.into()),
        ),
        (
            "entry_point",
            View::OptHex(
                (optional.address_of_entry_point != 0)
                    .then(|| base.wrapping_add(optional.address_of_entry_point.into())),
            ),
        ),
        ("base_of_code", View::Hex(optional.base_of_code.into())),
        (
            "base_of_data",
            View::OptHex(optional.base_of_data.map(u64::from)),
        ),
        ("image_base", View::Hex(optional.image_base)),
        (
            "section_alignment",
            View::Hex(optional.section_alignment.into()),
        ),
        ("file_alignment", View::Hex(optional.file_alignment.into())),
        (
            "operating_system_version",
            version(optional.operating_system_version),
        ),
        ("image_version", version(optional.image_version)),
        ("subsystem_version", version(optional.subsystem_version)),
        (
            "win32_version_value",
            View::Hex(optional.win32_version_value.into()),
        ),
        ("size_of_image", View::Hex(optional.size_of_image.into())),
        (
            "size_of_headers",
            View::Hex(optional.size_of_headers.into()),
        ),
        ("checksum", View::Hex(optional.checksum.into())),
        ("subsystem", View::Num(optional.subsystem.into())),
        (
            "subsystem_name",
            View::Str(subsystem_name(optional.subsystem).into()),
        ),
        (
            "dll_characteristics",
            View::Hex(optional.dll_characteristics.into()),
        ),
        (
            "dll_characteristics_names",
            flag_list(dll_characteristics(optional.dll_characteristics)),
        ),
        (
            "size_of_stack_reserve",
            View::Hex(optional.size_of_stack_reserve),
        ),
        (
            "size_of_stack_commit",
            View::Hex(optional.size_of_stack_commit),
        ),
        (
            "size_of_heap_reserve",
            View::Hex(optional.size_of_heap_reserve),
        ),
        (
            "size_of_heap_commit",
            View::Hex(optional.size_of_heap_commit),
        ),
        ("loader_flags", View::Hex(optional.loader_flags.into())),
        (
            "number_of_rva_and_sizes",
            View::Num(optional.number_of_rva_and_sizes.into()),
        ),
    ])
}

fn section_header(section: &SectionHeader) -> View {
    View::Object(vec![
        ("name", View::Str(section.name.clone())),
        ("virtual_size", View::Hex(section.virtual_size.into())),
        ("virtual_address", View::Hex(section.virtual_address.into())),
        (
            "size_of_raw_data",
            View::Hex(section.size_of_raw_data.into()),
        ),
        (
            "pointer_to_raw_data",
            View::Hex(section.pointer_to_raw_data.into()),
        ),
        (
            "pointer_to_relocations",
            View::Hex(section.pointer_to_relocations.into()),
        ),
        (
            "pointer_to_linenumbers",
            View::Hex(section.pointer_to_linenumbers.into()),
        ),
        (
            "number_of_relocations",
            View::Num(section.number_of_relocations.into()),
        ),
        (
            "number_of_linenumbers",
            View::Num(section.number_of_linenumbers.into()),
        ),
        ("characteristics", View::Hex(section.characteristics.into())),
        (
            "characteristics_names",
            flag_list(section_characteristics(section.characteristics)),
        ),
    ])
}

fn codeview(record: &CodeView) -> View {
    match record {
        CodeView::Rsds { guid, age, path } => View::Object(vec![
            ("format", View::Str("RSDS".into())),
            ("guid", View::Str(guid.to_string())),
            ("signature", View::Null),
            ("age", View::Num((*age).into())),
            ("pdb", View::Str(path.clone())),
        ]),
        CodeView::Nb10 {
            signature,
            age,
            path,
        } => View::Object(vec![
            ("format", View::Str("NB10".into())),
            ("guid", View::Null),
            ("signature", View::Hex((*signature).into())),
            ("age", View::Num((*age).into())),
            ("pdb", View::Str(path.clone())),
        ]),
    }
}

fn debug_entry(record: &DebugRecord) -> View {
    let entry = &record.entry;
    View::Object(vec![
        ("type", View::Num(entry.kind.into())),
        ("type_name", View::Str(debug_type_name(entry.kind).into())),
        ("characteristics", View::Hex(entry.characteristics.into())),
        ("time_date_stamp", View::Hex(entry.time_date_stamp.into())),
        ("version", version(entry.version)),
        ("size_of_data", View::Hex(entry.size_of_data.into())),
        (
            "address_of_raw_data",
            View::Hex(entry.address_of_raw_data.into()),
        ),
        (
            "pointer_to_raw_data",
            View::Hex(entry.pointer_to_raw_data.into()),
        ),
        (
            "codeview",
            record.codeview.as_ref().map_or(View::Null, |record| {
                diagnostic(
                    &record.as_ref().map_or_else(
                        |error| DiagnosticValue::Unavailable(error.clone()),
                        DiagnosticValue::Available,
                    ),
                    |record| codeview(record),
                )
            }),
        ),
    ])
}

fn export_directory(directory: &ExportDirectory) -> View {
    View::Object(vec![
        ("name", View::Str(directory.name.clone())),
        (
            "characteristics",
            View::Hex(directory.characteristics.into()),
        ),
        (
            "time_date_stamp",
            View::Hex(directory.time_date_stamp.into()),
        ),
        ("version", version(directory.version)),
        ("ordinal_base", View::Num(directory.ordinal_base.into())),
        (
            "number_of_functions",
            View::Num(directory.number_of_functions.into()),
        ),
        (
            "number_of_names",
            View::Num(directory.number_of_names.into()),
        ),
        (
            "address_of_functions",
            View::Hex(directory.address_of_functions.into()),
        ),
        (
            "address_of_names",
            View::Hex(directory.address_of_names.into()),
        ),
        (
            "address_of_name_ordinals",
            View::Hex(directory.address_of_name_ordinals.into()),
        ),
    ])
}

fn image_exports(exports: &ImageExports, base: u64) -> View {
    View::Object(vec![
        (
            "directory",
            exports
                .directory
                .as_ref()
                .map_or(View::Null, export_directory),
        ),
        (
            "exports",
            View::List(
                exports
                    .exports
                    .iter()
                    .map(|export| {
                        View::Object(vec![
                            ("ordinal", View::Num(export.ordinal.into())),
                            ("name", View::OptStr(export.name.clone())),
                            (
                                "rva",
                                View::OptHex(
                                    export.address.map(|address| address.0.wrapping_sub(base)),
                                ),
                            ),
                            (
                                "address",
                                View::OptHex(export.address.map(|address| address.0)),
                            ),
                            ("forwarder", View::OptStr(export.forwarder.clone())),
                        ])
                    })
                    .collect(),
            ),
        ),
    ])
}

fn import_descriptor(descriptor: &ImportDescriptor) -> View {
    View::Object(vec![
        ("name", View::OptStr(descriptor.name.as_ref().ok().cloned())),
        (
            "name_error",
            View::OptStr(descriptor.name.as_ref().err().cloned()),
        ),
        (
            "import_address_table",
            View::Hex(descriptor.first_thunk.into()),
        ),
        (
            "import_name_table",
            View::Hex(descriptor.original_first_thunk.into()),
        ),
        (
            "time_date_stamp",
            View::Hex(descriptor.time_date_stamp.into()),
        ),
        (
            "forwarder_chain",
            View::Hex(descriptor.forwarder_chain.into()),
        ),
        (
            "imports",
            View::List(
                descriptor
                    .entries
                    .iter()
                    .map(|entry| {
                        let (name, hint, ordinal, error) = match &entry.name {
                            ImportName::Name { hint, name } => {
                                (Some(name.clone()), Some(u64::from(*hint)), None, None)
                            }
                            ImportName::Ordinal(ordinal) => {
                                (None, None, Some(u64::from(*ordinal)), None)
                            }
                            ImportName::Unnamed => (None, None, None, None),
                            ImportName::Unreadable(error) => {
                                (None, None, None, Some(error.clone()))
                            }
                        };
                        View::Object(vec![
                            ("name", View::OptStr(name)),
                            ("hint", View::OptNum(hint)),
                            ("ordinal", View::OptNum(ordinal)),
                            ("bound", View::OptHex(entry.bound)),
                            ("error", View::OptStr(error)),
                        ])
                    })
                    .collect(),
            ),
        ),
        ("incomplete", View::OptStr(descriptor.incomplete.clone())),
    ])
}

/// `!dh`: a mapped image's headers; top-level keys: `base`, `module`,
/// `file_header`, `optional_header`, `data_directories`, `sections`, and,
/// when asked for, `debug_directory` (with the sections), `exports`, and
/// `imports`.
pub fn image_headers(detail: &ImageHeadersDetail) -> View {
    let headers = &detail.headers;
    let mut fields = vec![
        ("base", View::Hex(detail.base.0)),
        ("module", View::OptStr(detail.module.clone())),
        (
            "format",
            View::Str(
                if headers.is_pe32_plus() {
                    "PE32+"
                } else {
                    "PE32"
                }
                .into(),
            ),
        ),
        ("file_header", file_header(&headers.file)),
        (
            "optional_header",
            optional_header(&headers.optional, detail.base.0),
        ),
        (
            "data_directories",
            View::List(
                headers
                    .directories
                    .iter()
                    .map(|directory| {
                        View::Object(vec![
                            ("index", View::Num(directory.index as u64)),
                            ("name", View::Str(directory.name.into())),
                            ("rva", View::Hex(directory.rva.into())),
                            ("size", View::Hex(directory.size.into())),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "sections",
            View::List(headers.sections.iter().map(section_header).collect()),
        ),
    ];
    if let Some(debug) = &detail.debug {
        fields.push((
            "debug_directory",
            diagnostic(debug, |records| {
                View::List(records.iter().map(debug_entry).collect())
            }),
        ));
    }
    if let Some(exports) = &detail.exports {
        fields.push((
            "exports",
            diagnostic(exports, |exports| image_exports(exports, detail.base.0)),
        ));
    }
    if let Some(imports) = &detail.imports {
        fields.push((
            "imports",
            diagnostic(imports, |descriptors| {
                View::List(descriptors.iter().map(import_descriptor).collect())
            }),
        ));
    }
    View::Object(fields)
}
