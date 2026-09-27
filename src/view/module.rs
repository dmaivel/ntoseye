//! Loaded-module [`View`] builders: module identity and symbol
//! load status.

use super::View;
use super::shape::{Diag, Hex, Omit, shapes};
use crate::guest::{ModuleInfo, ModuleSymbolLoadReport};
use crate::pe::headers::{
    CodeView, DebugRecord, FileHeader, ImportDescriptor, ImportName, OptionalHeader, SectionHeader,
    debug_type_name, dll_characteristics, file_characteristics, machine_name,
    section_characteristics, subsystem_name,
};
use crate::pe::{self, ExportDirectory};
use crate::symbols::ModuleSymbolStatus;
use crate::target::image::{self, ImageHeadersDetail};
use crate::target::{DiagnosticValue, Target};
use crate::types::Dtb;

shapes! {
    /// A loaded image (`lm`).
    LoadedModule {
        /// The image file name (`ntoskrnl.exe`).
        name: String,
        /// The name `module!symbol` uses (`nt`).
        short_name: String,
        /// Full image path, when the loader recorded one.
        path: Option<String>,
        base: Hex,
        /// One past the image's last byte.
        end: Hex,
        /// Mapped image size in bytes.
        size: u32,
        /// PE timestamp, absent when the loader record lacks one.
        time_date_stamp: Omit<Hex>,
        /// PE checksum, absent when the loader record lacks one.
        checksum: Omit<Hex>,
        /// File version from the version resource, absent when unread.
        file_version: Omit<String>,
        /// Product version from the version resource, absent when unread.
        product_version: Omit<String>,
        /// Symbol status; present only on a kernel module's `inspect()`.
        symbols: Omit<ModuleSymbols>,
    }

    /// A module's symbol status and PDB identity (`lmv`).
    ModuleSymbols {
        /// `loaded`, `deferred`, `failed`, `unknown`, ...
        status: String,
        /// Where the PDB came from, when known.
        source: Option<String>,
        /// The loaded PDB's GUID as 32 hex digits, `None` without a PDB.
        pdb_guid: Option<String>,
        /// The loaded PDB's age, `None` without a PDB.
        pdb_age: Option<u32>,
        /// Why loading failed, for status `failed`.
        error: Option<String>,
    }

    /// The outcome of a symbol reload: how many modules loaded, lacked a
    /// PDB, were skipped, or failed, plus the first diagnostics (bounded).
    SymbolReloadReport {
        total: usize,
        loaded: usize,
        /// Symbol-bearing modules gone since the previous refresh.
        unloaded: usize,
        no_pdb: usize,
        skipped: usize,
        failed: usize,
        /// All diagnostics, including those past `diagnostics`' bound.
        diagnostic_count: usize,
        diagnostics: Vec<SymbolLoadDiagnostic>,
    }

    /// One problem found while loading a module's symbols.
    SymbolLoadDiagnostic {
        module: String,
        /// The load step that reported it.
        phase: String,
        /// The compiland it concerns, when it is compiland-specific.
        compiland: Option<String>,
        message: String,
    }

    /// `IMAGE_FILE_HEADER`.
    ImageFileHeader {
        machine: Hex,
        /// `AMD64`, `I386`, ...
        machine_name: &'static str,
        number_of_sections: u16,
        time_date_stamp: Hex,
        pointer_to_symbol_table: Hex,
        number_of_symbols: u32,
        size_of_optional_header: Hex,
        characteristics: Hex,
        /// The `IMAGE_FILE_*` flags set in `characteristics`.
        characteristics_names: Vec<String>,
    }

    /// `IMAGE_OPTIONAL_HEADER` (PE32 or PE32+).
    ImageOptionalHeader {
        magic: Hex,
        /// `major.minor`.
        linker_version: String,
        size_of_code: Hex,
        size_of_initialized_data: Hex,
        size_of_uninitialized_data: Hex,
        entry_point_rva: Hex,
        /// The mapped entry point, `None` when the image has none.
        entry_point: Option<Hex>,
        base_of_code: Hex,
        /// PE32 only; `None` for PE32+.
        base_of_data: Option<Hex>,
        /// The preferred base the image was linked for.
        image_base: Hex,
        section_alignment: Hex,
        file_alignment: Hex,
        /// `major.minor`.
        operating_system_version: String,
        /// `major.minor`.
        image_version: String,
        /// `major.minor`.
        subsystem_version: String,
        win32_version_value: Hex,
        size_of_image: Hex,
        size_of_headers: Hex,
        checksum: Hex,
        subsystem: u16,
        /// `Native`, `Windows GUI`, ...
        subsystem_name: &'static str,
        dll_characteristics: Hex,
        /// The `IMAGE_DLLCHARACTERISTICS_*` flags set.
        dll_characteristics_names: Vec<String>,
        size_of_stack_reserve: Hex,
        size_of_stack_commit: Hex,
        size_of_heap_reserve: Hex,
        size_of_heap_commit: Hex,
        loader_flags: Hex,
        number_of_rva_and_sizes: u32,
    }

    /// One `IMAGE_DATA_DIRECTORY` entry.
    ImageDataDirectory {
        /// Its slot in the directory table.
        index: usize,
        /// `Export`, `Import`, `Debug`, ...
        name: &'static str,
        rva: Hex,
        size: Hex,
    }

    /// One `IMAGE_SECTION_HEADER`.
    ImageSectionHeader {
        name: String,
        virtual_size: Hex,
        /// The section's RVA.
        virtual_address: Hex,
        size_of_raw_data: Hex,
        pointer_to_raw_data: Hex,
        pointer_to_relocations: Hex,
        pointer_to_linenumbers: Hex,
        number_of_relocations: u16,
        number_of_linenumbers: u16,
        characteristics: Hex,
        /// The `IMAGE_SCN_*` flags set.
        characteristics_names: Vec<String>,
    }

    /// A CodeView debug record: the PDB an image was built with.
    CodeViewRecord {
        /// `RSDS` (PDB 7.0) or `NB10` (PDB 2.0).
        format: &'static str,
        /// The PDB GUID, for `RSDS`.
        guid: Option<String>,
        /// The PDB timestamp signature, for `NB10`.
        signature: Option<Hex>,
        age: u32,
        /// The PDB path the linker recorded.
        pdb: String,
    }

    /// One `IMAGE_DEBUG_DIRECTORY` entry.
    ImageDebugEntry {
        /// `IMAGE_DEBUG_TYPE_*` value.
        r#type: u32,
        /// `CODEVIEW`, `POGO`, ...
        type_name: &'static str,
        characteristics: Hex,
        time_date_stamp: Hex,
        /// `major.minor`.
        version: String,
        size_of_data: Hex,
        address_of_raw_data: Hex,
        pointer_to_raw_data: Hex,
        /// The decoded CodeView record, `None` for other entry types.
        codeview: Option<Diag<CodeViewRecord>>,
    }

    /// `IMAGE_EXPORT_DIRECTORY`.
    ImageExportDirectory {
        /// The DLL name the directory records.
        name: String,
        characteristics: Hex,
        time_date_stamp: Hex,
        /// `major.minor`.
        version: String,
        ordinal_base: u32,
        number_of_functions: u32,
        number_of_names: u32,
        address_of_functions: Hex,
        address_of_names: Hex,
        address_of_name_ordinals: Hex,
    }

    /// An image's export directory and its exports (`!dh -e`).
    ImageExports {
        /// `None` when the image exports nothing.
        directory: Option<ImageExportDirectory>,
        exports: Vec<ImageExport>,
    }

    /// One export from an image's export directory.
    ImageExport {
        ordinal: u32,
        /// `None` for an ordinal-only export.
        name: Option<String>,
        /// `None` for a forwarder.
        rva: Option<Hex>,
        /// The mapped address, `None` for a forwarder.
        address: Option<Hex>,
        /// The forwarding target (`OTHER.Function`), for a forwarder.
        forwarder: Option<String>,
    }

    /// One `IMAGE_IMPORT_DESCRIPTOR`: a DLL an image imports from.
    ImageImportDescriptor {
        /// The DLL name, `None` when it did not read.
        name: Option<String>,
        /// Why the DLL name did not read.
        name_error: Option<String>,
        import_address_table: Hex,
        import_name_table: Hex,
        time_date_stamp: Hex,
        forwarder_chain: Hex,
        imports: Vec<ImageImport>,
        /// Why the thunk walk stopped early, when it did.
        incomplete: Option<String>,
    }

    /// One imported function.
    ImageImport {
        /// The imported name, `None` for an ordinal or unreadable import.
        name: Option<String>,
        /// The export-name-table hint, for a named import.
        hint: Option<u16>,
        /// The ordinal, for an import by ordinal.
        ordinal: Option<u16>,
        /// The bound address the import address table holds.
        bound: Option<Hex>,
        /// Why the import's name did not read.
        error: Option<String>,
    }

    /// A mapped image's headers (`!dh`).
    ImageHeaders {
        base: Hex,
        /// The loaded module at `base`, when there is one.
        module: Option<String>,
        /// `PE32` or `PE32+`.
        format: &'static str,
        file_header: ImageFileHeader,
        optional_header: ImageOptionalHeader,
        data_directories: Vec<ImageDataDirectory>,
        sections: Vec<ImageSectionHeader>,
        /// The debug directory, absent unless asked for.
        debug_directory: Omit<Diag<Vec<ImageDebugEntry>>>,
        /// The export directory, absent unless asked for.
        exports: Omit<Diag<ImageExports>>,
        /// The import descriptors, absent unless asked for.
        imports: Omit<Diag<Vec<ImageImportDescriptor>>>,
    }

    /// A module's image identity (`!lmi`): its file-header identity, debug
    /// directory (with the CodeView PDB name, GUID, and age), and symbol
    /// state.
    ModuleImageInfo {
        module: LoadedModule,
        machine: Hex,
        /// `AMD64`, `I386`, ...
        machine_name: &'static str,
        time_date_stamp: Hex,
        size_of_image: Hex,
        checksum: Hex,
        characteristics: Hex,
        /// The `IMAGE_FILE_*` flags set in `characteristics`.
        characteristics_names: Vec<String>,
        debug_directory: Diag<Vec<ImageDebugEntry>>,
        symbols: ModuleSymbols,
        /// The local PDB file, when one is loaded.
        symbol_file: Option<String>,
    }

    /// One PE section: its name, RVA, mapped size, and `rwx` permissions.
    Section {
        /// The section name (`.text`).
        name: String,
        /// Its offset from the image base.
        rva: Hex,
        /// Its mapped size.
        size: Hex,
        /// Mapped permissions as `rwx`, `-` for a missing one.
        permissions: String,
    }

    /// One PE export, by name or ordinal only; a forwarder has no address.
    Export {
        /// The export name, `None` for an ordinal-only export.
        name: Option<String>,
        ordinal: u32,
        /// The exported address, `None` for a forwarder.
        address: Option<Hex>,
        /// The forwarding target (`OTHER.Function`), for a forwarder.
        forwarder: Option<String>,
    }
}

/// A loaded image's identity, without its symbol status.
pub fn loaded_module(module: &ModuleInfo) -> LoadedModule {
    LoadedModule {
        name: module.name.clone(),
        short_name: module.short_name.clone(),
        path: module.path.clone(),
        base: Hex(module.base_address.0),
        end: Hex(module.end_address().0),
        size: module.size,
        time_date_stamp: Omit(module.time_date_stamp.map(|stamp| Hex(stamp.into()))),
        checksum: Omit(module.checksum.map(|checksum| Hex(checksum.into()))),
        file_version: Omit(module.file_version.clone()),
        product_version: Omit(module.product_version.clone()),
        symbols: Omit(None),
    }
}

pub fn module(module: &ModuleInfo) -> View {
    loaded_module(module).into_view()
}

/// The outcome of a symbol reload.
pub fn module_symbol_report(report: &ModuleSymbolLoadReport) -> View {
    SymbolReloadReport {
        total: report.total,
        loaded: report.loaded,
        unloaded: report.unloaded,
        no_pdb: report.no_pdb,
        skipped: report.skipped,
        failed: report.failed,
        diagnostic_count: report.diagnostic_count,
        diagnostics: report
            .diagnostics
            .iter()
            .map(|diagnostic| SymbolLoadDiagnostic {
                module: diagnostic.module.clone(),
                phase: diagnostic.phase.to_string(),
                compiland: diagnostic.compiland.clone(),
                message: diagnostic.message.clone(),
            })
            .collect(),
    }
    .into_view()
}

/// A module's symbol status and PDB identity (`lmv`).
pub fn module_symbols(target: &Target, info: &ModuleInfo, dtb: Dtb) -> ModuleSymbols {
    let status = target.symbols.module_symbol_status(dtb, info.base_address);
    let identity = target.symbols.module_pdb_identity(dtb, info.base_address);
    let source = target.symbols.module_symbol_source(dtb, info.base_address);
    let status_name = match (&status, &identity) {
        (Some(status), _) => status.label().to_string(),
        (None, Some(_)) => "loaded".to_string(),
        (None, None) => "unknown".to_string(),
    };
    let error = match &status {
        Some(ModuleSymbolStatus::Failed(error)) => Some(error.clone()),
        _ => None,
    };
    ModuleSymbols {
        status: status_name,
        source: source.as_ref().map(|source| source.label().to_string()),
        pdb_guid: identity
            .as_ref()
            .map(|identity| format!("{:032X}", identity.guid)),
        pdb_age: identity.map(|identity| identity.age),
        error,
    }
}

/// A module's identity with its symbol status (a kernel module's
/// `inspect()`).
pub fn module_with_symbols(target: &Target, info: &ModuleInfo, dtb: Dtb) -> View {
    LoadedModule {
        symbols: Omit(Some(module_symbols(target, info, dtb))),
        ..loaded_module(info)
    }
    .into_view()
}

fn version((major, minor): (u16, u16)) -> String {
    format!("{major}.{minor}")
}

fn file_header(file: &FileHeader) -> ImageFileHeader {
    ImageFileHeader {
        machine: Hex(file.machine.into()),
        machine_name: machine_name(file.machine),
        number_of_sections: file.number_of_sections,
        time_date_stamp: Hex(file.time_date_stamp.into()),
        pointer_to_symbol_table: Hex(file.pointer_to_symbol_table.into()),
        number_of_symbols: file.number_of_symbols,
        size_of_optional_header: Hex(file.size_of_optional_header.into()),
        characteristics: Hex(file.characteristics.into()),
        characteristics_names: file_characteristics(file.characteristics),
    }
}

fn optional_header(optional: &OptionalHeader, base: u64) -> ImageOptionalHeader {
    ImageOptionalHeader {
        magic: Hex(optional.magic.into()),
        linker_version: format!(
            "{}.{}",
            optional.linker_version.0, optional.linker_version.1
        ),
        size_of_code: Hex(optional.size_of_code.into()),
        size_of_initialized_data: Hex(optional.size_of_initialized_data.into()),
        size_of_uninitialized_data: Hex(optional.size_of_uninitialized_data.into()),
        entry_point_rva: Hex(optional.address_of_entry_point.into()),
        entry_point: (optional.address_of_entry_point != 0)
            .then(|| Hex(base.wrapping_add(optional.address_of_entry_point.into()))),
        base_of_code: Hex(optional.base_of_code.into()),
        base_of_data: optional.base_of_data.map(|base| Hex(base.into())),
        image_base: Hex(optional.image_base),
        section_alignment: Hex(optional.section_alignment.into()),
        file_alignment: Hex(optional.file_alignment.into()),
        operating_system_version: version(optional.operating_system_version),
        image_version: version(optional.image_version),
        subsystem_version: version(optional.subsystem_version),
        win32_version_value: Hex(optional.win32_version_value.into()),
        size_of_image: Hex(optional.size_of_image.into()),
        size_of_headers: Hex(optional.size_of_headers.into()),
        checksum: Hex(optional.checksum.into()),
        subsystem: optional.subsystem,
        subsystem_name: subsystem_name(optional.subsystem),
        dll_characteristics: Hex(optional.dll_characteristics.into()),
        dll_characteristics_names: dll_characteristics(optional.dll_characteristics),
        size_of_stack_reserve: Hex(optional.size_of_stack_reserve),
        size_of_stack_commit: Hex(optional.size_of_stack_commit),
        size_of_heap_reserve: Hex(optional.size_of_heap_reserve),
        size_of_heap_commit: Hex(optional.size_of_heap_commit),
        loader_flags: Hex(optional.loader_flags.into()),
        number_of_rva_and_sizes: optional.number_of_rva_and_sizes,
    }
}

fn section_header(section: &SectionHeader) -> ImageSectionHeader {
    ImageSectionHeader {
        name: section.name.clone(),
        virtual_size: Hex(section.virtual_size.into()),
        virtual_address: Hex(section.virtual_address.into()),
        size_of_raw_data: Hex(section.size_of_raw_data.into()),
        pointer_to_raw_data: Hex(section.pointer_to_raw_data.into()),
        pointer_to_relocations: Hex(section.pointer_to_relocations.into()),
        pointer_to_linenumbers: Hex(section.pointer_to_linenumbers.into()),
        number_of_relocations: section.number_of_relocations,
        number_of_linenumbers: section.number_of_linenumbers,
        characteristics: Hex(section.characteristics.into()),
        characteristics_names: section_characteristics(section.characteristics),
    }
}

fn codeview(record: &CodeView) -> CodeViewRecord {
    match record {
        CodeView::Rsds { guid, age, path } => CodeViewRecord {
            format: "RSDS",
            guid: Some(guid.to_string()),
            signature: None,
            age: *age,
            pdb: path.clone(),
        },
        CodeView::Nb10 {
            signature,
            age,
            path,
        } => CodeViewRecord {
            format: "NB10",
            guid: None,
            signature: Some(Hex((*signature).into())),
            age: *age,
            pdb: path.clone(),
        },
    }
}

fn debug_entry(record: &DebugRecord) -> ImageDebugEntry {
    let entry = &record.entry;
    ImageDebugEntry {
        r#type: entry.kind,
        type_name: debug_type_name(entry.kind),
        characteristics: Hex(entry.characteristics.into()),
        time_date_stamp: Hex(entry.time_date_stamp.into()),
        version: version(entry.version),
        size_of_data: Hex(entry.size_of_data.into()),
        address_of_raw_data: Hex(entry.address_of_raw_data.into()),
        pointer_to_raw_data: Hex(entry.pointer_to_raw_data.into()),
        codeview: record.codeview.as_ref().map(|record| {
            Diag::of(
                &record.as_ref().map_or_else(
                    |error| DiagnosticValue::Unavailable(error.clone()),
                    DiagnosticValue::Available,
                ),
                |record| codeview(record),
            )
        }),
    }
}

fn debug_directory(records: &DiagnosticValue<Vec<DebugRecord>>) -> Diag<Vec<ImageDebugEntry>> {
    Diag::of(records, |records| records.iter().map(debug_entry).collect())
}

fn export_directory(directory: &ExportDirectory) -> ImageExportDirectory {
    ImageExportDirectory {
        name: directory.name.clone(),
        characteristics: Hex(directory.characteristics.into()),
        time_date_stamp: Hex(directory.time_date_stamp.into()),
        version: version(directory.version),
        ordinal_base: directory.ordinal_base,
        number_of_functions: directory.number_of_functions,
        number_of_names: directory.number_of_names,
        address_of_functions: Hex(directory.address_of_functions.into()),
        address_of_names: Hex(directory.address_of_names.into()),
        address_of_name_ordinals: Hex(directory.address_of_name_ordinals.into()),
    }
}

fn image_exports(exports: &pe::ImageExports, base: u64) -> ImageExports {
    ImageExports {
        directory: exports.directory.as_ref().map(export_directory),
        exports: exports
            .exports
            .iter()
            .map(|export| ImageExport {
                ordinal: export.ordinal,
                name: export.name.clone(),
                rva: export
                    .address
                    .map(|address| Hex(address.0.wrapping_sub(base))),
                address: export.address.map(|address| Hex(address.0)),
                forwarder: export.forwarder.clone(),
            })
            .collect(),
    }
}

fn import_descriptor(descriptor: &ImportDescriptor) -> ImageImportDescriptor {
    ImageImportDescriptor {
        name: descriptor.name.as_ref().ok().cloned(),
        name_error: descriptor.name.as_ref().err().cloned(),
        import_address_table: Hex(descriptor.first_thunk.into()),
        import_name_table: Hex(descriptor.original_first_thunk.into()),
        time_date_stamp: Hex(descriptor.time_date_stamp.into()),
        forwarder_chain: Hex(descriptor.forwarder_chain.into()),
        imports: descriptor
            .entries
            .iter()
            .map(|entry| {
                let (name, hint, ordinal, error) = match &entry.name {
                    ImportName::Name { hint, name } => {
                        (Some(name.clone()), Some(*hint), None, None)
                    }
                    ImportName::Ordinal(ordinal) => (None, None, Some(*ordinal), None),
                    ImportName::Unnamed => (None, None, None, None),
                    ImportName::Unreadable(error) => (None, None, None, Some(error.clone())),
                };
                ImageImport {
                    name,
                    hint,
                    ordinal,
                    bound: entry.bound.map(Hex),
                    error,
                }
            })
            .collect(),
        incomplete: descriptor.incomplete.clone(),
    }
}

/// `!dh`: a mapped image's headers, with the debug directory, exports, and
/// imports when asked for.
pub fn image_headers(detail: &ImageHeadersDetail) -> View {
    let headers = &detail.headers;
    let base = detail.base.0;
    ImageHeaders {
        base: Hex(base),
        module: detail.module.clone(),
        format: if headers.is_pe32_plus() {
            "PE32+"
        } else {
            "PE32"
        },
        file_header: file_header(&headers.file),
        optional_header: optional_header(&headers.optional, base),
        data_directories: headers
            .directories
            .iter()
            .map(|directory| ImageDataDirectory {
                index: directory.index,
                name: directory.name,
                rva: Hex(directory.rva.into()),
                size: Hex(directory.size.into()),
            })
            .collect(),
        sections: headers.sections.iter().map(section_header).collect(),
        debug_directory: Omit(detail.debug.as_ref().map(debug_directory)),
        exports: Omit(
            detail
                .exports
                .as_ref()
                .map(|exports| Diag::of(exports, |exports| image_exports(exports, base))),
        ),
        imports: Omit(detail.imports.as_ref().map(|imports| {
            Diag::of(imports, |descriptors| {
                descriptors.iter().map(import_descriptor).collect()
            })
        })),
    }
    .into_view()
}

/// `!lmi`: the module, its file-header identity, debug directory (with the
/// CodeView PDB name, GUID, and age), and symbol state.
pub fn module_image_info(target: &Target, detail: &image::ModuleImageInfo) -> View {
    let file = &detail.headers.file;
    let optional = &detail.headers.optional;
    ModuleImageInfo {
        module: loaded_module(&detail.module),
        machine: Hex(file.machine.into()),
        machine_name: machine_name(file.machine),
        time_date_stamp: Hex(file.time_date_stamp.into()),
        size_of_image: Hex(optional.size_of_image.into()),
        checksum: Hex(optional.checksum.into()),
        characteristics: Hex(file.characteristics.into()),
        characteristics_names: file_characteristics(file.characteristics),
        debug_directory: debug_directory(&detail.debug),
        symbols: module_symbols(target, &detail.module, detail.dtb),
        symbol_file: target
            .symbols
            .module_pdb_path(detail.dtb, detail.module.base_address)
            .map(|path| path.display().to_string()),
    }
    .into_view()
}
