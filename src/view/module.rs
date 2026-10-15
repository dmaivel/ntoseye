//! Loaded-module [`View`] builders: module identity and symbol
//! load status.

use ntoseye_macros::record;

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
use crate::types::VirtAddr;

/// A loaded image (`lm`).
#[record]
pub struct LoadedModule {
    /// The image file name (`ntoskrnl.exe`).
    pub name: String,
    /// The short name that `module!symbol` uses (`nt`).
    pub short_name: String,
    /// The full image path, if the loader recorded one.
    pub path: Option<String>,
    pub base: VirtAddr,
    /// The address after the last byte of the image.
    #[record(hex)]
    pub end: u64,
    /// The mapped image size in bytes.
    pub size: u32,
    /// The PE timestamp. `None` if the loader record does not contain one.
    #[record(hex)]
    pub time_date_stamp: Option<u32>,
    /// The PE checksum. `None` if the loader record does not contain one.
    #[record(hex)]
    pub checksum: Option<u32>,
    /// The file version from the version resource. `None` if ntoseye did not read it.
    pub file_version: Option<String>,
    /// The product version from the version resource. `None` if ntoseye did not read it.
    pub product_version: Option<String>,
    /// The symbol status. `None` except in `inspect()` of a kernel module.
    pub symbols: Option<ModuleSymbols>,
}

/// The symbol status and PDB identity of a module (`lmv`).
#[record]
pub struct ModuleSymbols {
    /// `loaded`, `deferred`, `failed`, `unknown`, ...
    pub status: String,
    /// The source of the PDB, if known.
    pub source: Option<String>,
    /// The GUID of the loaded PDB as 32 hex digits. `None` if there is no PDB.
    pub pdb_guid: Option<String>,
    /// The age of the loaded PDB. `None` if there is no PDB.
    pub pdb_age: Option<u32>,
    /// The reason for the load failure, for status `failed`.
    pub error: Option<String>,
}

/// The result of a symbol reload. It counts the modules that loaded, had
/// no PDB, were skipped, or failed, and keeps the first diagnostics up to
/// a limit.
#[record]
pub struct SymbolReloadReport {
    pub total: usize,
    pub loaded: usize,
    /// The number of modules with symbols that unloaded after the previous refresh.
    pub unloaded: usize,
    pub no_pdb: usize,
    pub skipped: usize,
    pub failed: usize,
    /// The number of all diagnostics, including those after the limit of `diagnostics`.
    pub diagnostic_count: usize,
    pub diagnostics: Vec<SymbolLoadDiagnostic>,
}

/// One problem that ntoseye found when it loaded the symbols of a module.
#[record]
pub struct SymbolLoadDiagnostic {
    pub module: String,
    /// The load step that reported it.
    pub phase: String,
    /// The compiland of the problem, if the problem is specific to one compiland.
    pub compiland: Option<String>,
    pub message: String,
}

/// `IMAGE_FILE_HEADER`.
#[record]
pub struct ImageFileHeader {
    #[record(hex)]
    pub machine: u16,
    /// `AMD64`, `I386`, ...
    pub machine_name: &'static str,
    pub number_of_sections: u16,
    #[record(hex)]
    pub time_date_stamp: u32,
    #[record(hex)]
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    #[record(hex)]
    pub size_of_optional_header: u16,
    #[record(hex)]
    pub characteristics: u16,
    /// The `IMAGE_FILE_*` flags that are set in `characteristics`.
    pub characteristics_names: Vec<String>,
}

/// `IMAGE_OPTIONAL_HEADER` (PE32 or PE32+).
#[record]
pub struct ImageOptionalHeader {
    #[record(hex)]
    pub magic: u16,
    /// `major.minor`.
    pub linker_version: String,
    #[record(hex)]
    pub size_of_code: u32,
    #[record(hex)]
    pub size_of_initialized_data: u32,
    #[record(hex)]
    pub size_of_uninitialized_data: u32,
    #[record(hex)]
    pub entry_point_rva: u32,
    /// The mapped entry point. `None` if the image has no entry point.
    #[record(hex)]
    pub entry_point: Option<u64>,
    #[record(hex)]
    pub base_of_code: u32,
    /// Only for PE32. `None` for PE32+.
    #[record(hex)]
    pub base_of_data: Option<u32>,
    /// The preferred base address for which the image was linked.
    #[record(hex)]
    pub image_base: u64,
    #[record(hex)]
    pub section_alignment: u32,
    #[record(hex)]
    pub file_alignment: u32,
    /// `major.minor`.
    pub operating_system_version: String,
    /// `major.minor`.
    pub image_version: String,
    /// `major.minor`.
    pub subsystem_version: String,
    #[record(hex)]
    pub win32_version_value: u32,
    #[record(hex)]
    pub size_of_image: u32,
    #[record(hex)]
    pub size_of_headers: u32,
    #[record(hex)]
    pub checksum: u32,
    pub subsystem: u16,
    /// `Native`, `Windows GUI`, ...
    pub subsystem_name: &'static str,
    #[record(hex)]
    pub dll_characteristics: u16,
    /// The `IMAGE_DLLCHARACTERISTICS_*` flags that are set.
    pub dll_characteristics_names: Vec<String>,
    #[record(hex)]
    pub size_of_stack_reserve: u64,
    #[record(hex)]
    pub size_of_stack_commit: u64,
    #[record(hex)]
    pub size_of_heap_reserve: u64,
    #[record(hex)]
    pub size_of_heap_commit: u64,
    #[record(hex)]
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}

/// One `IMAGE_DATA_DIRECTORY` entry.
#[record]
pub struct ImageDataDirectory {
    /// The slot of the entry in the directory table.
    pub index: usize,
    /// `Export`, `Import`, `Debug`, ...
    pub name: &'static str,
    #[record(hex)]
    pub rva: u32,
    #[record(hex)]
    pub size: u32,
}

/// One `IMAGE_SECTION_HEADER`.
#[record]
pub struct ImageSectionHeader {
    pub name: String,
    #[record(hex)]
    pub virtual_size: u32,
    /// The RVA of the section.
    #[record(hex)]
    pub virtual_address: u32,
    #[record(hex)]
    pub size_of_raw_data: u32,
    #[record(hex)]
    pub pointer_to_raw_data: u32,
    #[record(hex)]
    pub pointer_to_relocations: u32,
    #[record(hex)]
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    #[record(hex)]
    pub characteristics: u32,
    /// The `IMAGE_SCN_*` flags that are set.
    pub characteristics_names: Vec<String>,
}

/// A CodeView debug record, which identifies the PDB that the image was built with.
#[record]
pub struct CodeViewRecord {
    /// `RSDS` (PDB 7.0) or `NB10` (PDB 2.0).
    pub format: &'static str,
    /// The PDB GUID, for `RSDS`.
    pub guid: Option<String>,
    /// The PDB timestamp signature, for `NB10`.
    #[record(hex)]
    pub signature: Option<u32>,
    pub age: u32,
    /// The PDB path that the linker recorded.
    pub pdb: String,
}

/// One `IMAGE_DEBUG_DIRECTORY` entry.
#[record]
pub struct ImageDebugEntry {
    /// The `IMAGE_DEBUG_TYPE_*` value.
    pub r#type: u32,
    /// `CODEVIEW`, `POGO`, ...
    pub type_name: &'static str,
    #[record(hex)]
    pub characteristics: u32,
    #[record(hex)]
    pub time_date_stamp: u32,
    /// `major.minor`.
    pub version: String,
    #[record(hex)]
    pub size_of_data: u32,
    #[record(hex)]
    pub address_of_raw_data: u32,
    #[record(hex)]
    pub pointer_to_raw_data: u32,
    /// The decoded CodeView record. `None` for other entry types.
    pub codeview: Option<DiagnosticValue<CodeViewRecord>>,
}

/// `IMAGE_EXPORT_DIRECTORY`.
#[record]
pub struct ImageExportDirectory {
    /// The DLL name that the directory records.
    pub name: String,
    #[record(hex)]
    pub characteristics: u32,
    #[record(hex)]
    pub time_date_stamp: u32,
    /// `major.minor`.
    pub version: String,
    pub ordinal_base: u32,
    pub number_of_functions: u32,
    pub number_of_names: u32,
    #[record(hex)]
    pub address_of_functions: u32,
    #[record(hex)]
    pub address_of_names: u32,
    #[record(hex)]
    pub address_of_name_ordinals: u32,
}

/// The export directory and the exports of an image (`!dh -e`).
#[record]
pub struct ImageExports {
    /// `None` if the image has no exports.
    pub directory: Option<ImageExportDirectory>,
    pub exports: Vec<Export>,
}

/// One PE export (`Module.exports`, `!dh -e`). An export has a name or
/// only an ordinal, and a forwarder has no address.
#[record]
pub struct Export {
    pub ordinal: u32,
    /// `None` for an ordinal-only export.
    pub name: Option<String>,
    /// `None` for a forwarder.
    #[record(hex)]
    pub rva: Option<u64>,
    /// The mapped address. `None` for a forwarder.
    pub address: Option<VirtAddr>,
    /// The target of a forwarder (`OTHER.Function`).
    pub forwarder: Option<String>,
}

/// One `IMAGE_IMPORT_DESCRIPTOR`, which identifies a DLL that the image imports from.
#[record]
pub struct ImageImportDescriptor {
    /// The DLL name. `None` if ntoseye could not read it.
    pub name: Option<String>,
    /// The reason that ntoseye could not read the DLL name.
    pub name_error: Option<String>,
    #[record(hex)]
    pub import_address_table: u32,
    #[record(hex)]
    pub import_name_table: u32,
    #[record(hex)]
    pub time_date_stamp: u32,
    #[record(hex)]
    pub forwarder_chain: u32,
    pub imports: Vec<ImageImport>,
    /// The reason that the thunk walk stopped early, if it did.
    pub incomplete: Option<String>,
}

/// One imported function.
#[record]
pub struct ImageImport {
    /// The imported name. `None` for an import by ordinal, or for an import
    /// that ntoseye could not read.
    pub name: Option<String>,
    /// The export-name-table hint, for a named import.
    pub hint: Option<u16>,
    /// The ordinal, for an import by ordinal.
    pub ordinal: Option<u16>,
    /// The bound address in the import address table.
    #[record(hex)]
    pub bound: Option<u64>,
    /// The reason that ntoseye could not read the import name.
    pub error: Option<String>,
}

/// The headers of a mapped image (`!dh`).
#[record]
pub struct ImageHeaders {
    #[record(hex)]
    pub base: u64,
    /// The loaded module at `base`, if there is one.
    pub module: Option<String>,
    /// `PE32` or `PE32+`.
    pub format: &'static str,
    pub file_header: ImageFileHeader,
    pub optional_header: ImageOptionalHeader,
    pub data_directories: Vec<ImageDataDirectory>,
    pub sections: Vec<ImageSectionHeader>,
    /// The debug directory. `None` if you did not ask for it.
    pub debug_directory: Option<DiagnosticValue<Vec<ImageDebugEntry>>>,
    /// The export directory. `None` if you did not ask for it.
    pub exports: Option<DiagnosticValue<ImageExports>>,
    /// The import descriptors. `None` if you did not ask for them.
    pub imports: Option<DiagnosticValue<Vec<ImageImportDescriptor>>>,
}

/// The image identity of a module (`!lmi`), with the file-header identity,
/// the symbol state, and the debug directory, which includes the CodeView
/// PDB name, GUID, and age.
#[record]
pub struct ModuleImageInfo {
    pub module: LoadedModule,
    #[record(hex)]
    pub machine: u16,
    /// `AMD64`, `I386`, ...
    pub machine_name: &'static str,
    #[record(hex)]
    pub time_date_stamp: u32,
    #[record(hex)]
    pub size_of_image: u32,
    #[record(hex)]
    pub checksum: u32,
    #[record(hex)]
    pub characteristics: u16,
    /// The `IMAGE_FILE_*` flags that are set in `characteristics`.
    pub characteristics_names: Vec<String>,
    pub debug_directory: DiagnosticValue<Vec<ImageDebugEntry>>,
    pub symbols: ModuleSymbols,
    /// The local PDB file, if a PDB is loaded.
    pub symbol_file: Option<String>,
}

/// One PE section with its name, RVA, mapped size, and `rwx` permissions.
#[record]
pub struct Section {
    /// The section name (`.text`).
    pub name: String,
    /// The offset of the section from the image base.
    #[record(hex)]
    pub rva: u32,
    /// The mapped size of the section.
    #[record(hex)]
    pub size: u32,
    /// The mapped permissions as `rwx`, with `-` for a missing permission.
    pub permissions: String,
}

/// A loaded image's identity, without its symbol status.
pub fn module(module: &ModuleInfo) -> LoadedModule {
    LoadedModule {
        name: module.name.clone(),
        short_name: module.short_name.clone(),
        path: module.path.clone(),
        base: module.base_address,
        end: module.end_address().0,
        size: module.size,
        time_date_stamp: module.time_date_stamp,
        checksum: module.checksum,
        file_version: module.file_version.clone(),
        product_version: module.product_version.clone(),
        symbols: None,
    }
}

/// The outcome of a symbol reload.
pub fn module_symbol_report(report: &ModuleSymbolLoadReport) -> SymbolReloadReport {
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

/// A module as `Module.inspect()` decodes it: a kernel module from the
/// loaded-module list, or a process module from its loader list.
#[record]
pub enum ModuleDetail {
    Kernel(LoadedModule),
    Process(super::usermode::LoaderModule),
}

/// A module's identity with its symbol status (a kernel module's
/// `inspect()`).
pub fn module_with_symbols(target: &Target, info: &ModuleInfo, dtb: Dtb) -> LoadedModule {
    LoadedModule {
        symbols: Some(module_symbols(target, info, dtb)),
        ..module(info)
    }
}

fn version((major, minor): (u16, u16)) -> String {
    format!("{major}.{minor}")
}

fn file_header(file: &FileHeader) -> ImageFileHeader {
    ImageFileHeader {
        machine: file.machine,
        machine_name: machine_name(file.machine),
        number_of_sections: file.number_of_sections,
        time_date_stamp: file.time_date_stamp,
        pointer_to_symbol_table: file.pointer_to_symbol_table,
        number_of_symbols: file.number_of_symbols,
        size_of_optional_header: file.size_of_optional_header,
        characteristics: file.characteristics,
        characteristics_names: file_characteristics(file.characteristics),
    }
}

fn optional_header(optional: &OptionalHeader, base: u64) -> ImageOptionalHeader {
    ImageOptionalHeader {
        magic: optional.magic,
        linker_version: format!(
            "{}.{}",
            optional.linker_version.0, optional.linker_version.1
        ),
        size_of_code: optional.size_of_code,
        size_of_initialized_data: optional.size_of_initialized_data,
        size_of_uninitialized_data: optional.size_of_uninitialized_data,
        entry_point_rva: optional.address_of_entry_point,
        entry_point: (optional.address_of_entry_point != 0)
            .then(|| base.wrapping_add(optional.address_of_entry_point.into())),
        base_of_code: optional.base_of_code,
        base_of_data: optional.base_of_data,
        image_base: optional.image_base,
        section_alignment: optional.section_alignment,
        file_alignment: optional.file_alignment,
        operating_system_version: version(optional.operating_system_version),
        image_version: version(optional.image_version),
        subsystem_version: version(optional.subsystem_version),
        win32_version_value: optional.win32_version_value,
        size_of_image: optional.size_of_image,
        size_of_headers: optional.size_of_headers,
        checksum: optional.checksum,
        subsystem: optional.subsystem,
        subsystem_name: subsystem_name(optional.subsystem),
        dll_characteristics: optional.dll_characteristics,
        dll_characteristics_names: dll_characteristics(optional.dll_characteristics),
        size_of_stack_reserve: optional.size_of_stack_reserve,
        size_of_stack_commit: optional.size_of_stack_commit,
        size_of_heap_reserve: optional.size_of_heap_reserve,
        size_of_heap_commit: optional.size_of_heap_commit,
        loader_flags: optional.loader_flags,
        number_of_rva_and_sizes: optional.number_of_rva_and_sizes,
    }
}

fn section_header(section: &SectionHeader) -> ImageSectionHeader {
    ImageSectionHeader {
        name: section.name.clone(),
        virtual_size: section.virtual_size,
        virtual_address: section.virtual_address,
        size_of_raw_data: section.size_of_raw_data,
        pointer_to_raw_data: section.pointer_to_raw_data,
        pointer_to_relocations: section.pointer_to_relocations,
        pointer_to_linenumbers: section.pointer_to_linenumbers,
        number_of_relocations: section.number_of_relocations,
        number_of_linenumbers: section.number_of_linenumbers,
        characteristics: section.characteristics,
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
            signature: Some(*signature),
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
        characteristics: entry.characteristics,
        time_date_stamp: entry.time_date_stamp,
        version: version(entry.version),
        size_of_data: entry.size_of_data,
        address_of_raw_data: entry.address_of_raw_data,
        pointer_to_raw_data: entry.pointer_to_raw_data,
        codeview: record.codeview.as_ref().map(|record| {
            record
                .as_ref()
                .map_or_else(
                    |error| DiagnosticValue::unavailable(error.clone()),
                    DiagnosticValue::Available,
                )
                .map(|record| codeview(record))
        }),
    }
}

fn debug_directory(
    records: &DiagnosticValue<Vec<DebugRecord>>,
) -> DiagnosticValue<Vec<ImageDebugEntry>> {
    records.map(|records| records.iter().map(debug_entry).collect())
}

fn export_directory(directory: &ExportDirectory) -> ImageExportDirectory {
    ImageExportDirectory {
        name: directory.name.clone(),
        characteristics: directory.characteristics,
        time_date_stamp: directory.time_date_stamp,
        version: version(directory.version),
        ordinal_base: directory.ordinal_base,
        number_of_functions: directory.number_of_functions,
        number_of_names: directory.number_of_names,
        address_of_functions: directory.address_of_functions,
        address_of_names: directory.address_of_names,
        address_of_name_ordinals: directory.address_of_name_ordinals,
    }
}

/// One export of the image mapped at `base`.
pub fn export(export: &pe::ModuleExportInfo, base: u64) -> Export {
    Export {
        ordinal: export.ordinal,
        name: export.name.clone(),
        rva: export.address.map(|address| address.0.wrapping_sub(base)),
        address: export.address,
        forwarder: export.forwarder.clone(),
    }
}

fn image_exports(exports: &pe::ImageExports, base: u64) -> ImageExports {
    ImageExports {
        directory: exports.directory.as_ref().map(export_directory),
        exports: exports
            .exports
            .iter()
            .map(|export| self::export(export, base))
            .collect(),
    }
}

fn import_descriptor(descriptor: &ImportDescriptor) -> ImageImportDescriptor {
    ImageImportDescriptor {
        name: descriptor.name.as_ref().ok().cloned(),
        name_error: descriptor.name.as_ref().err().cloned(),
        import_address_table: descriptor.first_thunk,
        import_name_table: descriptor.original_first_thunk,
        time_date_stamp: descriptor.time_date_stamp,
        forwarder_chain: descriptor.forwarder_chain,
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
                    bound: entry.bound,
                    error,
                }
            })
            .collect(),
        incomplete: descriptor.incomplete.clone(),
    }
}

/// `!dh`: a mapped image's headers, with the debug directory, exports, and
/// imports when asked for.
pub fn image_headers(detail: &ImageHeadersDetail) -> ImageHeaders {
    let headers = &detail.headers;
    let base = detail.base.0;
    ImageHeaders {
        base,
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
                rva: directory.rva,
                size: directory.size,
            })
            .collect(),
        sections: headers.sections.iter().map(section_header).collect(),
        debug_directory: detail.debug.as_ref().map(debug_directory),
        exports: detail
            .exports
            .as_ref()
            .map(|exports| exports.map(|exports| image_exports(exports, base))),
        imports: detail.imports.as_ref().map(|imports| {
            imports.map(|descriptors| descriptors.iter().map(import_descriptor).collect())
        }),
    }
}

/// `!lmi`: the module, its file-header identity, debug directory (with the
/// CodeView PDB name, GUID, and age), and symbol state.
pub fn module_image_info(target: &Target, detail: &image::ModuleImageInfo) -> ModuleImageInfo {
    let file = &detail.headers.file;
    let optional = &detail.headers.optional;
    ModuleImageInfo {
        module: module(&detail.module),
        machine: file.machine,
        machine_name: machine_name(file.machine),
        time_date_stamp: file.time_date_stamp,
        size_of_image: optional.size_of_image,
        checksum: optional.checksum,
        characteristics: file.characteristics,
        characteristics_names: file_characteristics(file.characteristics),
        debug_directory: debug_directory(&detail.debug),
        symbols: module_symbols(target, &detail.module, detail.dtb),
        symbol_file: target
            .symbols
            .module_pdb_path(detail.dtb, detail.module.base_address)
            .map(|path| path.display().to_string()),
    }
}
