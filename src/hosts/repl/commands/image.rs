use crate::base::error::{Error, Result};
use crate::hosts::repl::args::{ArgCursor, ArgCx, ArgError};
use crate::hosts::repl::*;
use crate::hosts::ui;
use crate::nt::expr::Expr;
use crate::nt::pe::ImageExports;
use crate::nt::pe::headers::{CodeView, DebugRecord, ImportDescriptor, ImportName, SectionHeader};
use crate::nt::symbols::ModuleSymbolStatus;
use crate::nt::target::DiagnosticValue;
use crate::nt::target::image::{DhParts, ImageHeaders, ImageRef, ModuleImageInfo};
use crate::session::Session;
use ntoseye_macros::{command, grammar};

/// The image `text` names (see [`crate::nt::target::Target::resolve_image`]),
/// its address evaluated in the current radix.
fn resolve_image(cx: &ArgCx<'_, '_>, text: &str) -> Result<ImageRef> {
    let target = &cx.state.ctx.target;
    let radix = cx.state.ctx.radix;
    let (base, module) =
        target.resolve_image(text, |text| Expr::eval_with_radix(text, target, radix))?;
    Ok(ImageRef {
        base,
        module,
        dtb: None,
    })
}

/// `command`'s argument error. An invalid argument's message already says
/// what is wrong with the word, so it goes without the `invalid argument: `
/// prefix its error type adds.
fn image_error(command: &str, error: Error) -> ArgError {
    let message = match error {
        Error::InvalidArgument(message) => message,
        other => other.to_string(),
    };
    ArgError::Message(format!("{command}: {message}"))
}

/// `!dh`'s options, read from every word without taking any. No words, or
/// `-h`/`-?` alone, print the help.
fn dh_options(cursor: &ArgCursor<'_>) -> std::result::Result<DhParts, ArgError> {
    let words: Vec<&str> = cursor.words().collect();
    if words.is_empty() || words == ["-h"] || words == ["-?"] {
        return Err(ArgError::Missing);
    }
    DhParts::parse(&words)
        .map(|(parts, _)| parts)
        .map_err(|error| ArgError::Message(format!("!dh: {error}")))
}

/// `-e` (or `-a`), possibly among other options in one word (`-fe`).
#[grammar(usage = "")]
fn dh_exports(
    _: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<bool, ArgError> {
    Ok(dh_options(cursor)?.exports)
}

/// `-i` (or `-a`), possibly among other options in one word (`-fi`).
#[grammar(usage = "")]
fn dh_imports(
    _: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<bool, ArgError> {
    Ok(dh_options(cursor)?.imports)
}

/// `[-f] [-s] [-e] [-i] [-a]`: the parts to show, taking the option words.
#[grammar(usage = "[-f] [-s] [-e] [-i] [-a]")]
fn dh_parts(
    _: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<DhParts, ArgError> {
    let parts = dh_options(cursor)?;
    cursor.take_all(|word| word.starts_with('-'));
    Ok(parts)
}

/// `<module|address>`: the one word the options leave.
#[grammar(usage = "<module|address>", complete = [Symbol])]
fn dh_image(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<ImageRef, ArgError> {
    let image = match cursor.remaining() {
        0 => Err(Error::InvalidArgument(
            "give a module name or an address".into(),
        )),
        1 => {
            let text = cursor.word().unwrap_or_default();
            resolve_image(cx, &text)
        }
        _ => Err(Error::InvalidArgument(format!(
            "takes one module or address, got '{}'",
            cursor.rest()
        ))),
    };
    image.map_err(|error| image_error("!dh", error))
}

/// Show the headers of a mapped PE image.
///
/// The argument is a module name, an address, or an image base. A module name
/// is `nt`, `hal`, `ntdll`, or the image name of the module, and ntoseye
/// looks for it in the `.process` module list first, and then in the kernel
/// module list. An address can be any address inside a loaded module. An
/// image base can be the base of an image that no loader list contains, if
/// that image starts with MZ. With no options, the command shows the file and
/// section headers, as WinDbg does. -f: the file header, the optional header
/// (entry point, image base, subsystem, DLL characteristics, stack and heap
/// sizes), and the data directories (RVA and size). For the security
/// directory, the value is a file offset. -s: the section table with decoded
/// flags, and the debug directory with its CodeView PDB name, GUID, and age.
/// -e: the export directory and all exports (ordinal, RVA, name or
/// forwarder). -i: each import descriptor and its imports (hint and name or
/// ordinal), with the address that the loader bound in the IAT. If a
/// descriptor has no import name table, the command shows only the bound
/// addresses, because its IAT no longer contains names. -a: all of these. You
/// can combine options (`-fs`, `-f -i`). If ntoseye cannot read a directory,
/// it shows the directory as unavailable and shows the other data. For
/// example, the import table of a driver is in its INIT section, and Windows
/// discards that section after load. The same applies to an import name or a
/// module name that ntoseye cannot read. The command reads the headers from
/// memory as they are mapped, so the values are the ones that the loader left
/// there.
#[command(
    names = ["!dh", "dh"],
    category = "processes and modules",
    kind = Query,
    python = Module,
    python_name = "headers",
)]
fn dh(
    session: &Session,
    #[arg(parse = dh_exports, default = false)] exports: bool,
    #[arg(parse = dh_imports, default = false)] imports: bool,
    #[arg(parse = dh_parts, render)] parts: DhParts,
    #[arg(receiver, parse = dh_image)] image: ImageRef,
) -> Result<ImageHeaders> {
    session
        .target
        .inspect_image_headers(&image, exports, imports)
        .map_err(|error| Error::DebugInfo(format!("!dh: {error}")))
}

impl Render<DhParts> for ImageHeaders {
    fn render(&self, _: &mut ReplState<'_>, parts: DhParts) {
        print_image_headers(self, parts);
    }
}

/// `<module|address>`: a loaded module's name or an address inside it.
#[grammar(usage = "<module|address>", complete = [Symbol])]
fn lmi_image(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<ImageRef, ArgError> {
    let text = cursor.word().ok_or(ArgError::Missing)?;
    resolve_image(cx, &text).map_err(|error| image_error("!lmi", error))
}

/// Show the image identity, debug directory, and symbol state of a loaded
/// module.
///
/// The argument is a module name as for !dh (`nt`, `ntdll`, an image name),
/// or any address inside the module. From the mapped headers, the command
/// shows the base, image name and path, machine, time stamp, size, checksum,
/// and characteristics. It also shows the debug directory with the CodeView
/// PDB name, GUID, and age. Last, it shows whether symbols are loaded, where
/// they come from, and the local PDB file.
#[command(
    names = ["!lmi", "lmi"],
    category = "processes and modules",
    kind = Query,
    target = Nt,
    python = Module,
    python_name = "image_info",
)]
fn lmi(
    session: &Session,
    #[arg(receiver, parse = lmi_image)] image: ImageRef,
) -> Result<ModuleImageInfo> {
    session
        .target
        .module_image_info(image)
        .map_err(|error| Error::DebugInfo(format!("!lmi: {error}")))
}

impl Render for ModuleImageInfo {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_module_image_info(self);
    }
}

fn print_module_image_info(detail: &ModuleImageInfo) {
    let module = &detail.module;
    let file = &detail.headers.file;
    let optional = &detail.headers.optional;
    outln!("Loaded Module Info: [{}]", module.short_name);
    outln!("         Module: {}", module.short_name);
    outln!("   Base Address: {}", ui::addr(module.base_address.0));
    outln!("     Image Name: {}", module.name);
    if let Some(path) = &module.path {
        outln!("     Image Path: {path}");
    }
    outln!(
        "   Machine Type: {} ({})",
        file.machine,
        file.machine_name()
    );
    outln!("     Time Stamp: {:x}", file.time_date_stamp);
    outln!("           Size: {:x}", optional.size_of_image);
    outln!("       CheckSum: {:x}", optional.checksum);
    let names = file.characteristics_names();
    if names.is_empty() {
        outln!("Characteristics: {:#x}", file.characteristics);
    } else {
        outln!(
            "Characteristics: {:#x} ({})",
            file.characteristics,
            names.join(" | ")
        );
    }
    print_debug_directory(&detail.debug);
    let symbols = &detail.symbols;
    let source = symbols
        .source
        .as_ref()
        .map(|source| format!(" (from {})", source.label()))
        .unwrap_or_default();
    outln!(
        "    Symbol Type: {}{source}",
        symbols
            .status
            .as_ref()
            .map_or("-", ModuleSymbolStatus::label)
    );
    if let Some(ModuleSymbolStatus::Failed(reason)) = &symbols.status {
        outln!("                 {reason}");
    }
    if let Some(identity) = &symbols.pdb {
        outln!(
            "            PDB: GUID {:032X}, age {}",
            identity.guid,
            identity.age
        );
    }
    if let Some(path) = &detail.symbol_file {
        outln!("    Symbol File: {path}");
    }
}

fn print_image_headers(detail: &ImageHeaders, parts: DhParts) {
    outln!(
        "{}  {}",
        ui::addr(detail.base.0),
        detail
            .module
            .as_deref()
            .unwrap_or("<image in no loader list>")
    );
    outln!();
    if parts.file {
        print_file_headers(detail);
    }
    if parts.sections {
        print_debug_directory(&detail.debug);
        for (index, section) in detail.sections.iter().enumerate() {
            print_section(index + 1, section);
        }
    }
    if let Some(exports) = &detail.exports {
        print_exports(exports);
    }
    if let Some(imports) = &detail.imports {
        print_imports(imports);
    }
}

fn print_flags(names: &[String]) {
    for name in names {
        outln!("            {name}");
    }
}

fn print_file_headers(detail: &ImageHeaders) {
    let ImageHeaders {
        file,
        optional,
        directories,
        ..
    } = detail;
    let file_type = if file.is_dll() {
        "DLL"
    } else {
        "EXECUTABLE IMAGE"
    };
    outln!("File Type: {file_type}");
    outln!("FILE HEADER VALUES");
    outln!("{:>8X} machine ({})", file.machine, file.machine_name());
    outln!("{:>8X} number of sections", file.number_of_sections);
    outln!("{:>8X} time date stamp", file.time_date_stamp);
    outln!(
        "{:>8X} file pointer to symbol table",
        file.pointer_to_symbol_table
    );
    outln!("{:>8X} number of symbols", file.number_of_symbols);
    outln!(
        "{:>8X} size of optional header",
        file.size_of_optional_header
    );
    outln!("{:>8X} characteristics", file.characteristics);
    print_flags(&file.characteristics_names());
    outln!();

    let format = detail.format();
    outln!("OPTIONAL HEADER VALUES");
    outln!("{:>8X} magic # ({format})", optional.magic);
    outln!(
        "{:>5}.{:<2} linker version",
        optional.linker_version.0,
        optional.linker_version.1
    );
    outln!("{:>8X} size of code", optional.size_of_code);
    outln!(
        "{:>8X} size of initialized data",
        optional.size_of_initialized_data
    );
    outln!(
        "{:>8X} size of uninitialized data",
        optional.size_of_uninitialized_data
    );
    outln!(
        "{:>8X} address of entry point ({})",
        optional.address_of_entry_point,
        detail
            .entry_point()
            .map_or_else(|| "-".to_string(), ui::addr)
    );
    outln!("{:>8X} base of code", optional.base_of_code);
    if let Some(base_of_data) = optional.base_of_data {
        outln!("{base_of_data:>8X} base of data");
    }
    outln!("         ----- new -----");
    outln!("{:>8X} image base", optional.image_base);
    outln!("{:>8X} section alignment", optional.section_alignment);
    outln!("{:>8X} file alignment", optional.file_alignment);
    outln!(
        "{:>8X} subsystem ({})",
        optional.subsystem,
        optional.subsystem_name()
    );
    for (label, (major, minor)) in [
        (
            "operating system version",
            optional.operating_system_version,
        ),
        ("image version", optional.image_version),
        ("subsystem version", optional.subsystem_version),
    ] {
        outln!("{:>5}.{:<2} {label}", major, minor);
    }
    outln!("{:>8X} Win32 version value", optional.win32_version_value);
    outln!("{:>8X} size of image", optional.size_of_image);
    outln!("{:>8X} size of headers", optional.size_of_headers);
    outln!("{:>8X} checksum", optional.checksum);
    outln!(
        "{:>8X} size of stack reserve",
        optional.size_of_stack_reserve
    );
    outln!("{:>8X} size of stack commit", optional.size_of_stack_commit);
    outln!("{:>8X} size of heap reserve", optional.size_of_heap_reserve);
    outln!("{:>8X} size of heap commit", optional.size_of_heap_commit);
    outln!("{:>8X} loader flags", optional.loader_flags);
    outln!(
        "{:>8X} number of directories",
        optional.number_of_rva_and_sizes
    );
    outln!("{:>8X} DLL characteristics", optional.dll_characteristics);
    print_flags(&optional.dll_characteristics_names());
    for directory in directories {
        outln!(
            "{:>8X} [{:>8X}] address [size] of {} Directory",
            directory.rva,
            directory.size,
            directory.name
        );
    }
    outln!();
}

fn print_debug_directory(debug: &DiagnosticValue<Vec<DebugRecord>>) {
    let records = match debug {
        DiagnosticValue::Available(records) => records,
        DiagnosticValue::Unavailable(error) => {
            outln!("Debug Directories: <unavailable: {error}>\n");
            return;
        }
    };
    if records.is_empty() {
        return;
    }
    outln!("Debug Directories({})", records.len());
    outln!("    Type                         Size  Address   Pointer");
    for record in records {
        let format = match &record.codeview {
            None => String::new(),
            Some(DiagnosticValue::Available(CodeView::Rsds { guid, age, path })) => {
                format!("  Format: RSDS, guid {guid}, age {age}, {path}")
            }
            Some(DiagnosticValue::Available(CodeView::Nb10 {
                signature,
                age,
                path,
            })) => format!("  Format: NB10, signature {signature:X}, age {age}, {path}"),
            Some(DiagnosticValue::Unavailable(error)) => format!("  <unavailable: {error}>"),
        };
        let entry = &record.entry;
        outln!(
            "    {:<26} {:>6X} {:>8X} {:>8X}{format}",
            format!("{} ({})", record.type_name(), entry.kind),
            entry.size_of_data,
            entry.address_of_raw_data,
            entry.pointer_to_raw_data
        );
    }
    outln!();
}

fn print_section(number: usize, section: &SectionHeader) {
    outln!("SECTION HEADER #{number}");
    outln!("{:>8} name", section.name);
    outln!("{:>8X} virtual size", section.virtual_size);
    outln!("{:>8X} virtual address", section.virtual_address);
    outln!("{:>8X} size of raw data", section.size_of_raw_data);
    outln!(
        "{:>8X} file pointer to raw data",
        section.pointer_to_raw_data
    );
    outln!(
        "{:>8X} file pointer to relocation table",
        section.pointer_to_relocations
    );
    outln!(
        "{:>8X} file pointer to line numbers",
        section.pointer_to_linenumbers
    );
    outln!(
        "{:>8X} number of relocations",
        section.number_of_relocations
    );
    outln!(
        "{:>8X} number of line numbers",
        section.number_of_linenumbers
    );
    outln!("{:>8X} flags", section.characteristics);
    for name in section.characteristics_names() {
        outln!("         {name}");
    }
    outln!();
}

fn print_exports(exports: &DiagnosticValue<ImageExports>) {
    let exports = match exports {
        DiagnosticValue::Available(exports) => exports,
        DiagnosticValue::Unavailable(error) => {
            outln!("EXPORTS: <unavailable: {error}>\n");
            return;
        }
    };
    let Some(directory) = &exports.directory else {
        outln!("EXPORTS: none (the export directory is empty)\n");
        return;
    };
    outln!("EXPORTS");
    outln!("    Name: {}", directory.name);
    outln!("{:>8X} characteristics", directory.characteristics);
    outln!("{:>8X} time date stamp", directory.time_date_stamp);
    outln!(
        "{:>5}.{:<2} version",
        directory.version.0,
        directory.version.1
    );
    outln!("{:>8X} ordinal base", directory.ordinal_base);
    outln!("{:>8X} number of functions", directory.number_of_functions);
    outln!("{:>8X} number of names", directory.number_of_names);
    outln!();
    outln!("    ordinal      RVA  name");
    for export in &exports.exports {
        let rva = export
            .rva
            .map(|rva| format!("{rva:>8X}"))
            .unwrap_or_else(|| format!("{:>8}", "-"));
        let name = export.name.as_deref().unwrap_or("[NONAME]");
        match &export.forwarder {
            Some(forwarder) => outln!(
                "    {:>7} {rva}  {name} (forwarded to {forwarder})",
                export.ordinal
            ),
            None => outln!("    {:>7} {rva}  {name}", export.ordinal),
        }
    }
    outln!();
}

fn print_imports(imports: &DiagnosticValue<Vec<ImportDescriptor>>) {
    let descriptors = match imports {
        DiagnosticValue::Available(descriptors) => descriptors,
        DiagnosticValue::Unavailable(error) => {
            outln!("IMPORTS: <unavailable: {error}>\n");
            return;
        }
    };
    if descriptors.is_empty() {
        outln!("IMPORTS: none (the import directory is empty)\n");
        return;
    }
    outln!("IMPORTS");
    for descriptor in descriptors {
        match &descriptor.name {
            Ok(name) => outln!("  _IMAGE_IMPORT_DESCRIPTOR {name}"),
            Err(error) => outln!(
                "  _IMAGE_IMPORT_DESCRIPTOR {}",
                ui::muted(&format!("<name unreadable: {error}>"))
            ),
        }
        outln!("{:>10X} Import Address Table", descriptor.first_thunk);
        outln!("{:>10X} Import Name Table", descriptor.original_first_thunk);
        outln!("{:>10X} time date stamp", descriptor.time_date_stamp);
        outln!(
            "{:>10X} Index of first forwarder reference",
            descriptor.forwarder_chain
        );
        outln!();
        if descriptor.original_first_thunk == 0 {
            outln!(
                "    {}",
                ui::muted("no import name table: the bound IAT holds addresses, not names")
            );
        }
        for entry in &descriptor.entries {
            let bound = entry
                .bound
                .map(ui::addr)
                .unwrap_or_else(|| ui::muted("unreadable"));
            match &entry.name {
                ImportName::Name { hint, name } => outln!("    {bound} {hint:>5X} {name}"),
                ImportName::Ordinal(ordinal) => {
                    outln!("    {bound}       Ordinal {ordinal}")
                }
                ImportName::Unnamed => outln!("    {bound}"),
                ImportName::Unreadable(error) => outln!(
                    "    {bound}       {}",
                    ui::muted(&format!("<name unreadable: {error}>"))
                ),
            }
        }
        if let Some(error) = &descriptor.incomplete {
            outln!(
                "    {}",
                ui::muted(&format!("<imports stop here: {error}>"))
            );
        }
        outln!();
    }
}
