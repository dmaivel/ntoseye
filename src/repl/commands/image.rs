use crate::error::Result;
use crate::expr::Expr;
use crate::pe::ImageExports;
use crate::pe::headers::{
    CodeView, DebugRecord, ImageHeaders, ImportDescriptor, ImportName, SectionHeader,
    debug_type_name, dll_characteristics, file_characteristics, machine_name,
    section_characteristics, subsystem_name,
};
use crate::repl::*;
use crate::symbols::ModuleSymbolStatus;
use crate::target::image::{ImageHeadersDetail, ModuleImageInfo};
use crate::target::{DiagnosticValue, Target};
use crate::ui;

repl_command! {
    cmd_dh;
    names: ["!dh", "dh"],
    usage: "!dh [-f] [-s] [-e] [-i] [-a] <module|address>",
    summary: "Show the headers of a mapped PE image.",
    details: "The argument is a module name, an address, or an image base. A module name is `nt`, `hal`, `ntdll`, or the image name of the module, and ntoseye looks for it in the `.process` module list first, and then in the kernel module list. An address can be any address inside a loaded module. An image base can be the base of an image that no loader list contains, if that image starts with MZ. With no options, the command shows the file and section headers, as WinDbg does. -f: the file header, the optional header (entry point, image base, subsystem, DLL characteristics, stack and heap sizes), and the data directories (RVA and size). For the security directory, the value is a file offset. -s: the section table with decoded flags, and the debug directory with its CodeView PDB name, GUID, and age. -e: the export directory and all exports (ordinal, RVA, name or forwarder). -i: each import descriptor and its imports (hint and name or ordinal), with the address that the loader bound in the IAT. If a descriptor has no import name table, the command shows only the bound addresses, because its IAT no longer contains names. -a: all of these. You can combine options (`-fs`, `-f -i`). If ntoseye cannot read a directory, it shows the directory as unavailable and shows the other data. For example, the import table of a driver is in its INIT section, and Windows discards that section after load. The same applies to an import name or a module name that ntoseye cannot read. The command reads the headers from memory as they are mapped, so the values are the ones that the loader left there.",
    completion: [Symbol],
}

repl_command! {
    cmd_lmi;
    names: ["!lmi", "lmi"],
    usage: "!lmi <module|address>",
    summary: "Show the image identity, debug directory, and symbol state of a loaded module.",
    details: "The argument is a module name as for !dh (`nt`, `ntdll`, an image name), or any address inside the module. From the mapped headers, the command shows the base, image name and path, machine, time stamp, size, checksum, and characteristics. It also shows the debug directory with the CodeView PDB name, GUID, and age. Last, it shows whether symbols are loaded, where they come from, and the local PDB file.",
    completion: [Symbol],
}

impl ReplState<'_> {
    fn cmd_dh(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let args: Vec<&str> = invocation.argv.iter().map(|arg| arg.as_ref()).collect();
        if args.is_empty() || args == ["-h"] || args == ["-?"] {
            outln!("{}\n", command_help("!dh"));
            return Ok(());
        }
        let target = &self.ctx.target;
        let radix = self.radix;
        match target.inspect_image_headers(&args, |text| Expr::eval_with_radix(text, target, radix))
        {
            Ok(detail) => print_image_headers(&detail),
            Err(error) => error!("!dh: {error}"),
        }
        Ok(())
    }

    fn cmd_lmi(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let text = require_arg!(invocation, 0, "!lmi");
        let target = &self.ctx.target;
        let radix = self.radix;
        match target.module_image_info(text, |text| Expr::eval_with_radix(text, target, radix)) {
            Ok(detail) => print_module_image_info(target, &detail),
            Err(error) => error!("!lmi: {error}"),
        }
        Ok(())
    }
}

fn print_module_image_info(target: &Target, detail: &ModuleImageInfo) {
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
        machine_name(file.machine)
    );
    outln!("     Time Stamp: {:x}", file.time_date_stamp);
    outln!("           Size: {:x}", optional.size_of_image);
    outln!("       CheckSum: {:x}", optional.checksum);
    outln!(
        "Characteristics: {:x}  {}",
        file.characteristics,
        file_characteristics(file.characteristics).join(", ")
    );
    print_debug_directory(&detail.debug);
    let symbols = &target.symbols;
    let base = module.base_address;
    let status = symbols.module_symbol_status(detail.dtb, base);
    let source = symbols
        .module_symbol_source(detail.dtb, base)
        .map(|source| format!(" (from {})", source.label()))
        .unwrap_or_default();
    outln!(
        "    Symbol Type: {}{source}",
        status.as_ref().map_or("unknown", ModuleSymbolStatus::label)
    );
    if let Some(ModuleSymbolStatus::Failed(reason)) = &status {
        outln!("                 {reason}");
    }
    if let Some(identity) = symbols.module_pdb_identity(detail.dtb, base) {
        outln!(
            "            PDB: GUID {:032X}, age {}",
            identity.guid,
            identity.age
        );
    }
    if let Some(path) = symbols.module_pdb_path(detail.dtb, base) {
        outln!("    Symbol File: {}", path.display());
    }
    outln!();
}

fn print_image_headers(detail: &ImageHeadersDetail) {
    let headers = &detail.headers;
    outln!(
        "{}  {}",
        ui::addr(detail.base.0),
        detail
            .module
            .as_deref()
            .unwrap_or("<image in no loader list>")
    );
    outln!();
    if detail.parts.file {
        print_file_headers(detail);
    }
    if let Some(debug) = &detail.debug {
        print_debug_directory(debug);
    }
    if detail.parts.sections {
        for (index, section) in headers.sections.iter().enumerate() {
            print_section(index + 1, section);
        }
    }
    if let Some(exports) = &detail.exports {
        print_exports(detail, exports);
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

fn print_file_headers(detail: &ImageHeadersDetail) {
    let ImageHeaders {
        file,
        optional,
        directories,
        ..
    } = &detail.headers;
    let file_type = if file.characteristics & 0x2000 != 0 {
        "DLL"
    } else {
        "EXECUTABLE IMAGE"
    };
    outln!("File Type: {file_type}");
    outln!("FILE HEADER VALUES");
    outln!(
        "{:>8X} machine ({})",
        file.machine,
        machine_name(file.machine)
    );
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
    print_flags(&file_characteristics(file.characteristics));
    outln!();

    let format = if detail.headers.is_pe32_plus() {
        "PE32+"
    } else {
        "PE32"
    };
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
        if optional.address_of_entry_point == 0 {
            "none".to_string()
        } else {
            ui::addr(
                detail
                    .base
                    .0
                    .wrapping_add(optional.address_of_entry_point.into()),
            )
        }
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
        subsystem_name(optional.subsystem)
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
    print_flags(&dll_characteristics(optional.dll_characteristics));
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
    for DebugRecord { entry, codeview } in records {
        let format = match codeview {
            None => String::new(),
            Some(Ok(CodeView::Rsds { guid, age, path })) => {
                format!("  Format: RSDS, guid {guid}, age {age}, {path}")
            }
            Some(Ok(CodeView::Nb10 {
                signature,
                age,
                path,
            })) => format!("  Format: NB10, signature {signature:X}, age {age}, {path}"),
            Some(Err(error)) => format!("  <unavailable: {error}>"),
        };
        outln!(
            "    {:<26} {:>6X} {:>8X} {:>8X}{format}",
            format!("{} ({})", debug_type_name(entry.kind), entry.kind),
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
    for name in section_characteristics(section.characteristics) {
        outln!("         {name}");
    }
    outln!();
}

fn print_exports(detail: &ImageHeadersDetail, exports: &DiagnosticValue<ImageExports>) {
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
            .address
            .map(|address| format!("{:>8X}", address.0.wrapping_sub(detail.base.0)))
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
