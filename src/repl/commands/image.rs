use crate::error::Result;
use crate::expr::Expr;
use crate::pe::headers::{
    CodeView, DebugDirectoryEntry, ImageHeaders, ImportDescriptor, ImportName, SectionHeader,
    debug_type_name, dll_characteristics, file_characteristics, machine_name,
    section_characteristics, subsystem_name,
};
use crate::repl::*;
use crate::target::DiagnosticValue;
use crate::target::image::{ImageExports, ImageHeadersDetail};
use crate::ui;

repl_command! {
    cmd_dh;
    names: ["!dh", "dh"],
    usage: "!dh [-f] [-s] [-e] [-i] [-a] <module|address>",
    summary: "Display a mapped PE image's headers.",
    details: "The image is a module name (`nt`, `hal`, `ntdll`, or its image name) in the `.process` module list and then the kernel's, or any address inside a loaded module, or the base of an image no loader list names (it must start with MZ). Without options it shows the file and section headers, as WinDbg does. -f: the file header, optional header (entry point, image base, subsystem, DLL characteristics, stack and heap sizes), and data directories (RVA and size; the security directory's is a file offset). -s: the section table with decoded flags, and the debug directory with its CodeView PDB name, GUID, and age. -e: the export directory and every export (ordinal, RVA, name or forwarder). -i: each import descriptor and its imports (hint and name or ordinal) with the address the loader bound in the IAT. -a: all of these. Options combine (`-fs`, `-f -i`). A directory that does not read (a driver's import table lives in its INIT section, which is discarded after load) is reported as unavailable, and the rest is still shown. The headers are read from memory as mapped, so the values are what the loader left there.",
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
    if detail.parts.sections {
        print_debug_directory(&detail.debug);
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

fn print_debug_directory(debug: &DiagnosticValue<Vec<DebugDirectoryEntry>>) {
    let entries = match debug {
        DiagnosticValue::Available(entries) => entries,
        DiagnosticValue::Unavailable(error) => {
            outln!("Debug Directories: <unavailable: {error}>\n");
            return;
        }
    };
    if entries.is_empty() {
        return;
    }
    outln!("Debug Directories({})", entries.len());
    outln!("    Type                         Size  Address   Pointer");
    for entry in entries {
        let format = match &entry.codeview {
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
        outln!("  _IMAGE_IMPORT_DESCRIPTOR {}", descriptor.name);
        outln!("{:>10X} Import Address Table", descriptor.first_thunk);
        outln!("{:>10X} Import Name Table", descriptor.original_first_thunk);
        outln!("{:>10X} time date stamp", descriptor.time_date_stamp);
        outln!(
            "{:>10X} Index of first forwarder reference",
            descriptor.forwarder_chain
        );
        outln!();
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
            }
        }
        outln!();
    }
}
