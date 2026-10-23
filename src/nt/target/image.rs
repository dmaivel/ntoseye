//! `!dh` and `!lmi`: a mapped PE image's headers, found by module name or by
//! any address inside a module (or an image base no loader list names), in
//! the module-list scope (`.process`) and then the kernel's.

use ntoseye_macros::record;

use super::{DiagnosticValue, Target};
use crate::base::error::{Error, Result};
use crate::base::memory::MemoryOps;
use crate::base::types::{Dtb, VirtAddr};
use crate::nt::bugchecks::looks_like_kernel_pointer;
use crate::nt::guest::ModuleInfo;
use crate::nt::pe::headers::{
    DataDirectory, DebugRecord, FileHeader, ImportDescriptor, OptionalHeader, PeHeaders,
    SectionHeader, debug_directory, decode_headers, imports as pe_imports,
};
use crate::nt::pe::{ImageExports, PeImage, read_pe_exports};
use crate::nt::symbols::ModuleSymbols;

/// Which parts of the image `!dh` shows (`-f`, `-s`, `-e`, `-i`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DhParts {
    /// File header, optional header, and data directories.
    pub file: bool,
    /// Section table and debug directory.
    pub sections: bool,
    pub exports: bool,
    pub imports: bool,
}

impl DhParts {
    /// WinDbg's `!dh` without options: file and section headers.
    pub const HEADERS: Self = Self {
        file: true,
        sections: true,
        exports: false,
        imports: false,
    };
    /// `-a`.
    pub const ALL: Self = Self {
        file: true,
        sections: true,
        exports: true,
        imports: true,
    };
    pub const NONE: Self = Self {
        file: false,
        sections: false,
        exports: false,
        imports: false,
    };

    /// Parse `!dh` options: none selects [`Self::HEADERS`], `-a` everything,
    /// and `-f`/`-s`/`-e`/`-i` combine. Returns the parts and the remaining
    /// (address) arguments.
    pub fn parse<'a>(args: &[&'a str]) -> Result<(Self, Vec<&'a str>)> {
        let mut parts = Self::NONE;
        let mut rest = Vec::new();
        for &arg in args {
            let Some(flags) = arg.strip_prefix('-') else {
                rest.push(arg);
                continue;
            };
            if flags.is_empty() {
                return Err(Error::InvalidArgument("empty !dh option '-'".into()));
            }
            for flag in flags.chars() {
                match flag.to_ascii_lowercase() {
                    'a' => parts = Self::ALL,
                    'f' => parts.file = true,
                    's' => parts.sections = true,
                    'e' => parts.exports = true,
                    'i' => parts.imports = true,
                    other => {
                        return Err(Error::InvalidArgument(format!(
                            "unknown !dh option -{other}: expected -f, -s, -e, -i, or -a"
                        )));
                    }
                }
            }
        }
        if parts == Self::NONE {
            parts = Self::HEADERS;
        }
        Ok((parts, rest))
    }
}

/// The image `!dh` or `!lmi` describes: its base, the loaded module there
/// (`None` for an image base no loader list names), and the address space it
/// is mapped in when the caller knows it (an SDK module handle's); `None`
/// leaves that to the command (see [`Target::inspect_image_headers`] and
/// [`Target::module_image_info`]).
#[derive(Debug, Clone)]
pub struct ImageRef {
    pub base: VirtAddr,
    pub module: Option<ModuleInfo>,
    pub dtb: Option<Dtb>,
}

/// The headers of a mapped image (`!dh`). Each directory is read on its own:
/// a discarded or paged-out one (a driver's `INIT`-resident import table) is
/// unavailable beside the headers that did read.
#[record(impl)]
pub struct ImageHeaders {
    pub base: VirtAddr,
    /// The loaded module at `base`, if there is one.
    pub module: Option<String>,
    #[record(rename = "file_header")]
    pub file: FileHeader,
    #[record(rename = "optional_header")]
    pub optional: OptionalHeader,
    #[record(rename = "data_directories")]
    pub directories: Vec<DataDirectory>,
    pub sections: Vec<SectionHeader>,
    /// The debug directory, with each CodeView record decoded.
    #[record(rename = "debug_directory")]
    pub debug: DiagnosticValue<Vec<DebugRecord>>,
    /// The export directory. `None` if you did not ask for it.
    pub exports: Option<DiagnosticValue<ImageExports>>,
    /// The import descriptors. `None` if you did not ask for them.
    pub imports: Option<DiagnosticValue<Vec<ImportDescriptor>>>,
}

#[record]
impl ImageHeaders {
    /// `PE32` or `PE32+`.
    #[record(getter)]
    pub fn format(&self) -> &'static str {
        if self.optional.is_pe32_plus() {
            "PE32+"
        } else {
            "PE32"
        }
    }

    /// The mapped entry point. `None` if the image has no entry point.
    #[record(getter, hex)]
    pub fn entry_point(&self) -> Option<u64> {
        let rva = self.optional.address_of_entry_point;
        (rva != 0).then(|| self.base.0.wrapping_add(rva.into()))
    }
}

/// The image identity of a loaded module (`!lmi`): the file-header identity
/// from its mapped headers, the debug directory, which includes the CodeView
/// PDB name, GUID, and age, and the symbol state.
#[record(impl)]
pub struct ModuleImageInfo {
    #[record(rename = "info")]
    pub module: ModuleInfo,
    #[record(skip)]
    pub headers: PeHeaders,
    #[record(rename = "debug_directory")]
    pub debug: DiagnosticValue<Vec<DebugRecord>>,
    /// The symbol state, from the symbol store under the address space the
    /// module's symbols load in.
    pub symbols: ModuleSymbols,
    /// The local PDB file, if a PDB is loaded.
    pub symbol_file: Option<String>,
}

#[record]
impl ModuleImageInfo {
    #[record(getter, hex)]
    pub fn machine(&self) -> u16 {
        self.headers.file.machine
    }

    /// `X64`, `X86`, `ARM64`, ...
    #[record(getter)]
    pub fn machine_name(&self) -> &'static str {
        self.headers.file.machine_name()
    }

    #[record(getter, hex)]
    pub fn time_date_stamp(&self) -> u32 {
        self.headers.file.time_date_stamp
    }

    #[record(getter, hex)]
    pub fn size_of_image(&self) -> u32 {
        self.headers.optional.size_of_image
    }

    #[record(getter, hex)]
    pub fn checksum(&self) -> u32 {
        self.headers.optional.checksum
    }

    #[record(getter, hex)]
    pub fn characteristics(&self) -> u16 {
        self.headers.file.characteristics
    }

    /// The `IMAGE_FILE_*` flags that are set in `characteristics`.
    #[record(getter)]
    pub fn characteristics_names(&self) -> Vec<String> {
        self.headers.file.characteristics_names()
    }
}

impl Target {
    /// `!lmi`: the loaded module of `image` with its headers, debug
    /// directory, and symbol state. Its symbols are those loaded under
    /// `image.dtb`, else the kernel's for a kernel module and the module-list
    /// scope's for any other.
    pub fn module_image_info(&self, image: ImageRef) -> Result<ModuleImageInfo> {
        let module = image.module.ok_or_else(|| {
            Error::DebugInfo(format!(
                "{:#x} is the base of no loaded module",
                image.base.0
            ))
        })?;
        let base = module.base_address;
        let dtb = image.dtb.unwrap_or_else(|| {
            if looks_like_kernel_pointer(self.arch(), base.0) {
                self.kernel_dtb()
            } else {
                self.process_dtb()
            }
        });
        let (image, headers) = self.decoded_image(dtb, base)?;
        let debug = DiagnosticValue::from_result(debug_directory(&image, &headers));
        Ok(ModuleImageInfo {
            symbols: self.symbols.module_symbols(dtb, base),
            symbol_file: self
                .symbols
                .module_pdb_path(dtb, base)
                .map(|path| path.display().to_string()),
            module,
            headers,
            debug,
        })
    }

    /// `!dh`: decode the headers and debug directory of `image`, mapped in
    /// `image.dtb`'s address space (else the module-list scope's), plus its
    /// exports and imports when asked for.
    pub fn inspect_image_headers(
        &self,
        image: &ImageRef,
        exports: bool,
        imports: bool,
    ) -> Result<ImageHeaders> {
        let base = image.base;
        let dtb = image.dtb.unwrap_or_else(|| self.process_dtb());
        let (image_bytes, headers) = self.decoded_image(dtb, base)?;
        let debug = DiagnosticValue::from_result(debug_directory(&image_bytes, &headers));
        let exports =
            exports.then(|| DiagnosticValue::from_result(read_pe_exports(&image_bytes, base)));
        let imports =
            imports.then(|| DiagnosticValue::from_result(pe_imports(&image_bytes, &headers)));
        let PeHeaders {
            file,
            optional,
            directories,
            sections,
        } = headers;
        Ok(ImageHeaders {
            base,
            module: image.module.as_ref().map(|module| module.name.clone()),
            file,
            optional,
            directories,
            sections,
            debug,
            exports,
            imports,
        })
    }

    /// The loaded module named `name` (its short name, `nt` for the kernel,
    /// or its image name, case-insensitively), searched in the module-list
    /// scope and then the kernel's.
    pub fn module_named(&self, name: &str) -> Option<ModuleInfo> {
        let named = |module: &ModuleInfo| {
            module.short_name.eq_ignore_ascii_case(name) || module.name.eq_ignore_ascii_case(name)
        };
        self.modules()
            .ok()
            .and_then(|modules| modules.into_iter().find(named))
            .or_else(|| {
                self.kernel_modules()
                    .ok()
                    .and_then(|modules| modules.into_iter().find(named))
            })
    }

    /// The loaded module whose image contains `address`, searched like
    /// [`Self::module_named`].
    pub fn module_containing(&self, address: VirtAddr) -> Option<ModuleInfo> {
        let contains = |module: &ModuleInfo| module.contains_address(address);
        self.modules()
            .ok()
            .and_then(|modules| modules.into_iter().find(contains))
            .or_else(|| {
                self.kernel_modules()
                    .ok()
                    .and_then(|modules| modules.into_iter().find(contains))
            })
    }

    /// `module!symbol+offset` for `address` in the address space `dtb`, or
    /// `module+offset` in a module whose symbols are not loaded, as WinDbg
    /// names it: from the kernel's module list, or the current process's
    /// when `dtb` is its address space. `None` outside every module.
    pub fn format_code_address(&self, dtb: Dtb, address: VirtAddr) -> Option<String> {
        if let Some(symbol) = self.symbols.format_closest_symbol_for_address(dtb, address) {
            return Some(symbol);
        }
        let contains = |module: &ModuleInfo| module.contains_address(address);
        let module = self
            .kernel_modules()
            .ok()
            .and_then(|modules| modules.into_iter().find(contains))
            .or_else(|| {
                let mask = self.arch().dtb_page_mask();
                (dtb & mask == self.current_dtb() & mask)
                    .then(|| self.modules().ok())
                    .flatten()
                    .and_then(|modules| modules.into_iter().find(contains))
            })?;
        Some(format!(
            "{}+{:#x}",
            module.short_name,
            address.0 - module.base_address.0
        ))
    }

    /// The image `!dh` names: a module name first, otherwise the address
    /// `eval` makes of `text`, which is either inside a loaded module or the
    /// base of an image no loader list names (it must start with `MZ`).
    pub fn resolve_image(
        &self,
        text: &str,
        eval: impl FnOnce(&str) -> Result<VirtAddr>,
    ) -> Result<(VirtAddr, Option<ModuleInfo>)> {
        if let Some(module) = self.module_named(text) {
            return Ok((module.base_address, Some(module)));
        }
        let address = eval(text).map_err(|error| match error {
            // The name alone says it all; an expression's error explains what
            // in it went wrong.
            Error::SymbolNotFound(_) => Error::InvalidArgument(format!(
                "'{text}' is neither a loaded module nor an address"
            )),
            error => Error::InvalidArgument(format!(
                "'{text}' is neither a loaded module nor an address: {error}"
            )),
        })?;
        if let Some(module) = self.module_containing(address) {
            return Ok((module.base_address, Some(module)));
        }
        let mut magic = [0u8; 2];
        match self.process_memory().read_bytes(address, &mut magic) {
            Ok(()) if &magic == b"MZ" => Ok((address, None)),
            Ok(()) => Err(Error::DebugInfo(format!(
                "{:#x} is in no loaded module and does not start with an MZ header",
                address.0
            ))),
            Err(error) => Err(Error::DebugInfo(format!(
                "{:#x} is in no loaded module and cannot be read: {error}",
                address.0
            ))),
        }
    }

    /// The image mapped at `base` in `dtb`'s address space and its decoded
    /// headers.
    fn decoded_image(&self, dtb: Dtb, base: VirtAddr) -> Result<(PeImage, PeHeaders)> {
        let image = self.mapped_pe_image(dtb, base).map_err(|error| {
            Error::DebugInfo(format!("cannot read PE headers at {:#x}: {error}", base.0))
        })?;
        let headers = decode_headers(image.headers()).map_err(|error| {
            Error::DebugInfo(format!(
                "{:#x} does not hold valid PE headers: {error}",
                base.0
            ))
        })?;
        Ok((image, headers))
    }
}

#[cfg(test)]
mod tests {
    use super::DhParts;

    #[test]
    fn dh_options_default_to_headers_and_combine() {
        assert_eq!(
            DhParts::parse(&["nt"]).unwrap(),
            (DhParts::HEADERS, vec!["nt"])
        );
        let (parts, rest) = DhParts::parse(&["-s", "hal"]).unwrap();
        assert_eq!(
            parts,
            DhParts {
                sections: true,
                ..DhParts::NONE
            }
        );
        assert_eq!(rest, ["hal"]);
        assert_eq!(
            DhParts::parse(&["-fi", "nt"]).unwrap().0,
            DhParts {
                file: true,
                imports: true,
                ..DhParts::NONE
            }
        );
        assert_eq!(DhParts::parse(&["-a", "nt"]).unwrap().0, DhParts::ALL);
        assert!(DhParts::parse(&["-x", "nt"]).is_err());
    }
}
