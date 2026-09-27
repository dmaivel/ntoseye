//! `!dh`: a mapped PE image's headers, found by module name or by any
//! address inside a module (or an image base no loader list names), in the
//! module-list scope (`.process`) and then the kernel's.

use std::sync::Arc;

use super::{DiagnosticValue, Target};
use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::guest::ModuleInfo;
use crate::memory::AddressSpace;
use crate::pe::headers::{
    DebugDirectoryEntry, ExportDirectory, ImageHeaders, ImportDescriptor, debug_directory,
    decode_headers, export_directory, imports,
};
use crate::pe::{ModuleExportInfo, PeImage, read_pe_exports, read_pe_image};
use crate::types::VirtAddr;

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

/// The export directory and its entries.
#[derive(Debug, Clone)]
pub struct ImageExports {
    pub directory: Option<ExportDirectory>,
    pub exports: Vec<ModuleExportInfo>,
}

/// What `!dh` shows for one image. Each directory is read on its own: a
/// discarded or paged-out one (a driver's `INIT`-resident import table) is
/// `Unavailable` beside the headers that did read.
#[derive(Debug, Clone)]
pub struct ImageHeadersDetail {
    pub base: VirtAddr,
    /// The loader's name for the image, `None` for a base no list names.
    pub module: Option<String>,
    pub parts: DhParts,
    pub headers: ImageHeaders,
    pub debug: DiagnosticValue<Vec<DebugDirectoryEntry>>,
    /// Present when [`DhParts::exports`] was asked for.
    pub exports: Option<DiagnosticValue<ImageExports>>,
    /// Present when [`DhParts::imports`] was asked for.
    pub imports: Option<DiagnosticValue<Vec<ImportDescriptor>>>,
}

impl Target {
    /// `!dh [options] <module|address>`: parse the options, resolve the image
    /// (see [`Self::resolve_image`]), and decode it.
    pub fn inspect_image_headers(
        &self,
        args: &[&str],
        eval: impl FnOnce(&str) -> Result<VirtAddr>,
    ) -> Result<ImageHeadersDetail> {
        let (parts, rest) = DhParts::parse(args)?;
        let text = match rest.as_slice() {
            [text] => *text,
            [] => {
                return Err(Error::InvalidArgument(
                    "!dh needs a module name or an address".into(),
                ));
            }
            _ => {
                return Err(Error::InvalidArgument(format!(
                    "!dh takes one module or address, got '{}'",
                    rest.join(" ")
                )));
            }
        };
        let (base, module) = self.resolve_image(text, eval)?;
        self.image_headers(base, module.as_ref(), parts)
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
        let address = eval(text).map_err(|error| {
            Error::InvalidArgument(format!(
                "'{text}' is neither a loaded module nor an address: {error}"
            ))
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

    /// Decode the headers of the image mapped at `base` in the module-list
    /// scope's address space, plus the directories `parts` asks for.
    pub fn image_headers(
        &self,
        base: VirtAddr,
        module: Option<&ModuleInfo>,
        parts: DhParts,
    ) -> Result<ImageHeadersDetail> {
        let image = self.mapped_image(base)?;
        let headers = decode_headers(image.headers()).map_err(|error| {
            Error::DebugInfo(format!(
                "{:#x} does not hold valid PE headers: {error}",
                base.0
            ))
        })?;
        let debug = DiagnosticValue::from_result(debug_directory(&image, &headers));
        let exports = parts.exports.then(|| {
            DiagnosticValue::from_result(export_directory(&image, &headers).and_then(|directory| {
                Ok(ImageExports {
                    exports: read_pe_exports(&image, base)?,
                    directory,
                })
            }))
        });
        let imports = parts
            .imports
            .then(|| DiagnosticValue::from_result(imports(&image, &headers)));
        Ok(ImageHeadersDetail {
            base,
            module: module.map(|module| module.name.clone()),
            parts,
            headers,
            debug,
            exports,
            imports,
        })
    }

    /// The image at `base`, demand-read through the module-list scope.
    fn mapped_image(&self, base: VirtAddr) -> Result<PeImage> {
        let (phys, dtb, kernel_dtb, arch) = (
            Arc::clone(&self.phys),
            self.process_dtb(),
            self.kernel_dtb(),
            self.arch(),
        );
        read_pe_image(base, move |address, buf| {
            AddressSpace::for_arch(&phys, dtb, kernel_dtb, arch).read_bytes(address, buf)
        })
        .map_err(|error| {
            Error::DebugInfo(format!("cannot read PE headers at {:#x}: {error}", base.0))
        })
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
