//! Loaded modules and their images, symbol loading, and symbol, source-line,
//! and procedure-local lookup in the target's inspection scope.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use super::{SymbolSearchMatch, Target, lookup_register};
use crate::{
    backend::MemoryOps,
    error::{Error, Result},
    guest::{Guest, ModuleInfo, ModuleSymbolLoadReport, SessionSpace},
    memory::AddressSpace,
    pe::{ModuleExportInfo, read_pe_exports, read_pe_image, read_pe_version_info},
    symbols::{
        LocalVariableLocation, ProcedureLocal, SourceLineExtent, SourceLocation, SymbolCandidate,
        SymbolIndex, SymbolStore, format_symbol_with_offset,
    },
    types::{Dtb, VirtAddr},
    unwind::frame_base_for_register_values,
};

impl Target {
    pub fn kernel_modules(&self) -> Result<Vec<ModuleInfo>> {
        match self.guest() {
            // The triage snapshot only substitutes when one exists; live
            // enumeration failures propagate instead of being remapped to
            // NtoskrnlNotFound.
            Ok(g) => g.kernel_modules().or_else(|e| {
                if self.triage_modules_cache.is_some() {
                    self.triage_modules()
                } else {
                    Err(e)
                }
            }),
            Err(_) => self.triage_modules(),
        }
    }

    pub fn kernel_modules_with_versions(&self) -> Result<Vec<ModuleInfo>> {
        let mut mods = self.kernel_modules()?;
        if let Ok(g) = self.guest() {
            g.populate_kernel_module_versions(&mut mods);
        }
        Ok(mods)
    }

    /// Loaded modules in the current inspection scope: the attached process's
    /// user-mode modules when attached to a process, otherwise the kernel module
    /// list. Shared by the REPL `lm`, the SDK, and MCP.
    pub fn modules(&self) -> Result<Vec<ModuleInfo>> {
        if self.in_secure_scope() {
            return self.secure_kernel()?.modules(self.guest()?);
        }
        match &self.process {
            Some(process) => self.guest()?.process_modules(process),
            None => self.kernel_modules(),
        }
    }

    pub fn modules_with_versions(&self) -> Result<Vec<ModuleInfo>> {
        let mut mods = self.modules()?;
        if self.in_secure_scope() {
            let memory = self.process_memory();
            for module in &mut mods {
                if let Some((file, product)) = read_pe_version_info(module.base_address, &memory) {
                    module.file_version = Some(file);
                    module.product_version = Some(product);
                }
            }
            return Ok(mods);
        }
        if let Ok(g) = self.guest() {
            match &self.process {
                Some(info) => g.populate_process_module_versions(&mut mods, info),
                None => g.populate_kernel_module_versions(&mut mods),
            }
        }
        Ok(mods)
    }

    fn triage_modules(&self) -> Result<Vec<ModuleInfo>> {
        self.triage_modules_cache
            .clone()
            .ok_or(Error::NtoskrnlNotFound)
    }

    /// A loaded module's PE file in the symbol cache, downloaded when absent.
    /// Blocks for the download; see `Self::module_image_key` for the lookup.
    pub fn fetch_module_image(&self, name: &str) -> Result<PathBuf> {
        let (module, time_date_stamp, size_of_image) = self.module_image_key(name)?;
        self.symbols
            .ensure_module_image_on_disk(&module.name, time_date_stamp, size_of_image)
            .map_err(|error| {
                Error::DebugInfo(format!(
                    "{} (timestamp {time_date_stamp:#010x}, size {size_of_image:#x}) could not \
                     be downloaded: {error}; if no symbol server has it, copy the file from the \
                     guest and check that its timestamp matches",
                    module.name
                ))
            })
    }

    /// A loaded module's PE file when it is already in the symbol cache;
    /// otherwise `None`, with the download started in the background. For
    /// callers that must not wait on the network.
    pub fn module_image_or_fetch_later(&self, name: &str) -> Result<Option<PathBuf>> {
        let (module, time_date_stamp, size_of_image) = self.module_image_key(name)?;
        self.symbols
            .image_or_fetch_later(&module.name, time_date_stamp, size_of_image)
    }

    /// The loaded module named `name` (module name or `module!` qualifier,
    /// case-insensitively, searched in the current scope and then the
    /// kernel's) and its symbol-server image key: the TimeDateStamp and
    /// SizeOfImage in the mapped PE header, so the file is the build that is
    /// running, or the loader entry's copy when the header page is not
    /// resident. Reads guest memory only.
    fn module_image_key(&self, name: &str) -> Result<(ModuleInfo, u32, u32)> {
        let named = |module: &ModuleInfo| {
            module.short_name.eq_ignore_ascii_case(name) || module.name.eq_ignore_ascii_case(name)
        };
        let module = self
            .modules()
            .ok()
            .and_then(|modules| modules.into_iter().find(named))
            .or_else(|| {
                self.kernel_modules()
                    .ok()
                    .and_then(|modules| modules.into_iter().find(named))
            })
            .ok_or_else(|| Error::InvalidArgument(format!("no loaded module named '{name}'")))?;
        let (time_date_stamp, size_of_image) = SymbolStore::read_image_lookup_info(
            &self.process_memory(),
            module.base_address,
        )
        .ok()
        .or_else(|| module.time_date_stamp.map(|stamp| (stamp, module.size)))
        .ok_or_else(|| {
            Error::DebugInfo(format!(
                "{}: neither its PE header nor its loader entry gives a timestamp to look it up by",
                module.name
            ))
        })?;
        Ok((module, time_date_stamp, size_of_image))
    }

    /// The exports of the module mapped at `base` in `dtb`'s address space,
    /// read from its in-memory export directory ([`read_pe_exports`]).
    pub fn module_exports(&self, dtb: Dtb, base: VirtAddr) -> Result<Vec<ModuleExportInfo>> {
        let (phys, kernel_dtb, arch) = (Arc::clone(&self.phys), self.kernel_dtb(), self.arch());
        let image = read_pe_image(base, move |address, buf| {
            AddressSpace::for_arch(&phys, dtb, kernel_dtb, arch).read_bytes(address, buf)
        })?;
        read_pe_exports(&image, base)
    }

    /// Load symbols for one module (by short name, e.g. `user32`) or, with
    /// `None`, every module of process `pid`, without changing the inspection
    /// scope. A process-scoped breakpoint names the address space it wants;
    /// the debugger can read that process's loader list and its PDBs itself
    /// rather than defer until someone runs `.process /p`. Modules already
    /// attempted are left alone. Returns whether any load was attempted.
    pub fn load_process_module_symbols(
        &self,
        pid: u64,
        dtb: Dtb,
        module_short: Option<&str>,
    ) -> Result<bool> {
        let guest = self.guest()?;
        let info = guest
            .enumerate_processes()?
            .into_iter()
            .find(|p| p.pid == pid)
            .ok_or(Error::ProcessNotFound(pid))?;
        let modules: Vec<ModuleInfo> = guest
            .process_modules(&info)?
            .into_iter()
            .filter(|module| {
                module_short.is_none_or(|short| module.short_name.eq_ignore_ascii_case(short))
            })
            .filter(|module| {
                self.symbols
                    .module_symbol_status(dtb, module.base_address)
                    .is_none()
            })
            .collect();
        if modules.is_empty() {
            return Ok(false);
        }
        guest.load_symbols_for_modules(&self.phys, &self.symbols, modules, dtb)?;
        Ok(true)
    }

    pub fn refresh_kernel_module_symbols(&self) -> Result<ModuleSymbolLoadReport> {
        self.guest
            .as_ref()
            .ok_or(Error::NtoskrnlNotFound)?
            .load_missing_kernel_module_symbols(&self.phys, &self.symbols)
    }

    /// Re-run source selection and symbol indexing for all modules in the
    /// current inspection scope, or for one exact module/short name.
    pub fn reload_module_symbols(
        &self,
        module_name: Option<&str>,
    ) -> Result<ModuleSymbolLoadReport> {
        let mut modules = self.modules()?;
        if let Some(name) = module_name {
            modules.retain(|module| {
                module.short_name.eq_ignore_ascii_case(name)
                    || module
                        .name
                        .rsplit(['\\', '/'])
                        .next()
                        .is_some_and(|image| image.eq_ignore_ascii_case(name))
            });
            if modules.is_empty() {
                return Err(Error::DebugInfo(format!("module not found: {name}")));
            }
        }

        let dtb = self.process_dtb();
        let bases = modules
            .iter()
            .map(|module| module.base_address)
            .collect::<Vec<_>>();
        self.symbols.invalidate_modules(dtb, &bases);

        if self.in_secure_scope() {
            return Guest::load_module_symbols(
                &self.phys,
                &self.symbols,
                modules,
                dtb,
                SessionSpace::Load,
                self.arch(),
            );
        }
        match self.guest.as_ref() {
            Some(guest) => guest.load_symbols_for_modules(&self.phys, &self.symbols, modules, dtb),
            None => Guest::load_module_symbols(
                &self.phys,
                &self.symbols,
                modules,
                dtb,
                SessionSpace::Load,
                self.arch(),
            ),
        }
    }

    /// All matching symbol identities visible from the active address space.
    pub fn symbol_candidates(&self, name: &str) -> Vec<SymbolCandidate> {
        self.symbols
            .find_symbol_candidates(self.current_dtb(), name)
    }

    /// Fuzzy-search the active symbol index and resolve only unambiguous
    /// module/address identities. `module!query` restricts the search.
    pub fn search_symbols(&self, query: &str, limit: usize) -> Vec<SymbolSearchMatch> {
        let dtb = self.current_dtb();
        let names: Vec<String> = match query.split_once('!') {
            Some((module, query)) => self
                .symbols
                .search_symbols_in_module(dtb, module, query, limit)
                .into_iter()
                .map(|name| format!("{module}!{name}"))
                .collect(),
            None => self.current_symbol_index().search(query, limit),
        };
        names
            .into_iter()
            .map(|qualified| {
                let locations: HashSet<(String, u64)> = self
                    .symbol_candidates(&qualified)
                    .into_iter()
                    .map(|candidate| (candidate.module, candidate.address.0))
                    .collect();
                let (resolved_module, address) = if locations.len() == 1 {
                    let (module, address) = locations.into_iter().next().unwrap();
                    (Some(module), Some(VirtAddr(address)))
                } else {
                    (None, None)
                };
                let name = qualified
                    .rsplit_once('!')
                    .map_or(qualified.as_str(), |(_, bare)| bare)
                    .to_string();
                SymbolSearchMatch {
                    name,
                    address,
                    module: resolved_module,
                }
            })
            .collect()
    }

    pub fn nearest_symbol_current_context(
        &self,
        address: VirtAddr,
    ) -> Option<(String, String, u32)> {
        self.symbols
            .find_closest_symbol_for_address(self.current_dtb(), address)
    }

    pub fn closest_symbol_current_context(&self, address: VirtAddr) -> Option<String> {
        self.nearest_symbol_current_context(address)
            .map(|(module, name, offset)| format_symbol_with_offset(&module, &name, offset))
    }

    pub fn source_location(&self, address: VirtAddr) -> Option<SourceLocation> {
        self.symbols.source_location(self.current_dtb(), address)
    }

    /// Resolve the source line and exclusive address extent in the current
    /// inspection context for consumers that step complete source lines.
    pub fn source_line_extent(&self, address: VirtAddr) -> Option<SourceLineExtent> {
        self.symbols.source_line_extent(self.current_dtb(), address)
    }

    /// End of the function's opening source-line range, after the prologue.
    /// Return `None` without private line records or if the next record leaves
    /// the function.
    pub fn post_prologue_address(&self, dtb: Dtb, address: VirtAddr) -> Option<VirtAddr> {
        let end = self.symbols.source_line_extent(dtb, address)?.end?;
        let function = self.symbols.find_closest_symbol_for_address(dtb, address)?;
        let at_end = self.symbols.find_closest_symbol_for_address(dtb, end)?;
        (function.0 == at_end.0
            && function.1 == at_end.1
            && self.symbols.source_line_extent(dtb, end).is_some())
        .then_some(end)
    }

    pub fn source_addresses(&self, file: &str, line: u32) -> Vec<VirtAddr> {
        self.symbols
            .source_addresses(self.current_dtb(), file, line)
    }

    /// Return private procedure locals in scope at `address`.
    pub fn procedure_locals(&self, address: VirtAddr) -> Result<Option<Arc<Vec<ProcedureLocal>>>> {
        self.symbols.procedure_locals(self.current_dtb(), address)
    }

    /// Address of a memory-resident local in the current inspection context
    /// (the selected frame's registers when one is selected, else the live
    /// ones). `None` for register-held locals, unavailable PDB recipes, and
    /// frame-relative locals whose base could not be recovered.
    pub fn procedure_local_address(&self, local: &ProcedureLocal) -> Option<u64> {
        let registers = self.registers.as_ref()?;
        match &local.location {
            LocalVariableLocation::Register { .. } | LocalVariableLocation::Unavailable { .. } => {
                None
            }
            LocalVariableLocation::RegisterRelative { register, offset } => {
                let base = lookup_register(registers, register)?;
                Some(base.wrapping_add_signed(i64::from(*offset)))
            }
            LocalVariableLocation::FrameRelative { offset } => {
                let frame_base = self
                    .selected_frame
                    .as_ref()
                    .and_then(|frame| frame.frame_base)
                    .or_else(|| frame_base_for_register_values(self, registers))
                    .or_else(|| lookup_register(registers, self.stack_pointer_register()))?;
                Some(frame_base.wrapping_add_signed(i64::from(*offset)))
            }
        }
    }

    /// Resolve a scalar local from the current halted register/memory context.
    /// Returns `None` when the PDB recipe is unavailable, the register context
    /// does not correspond to the requested procedure, or the value is wider
    /// than a scalar u64.
    pub fn resolve_procedure_local_value(
        &self,
        address: VirtAddr,
        local: &ProcedureLocal,
    ) -> Option<u64> {
        if self
            .register_value("rip")
            .is_none_or(|rip| rip != address.0)
        {
            return None;
        }
        let size = usize::try_from(local.byte_size?).ok()?;
        if size == 0 || size > 8 {
            return None;
        }
        let registers = self.registers.as_ref()?;
        match &local.location {
            LocalVariableLocation::Register { register } => {
                let value = lookup_register(registers, register)?;
                Some(if size == 8 {
                    value
                } else {
                    value & ((1u64 << (size * 8)) - 1)
                })
            }
            LocalVariableLocation::RegisterRelative { .. }
            | LocalVariableLocation::FrameRelative { .. } => {
                let address = VirtAddr(self.procedure_local_address(local)?);
                let mut bytes = [0u8; 8];
                self.context_memory()
                    .read_bytes(address, &mut bytes[..size])
                    .ok()?;
                Some(u64::from_le_bytes(bytes))
            }
            LocalVariableLocation::Unavailable { .. } => None,
        }
    }

    pub fn current_symbol_index(&self) -> SymbolIndex {
        self.symbols.merged_symbol_index(Some(self.current_dtb()))
    }

    pub fn current_types_index(&self) -> SymbolIndex {
        self.symbols.merged_types_index(Some(self.current_dtb()))
    }

    pub fn current_enums_index(&self) -> SymbolIndex {
        self.symbols.merged_enum_index(Some(self.current_dtb()))
    }
}

#[cfg(test)]
mod tests {
    use crate::session::{Session, session_over_memory};
    use crate::types::VirtAddr;

    /// A target whose only module records `records` as its line table and
    /// `symbols` as its exports, for resolution tests that need private line
    /// information without a PDB.
    fn target_with_lines(symbols: &[(&str, u32)], records: &[(u32, Option<u32>, u32)]) -> Session {
        let session = session_over_memory(0x1000, &[0u8; 0x80]);
        let dtb = session.target.current_dtb();
        session.target.symbols.set_kernel(Some(1), dtb);
        session
            .target
            .symbols
            .inject_module_for_test(1, Vec::new(), symbols);
        session.target.symbols.inject_source_lines_for_test(
            1,
            dtb,
            VirtAddr(0x1000),
            0x1000,
            "driver.c",
            records,
        );
        session
    }

    #[test]
    fn post_prologue_address_lands_on_the_first_statement() {
        // Line 123 is the opening brace, covering the prologue; line 132 is the
        // first statement, where the arguments are finally where the PDB says.
        let session = target_with_lines(
            &[("DriverEntry", 0)],
            &[(0, Some(0x0e), 123), (0x0e, Some(0x1b), 132)],
        );
        assert_eq!(
            session
                .target
                .post_prologue_address(session.target.current_dtb(), VirtAddr(0x1000)),
            Some(VirtAddr(0x100e))
        );
    }

    #[test]
    fn post_prologue_address_refuses_to_leave_the_function() {
        // The next record belongs to the following function: skipping there
        // would move the breakpoint out of the one that was asked for.
        let session = target_with_lines(
            &[("DriverEntry", 0), ("Unload", 0x10)],
            &[(0, Some(0x10), 123), (0x10, Some(0x20), 200)],
        );
        assert_eq!(
            session
                .target
                .post_prologue_address(session.target.current_dtb(), VirtAddr(0x1000)),
            None
        );

        // No following record at all: nothing to skip to.
        let single = target_with_lines(&[("DriverEntry", 0)], &[(0, None, 123)]);
        assert_eq!(
            single
                .target
                .post_prologue_address(single.target.current_dtb(), VirtAddr(0x1000)),
            None
        );
    }
}
