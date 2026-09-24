//! Procedure locals: scanning a PDB for the variables in scope at an address
//! and describing where each lives by register and live range.

use super::{LocalVariableLocation, ProcedureLocal, SymbolStore};
use crate::{
    error::Result,
    layout::ParsedType,
    types::{Dtb, VirtAddr},
};
use pdb2::{FallibleIterator, TypeFinder, TypeIndex};
use std::sync::Arc;

#[cfg(test)]
pub(super) fn live_range_contains(
    start_rva: u32,
    length: u16,
    gaps: &[(u16, u16)],
    target_rva: u32,
) -> bool {
    let Some(relative) = target_rva.checked_sub(start_rva) else {
        return false;
    };
    relative < u32::from(length)
        && !gaps.iter().any(|(start, length)| {
            relative >= u32::from(*start)
                && relative < u32::from(*start).saturating_add(u32::from(*length))
        })
}

fn pdb_register_name(register: pdb2::Register, cpu: Option<pdb2::CPUType>) -> String {
    let Some(cpu) = cpu else {
        return format!("cvreg{}", register.0);
    };
    let Ok(register) = pdb2::register::Register::new(register, cpu) else {
        return format!("cvreg{}", register.0);
    };
    let display = register.to_string();
    display
        .split_once('(')
        .and_then(|(_, rest)| rest.strip_suffix(')'))
        .unwrap_or(&display)
        .to_ascii_lowercase()
}

fn pdb_live_range_contains(
    range: &pdb2::AddressRange,
    gaps: &[pdb2::AddressGap],
    address_map: &pdb2::AddressMap,
    target_rva: u32,
) -> bool {
    let Some(start) = range.offset.to_rva(address_map) else {
        return false;
    };
    let Some(relative) = target_rva.checked_sub(start.0) else {
        return false;
    };
    relative < u32::from(range.cb_range)
        && !gaps.iter().any(|gap| {
            relative >= u32::from(gap.gap_start_offset)
                && relative
                    < u32::from(gap.gap_start_offset).saturating_add(u32::from(gap.cb_range))
        })
}

// pdb2 0.10.1 debug-asserts on valid Windows S_CALLEES/S_CALLERS records whose
// optional invocation-count tail is longer than the function list. Neither
// record contributes addresses or local-variable state, so never parse them.
const PDB_S_CALLEES: u16 = 0x115a;

const PDB_S_CALLERS: u16 = 0x115b;

fn is_pdb2_function_list_symbol(kind: u16) -> bool {
    matches!(kind, PDB_S_CALLEES | PDB_S_CALLERS)
}

const MAX_LOCALS_CACHE_ENTRIES: usize = 4096;

impl SymbolStore {
    fn procedure_local(
        &self,
        guid: u128,
        finder: &TypeFinder<'_>,
        name: String,
        type_index: TypeIndex,
        is_parameter: bool,
        location: LocalVariableLocation,
    ) -> ProcedureLocal {
        let prefix = self.nested_type_prefix(guid);
        let (type_name, type_data) = match self.resolve_type(guid, finder, type_index, &prefix) {
            Ok(parsed) => (parsed.to_string(), parsed),
            Err(_) => (format!("type({:#x})", type_index.0), ParsedType::Unknown),
        };
        ProcedureLocal {
            name,
            type_name,
            type_data,
            byte_size: self.type_size(guid, finder, type_index).ok(),
            is_parameter,
            location,
        }
    }

    /// Return locals and parameters belonging to the procedure that covers
    /// `address`. Definition ranges are filtered against the requested RVA and
    /// gaps. Unsupported DIA recipes and split locations remain explicit
    /// `Unavailable` entries rather than guessed values.
    pub fn procedure_locals(
        &self,
        dtb: Dtb,
        address: VirtAddr,
    ) -> Result<Option<Arc<Vec<ProcedureLocal>>>> {
        let Some(module) = self.find_module_for_address(dtb, address) else {
            return Ok(None);
        };
        let Some(relative) = address.0.checked_sub(module.base_address.0) else {
            return Ok(None);
        };
        let Ok(target_rva) = u32::try_from(relative) else {
            return Ok(None);
        };
        let key = (module.guid, target_rva);
        if let Some(cached) = self.locals_cache.get(&key) {
            return Ok(cached.clone());
        }
        let locals = self
            .scan_procedure_locals(module.guid, target_rva)?
            .map(Arc::new);
        if self.locals_cache.len() >= MAX_LOCALS_CACHE_ENTRIES {
            self.locals_cache.clear();
        }
        self.locals_cache.insert(key, locals.clone());
        Ok(locals)
    }

    fn scan_procedure_locals(
        &self,
        guid: u128,
        target_rva: u32,
    ) -> Result<Option<Vec<ProcedureLocal>>> {
        let Some(pdb) = self.pdbs.get_mut(&guid) else {
            return Ok(None);
        };
        let mut pdb_lock = pdb.lock();
        let address_map = pdb_lock.address_map()?;

        let type_information = pdb_lock.type_information()?;
        let mut finder = type_information.finder();
        let mut types = type_information.iter();
        while types.next()?.is_some() {
            finder.update(&types);
        }

        let debug_information = pdb_lock.debug_information()?;
        let mut modules = debug_information.modules()?;
        while let Some(dbi_module) = modules.next()? {
            let Some(module_info) = pdb_lock.module_info(&dbi_module)? else {
                continue;
            };
            let mut symbols = module_info.symbols()?;

            let mut procedure_end = None;
            let mut block_scopes: Vec<(pdb2::SymbolIndex, bool)> = Vec::new();
            let mut locals = Vec::new();
            let mut current_local = None;
            let mut current_optimized_out = false;
            let mut cpu_type = None;

            while let Some(symbol) = symbols.next()? {
                if let Some(end) = procedure_end {
                    if symbol.index() == end {
                        return Ok(Some(locals));
                    }
                    while block_scopes
                        .last()
                        .is_some_and(|(block_end, _)| *block_end == symbol.index())
                    {
                        block_scopes.pop();
                    }
                }

                if is_pdb2_function_list_symbol(symbol.raw_kind()) {
                    continue;
                }
                let data = symbol.parse()?;
                if let pdb2::SymbolData::CompileFlags(compile) = &data {
                    cpu_type = Some(compile.cpu_type);
                }
                if procedure_end.is_none() {
                    let pdb2::SymbolData::Procedure(procedure) = data else {
                        continue;
                    };
                    let Some(start) = procedure.offset.to_rva(&address_map) else {
                        continue;
                    };
                    if target_rva >= start.0 && target_rva < start.0.saturating_add(procedure.len) {
                        procedure_end = Some(procedure.end);
                    }
                    continue;
                }

                let visible = block_scopes.iter().all(|(_, contains)| *contains);
                match data {
                    pdb2::SymbolData::Block(block) => {
                        let contains = block.offset.to_rva(&address_map).is_some_and(|start| {
                            target_rva >= start.0 && target_rva < start.0.saturating_add(block.len)
                        });
                        block_scopes.push((block.end, contains));
                        current_local = None;
                    }
                    pdb2::SymbolData::Local(local) if visible => {
                        current_optimized_out = local.flags.isoptimizedout;
                        let reason = if current_optimized_out {
                            "optimized out"
                        } else {
                            "not live at this address"
                        };
                        locals.push(self.procedure_local(
                            guid,
                            &finder,
                            local.name.to_string().into(),
                            local.type_index,
                            local.flags.isparam,
                            LocalVariableLocation::Unavailable {
                                reason: reason.to_string(),
                            },
                        ));
                        current_local = Some(locals.len() - 1);
                    }
                    pdb2::SymbolData::Local(_) => {
                        current_local = None;
                        current_optimized_out = false;
                    }
                    pdb2::SymbolData::DefRangeRegister(range)
                        if !current_optimized_out
                            && current_local.is_some()
                            && pdb_live_range_contains(
                                &range.range,
                                &range.gaps,
                                &address_map,
                                target_rva,
                            ) =>
                    {
                        let location = if range.flags.maybe {
                            LocalVariableLocation::Unavailable {
                                reason: format!(
                                    "conditionally available in {}",
                                    pdb_register_name(range.register, cpu_type)
                                ),
                            }
                        } else {
                            LocalVariableLocation::Register {
                                register: pdb_register_name(range.register, cpu_type),
                            }
                        };
                        locals[current_local.unwrap()].location = location;
                    }
                    pdb2::SymbolData::DefRangeRegisterRelative(range)
                        if !current_optimized_out
                            && current_local.is_some()
                            && pdb_live_range_contains(
                                &range.range,
                                &range.gaps,
                                &address_map,
                                target_rva,
                            ) =>
                    {
                        locals[current_local.unwrap()].location =
                            if range.spilled_udt_member == 0 && range.offset_parent == 0 {
                                LocalVariableLocation::RegisterRelative {
                                    register: pdb_register_name(range.base_register, cpu_type),
                                    offset: range.offset_base_pointer,
                                }
                            } else {
                                LocalVariableLocation::Unavailable {
                                    reason: "split register-relative location".to_string(),
                                }
                            };
                    }
                    pdb2::SymbolData::DefRangeFramePointerRelative(range)
                        if !current_optimized_out
                            && current_local.is_some()
                            && pdb_live_range_contains(
                                &range.range,
                                &range.gaps,
                                &address_map,
                                target_rva,
                            ) =>
                    {
                        locals[current_local.unwrap()].location =
                            LocalVariableLocation::FrameRelative {
                                offset: range.offset,
                            };
                    }
                    pdb2::SymbolData::DefRangeFramePointerRelativeFullScope(range)
                        if !current_optimized_out && current_local.is_some() =>
                    {
                        locals[current_local.unwrap()].location =
                            LocalVariableLocation::FrameRelative {
                                offset: range.offset,
                            };
                    }
                    pdb2::SymbolData::DefRange(range)
                        if !current_optimized_out
                            && current_local.is_some()
                            && pdb_live_range_contains(
                                &range.range,
                                &range.gaps,
                                &address_map,
                                target_rva,
                            ) =>
                    {
                        locals[current_local.unwrap()].location =
                            LocalVariableLocation::Unavailable {
                                reason: format!(
                                    "unsupported DIA location program {}",
                                    range.program
                                ),
                            };
                    }
                    pdb2::SymbolData::DefRangeSubField(range)
                        if !current_optimized_out
                            && current_local.is_some()
                            && pdb_live_range_contains(
                                &range.range,
                                &range.gaps,
                                &address_map,
                                target_rva,
                            ) =>
                    {
                        locals[current_local.unwrap()].location =
                            LocalVariableLocation::Unavailable {
                                reason: "split subfield location".to_string(),
                            };
                    }
                    pdb2::SymbolData::DefRangeSubFieldRegister(range)
                        if !current_optimized_out
                            && current_local.is_some()
                            && pdb_live_range_contains(
                                &range.range,
                                &range.gaps,
                                &address_map,
                                target_rva,
                            ) =>
                    {
                        locals[current_local.unwrap()].location =
                            LocalVariableLocation::Unavailable {
                                reason: "split subfield register location".to_string(),
                            };
                    }
                    pdb2::SymbolData::RegisterVariable(variable) if visible => {
                        locals.push(self.procedure_local(
                            guid,
                            &finder,
                            variable.name.to_string().into(),
                            variable.type_index,
                            variable.slot.is_some(),
                            LocalVariableLocation::Register {
                                register: pdb_register_name(variable.register, cpu_type),
                            },
                        ));
                        current_local = None;
                    }
                    pdb2::SymbolData::RegisterRelative(variable) if visible => {
                        locals.push(self.procedure_local(
                            guid,
                            &finder,
                            variable.name.to_string().into(),
                            variable.type_index,
                            variable.slot.is_some(),
                            LocalVariableLocation::RegisterRelative {
                                register: pdb_register_name(variable.register, cpu_type),
                                offset: variable.offset,
                            },
                        ));
                        current_local = None;
                    }
                    pdb2::SymbolData::BasePointerRelative(variable) if visible => {
                        locals.push(self.procedure_local(
                            guid,
                            &finder,
                            variable.name.to_string().into(),
                            variable.type_index,
                            variable.slot.is_some(),
                            LocalVariableLocation::FrameRelative {
                                offset: variable.offset,
                            },
                        ));
                        current_local = None;
                    }
                    pdb2::SymbolData::MultiRegisterVariable(variable) if visible => {
                        if let Some((_, name)) = variable.registers.first() {
                            locals.push(self.procedure_local(
                                guid,
                                &finder,
                                name.to_string().into(),
                                variable.type_index,
                                false,
                                LocalVariableLocation::Unavailable {
                                    reason: "value spans multiple registers".to_string(),
                                },
                            ));
                        }
                        current_local = None;
                    }
                    _ => {}
                }
            }
        }
        Ok(None)
    }
}
