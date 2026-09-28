//! Frame locals: scanning a PDB for the variables in scope at an address,
//! sorting them into the frames there (the procedure's and each inlined
//! call's), and describing where each lives by register and live range.

use super::{CodeFrame, FrameLocals, LocalVariableLocation, ProcedureLocal, SymbolStore};
use crate::{error::Result, layout::ParsedType, types::Dtb};
use pdb2::{FallibleIterator, TypeFinder, TypeIndex};
use std::collections::HashSet;
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

/// A scope open in a procedure's symbols: a block or an inline site, until
/// the record `end`.
/// Whether `data` is one of the definition-range records that follow an
/// S_LOCAL and say where it lives.
fn is_definition_range(data: &pdb2::SymbolData<'_>) -> bool {
    matches!(
        data,
        pdb2::SymbolData::DefRange(_)
            | pdb2::SymbolData::DefRangeSubField(_)
            | pdb2::SymbolData::DefRangeRegister(_)
            | pdb2::SymbolData::DefRangeFramePointerRelative(_)
            | pdb2::SymbolData::DefRangeFramePointerRelativeFullScope(_)
            | pdb2::SymbolData::DefRangeSubFieldRegister(_)
            | pdb2::SymbolData::DefRangeRegisterRelative(_)
    )
}

/// Say that `local`, an S_LOCAL no definition range follows, was optimized
/// out, unless a range already located it.
fn mark_optimized_out(local: &mut ProcedureLocal) {
    if matches!(local.location, LocalVariableLocation::Unavailable { .. }) {
        local.location = LocalVariableLocation::Unavailable {
            reason: "optimized out".to_string(),
        };
    }
}

/// Whether a classic record (S_REGREL32, S_BPREL32, S_REGISTER) of `name` is
/// listed: not when an S_LOCAL in the frame describes the name. One that is
/// listed is remembered in `classic`, so a later S_LOCAL replaces it.
fn classic_record_wanted(
    described: &HashSet<String>,
    classic: &mut HashSet<String>,
    name: &pdb2::RawString<'_>,
) -> bool {
    let name = name.to_string().into_owned();
    if described.contains(&name) {
        return false;
    }
    classic.insert(name);
    true
}

struct OpenScope {
    end: pdb2::SymbolIndex,
    /// Whether the scope's code runs at the target address: a block's range
    /// covers it, or an inline site is one of the frames there.
    contains: bool,
    /// The frame the variables declared in the scope belong to (see
    /// [`CodeFrame::inline_depth`]).
    frame: usize,
}

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

    /// The locals and parameters of `frame`: the variables in scope at its
    /// address that are its own. An inline frame's are those of its inline
    /// site, the physical frame's those of its procedure outside every
    /// inline site. Definition ranges are filtered against the address and
    /// gaps. Unsupported DIA recipes and split locations remain explicit
    /// `Unavailable` entries rather than guessed values. `None` outside any
    /// private procedure, or for a frame the address does not have.
    pub fn frame_locals(
        &self,
        dtb: Dtb,
        frame: CodeFrame,
    ) -> Result<Option<Arc<Vec<ProcedureLocal>>>> {
        let Some(module) = self.find_module_for_address(dtb, frame.address) else {
            return Ok(None);
        };
        let Some(relative) = frame.address.0.checked_sub(module.base_address.0) else {
            return Ok(None);
        };
        let Ok(target_rva) = u32::try_from(relative) else {
            return Ok(None);
        };
        let key = (module.guid, target_rva);
        let frames = match self.locals_cache.get(&key) {
            Some(cached) => cached.clone(),
            None => {
                let frames = self.scan_frame_locals(module.guid, target_rva)?;
                if self.locals_cache.len() >= MAX_LOCALS_CACHE_ENTRIES {
                    self.locals_cache.clear();
                }
                self.locals_cache.insert(key, frames.clone());
                frames
            }
        };
        Ok(frames.and_then(|frames| frames.get(frame.inline_depth).cloned()))
    }

    /// The locals of every frame at `target_rva`, innermost first.
    fn scan_frame_locals(&self, guid: u128, target_rva: u32) -> Result<Option<FrameLocals>> {
        let Some(procedure) = self.procedure_at(guid, target_rva) else {
            return Ok(None);
        };
        // Decoded before the PDB is locked below: decoding locks it too.
        let chain = self.procedure_inlines(guid, procedure)?.chain(target_rva);
        let physical = chain.len();

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
        let Some(dbi_module) = debug_information.modules()?.nth(procedure.module)? else {
            return Ok(None);
        };
        let Some(module_info) = pdb_lock.module_info(&dbi_module)? else {
            return Ok(None);
        };

        // The compile flags open the module's stream, ahead of its procedures.
        let mut cpu_type = None;
        let mut symbols = module_info.symbols()?;
        while let Some(symbol) = symbols.next()? {
            if is_pdb2_function_list_symbol(symbol.raw_kind()) {
                continue;
            }
            match symbol.parse() {
                Ok(pdb2::SymbolData::CompileFlags(compile)) => {
                    cpu_type = Some(compile.cpu_type);
                    break;
                }
                Ok(pdb2::SymbolData::Procedure(_)) => break,
                _ => {}
            }
        }

        let mut symbols = module_info.symbols_at(procedure.record)?;
        let Some(first) = symbols.next()? else {
            return Ok(None);
        };
        let pdb2::SymbolData::Procedure(record) = first.parse()? else {
            return Ok(None);
        };

        let mut frames: Vec<Vec<ProcedureLocal>> = vec![Vec::new(); physical + 1];
        let mut scopes: Vec<OpenScope> = Vec::new();
        // The frame and index of the local the next definition ranges are for,
        // and whether any followed it yet.
        let mut current_local: Option<(usize, usize)> = None;
        let mut current_ranged = false;
        let mut current_optimized_out = false;
        // Per frame: names an S_LOCAL describes, and names only a classic
        // record (S_REGREL32, S_BPREL32, S_REGISTER) does so far.
        let mut described: Vec<HashSet<String>> = vec![HashSet::new(); physical + 1];
        let mut classic: Vec<HashSet<String>> = vec![HashSet::new(); physical + 1];

        while let Some(symbol) = symbols.next()? {
            if symbol.index() == record.end {
                break;
            }
            while scopes
                .last()
                .is_some_and(|scope| scope.end == symbol.index())
            {
                scopes.pop();
            }

            if is_pdb2_function_list_symbol(symbol.raw_kind()) {
                continue;
            }
            let data = symbol.parse()?;
            // An S_LOCAL no definition range follows has no location at
            // any address: the compiler dropped it.
            if is_definition_range(&data) {
                current_ranged |= current_local.is_some();
            } else if let Some((frame, index)) = current_local.take()
                && !current_ranged
            {
                mark_optimized_out(&mut frames[frame][index]);
            }
            let visible = scopes.iter().all(|scope| scope.contains);
            let frame = scopes.last().map_or(physical, |scope| scope.frame);
            let live = |range: &pdb2::AddressRange, gaps: &[pdb2::AddressGap]| {
                !current_optimized_out
                    && current_local.is_some()
                    && pdb_live_range_contains(range, gaps, &address_map, target_rva)
            };
            let mut located = None;
            match data {
                pdb2::SymbolData::Block(block) => {
                    let contains = block.offset.to_rva(&address_map).is_some_and(|start| {
                        target_rva >= start.0 && target_rva < start.0.saturating_add(block.len)
                    });
                    scopes.push(OpenScope {
                        end: block.end,
                        contains,
                        frame,
                    });
                    current_local = None;
                }
                // An inlined call's variables are its inline frame's; a
                // call not running at the address has no frame there.
                pdb2::SymbolData::InlineSite(site) => {
                    let position = chain.iter().position(|site| *site == symbol.index());
                    scopes.push(OpenScope {
                        end: site.end,
                        contains: position.is_some(),
                        frame: position.unwrap_or(frame),
                    });
                    current_local = None;
                }
                pdb2::SymbolData::Local(local) if visible => {
                    current_optimized_out = local.flags.isoptimizedout;
                    let reason = if current_optimized_out {
                        "optimized out"
                    } else {
                        "not live at this address"
                    };
                    // The S_LOCAL supersedes a classic record of the name:
                    // optimized MSVC code keeps one for a parameter's home
                    // slot, which the code never writes.
                    let name = local.name.to_string().into_owned();
                    if classic[frame].remove(&name) {
                        frames[frame].retain(|existing| existing.name != name);
                    }
                    described[frame].insert(name);
                    current_ranged = false;
                    frames[frame].push(self.procedure_local(
                        guid,
                        &finder,
                        local.name.to_string().into(),
                        local.type_index,
                        local.flags.isparam,
                        LocalVariableLocation::Unavailable {
                            reason: reason.to_string(),
                        },
                    ));
                    current_local = Some((frame, frames[frame].len() - 1));
                }
                pdb2::SymbolData::Local(_) => {
                    current_local = None;
                    current_optimized_out = false;
                }
                pdb2::SymbolData::DefRangeRegister(range) if live(&range.range, &range.gaps) => {
                    located = Some(if range.flags.maybe {
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
                    });
                }
                pdb2::SymbolData::DefRangeRegisterRelative(range)
                    if live(&range.range, &range.gaps) =>
                {
                    located = Some(
                        if range.spilled_udt_member == 0 && range.offset_parent == 0 {
                            LocalVariableLocation::RegisterRelative {
                                register: pdb_register_name(range.base_register, cpu_type),
                                offset: range.offset_base_pointer,
                            }
                        } else {
                            LocalVariableLocation::Unavailable {
                                reason: "split register-relative location".to_string(),
                            }
                        },
                    );
                }
                pdb2::SymbolData::DefRangeFramePointerRelative(range)
                    if live(&range.range, &range.gaps) =>
                {
                    located = Some(LocalVariableLocation::FrameRelative {
                        offset: range.offset,
                    });
                }
                pdb2::SymbolData::DefRangeFramePointerRelativeFullScope(range)
                    if !current_optimized_out && current_local.is_some() =>
                {
                    located = Some(LocalVariableLocation::FrameRelative {
                        offset: range.offset,
                    });
                }
                pdb2::SymbolData::DefRange(range) if live(&range.range, &range.gaps) => {
                    located = Some(LocalVariableLocation::Unavailable {
                        reason: format!("unsupported DIA location program {}", range.program),
                    });
                }
                pdb2::SymbolData::DefRangeSubField(range) if live(&range.range, &range.gaps) => {
                    located = Some(LocalVariableLocation::Unavailable {
                        reason: "split subfield location".to_string(),
                    });
                }
                pdb2::SymbolData::DefRangeSubFieldRegister(range)
                    if live(&range.range, &range.gaps) =>
                {
                    located = Some(LocalVariableLocation::Unavailable {
                        reason: "split subfield register location".to_string(),
                    });
                }
                pdb2::SymbolData::RegisterVariable(variable)
                    if visible
                        && classic_record_wanted(
                            &described[frame],
                            &mut classic[frame],
                            &variable.name,
                        ) =>
                {
                    frames[frame].push(self.procedure_local(
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
                pdb2::SymbolData::RegisterRelative(variable)
                    if visible
                        && classic_record_wanted(
                            &described[frame],
                            &mut classic[frame],
                            &variable.name,
                        ) =>
                {
                    frames[frame].push(self.procedure_local(
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
                pdb2::SymbolData::BasePointerRelative(variable)
                    if visible
                        && classic_record_wanted(
                            &described[frame],
                            &mut classic[frame],
                            &variable.name,
                        ) =>
                {
                    frames[frame].push(self.procedure_local(
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
                        frames[frame].push(self.procedure_local(
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
            if let (Some(location), Some((frame, index))) = (located, current_local) {
                frames[frame][index].location = location;
            }
        }
        if let Some((frame, index)) = current_local
            && !current_ranged
        {
            mark_optimized_out(&mut frames[frame][index]);
        }
        Ok(Some(frames.into_iter().map(Arc::new).collect()))
    }
}
