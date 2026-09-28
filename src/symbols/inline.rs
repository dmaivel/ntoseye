//! Inline frames: the calls a compiler inlined into a procedure, decoded from
//! its `S_INLINESITE` records, and the frames they make at an address.

use super::{
    CodeFrame, InlineFrame, ProcedureSpan, SourceLocation, SymbolStore, format_symbol_with_offset,
};
use crate::{
    error::Result,
    types::{Dtb, VirtAddr},
};
use pdb2::{FallibleIterator, FileIndex, IdData, IdIndex, SymbolIndex, TypeData};
use std::{collections::HashMap, io::Cursor, sync::Arc};

/// `S_INLINESITE` and `S_INLINESITE2`.
const S_INLINESITE: u16 = 0x114d;
const S_INLINESITE2: u16 = 0x115d;

const MAX_INLINE_CACHE_ENTRIES: usize = 4096;

/// The inline sites of one procedure, in record order: a site's parent comes
/// before it.
#[derive(Debug, Default)]
pub struct ProcedureInlines {
    sites: Vec<InlineSite>,
}

#[derive(Debug)]
struct InlineSite {
    /// Its `S_INLINESITE` record.
    record: SymbolIndex,
    /// The site it is inlined into; `None` for one in the procedure's own
    /// code.
    parent: Option<usize>,
    /// How many sites it is nested in.
    depth: usize,
    /// The inlined function, qualified by its namespace or class.
    name: String,
    /// The code the site covers, sorted by start, each range with the
    /// inlined function's line there.
    lines: Vec<InlineLine>,
}

#[derive(Debug)]
struct InlineLine {
    start: u32,
    end: u32,
    location: SourceLocation,
}

impl InlineSite {
    fn line_at(&self, rva: u32) -> Option<&InlineLine> {
        self.lines
            .iter()
            .find(|line| line.start <= rva && rva < line.end)
    }

    /// Its line where it calls `callee`: the line at `rva`, or, when its
    /// ranges leave the callee's code out, its last line starting at or
    /// before the callee's code.
    fn call_line(&self, rva: u32, callee: &InlineSite) -> Option<&InlineLine> {
        self.line_at(rva).or_else(|| {
            let start = callee.lines.first()?.start;
            self.lines.iter().rfind(|line| line.start <= start)
        })
    }
}

impl ProcedureInlines {
    /// The sites running at `rva`, innermost first: the deepest site whose
    /// code covers `rva`, then each site it is inlined into.
    fn chain_sites(&self, rva: u32) -> Vec<&InlineSite> {
        let mut next = self
            .sites
            .iter()
            .enumerate()
            .filter(|(_, site)| site.line_at(rva).is_some())
            .max_by_key(|(_, site)| site.depth)
            .map(|(index, _)| index);
        let mut chain = Vec::new();
        while let Some(index) = next {
            chain.push(&self.sites[index]);
            next = self.sites[index].parent;
        }
        chain
    }

    /// The `S_INLINESITE` records of the sites running at `rva`, innermost
    /// first: position `n` is the record of the frame with
    /// [`CodeFrame::inline_depth`] `n`.
    pub fn chain(&self, rva: u32) -> Vec<SymbolIndex> {
        self.chain_sites(rva)
            .into_iter()
            .map(|site| site.record)
            .collect()
    }
}

impl SymbolStore {
    /// The private procedure containing `rva` in PDB `guid`.
    pub fn procedure_at(&self, guid: u128, rva: u32) -> Option<ProcedureSpan> {
        let procedures = self.procedures.get(&guid)?;
        let index = procedures
            .partition_point(|procedure| procedure.rva <= rva)
            .checked_sub(1)?;
        let procedure = procedures[index];
        (rva - procedure.rva < procedure.len).then_some(procedure)
    }

    /// `procedure`'s inline sites, decoded on first use.
    pub fn procedure_inlines(
        &self,
        guid: u128,
        procedure: ProcedureSpan,
    ) -> Result<Arc<ProcedureInlines>> {
        let key = (guid, procedure.rva);
        if let Some(cached) = self.inline_cache.get(&key) {
            return Ok(cached.clone());
        }
        let inlines = Arc::new(self.decode_inlines(guid, procedure)?);
        if self.inline_cache.len() >= MAX_INLINE_CACHE_ENTRIES {
            self.inline_cache.clear();
        }
        self.inline_cache.insert(key, inlines.clone());
        Ok(inlines)
    }

    fn decode_inlines(&self, guid: u128, procedure: ProcedureSpan) -> Result<ProcedureInlines> {
        let Some(pdb) = self.pdbs.get_mut(&guid) else {
            return Ok(ProcedureInlines::default());
        };
        let mut pdb = pdb.lock();
        let address_map = pdb.address_map()?;
        // A PDB without source-file names still has inline ranges.
        let string_table = pdb.string_table().ok();
        let debug_information = pdb.debug_information()?;
        let Some(module) = debug_information.modules()?.nth(procedure.module)? else {
            return Ok(ProcedureInlines::default());
        };
        let Some(module_info) = pdb.module_info(&module)? else {
            return Ok(ProcedureInlines::default());
        };
        let line_program = module_info.line_program()?;
        let inlinees: HashMap<IdIndex, pdb2::Inlinee<'_>> = module_info
            .inlinees()?
            .map(|inlinee| Ok((inlinee.index(), inlinee)))
            .collect()?;
        let mut symbols = module_info.symbols_at(procedure.record)?;
        let Some(first) = symbols.next()? else {
            return Ok(ProcedureInlines::default());
        };
        let pdb2::SymbolData::Procedure(record) = first.parse()? else {
            return Ok(ProcedureInlines::default());
        };

        let mut files: HashMap<FileIndex, String> = HashMap::new();
        let mut file_name = |index: FileIndex| -> String {
            files
                .entry(index)
                .or_insert_with(|| {
                    line_program
                        .get_file_info(index)
                        .ok()
                        .and_then(|info| string_table.as_ref()?.get(info.name).ok())
                        .map(|name| name.to_string().into_owned())
                        .unwrap_or_default()
                })
                .clone()
        };

        let mut sites: Vec<InlineSite> = Vec::new();
        let mut inlinee_ids = Vec::new();
        // The open sites: each one's `S_INLINESITE_END` and index in `sites`.
        let mut open: Vec<(SymbolIndex, usize)> = Vec::new();
        while let Some(symbol) = symbols.next()? {
            if symbol.index() == record.end {
                break;
            }
            while open.last().is_some_and(|(end, _)| *end == symbol.index()) {
                open.pop();
            }
            if !matches!(symbol.raw_kind(), S_INLINESITE | S_INLINESITE2) {
                continue;
            }
            let pdb2::SymbolData::InlineSite(site) = symbol.parse()? else {
                continue;
            };
            let parent = open.last().map(|(_, index)| *index);
            let mut lines = Vec::new();
            if let Some(inlinee) = inlinees.get(&site.inlinee) {
                let mut records = inlinee.lines(record.offset, &site);
                while let Some(line) = records.next()? {
                    let (Some(start), Some(length)) =
                        (line.offset.to_rva(&address_map), line.length)
                    else {
                        continue;
                    };
                    if length == 0 {
                        continue;
                    }
                    lines.push(InlineLine {
                        start: start.0,
                        end: start.0.saturating_add(length),
                        location: SourceLocation {
                            file: file_name(line.file_index),
                            line: line.line_start,
                            column: line.column_start.filter(|column| *column != 0),
                            local: None,
                        },
                    });
                }
            }
            lines.sort_by_key(|line| line.start);
            inlinee_ids.push(site.inlinee);
            open.push((site.end, sites.len()));
            sites.push(InlineSite {
                record: symbol.index(),
                parent,
                depth: parent.map_or(0, |parent| sites[parent].depth + 1),
                name: String::new(),
                lines,
            });
        }

        if !sites.is_empty() {
            let names = inlinee_names(&mut pdb, &inlinee_ids)?;
            for (site, id) in sites.iter_mut().zip(&inlinee_ids) {
                site.name = names[id].clone();
            }
        }
        Ok(ProcedureInlines { sites })
    }

    /// The calls the compiler inlined at `address`, innermost first; empty
    /// where it inlined none, or without private symbols. Each is at its
    /// inlined function's line there, except that the line of a frame that
    /// called an inner one is its line where it made that call.
    pub fn inline_frames(&self, dtb: Dtb, address: VirtAddr) -> Vec<InlineFrame> {
        let Some(module) = self.find_module_for_address(dtb, address) else {
            return Vec::new();
        };
        let Some(rva) = address
            .0
            .checked_sub(module.base_address.0)
            .and_then(|relative| u32::try_from(relative).ok())
        else {
            return Vec::new();
        };
        let Some(procedure) = self.procedure_at(module.guid, rva) else {
            return Vec::new();
        };
        // An unreadable procedure shows as its physical frame alone.
        let Ok(inlines) = self.procedure_inlines(module.guid, procedure) else {
            return Vec::new();
        };
        let chain = inlines.chain_sites(rva);
        let mappings = self.source_paths.read();
        chain
            .iter()
            .enumerate()
            .map(|(position, site)| {
                let line = match position.checked_sub(1) {
                    Some(callee) => site.call_line(rva, chain[callee]),
                    None => site.line_at(rva),
                };
                InlineFrame {
                    symbol: format_symbol_with_offset(&module.short_name, &site.name, 0),
                    location: line.map(|line| {
                        let mut location = line.location.clone();
                        location.local = self.local_source(module.guid, &location.file, &mappings);
                        location
                    }),
                }
            })
            .collect()
    }

    /// The inline frame `frame` is, `None` for a physical frame.
    pub fn inline_frame(&self, dtb: Dtb, frame: CodeFrame) -> Option<InlineFrame> {
        self.inline_frames(dtb, frame.address)
            .into_iter()
            .nth(frame.inline_depth)
    }

    /// The source line of `frame`: an inline frame's own (see
    /// [`Self::inline_frames`]), else the line table's at its address, which
    /// for code inlined there is where the procedure made the call.
    pub fn frame_source_location(&self, dtb: Dtb, frame: CodeFrame) -> Option<SourceLocation> {
        match self.inline_frame(dtb, frame) {
            Some(inline) => inline.location,
            None => self.source_location(dtb, frame.address),
        }
    }
}

/// The qualified names of the functions `ids` name in the IPI stream: a
/// function by its namespace, a member function by its class.
fn inlinee_names(
    pdb: &mut pdb2::PDB<'static, Cursor<&'static [u8]>>,
    ids: &[IdIndex],
) -> Result<HashMap<IdIndex, String>> {
    let id_information = pdb.id_information()?;
    let mut id_finder = id_information.finder();
    let mut id_iter = id_information.iter();
    while id_iter.next()?.is_some() {
        id_finder.update(&id_iter);
    }

    let mut names = HashMap::new();
    let mut members = Vec::new();
    for id in ids {
        if names.contains_key(id) {
            continue;
        }
        let parsed = id_finder.find(*id).and_then(|item| item.parse());
        let name = match parsed {
            Ok(IdData::Function(function)) => {
                let name = function.name.to_string();
                match function
                    .scope
                    .and_then(|scope| id_string(&id_finder, scope))
                    .filter(|scope| !scope.is_empty())
                {
                    Some(scope) => format!("{scope}::{name}"),
                    None => name.into_owned(),
                }
            }
            Ok(IdData::MemberFunction(member)) => {
                members.push((*id, member.parent));
                member.name.to_string().into_owned()
            }
            _ => format!("inlinee_{:#x}", id.0),
        };
        names.insert(*id, name);
    }

    // A member function's class is a type: read the type stream only as far
    // as the last class needed.
    if let Some(last) = members.iter().map(|(_, class)| *class).max() {
        let type_information = pdb.type_information()?;
        let mut type_finder = type_information.finder();
        let mut type_iter = type_information.iter();
        while let Some(item) = type_iter.next()? {
            type_finder.update(&type_iter);
            if item.index() >= last {
                break;
            }
        }
        for (id, class) in members {
            let class_name = match type_finder.find(class).and_then(|item| item.parse()) {
                Ok(TypeData::Class(class)) => Some(class.name.to_string().into_owned()),
                Ok(TypeData::Union(union)) => Some(union.name.to_string().into_owned()),
                Ok(TypeData::Enumeration(enumeration)) => {
                    Some(enumeration.name.to_string().into_owned())
                }
                _ => None,
            };
            if let (Some(class_name), Some(name)) = (class_name, names.get_mut(&id)) {
                *name = format!("{class_name}::{name}");
            }
        }
    }
    Ok(names)
}

/// The string an `LF_STRING_ID` holds, its substrings first.
fn id_string(finder: &pdb2::IdFinder<'_>, id: IdIndex) -> Option<String> {
    let IdData::String(string) = finder.find(id).ok()?.parse().ok()? else {
        return None;
    };
    let mut text = String::new();
    if let Some(list) = string.substrings
        && let Ok(IdData::StringList(list)) = finder.find(list).and_then(|item| item.parse())
    {
        for part in list.substrings {
            if let Ok(IdData::String(part)) =
                finder.find(IdIndex(part.0)).and_then(|item| item.parse())
            {
                text.push_str(&part.name.to_string());
            }
        }
    }
    text.push_str(&string.name.to_string());
    Some(text)
}
