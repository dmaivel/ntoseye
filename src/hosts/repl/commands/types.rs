use std::borrow::Cow;
use std::sync::Arc;

use crate::base::error::Result;
use crate::base::types::VirtAddr;
use crate::hosts::ui;
use crate::nt::expr::{Expr, ExprValue};
use crate::nt::layout::{
    FieldInfo, ParsedType, TypeInfo, abi_layout, find_field, le_uint, named_type,
    nested_layout_name, unqualified_type_name,
};
use crate::nt::symbols::glob_matches;
use crate::nt::target::{ListCursor, ListTermination, UserVar};
use crate::session::typeview::{MAX_ARRAY_ELEMENTS, TypeView};

use ntoseye_macros::{command, grammar};

use crate::hosts::repl::args::{ArgCursor, ArgCx, ArgError};
use crate::hosts::repl::*;

const MAX_LIST_ENTRIES: usize = 4096;
pub const MAX_RECURSION_DEPTH: usize = 64;
const MAX_DL_WORDS: usize = 64;

/// Why `dt` and `dx` cannot show the value of `name`, a symbol or module at
/// `address` that has no type: public symbols record a global's address but
/// not its type, so the value is only readable once a cast names the type.
pub fn untyped_symbol_message(name: &str, address: VirtAddr) -> String {
    format!(
        "{name} ({:#x}) has no type information in its symbols; name the type \
         with a cast, as in `dx *(<type> *){name}`",
        address.0
    )
}

/// Show a type layout or a decoded structure.
///
/// -r expands nested structures, -a expands bounded arrays, and -v shows field
/// sizes. -y matches names by case-insensitive prefix, and -l <field> walks a
/// LIST_ENTRY field. ntoseye looks for a bare type name in the kernel PDB
/// first, and then in the modules of the current address space. If the PDB of a
/// module defines a member type, ntoseye names the type with that module
/// (wdf01000!_WDF_DRIVER_GLOBALS) and expands it from that PDB. If the PDB only
/// declares the type (a driver's _EPROCESS*), ntoseye resolves it as a bare
/// name. Nested field paths use dots, and field patterns support * and ?. A
/// word that names a field of the type is a field pattern, so the address may
/// come before or after the fields, as in WinDbg. With
/// -l, the given address is the first element, as in WinDbg, so the walk
/// includes all nodes until it returns to that address. In memory, a list head
/// and a record link look the same, so if you start at a list head instead of
/// at `poi(ListHead)`, the command shows the head as one pseudo-record and does
/// not drop a real record. If the list is empty, its link points to itself, and
/// the command shows nothing. The walk keeps the entries that it collected, and
/// reports null links, cycles, unreadable links, and when it reaches the entry
/// limit.
#[command(
    names = ["dt"],
    category = "symbols, types, and expressions",
    kind = Query,
    python = none,
)]
fn dt(state: &mut ReplState<'_>, #[arg(parse = dt_arguments)] parsed: ParsedDtArgs) -> Result<()> {
    state.dt(parsed)
}

/// `dt`'s words.
#[grammar(
    usage = "[-r[N]] [-a[N]] [-v] [-y] [-l <field>] [module!]<type> [field-pattern]... [address] [field-pattern]...",
    complete = Type
)]
fn dt_arguments(
    _: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<ParsedDtArgs, ArgError> {
    parse_dt_args(&cursor.take_all(|_| true)).map_err(|error| {
        if error == "missing type name" {
            ArgError::Missing
        } else {
            ArgError::Message(format!("dt: {error}"))
        }
    })
}

/// Dump a bounded _LIST_ENTRY chain.
///
/// By default, the walk follows Flink, and -b follows Blink. The optional size
/// is the number of pointer-sized words that the command shows for each
/// element, 2 by default. The given address is the first element, as in WinDbg,
/// so the walk includes all nodes until it returns to that address. In memory,
/// a list head and a record link look the same, so if you start at a list head
/// instead of at `poi(ListHead)`, the command shows the head as one
/// pseudo-record and does not drop a real record. If the list is empty, its
/// link points to itself, and the command shows nothing. The walk keeps the
/// entries that it collected, and reports null links, cycles, unreadable links,
/// and when it reaches the entry limit. It does not report when it reaches the
/// requested maxcount.
#[command(
    names = ["dl"],
    category = "memory and disassembly",
    kind = Query,
    python = none,
)]
fn dl(state: &mut ReplState<'_>, #[arg(parse = dl_arguments)] words: DlArgs) -> Result<()> {
    state.dl(words)
}

/// `dl`'s words: `-b` anywhere, and two or three expressions.
struct DlArgs {
    backward: bool,
    positional: Vec<String>,
}

#[grammar(usage = "[-b] <address> <maxcount> [size]", complete = Expression)]
fn dl_arguments(
    _: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<DlArgs, ArgError> {
    let backward = !cursor.take_all(|word| word == "-b").is_empty();
    let positional: Vec<String> = cursor
        .take_all(|_| true)
        .into_iter()
        .map(|word| word.into_owned())
        .collect();
    if !(2..=3).contains(&positional.len()) {
        return Err(ArgError::Missing);
    }
    Ok(DlArgs {
        backward,
        positional,
    })
}

/// `!list`'s words: `-t [module!]<type>.<field>`, `-x "<commands>"`, and the
/// list head address, in any order.
struct ListArguments {
    type_field: String,
    commands: String,
    address: String,
}

#[grammar(
    usage = "-t [module!]<type>.<field> -x \"<commands>\" <address>",
    complete = Expression
)]
fn list_arguments(
    _: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<ListArguments, ArgError> {
    let message = |text: &str| ArgError::Message(text.to_string());
    let mut type_field = None;
    let mut commands = None;
    let mut positional = Vec::new();
    while let Some(word) = cursor.word() {
        match word.as_ref() {
            "-t" => {
                let value = cursor
                    .word()
                    .ok_or_else(|| message("!list: missing type after -t"))?;
                type_field = Some(value.into_owned());
            }
            "-x" => {
                let value = cursor
                    .word()
                    .ok_or_else(|| message("!list: missing commands after -x"))?;
                commands = Some(value.into_owned());
            }
            arg if arg.starts_with('-') => {
                return Err(ArgError::Message(format!("!list: unknown option `{arg}`")));
            }
            _ => positional.push(word.into_owned()),
        }
    }
    let (Some(type_field), Some(commands), Some(address)) =
        (type_field, commands, positional.first().cloned())
    else {
        return Err(ArgError::Missing);
    };
    if positional.len() > 1 {
        return Err(message("!list accepts one list head address"));
    }
    Ok(ListArguments {
        type_field,
        commands,
        address,
    })
}

/// Run commands for each element of a typed LIST_ENTRY chain.
///
/// Each command can get the element address as $extret, @extret, or @$extret.
/// The walk stops at the head, at a repeated link, or after 4096 elements. The
/// given address is the first element, as in WinDbg, so the walk includes all
/// nodes until it returns to that address. In memory, a list head and a record
/// link look the same, so if you start at a list head instead of at
/// `poi(ListHead)`, the command uses the head as one pseudo-record and does not
/// drop a real record. If the list is empty, its link points to itself, and the
/// command runs nothing. The walk keeps the entries that it collected, and
/// reports null links, cycles, unreadable links, and when it reaches the entry
/// limit. Ctrl+C stops the commands between elements. A command that the
/// session does not accept, for example a resume inside a breakpoint action,
/// stops the element commands and the rest of the command line, but a command
/// that only reports an error does not stop them.
#[command(
    names = ["!list"],
    category = "objects and I/O",
    kind = Host,
    python = none,
)]
fn list(
    state: &mut ReplState<'_>,
    #[arg(parse = list_arguments)] arguments: ListArguments,
) -> Result<Flow> {
    let ListArguments {
        type_field,
        commands,
        address: address_text,
    } = arguments;
    let Some((type_name, field_name)) = type_field.rsplit_once('.') else {
        error!(
            "{}",
            usage_error(
                "!list",
                format!("!list -t names no field in '{type_field}'")
            )
        );
        return Ok(Flow::Continue);
    };
    let path = match parse_field_path(field_name) {
        Ok(path) => path,
        Err(error) => {
            error!("!list: {}", error);
            return Ok(Flow::Continue);
        }
    };
    let type_info = match state.lookup_type(type_name) {
        Some(type_info) => type_info,
        None => {
            error!("!list: type '{}' not found", type_name);
            return Ok(Flow::Continue);
        }
    };
    let head = match state.eval_or_report(&address_text) {
        Some(address) if !address.is_zero() => address,
        Some(_) => {
            error!("!list requires a nonzero list head address");
            return Ok(Flow::Continue);
        }
        None => return Ok(Flow::Continue),
    };
    let resolved = match state.resolve_field_path(type_info.as_ref(), &path) {
        Ok(path) => path,
        Err(error) => {
            error!("!list -t {}: {}", type_field, error);
            return Ok(Flow::Continue);
        }
    };
    let (link_offset, next_offset, pointer_size) = match state.list_offsets(&resolved) {
        Ok(offsets) => offsets,
        Err(error) => {
            error!("!list -t {}: {}", type_field, error);
            return Ok(Flow::Continue);
        }
    };
    let (records, termination) =
        state.collect_typed_list(head, link_offset, next_offset, pointer_size);
    let command = commands.replace("@$extret", "@extret");
    let flow = state.in_command_loop("!list", |state| {
        state.run_iterations("!list", records.len(), |state, index| {
            state.ctx.target.user_vars.insert(
                "extret".to_string(),
                UserVar {
                    value: records[index].0,
                    source: "!list element".to_string(),
                },
            );
            Some(Cow::Borrowed(command.as_str()))
        })
    })?;
    if let Some(stop) = termination.diagnostic() {
        outln!("!list: list walk stopped: {stop}");
    }
    Ok(flow)
}

#[derive(Debug, Clone, Default)]
struct DtOptions {
    recursive_depth: usize,
    array_limit: Option<usize>,
    verbose: bool,
    prefix_match: bool,
    list_field: Option<Vec<String>>,
    show_values: bool,
}

#[derive(Debug, Clone)]
struct ParsedDtArgs {
    type_name: String,
    /// The words after the type: field patterns and at most one address,
    /// told apart once the type's fields are known (see `ReplState::dt`).
    words: Vec<String>,
    options: DtOptions,
}

#[derive(Debug, Clone)]
struct PathComponent {
    name: String,
    info: FieldInfo,
}

#[derive(Debug, Clone)]
struct ResolvedFieldPath {
    components: Vec<PathComponent>,
}

fn parse_depth_option(arg: &str, prefix: &str, bare: usize) -> std::result::Result<usize, String> {
    let suffix = &arg[prefix.len()..];
    if suffix.is_empty() {
        return Ok(bare);
    }
    let value = suffix
        .parse::<usize>()
        .map_err(|_| format!("invalid {} depth '{}'", prefix, suffix))?;
    Ok(value.min(MAX_RECURSION_DEPTH))
}

fn parse_array_option(arg: &str) -> std::result::Result<usize, String> {
    let suffix = &arg[2..];
    if suffix.is_empty() {
        return Ok(MAX_ARRAY_ELEMENTS);
    }
    let value = suffix
        .parse::<usize>()
        .map_err(|_| format!("invalid -a count '{}'", suffix))?;
    Ok(value.min(MAX_ARRAY_ELEMENTS))
}

fn parse_dt_args(args: &[Cow<'_, str>]) -> std::result::Result<ParsedDtArgs, String> {
    let mut options = DtOptions::default();
    let mut positional = Vec::new();
    let mut index = 0;
    let mut parse_options = true;

    while index < args.len() {
        let arg = args[index].as_ref();
        if parse_options && arg == "--" {
            parse_options = false;
            index += 1;
            continue;
        }
        if parse_options && (arg == "-r" || arg.starts_with("-r")) {
            options.recursive_depth = parse_depth_option(arg, "-r", 1)?;
            index += 1;
            continue;
        }
        if parse_options && (arg == "-a" || arg.starts_with("-a")) {
            options.array_limit = Some(parse_array_option(arg)?);
            index += 1;
            continue;
        }
        if parse_options && arg == "-v" {
            options.verbose = true;
            index += 1;
            continue;
        }
        if parse_options && arg == "-y" {
            options.prefix_match = true;
            index += 1;
            continue;
        }
        if parse_options && arg == "-l" {
            let Some(field) = args.get(index + 1).map(|value| value.as_ref()) else {
                return Err("missing field after -l".to_string());
            };
            options.list_field = Some(parse_field_path(field)?);
            index += 2;
            continue;
        }
        if parse_options && arg.starts_with('-') {
            return Err(format!("unknown dt option `{arg}`"));
        }
        positional.push(arg.to_string());
        index += 1;
    }

    let mut positional = positional.into_iter();
    let Some(type_name) = positional.next() else {
        return Err("missing type name".to_string());
    };
    Ok(ParsedDtArgs {
        type_name,
        words: positional.collect(),
        options,
    })
}

/// Parse a dotted field path without resolving it against a particular PDB.
fn parse_field_path(path: &str) -> std::result::Result<Vec<String>, String> {
    if path.is_empty() {
        return Err("field path is empty".to_string());
    }
    let mut fields = Vec::new();
    for field in path.split('.') {
        if field.is_empty()
            || !field
                .chars()
                .next()
                .is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '_')
            || !field
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        {
            return Err(format!("invalid field path `{path}`"));
        }
        fields.push(field.to_string());
    }
    Ok(fields)
}

fn field_matches(name: &str, patterns: &[String], prefix_match: bool) -> bool {
    patterns.is_empty()
        || patterns
            .iter()
            .any(|pattern| field_matches_pattern(name, pattern, prefix_match))
}

fn field_matches_pattern(name: &str, pattern: &str, prefix_match: bool) -> bool {
    if prefix_match {
        name.to_ascii_lowercase()
            .starts_with(&pattern.to_ascii_lowercase())
    } else {
        glob_matches(pattern, name, true)
    }
}

/// Whether `word` reads as a field pattern of `type_info`: it matches one of
/// its fields, or starts a dotted path at one (`Pcb.Header`).
fn names_field(type_info: &TypeInfo, word: &str, prefix_match: bool) -> bool {
    let first = word.split('.').next().unwrap_or(word);
    !first.is_empty()
        && type_info
            .fields
            .keys()
            .any(|name| field_matches_pattern(name, first, prefix_match))
}

/// What `dt` shows for a type: its header, then its fields (or the
/// records of a `-l` walk). Gathered once, then printed as text or drawn as
/// a tree.
pub struct DtDump {
    pub type_name: String,
    pub size: usize,
    /// The instance's address; `None` for a layout.
    pub address: Option<u64>,
    pub body: DtBody,
}

pub enum DtBody {
    /// The layout's fields, or one instance's.
    Fields(Vec<DtEntry>),
    /// `dt -l`: each record's address and fields, then the line saying
    /// why the walk stopped early.
    List {
        records: Vec<(u64, Vec<DtEntry>)>,
        stop: Option<String>,
    },
    /// `dt -l` could not walk: the error after the header.
    Failed(String),
}

/// One line of a `dt` dump, with the lines nested under it.
pub enum DtEntry {
    /// A field, or an element of an array field.
    Field(DtField),
    /// A line about its level: a nested type that isn't found, an array
    /// whose elements can't be shown, elements left out, a field path that
    /// can't be read.
    Note(String),
    /// A field path that doesn't resolve, printed as an error.
    Error(String),
}

pub struct DtField {
    /// The field's offset; `None` for an array element.
    pub offset: Option<u32>,
    /// The field's name, a dotted path, or an element's `[index]`.
    pub name: String,
    pub type_name: String,
    /// The field's size, with `-v`.
    pub size: Option<usize>,
    /// The decoded value, when `dt` has an address and the field is not a
    /// nested structure or array.
    pub value: Option<String>,
    /// The value is a number (an integer or a bitfield), not a pointer,
    /// an enum or a string.
    pub numeric: bool,
    /// A nested structure's fields or an array's elements.
    pub children: Vec<DtEntry>,
}

impl DtField {
    /// The field's line without its value, indented `indent` spaces.
    fn label(&self, indent: usize) -> String {
        // WinDbg pads a field offset to three hex digits and lets wider
        // offsets grow naturally (`+0x000`, `+0x2e0`, `+0x1150`), so a
        // layout dump lines up with the reference output people compare
        // against and with anything grepping for `+0x000 `.
        let mut label = " ".repeat(indent);
        if let Some(offset) = self.offset {
            label.push_str(&format!("+0x{offset:03x} "));
        }
        label.push_str(&format!("{} : {}", self.name, self.type_name));
        if let Some(size) = self.size {
            label.push_str(&format!(" [size {size}]"));
        }
        label
    }
}

fn print_dt(dump: &DtDump) {
    outln!(
        "{} ({:#x} bytes){}",
        dump.type_name,
        dump.size,
        dump.address
            .map(|address| format!(" @ {}", ui::addr(address)))
            .unwrap_or_default()
    );
    match &dump.body {
        DtBody::Fields(entries) => {
            print_dt_entries(entries, 2);
        }
        DtBody::List { records, stop } => {
            for (record, entries) in records {
                outln!("{} @ {}", dump.type_name, ui::addr(*record));
                print_dt_entries(entries, 2);
            }
            if let Some(stop) = stop {
                outln!("{stop}");
            }
        }
        DtBody::Failed(message) => error!("{message}"),
    }
}

fn print_dt_entries(entries: &[DtEntry], indent: usize) {
    for entry in entries {
        match entry {
            DtEntry::Field(field) => {
                match &field.value {
                    Some(value) => outln!("{} = {}", field.label(indent), value),
                    None => outln!("{}", field.label(indent)),
                }
                print_dt_entries(&field.children, indent + 2);
            }
            DtEntry::Note(note) => outln!("{}{}", " ".repeat(indent), note),
            DtEntry::Error(message) => error!("{message}"),
        }
    }
}

fn print_enum(name: &str, variants: &[(String, i64)]) {
    outln!("enum {} ({} values)", name, variants.len());
    // The values in one right-aligned column, as `dt` lists an enum's.
    let width = variants
        .iter()
        .map(|(_, value)| format!("{value:#x}").len())
        .max()
        .unwrap_or(0);
    for (name, value) in variants {
        outln!("  {:>width$}  {}", format!("{value:#x}"), name);
    }
}

impl ReplState<'_> {
    fn type_view(&self) -> TypeView<'_> {
        TypeView::new(self.ctx)
    }

    fn lookup_type(&self, type_name: &str) -> Option<Arc<TypeInfo>> {
        self.type_view().lookup_type(type_name)
    }

    fn lookup_enum(&self, type_name: &str) -> Option<Vec<(String, i64)>> {
        self.type_view().lookup_enum(type_name)
    }

    /// `field` at `address` as a dump entry: named `name`, at `offset`
    /// (`None` for an array element, which `-v` shows no size for either),
    /// with its value or, `depth` levels down, its nested fields.
    fn field_entry(
        &self,
        address: VirtAddr,
        field: &FieldInfo,
        name: String,
        offset: Option<u32>,
        options: &DtOptions,
        depth: usize,
    ) -> DtEntry {
        let mut entry = DtField {
            offset,
            name,
            type_name: field.type_data.to_string(),
            size: (offset.is_some() && options.verbose).then(|| self.type_view().field_size(field)),
            value: None,
            numeric: false,
            children: Vec::new(),
        };
        match &field.type_data {
            // A nested layout shows its own fields rather than a value, but
            // the two Windows aggregates `TypeView` renders as text do not.
            ParsedType::Struct(type_name) | ParsedType::Union(type_name)
                if !named_type(&field.type_data, "_UNICODE_STRING")
                    && !named_type(&field.type_data, "_LIST_ENTRY") =>
            {
                if depth > 0 {
                    if let Some(type_info) = self.lookup_type(type_name) {
                        entry.children = self.struct_entries(
                            type_info.as_ref(),
                            address,
                            options,
                            &[],
                            depth.saturating_sub(1),
                        );
                    } else {
                        entry
                            .children
                            .push(DtEntry::Note(format!("type '{}' not found", type_name)));
                    }
                }
            }
            // An array shows its elements, unless it is an inline C string.
            ParsedType::Array(_, _) if field.type_data.c_string_len().is_none() => {
                entry.children =
                    self.array_entries(address, field, options, depth.saturating_sub(1));
            }
            // Everything else has a text value: scalars, enums, bitfields,
            // `_UNICODE_STRING`, `_LIST_ENTRY` and C-string arrays.
            _ => {
                if options.show_values {
                    entry.value = Some(self.type_view().value_text(address, field));
                    entry.numeric = matches!(
                        field.type_data,
                        ParsedType::Primitive(_) | ParsedType::Bitfield { .. }
                    ) && !named_type(&field.type_data, "_UNICODE_STRING")
                        && !named_type(&field.type_data, "_LIST_ENTRY");
                }
            }
        }
        DtEntry::Field(entry)
    }

    fn array_entries(
        &self,
        address: VirtAddr,
        field: &FieldInfo,
        options: &DtOptions,
        depth: usize,
    ) -> Vec<DtEntry> {
        let ParsedType::Array(inner, count) = &field.type_data else {
            return Vec::new();
        };
        let max_elements = options
            .array_limit
            .unwrap_or(MAX_ARRAY_ELEMENTS)
            .min(MAX_ARRAY_ELEMENTS);
        let count_usize = *count as usize;
        let shown = count_usize.min(max_elements);
        if shown == 0 {
            return Vec::new();
        }
        let total_size = self.type_view().field_size(field);
        let Some(element_size) = self.type_view().element_stride(total_size, inner, *count) else {
            return vec![DtEntry::Note(
                "[array elements unavailable: element size is unknown]".to_string(),
            )];
        };

        let mut entries = Vec::with_capacity(shown + 1);
        for index in 0..shown {
            let element_address = address + (index.saturating_mul(element_size)) as u64;
            let element_field = FieldInfo {
                offset: 0,
                size: element_size as u64,
                type_data: inner.as_ref().clone(),
            };
            entries.push(self.field_entry(
                element_address,
                &element_field,
                format!("[{index}]"),
                None,
                options,
                depth.max(1),
            ));
        }
        if shown < count_usize {
            entries.push(DtEntry::Note(format!(
                "... {} array elements omitted",
                count_usize - shown
            )));
        }
        entries
    }

    fn struct_entries(
        &self,
        type_info: &TypeInfo,
        base: VirtAddr,
        options: &DtOptions,
        patterns: &[String],
        depth: usize,
    ) -> Vec<DtEntry> {
        type_info
            .fields_in_order()
            .into_iter()
            .filter(|(name, _)| field_matches(name, patterns, options.prefix_match))
            .map(|(name, field)| {
                self.field_entry(
                    base + field.offset as u64,
                    field,
                    name.to_string(),
                    Some(field.offset),
                    options,
                    depth,
                )
            })
            .collect()
    }

    fn resolve_field_path(
        &self,
        root: &TypeInfo,
        path: &[String],
    ) -> std::result::Result<ResolvedFieldPath, String> {
        if path.is_empty() {
            return Err("field path is empty".to_string());
        }
        let mut current_type: Option<Arc<TypeInfo>> = None;
        let mut components = Vec::with_capacity(path.len());
        for (index, requested_name) in path.iter().enumerate() {
            let Some((name, info)) =
                find_field(current_type.as_deref().unwrap_or(root), requested_name)
                    .map(|(name, info)| (name.to_string(), info.clone()))
            else {
                return Err(format!("field '{requested_name}' not found"));
            };
            let next_type_name = nested_layout_name(&info.type_data);
            components.push(PathComponent { name, info });
            if index + 1 < path.len() {
                let Some(next_type_name) = next_type_name else {
                    return Err(format!(
                        "field `{requested_name}` is not a nested structure"
                    ));
                };
                let next_type = self
                    .lookup_type(&next_type_name)
                    .or_else(|| abi_layout(&next_type_name).map(Arc::new));
                let Some(next_type) = next_type else {
                    return Err(format!("nested type '{next_type_name}' not found"));
                };
                current_type = Some(next_type);
            }
        }
        Ok(ResolvedFieldPath { components })
    }

    /// The address of the path's last field, and that field with its offset
    /// taken from the struct it is read out of: the `dt` root, or the target
    /// of the last pointer the path follows.
    fn runtime_field_address(
        &self,
        base: VirtAddr,
        path: &ResolvedFieldPath,
    ) -> std::result::Result<(VirtAddr, FieldInfo), String> {
        let mut current = base;
        let mut offset = 0u32;
        for (index, component) in path.components.iter().enumerate() {
            let field_address = current + component.info.offset as u64;
            offset = offset.saturating_add(component.info.offset);
            if index + 1 == path.components.len() {
                let field = FieldInfo {
                    offset,
                    ..component.info.clone()
                };
                return Ok((field_address, field));
            }
            if matches!(component.info.type_data, ParsedType::Pointer(_)) {
                let pointer = self.type_view().read_display_uint(
                    field_address,
                    self.type_view().field_size(&component.info),
                )?;
                if pointer == 0 {
                    return Err(format!("field '{}' points to null", component.name));
                }
                current = VirtAddr(pointer);
                offset = 0;
            } else {
                current = field_address;
            }
        }
        Err("field path is empty".to_string())
    }

    fn resolved_path_entry(
        &self,
        root: &TypeInfo,
        base: VirtAddr,
        path: &[String],
        options: &DtOptions,
    ) -> DtEntry {
        let resolved = match self.resolve_field_path(root, path) {
            Ok(path) => path,
            Err(error) => return DtEntry::Error(format!("{}: {}", path.join("."), error)),
        };
        let (address, field) = match self.runtime_field_address(base, &resolved) {
            Ok(value) => value,
            Err(error) => {
                return DtEntry::Note(format!("{} : <unavailable: {}>", path.join("."), error));
            }
        };
        self.field_entry(
            address,
            &field,
            path.join("."),
            Some(field.offset),
            options,
            options.recursive_depth.max(1),
        )
    }

    fn list_offsets(
        &self,
        path: &ResolvedFieldPath,
    ) -> std::result::Result<(u64, u64, usize), String> {
        let Some(last) = path.components.last() else {
            return Err("field path is empty".to_string());
        };
        let mut link_offset = 0u64;
        for component in &path.components[..path.components.len() - 1] {
            if matches!(component.info.type_data, ParsedType::Pointer(_)) {
                return Err("list field path cannot pass through a pointer".to_string());
            }
            link_offset = link_offset.saturating_add(component.info.offset as u64);
        }
        if named_type(&last.info.type_data, "_LIST_ENTRY") {
            let entry_offset = link_offset.saturating_add(last.info.offset as u64);
            // `_LIST_ENTRY` is Flink then Blink, so each link is half its size.
            let pointer_size = (self.type_view().field_size(&last.info) / 2).clamp(1, 8);
            return Ok((entry_offset, entry_offset, pointer_size));
        }
        let next_offset = link_offset.saturating_add(last.info.offset as u64);
        let pointer_size = self.type_view().field_size(&last.info).clamp(1, 8);
        Ok((link_offset, next_offset, pointer_size))
    }

    /// Walk a typed list treating `first` as the first element, the way
    /// WinDbg's `!list` treats its address argument: every node up to the
    /// return to `first` is emitted. A list head and a record link are
    /// structurally identical, so starting from a head yields the head as one
    /// pseudo-record instead of silently dropping the real last record.
    fn collect_typed_list(
        &self,
        first: VirtAddr,
        link_offset: u64,
        next_offset: u64,
        pointer_size: usize,
    ) -> (Vec<VirtAddr>, ListTermination) {
        // A link pointing at itself is an empty list's head: the one sentinel
        // that is provably not a record.
        if self
            .type_view()
            .read_display_uint(first - link_offset + next_offset, pointer_size)
            .ok()
            .is_some_and(|next| next == first.0)
        {
            return (Vec::new(), ListTermination::Head);
        }
        let mut cursor = ListCursor::from_first(first, MAX_LIST_ENTRIES);
        let mut records = Vec::new();
        while let Some(link) = cursor.take_current() {
            let record = link - link_offset;
            records.push(record);
            cursor.advance(
                self.type_view()
                    .read_display_uint(record + next_offset, pointer_size)
                    .map(VirtAddr)
                    .map_err(|error| error.to_string()),
            );
        }
        (records, cursor.finish())
    }

    fn dt(&mut self, mut parsed: ParsedDtArgs) -> Result<()> {
        let type_info = match self.lookup_type(&parsed.type_name) {
            Some(type_info) => type_info,
            None => {
                if let Some(variants) = self.lookup_enum(&parsed.type_name) {
                    let name = unqualified_type_name(&parsed.type_name);
                    print_enum(name, &variants);
                } else if let Ok(ExprValue::Raw {
                    address: Some(address),
                    ..
                }) =
                    Expr::parse(&parsed.type_name).and_then(|expr| expr.evaluate(&self.ctx.target))
                {
                    error!("{}", untyped_symbol_message(&parsed.type_name, address));
                } else {
                    error!("type '{}' not found", parsed.type_name);
                }
                return Ok(());
            }
        };

        // As in WinDbg, a word that names a field of the type is a field
        // pattern, even one that would also evaluate (a bare pseudo-register
        // such as `BasePriority`, or a hex-looking name), and the first word
        // that names none is the address, before or after the fields.
        let mut address_text = None;
        let mut patterns = Vec::with_capacity(parsed.words.len());
        for word in std::mem::take(&mut parsed.words) {
            if address_text.is_none()
                && !names_field(&type_info, &word, parsed.options.prefix_match)
            {
                address_text = Some(word);
            } else {
                patterns.push(word);
            }
        }
        let address = address_text
            .as_deref()
            .and_then(|text| Expr::eval_with_radix(text, &self.ctx.target, self.radix).ok());
        let base = address.filter(|address| !address.is_zero());
        parsed.options.show_values = base.is_some();
        // A word that is neither a field nor an expression is still tried
        // as a pattern, which reports that nothing matches it.
        if address.is_none()
            && let Some(text) = address_text
        {
            patterns.insert(0, text);
        }

        let body = if let Some(list_path) = parsed.options.list_field.as_ref() {
            self.dt_list(
                type_info.as_ref(),
                base,
                list_path,
                &parsed.options,
                &patterns,
            )
        } else if let Some(base) = base {
            let mut path_patterns = Vec::new();
            let mut glob_patterns = Vec::new();
            let had_patterns = !patterns.is_empty();
            for pattern in patterns {
                if !pattern.contains('*') && !pattern.contains('?') && pattern.contains('.') {
                    match parse_field_path(&pattern) {
                        Ok(path) => path_patterns.push(path),
                        Err(_) => glob_patterns.push(pattern),
                    }
                } else {
                    glob_patterns.push(pattern);
                }
            }
            let mut entries: Vec<DtEntry> = path_patterns
                .iter()
                .map(|path| {
                    self.resolved_path_entry(type_info.as_ref(), base, path, &parsed.options)
                })
                .collect();
            if !glob_patterns.is_empty() || !had_patterns {
                entries.extend(self.struct_entries(
                    type_info.as_ref(),
                    base,
                    &parsed.options,
                    &glob_patterns,
                    parsed.options.recursive_depth,
                ));
            }
            DtBody::Fields(entries)
        } else {
            DtBody::Fields(self.struct_entries(
                type_info.as_ref(),
                VirtAddr(0),
                &parsed.options,
                &patterns,
                parsed.options.recursive_depth,
            ))
        };
        let dump = DtDump {
            type_name: type_info.name.clone(),
            size: type_info.size,
            address: base.map(|address| address.0),
            body,
        };
        print_dt(&dump);
        Ok(())
    }

    /// `dt -l`: the records of the list `list_path` links, from `head`,
    /// each with its fields.
    fn dt_list(
        &self,
        type_info: &TypeInfo,
        head: Option<VirtAddr>,
        list_path: &[String],
        options: &DtOptions,
        patterns: &[String],
    ) -> DtBody {
        let Some(head) = head else {
            return DtBody::Failed("dt -l requires a nonzero list head address".to_string());
        };
        let resolved = match self.resolve_field_path(type_info, list_path) {
            Ok(path) => path,
            Err(error) => {
                return DtBody::Failed(format!("dt -l {}: {}", list_path.join("."), error));
            }
        };
        let (link_offset, next_offset, pointer_size) = match self.list_offsets(&resolved) {
            Ok(offsets) => offsets,
            Err(error) => {
                return DtBody::Failed(format!("dt -l {}: {}", list_path.join("."), error));
            }
        };
        let (records, termination) =
            self.collect_typed_list(head, link_offset, next_offset, pointer_size);
        DtBody::List {
            records: records
                .into_iter()
                .map(|record| {
                    (
                        record.0,
                        self.struct_entries(
                            type_info,
                            record,
                            options,
                            patterns,
                            options.recursive_depth,
                        ),
                    )
                })
                .collect(),
            stop: termination
                .diagnostic()
                .map(|stop| format!("dt -l {}: list walk stopped: {stop}", list_path.join("."))),
        }
    }

    fn dl(
        &mut self,
        DlArgs {
            backward,
            positional,
        }: DlArgs,
    ) -> Result<()> {
        let Some(address) = self.eval_or_report(&positional[0]) else {
            return Ok(());
        };
        let limit = match self.eval_or_report(&positional[1]) {
            Some(count) => count.0.min(MAX_LIST_ENTRIES as u64) as usize,
            None => return Ok(()),
        };
        let display_words = match positional.get(2) {
            Some(size) => match self.eval_or_report(size) {
                Some(size) if size.0 > 0 => size.0.min(MAX_DL_WORDS as u64) as usize,
                Some(_) => {
                    error!("dl size must be greater than zero");
                    return Ok(());
                }
                None => return Ok(()),
            },
            None => 2,
        };
        let mut cursor = ListCursor::from_first(address, limit);
        let arch = self.ctx.target.arch();
        let pointer = arch.pointer_size() as usize;
        let mut bytes = [0u8; MAX_DL_WORDS * 8];
        while let Some(current) = cursor.take_current() {
            let read_words = display_words.max(2);
            let width = read_words * pointer;
            if let Err(error) = self.ctx.read_masked(current, &mut bytes[..width]) {
                outln!("{}: <unavailable: {}>", ui::addr(current.0), error);
                cursor.advance(Err(error.to_string()));
                continue;
            }
            let first = arch.decode_pointer(&bytes).0;
            let second = arch.decode_pointer(&bytes[pointer..]).0;
            let words = (0..display_words)
                .map(|index| {
                    let word = &bytes[index * pointer..(index + 1) * pointer];
                    format!("{:#x}", le_uint(word))
                })
                .collect::<Vec<_>>();
            outln!("{}  {}", ui::addr(current.0), words.join(" "));
            let next = if backward { second } else { first };
            cursor.advance(Ok(VirtAddr(next)));
        }
        match cursor.finish() {
            // A closed ring or the requested count is the normal stop, and an
            // unreadable link was already reported against its address.
            ListTermination::Head | ListTermination::Bound | ListTermination::Corrupt(_) => {}
            stop => {
                if let Some(stop) = stop.diagnostic() {
                    outln!("dl: list walk stopped: {stop}");
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::bytes::write_u64;
    use crate::base::output::capture;
    use crate::session::{Session, session_over_memory};

    fn list_session(last_next: u64) -> Session {
        // A _LIST_ENTRY ring: head at 0x1000, records linked at 0x1020 and
        // 0x1040, with the last Flink under test.
        let mut memory = [0u8; 0x80];
        for (offset, value) in [
            (0x00, 0x1020u64),
            (0x08, 0x1040),
            (0x20, 0x1040),
            (0x28, 0x1000),
            (0x40, last_next),
            (0x48, 0x1020),
        ] {
            write_u64(&mut memory, offset, value);
        }
        session_over_memory(0x1000, &memory)
    }

    #[test]
    fn dt_renders_each_value_kind_in_windbg_form() {
        let mut memory = [0u8; 0x80];
        memory[0] = 0x2a;
        memory[1] = 0b1000_0001;
        write_u64(&mut memory, 0x08, 0x1000);
        memory[0x10..0x13].copy_from_slice(b"abc");
        write_u64(&mut memory, 0x20, 0x1040);
        write_u64(&mut memory, 0x28, 0x1000);
        let mut session = session_over_memory(0x1000, &memory);
        let dtb = session.target.current_dtb();
        session.target.symbols.set_kernel(Some(1), dtb);
        let fields = [
            (
                "Value".to_string(),
                FieldInfo {
                    offset: 0,
                    size: 1,
                    type_data: ParsedType::Primitive("UCHAR".to_string()),
                },
            ),
            (
                "Busy".to_string(),
                FieldInfo {
                    offset: 1,
                    size: 1,
                    type_data: ParsedType::Bitfield {
                        underlying: Box::new(ParsedType::Primitive("UCHAR".to_string())),
                        pos: 0,
                        len: 1,
                    },
                },
            ),
            (
                "Next".to_string(),
                FieldInfo {
                    offset: 8,
                    size: 8,
                    type_data: ParsedType::Pointer(Box::new(ParsedType::Struct(
                        "_NODE".to_string(),
                    ))),
                },
            ),
            (
                "Name".to_string(),
                FieldInfo {
                    offset: 0x10,
                    size: 3,
                    type_data: ParsedType::Array(
                        Box::new(ParsedType::Primitive("UCHAR".to_string())),
                        3,
                    ),
                },
            ),
            (
                "Links".to_string(),
                FieldInfo {
                    offset: 0x20,
                    size: 0x10,
                    type_data: ParsedType::Struct("_LIST_ENTRY".to_string()),
                },
            ),
        ];
        session.target.symbols.inject_module_for_test(
            1,
            vec![TypeInfo {
                name: "_NODE".to_string(),
                pointer_size: 8,
                size: 0x30,
                fields: fields.into_iter().collect(),
            }],
            &[],
        );

        let mut state = ReplState::for_oneshot(&mut session);
        let (result, text) = capture(|| state.dispatch_line("dt _NODE 1000"));
        result.unwrap();

        for expected in [
            "+0x000 Value : UCHAR = 0x2a",
            "+0x001 Busy : UCHAR : 1 @ bit 0 = Y",
            "+0x008 Next : _NODE* = 0x1000",
            "+0x010 Name : UCHAR[3] = \"abc\"",
            "+0x020 Links : _LIST_ENTRY = [ 0x1040 - 0x1000 ]",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in {text}");
        }

        // No PDB describes `_LIST_ENTRY` here, so the path resolves through
        // its ABI layout.
        let (result, text) = capture(|| state.dispatch_line("dt _NODE 1000 Links.blink"));
        result.unwrap();
        assert!(
            text.contains("+0x028 Links.blink : <?>* = 0x1000"),
            "{text}"
        );
    }

    #[test]
    fn dt_reads_a_word_that_names_a_field_as_a_field_in_either_order() {
        let mut memory = [0u8; 0x10];
        memory[0] = 0x11;
        memory[4..8].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        let mut session = session_over_memory(0x1000, &memory);
        let dtb = session.target.current_dtb();
        session.target.symbols.set_kernel(Some(1), dtb);
        let field = |offset, size, name: &str| FieldInfo {
            offset,
            size,
            type_data: ParsedType::Primitive(name.to_string()),
        };
        session.target.symbols.inject_module_for_test(
            1,
            vec![TypeInfo {
                name: "_HDR".to_string(),
                pointer_size: 8,
                size: 8,
                fields: [
                    // `Cafe` also evaluates, as the number 0xcafe.
                    ("Cafe".to_string(), field(0, 1, "UCHAR")),
                    ("Value".to_string(), field(4, 4, "ULONG")),
                ]
                .into_iter()
                .collect(),
            }],
            &[],
        );
        let mut state = ReplState::for_oneshot(&mut session);

        let (result, text) = capture(|| state.dispatch_line("dt _HDR Cafe"));
        result.unwrap();
        assert!(text.contains("+0x000 Cafe : UCHAR"), "{text}");
        assert!(!text.contains("Value"), "the layout, filtered: {text}");

        for line in ["dt _HDR Value 1000", "dt _HDR 1000 Value"] {
            let (result, text) = capture(|| state.dispatch_line(line));
            result.unwrap();
            assert!(
                text.contains("+0x004 Value : ULONG = 0x12345678"),
                "{line}: {text}"
            );
            assert!(!text.contains("Cafe"), "{line}: {text}");
        }
    }

    #[test]
    fn dl_keeps_the_last_node_and_reports_how_the_walk_ended() {
        for (next, expected) in [
            (0x1000u64, None),
            (0x1020, Some("cycle")),
            (0, Some("null")),
        ] {
            let mut session = list_session(next);
            let mut state = ReplState::for_oneshot(&mut session);
            let (result, text) = capture(|| state.dispatch_line("dl 1000 8"));
            result.unwrap();
            assert!(
                text.contains("0000000000001040"),
                "last node omitted: {text}"
            );
            match expected {
                Some(note) => assert!(text.contains(note), "missing {note} diagnostic: {text}"),
                None => assert!(!text.contains("stopped"), "unexpected diagnostic: {text}"),
            }
        }
    }

    #[test]
    fn typed_list_walks_every_node_from_either_entry_address() {
        // Closed ring: the two records plus the head as a pseudo-record,
        // whichever address the walk starts from. No record is dropped.
        let mut session = list_session(0x1000);
        let state = ReplState::for_oneshot(&mut session);
        let (records, termination) = state.collect_typed_list(VirtAddr(0x1020), 0x10, 0x10, 8);
        assert_eq!(
            records,
            vec![VirtAddr(0x1010), VirtAddr(0x1030), VirtAddr(0x0ff0)]
        );
        assert_eq!(termination, ListTermination::Head);
        let (records, termination) = state.collect_typed_list(VirtAddr(0x1000), 0x10, 0x10, 8);
        assert_eq!(
            records,
            vec![VirtAddr(0x0ff0), VirtAddr(0x1010), VirtAddr(0x1030)]
        );
        assert_eq!(termination, ListTermination::Head);

        // Headless ring: both records, and the wrap is not corruption.
        let mut session = list_session(0x1020);
        let state = ReplState::for_oneshot(&mut session);
        let (records, termination) = state.collect_typed_list(VirtAddr(0x1020), 0x10, 0x10, 8);
        assert_eq!(records, vec![VirtAddr(0x1010), VirtAddr(0x1030)]);
        assert_eq!(termination, ListTermination::Head);

        // A null link and an unreadable link both keep what was collected.
        let mut session = list_session(0);
        let state = ReplState::for_oneshot(&mut session);
        let (records, termination) = state.collect_typed_list(VirtAddr(0x1020), 0x10, 0x10, 8);
        assert_eq!(records, vec![VirtAddr(0x1010), VirtAddr(0x1030)]);
        assert_eq!(termination, ListTermination::Null);

        let mut session = list_session(0x8000);
        let state = ReplState::for_oneshot(&mut session);
        let (records, termination) = state.collect_typed_list(VirtAddr(0x1020), 0x10, 0x10, 8);
        assert_eq!(
            records,
            vec![VirtAddr(0x1010), VirtAddr(0x1030), VirtAddr(0x7ff0)]
        );
        assert!(matches!(termination, ListTermination::Corrupt(_)));
    }

    #[test]
    fn a_nested_list_link_is_offset_from_the_record_start() {
        let mut session = session_over_memory(0x1000, &[0u8; 0x10]);
        let dtb = session.target.current_dtb();
        session.target.symbols.set_kernel(Some(1), dtb);
        let layout = |name: &str, field: &str, offset, type_name: &str| TypeInfo {
            name: name.to_string(),
            pointer_size: 8,
            size: 0x40,
            fields: [(
                field.to_string(),
                FieldInfo {
                    offset,
                    size: 0x10,
                    type_data: ParsedType::Struct(type_name.to_string()),
                },
            )]
            .into_iter()
            .collect(),
        };
        session.target.symbols.inject_module_for_test(
            1,
            vec![
                layout("_OUTER", "Inner", 0x10, "_INNER"),
                layout("_INNER", "Links", 0x8, "_LIST_ENTRY"),
            ],
            &[],
        );
        let state = ReplState::for_oneshot(&mut session);
        let outer = state.lookup_type("_OUTER").unwrap();

        // Naming the entry and naming its Flink find the same link.
        for path in ["Inner.Links", "Inner.Links.Flink"] {
            let path: Vec<String> = parse_field_path(path).unwrap();
            let resolved = state.resolve_field_path(&outer, &path).unwrap();
            assert_eq!(state.list_offsets(&resolved), Ok((0x18, 0x18, 8)));
        }
    }

    #[test]
    fn field_path_parser_accepts_dotted_names_and_rejects_empty_segments() {
        assert_eq!(
            parse_field_path("ActiveProcessLinks.Flink").unwrap(),
            vec!["ActiveProcessLinks", "Flink"]
        );
        assert_eq!(parse_field_path("Pcb.Header.Type").unwrap().len(), 3);
        assert!(parse_field_path(".Flink").is_err());
        assert!(parse_field_path("Flink.").is_err());
        assert!(parse_field_path("Links..Flink").is_err());
    }
}
