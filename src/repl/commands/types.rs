use std::borrow::Cow;
use std::sync::Arc;

use crate::error::Result;
use crate::expr::Expr;
use crate::layout::{
    FieldInfo, ParsedType, TypeInfo, abi_layout, find_field, le_uint, named_type,
    nested_layout_name, unqualified_type_name,
};
use crate::symbols::glob_matches;
use crate::target::{ListCursor, ListTermination, UserVar};
use crate::types::VirtAddr;
use crate::typeview::{MAX_ARRAY_ELEMENTS, TypeView};
use crate::ui;

use crate::repl::*;

const MAX_LIST_ENTRIES: usize = 4096;
const MAX_RECURSION_DEPTH: usize = 64;
const MAX_DL_WORDS: usize = 64;

repl_command! {
    cmd_dt;
    names: ["dt"],
    usage: "dt [-r[N]] [-a[N]] [-v] [-y] [-l <field>] [module!]<type> [address] [field-pattern...]",
    summary: "Display a type layout or decoded structure.",
    details: "-r expands nested structures, -a expands bounded arrays, -v shows field sizes, -y uses case-insensitive prefix matching, and -l walks a LIST_ENTRY field.",
    completion: Type,
}

repl_command! {
    cmd_dl;
    names: ["dl"],
    usage: "dl [-b] <address> <maxcount> [size]",
    summary: "Dump a bounded _LIST_ENTRY chain.",
    details: "The default walk follows Flink; -b follows Blink. The optional size is the number of pointer-sized words displayed per element (default 2).",
    completion: Expression,
}

repl_command! {
    cmd_list_command;
    names: ["!list"],
    usage: "!list -t [module!]<type>.<field> -x \"<commands>\" <address>",
    summary: "Run commands for every element of a typed LIST_ENTRY chain.",
    details: "The element address is available as $extret, @extret, or @$extret in each command. Walks stop at the head, repeated links, or 4096 elements.",
    completion: Expression,
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
    address_text: Option<String>,
    field_patterns: Vec<String>,
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
        .map_err(|_| format!("invalid {} depth `{}`", prefix, suffix))?;
    Ok(value.min(MAX_RECURSION_DEPTH))
}

fn parse_array_option(arg: &str) -> std::result::Result<usize, String> {
    let suffix = &arg[2..];
    if suffix.is_empty() {
        return Ok(MAX_ARRAY_ELEMENTS);
    }
    let value = suffix
        .parse::<usize>()
        .map_err(|_| format!("invalid -a count `{}`", suffix))?;
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

    let Some(type_name) = positional.first().cloned() else {
        return Err("missing type name".to_string());
    };
    Ok(ParsedDtArgs {
        type_name,
        address_text: positional.get(1).cloned(),
        field_patterns: positional.into_iter().skip(2).collect(),
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
    if patterns.is_empty() {
        return true;
    }
    patterns.iter().any(|pattern| {
        if prefix_match {
            name.to_ascii_lowercase()
                .starts_with(&pattern.to_ascii_lowercase())
        } else {
            glob_matches(pattern, name, true)
        }
    })
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

    fn field_descriptor(
        &self,
        indent: usize,
        name: &str,
        field: &FieldInfo,
        options: &DtOptions,
    ) -> String {
        let prefix = " ".repeat(indent);
        let type_name = field.type_data.to_string();
        // WinDbg pads a field offset to three hex digits and lets wider
        // offsets grow naturally (`+0x000`, `+0x2e0`, `+0x1150`), so a layout
        // dump lines up with the reference output people compare against and
        // with anything grepping for `+0x000 `.
        if options.verbose {
            format!(
                "{prefix}+0x{:03x} {name} : {type_name} [size {}]",
                field.offset,
                self.type_view().field_size(field)
            )
        } else {
            format!("{prefix}+0x{:03x} {name} : {type_name}", field.offset)
        }
    }

    fn print_field_value(
        &self,
        address: VirtAddr,
        field: &FieldInfo,
        label: &str,
        options: &DtOptions,
        indent: usize,
        depth: usize,
    ) {
        match &field.type_data {
            // A nested layout prints its own fields rather than a value, but
            // the two Windows aggregates `TypeView` renders as text do not.
            ParsedType::Struct(type_name) | ParsedType::Union(type_name)
                if !named_type(&field.type_data, "_UNICODE_STRING")
                    && !named_type(&field.type_data, "_LIST_ENTRY") =>
            {
                outln!("{}", label);
                if depth > 0 {
                    if let Some(type_info) = self.lookup_type(type_name) {
                        self.print_struct_fields(
                            type_info.as_ref(),
                            address,
                            options,
                            &[],
                            depth.saturating_sub(1),
                            indent + 2,
                        );
                    } else {
                        outln!(
                            "{}<unavailable: type {} not found>",
                            " ".repeat(indent + 2),
                            type_name
                        );
                    }
                }
            }
            // An array prints its elements, unless it is an inline C string.
            ParsedType::Array(_, _) if field.type_data.c_string_len().is_none() => {
                outln!("{}", label);
                self.print_array_elements(
                    address,
                    field,
                    options,
                    indent + 2,
                    depth.saturating_sub(1),
                );
            }
            // Everything else has a text value: scalars, enums, bitfields,
            // `_UNICODE_STRING`, `_LIST_ENTRY` and C-string arrays.
            _ => {
                if options.show_values {
                    outln!(
                        "{} = {}",
                        label,
                        self.type_view().value_text(address, field)
                    );
                } else {
                    outln!("{}", label);
                }
            }
        }
    }

    fn print_array_elements(
        &self,
        address: VirtAddr,
        field: &FieldInfo,
        options: &DtOptions,
        indent: usize,
        depth: usize,
    ) {
        let ParsedType::Array(inner, count) = &field.type_data else {
            return;
        };
        let max_elements = options
            .array_limit
            .unwrap_or(MAX_ARRAY_ELEMENTS)
            .min(MAX_ARRAY_ELEMENTS);
        let count_usize = *count as usize;
        let shown = count_usize.min(max_elements);
        if shown == 0 {
            return;
        }
        let total_size = self.type_view().field_size(field);
        let Some(element_size) = self.type_view().element_stride(total_size, inner, *count) else {
            outln!(
                "{}[array elements unavailable: element size is unknown]",
                " ".repeat(indent)
            );
            return;
        };

        for index in 0..shown {
            let element_address = address + (index.saturating_mul(element_size)) as u64;
            let element_field = FieldInfo {
                offset: 0,
                size: element_size as u64,
                type_data: inner.as_ref().clone(),
            };
            let prefix = " ".repeat(indent);
            self.print_field_value(
                element_address,
                &element_field,
                &format!("{}[{}] : {}", prefix, index, inner),
                options,
                indent,
                depth.max(1),
            );
        }
        if shown < count_usize {
            outln!(
                "{}... {} array elements omitted",
                " ".repeat(indent),
                count_usize - shown
            );
        }
    }

    fn print_struct_fields(
        &self,
        type_info: &TypeInfo,
        base: VirtAddr,
        options: &DtOptions,
        patterns: &[String],
        depth: usize,
        indent: usize,
    ) {
        for (name, field) in type_info.fields_in_order() {
            if !field_matches(name, patterns, options.prefix_match) {
                continue;
            }
            let address = base + field.offset as u64;
            let descriptor = self.field_descriptor(indent, name, field, options);
            self.print_field_value(address, field, &descriptor, options, indent, depth);
        }
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
                return Err(format!("field `{requested_name}` not found"));
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
                    return Err(format!("nested type `{next_type_name}` not found"));
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
                    return Err(format!("field `{}` points to null", component.name));
                }
                current = VirtAddr(pointer);
                offset = 0;
            } else {
                current = field_address;
            }
        }
        Err("field path is empty".to_string())
    }

    fn print_resolved_path(
        &self,
        root: &TypeInfo,
        base: VirtAddr,
        path: &[String],
        options: &DtOptions,
    ) {
        let resolved = match self.resolve_field_path(root, path) {
            Ok(path) => path,
            Err(error) => {
                error!("{}: {}", path.join("."), error);
                return;
            }
        };
        let (address, field) = match self.runtime_field_address(base, &resolved) {
            Ok(value) => value,
            Err(error) => {
                outln!("  {} : <unavailable: {}>", path.join("."), error);
                return;
            }
        };
        let descriptor = self.field_descriptor(2, &path.join("."), &field, options);
        self.print_field_value(
            address,
            &field,
            &descriptor,
            options,
            2,
            options.recursive_depth.max(1),
        );
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
            return Ok((entry_offset, entry_offset, 8));
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

    fn cmd_dt(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let mut parsed = match parse_dt_args(&invocation.argv) {
            Ok(parsed) => parsed,
            Err(error) => {
                if error == "missing type name" {
                    outln!("{}\n", command_help("dt"));
                } else {
                    error!("dt: {}", error);
                }
                return Ok(());
            }
        };
        let type_info = match self.lookup_type(&parsed.type_name) {
            Some(type_info) => type_info,
            None => {
                if let Some(variants) = self.lookup_enum(&parsed.type_name) {
                    outln!(
                        "enum {} ({} values)",
                        unqualified_type_name(&parsed.type_name),
                        variants.len()
                    );
                    for (name, value) in variants {
                        outln!("  {:#x}  {}", value, name);
                    }
                    outln!();
                } else {
                    error!(
                        "failed to get type information: type `{}` not found",
                        parsed.type_name
                    );
                }
                return Ok(());
            }
        };

        let address = parsed
            .address_text
            .as_deref()
            .and_then(|text| Expr::eval_with_radix(text, &self.ctx.target, self.radix).ok());
        let base = address.filter(|address| !address.is_zero());
        parsed.options.show_values = base.is_some();
        let patterns = if parsed.address_text.is_some() && address.is_some() {
            parsed.field_patterns.clone()
        } else if let Some(address_text) = parsed.address_text {
            let mut all = Vec::with_capacity(parsed.field_patterns.len() + 1);
            all.push(address_text);
            all.extend(parsed.field_patterns);
            all
        } else {
            parsed.field_patterns.clone()
        };

        outln!(
            "{} ({} bytes){}",
            type_info.name,
            type_info.size,
            base.map(|address| format!(" @ {}", ui::addr(address.0)))
                .unwrap_or_default()
        );

        if let Some(list_path) = parsed.options.list_field.as_ref() {
            let Some(head) = base else {
                error!("dt -l requires a nonzero list head address");
                return Ok(());
            };
            let resolved = match self.resolve_field_path(type_info.as_ref(), list_path) {
                Ok(path) => path,
                Err(error) => {
                    error!("dt -l {}: {}", list_path.join("."), error);
                    return Ok(());
                }
            };
            let (link_offset, next_offset, pointer_size) = match self.list_offsets(&resolved) {
                Ok(offsets) => offsets,
                Err(error) => {
                    error!("dt -l {}: {}", list_path.join("."), error);
                    return Ok(());
                }
            };
            let (records, termination) =
                self.collect_typed_list(head, link_offset, next_offset, pointer_size);
            for record in records {
                outln!("{} @ {}", type_info.name, ui::addr(record.0));
                self.print_struct_fields(
                    type_info.as_ref(),
                    record,
                    &parsed.options,
                    &patterns,
                    parsed.options.recursive_depth,
                    2,
                );
            }
            if let Some(stop) = termination.diagnostic() {
                outln!("dt -l {}: list walk stopped: {stop}", list_path.join("."));
            }
            return Ok(());
        }

        if let Some(base) = base {
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
            for path in path_patterns {
                self.print_resolved_path(type_info.as_ref(), base, &path, &parsed.options);
            }
            if !glob_patterns.is_empty() || !had_patterns {
                self.print_struct_fields(
                    type_info.as_ref(),
                    base,
                    &parsed.options,
                    &glob_patterns,
                    parsed.options.recursive_depth,
                    2,
                );
            }
        } else {
            self.print_struct_fields(
                type_info.as_ref(),
                VirtAddr(0),
                &parsed.options,
                &patterns,
                parsed.options.recursive_depth,
                2,
            );
        }
        outln!();
        Ok(())
    }

    fn cmd_dl(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let mut positional = Vec::new();
        let mut backward = false;
        for arg in &invocation.argv {
            if arg.as_ref() == "-b" {
                backward = true;
            } else {
                positional.push(arg.as_ref());
            }
        }
        if positional.len() < 2 || positional.len() > 3 {
            outln!("{}\n", command_help("dl"));
            return Ok(());
        }
        let Some(address) = self.eval_or_report(positional[0]) else {
            return Ok(());
        };
        let limit = match self.eval_or_report(positional[1]) {
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
        let mut bytes = [0u8; MAX_DL_WORDS * 8];
        while let Some(current) = cursor.take_current() {
            let read_words = display_words.max(2);
            let width = read_words * 8;
            if let Err(error) = self.ctx.read_masked(current, &mut bytes[..width]) {
                outln!("{}: <unavailable: {}>", ui::addr(current.0), error);
                cursor.advance(Err(error.to_string()));
                continue;
            }
            let first = le_uint(&bytes[..8]);
            let second = le_uint(&bytes[8..16]);
            let words = (0..display_words)
                .map(|index| format!("{:#x}", le_uint(&bytes[index * 8..index * 8 + 8])))
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

    fn cmd_list_command(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let mut type_field = None;
        let mut commands = None;
        let mut positional = Vec::new();
        let mut index = 0;
        while index < invocation.argv.len() {
            match invocation.arg(index).unwrap_or_default() {
                "-t" => {
                    let Some(value) = invocation.arg(index + 1) else {
                        error!("!list: missing type after -t");
                        return Ok(());
                    };
                    type_field = Some(value.to_string());
                    index += 2;
                }
                "-x" => {
                    let Some(value) = invocation.arg(index + 1) else {
                        error!("!list: missing commands after -x");
                        return Ok(());
                    };
                    commands = Some(value.to_string());
                    index += 2;
                }
                arg if arg.starts_with('-') => {
                    error!("!list: unknown option `{arg}`");
                    return Ok(());
                }
                arg => {
                    positional.push(arg.to_string());
                    index += 1;
                }
            }
        }
        let Some(type_field) = type_field else {
            outln!("{}\n", command_help("!list"));
            return Ok(());
        };
        let Some(commands) = commands else {
            outln!("{}\n", command_help("!list"));
            return Ok(());
        };
        let Some(address_text) = positional.first() else {
            outln!("{}\n", command_help("!list"));
            return Ok(());
        };
        if positional.len() > 1 {
            error!("!list accepts one list head address");
            return Ok(());
        }
        let Some((type_name, field_name)) = type_field.rsplit_once('.') else {
            error!("!list -t expects [module!]<type>.<field>");
            return Ok(());
        };
        let path = match parse_field_path(field_name) {
            Ok(path) => path,
            Err(error) => {
                error!("!list: {}", error);
                return Ok(());
            }
        };
        let type_info = match self.lookup_type(type_name) {
            Some(type_info) => type_info,
            None => {
                error!("!list: type `{}` not found", type_name);
                return Ok(());
            }
        };
        let head = match self.eval_or_report(address_text) {
            Some(address) if !address.is_zero() => address,
            Some(_) => {
                error!("!list requires a nonzero list head address");
                return Ok(());
            }
            None => return Ok(()),
        };
        let resolved = match self.resolve_field_path(type_info.as_ref(), &path) {
            Ok(path) => path,
            Err(error) => {
                error!("!list -t {}: {}", type_field, error);
                return Ok(());
            }
        };
        let (link_offset, next_offset, pointer_size) = match self.list_offsets(&resolved) {
            Ok(offsets) => offsets,
            Err(error) => {
                error!("!list -t {}: {}", type_field, error);
                return Ok(());
            }
        };
        let (records, termination) =
            self.collect_typed_list(head, link_offset, next_offset, pointer_size);
        let command = commands.replace("@$extret", "@extret");
        for record in records {
            self.ctx.target.user_vars.insert(
                "extret".to_string(),
                UserVar {
                    value: record.0,
                    source: "!list element".to_string(),
                },
            );
            match self.dispatch_line(&command) {
                Ok(Flow::Quit) => break,
                Ok(Flow::Continue | Flow::Denied) => {}
                Err(error) => {
                    error!("!list command failed at {}: {}", ui::addr(record.0), error);
                    break;
                }
            }
        }
        if let Some(stop) = termination.diagnostic() {
            outln!("!list: list walk stopped: {stop}");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::write_u64;
    use crate::output::capture;
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
