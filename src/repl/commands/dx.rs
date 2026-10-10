//! `dx`: a typed expression's value and its fields, laid out as WinDbg's
//! `dx` lays them out, and the debugger data model (`dx_model`) with its
//! queries (`dx_query`); NatVis is not supported.

use std::sync::Arc;

use crate::error::{Error, Result};
use crate::expr::{Expr, ExprValue, NumberRadix};
use crate::layout::{
    ParsedType, TypeInfo, abi_layout, bitfield_value, is_signed_primitive, named_type,
    nested_layout_name, utf16le_lossy, windbg_type_name,
};
use crate::types::VirtAddr;
use crate::typeview::TypeView;

use super::dx_model::{self as model, ModelValue};
use super::dx_query;
use super::types::MAX_RECURSION_DEPTH;
use crate::repl::*;

repl_command! {
    cmd_dx;
    names: ["dx"],
    usage: "dx [-r<depth>] [-g] <expression>[, d | , <count>]",
    summary: "Show a typed expression's value and its fields.",
    details: "Evaluates an expression with casts, ->, ., [] and *, such as dx -r1 (*((nt!_IO_STACK_LOCATION *)0xffff...)) or dx ((nt!_EPROCESS*)@rcx)->UniqueProcessId, and shows its value with its type, then its fields -r levels deep (1 by default, -r0 for the value alone), following a pointer to a structure to the structure. Types read as in WinDbg (unsigned long, _EPROCESS *), and a cast takes them as WinDbg writes them, such as (unsigned long *). A pointer to a number shows the number it points to, a char or wchar_t pointer its string, and a function pointer the function. Numbers are decimal unless written with 0x, as in C++. @$proc, @$thread, @$teb and @$peb are typed pointers. The debugger data model's objects read as in WinDbg: Debugger.Sessions, @$cursession, @$curprocess, and @$curthread, a session's Processes (indexed by process ID), a process's Name, Id, Threads (indexed by thread ID), Modules (indexed from 0), and Io.Handles (indexed by handle, each with its Type and Object), a thread's Id, and a module's Name, BaseAddress, and Size. KernelObject is the typed _EPROCESS or _ETHREAD, which reads on as a typed expression: dx @$curprocess.KernelObject.Pcb. A collection takes .Count() and the queries Where, Select, SelectMany, First, Last, Any, All, OrderBy, OrderByDescending, Take, and Skip with lambdas, as in dx @$cursession.Processes.Where(p => p.Name.Contains(\"svchost\")).Select(p => new { p.Name, p.Id }), and Debugger.Utility.Collections.FromListEntry(head, \"nt!_EPROCESS\", \"ActiveProcessLinks\") walks a kernel list. -g shows a collection as a grid, and a format after the expression lists more elements than 100 (, 500) or shows the model's numbers in decimal (, d). NatVis views (such as a driver object's) are not supported. -nv is accepted as in WinDbg.",
    completion: Expression,
}

/// The elements `dx` lists of an array or a collection before its `[...]`
/// line.
const MAX_DX_ELEMENTS: u32 = 100;

/// The longest string `dx` reads for a `char *`, a `wchar_t *` or a
/// `_UNICODE_STRING`, in characters.
const MAX_DX_STRING: usize = 2048;

/// The width `dx` pads a name to before its value.
const NAME_WIDTH: usize = 16;

/// The widest a `dx -g` cell gets before it is cut short.
const MAX_GRID_CELL: usize = 48;

/// What `dx` was asked: its depth (`-r<n>`, 1 without it), whether to show
/// a collection as a grid (`-g`), the expression, and the format after it.
#[derive(Debug, PartialEq)]
struct DxArgs<'a> {
    depth: usize,
    grid: bool,
    text: &'a str,
    format: DxFormat,
}

/// A format specifier after the expression: `, d` shows the data model's
/// integers and keys in decimal, and `, <count>` lists that many elements
/// of a collection rather than [`MAX_DX_ELEMENTS`].
#[derive(Debug, Default, PartialEq)]
struct DxFormat {
    decimal: bool,
    limit: Option<usize>,
}

/// `dx`'s options and expression. `-nv` and `-v` change nothing here; any
/// other option is refused by name. A `-` followed by a digit starts the
/// expression.
fn parse_dx_args(raw: &str) -> std::result::Result<DxArgs<'_>, String> {
    let mut depth = 1;
    let mut grid = false;
    let mut rest = raw.trim_start();
    while let Some(option) = rest.strip_prefix('-') {
        if option.starts_with(|ch: char| ch.is_ascii_digit()) {
            break;
        }
        let end = option.find(char::is_whitespace).unwrap_or(option.len());
        let (flag, after) = option.split_at(end);
        match flag {
            "nv" | "v" => {}
            "g" => grid = true,
            _ if flag.starts_with('r') => {
                let digits = &flag[1..];
                depth = if digits.is_empty() {
                    1
                } else {
                    digits
                        .parse()
                        .map_err(|_| format!("'-{flag}' takes a depth, as in -r2"))?
                };
            }
            _ => {
                return Err(format!(
                    "option '-{flag}' is not supported; dx takes -r<depth>, -g, and -nv"
                ));
            }
        }
        rest = after.trim_start();
    }
    let (text, format) = split_format(rest.trim_end())?;
    Ok(DxArgs {
        depth: depth.min(MAX_RECURSION_DEPTH),
        grid,
        text,
        format,
    })
}

/// The expression and its format specifier: the text after the last comma
/// outside brackets and strings.
fn split_format(text: &str) -> std::result::Result<(&str, DxFormat), String> {
    let mut nesting = 0i32;
    let mut quoted = false;
    let mut comma = None;
    for (index, ch) in text.char_indices() {
        match ch {
            '"' => quoted = !quoted,
            '(' | '[' | '{' if !quoted => nesting += 1,
            ')' | ']' | '}' if !quoted => nesting -= 1,
            ',' if !quoted && nesting == 0 => comma = Some(index),
            _ => {}
        }
    }
    let Some(comma) = comma else {
        return Ok((text, DxFormat::default()));
    };
    let spec = text[comma + 1..].trim();
    let mut format = DxFormat::default();
    match spec {
        "d" => format.decimal = true,
        "x" => {}
        _ => {
            let count = match spec.strip_prefix("0x") {
                Some(hex) => usize::from_str_radix(hex, 16).ok(),
                None => spec.parse().ok(),
            };
            format.limit = Some(count.ok_or_else(|| {
                format!(
                    "format specifier ', {spec}' is not supported; dx takes , d, , x, and an \
                     element count"
                )
            })?);
        }
    }
    Ok((text[..comma].trim_end(), format))
}

/// One line of `dx` output and the lines under it.
#[derive(Debug, Clone, Default, PartialEq)]
struct DxLine {
    /// `[+0x1f0]`, or `[+0x1f0 ( 3: 0)]` for a bitfield; `None` for the
    /// root, an array element and a pointer's target.
    offset: Option<String>,
    /// The expression, the field, `[index]`; `None` for a pointer's target,
    /// which shows its value alone.
    name: Option<String>,
    /// The value, or why it can't be read.
    value: Option<String>,
    /// `None` for an untyped number and for memory that can't be read.
    type_name: Option<String>,
    /// Whether the value has lines under it in WinDbg (a structure, an
    /// array, a pointer that isn't null), which pads the root's name.
    expandable: bool,
    children: Vec<DxLine>,
}

/// The root line: an expandable value's name stands apart from its value,
/// a scalar's pads to the name column.
fn root_text(line: &DxLine) -> String {
    let name = line.name.as_deref().unwrap_or_default();
    let mut text = if line.expandable {
        format!("{name} {:NAME_WIDTH$}", "")
    } else {
        format!("{name:<NAME_WIDTH$}")
    };
    match (&line.value, line.expandable) {
        (Some(value), true) => text.push_str(&format!(": {value}")),
        (Some(value), false) => text.push_str(&format!(" : {value}")),
        (None, _) => {}
    }
    if let Some(type_name) = &line.type_name {
        if line.value.is_some() || !line.expandable {
            text.push(' ');
        }
        text.push_str(&format!("[Type: {type_name}]"));
    }
    text
}

/// A line under the root, `indent` spaces in.
fn child_text(line: &DxLine, indent: usize) -> String {
    let mut text = " ".repeat(indent);
    if let Some(offset) = &line.offset {
        text.push_str(offset);
        text.push(' ');
    }
    match &line.name {
        Some(name) => {
            text.push_str(&format!("{name:<NAME_WIDTH$}"));
            if let Some(value) = &line.value {
                text.push_str(&format!(" : {value}"));
            }
        }
        None => text.push_str(line.value.as_deref().unwrap_or_default()),
    }
    if let Some(type_name) = &line.type_name {
        text.push_str(&format!(" [Type: {type_name}]"));
    }
    text
}

fn print_dx(root: &DxLine) {
    outln!("{}", root_text(root));
    print_dx_children(&root.children, 4);
    outln!();
}

/// A collection as a grid (`dx -g`): a row for each element, a column for
/// each of their fields. A value whose elements have no fields shows as
/// `dx` shows it.
fn print_dx_grid(root: &DxLine) {
    let mut columns: Vec<&str> = Vec::new();
    for row in &root.children {
        for cell in &row.children {
            if let Some(name) = cell.name.as_deref()
                && !columns.contains(&name)
            {
                columns.push(name);
            }
        }
    }
    if columns.is_empty() {
        print_dx(root);
        return;
    }
    let cell_text = |cell: &DxLine| {
        let mut text = cell
            .value
            .clone()
            .or_else(|| {
                cell.type_name
                    .as_ref()
                    .map(|name| format!("[Type: {name}]"))
            })
            .unwrap_or_default();
        if text.chars().count() > MAX_GRID_CELL {
            text = text.chars().take(MAX_GRID_CELL - 3).collect::<String>() + "...";
        }
        text
    };
    let mut rows = vec![
        std::iter::once(String::new())
            .chain(columns.iter().map(|name| name.to_string()))
            .collect::<Vec<_>>(),
    ];
    for row in &root.children {
        let mut cells = vec![row.name.clone().unwrap_or_default()];
        cells.extend(columns.iter().map(|column| {
            row.children
                .iter()
                .find(|cell| cell.name.as_deref() == Some(column))
                .map(cell_text)
                .unwrap_or_default()
        }));
        rows.push(cells);
    }
    let widths: Vec<usize> = (0..=columns.len())
        .map(|column| {
            rows.iter()
                .map(|row| row[column].chars().count())
                .max()
                .unwrap_or(0)
        })
        .collect();
    outln!(
        "{}",
        root_text(&DxLine {
            children: Vec::new(),
            ..root.clone()
        })
    );
    for row in rows {
        let line = row
            .iter()
            .zip(&widths)
            .map(|(cell, width)| format!("{cell:<width$}"))
            .collect::<Vec<_>>()
            .join("  ");
        outln!("    {}", line.trim_end());
    }
    outln!();
}

fn print_dx_children(lines: &[DxLine], indent: usize) {
    for line in lines {
        outln!("{}", child_text(line, indent));
        print_dx_children(&line.children, indent + 4);
    }
}

/// `[+0x1f0]`, or for a bitfield its bits, high to low: `[+0x1f0 (14:12)]`.
fn offset_text(offset: u64, type_data: &ParsedType) -> String {
    match type_data {
        ParsedType::Bitfield { pos, len, .. } => {
            let high = u16::from(*pos) + u16::from(*len).max(1) - 1;
            format!("[+0x{offset:03x} ({high:2}:{pos:2})]")
        }
        _ => format!("[+0x{offset:03x}]"),
    }
}

/// A number as `dx` writes it: a signed type in decimal, an unsigned one
/// in hex, a character with the character after it when it prints.
fn number_text(raw: u64, name: &str, size: usize) -> String {
    let signed = |raw: u64| match size {
        1 => raw as i8 as i64,
        2 => raw as i16 as i64,
        4 => raw as i32 as i64,
        _ => raw as i64,
    };
    match name {
        "CHAR" => {
            let value = raw as u8 as i8;
            match value as u8 {
                0x20..=0x7e => format!("{value} '{}'", value as u8 as char),
                _ => value.to_string(),
            }
        }
        "WCHAR" => {
            let value = raw as u16;
            match char::from_u32(u32::from(value)).filter(|ch| !ch.is_control()) {
                Some(ch) => format!("{value} '{ch}'"),
                None => value.to_string(),
            }
        }
        "bool" => (raw != 0).to_string(),
        "float" => f32::from_bits(raw as u32).to_string(),
        "double" => f64::from_bits(raw).to_string(),
        _ if is_signed_primitive(name) => signed(raw).to_string(),
        _ => format!("{raw:#x}"),
    }
}

fn unreadable(address: VirtAddr) -> String {
    format!("Unable to read memory at Address {:#x}", address.0)
}

/// Where a value is: in memory, or held as a number (a register, a cast).
#[derive(Clone, Copy)]
enum Place {
    Memory(VirtAddr),
    Value(u64),
}

impl ReplState<'_> {
    fn cmd_dx(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let args = match parse_dx_args(invocation.raw_tail) {
            Ok(parsed) => parsed,
            Err(message) => {
                error!("dx: {message}");
                return Ok(());
            }
        };
        let text = args.text;
        if text.is_empty() {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        }
        // A grid shows each element's fields, so it reads two levels.
        let depth = if args.grid {
            args.depth.max(2)
        } else {
            args.depth
        };
        let root = if dx_query::is_query(text) {
            match dx_query::evaluate(&self.ctx.target, text) {
                // A typed result fails as a typed expression does.
                Ok(ModelValue::Typed(expression)) => self.dx_typed(text, &expression, depth),
                Ok(value) => Ok(self.dx_model_line(text, &value, depth, &args.format)),
                Err(error) => Err(error),
            }
        } else {
            self.dx_typed(text, text, depth)
        };
        match root {
            Ok(root) if args.grid => print_dx_grid(&root),
            Ok(root) => print_dx(&root),
            Err(error) => error!("dx: {error}"),
        }
        Ok(())
    }

    /// The `dx` tree of the typed expression `expression`, named `name`.
    fn dx_typed(&self, name: &str, expression: &str, depth: usize) -> Result<DxLine> {
        let expr = Expr::parse_with_radix(expression, NumberRadix::Decimal)?;
        let value = expr.evaluate(&self.ctx.target)?;
        self.dx_root(name, &expr, &value, depth)
    }

    /// The `dx` tree of a data model value named `name`: its summary, then
    /// `depth` levels of its properties or a collection's elements. A typed
    /// value, such as a `KernelObject` property, is its typed tree.
    fn dx_model_line(
        &self,
        name: &str,
        value: &ModelValue,
        depth: usize,
        format: &DxFormat,
    ) -> DxLine {
        let target = &self.ctx.target;
        let failed = |error: Error| DxLine {
            name: Some(name.to_string()),
            value: Some(error.to_string()),
            ..DxLine::default()
        };
        match value {
            ModelValue::Typed(expression) => {
                return self
                    .dx_typed(name, expression, depth)
                    .unwrap_or_else(failed);
            }
            // A handle's object is its typed header, with the object's name
            // and the object itself before the header's fields.
            ModelValue::ObjectHeader { header, .. } => {
                let expression = format!("(*((nt!_OBJECT_HEADER *){:#x}))", header.0);
                let mut line = match self.dx_typed(name, &expression, depth) {
                    Ok(line) => line,
                    Err(error) => return failed(error),
                };
                if depth > 0 {
                    let extra =
                        model::properties(value)
                            .into_iter()
                            .map(|property| match model::property(target, value, &property) {
                                Ok(child) => {
                                    self.dx_model_line(&property, &child, depth - 1, format)
                                }
                                Err(error) => DxLine {
                                    name: Some(property),
                                    value: Some(error.to_string()),
                                    ..DxLine::default()
                                },
                            });
                    line.children.splice(0..0, extra);
                }
                return line;
            }
            _ => {}
        }
        let collection = model::is_collection(value);
        let properties = model::properties(value);
        let mut line = DxLine {
            name: Some(name.to_string()),
            value: model::summary(target, value, format.decimal),
            expandable: collection || !properties.is_empty(),
            ..DxLine::default()
        };
        if depth == 0 {
            return line;
        }
        if collection {
            match model::elements(target, value) {
                Ok(elements) => {
                    let limit = format.limit.unwrap_or(MAX_DX_ELEMENTS as usize);
                    let more = elements.len() > limit;
                    for (key, element) in elements.into_iter().take(limit) {
                        let key = model::int_text(i128::from(key), true, format.decimal);
                        line.children.push(self.dx_model_line(
                            &format!("[{key}]"),
                            &element,
                            depth - 1,
                            format,
                        ));
                    }
                    if more {
                        line.children.push(DxLine {
                            name: Some("[...]".to_string()),
                            ..DxLine::default()
                        });
                    }
                }
                Err(error) => line.children.push(DxLine {
                    value: Some(error.to_string()),
                    ..DxLine::default()
                }),
            }
            return line;
        }
        for property in properties {
            let child = match model::property(target, value, &property) {
                Ok(child) => self.dx_model_line(&property, &child, depth - 1, format),
                Err(error) => DxLine {
                    name: Some(property),
                    value: Some(error.to_string()),
                    ..DxLine::default()
                },
            };
            line.children.push(child);
        }
        line
    }

    /// The `dx` tree of `value`, the result of `expr`, written `text`.
    fn dx_root(&self, text: &str, expr: &Expr, value: &ExprValue, depth: usize) -> Result<DxLine> {
        let view = TypeView::new(self.ctx);
        let (place, type_data, byte_size) = match value {
            ExprValue::Memory {
                address,
                type_data,
                byte_size,
            } => (Place::Memory(*address), type_data.clone(), *byte_size),
            ExprValue::Register {
                value,
                type_data,
                byte_size,
                ..
            }
            | ExprValue::Immediate {
                value,
                type_data,
                byte_size,
            } => (Place::Value(value.0), type_data.clone(), *byte_size),
            // A register is an `unsigned __int64` in WinDbg's C++
            // expressions; any other untyped number is an integer, which
            // `dx` writes in decimal.
            ExprValue::Raw { value, .. } => {
                if matches!(expr, Expr::Register(_)) {
                    (
                        Place::Value(value.0),
                        ParsedType::Primitive("ULONGLONG".to_string()),
                        Some(8),
                    )
                } else {
                    return Ok(DxLine {
                        name: Some(text.to_string()),
                        value: Some((value.0 as i64).to_string()),
                        ..DxLine::default()
                    });
                }
            }
            ExprValue::Unavailable { reason, .. } => {
                return Err(Error::InvalidExpression(reason.clone()));
            }
        };
        if let Place::Value(_) = place
            && matches!(
                type_data,
                ParsedType::Struct(_) | ParsedType::Union(_) | ParsedType::Array(..)
            )
        {
            return Err(Error::InvalidExpression(format!(
                "{} is held in a register and has no fields to read",
                windbg_type_name(&type_data)
            )));
        }
        let size = byte_size
            .and_then(|size| usize::try_from(size).ok())
            .filter(|size| *size != 0)
            .unwrap_or_else(|| view.parsed_type_size(&type_data));
        let mut root = self.dx_line(&view, place, &type_data, size, depth);
        root.name = Some(text.to_string());
        Ok(root)
    }

    /// The line for a value of `type_data`, `size` bytes at `place`, and
    /// `depth` levels of lines under it; the caller names it.
    fn dx_line(
        &self,
        view: &TypeView<'_>,
        place: Place,
        type_data: &ParsedType,
        size: usize,
        depth: usize,
    ) -> DxLine {
        let mut line = DxLine {
            type_name: Some(windbg_type_name(type_data)),
            ..DxLine::default()
        };
        match type_data {
            ParsedType::Struct(_) | ParsedType::Union(_) => {
                line.expandable = true;
                let Place::Memory(address) = place else {
                    return line;
                };
                // `_UNICODE_STRING` reads as its text in WinDbg through a
                // NatVis view; `dx` keeps the text `dt` shows.
                if named_type(type_data, "_UNICODE_STRING") {
                    line.value = Some(self.dx_unicode_string(view, address, type_data));
                }
                if depth > 0 {
                    line.children = self.dx_fields(view, address, type_data, depth);
                }
            }
            ParsedType::Array(element, count) => {
                line.expandable = true;
                let Place::Memory(address) = place else {
                    return line;
                };
                // A character array reads as its string, with no elements.
                if let ParsedType::Primitive(name) = element.as_ref()
                    && matches!(name.as_str(), "CHAR" | "WCHAR")
                {
                    let unit = if name == "CHAR" { 1 } else { 2 };
                    let bytes = (*count as usize)
                        .saturating_mul(unit)
                        .min(MAX_DX_STRING * 2);
                    line.value = Some(match view.read_display_bytes(address, bytes) {
                        Ok(bytes) => format!("\"{}\"", decode_string(&bytes, unit)),
                        Err(_) => unreadable(address),
                    });
                    return line;
                }
                if depth > 0 {
                    line.children = self.dx_elements(view, address, type_data, size, depth);
                }
            }
            _ => {
                let raw = match place {
                    Place::Value(raw) => raw,
                    Place::Memory(address) => match view.read_display_uint(address, size) {
                        Ok(raw) => raw,
                        Err(_) => {
                            line.value = Some(unreadable(address));
                            line.type_name = None;
                            return line;
                        }
                    },
                };
                self.dx_scalar(view, &mut line, raw, type_data, size, depth);
            }
        }
        line
    }

    /// A scalar's value, and for a pointer what it points to.
    fn dx_scalar(
        &self,
        view: &TypeView<'_>,
        line: &mut DxLine,
        raw: u64,
        type_data: &ParsedType,
        size: usize,
        depth: usize,
    ) {
        match type_data {
            ParsedType::Primitive(name) if name == "void" => {}
            ParsedType::Primitive(name) => line.value = Some(number_text(raw, name, size)),
            ParsedType::Enum(name) => line.value = Some(self.dx_enum(view, name, raw, size)),
            ParsedType::Bitfield {
                underlying,
                pos,
                len,
            } => {
                let bits = bitfield_value(raw, *pos, *len);
                line.value = Some(match underlying.as_ref() {
                    ParsedType::Enum(name) => self.dx_enum(view, name, bits, size),
                    ParsedType::Primitive(name) if is_signed_primitive(name) => bits.to_string(),
                    _ => format!("{bits:#x}"),
                });
            }
            ParsedType::Pointer(pointee) => {
                self.dx_pointer(view, line, raw, pointee, depth);
            }
            _ => line.value = Some(format!("{raw:#x}")),
        }
    }

    /// A pointer's value with what WinDbg says about its target after it
    /// (the number, string or function there), and the target as the line
    /// under it: a structure's fields, or the value it points to.
    fn dx_pointer(
        &self,
        view: &TypeView<'_>,
        line: &mut DxLine,
        raw: u64,
        pointee: &ParsedType,
        depth: usize,
    ) {
        let mut value = format!("{raw:#x}");
        let target = VirtAddr(raw);
        match pointee {
            ParsedType::Function(..) => {
                // A function pointer names its function, even when null.
                line.expandable = true;
                let function = self.dx_function(target);
                value.push_str(&format!(
                    " : {}",
                    function.as_deref().unwrap_or(&value.clone())
                ));
                if raw != 0 && depth > 0 {
                    line.children.push(DxLine {
                        value: Some(function.unwrap_or_else(|| format!("{raw:#x}"))),
                        type_name: Some(windbg_type_name(pointee)),
                        ..DxLine::default()
                    });
                }
            }
            _ if raw == 0 => {}
            ParsedType::Primitive(name) if name == "void" => {}
            ParsedType::Primitive(_) | ParsedType::Enum(_) | ParsedType::Pointer(_) => {
                line.expandable = true;
                let size = view.parsed_type_size(pointee);
                let target_line = self.dx_line(
                    view,
                    Place::Memory(target),
                    pointee,
                    size,
                    depth.saturating_sub(1),
                );
                let description = match pointee {
                    ParsedType::Primitive(name) if matches!(name.as_str(), "CHAR" | "WCHAR") => {
                        let unit = if name == "CHAR" { 1 } else { 2 };
                        Some(self.dx_c_string(view, target, unit))
                    }
                    ParsedType::Pointer(_) => None,
                    _ => target_line.value.clone(),
                };
                if let Some(description) = description {
                    value.push_str(&format!(" : {description}"));
                }
                if depth > 0 {
                    line.children.push(target_line);
                }
            }
            ParsedType::Struct(_) | ParsedType::Union(_) => {
                line.expandable = true;
                if depth > 0 {
                    line.children = self.dx_fields(view, target, pointee, depth);
                }
            }
            _ => line.expandable = true,
        }
        line.value = Some(value);
    }

    /// The fields of the structure `type_data` at `address`, in the order
    /// the PDB declares them, each `depth - 1` levels deep. A type no PDB
    /// describes has none, as in WinDbg.
    fn dx_fields(
        &self,
        view: &TypeView<'_>,
        address: VirtAddr,
        type_data: &ParsedType,
        depth: usize,
    ) -> Vec<DxLine> {
        let Some(layout) = nested_layout_name(type_data).and_then(|name| {
            view.lookup_type(&name)
                .or_else(|| abi_layout(&name).map(Arc::new))
        }) else {
            return Vec::new();
        };
        self.dx_layout_fields(view, address, &layout, depth)
    }

    fn dx_layout_fields(
        &self,
        view: &TypeView<'_>,
        address: VirtAddr,
        layout: &TypeInfo,
        depth: usize,
    ) -> Vec<DxLine> {
        layout
            .fields
            .iter()
            .map(|(name, field)| {
                let offset = u64::from(field.offset);
                let mut line = self.dx_line(
                    view,
                    Place::Memory(address + offset),
                    &field.type_data,
                    view.field_size(field),
                    depth - 1,
                );
                line.offset = Some(offset_text(offset, &field.type_data));
                line.name = Some(name.clone());
                line
            })
            .collect()
    }

    /// The elements of `array`, the first [`MAX_DX_ELEMENTS`] and then
    /// `[...]`.
    fn dx_elements(
        &self,
        view: &TypeView<'_>,
        address: VirtAddr,
        array: &ParsedType,
        size: usize,
        depth: usize,
    ) -> Vec<DxLine> {
        let ParsedType::Array(element, count) = array else {
            return Vec::new();
        };
        let (element, count) = (element.as_ref(), *count);
        let Some(stride) = view.element_stride(size, element, count) else {
            return Vec::new();
        };
        let mut lines: Vec<DxLine> = (0..count.min(MAX_DX_ELEMENTS))
            .map(|index| {
                let element_address = address + u64::from(index) * stride as u64;
                let mut line = self.dx_line(
                    view,
                    Place::Memory(element_address),
                    element,
                    stride,
                    depth - 1,
                );
                line.name = Some(format!("[{index}]"));
                line
            })
            .collect();
        if count > MAX_DX_ELEMENTS {
            lines.push(DxLine {
                name: Some("[...]".to_string()),
                type_name: Some(windbg_type_name(array)),
                ..DxLine::default()
            });
        }
        lines
    }

    /// `NonPagedPoolNx (512)`, or the number alone when no name has it.
    fn dx_enum(&self, view: &TypeView<'_>, name: &str, raw: u64, size: usize) -> String {
        let value = match size {
            1 => raw as i8 as i64,
            2 => raw as i16 as i64,
            4 => raw as i32 as i64,
            _ => raw as i64,
        };
        view.lookup_enum(name)
            .and_then(|variants| variants.into_iter().find(|(_, known)| *known == value))
            .map_or_else(
                || value.to_string(),
                |(variant, _)| format!("{variant} ({value})"),
            )
    }

    /// `mouclass!MouseAddDevice+0x0`: the function at `address`, written
    /// with its offset even when it is zero, as `dx` does.
    fn dx_function(&self, address: VirtAddr) -> Option<String> {
        self.ctx
            .target
            .symbols
            .find_closest_symbol_for_address(self.ctx.target.current_dtb(), address)
            .map(|(module, name, offset)| format!("{module}!{name}+{offset:#x}"))
    }

    /// The NUL-terminated string of `unit`-byte characters at `address`,
    /// quoted, read a page at a time so a string that ends just before an
    /// unmapped page still reads.
    fn dx_c_string(&self, view: &TypeView<'_>, address: VirtAddr, unit: usize) -> String {
        let mut bytes = Vec::new();
        let mut cursor = address;
        while bytes.len() < MAX_DX_STRING * unit {
            let to_page_end = 0x1000 - (cursor.0 & 0xfff) as usize;
            let Ok(chunk) = view.read_display_bytes(cursor, to_page_end) else {
                if bytes.is_empty() {
                    return unreadable(address);
                }
                break;
            };
            bytes.extend_from_slice(&chunk);
            if chunk
                .chunks_exact(unit)
                .any(|ch| ch.iter().all(|byte| *byte == 0))
            {
                break;
            }
            cursor += to_page_end as u64;
        }
        format!("\"{}\"", decode_string(&bytes, unit))
    }

    /// A `_UNICODE_STRING`'s text, quoted: `Length` bytes at `Buffer`.
    fn dx_unicode_string(
        &self,
        view: &TypeView<'_>,
        address: VirtAddr,
        type_data: &ParsedType,
    ) -> String {
        let Some(layout) = nested_layout_name(type_data).and_then(|name| {
            view.lookup_type(&name)
                .or_else(|| abi_layout(&name).map(Arc::new))
        }) else {
            return String::new();
        };
        let read = |name: &str| {
            let field = layout.fields.get(name)?;
            view.read_display_uint(address + u64::from(field.offset), view.field_size(field))
                .ok()
        };
        let (Some(length), Some(buffer)) = (read("Length"), read("Buffer")) else {
            return unreadable(address);
        };
        let length = (length as usize).min(MAX_DX_STRING * 2) & !1;
        if length == 0 || buffer == 0 {
            return "\"\"".to_string();
        }
        match view.read_display_bytes(VirtAddr(buffer), length) {
            Ok(bytes) => format!("\"{}\"", utf16le_lossy(&bytes)),
            Err(_) => unreadable(VirtAddr(buffer)),
        }
    }
}

/// The text of `bytes`, characters of `unit` bytes (1 or 2), up to the first
/// NUL, as written, without escapes, as `dx` shows it.
fn decode_string(bytes: &[u8], unit: usize) -> String {
    if unit == 2 {
        let end = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .position(|ch| *ch == [0, 0])
            .map_or(bytes.len(), |index| index * 2);
        utf16le_lossy(&bytes[..end])
    } else {
        let end = bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.len());
        String::from_utf8_lossy(&bytes[..end]).into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `-r<n>` sets the depth (1 without it, and for a bare `-r`), `-g` asks
    /// for a grid, `-nv` changes nothing, a `-` before a digit begins the
    /// expression, and any other option is refused by name rather than read
    /// as the expression.
    #[test]
    fn dx_options_set_the_depth_and_leave_the_expression() {
        let parsed = |raw| parse_dx_args(raw).map(|args| (args.depth, args.grid, args.text));
        assert_eq!(
            parsed(" -r2 -nv (*((nt!_EPROCESS *)0x10)) "),
            Ok((2, false, "(*((nt!_EPROCESS *)0x10))"))
        );
        assert_eq!(parsed("@$proc"), Ok((1, false, "@$proc")));
        assert_eq!(parsed("-r0 @$thread"), Ok((0, false, "@$thread")));
        assert_eq!(parsed("-r @rcx"), Ok((1, false, "@rcx")));
        assert_eq!(parsed("-1 + 2"), Ok((1, false, "-1 + 2")));
        assert_eq!(
            parsed("-g @$cursession.Processes"),
            Ok((1, true, "@$cursession.Processes"))
        );
        assert!(parsed("-h @$curprocess").is_err_and(|message| message.contains("'-h'")));
    }

    /// The format follows the last comma outside brackets and strings: a
    /// comma inside a query's arguments or a string is the expression's.
    #[test]
    fn dx_formats_follow_the_last_top_level_comma() {
        let parsed = |raw| parse_dx_args(raw).map(|args| (args.text, args.format));
        assert_eq!(
            parsed("@$cursession.Processes, d"),
            Ok((
                "@$cursession.Processes",
                DxFormat {
                    decimal: true,
                    limit: None
                }
            ))
        );
        assert_eq!(
            parsed("@$cursession.Processes, 0x200"),
            Ok((
                "@$cursession.Processes",
                DxFormat {
                    decimal: false,
                    limit: Some(0x200)
                }
            ))
        );
        let query = "Debugger.Utility.Collections.FromListEntry(h, \"a,b\", \"c\")";
        assert_eq!(parsed(query), Ok((query, DxFormat::default())));
        assert!(parsed("@$curprocess, su").is_err_and(|message| message.contains("', su'")));
    }

    /// Values read as kd.exe's `dx` writes them on the same dump: signed
    /// types in decimal, a printable character after its code, unsigned
    /// types in hex, and a bitfield's bits high to low beside its offset.
    #[test]
    fn dx_numbers_and_bitfield_offsets_follow_windbg() {
        assert_eq!(number_text(0x80, "CHAR", 1), "-128");
        assert_eq!(number_text(8, "CHAR", 1), "8");
        assert_eq!(number_text(65, "CHAR", 1), "65 'A'");
        assert_eq!(number_text(67, "WCHAR", 2), "67 'C'");
        assert_eq!(number_text(0x103, "LONG", 4), "259");
        assert_eq!(number_text(0xffff_fffb, "INT", 4), "-5");
        assert_eq!(
            number_text(0x1dd_555d_e893_46ad, "LONGLONG", 8),
            "134357425713268397"
        );
        assert_eq!(number_text(0xd000, "ULONG", 4), "0xd000");
        assert_eq!(number_text(0x53, "UCHAR", 1), "0x53");

        let bits = |pos, len| ParsedType::Bitfield {
            underlying: Box::new(ParsedType::Primitive("ULONG".to_string())),
            pos,
            len,
        };
        assert_eq!(offset_text(0x1f0, &bits(0, 1)), "[+0x1f0 ( 0: 0)]");
        assert_eq!(offset_text(0x1f0, &bits(12, 3)), "[+0x1f0 (14:12)]");
        assert_eq!(offset_text(0x6a0, &bits(0, 61)), "[+0x6a0 (60: 0)]");
        assert_eq!(
            offset_text(0x1150, &ParsedType::Primitive("ULONG".to_string())),
            "[+0x1150]"
        );
    }

    /// The root's name stands 17 spaces from an expandable value and pads to
    /// 16 before a scalar's; a line under it pads its name to 16.
    #[test]
    fn dx_lines_pad_as_windbg_does() {
        let line = |name: &str, value: Option<&str>, type_name: Option<&str>, expandable| DxLine {
            name: Some(name.to_string()),
            value: value.map(str::to_string),
            type_name: type_name.map(str::to_string),
            expandable,
            ..DxLine::default()
        };
        assert_eq!(
            root_text(&line(
                "@$thread",
                Some("0xffff9888a3f4e080"),
                Some("_ETHREAD *"),
                true
            )),
            "@$thread                 : 0xffff9888a3f4e080 [Type: _ETHREAD *]"
        );
        assert_eq!(
            root_text(&line(
                "*(nt!_LIST_ENTRY *)0x1000",
                None,
                Some("_LIST_ENTRY"),
                true
            )),
            "*(nt!_LIST_ENTRY *)0x1000                 [Type: _LIST_ENTRY]"
        );
        assert_eq!(
            root_text(&line("(char)65", Some("65 'A'"), Some("char"), false)),
            "(char)65         : 65 'A' [Type: char]"
        );
        assert_eq!(
            root_text(&line("10 + 0x10", Some("26"), None, false)),
            "10 + 0x10        : 26"
        );
        let mut field = line(
            "Flink",
            Some("Unable to read memory at Address 0x1000"),
            None,
            false,
        );
        field.offset = Some("[+0x000]".to_string());
        assert_eq!(
            child_text(&field, 4),
            "    [+0x000] Flink            : Unable to read memory at Address 0x1000"
        );
        let target = DxLine {
            value: Some("0xf".to_string()),
            type_name: Some("unsigned __int64".to_string()),
            ..DxLine::default()
        };
        assert_eq!(child_text(&target, 4), "    0xf [Type: unsigned __int64]");
    }
}
