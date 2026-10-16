//! The registry (`!reg`): the hives loaded in kernel memory, and keys and
//! values read from them.

use std::fmt::Display;

use tabled::builder::Builder;

use ntoseye_macros::{command, grammar};

use crate::error::{Error, Result};
use crate::repl::args::{ArgCursor, ArgCx, ArgError};
use crate::repl::*;
use crate::session::Session;
use crate::target::DiagnosticValue;
use crate::target::registry::{
    CellLocation, DataStorage, HiveList, RegData, RegKey, RegValue, key_flag_names, names_equal,
    value_type_name,
};
use crate::triage_report::time::filetime_to_iso;
use crate::types::VirtAddr;
use crate::ui;

/// The most characters of a string, and bytes of binary data, a value
/// list shows.
const PREVIEW_CHARS: usize = 96;
const PREVIEW_BYTES: usize = 32;

/// A labeled line of a detail view.
fn field(label: &str, value: impl Display) {
    outln!("{} {value}", ui::label(&format!("{label:<12}")));
}

/// A FILETIME as UTC to the second, or muted `never` for zero.
fn written(filetime: u64) -> String {
    if filetime == 0 {
        return ui::muted("never");
    }
    match filetime_to_iso(filetime) {
        Some(iso) => iso.trim_end_matches('Z').replace('T', " "),
        None => format!("{filetime:#x}"),
    }
}

fn type_text(value_type: u32) -> String {
    value_type_name(value_type).map_or_else(|| format!("{value_type:#x}"), str::to_string)
}

fn value_name(name: &str) -> String {
    if name.is_empty() {
        "(Default)".to_string()
    } else {
        name.to_string()
    }
}

/// `text` with its control characters escaped, so it stays on one line.
fn one_line(text: &str) -> String {
    text.chars()
        .flat_map(|ch| {
            if ch.is_control() {
                ch.escape_default().collect::<Vec<_>>()
            } else {
                vec![ch]
            }
        })
        .collect()
}

/// `text`, cut to `PREVIEW_CHARS` with how long it was.
fn preview_text(text: &str, truncated: &mut bool) -> String {
    let count = text.chars().count();
    if count <= PREVIEW_CHARS {
        return text.to_string();
    }
    *truncated = true;
    let head: String = text.chars().take(PREVIEW_CHARS).collect();
    format!("{head}... {}", ui::muted(&format!("({count} characters)")))
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

/// A value's data as the value list shows it: numbers in hex and decimal,
/// strings and bytes cut short.
fn data_preview(value: &RegValue, truncated: &mut bool) -> String {
    let data = match value.decoded() {
        DiagnosticValue::Available(data) => data,
        DiagnosticValue::Unavailable(_) => return ui::muted("(does not read; see below)"),
    };
    match data {
        RegData::Text(text) => preview_text(&one_line(&text), truncated),
        RegData::Strings(strings) => {
            let joined = strings
                .iter()
                .map(|string| one_line(string))
                .collect::<Vec<_>>()
                .join("\\0");
            preview_text(&joined, truncated)
        }
        RegData::Number(number) => format!("{number:#x} ({number})"),
        RegData::Bytes(bytes) if bytes.len() > PREVIEW_BYTES => {
            *truncated = true;
            format!(
                "{}... {}",
                hex_bytes(&bytes[..PREVIEW_BYTES]),
                ui::muted(&format!("({:#x} bytes)", bytes.len()))
            )
        }
        RegData::Bytes(bytes) => hex_bytes(&bytes),
    }
}

/// Every byte, 16 to a line with their offset and ASCII.
fn print_hex_dump(bytes: &[u8]) {
    for (line, chunk) in bytes.chunks(16).enumerate() {
        let (hex, text) = hex_ascii_row(chunk, HexCase::Upper);
        outln!("  {:06x}  {hex:<47}  {text}", line * 16);
    }
}

fn print_hives(list: &HiveList) {
    let mut builder = Builder::default();
    builder.push_record(["Hive", "Stable", "Volatile", "Mount point", "File"]);
    let mut problems = Vec::new();
    for entry in &list.hives {
        match entry {
            Ok(hive) => {
                let file = match (&hive.file, &hive.base_block_name) {
                    (Some(file), _) => file.clone(),
                    (None, Some(name)) => ui::muted(&format!("{name} (base block)")),
                    (None, None) if hive.master => ui::muted("(master hive)"),
                    (None, None) => ui::muted("(in memory only)"),
                };
                builder.push_record([
                    ui::addr(hive.address.0),
                    format!("{:#x}", hive.stable.length),
                    format!("{:#x}", hive.volatile.length),
                    hive.mount
                        .clone()
                        .unwrap_or_else(|| ui::muted("(not mounted)")),
                    file,
                ]);
            }
            Err((address, error)) => {
                problems.push(format!("hive {}: {error}", ui::addr(address.0)))
            }
        }
    }
    if list.hives.is_empty() {
        outln!("{}\n", ui::muted("no hives are loaded"));
    } else {
        print_padded_table(builder);
    }
    for problem in problems {
        outln!("{}", ui::muted(&problem));
    }
    if let Some(stopped) = &list.stopped {
        outln!("{}", ui::muted(&format!("(hive list stopped: {stopped})")));
    }
}

fn print_key_header(key: &RegKey) {
    field("Key", &key.path);
    for link in &key.links {
        field("Link", format!("{} -> {}", link.from, link.to));
    }
    field("Hive", ui::addr(key.hive.0));
    match key.cell {
        Some(cell) => field(
            "Key node",
            format!("{}  cell {cell:#x}", ui::addr(key.node.0)),
        ),
        None => field("Key node", ui::addr(key.node.0)),
    }
    let flags = key_flag_names(key.flags);
    if !flags.is_empty() {
        field("Flags", flags.join(" "));
    }
    field("Last write", written(key.last_write));
}

fn print_key(key: &RegKey, command: &str) {
    print_key_header(key);
    outln!();

    let readable = key.subkeys.iter().flatten().count();
    outln!(
        "{}",
        ui::label(&format!(
            "{} of {} subkeys",
            readable,
            key.subkey_count.max(key.subkeys.len() as u32)
        ))
    );
    if readable > 0 {
        let mut builder = Builder::default();
        builder.push_record(["Key node", "Last write", "Subkeys", "Values", "Name"]);
        for subkey in key.subkeys.iter().flatten() {
            let mut name = subkey.name.clone();
            let flags = key_flag_names(subkey.flags);
            if flags.contains(&"KEY_SYM_LINK") {
                name.push_str(&ui::muted(" (symbolic link)"));
            }
            if flags.contains(&"KEY_HIVE_EXIT") {
                name.push_str(&ui::muted(" (hive mounted here)"));
            }
            builder.push_record([
                ui::addr(subkey.node.0),
                written(subkey.last_write),
                subkey.subkeys.to_string(),
                subkey.values.to_string(),
                name,
            ]);
        }
        print_padded_table(builder);
    } else {
        outln!();
    }
    for (_, error) in key.subkeys.iter().filter_map(|entry| entry.as_ref().err()) {
        outln!("{}", ui::muted(&format!("subkey {error}")));
    }

    let readable = key.values.iter().flatten().count();
    outln!(
        "{}",
        ui::label(&format!(
            "{} of {} values",
            readable,
            key.value_count.max(key.values.len() as u32)
        ))
    );
    let mut truncated = false;
    if readable > 0 {
        let mut builder = Builder::default();
        builder.push_record(["Type", "Name", "Data"]);
        for value in key.values.iter().flatten() {
            builder.push_record([
                type_text(value.value_type),
                value_name(&value.name),
                data_preview(value, &mut truncated),
            ]);
        }
        print_padded_table(builder);
    } else {
        outln!();
    }
    for value in key.values.iter().flatten() {
        if let DiagnosticValue::Unavailable(error) = &value.data {
            outln!(
                "{}",
                ui::muted(&format!(
                    "value {}: its {:#x} bytes of data do not read: {error}",
                    value_name(&value.name),
                    value.length
                ))
            );
        }
    }
    for (_, error) in key.values.iter().filter_map(|entry| entry.as_ref().err()) {
        outln!("{}", ui::muted(&format!("value {error}")));
    }
    for problem in &key.problems {
        outln!("{}", ui::muted(problem));
    }
    if truncated {
        outln!(
            "{}",
            ui::muted(&format!(
                "(data cut short; {command} <path> -v <value> shows a value in full)"
            ))
        );
    }
    outln!();
}

fn print_value(key: &RegKey, value: &RegValue) {
    print_key_header(key);
    outln!();
    field("Value", value_name(&value.name));
    field("Type", type_text(value.value_type));
    let storage = match value.storage {
        DataStorage::Inline => "in the value record",
        DataStorage::Cell => "in a cell",
        DataStorage::Big => "in big data segments",
    };
    field("Length", format!("{:#x} bytes, {storage}", value.length));
    field(
        "Value node",
        format!("{}  cell {:#x}", ui::addr(value.node.0), value.cell),
    );
    let bytes = match &value.data {
        DiagnosticValue::Available(bytes) => bytes,
        DiagnosticValue::Unavailable(error) => {
            error!("its data does not read: {error}");
            return;
        }
    };
    match RegData::decode(value.value_type, bytes) {
        RegData::Text(text) => field("Data", text),
        RegData::Strings(strings) => {
            field("Data", format!("{} strings", strings.len()));
            for (index, string) in strings.iter().enumerate() {
                outln!("  [{index}] {string}");
            }
        }
        RegData::Number(number) => field("Data", format!("{number:#x} ({number})")),
        RegData::Bytes(_) => {}
    }
    outln!();
    print_hex_dump(bytes);
    outln!();
}

fn print_cell(location: &CellLocation) {
    field(
        "Cell",
        format!(
            "{:#x} ({})  hive {}",
            location.cell,
            if location.volatile {
                "volatile"
            } else {
                "stable"
            },
            ui::addr(location.hive.0)
        ),
    );
    match &location.map {
        Some(map) => {
            field(
                "Map",
                format!(
                    "directory {}, table {}, offset {:#x}",
                    map.directory, map.table, map.offset
                ),
            );
            field(
                "Map entry",
                format!("{}  block {}", ui::addr(map.entry.0), ui::addr(map.block.0)),
            );
        }
        None => field("Map", "none: a flat hive, read from its base block"),
    }
    field(
        "Address",
        format!(
            "{}  data at {}",
            ui::addr(location.address.0),
            ui::addr(location.address.0 + 4)
        ),
    );
    match &location.size {
        DiagnosticValue::Available(size) if *size < 0 => {
            field("Size", format!("{:#x}, in use", size.unsigned_abs()))
        }
        DiagnosticValue::Available(size) => field("Size", format!("{size:#x}, free")),
        DiagnosticValue::Unavailable(error) => {
            field("Size", ui::muted(&format!("does not read: {error}")))
        }
    }
    outln!();
}

/// What `!reg` was asked for.
pub enum RegRequest {
    Hives,
    /// `querykey` (or `q`, `command` names it) of `path`, or of its value
    /// `value`.
    Query {
        command: String,
        path: String,
        value: Option<String>,
    },
    KeyAt {
        hive: VirtAddr,
        node: VirtAddr,
    },
    Cell {
        hive: VirtAddr,
        cell: u32,
    },
}

/// `!reg`'s subcommand and its arguments.
#[grammar(
    usage = "hivelist | querykey|q <path> [-v <value>] | keyinfo <hive> <knode> | cellindex <hive> <cell>",
    complete = [None, RegistryKey]
)]
fn reg_request(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<RegRequest, ArgError> {
    let message = |text: String| ArgError::Message(text);
    let subcommand = cursor.word().ok_or(ArgError::Missing)?.into_owned();
    match subcommand.to_ascii_lowercase().as_str() {
        "hivelist" => Ok(RegRequest::Hives),
        "querykey" | "q" => {
            let command = format!("!reg {subcommand}");
            let mut path = Vec::new();
            let mut value = None;
            while let Some(word) = cursor.word() {
                if word == "-v" {
                    let Some(name) = cursor.word() else {
                        return Err(ArgError::usage(
                            cx.name,
                            format!("{command}: -v needs a value name"),
                        ));
                    };
                    value = Some(name.into_owned());
                } else {
                    path.push(word.into_owned());
                }
            }
            if path.is_empty() {
                return Err(ArgError::usage(
                    cx.name,
                    format!("{command}: give a key's full path"),
                ));
            }
            Ok(RegRequest::Query {
                command,
                path: path.join(" "),
                value,
            })
        }
        "keyinfo" => {
            let words: Vec<String> = std::iter::from_fn(|| cursor.word())
                .map(|word| word.into_owned())
                .collect();
            let [hive, node] = words.as_slice() else {
                return Err(ArgError::usage(
                    cx.name,
                    format!("{} keyinfo: give the hive and the key node", cx.name),
                ));
            };
            Ok(RegRequest::KeyAt {
                hive: cx.eval(hive)?,
                node: cx.eval(node)?,
            })
        }
        "cellindex" => {
            let words: Vec<String> = std::iter::from_fn(|| cursor.word())
                .map(|word| word.into_owned())
                .collect();
            let [hive, cell] = words.as_slice() else {
                return Err(ArgError::usage(
                    cx.name,
                    format!("{} cellindex: give the hive and the cell index", cx.name),
                ));
            };
            let hive = cx.eval(hive)?;
            let VirtAddr(cell) = cx.eval(cell)?;
            let cell = u32::try_from(cell).map_err(|_| {
                message(format!(
                    "!reg cellindex: {cell:#x} is not a cell index, which is 32 bits"
                ))
            })?;
            Ok(RegRequest::Cell { hive, cell })
        }
        other => Err(ArgError::usage(
            cx.name,
            format!("{}: unknown subcommand {other}", cx.name),
        )),
    }
}

/// What `!reg` shows.
pub enum RegOutput {
    Hives(HiveList),
    /// A key, and the command that read it (for the hint on cut data).
    Key(RegKey, String),
    Value(RegKey, RegValue),
    Cell(CellLocation),
}

/// Show the loaded registry hives, and keys and values read from them.
///
/// The commands read the configuration manager's hives in kernel memory, so
/// they work on every backend, live or in a crash dump, without the guest's
/// help. hivelist lists each hive on nt!CmpHiveListHead: its _CMHIVE, the bytes
/// of its stable and volatile storage, where it is mounted, such as
/// \REGISTRY\MACHINE\SYSTEM, and the file it was loaded from. querykey (or q)
/// shows a key: its last write time, its subkeys, and its values with their
/// data decoded by type, REG_SZ, REG_EXPAND_SZ, and REG_LINK as text,
/// REG_MULTI_SZ as its strings separated by \0, REG_DWORD,
/// REG_DWORD_BIG_ENDIAN, and REG_QWORD as numbers, and other types as hex
/// bytes. The path is a full one, \REGISTRY\MACHINE\..., or starts with HKLM,
/// HKU, HKCR (the machine's classes), or HKCC; HKCU depends on the user, so
/// give that user's HKU\<SID> instead. A path with spaces can be given
/// unquoted. The path resolves as the kernel parses it: across the link of each
/// hive to where it is mounted, and through symbolic links such as
/// CurrentControlSet, which the output names. Long data is cut short in the
/// list; -v <value> shows one value in full, its decoded data and every byte,
/// and -v "" the default value. keyinfo shows the key whose _CM_KEY_NODE is at
/// <knode> in the hive at <hive>, as querykey does, with its path found from
/// its parents. cellindex shows where a cell of a hive is: the cell map
/// directory and table, the map entry of its block and where it maps the block,
/// and the cell's address and size. The bins of a hive loaded from a file are a
/// view of the file in the Registry process, whose pages Windows loads as they
/// are used and can trim; a cell whose page is not in memory, or not in the
/// dump, is reported as such, and the rest of the key still shows.
#[command(
    names = ["!reg"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    forms = [registry_hives, registry_key, registry_value, registry_key_at, registry_cell],
)]
fn reg(session: &Session, #[arg(parse = reg_request)] request: RegRequest) -> Result<RegOutput> {
    let failed = |command: &str, error: Error| Error::DebugInfo(format!("{command}: {error}"));
    match request {
        RegRequest::Hives => registry_hives(session)
            .map(RegOutput::Hives)
            .map_err(|error| failed("!reg hivelist", error)),
        RegRequest::KeyAt { hive, node } => registry_key_at(session, hive, node)
            .map(|key| RegOutput::Key(key, "!reg querykey".to_string()))
            .map_err(|error| failed("!reg keyinfo", error)),
        RegRequest::Cell { hive, cell } => registry_cell(session, hive, cell)
            .map(RegOutput::Cell)
            .map_err(|error| failed("!reg cellindex", error)),
        RegRequest::Query {
            command,
            path,
            value,
        } => {
            let key = registry_key(session, path).map_err(|error| failed(&command, error))?;
            let Some(wanted) = value else {
                return Ok(RegOutput::Key(key, command));
            };
            // `(Default)` as the list shows the default value names it too.
            let wanted = if wanted.eq_ignore_ascii_case("(Default)") {
                ""
            } else {
                &wanted
            };
            let found = key
                .values
                .iter()
                .flatten()
                .find(|value| names_equal(&value.name, wanted))
                .cloned();
            match found {
                Some(value) => Ok(RegOutput::Value(key, value)),
                None => {
                    let unreadable = key.values.iter().filter(|entry| entry.is_err()).count();
                    Err(Error::DebugInfo(format!(
                        "{command}: {} has no value named {}{}",
                        key.path,
                        value_name(wanted),
                        if unreadable > 0 {
                            format!(" among those that read ({unreadable} do not)")
                        } else {
                            String::new()
                        }
                    )))
                }
            }
        }
    }
}

/// List the registry hives loaded in kernel memory, with where each is
/// mounted and the file it was loaded from (`!reg hivelist`).
#[command(form_of = reg, python = Inspect)]
fn registry_hives(session: &Session) -> Result<HiveList> {
    session.target.registry_hives()
}

/// Read the registry key at `path`, a full path such as
/// `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip` or
/// `\REGISTRY\MACHINE\...`, with its subkeys and its values, each
/// value's data typed by its type (`!reg querykey`).
#[command(form_of = reg, python = Inspect)]
fn registry_key(session: &Session, path: String) -> Result<RegKey> {
    session.target.registry_key(&path)
}

/// Read the value `name` of the registry key at `path`; `""` names the
/// key's default value. Its `data` is a `str`, a `list[str]`, an `int`,
/// or `bytes`, by the value's type (`!reg querykey <path> -v <name>`).
#[command(form_of = reg, python = Inspect)]
fn registry_value(session: &Session, path: String, name: String) -> Result<RegValue> {
    let key = session.target.registry_key(&path)?;
    key.values
        .iter()
        .flatten()
        .find(|value| names_equal(&value.name, &name))
        .cloned()
        .ok_or_else(|| {
            Error::DebugInfo(format!("{} has no readable value named {name:?}", key.path))
        })
}

/// Read the registry key whose key node (`_CM_KEY_NODE`) is at `node`
/// in the hive at `hive` (`!reg keyinfo`).
#[command(form_of = reg, python = Inspect)]
fn registry_key_at(session: &Session, hive: VirtAddr, node: VirtAddr) -> Result<RegKey> {
    session.target.registry_key_at(hive, node)
}

/// Find where cell index `cell` of the hive at `hive` is, through the
/// hive's cell map (`!reg cellindex`).
#[command(form_of = reg, python = Inspect)]
fn registry_cell(session: &Session, hive: VirtAddr, cell: u32) -> Result<CellLocation> {
    session.target.registry_cell(hive, cell)
}

impl Render for RegOutput {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        match self {
            Self::Hives(list) => print_hives(list),
            Self::Key(key, command) => print_key(key, command),
            Self::Value(key, value) => print_value(key, value),
            Self::Cell(location) => print_cell(location),
        }
    }
}
