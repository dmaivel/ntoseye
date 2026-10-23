use std::collections::HashSet;
use std::path::{Path, PathBuf};

use tabled::builder::Builder;

use owo_colors::OwoColorize;

use ntoseye_macros::{command, grammar};

use crate::base::error::{Error, Result};
use crate::base::types::VirtAddr;
use crate::hosts::repl::args::{ArgCursor, ArgCx, ArgError, words};
use crate::hosts::ui;
use crate::nt::breakpoints::BreakpointManager;
use crate::nt::expr::{Expr, ExprValue};
use crate::nt::guest::{ModuleInfo, ModuleSymbolLoadReport};
use crate::nt::layout::{FieldInfo, nested_layout_name};
use crate::nt::symbols::{
    CodeFrame, ImageSource, LocalSourceState, ModuleListing, ModuleSymbolStatus, SourceLocation,
    SourcePath, Symbol, SymbolPath, glob_matches, parse_source_paths, parse_symbol_sources,
};
use crate::nt::target::{ReloadScope, Target, UserVar};
use crate::session::Session;
use crate::session::typeview::TypeView;

use crate::hosts::repl::*;

/// The first word; `x` ignores the words after it, as it always did.
#[grammar(usage = "[module!]<query>", complete = Symbol)]
fn first_word(
    _: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<String, ArgError> {
    let first = cursor.word().ok_or(ArgError::Missing)?.into_owned();
    cursor.rest();
    Ok(first)
}

/// Search for symbols by fuzzy name match.
///
/// `*` and `?` are glob characters. The operators are `^` prefix, `$`
/// suffix, `'` exact match, and `!` negation. If you separate terms with
/// spaces, a symbol must match all the terms.
#[command(
    names = ["x"],
    category = "symbols, types, and expressions",
    kind = Query,
    python = none,
)]
fn x(state: &mut ReplState<'_>, #[arg(parse = first_word)] query: String) -> Result<()> {
    // bounded purely for terminal-output sanity (resolution
    // is O(1) now); a huge match set just floods the screen
    const X_LIMIT: usize = 4096;
    let query = query.as_str();
    let dtb = state.ctx.target.current_dtb();
    // `module!query` scopes the search to one module; a bare query
    // fuzzy-matches the cached merged index, whose names are already
    // module-qualified.
    let names: Vec<String> = match query.split_once('!') {
        Some((module, q)) => state
            .ctx
            .target
            .symbols
            .search_symbols_in_module(dtb, module, q, X_LIMIT)
            .into_iter()
            .map(|name| format!("{module}!{name}"))
            .collect(),
        None => {
            state.caches.refresh_loaded_symbols(&state.ctx.target);
            state.caches.symbols.read().unwrap().search(query, X_LIMIT)
        }
    };
    let truncated = names.len() >= X_LIMIT;
    let mut matches: Vec<(u64, String)> = Vec::new();
    for name in &names {
        let bare = name
            .rsplit_once('!')
            .map_or(name.as_str(), |(_, bare)| bare);
        let mut seen = HashSet::new();
        for candidate in state.ctx.target.symbols.find_symbol_candidates(dtb, name) {
            if !seen.insert((candidate.module.to_ascii_lowercase(), candidate.address.0)) {
                continue;
            }
            matches.push((
                candidate.address.0,
                format!("{}!{}", candidate.module, bare),
            ));
        }
    }
    if matches.is_empty() {
        outln!("no symbols match '{}'", query);
        outln!();
        state.ctx.target.set_results(Vec::new(), state.line.clone());
        return Ok(());
    }
    let print_text = || {
        for (address, label) in &matches {
            outln!("{}  {}", ui::addr(*address), ui::symbol(label));
        }
        outln!(
            "\n{} {}{} (in $0..${})",
            matches.len(),
            if matches.len() == 1 {
                "symbol"
            } else {
                "symbols"
            },
            if truncated {
                ", truncated; refine query"
            } else {
                ""
            },
            matches.len() - 1
        );
        outln!();
    };
    #[cfg(feature = "cli")]
    native::render(
        || native::lists::symbol_matches(&matches, truncated),
        print_text,
    );
    #[cfg(not(feature = "cli"))]
    print_text();
    let hits = matches.iter().map(|(address, _)| *address).collect();
    state.ctx.target.set_results(hits, state.line.clone());

    Ok(())
}

/// The next word as an address, left for the argument after, which takes it
/// too: `ln` names the address it was given when no symbol covers it.
#[grammar(usage = "")]
fn peek_address(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<VirtAddr, ArgError> {
    let word = cursor.words().next().ok_or(ArgError::Missing)?.to_string();
    cx.eval(&word)
}

/// List the symbol nearest to an address.
#[command(
    names = ["ln"],
    category = "symbols, types, and expressions",
    kind = Query,
    python = Symbols,
    python_name = "nearest",
)]
fn ln(
    session: &Session,
    #[arg(render, parse = peek_address)] shown: VirtAddr,
    address: VirtAddr,
) -> Result<Option<Symbol>> {
    Ok(session.target.nearest_symbol(address))
}

/// `ln`: the symbol, or where the address is when its module has no
/// symbols (WinDbg's `module+offset`).
impl Render<VirtAddr> for Option<Symbol> {
    fn render(&self, repl: &mut ReplState<'_>, address: VirtAddr) {
        match self {
            Some(symbol) => {
                outln!("{}  {}\n", ui::addr(address.0), ui::symbol(&symbol.label()));
                // $0 = the symbol's base address (the resolved target)
                repl.ctx
                    .target
                    .set_results(vec![symbol.address.0], repl.line.clone());
            }
            None => {
                let dtb = repl.ctx.target.current_dtb();
                match repl.ctx.target.format_code_address(dtb, address) {
                    Some(label) => {
                        outln!(
                            "{}  {}  {}\n",
                            ui::addr(address.0),
                            ui::symbol(&label),
                            ui::muted("(no symbols loaded for this module)")
                        );
                    }
                    None => outln!("no symbol found for {}\n", ui::addr(address.0)),
                }
            }
        }
    }
}

/// Evaluate an expression.
///
/// Memory read functions and their sizes in bytes: by() 1, wo() 2, dwo()
/// 4, qwo()/poi() 8. `&expr` gives the address of `expr`. `->` and `.`
/// give field values.
#[command(
    names = ["?", "ev"],
    category = "symbols, types, and expressions",
    kind = Query,
    forms = [eval],
    style = ExpressionTail,
)]
fn ev(
    state: &mut ReplState<'_>,
    #[arg(raw, usage = "<expression>", complete = Expression)] expression: String,
) -> Result<()> {
    if expression.is_empty() {
        outln!("{}\n", command_help("ev"));
        return Ok(());
    }

    let value = match Expr::parse_with_radix(&expression, state.radix)
        .and_then(|expr| expr.evaluate(&state.ctx.target))
    {
        Ok(value) => value,
        Err(e) => {
            error!("{}", e);
            return Ok(());
        }
    };
    if let Err(e) = state.print_expr_value(&value) {
        error!("{}", e);
    }

    Ok(())
}

/// Evaluate a debugger (MASM) expression to an integer (`?`) in this
/// object's scope: the debugger's is the kernel's, with the registers of the
/// stopped vCPU (on a user-mode minidump, of the selected thread); a
/// process's resolves the symbols of its modules, which it loads first; a
/// VTL1 address space's (the secure kernel's, a trustlet's) has no
/// registers, as the live ones hold VTL0 state.
#[command(form_of = ev, python = [Debugger, Process, SecureKernel, Trustlet])]
fn eval(session: &Session, expr: String) -> Result<u64> {
    let target = &session.target;
    if let Some(process) = target.attached_process() {
        target.load_process_module_symbols(process.pid, process.dtb, None)?;
    }
    Ok(Expr::eval(&expr, target)?.0)
}

/// Every word left, at least one.
#[grammar(operation)]
fn some_words(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<Vec<String>, ArgError> {
    let words = words(cx, cursor)?;
    if words.is_empty() {
        return Err(ArgError::Missing);
    }
    Ok(words)
}

/// Show or replace the ordered symbol source path.
#[command(
    names = [".sympath"],
    category = "symbols, types, and expressions",
    kind = Action,
    writes = [Symbols],
    python = none,
)]
fn sympath(
    session: &Session,
    #[arg(parse = words, usage = "[directory|http-server]...", complete = None)] sources: Vec<
        String,
    >,
) -> Result<SymbolPath> {
    let symbols = &session.target.symbols;
    if !sources.is_empty() {
        symbols.set_symbol_sources(parse_symbol_sources(&sources));
    }
    Ok(symbols.symbol_path())
}

/// Add entries to the end of the ordered symbol source path.
#[command(
    names = [".sympath+"],
    category = "symbols, types, and expressions",
    kind = Action,
    writes = [Symbols],
    python = none,
)]
fn sympath_append(
    session: &Session,
    #[arg(parse = some_words, usage = "<directory|http-server>...", complete = None)] sources: Vec<
        String,
    >,
) -> Result<SymbolPath> {
    let symbols = &session.target.symbols;
    for source in parse_symbol_sources(&sources) {
        symbols.append_symbol_source(source);
    }
    Ok(symbols.symbol_path())
}

/// Set the symbol source path back to the defaults, the ntoseye cache and the Microsoft symbol server.
#[command(
    names = [".symfix"],
    category = "symbols, types, and expressions",
    kind = Action,
    writes = [Symbols],
    python = Symbols,
    python_name = "reset_path",
)]
fn symfix(session: &Session) -> Result<SymbolPath> {
    let symbols = &session.target.symbols;
    symbols.reset_symbol_sources();
    Ok(symbols.symbol_path())
}

impl Render for SymbolPath {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        outln!("symbol sources:");
        for (index, source) in self.sources.iter().enumerate() {
            outln!("  {:>2}: {}", index, source);
        }
        outln!();
    }
}

/// Show or replace the ordered local source path mappings.
///
/// A local root contains the source tree, and a recorded path such as
/// C:\Users\me\repos\MyDriver\src\queue.c maps to a file under the root.
/// ntoseye uses the longest trailing part of the recorded path that names a
/// file under the root, so root/src/queue.c comes before root/queue.c. It
/// tries an exact match first, and then a match that ignores case. A
/// recorded-prefix=local-root mapping replaces the recorded prefix with the
/// local root. If the PDB records the checksum of a source file, ntoseye
/// shows only a file with that checksum, and reports a file with a different
/// checksum as not the compiled source.
#[command(
    names = [".srcpath"],
    category = "symbols, types, and expressions",
    kind = Action,
    writes = [Symbols],
    python = none,
)]
fn srcpath(
    session: &Session,
    #[arg(parse = words, usage = "[local-root|recorded-prefix=local-root]...", complete = None)]
    paths: Vec<String>,
) -> Result<SourcePath> {
    let symbols = &session.target.symbols;
    if !paths.is_empty() {
        symbols.set_source_paths(parse_source_paths(&paths));
    }
    Ok(symbols.source_path())
}

/// Add local source path mappings to the end of the list.
///
/// ntoseye tries the mappings in order, as .srcpath describes.
#[command(
    names = [".srcpath+"],
    category = "symbols, types, and expressions",
    kind = Action,
    writes = [Symbols],
    python = none,
)]
fn srcpath_append(
    session: &Session,
    #[arg(parse = some_words, usage = "<local-root|recorded-prefix=local-root>...", complete = None)]
    paths: Vec<String>,
) -> Result<SourcePath> {
    let symbols = &session.target.symbols;
    for mapping in parse_source_paths(&paths) {
        symbols.append_source_path(mapping);
    }
    Ok(symbols.source_path())
}

impl Render for SourcePath {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        if self.mappings.is_empty() {
            outln!("source paths: <empty>\n");
            return;
        }
        outln!("source paths:");
        for (index, path) in self.mappings.iter().enumerate() {
            outln!("  {:>2}: {}", index, path);
        }
        outln!();
    }
}

/// `ls [.] [first][,count]`.
#[grammar(usage = "[.] [first][,count]", complete = None)]
fn ls_arguments(
    _: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<LsArgs, ArgError> {
    parse_ls_args(&cursor.take_all(|_| true)).ok_or(ArgError::Missing)
}

/// `lsa [address][,first][,count]`.
#[grammar(usage = "[address][,first][,count]", complete = Expression)]
fn lsa_arguments(
    _: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<LsaArgs, ArgError> {
    parse_lsa_args(&cursor.take_all(|_| true)).ok_or(ArgError::Missing)
}

/// List source lines of the file for the current scope.
///
/// With no arguments, the command continues after the lines that the
/// previous ls or lsa showed, and `.` starts again at the current line.
/// `first` is a line number, and `count` is 10 by default. The file is the
/// file of the source line of the selected frame, which for an inline frame
/// is in the inlined function. ntoseye finds the file through .srcpath.
#[command(
    names = ["ls"],
    category = "symbols, types, and expressions",
    kind = Query,
    python = none,
)]
fn ls(state: &mut ReplState<'_>, #[arg(parse = ls_arguments)] spec: LsArgs) -> Result<()> {
    const DEFAULT_COUNT: u32 = 10;
    let count = spec.count.unwrap_or(DEFAULT_COUNT);
    let (path, first, current) = match (spec.first, spec.restart, &state.source_cursor) {
        (None, false, Some((path, next))) => (path.clone(), *next, None),
        _ => {
            let Some(frame) = state.ctx.target.scope_frame() else {
                error!("ls requires a halted register context");
                return Ok(());
            };
            let (path, location) = match source_file_at(&state.ctx.target, frame) {
                Ok(found) => found,
                Err(message) => {
                    error!("{message}");
                    return Ok(());
                }
            };
            (
                path,
                spec.first.unwrap_or(location.line),
                Some(location.line),
            )
        }
    };
    state.list_source(&path, first, count, current);
    Ok(())
}

/// List source lines around an address.
///
/// By default, the command uses the source line of the selected frame, and
/// shows twelve lines in total, starting five lines before that line. If you
/// give an address, the command uses the line of the innermost frame at that
/// address, which is the inlined function if a function is inlined there.
/// `first` is an offset from that line, with a negative value for lines
/// before it. The command marks the line with `>`.
#[command(
    names = ["lsa"],
    category = "symbols, types, and expressions",
    kind = Query,
    python = none,
)]
fn lsa(state: &mut ReplState<'_>, #[arg(parse = lsa_arguments)] spec: LsaArgs) -> Result<()> {
    const DEFAULT_FIRST: i64 = -5;
    const DEFAULT_COUNT: u32 = 12;
    let frame = match spec.address {
        Some(text) => match state.eval_or_report(&text) {
            Some(address) => CodeFrame::at(address),
            None => return Ok(()),
        },
        None => match state.ctx.target.scope_frame() {
            Some(frame) => frame,
            None => {
                error!("lsa requires an address or a halted register context");
                return Ok(());
            }
        },
    };
    let (path, location) = match source_file_at(&state.ctx.target, frame) {
        Ok(found) => found,
        Err(message) => {
            error!("{message}");
            return Ok(());
        }
    };
    let first = (i64::from(location.line) + spec.first.unwrap_or(DEFAULT_FIRST)).max(1) as u32;
    state.list_source(
        &path,
        first,
        spec.count.unwrap_or(DEFAULT_COUNT),
        Some(location.line),
    );
    Ok(())
}

/// Show the locals and parameters of the selected frame.
///
/// Each frame shows only its own variables. For an inline frame, these are
/// the variables of the inlined function, and the frame that contains the
/// inlined call shows the variables of its procedure but not those of the
/// calls that are inlined into it. Without an address, the command uses the
/// frame that .frame selected or, if no frame is selected, the innermost
/// frame at the stop. With an address, it uses the innermost frame at that
/// address.
#[command(
    names = ["dv"],
    category = "symbols, types, and expressions",
    kind = Query,
    python = none,
)]
fn dv(state: &mut ReplState<'_>, address: Option<VirtAddr>) -> Result<()> {
    let target = &state.ctx.target;
    let (address, frame) = match address {
        Some(address) => (address, CodeFrame::at(address)),
        None => {
            let (Some(rip), Some(frame)) = (scope_ip(target), target.scope_frame()) else {
                error!("dv requires a halted register context or an explicit address");
                return Ok(());
            };
            (rip, frame)
        }
    };

    let Some(locals) = target.frame_locals(frame)? else {
        outln!("no procedure locals found at {}\n", ui::addr(address.0));
        return Ok(());
    };
    if locals.is_empty() {
        outln!("no locals in scope at {}\n", ui::addr(address.0));
        return Ok(());
    }

    for local in locals.iter() {
        let kind = if local.is_parameter { "param" } else { "local" };
        let location = local.location.describe();
        match target.resolve_procedure_local_value(address, local) {
            Some(value) => outln!(
                "{:<20} {:<24} {:<7} {:<24} {:#x}",
                local.name,
                local.type_name,
                kind,
                location,
                value
            ),
            None => outln!(
                "{:<20} {:<24} {:<7} {}",
                local.name,
                local.type_name,
                kind,
                location
            ),
        }
    }
    outln!();
    Ok(())
}

/// `.reload`'s options, anywhere on the line: `/n` (the kernel's modules)
/// or `/user` (the process's), and `/f` and `/v`, which change nothing.
/// Every word is checked in order, so the first bad one is reported.
#[grammar(usage = "[/f] [/v] [/n|/user]")]
fn reload_scope(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<Option<ReloadScope>, ArgError> {
    let line: Vec<String> = cursor.words().map(str::to_string).collect();
    let mut scope = None;
    let mut module = false;
    for arg in &line {
        let option = arg.strip_prefix('/').or_else(|| arg.strip_prefix('-'));
        match option.map(str::to_ascii_lowercase).as_deref() {
            None if !module => module = true,
            Some("f" | "v") => {}
            Some("n") if scope != Some(ReloadScope::User) => scope = Some(ReloadScope::Kernel),
            Some("user") if scope != Some(ReloadScope::Kernel) => scope = Some(ReloadScope::User),
            Some("n" | "user") => {
                return Err(ArgError::Message(
                    ".reload: /n reloads only the kernel's modules and /user only the process's; give one"
                        .to_string(),
                ));
            }
            Some("u") => {
                return Err(ArgError::Message(
                    ".reload /u is not supported: ntoseye loads the symbols of every loaded \
                     kernel module again at the next stop, and it does not lock PDB files, so \
                     a rebuilt driver's PDB can replace one on disk; .reload <module> loads \
                     the new one"
                        .to_string(),
                ));
            }
            Some("?") | None => return Err(ArgError::Missing),
            Some(_) => {
                return Err(ArgError::usage(
                    cx.name,
                    format!("{}: unknown option '{arg}'", cx.name),
                ));
            }
        }
    }
    cursor.take_all(|word| word.starts_with('/') || word.starts_with('-'));
    Ok(scope)
}

/// Reload symbols for the modules in the current scope, or for the modules a name or pattern names.
///
/// Asks the symbol path again for each module's PDB, whatever failed before,
/// and loads it at once. The current scope's modules are the selected
/// process's user-mode modules, else the kernel's; /n reloads the kernel's
/// and /user the selected process's. A module is a name such as nt or
/// viostor.sys, or a pattern with * and ? such as vio*. /f and /v are
/// accepted as in WinDbg: ntoseye always loads at once, and lm shows each
/// module's symbol status.
#[command(
    names = [".reload"],
    category = "symbols, types, and expressions",
    kind = Action,
    writes = [Symbols],
    python = Symbols,
)]
fn reload(
    session: &mut Session,
    #[arg(parse = reload_scope)] scope: Option<ReloadScope>,
    module: Option<String>,
) -> Result<ModuleSymbolLoadReport> {
    reload_symbols(
        session,
        scope.unwrap_or(ReloadScope::Current),
        module.as_deref(),
    )
}

/// Force ntoseye to select the symbol source and index the symbols for one module.
#[command(
    names = ["ld"],
    category = "processes and modules",
    kind = Action,
    writes = [Symbols],
    python = Module,
    python_name = "reload_symbols",
)]
fn ld(session: &mut Session, #[arg(receiver)] module: String) -> Result<ModuleSymbolLoadReport> {
    reload_symbols(session, ReloadScope::Current, Some(&module))
}

/// Reload the symbols `scope` and `module` name, then resolve the symbolic
/// breakpoints again.
fn reload_symbols(
    session: &mut Session,
    scope: ReloadScope,
    module: Option<&str>,
) -> Result<ModuleSymbolLoadReport> {
    let mut report = session
        .target
        .reload_module_symbols(scope, module)
        .map_err(|error| Error::DebugInfo(format!("symbol reload failed: {error}")))?;
    if let Err(error) = session
        .breakpoints
        .resolve_symbolic(session.backend.as_mut(), &session.target)
    {
        report.breakpoint_error = Some(error.to_string());
    }
    Ok(report)
}

/// `.reload`, `ld`: the report, then the REPL's symbol and breakpoint
/// completion caches, which the reload changed.
impl Render for ModuleSymbolLoadReport {
    fn render(&self, repl: &mut ReplState<'_>, (): ()) {
        print_module_symbol_report(self);
        repl.caches.rebuild_symbol_context(&repl.ctx.target);
        if let Some(error) = &self.breakpoint_error {
            error!("symbolic breakpoint re-resolution failed: {}", error);
        }
        repl.caches.refresh_breakpoints(&repl.ctx.breakpoints);
    }
}

/// `.fetchimage <module>` or `.fetchimage /f <file>`.
#[grammar(usage = "<module> | /f <file>", complete = Symbol)]
fn image_source(
    _: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<ImageSource, ArgError> {
    let word = cursor.word().ok_or(ArgError::Missing)?;
    if word.eq_ignore_ascii_case("/f") {
        let file = cursor.word().ok_or(ArgError::Missing)?;
        return Ok(ImageSource::File(PathBuf::from(file.as_ref())));
    }
    Ok(ImageSource::Module(word.into_owned()))
}

/// Download the PE file of a loaded module into the symbol cache, or copy a file into it, and print its path.
///
/// The command finds the file by the TimeDateStamp and SizeOfImage values
/// in the mapped PE header of the module. These values are the
/// symbol-server key, so the file is the same build that is running, and a
/// disassembler database that you make from this file rebases onto the live
/// module. A copy in a local directory on the symbol path, at its root or in
/// symbol-store layout, is used before a symbol server. `/f` copies a PE
/// file that you have into the cache under the key in its own header, with
/// the name of its PDB, so ntoseye finds it for the module that runs that
/// build. Use it for the Windows hypervisor, which Microsoft's symbol server
/// does not have: copy C:\Windows\System32\hvix64.exe from the guest and run
/// `.fetchimage /f hvix64.exe`, after which the stacks of a vCPU in the
/// hypervisor unwind through the file's unwind data.
#[command(
    names = [".fetchimage"],
    category = "symbols, types, and expressions",
    kind = Action,
    writes = [Symbols],
    forms = [fetch_image, import_image],
)]
fn fetchimage(
    session: &Session,
    #[arg(parse = image_source)] image: ImageSource,
) -> Result<String> {
    fetch_image(session, image)
}

/// Download the module's PE file into the symbol cache and return its path
/// there (`.fetchimage`). The file is found by the TimeDateStamp and
/// SizeOfImage values in the module's mapped PE header, the symbol-server
/// key, so it is the same build that is running; a copy in a local
/// directory on the symbol path is used before a symbol server.
#[command(form_of = fetchimage, python = Module)]
fn fetch_image(session: &Session, #[arg(receiver)] image: ImageSource) -> Result<String> {
    let target = &session.target;
    let path = match image {
        ImageSource::Module(name) => target.fetch_module_image(&name)?,
        ImageSource::File(file) => target.symbols.import_image(&file)?,
    };
    Ok(path.display().to_string())
}

/// Copy a PE file into the symbol cache under the key in its own header, and
/// return its path in the cache (`.fetchimage /f`). Use it for an image that
/// no symbol server has, such as the Windows hypervisor's `hvix64.exe`.
#[command(form_of = fetchimage, python = Symbols)]
fn import_image(session: &Session, path: String) -> Result<String> {
    fetch_image(session, ImageSource::File(PathBuf::from(path)))
}

/// `lm`'s words that choose what the text shows: `v` (the details) and `t`
/// (time stamps).
#[derive(Debug, Default, Clone, Copy)]
pub struct ModuleDisplay {
    verbose: bool,
    timestamp: bool,
}

/// `lm`'s words that choose the modules.
pub struct ModuleFilter {
    pattern: Option<String>,
    /// `m <pattern>`: a glob, not a substring.
    glob: bool,
    user: bool,
    kernel: bool,
    /// `a <address>`: the module containing it.
    containing: Option<VirtAddr>,
}

/// `lm`'s words, read as WinDbg does: `m` and `a` take the word after them,
/// and the first other word that is not an option is the pattern.
struct ModuleWords<'w> {
    display: ModuleDisplay,
    pattern: Option<&'w str>,
    glob: bool,
    user: bool,
    kernel: bool,
    /// `a` and the word after it, if there is one.
    containing: Option<Option<&'w str>>,
}

fn module_words<'w>(line: &[&'w str]) -> ModuleWords<'w> {
    let mut words = ModuleWords {
        display: ModuleDisplay::default(),
        pattern: None,
        glob: false,
        user: false,
        kernel: false,
        containing: None,
    };
    let mut index = 0;
    while index < line.len() {
        let arg = line[index];
        match arg.to_ascii_lowercase().as_str() {
            "v" => words.display.verbose = true,
            "u" => words.user = true,
            "k" => words.kernel = true,
            "t" => words.display.timestamp = true,
            "m" => {
                words.glob = true;
                index += 1;
                words.pattern = line.get(index).copied();
            }
            "a" => {
                index += 1;
                words.containing = Some(line.get(index).copied());
                if words.containing == Some(None) {
                    break;
                }
            }
            _ if words.pattern.is_none() => words.pattern = Some(arg),
            _ => {}
        }
        index += 1;
    }
    words
}

/// `lm`'s display words, left for [`module_filter`].
#[grammar(usage = "")]
fn module_display(
    _: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<ModuleDisplay, ArgError> {
    let line: Vec<&str> = cursor.words().collect();
    Ok(module_words(&line).display)
}

/// `lmv`'s display words: always the details.
#[grammar(usage = "")]
fn module_details_display(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<ModuleDisplay, ArgError> {
    Ok(ModuleDisplay {
        verbose: true,
        ..module_display(cx, cursor)?
    })
}

/// `lm`'s filter: every word.
#[grammar(usage = "[m <pattern>|a <address>|<name>] [v] [u|k] [t]", complete = [None, Symbol, None, None])]
fn module_filter(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<ModuleFilter, ArgError> {
    let taken = cursor.take_all(|_| true);
    let line: Vec<&str> = taken.iter().map(AsRef::as_ref).collect();
    let words = module_words(&line);
    let containing = match words.containing {
        Some(Some(text)) => Some(cx.eval(text)?),
        Some(None) => return Err(ArgError::Missing),
        None => None,
    };
    Ok(ModuleFilter {
        pattern: words.pattern.map(str::to_string),
        glob: words.glob,
        user: words.user,
        kernel: words.kernel,
        containing,
    })
}

/// List loaded modules.
///
/// `m` applies a module-name glob, and `v m` prints verbose symbol
/// information. `a <address>` shows only the module that contains the
/// address, a kernel module for a kernel address. `u` selects user modules,
/// `k` selects kernel modules, and `t` adds timestamps.
#[command(
    names = ["lm"],
    category = "processes and modules",
    kind = Query,
    python = none,
)]
fn lm(
    session: &Session,
    #[arg(render, parse = module_display)] display: ModuleDisplay,
    #[arg(parse = module_filter)] filter: ModuleFilter,
) -> Result<Vec<ModuleListing>> {
    list_modules(&session.target, &filter)
}

/// Show the detailed symbol status and PDB identity of each module.
///
/// This command is the same as `lm v` and uses the same filters, for example
/// `lmv m nt`.
#[command(
    names = ["lmv"],
    category = "processes and modules",
    kind = Query,
    python = none,
)]
fn lmv(
    session: &Session,
    #[arg(render, parse = module_details_display)] display: ModuleDisplay,
    #[arg(parse = module_filter)] filter: ModuleFilter,
) -> Result<Vec<ModuleListing>> {
    list_modules(&session.target, &filter)
}

/// The modules `filter` selects, with their symbols' state.
fn list_modules(target: &Target, filter: &ModuleFilter) -> Result<Vec<ModuleListing>> {
    let mut kernel = filter.kernel;
    // An address names its own list: a kernel address is in a kernel
    // module even while a process is selected, as in WinDbg.
    if let Some(address) = filter.containing
        && !filter.user
    {
        kernel |= BreakpointManager::is_kernel_space(target.arch(), address);
    }
    let dtb = if kernel {
        target.kernel_dtb()
    } else {
        target.process_dtb()
    };
    let modules = if kernel {
        target.kernel_modules_with_versions()
    } else if filter.user && target.attached_process().is_none() && target.user_modules().is_none()
    {
        Ok(Vec::new())
    } else {
        target.modules_with_versions()
    }
    .map_err(|error| Error::DebugInfo(format!("failed to list modules: {error}")))?;
    let matches = |module: &ModuleInfo| {
        filter
            .containing
            .is_none_or(|address| module.contains_address(address))
            && filter.pattern.as_deref().is_none_or(|pattern| {
                if filter.glob {
                    glob_matches(pattern, &module.short_name, true)
                        || glob_matches(pattern, &module.name, true)
                        || module
                            .name
                            .rsplit(['\\', '/'])
                            .next()
                            .is_some_and(|name| glob_matches(pattern, name, true))
                } else {
                    module
                        .short_name
                        .to_ascii_lowercase()
                        .contains(&pattern.to_ascii_lowercase())
                        || module
                            .name
                            .to_ascii_lowercase()
                            .contains(&pattern.to_ascii_lowercase())
                }
            })
    };
    Ok(modules
        .into_iter()
        .filter(|module| matches(module))
        .map(|module| ModuleListing {
            symbols: target.symbols.module_symbols(dtb, module.base_address),
            module,
        })
        .collect())
}

/// `lm`: the table, or with `v` each module's details.
impl Render<ModuleDisplay> for Vec<ModuleListing> {
    fn render(&self, _: &mut ReplState<'_>, display: ModuleDisplay) {
        let ModuleDisplay { verbose, timestamp } = display;
        if self.is_empty() {
            outln!("{}\n", "no matching modules".bright_black());
        } else if verbose {
            #[cfg(feature = "cli")]
            native::render(
                || native::lists::module_details(self, timestamp),
                || print_module_details(self, timestamp),
            );
            #[cfg(not(feature = "cli"))]
            print_module_details(self, timestamp);
        } else {
            #[cfg(feature = "cli")]
            native::render(
                || native::lists::modules(self, timestamp),
                || print_modules(self, timestamp),
            );
            #[cfg(not(feature = "cli"))]
            print_modules(self, timestamp);
        }
    }
}

/// The selected frame's IP, else the live one.
fn scope_ip(target: &Target) -> Option<VirtAddr> {
    target
        .selected_frame
        .as_ref()
        .map(|frame| frame.ip)
        .or_else(|| target.register_value(target.arch().pc_register()))
        .map(VirtAddr)
}

/// The source line of `frame`, with its local file: the error names what
/// is missing (line info, or the file `.srcpath` should map).
fn source_file_at(
    target: &Target,
    frame: CodeFrame,
) -> std::result::Result<(PathBuf, SourceLocation), String> {
    let address = frame.address;
    let Some(location) = target.frame_source_location(frame) else {
        return Err(format!(
            "no source line information for {}",
            ui::addr(address.0)
        ));
    };
    match &location.local {
        Some(local) if local.state == LocalSourceState::Found => Ok((local.path.clone(), location)),
        Some(local) if local.state == LocalSourceState::Differs => Err(format!(
            "{} is not the source compiled for {} (its checksum differs from the one {} records)",
            local.path.display(),
            ui::addr(address.0),
            location.file
        )),
        _ => Err(format!(
            "source file for {} is not available locally (recorded as {}); map it with .srcpath",
            ui::addr(address.0),
            location.file
        )),
    }
}

/// Define a convenience variable that you can use in expressions as $<name>.
#[command(
    names = ["set"],
    category = "symbols, types, and expressions",
    kind = Host,
    python = none,
)]
fn set(
    state: &mut ReplState<'_>,
    #[arg(rest, usage = "<$name> <expression>", complete = [None, Expression])] rest: String,
) -> Result<()> {
    let Some((lhs, rhs)) = rest.split_once(char::is_whitespace) else {
        outln!("{}\n", command_help("set"));
        return Ok(());
    };
    let name = lhs.trim().strip_prefix('$').unwrap_or(lhs.trim()).trim();
    // names must start with a letter or '_'; this reserves
    // $<digits> (and digit-leading names) for the $0..$N
    // result slots, avoiding any collision
    let valid = name
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !valid {
        error!(
            "invalid variable name '${}' (must start with a letter or '_'; $<digits> are reserved for result slots)",
            name
        );
        return Ok(());
    }
    let source = rhs.trim().to_string();
    match Expr::eval_with_radix(&source, &state.ctx.target, state.radix) {
        Ok(v) => {
            state
                .ctx
                .target
                .user_vars
                .insert(name.to_string(), UserVar { value: v.0, source });
            outln!("${} = {}\n", name, ui::addr(v.0));
        }
        Err(e) => error!("{}", e),
    }

    Ok(())
}

/// List the defined convenience variables and result slots.
#[command(
    names = ["vars"],
    category = "symbols, types, and expressions",
    kind = Host,
    python = none
)]
fn vars(state: &mut ReplState<'_>) -> Result<()> {
    let builtins = state.ctx.target.builtin_variables();
    if state.ctx.target.user_vars.is_empty()
        && state.ctx.target.results.is_empty()
        && builtins.is_empty()
    {
        outln!("no variables defined\n");
        return Ok(());
    }
    let mut names: Vec<&String> = state.ctx.target.user_vars.keys().collect();
    names.sort();
    let user: Vec<(&str, &UserVar)> = names
        .into_iter()
        .map(|name| (name.as_str(), &state.ctx.target.user_vars[name]))
        .collect();
    let results = state.ctx.target.results.len();
    let origin = state.ctx.target.results_origin.as_deref();
    let print_text = || {
        if !user.is_empty() {
            outln!("{}", ui::label("user"));
            for (name, var) in &user {
                outln!(
                    "  ${:<16} {}   {}",
                    name,
                    ui::addr(var.value),
                    ui::muted(&var.source)
                );
            }
        }
        if results != 0 {
            if !user.is_empty() {
                outln!();
            }
            let origin = origin
                .map(|cmd| format!("from: {}", cmd))
                .unwrap_or_default();
            outln!(
                "  {}   {}",
                ui::muted(&format!("$0..${}", results - 1)),
                ui::muted(&origin)
            );
        }
        if !builtins.is_empty() {
            if !user.is_empty() || results != 0 {
                outln!();
            }
            outln!("{}", ui::label("builtins"));
            for var in &builtins {
                outln!(
                    "  ${:<16} {}   {}",
                    var.name,
                    ui::addr(var.value),
                    ui::muted(var.source)
                );
            }
        }
        outln!();
    };
    #[cfg(feature = "cli")]
    native::render(
        || native::inspect::vars(&user, results, origin, &builtins),
        print_text,
    );
    #[cfg(not(feature = "cli"))]
    print_text();

    Ok(())
}

/// Remove a convenience variable.
#[command(
    names = ["unset"],
    category = "symbols, types, and expressions",
    kind = Host,
    python = none,
)]
fn unset(state: &mut ReplState<'_>, #[arg(name = "$name")] variable: String) -> Result<()> {
    let name = variable.strip_prefix('$').unwrap_or(&variable);
    if state.ctx.target.user_vars.remove(name).is_some() {
        outln!("unset ${}\n", name);
    } else {
        error!("no such variable: ${}", name);
    }

    Ok(())
}

impl ReplState<'_> {
    /// Render an evaluated expression. A raw expression is a u64 and prints as
    /// an address, the way every earlier release did. A typed expression
    /// prints its type and the same value text `dt` and the editor show, so
    /// `? index` on an `int` is not mistaken for an address.
    fn print_expr_value(&mut self, value: &ExprValue) -> Result<()> {
        let Some(type_data) = value.type_data() else {
            let raw = value.scalar(&self.ctx.target)?;
            self.ctx.target.set_results(vec![raw.0], self.line.clone());
            outln!("{}", ui::addr(raw.0));
            return Ok(());
        };

        let byte_size = value.byte_size();
        let type_name = type_data.to_string();
        let scalar = value.scalar(&self.ctx.target);
        let view = TypeView::new(self.ctx);
        if let Ok(scalar) = scalar {
            let text = view.scalar_text(scalar.0, type_data, byte_size);
            outln!("{} {}", ui::muted(&type_name), text);
            self.ctx
                .target
                .set_results(vec![scalar.0], self.line.clone());
            return Ok(());
        }

        // An aggregate has no scalar value. Where it lives in memory, render
        // what `dt` would render for it and name the command that expands it;
        // the result slot holds its address so `$0` stays useful.
        let address = match value.address() {
            Ok(address) => address,
            // Report why the value has no number, not why it has no address:
            // an unavailable local must say it was optimized out.
            Err(_) => return Err(scalar.unwrap_err()),
        };
        let field = FieldInfo {
            offset: 0,
            size: byte_size.unwrap_or_default(),
            type_data: type_data.clone(),
        };
        let text = view.value_text(address, &field);
        if text.is_empty() {
            let expand = match nested_layout_name(type_data) {
                Some(layout) => format!("dt {layout} {:#x}", address.0),
                None => format!("db {:#x} L{:#x}", address.0, byte_size.unwrap_or(8)),
            };
            outln!(
                "{} at {}   {}",
                ui::muted(&type_name),
                ui::addr(address.0),
                ui::muted(&expand)
            );
        } else {
            outln!("{} {}", ui::muted(&type_name), text);
        }
        self.ctx
            .target
            .set_results(vec![address.0], self.line.clone());
        Ok(())
    }

    /// Print `count` lines of `path` from 1-based line `first`, marking
    /// `current` with `>`. Returns the line after the last one printed.
    fn list_source(&mut self, path: &Path, first: u32, count: u32, current: Option<u32>) -> u32 {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) => {
                error!("failed to read {}: {error}", path.display());
                return first;
            }
        };
        let lines: Vec<&str> = text.lines().collect();
        let first = first.max(1);
        if first as usize > lines.len() {
            outln!(
                "{}: line {first} is past the end ({} lines)\n",
                path.display(),
                lines.len()
            );
            return first;
        }
        let last = (first as usize + count as usize - 1).min(lines.len());
        let shown = &lines[first as usize - 1..last];
        let print_text = || {
            outln!("{}:", path.display());
            for (number, line) in (first as usize..).zip(shown) {
                let mark = if Some(number as u32) == current {
                    '>'
                } else {
                    ' '
                };
                outln!("{mark}{number:>6}: {line}");
            }
            outln!();
        };
        #[cfg(feature = "cli")]
        native::render(
            || native::source::view(path, shown, first, current),
            print_text,
        );
        #[cfg(not(feature = "cli"))]
        print_text();
        let next = last as u32 + 1;
        self.source_cursor = Some((path.to_path_buf(), next));
        next
    }
}

/// The `lm` table: one row per module.
fn print_modules(listings: &[ModuleListing], timestamp: bool) {
    let mut builder = Builder::default();
    let mut header = vec![
        "Start".to_string(),
        "End".to_string(),
        "Module".to_string(),
        "Version".to_string(),
        "Symbols".to_string(),
        "Source".to_string(),
    ];
    if timestamp {
        header.push("Timestamp".to_string());
    }
    header.push("Image".to_string());
    builder.push_record(header);

    for listing in listings {
        let module = &listing.module;
        let mut row = vec![
            ui::addr(module.base_address.0).to_string(),
            ui::addr(module.end_address().0).to_string(),
            module.short_name.to_string(),
            module.file_version.as_deref().unwrap_or("-").to_string(),
            listing
                .symbols
                .status
                .as_ref()
                .map(|status| status.label().to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            listing
                .symbols
                .source
                .as_ref()
                .map(|source| source.label().to_string())
                .unwrap_or_else(|| "-".to_string()),
        ];
        if timestamp {
            row.push(
                module
                    .time_date_stamp
                    .map(|stamp| format!("{stamp:#x}"))
                    .unwrap_or_else(|| "-".to_string()),
            );
        }
        row.push(module.name.clone());
        builder.push_record(row);
    }
    print_padded_table(builder);
}

/// `lm v`: each module's range and symbol details.
fn print_module_details(listings: &[ModuleListing], timestamp: bool) {
    for listing in listings {
        let module = &listing.module;
        outln!("{} ({})", module.name, module.short_name);
        outln!(
            "  range   : {} - {}",
            ui::addr(module.base_address.0),
            ui::addr(module.end_address().0)
        );
        outln!(
            "  symbols : {}",
            listing
                .symbols
                .status
                .as_ref()
                .map(|status| status.label().to_string())
                .unwrap_or_else(|| "unknown".to_string())
        );
        outln!(
            "  source  : {}",
            listing
                .symbols
                .source
                .as_ref()
                .map(|source| source.label().to_string())
                .unwrap_or_else(|| "-".to_string())
        );
        match listing.symbols.pdb {
            Some(identity) => {
                outln!("  pdb guid: {:032X}", identity.guid);
                outln!("  pdb age : {}", identity.age);
            }
            None => outln!("  pdb     : -"),
        }
        if let Some(ModuleSymbolStatus::Failed(reason)) = &listing.symbols.status {
            outln!("  error   : {}", reason);
        }
        if timestamp {
            outln!(
                "  timestamp: {}",
                module
                    .time_date_stamp
                    .map(|stamp| format!("{stamp:#x}"))
                    .unwrap_or_else(|| "-".to_string())
            );
        }
        outln!();
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct LsArgs {
    /// `.`: list from the current line rather than continuing.
    restart: bool,
    first: Option<u32>,
    count: Option<u32>,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct LsaArgs {
    address: Option<String>,
    first: Option<i64>,
    count: Option<u32>,
}

/// WinDbg's `ls [.] [first][,count]`: the line and count are decimal, and
/// the comma may carry spaces around it (`ls 10, 5`, `ls ,20`).
fn parse_ls_args<S: AsRef<str>>(argv: &[S]) -> Option<LsArgs> {
    let mut spec = LsArgs::default();
    let joined = argv.iter().map(AsRef::as_ref).collect::<Vec<_>>().join(" ");
    let mut rest = joined.trim();
    if let Some(tail) = rest.strip_prefix('.') {
        spec.restart = true;
        rest = tail.trim_start();
    }
    if rest.is_empty() {
        return Some(spec);
    }
    let (first, count) = match rest.split_once(',') {
        Some((first, count)) => (first.trim(), Some(count.trim())),
        None => (rest, None),
    };
    if !first.is_empty() {
        spec.first = Some(first.parse().ok().filter(|line| *line > 0)?);
    }
    if let Some(count) = count {
        spec.count = Some(count.parse().ok().filter(|count| *count > 0)?);
    }
    Some(spec)
}

/// WinDbg's `lsa [address][,first][,count]`: the address is an expression
/// (so it may contain spaces), the offset is a signed decimal, the count a
/// positive decimal.
fn parse_lsa_args<S: AsRef<str>>(argv: &[S]) -> Option<LsaArgs> {
    let joined = argv.iter().map(AsRef::as_ref).collect::<Vec<_>>().join(" ");
    let mut parts = joined.split(',').map(str::trim);
    let mut spec = LsaArgs {
        address: parts
            .next()
            .filter(|text| !text.is_empty())
            .map(str::to_string),
        ..LsaArgs::default()
    };
    if let Some(first) = parts.next().filter(|text| !text.is_empty()) {
        spec.first = Some(first.parse().ok()?);
    }
    if let Some(count) = parts.next().filter(|text| !text.is_empty()) {
        spec.count = Some(count.parse().ok().filter(|count| *count > 0)?);
    }
    if parts.next().is_some() {
        return None;
    }
    Some(spec)
}

#[cfg(test)]
mod tests {
    use super::{LsArgs, LsaArgs, parse_ls_args, parse_lsa_args};
    use crate::base::output::capture;
    use crate::base::types::VirtAddr;
    use crate::hosts::repl::{CommandStyle, ReplState, parse_command};
    use crate::nt::layout::{FieldInfo, ParsedType, TypeInfo};
    use crate::nt::symbols::parse_source_paths;
    use crate::session::session_over_memory;

    #[test]
    fn source_listing_arguments_follow_windbg() {
        let ls = |argv: &[&str]| parse_ls_args(argv);
        assert_eq!(ls(&[]), Some(LsArgs::default()));
        assert_eq!(
            ls(&["."]),
            Some(LsArgs {
                restart: true,
                ..LsArgs::default()
            })
        );
        assert_eq!(
            ls(&["120,", "5"]),
            Some(LsArgs {
                restart: false,
                first: Some(120),
                count: Some(5),
            })
        );
        assert_eq!(
            ls(&[",20"]),
            Some(LsArgs {
                count: Some(20),
                ..LsArgs::default()
            })
        );
        assert_eq!(ls(&["0"]), None);
        assert_eq!(ls(&["12,0"]), None);

        let lsa = |argv: &[&str]| parse_lsa_args(argv);
        assert_eq!(lsa(&[]), Some(LsaArgs::default()));
        assert_eq!(
            lsa(&["nt!KeBugCheckEx", "+", "0x10,-2,4"]),
            Some(LsaArgs {
                address: Some("nt!KeBugCheckEx + 0x10".to_string()),
                first: Some(-2),
                count: Some(4),
            })
        );
        assert_eq!(
            lsa(&[",,3"]),
            Some(LsaArgs {
                count: Some(3),
                ..LsaArgs::default()
            })
        );
        assert_eq!(lsa(&["1000,1,2,3"]), None);
    }

    /// `lsa` lists around the address's line and marks it; a following bare
    /// `ls` picks up after the listed window.
    #[test]
    fn lsa_marks_the_line_and_ls_continues_after_it() {
        let dir = std::env::temp_dir().join(format!("ntoseye-ls-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let source = dir.join("driver.c");
        let text: String = (1..=30).map(|n| format!("line {n}\n")).collect();
        std::fs::write(&source, text).unwrap();

        let mut session = session_over_memory(0x1000, &[0x90; 0x100]);
        let dtb = session.target.current_dtb();
        session.target.symbols.inject_source_lines_for_test(
            7,
            dtb,
            VirtAddr(0x1000),
            0x100,
            "D:\\src\\driver.c",
            &[(0x0, Some(0x10), 12), (0x10, Some(0x10), 20)],
        );
        session
            .target
            .symbols
            .set_source_paths(parse_source_paths(&[format!("D:\\src={}", dir.display())]));
        let mut state = ReplState::for_oneshot(&mut session);

        let (result, text) = capture(|| state.dispatch_line("lsa 0x1014,-1,3"));
        result.unwrap();
        let listed: Vec<&str> = text.lines().skip(1).take(3).collect();
        assert_eq!(
            listed,
            ["     19: line 19", ">    20: line 20", "     21: line 21"],
            "{text}"
        );

        let (result, text) = capture(|| state.dispatch_line("ls ,2"));
        result.unwrap();
        let listed: Vec<&str> = text.lines().skip(1).take(2).collect();
        assert_eq!(listed, ["     22: line 22", "     23: line 23"], "{text}");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ev_keeps_expression_tail() {
        let parsed = parse_command("ev rax + rbx").unwrap().unwrap();
        let invocation = parsed.invocation(CommandStyle::ExpressionTail).unwrap();
        assert_eq!(invocation.raw_tail, "rax + rbx");
        assert!(invocation.argv.is_empty());
    }

    #[test]
    fn ev_reads_each_masm_width() {
        let memory = [0x78, 0x56, 0x34, 0x12, 0xaa, 0xbb, 0xcc, 0xdd];
        let mut session = session_over_memory(0x1000, &memory);
        let mut state = ReplState::for_oneshot(&mut session);
        for (line, expected) in [
            ("? by(1000)", "0000000000000078"),
            ("? wo(1000)", "0000000000005678"),
            ("? dwo(1000)", "0000000012345678"),
            ("? qwo(1000)", "ddccbbaa12345678"),
            ("? poi(1000)", "ddccbbaa12345678"),
        ] {
            let (result, text) = capture(|| state.dispatch_line(line));
            result.unwrap();
            assert!(text.contains(expected), "{line} printed {text:?}");
        }
    }

    #[test]
    fn ev_renders_typed_values_with_their_type() {
        let mut memory = [0u8; 0x20];
        memory[..4].copy_from_slice(&0x12345678u32.to_le_bytes());
        memory[8..16].copy_from_slice(&0x1000u64.to_le_bytes());
        let mut session = session_over_memory(0x1000, &memory);
        let dtb = session.target.current_dtb();
        session.target.symbols.set_kernel(Some(1), dtb);
        session.target.symbols.inject_module_for_test(
            1,
            vec![TypeInfo {
                name: "_NODE".to_string(),
                pointer_size: 8,
                size: 0x10,
                fields: [(
                    "Value".to_string(),
                    FieldInfo {
                        offset: 0,
                        size: 4,
                        type_data: ParsedType::Primitive("ULONG".to_string()),
                    },
                )]
                .into_iter()
                .collect(),
            }],
            &[],
        );
        let mut state = ReplState::for_oneshot(&mut session);

        let (result, text) = capture(|| state.dispatch_line("? ((_NODE*)1000)->Value"));
        result.unwrap();
        assert!(text.contains("ULONG 0x12345678"), "field value: {text:?}");

        let (result, text) = capture(|| state.dispatch_line("? &((_NODE*)1000)->Value"));
        result.unwrap();
        assert!(text.contains("ULONG* 0x1000"), "field address: {text:?}");

        let (result, text) = capture(|| state.dispatch_line("? *((_NODE*)1000)"));
        result.unwrap();
        assert!(
            text.contains("_NODE at 0000000000001000") && text.contains("dt _NODE 0x1000"),
            "aggregate: {text:?}"
        );
    }
}
