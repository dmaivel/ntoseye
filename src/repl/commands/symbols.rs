use std::collections::HashSet;
use std::path::{Path, PathBuf};

use tabled::builder::Builder;

use owo_colors::OwoColorize;

use crate::breakpoints::BreakpointManager;
use crate::error::Result;
use crate::expr::{Expr, ExprValue};
use crate::guest::ModuleInfo;
use crate::layout::{FieldInfo, nested_layout_name};
use crate::symbols::{
    CodeFrame, LocalSourceState, ModuleSymbolSource, ModuleSymbolStatus, PdbIdentity,
    SourceLocation, format_symbol_with_offset, glob_matches, parse_source_paths,
    parse_symbol_sources,
};
use crate::target::UserVar;
use crate::types::VirtAddr;
use crate::typeview::TypeView;
use crate::ui;

use crate::repl::*;

repl_command! {
    cmd_x;
    names: ["x"],
    usage: "x <query>  or  x <module>!<query>",
    summary: "Search for symbols by fuzzy name match.",
    details: "`*` and `?` are glob characters. The operators are `^` prefix, `$` suffix, `'` exact match, and `!` negation. If you separate terms with spaces, a symbol must match all the terms.",
    completion: Symbol,
}

repl_command! {
    cmd_ln;
    names: ["ln"],
    usage: "ln <address>",
    summary: "List the symbol nearest to an address.",
    completion: Expression,
}

repl_command! {
    cmd_ev;
    names: ["?", "ev"],
    usage: "? <expression>",
    summary: "Evaluate an expression.",
    details: "Memory read functions and their sizes in bytes: by() 1, wo() 2, dwo() 4, qwo()/poi() 8. `&expr` gives the address of `expr`. `->` and `.` give field values.",
    completion: Expression,
    style: ExpressionTail,
}

repl_command! {
    cmd_set;
    names: ["set"],
    usage: "set $<name> <expression>",
    summary: "Define a convenience variable that you can use in expressions as $<name>.",
    completion: [None, Expression],
}

repl_command! {
    cmd_vars();
    names: ["vars"],
    usage: "vars",
    summary: "List the defined convenience variables and result slots.",
}

repl_command! {
    cmd_unset;
    names: ["unset"],
    usage: "unset $<name>",
    summary: "Remove a convenience variable.",
}

repl_command! {
    cmd_sympath;
    names: [".sympath"],
    usage: ".sympath [<directory|http-server> ...]",
    summary: "Show or replace the ordered symbol source path.",
}

repl_command! {
    cmd_sympath_append;
    names: [".sympath+"],
    usage: ".sympath+ <directory|http-server> ...",
    summary: "Add entries to the end of the ordered symbol source path.",
}

repl_command! {
    cmd_symfix();
    names: [".symfix"],
    usage: ".symfix",
    summary: "Set the symbol source path back to the defaults, the ntoseye cache and the Microsoft symbol server.",
}

repl_command! {
    cmd_srcpath;
    names: [".srcpath"],
    usage: ".srcpath [<local-root|recorded-prefix=local-root> ...]",
    summary: "Show or replace the ordered local source path mappings.",
    details: "A local root contains the source tree, and a recorded path such as C:\\Users\\me\\repos\\MyDriver\\src\\queue.c maps to a file under the root. ntoseye uses the longest trailing part of the recorded path that names a file under the root, so root/src/queue.c comes before root/queue.c. It tries an exact match first, and then a match that ignores case. A recorded-prefix=local-root mapping replaces the recorded prefix with the local root. If the PDB records the checksum of a source file, ntoseye shows only a file with that checksum, and reports a file with a different checksum as not the compiled source.",
}

repl_command! {
    cmd_srcpath_append;
    names: [".srcpath+"],
    usage: ".srcpath+ <local-root|recorded-prefix=local-root> ...",
    summary: "Add local source path mappings to the end of the list.",
    details: "ntoseye tries the mappings in order, as .srcpath describes.",
}

repl_command! {
    cmd_ls;
    names: ["ls"],
    usage: "ls [.] [first][,count]",
    summary: "List source lines of the file for the current scope.",
    details: "With no arguments, the command continues after the lines that the previous ls or lsa showed, and `.` starts again at the current line. `first` is a line number, and `count` is 10 by default. The file is the file of the source line of the selected frame, which for an inline frame is in the inlined function. ntoseye finds the file through .srcpath.",
}

repl_command! {
    cmd_lsa;
    names: ["lsa"],
    usage: "lsa [address][,first][,count]",
    summary: "List source lines around an address.",
    details: "By default, the command uses the source line of the selected frame, and shows twelve lines in total, starting five lines before that line. If you give an address, the command uses the line of the innermost frame at that address, which is the inlined function if a function is inlined there. `first` is an offset from that line, with a negative value for lines before it. The command marks the line with `>`.",
    completion: Expression,
}

repl_command! {
    cmd_dv;
    names: ["dv"],
    usage: "dv [address]",
    summary: "Show the locals and parameters of the selected frame.",
    details: "Each frame shows only its own variables. For an inline frame, these are the variables of the inlined function, and the frame that contains the inlined call shows the variables of its procedure but not those of the calls that are inlined into it. Without an address, the command uses the frame that .frame selected or, if no frame is selected, the innermost frame at the stop. With an address, it uses the innermost frame at that address.",
    completion: Expression,
}

repl_command! {
    cmd_reload_symbols;
    names: [".reload"],
    usage: ".reload [module]",
    summary: "Reload symbols for one module or for all modules in the current scope.",
}

repl_command! {
    cmd_ld;
    names: ["ld"],
    usage: "ld <module>",
    summary: "Force ntoseye to select the symbol source and index the symbols for one module.",
}

repl_command! {
    cmd_fetchimage;
    names: [".fetchimage"],
    usage: ".fetchimage <module>  or  .fetchimage /f <file>",
    summary: "Download the PE file of a loaded module into the symbol cache, or copy a file into it, and print its path.",
    details: "The command finds the file by the TimeDateStamp and SizeOfImage values in the mapped PE header of the module. These values are the symbol-server key, so the file is the same build that is running, and a disassembler database that you make from this file rebases onto the live module. A copy in a local directory on the symbol path, at its root or in symbol-store layout, is used before a symbol server. `/f` copies a PE file that you have into the cache under the key in its own header, with the name of its PDB, so ntoseye finds it for the module that runs that build. Use it for the Windows hypervisor, which Microsoft's symbol server does not have: copy C:\\Windows\\System32\\hvix64.exe from the guest and run `.fetchimage /f hvix64.exe`, after which the stacks of a vCPU in the hypervisor unwind through the file's unwind data.",
    completion: Symbol,
}

repl_command! {
    cmd_lm;
    names: ["lm"],
    usage: "lm [m <pattern>|a <address>] [v] [u|k] [t]",
    summary: "List loaded modules.",
    details: "`m` applies a module-name glob, and `v m` prints verbose symbol information. `a <address>` shows only the module that contains the address, a kernel module for a kernel address. `u` selects user modules, `k` selects kernel modules, and `t` adds timestamps.",
    completion: [None, Symbol, None, None],
}

repl_command! {
    cmd_lmv;
    names: ["lmv"],
    usage: "lmv [m <pattern>|a <address>|<name>] [u|k] [t]",
    summary: "Show the detailed symbol status and PDB identity of each module.",
    details: "This command is the same as `lm v` and uses the same filters, for example `lmv m nt`.",
}

impl ReplState<'_> {
    fn cmd_x(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(query) = invocation.arg(0) else {
            outln!("{}\n", command_help("x"));
            return Ok(());
        };
        // bounded purely for terminal-output sanity (resolution
        // is O(1) now); a huge match set just floods the screen
        const X_LIMIT: usize = 4096;
        let dtb = self.ctx.target.current_dtb();
        // `module!query` scopes the search to one module; a bare query
        // fuzzy-matches the cached merged index, whose names are already
        // module-qualified.
        let names: Vec<String> = match query.split_once('!') {
            Some((module, q)) => self
                .ctx
                .target
                .symbols
                .search_symbols_in_module(dtb, module, q, X_LIMIT)
                .into_iter()
                .map(|name| format!("{module}!{name}"))
                .collect(),
            None => self.caches.symbols.read().unwrap().search(query, X_LIMIT),
        };
        let truncated = names.len() >= X_LIMIT;
        let mut matches: Vec<(u64, String)> = Vec::new();
        for name in &names {
            let bare = name
                .rsplit_once('!')
                .map_or(name.as_str(), |(_, bare)| bare);
            let mut seen = HashSet::new();
            for candidate in self.ctx.target.symbols.find_symbol_candidates(dtb, name) {
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
            self.ctx.target.set_results(Vec::new(), self.line.clone());
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
        self.ctx.target.set_results(hits, self.line.clone());

        Ok(())
    }

    fn cmd_ln(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(arg) = invocation.arg(0) else {
            outln!("{}\n", command_help("ln"));
            return Ok(());
        };
        let Some(addr) = self.eval_or_report(arg) else {
            return Ok(());
        };
        match self.ctx.target.nearest_symbol_current_context(addr) {
            Some((module, sym, offset)) => {
                let label = format_symbol_with_offset(&module, &sym, offset);
                outln!("{}  {}\n", ui::addr(addr.0), ui::symbol(&label));
                // $0 = the symbol's base address (the resolved target)
                self.ctx
                    .target
                    .set_results(vec![(addr - offset as u64).0], self.line.clone());
            }
            None => {
                outln!("no symbol found for {}\n", ui::addr(addr.0));
            }
        }

        Ok(())
    }

    fn cmd_ev(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let expr_str = invocation.raw_tail;
        if expr_str.is_empty() {
            outln!("{}\n", command_help("ev"));
            return Ok(());
        }

        let value = match Expr::parse_with_radix(expr_str, self.radix)
            .and_then(|expr| expr.evaluate(&self.ctx.target))
        {
            Ok(value) => value,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };
        if let Err(e) = self.print_expr_value(&value) {
            error!("{}", e);
        }

        Ok(())
    }

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

    fn cmd_set(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let rest = invocation.join_args(0);
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
        match Expr::eval_with_radix(&source, &self.ctx.target, self.radix) {
            Ok(v) => {
                self.ctx
                    .target
                    .user_vars
                    .insert(name.to_string(), UserVar { value: v.0, source });
                outln!("${} = {}\n", name, ui::addr(v.0));
            }
            Err(e) => error!("{}", e),
        }

        Ok(())
    }

    fn cmd_vars(&mut self) -> Result<()> {
        let builtins = self.ctx.target.builtin_variables();
        if self.ctx.target.user_vars.is_empty()
            && self.ctx.target.results.is_empty()
            && builtins.is_empty()
        {
            outln!("no variables defined\n");
            return Ok(());
        }
        let mut names: Vec<&String> = self.ctx.target.user_vars.keys().collect();
        names.sort();
        let user: Vec<(&str, &UserVar)> = names
            .into_iter()
            .map(|name| (name.as_str(), &self.ctx.target.user_vars[name]))
            .collect();
        let results = self.ctx.target.results.len();
        let origin = self.ctx.target.results_origin.as_deref();
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

    fn cmd_unset(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(arg) = invocation.arg(0) else {
            outln!("{}\n", command_help("unset"));
            return Ok(());
        };
        let name = arg.strip_prefix('$').unwrap_or(arg);
        if self.ctx.target.user_vars.remove(name).is_some() {
            outln!("unset ${}\n", name);
        } else {
            error!("no such variable: ${}", name);
        }

        Ok(())
    }

    fn cmd_sympath(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if invocation.argv.is_empty() {
            self.print_symbol_sources();
            return Ok(());
        }

        self.ctx
            .target
            .symbols
            .set_symbol_sources(parse_symbol_sources(&invocation.argv));
        self.print_symbol_sources();
        Ok(())
    }

    fn cmd_sympath_append(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if invocation.argv.is_empty() {
            outln!("{}\n", command_help(".sympath+"));
            return Ok(());
        }

        for source in parse_symbol_sources(&invocation.argv) {
            self.ctx.target.symbols.append_symbol_source(source);
        }
        self.print_symbol_sources();
        Ok(())
    }

    fn cmd_symfix(&mut self) -> Result<()> {
        self.ctx.target.symbols.reset_symbol_sources();
        self.print_symbol_sources();
        Ok(())
    }

    fn print_symbol_sources(&self) {
        outln!("symbol sources:");
        for (index, source) in self.ctx.target.symbols.symbol_sources().iter().enumerate() {
            outln!("  {:>2}: {}", index, source);
        }
        outln!();
    }

    fn cmd_srcpath(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if !invocation.argv.is_empty() {
            self.ctx
                .target
                .symbols
                .set_source_paths(parse_source_paths(&invocation.argv));
        }
        self.print_source_paths();
        Ok(())
    }

    fn cmd_srcpath_append(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if invocation.argv.is_empty() {
            outln!("{}\n", command_help(".srcpath+"));
            return Ok(());
        }
        for mapping in parse_source_paths(&invocation.argv) {
            self.ctx.target.symbols.append_source_path(mapping);
        }
        self.print_source_paths();
        Ok(())
    }

    fn print_source_paths(&self) {
        let paths = self.ctx.target.symbols.source_paths();
        if paths.is_empty() {
            outln!("source paths: <empty>\n");
            return;
        }
        outln!("source paths:");
        for (index, path) in paths.iter().enumerate() {
            outln!("  {:>2}: {}", index, path);
        }
        outln!();
    }

    /// The selected frame's IP, else the live one.
    fn scope_ip(&self) -> Option<VirtAddr> {
        self.ctx
            .target
            .selected_frame
            .as_ref()
            .map(|frame| frame.ip)
            .or_else(|| {
                self.ctx
                    .target
                    .register_value(self.ctx.target.instruction_pointer_register())
            })
            .map(VirtAddr)
    }

    /// The source line of `frame`, with its local file: the error names what
    /// is missing (line info, or the file `.srcpath` should map).
    fn source_file_at(
        &self,
        frame: CodeFrame,
    ) -> std::result::Result<(PathBuf, SourceLocation), String> {
        let address = frame.address;
        let Some(location) = self.ctx.target.frame_source_location(frame) else {
            return Err(format!(
                "no source line information for {}",
                ui::addr(address.0)
            ));
        };
        match &location.local {
            Some(local) if local.state == LocalSourceState::Found => {
                Ok((local.path.clone(), location))
            }
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

    fn cmd_ls(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        const DEFAULT_COUNT: u32 = 10;
        let Some(spec) = parse_ls_args(&invocation.argv) else {
            outln!("{}\n", command_help("ls"));
            return Ok(());
        };
        let count = spec.count.unwrap_or(DEFAULT_COUNT);
        let (path, first, current) = match (spec.first, spec.restart, &self.source_cursor) {
            (None, false, Some((path, next))) => (path.clone(), *next, None),
            _ => {
                let Some(frame) = self.ctx.target.scope_frame() else {
                    error!("ls requires a halted register context");
                    return Ok(());
                };
                let (path, location) = match self.source_file_at(frame) {
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
        self.list_source(&path, first, count, current);
        Ok(())
    }

    fn cmd_lsa(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        const DEFAULT_FIRST: i64 = -5;
        const DEFAULT_COUNT: u32 = 12;
        let Some(spec) = parse_lsa_args(&invocation.argv) else {
            outln!("{}\n", command_help("lsa"));
            return Ok(());
        };
        let frame = match spec.address {
            Some(text) => match self.eval_or_report(&text) {
                Some(address) => CodeFrame::at(address),
                None => return Ok(()),
            },
            None => match self.ctx.target.scope_frame() {
                Some(frame) => frame,
                None => {
                    error!("lsa requires an address or a halted register context");
                    return Ok(());
                }
            },
        };
        let (path, location) = match self.source_file_at(frame) {
            Ok(found) => found,
            Err(message) => {
                error!("{message}");
                return Ok(());
            }
        };
        let first = (i64::from(location.line) + spec.first.unwrap_or(DEFAULT_FIRST)).max(1) as u32;
        self.list_source(
            &path,
            first,
            spec.count.unwrap_or(DEFAULT_COUNT),
            Some(location.line),
        );
        Ok(())
    }

    fn cmd_dv(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let (address, frame) = if let Some(arg) = invocation.arg(0) {
            match self.eval_or_report(arg) {
                Some(address) => (address, CodeFrame::at(address)),
                None => return Ok(()),
            }
        } else {
            let (Some(rip), Some(frame)) = (self.scope_ip(), self.ctx.target.scope_frame()) else {
                error!("dv requires a halted register context or an explicit address");
                return Ok(());
            };
            (rip, frame)
        };

        let Some(locals) = self.ctx.target.frame_locals(frame)? else {
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
            match self
                .ctx
                .target
                .resolve_procedure_local_value(address, local)
            {
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

    fn cmd_reload_symbols(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.reload_symbols(invocation.arg(0));
        Ok(())
    }

    fn cmd_ld(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(module) = invocation.arg(0) else {
            outln!("{}\n", command_help("ld"));
            return Ok(());
        };
        self.reload_symbols(Some(module));
        Ok(())
    }

    fn cmd_fetchimage(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(name) = invocation.arg(0) else {
            outln!("{}\n", command_help(".fetchimage"));
            return Ok(());
        };
        let fetched = if name.eq_ignore_ascii_case("/f") {
            let Some(file) = invocation.arg(1) else {
                outln!("{}\n", command_help(".fetchimage"));
                return Ok(());
            };
            self.ctx.target.symbols.import_image(Path::new(file))
        } else {
            self.ctx.target.fetch_module_image(name)
        };
        match fetched {
            Ok(path) => outln!("{}\n", path.display()),
            Err(err) => error!("{}", err),
        }
        Ok(())
    }

    fn reload_symbols(&mut self, module: Option<&str>) {
        match self.ctx.target.reload_module_symbols(module) {
            Ok(report) => {
                print_module_symbol_report(&report);
                *self.caches.symbols.write().unwrap() = self.ctx.target.current_symbol_index();
                *self.caches.types.write().unwrap() = self.ctx.target.current_types_index();
                if let Err(err) = self
                    .ctx
                    .breakpoints
                    .resolve_symbolic(&mut *self.ctx.backend, &self.ctx.target)
                {
                    error!("symbolic breakpoint re-resolution failed: {}", err);
                }
                self.caches.refresh_breakpoints(&self.ctx.breakpoints);
            }
            Err(err) => error!("symbol reload failed: {}", err),
        }
    }

    fn cmd_lm(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.list_modules(invocation, false)
    }

    /// `lmv`: `lm v`, so it takes the same filters (`lmv m nt`).
    fn cmd_lmv(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.list_modules(invocation, true)
    }

    fn list_modules(&mut self, invocation: CommandInvocation<'_>, mut verbose: bool) -> Result<()> {
        let mut pattern = None;
        let mut user = false;
        let mut kernel = false;
        let mut timestamp = false;
        let mut glob_filter = false;
        let mut containing = None;
        let mut index = 0;
        while index < invocation.argv.len() {
            let arg = invocation.arg(index).unwrap_or_default();
            let lower = arg.to_ascii_lowercase();
            match lower.as_str() {
                "v" => verbose = true,
                "u" => user = true,
                "k" => kernel = true,
                "t" => timestamp = true,
                "m" => {
                    glob_filter = true;
                    index += 1;
                    pattern = invocation.arg(index);
                }
                "a" => {
                    index += 1;
                    let Some(text) = invocation.arg(index) else {
                        outln!("{}\n", command_help(invocation.name));
                        return Ok(());
                    };
                    let Some(address) = self.eval_or_report(text) else {
                        return Ok(());
                    };
                    containing = Some(address);
                }
                _ if pattern.is_none() => pattern = Some(arg),
                _ => {}
            }
            index += 1;
        }
        // An address names its own list: a kernel address is in a kernel
        // module even while a process is selected, as in WinDbg.
        if let Some(address) = containing
            && !user
        {
            kernel |= BreakpointManager::is_kernel_space(self.ctx.target.arch(), address);
        }
        let dtb = if kernel {
            self.ctx.target.kernel_dtb()
        } else {
            self.ctx.target.process_dtb()
        };
        let modules = if kernel {
            self.ctx.target.kernel_modules_with_versions()
        } else if user {
            if self.ctx.target.attached_process().is_none() {
                Ok(Vec::new())
            } else {
                self.ctx.target.modules_with_versions()
            }
        } else {
            self.ctx.target.modules_with_versions()
        };
        match modules {
            Ok(modules) => {
                let matches = |module: &ModuleInfo| {
                    containing.is_none_or(|address| module.contains_address(address))
                        && pattern.is_none_or(|pattern| {
                            if glob_filter {
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
                let symbols = &self.ctx.target.symbols;
                let listings = modules
                    .into_iter()
                    .filter(|module| matches(module))
                    .map(|module| ModuleListing {
                        status: symbols.module_symbol_status(dtb, module.base_address),
                        source: symbols.module_symbol_source(dtb, module.base_address),
                        pdb: if verbose {
                            symbols.module_pdb_identity(dtb, module.base_address)
                        } else {
                            None
                        },
                        module,
                    })
                    .collect::<Vec<_>>();
                if listings.is_empty() {
                    outln!("{}\n", "no matching modules".bright_black());
                } else if verbose {
                    #[cfg(feature = "cli")]
                    native::render(
                        || native::lists::module_details(&listings, timestamp),
                        || print_module_details(&listings, timestamp),
                    );
                    #[cfg(not(feature = "cli"))]
                    print_module_details(&listings, timestamp);
                } else {
                    #[cfg(feature = "cli")]
                    native::render(
                        || native::lists::modules(&listings, timestamp),
                        || print_modules(&listings, timestamp),
                    );
                    #[cfg(not(feature = "cli"))]
                    print_modules(&listings, timestamp);
                }
            }
            Err(e) => {
                error!("failed to list modules: {}", e);
            }
        }

        Ok(())
    }
}

/// A module `lm` lists with its symbols' state, gathered once for either
/// renderer.
pub struct ModuleListing {
    pub module: ModuleInfo,
    pub status: Option<ModuleSymbolStatus>,
    pub source: Option<ModuleSymbolSource>,
    /// The PDB identity, looked up only for `lm v`.
    pub pdb: Option<PdbIdentity>,
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
                .status
                .as_ref()
                .map(|status| status.label().to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            listing
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
                .status
                .as_ref()
                .map(|status| status.label().to_string())
                .unwrap_or_else(|| "unknown".to_string())
        );
        outln!(
            "  source  : {}",
            listing
                .source
                .as_ref()
                .map(|source| source.label().to_string())
                .unwrap_or_else(|| "-".to_string())
        );
        match listing.pdb {
            Some(identity) => {
                outln!("  pdb guid: {:032X}", identity.guid);
                outln!("  pdb age : {}", identity.age);
            }
            None => outln!("  pdb     : -"),
        }
        if let Some(ModuleSymbolStatus::Failed(reason)) = &listing.status {
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
    use crate::layout::{FieldInfo, ParsedType, TypeInfo};
    use crate::output::capture;
    use crate::repl::{CommandStyle, ReplState, parse_command};
    use crate::session::session_over_memory;
    use crate::symbols::parse_source_paths;
    use crate::types::VirtAddr;

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
