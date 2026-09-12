use std::collections::HashSet;

use crate::error::Result;
use crate::expr::Expr;
use crate::symbols::{
    LocalVariableLocation, ModuleSymbolStatus, SourcePathMapping, SymbolSource,
    format_symbol_with_offset,
};
use crate::target::UserVar;
use crate::types::VirtAddr;
use crate::ui;

use crate::repl::*;

repl_command! {
    cmd_x;
    names: ["x"],
    usage: "x <query>  or  x <module>!<query>",
    summary: "Fuzzy-search symbols by name.",
    details: "operators: ^prefix  suffix$  'exact  !negate  (space = AND)",
    completion: Symbol,
}

repl_command! {
    cmd_ln;
    names: ["ln"],
    usage: "ln <address>",
    summary: "List the nearest symbol to an address.",
    completion: Expression,
}

repl_command! {
    cmd_ev;
    names: ["?", "ev"],
    usage: "? <expression>",
    summary: "Evaluate an expression.",
    completion: Expression,
    style: ExpressionTail,
}

repl_command! {
    cmd_set;
    names: ["set"],
    usage: "set $<name> <expression>",
    summary: "Define a convenience variable usable in expressions as $<name>.",
    completion: [None, Expression],
}

repl_command! {
    cmd_vars();
    names: ["vars"],
    usage: "vars",
    summary: "List defined convenience variables and result slots.",
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
    summary: "Display or replace the ordered symbol source path.",
}

repl_command! {
    cmd_sympath_append;
    names: [".sympath+"],
    usage: ".sympath+ <directory|http-server> ...",
    summary: "Append entries to the ordered symbol source path.",
}

repl_command! {
    cmd_symfix();
    names: [".symfix"],
    usage: ".symfix",
    summary: "Restore the ntoseye cache and Microsoft symbol server defaults.",
}

repl_command! {
    cmd_srcpath;
    names: [".srcpath"],
    usage: ".srcpath [<local-root|recorded-prefix=local-root> ...]",
    summary: "Display or replace ordered local source path mappings.",
}

repl_command! {
    cmd_srcpath_append;
    names: [".srcpath+"],
    usage: ".srcpath+ <local-root|recorded-prefix=local-root> ...",
    summary: "Append local source path mappings.",
}

repl_command! {
    cmd_dv;
    names: ["dv"],
    usage: "dv [address]",
    summary: "Display procedure locals and parameters at an address.",
    completion: Expression,
}

repl_command! {
    cmd_reload_symbols;
    names: [".reload"],
    usage: ".reload [module]",
    summary: "Reload symbols for one module or every module in the current scope.",
}

repl_command! {
    cmd_ld;
    names: ["ld"],
    usage: "ld <module>",
    summary: "Force symbol source selection and indexing for one module.",
}

repl_command! {
    cmd_lmv;
    names: ["lmv"],
    usage: "lmv [module]",
    summary: "Display detailed per-module symbol status and PDB identity.",
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
        let mut hits: Vec<u64> = Vec::new();
        for name in &names {
            let bare = name
                .rsplit_once('!')
                .map_or(name.as_str(), |(_, bare)| bare);
            let mut seen = HashSet::new();
            for candidate in self.ctx.target.symbols.find_symbol_candidates(dtb, name) {
                if !seen.insert((candidate.module.to_ascii_lowercase(), candidate.address.0)) {
                    continue;
                }
                outln!(
                    "{}  {}",
                    ui::addr(candidate.address.0),
                    ui::symbol(&format!("{}!{}", candidate.module, bare))
                );
                hits.push(candidate.address.0);
            }
        }
        if hits.is_empty() {
            outln!("no symbols match '{}'", query);
        } else {
            outln!(
                "\n{} {}{} (in $0..${})",
                hits.len(),
                if hits.len() == 1 { "symbol" } else { "symbols" },
                if truncated {
                    ", truncated; refine query"
                } else {
                    ""
                },
                hits.len() - 1
            );
        }
        self.ctx.target.set_results(hits, self.line.clone());
        outln!();

        Ok(())
    }

    fn cmd_ln(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(arg) = invocation.arg(0) else {
            outln!("{}\n", command_help("ln"));
            return Ok(());
        };
        let addr = match Expr::eval_with_radix(arg, &self.ctx.target, self.radix) {
            Ok(a) => a,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };
        match self
            .ctx
            .target
            .symbols
            .find_closest_symbol_for_address(self.ctx.target.current_dtb(), addr)
        {
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

        match Expr::eval_with_radix(expr_str, &self.ctx.target, self.radix) {
            Ok(addr) => {
                self.ctx.target.set_results(vec![addr.0], self.line.clone());
                outln!("{}", ui::addr(addr.0));
            }
            Err(e) => error!("{}", e),
        }

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
        if !names.is_empty() {
            outln!("{}", ui::label("user"));
            for name in names {
                let var = &self.ctx.target.user_vars[name];
                outln!(
                    "  ${:<16} {}   {}",
                    name,
                    ui::addr(var.value),
                    ui::muted(&var.source)
                );
            }
        }
        if !self.ctx.target.results.is_empty() {
            if !self.ctx.target.user_vars.is_empty() {
                outln!();
            }
            let origin = self
                .ctx
                .target
                .results_origin
                .as_deref()
                .map(|cmd| format!("from: {}", cmd))
                .unwrap_or_default();
            outln!(
                "  {}   {}",
                ui::muted(&format!("$0..${}", self.ctx.target.results.len() - 1)),
                ui::muted(&origin)
            );
        }
        if !builtins.is_empty() {
            if !self.ctx.target.user_vars.is_empty() || !self.ctx.target.results.is_empty() {
                outln!();
            }
            outln!("{}", ui::label("builtins"));
            for var in builtins {
                outln!(
                    "  ${:<16} {}   {}",
                    var.name,
                    ui::addr(var.value),
                    ui::muted(var.source)
                );
            }
        }
        outln!();

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

    fn cmd_dv(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let address = if let Some(arg) = invocation.arg(0) {
            match Expr::eval_with_radix(arg, &self.ctx.target, self.radix) {
                Ok(address) => address,
                Err(err) => {
                    error!("{}", err);
                    return Ok(());
                }
            }
        } else {
            let Some(rip) = self
                .ctx
                .target
                .selected_frame
                .as_ref()
                .map(|frame| frame.ip)
                .or_else(|| self.ctx.target.register_value("rip"))
            else {
                error!("dv requires a halted register context or an explicit address");
                return Ok(());
            };
            VirtAddr(rip)
        };

        let Some(locals) = self.ctx.target.procedure_locals(address)? else {
            outln!("no procedure locals found at {}\n", ui::addr(address.0));
            return Ok(());
        };
        if locals.is_empty() {
            outln!("no locals in scope at {}\n", ui::addr(address.0));
            return Ok(());
        }

        for local in locals {
            let kind = if local.is_parameter { "param" } else { "local" };
            let location = format_local_location(&local.location);
            match self
                .ctx
                .target
                .resolve_procedure_local_value(address, &local)
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

    fn cmd_lmv(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let filter = invocation.arg(0);
        let dtb = self
            .ctx
            .target
            .current_process_info
            .as_ref()
            .map(|process| process.dtb)
            .unwrap_or_else(|| self.ctx.target.kernel_dtb());
        let modules = match self.ctx.target.modules() {
            Ok(modules) => modules,
            Err(err) => {
                error!("failed to enumerate modules: {}", err);
                return Ok(());
            }
        };
        let mut shown = 0;
        for module in modules {
            if filter.is_some_and(|filter| {
                !module.short_name.eq_ignore_ascii_case(filter)
                    && !module.name.eq_ignore_ascii_case(filter)
            }) {
                continue;
            }
            shown += 1;
            let status = self
                .ctx
                .target
                .symbols
                .module_symbol_status(dtb, module.base_address);
            let source = self
                .ctx
                .target
                .symbols
                .module_symbol_source(dtb, module.base_address);
            let identity = self
                .ctx
                .target
                .symbols
                .module_pdb_identity(dtb, module.base_address);
            outln!("{} ({})", module.name, module.short_name);
            outln!(
                "  range   : {} - {}",
                ui::addr(module.base_address.0),
                ui::addr(module.end_address().0)
            );
            outln!(
                "  symbols : {}",
                status
                    .as_ref()
                    .map(|status| status.label())
                    .unwrap_or("unknown")
            );
            outln!(
                "  source  : {}",
                source.as_ref().map(|source| source.label()).unwrap_or("-")
            );
            match identity {
                Some(identity) => {
                    outln!("  pdb guid: {:032X}", identity.guid);
                    outln!("  pdb age : {}", identity.age);
                }
                None => outln!("  pdb     : -"),
            }
            if let Some(ModuleSymbolStatus::Failed(reason)) = status {
                outln!("  error   : {}", reason);
            }
            outln!();
        }
        if shown == 0 {
            outln!("no matching modules\n");
        }
        Ok(())
    }
}

fn format_signed_hex(offset: i32) -> String {
    if offset < 0 {
        format!("-0x{:x}", offset.unsigned_abs())
    } else {
        format!("+0x{:x}", offset)
    }
}

fn format_local_location(location: &LocalVariableLocation) -> String {
    match location {
        LocalVariableLocation::Register { register } => register.clone(),
        LocalVariableLocation::RegisterRelative { register, offset } => {
            format!("[{}{}]", register, format_signed_hex(*offset))
        }
        LocalVariableLocation::FrameRelative { offset } => {
            format!("[frame{}]", format_signed_hex(*offset))
        }
        LocalVariableLocation::Unavailable { reason } => format!("<{}>", reason),
    }
}

fn parse_symbol_sources<S: AsRef<str>>(args: &[S]) -> Vec<SymbolSource> {
    args.iter()
        .flat_map(|arg| arg.as_ref().split(';'))
        .filter(|entry| !entry.is_empty())
        .flat_map(|entry| {
            if entry.eq_ignore_ascii_case("cache") || entry.starts_with("cache*") {
                vec![SymbolSource::Cache]
            } else if let Some(rest) = entry.strip_prefix("srv*") {
                let parts = rest.split('*').filter(|part| !part.is_empty());
                parts
                    .map(|part| {
                        if part.starts_with("http://") || part.starts_with("https://") {
                            SymbolSource::Http(part.trim_end_matches('/').to_string())
                        } else {
                            SymbolSource::LocalDirectory(part.into())
                        }
                    })
                    .collect()
            } else if entry.starts_with("http://") || entry.starts_with("https://") {
                vec![SymbolSource::Http(entry.trim_end_matches('/').to_string())]
            } else {
                vec![SymbolSource::LocalDirectory(entry.into())]
            }
        })
        .collect()
}

fn parse_source_paths<S: AsRef<str>>(args: &[S]) -> Vec<SourcePathMapping> {
    args.iter()
        .flat_map(|arg| arg.as_ref().split(';'))
        .filter(|entry| !entry.is_empty())
        .map(|entry| match entry.split_once('=') {
            Some((recorded, local)) => SourcePathMapping {
                recorded_prefix: Some(recorded.to_string()),
                local_root: local.into(),
            },
            None => SourcePathMapping {
                recorded_prefix: None,
                local_root: entry.into(),
            },
        })
        .collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::repl::{CommandStyle, parse_command};

    #[test]
    fn ev_keeps_expression_tail() {
        let parsed = parse_command("ev rax + rbx").unwrap().unwrap();
        let invocation = parsed.invocation(CommandStyle::ExpressionTail).unwrap();
        assert_eq!(invocation.raw_tail, "rax + rbx");
        assert!(invocation.argv.is_empty());
    }

    #[test]
    fn symbol_path_parser_supports_local_http_and_srv_syntax() {
        let sources = parse_symbol_sources(&[
            "/private",
            "https://symbols.example.test/",
            "srv*/cache*https://backup.example.test",
        ]);
        assert_eq!(
            sources,
            vec![
                SymbolSource::LocalDirectory("/private".into()),
                SymbolSource::Http("https://symbols.example.test".to_string()),
                SymbolSource::LocalDirectory("/cache".into()),
                SymbolSource::Http("https://backup.example.test".to_string()),
            ]
        );
    }

    #[test]
    fn source_path_parser_supports_roots_and_prefix_mappings() {
        assert_eq!(
            parse_source_paths(&["/source", r"C:\build\src=/checkout"]),
            vec![
                SourcePathMapping {
                    recorded_prefix: None,
                    local_root: "/source".into(),
                },
                SourcePathMapping {
                    recorded_prefix: Some(r"C:\build\src".to_string()),
                    local_root: "/checkout".into(),
                },
            ]
        );
    }

    #[test]
    fn local_location_presentation_preserves_provenance() {
        assert_eq!(
            format_local_location(&LocalVariableLocation::RegisterRelative {
                register: "rsp".to_string(),
                offset: -0x20,
            }),
            "[rsp-0x20]"
        );
        assert_eq!(
            format_local_location(&LocalVariableLocation::Unavailable {
                reason: "optimized out".to_string(),
            }),
            "<optimized out>"
        );
    }
}
