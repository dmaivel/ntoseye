use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::Arc;

use tabled::builder::Builder;
use tabled::settings::Padding;

use owo_colors::OwoColorize;

use crate::dbg_backend::HwBreakpointAccess;
use crate::error::{Error, Result};
use crate::expr::{Expr, NumberRadix};
use crate::gdb::breakpoints::{
    BreakpointConfig, BreakpointManager, BreakpointScope, BreakpointSpec,
};
use crate::ui;

use crate::repl::*;

repl_command! {
    cmd_bp;
    names: ["bp"],
    usage: "bp [/1] [/p <pid>] [/w \"<expr>\"] <address> [<passes>] [if <expr>] [do <commands>]",
    summary: "Set a breakpoint.",
    completion: Expression,
    run_state: Halted,
}
repl_command! {
    cmd_bu;
    names: ["bu"],
    usage: "bu [/1] [/p <pid>] [/w \"<expr>\"] <symbol> [<passes>] [if <expr>] [do <commands>]",
    summary: "Set a deferred symbolic breakpoint.",
    completion: Expression,
    run_state: Halted,
}

repl_command! {
    cmd_bm;
    names: ["bm"],
    usage: "bm [/1] [/p <pid>] [/w \"<expr>\"] <symbol-pattern> [<passes>] [if <expr>] [do <commands>]",
    summary: "Set deferred symbolic breakpoints for matching symbols.",
    completion: Expression,
    run_state: Halted,
}

repl_command! {
    cmd_ba;
    names: ["ba"],
    usage: "ba [/1] [/p <pid>] [/w \"<expr>\"] <access><size> <address> [<passes>] [if <expr>] [do <commands>]",
    summary: "Set a hardware (debug-register) breakpoint (KD backend only).",
    details: "access: e=execute, r=read/write, w=write; size: 1,2,4,8 bytes (execute is 1). e.g. ba w4 nt!MyGlobal",
    completion: [None, Expression],
    run_state: Halted,
}

repl_command! {
    cmd_bl();
    names: ["bl"],
    usage: "bl",
    summary: "List all breakpoints.",
}

repl_command! {
    cmd_bc;
    names: ["bc"],
    usage: "bc <id|id-id|*>",
    summary: "Clear one or more breakpoints by ID.",
    completion: Breakpoint,
    run_state: Halted,
}

repl_command! {
    cmd_bd;
    names: ["bd"],
    usage: "bd <id|id-id|*>",
    summary: "Disable one or more breakpoints by ID.",
    completion: Breakpoint,
    run_state: Halted,
}

repl_command! {
    cmd_be;
    names: ["be"],
    usage: "be <id|id-id|*>",
    summary: "Enable one or more breakpoints by ID.",
    completion: Breakpoint,
    run_state: Halted,
}
repl_command! {
    cmd_bpc;
    names: ["bpc"],
    usage: "bpc <id> <condition|clear>",
    summary: "Update or clear a breakpoint condition.",
    completion: [Breakpoint, Expression],
    run_state: Halted,
}

repl_command! {
    cmd_bs;
    names: ["bs", "bpa"],
    usage: "bs <id> <commands|clear>",
    summary: "Set or clear a breakpoint command action.",
    completion: Breakpoint,
    run_state: Halted,
}

repl_command! {
    cmd_br;
    names: ["br"],
    usage: "br <id> <newid>",
    summary: "Renumber a breakpoint.",
    completion: Breakpoint,
    run_state: Halted,
}

repl_command! {
    cmd_bpp;
    names: ["bpp"],
    usage: "bpp <id> <passes>",
    summary: "Reset a breakpoint pass count.",
    completion: Breakpoint,
    run_state: Halted,
}

struct CodeBreakpointArgs {
    spec: String,
    config: BreakpointConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedBreakpointArgs {
    target: String,
    access_spec: Option<String>,
    one_shot: bool,
    pid: Option<u64>,
    pass_count: u64,
    condition: Option<String>,
    action: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum BreakpointIdSelection {
    All,
    Ids(Vec<u32>),
}

fn parse_radix_u64_text(value: &str, radix: NumberRadix, what: &str) -> Result<u64> {
    let value = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    u64::from_str_radix(value, radix.value())
        .map_err(|_| Error::Rsp(format!("invalid {what}: {value}")))
}

fn parse_breakpoint_arguments(
    argv: &[Cow<'_, str>],
    radix: NumberRadix,
    command: &str,
    wants_access_spec: bool,
) -> Result<ParsedBreakpointArgs> {
    let mut index = 0;
    let mut one_shot = false;
    let mut pid = None;
    let mut shorthand_condition = None;

    while let Some(arg) = argv.get(index) {
        match arg.as_ref().to_ascii_lowercase().as_str() {
            "/1" => {
                one_shot = true;
                index += 1;
            }
            "/p" => {
                let pid_text = argv
                    .get(index + 1)
                    .ok_or_else(|| Error::Rsp(format!("{command}: /p requires a PID")))?;
                pid = Some(parse_radix_u64_text(pid_text.as_ref(), radix, "PID")?);
                index += 2;
            }
            "/t" => {
                return Err(Error::Rsp(
                    "thread-scoped breakpoints are not supported by the current backends".into(),
                ));
            }
            "/w" => {
                let condition = argv
                    .get(index + 1)
                    .ok_or_else(|| Error::Rsp(format!("{command}: /w requires an expression")))?;
                shorthand_condition = Some(condition.as_ref().to_string());
                index += 2;
            }
            _ => break,
        }
    }

    let access_spec = if wants_access_spec {
        let access = argv
            .get(index)
            .ok_or_else(|| Error::Rsp(format!("{command}: missing access/size")))?;
        index += 1;
        Some(access.as_ref().to_string())
    } else {
        None
    };
    let target = argv
        .get(index)
        .ok_or_else(|| Error::Rsp(format!("{command}: missing breakpoint target")))?;
    let target = target.as_ref().to_string();
    index += 1;

    let mut pass_count = 0;
    if let Some(value) = argv.get(index)
        && !value.as_ref().eq_ignore_ascii_case("if")
        && !value.as_ref().eq_ignore_ascii_case("do")
        && let Ok(parsed) = parse_radix_u64_text(value.as_ref(), radix, "pass count")
    {
        pass_count = parsed;
        index += 1;
    }

    let mut condition = shorthand_condition;
    let tail = &argv[index..];
    let do_index = tail
        .iter()
        .position(|arg| arg.as_ref().eq_ignore_ascii_case("do"));
    let (condition_tail, action_tail) = match do_index {
        Some(index) => (&tail[..index], Some(&tail[index + 1..])),
        None => (tail, None),
    };
    let explicit_if = condition_tail
        .first()
        .is_some_and(|arg| arg.as_ref().eq_ignore_ascii_case("if"));
    let condition_tail = if explicit_if {
        &condition_tail[1..]
    } else {
        condition_tail
    };
    let bare_condition = condition_tail
        .first()
        .is_some_and(|arg| !matches!(arg, Cow::Owned(_)));
    let mut action = None;
    if explicit_if || bare_condition {
        if condition.is_some() {
            return Err(Error::Rsp(
                "breakpoint condition specified more than once".into(),
            ));
        }
        if condition_tail.is_empty() {
            return Err(Error::Rsp("missing breakpoint condition after 'if'".into()));
        }
        condition = Some(join_breakpoint_args(condition_tail));
    } else if action_tail.is_none() && condition_tail.len() == 1 {
        if let Cow::Owned(action_text) = &condition_tail[0] {
            if action_text.is_empty() {
                return Err(Error::Rsp("missing breakpoint commands after 'do'".into()));
            }
            action = Some(action_text.clone());
        }
    } else if !condition_tail.is_empty() {
        return Err(Error::Rsp("invalid breakpoint condition or action".into()));
    }

    if let Some(action_tail) = action_tail {
        if action_tail.is_empty() {
            return Err(Error::Rsp("missing breakpoint commands after 'do'".into()));
        }
        let action_text = join_breakpoint_args(action_tail);
        if action_text.is_empty() {
            return Err(Error::Rsp("missing breakpoint commands after 'do'".into()));
        }
        action = Some(action_text);
    }

    Ok(ParsedBreakpointArgs {
        target,
        access_spec,
        one_shot,
        pid,
        pass_count,
        condition,
        action,
    })
}

fn join_breakpoint_args(args: &[Cow<'_, str>]) -> String {
    args.iter()
        .map(|arg| arg.as_ref())
        .collect::<Vec<_>>()
        .join(" ")
}

fn parse_breakpoint_id_selectors(args: &[&str]) -> Result<BreakpointIdSelection> {
    if args.is_empty() {
        return Err(Error::Rsp("missing breakpoint ID".into()));
    }
    if args.len() == 1 && args[0] == "*" {
        return Ok(BreakpointIdSelection::All);
    }
    if args.contains(&"*") {
        return Err(Error::Rsp(
            "'*' cannot be combined with breakpoint IDs".into(),
        ));
    }

    let mut ids = Vec::new();
    let mut seen = HashSet::new();
    for selector in args {
        if let Some((first, last)) = selector.split_once('-') {
            let first = first
                .parse::<u32>()
                .map_err(|_| Error::Rsp(format!("invalid breakpoint ID range: {selector}")))?;
            let last = last
                .parse::<u32>()
                .map_err(|_| Error::Rsp(format!("invalid breakpoint ID range: {selector}")))?;
            if first > last {
                return Err(Error::Rsp(format!(
                    "breakpoint ID range must be ascending: {selector}"
                )));
            }
            for id in first..=last {
                if seen.insert(id) {
                    ids.push(id);
                }
            }
        } else {
            let id = selector
                .parse::<u32>()
                .map_err(|_| Error::Rsp(format!("invalid breakpoint ID: {selector}")))?;
            if seen.insert(id) {
                ids.push(id);
            }
        }
    }
    Ok(BreakpointIdSelection::Ids(ids))
}
fn compile_repl_condition(
    condition: Option<&str>,
    radix: NumberRadix,
) -> Result<Option<Arc<Expr>>> {
    condition
        .map(|text| Expr::parse_with_radix(text, radix).map(Arc::new))
        .transpose()
}

/// Parse a WinDbg-style `ba` access/size token like `w4`, `r1`, `e1`: a leading
/// access letter (`e`/`r`/`w`) followed by the watch width in bytes.
fn parse_hw_breakpoint_spec(spec: &str) -> Result<(HwBreakpointAccess, u8)> {
    let mut chars = spec.chars();
    let access = match chars.next().map(|c| c.to_ascii_lowercase()) {
        Some('e') => HwBreakpointAccess::Execute,
        Some('w') => HwBreakpointAccess::Write,
        Some('r') => HwBreakpointAccess::ReadWrite,
        _ => {
            return Err(Error::Rsp(format!(
                "invalid access in '{spec}' (use e=execute, r=read/write, w=write)"
            )));
        }
    };
    let size: String = chars.collect();
    let len = match size.as_str() {
        // Execute watches are always a single byte; allow the bare `e`.
        "" if matches!(access, HwBreakpointAccess::Execute) => 1,
        "" => {
            return Err(Error::Rsp(format!(
                "missing size in '{spec}' (e.g. ba w4 <address>)"
            )));
        }
        other => other
            .parse()
            .map_err(|_| Error::Rsp(format!("invalid size '{other}' (use 1, 2, 4, or 8)")))?,
    };
    Ok((access, len))
}

fn apply_breakpoint_updates(
    ids: Vec<u32>,
    breakpoints: &mut BreakpointManager,
    caches: &ReplCaches,
    verb: &str,
    mut update: impl FnMut(&mut BreakpointManager, u32) -> Result<()>,
) -> Result<()> {
    let mut changed = false;
    for id in ids {
        match update(breakpoints, id) {
            Ok(()) => {
                changed = true;
                outln!("breakpoint {} {verb}", ui::bp_id(id));
            }
            Err(error) => error!("{error}"),
        }
    }
    if changed {
        caches.refresh_breakpoints(breakpoints);
        outln!();
    }
    Ok(())
}

impl ReplState<'_> {
    fn breakpoint_id_arg(invocation: &CommandInvocation<'_>, command: &str) -> Option<u32> {
        let Some(id_str) = invocation.arg(0) else {
            outln!("{}\n", command_help(command));
            return None;
        };

        match id_str.parse::<u32>() {
            Ok(id) => Some(id),
            Err(_) => {
                error!("invalid breakpoint ID: {}", id_str);
                None
            }
        }
    }
    fn parse_radix_u64(&self, value: &str, what: &str) -> Result<u64> {
        parse_radix_u64_text(value, self.radix, what)
    }

    fn breakpoint_scope(&self, pid: Option<u64>) -> Result<Option<BreakpointScope>> {
        let Some(pid) = pid else {
            return Ok(None);
        };
        let process = self
            .ctx
            .target
            .guest
            .as_ref()
            .ok_or(Error::NtoskrnlNotFound)?
            .enumerate_processes()?
            .into_iter()
            .find(|process| process.pid == pid)
            .ok_or_else(|| Error::Rsp(format!("process {pid:#x} not found")))?;
        Ok(Some(BreakpointScope::process(&process)))
    }

    fn breakpoint_config(&self, parsed: ParsedBreakpointArgs) -> Result<BreakpointConfig> {
        let condition_expr = compile_repl_condition(parsed.condition.as_deref(), self.radix)?;
        let scope = self.breakpoint_scope(parsed.pid)?;
        Ok(BreakpointConfig {
            condition: parsed.condition,
            condition_expr,
            pass_count: parsed.pass_count,
            one_shot: parsed.one_shot,
            action: parsed.action,
            scope,
        })
    }

    fn code_breakpoint_args(
        &self,
        invocation: &CommandInvocation<'_>,
        command: &str,
    ) -> Result<CodeBreakpointArgs> {
        let parsed = parse_breakpoint_arguments(&invocation.argv, self.radix, command, false)?;
        let spec = parsed.target.clone();
        Ok(CodeBreakpointArgs {
            spec,
            config: self.breakpoint_config(parsed)?,
        })
    }

    fn report_breakpoint_result(&mut self, result: Result<u32>, label: &str) -> Option<u32> {
        match result {
            Ok(id) => {
                self.caches.refresh_breakpoints(&self.ctx.breakpoints);
                outln!("{label} {}\n", ui::bp_id(id));
                Some(id)
            }
            Err(error) => {
                error!("{error}");
                None
            }
        }
    }

    fn cmd_bu(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let args = match self.code_breakpoint_args(&invocation, "bu") {
            Ok(args) => args,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let spec = args.spec.clone();
        if BreakpointSpec::source(&spec, 0).is_some() {
            match self.ctx.breakpoints.add_source(
                &mut *self.ctx.backend,
                &self.ctx.target,
                args.spec,
                args.config,
            ) {
                Ok(ids) => {
                    self.caches.refresh_breakpoints(&self.ctx.breakpoints);
                    if ids.len() == 1 {
                        let deferred = self
                            .ctx
                            .breakpoints
                            .list()
                            .into_iter()
                            .find(|bp| bp.id == ids[0])
                            .is_some_and(|bp| bp.deferred());
                        if deferred {
                            outln!(
                                "source breakpoint {} deferred until '{}' resolves\n",
                                ui::bp_id(ids[0]),
                                spec
                            );
                        } else {
                            outln!(
                                "source breakpoint {} set for '{}'\n",
                                ui::bp_id(ids[0]),
                                spec
                            );
                        }
                    } else {
                        outln!("{} source breakpoints set for '{}'\n", ids.len(), spec);
                    }
                }
                Err(error) => error!("{error}"),
            }
            return Ok(());
        }

        let result = self.ctx.breakpoints.add_symbolic(
            &mut *self.ctx.backend,
            &self.ctx.target,
            args.spec,
            args.config,
        );
        if let Some(id) = self.report_breakpoint_result(result, "symbolic breakpoint") {
            let bp = self
                .ctx
                .breakpoints
                .list()
                .into_iter()
                .find(|bp| bp.id == id);
            if bp.is_some_and(|bp| bp.deferred()) {
                outln!(
                    "  {} is deferred until '{}' resolves\n",
                    ui::bp_id(id),
                    spec
                );
            }
        }
        Ok(())
    }

    fn cmd_bm(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        const BM_LIMIT: usize = 256;
        let args = match self.code_breakpoint_args(&invocation, "bm") {
            Ok(args) => args,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let dtb = self.ctx.target.current_dtb();
        let (module_filter, names) = match args.spec.split_once('!') {
            Some((module, query)) => (
                Some(module.to_string()),
                self.ctx
                    .target
                    .symbols
                    .search_symbols_in_module(dtb, module, query, BM_LIMIT),
            ),
            None => (
                None,
                self.caches
                    .symbols
                    .read()
                    .unwrap()
                    .search(&args.spec, BM_LIMIT),
            ),
        };
        let mut created = 0usize;
        for name in names.iter().take(BM_LIMIT) {
            let lookup = module_filter
                .as_ref()
                .map(|module| format!("{module}!{name}"))
                .unwrap_or_else(|| name.clone());
            let canonical = self
                .ctx
                .target
                .symbols
                .find_symbol_with_module(dtb, &lookup)?
                .map(|(_, module)| format!("{module}!{name}"))
                .unwrap_or(lookup);
            match self.ctx.breakpoints.add_symbolic(
                &mut *self.ctx.backend,
                &self.ctx.target,
                canonical,
                args.config.clone(),
            ) {
                Ok(_) => created += 1,
                Err(error) => error!("bm: {error}"),
            }
        }
        self.caches.refresh_breakpoints(&self.ctx.breakpoints);
        if created == 0 {
            outln!("no symbols match '{}'\n", args.spec);
        } else {
            let suffix = if names.len() >= BM_LIMIT {
                "; results limited to 256, refine the pattern"
            } else {
                ""
            };
            outln!("{created} symbolic breakpoint(s) set{suffix}\n");
        }
        Ok(())
    }

    fn cmd_ba(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let parsed = match parse_breakpoint_arguments(&invocation.argv, self.radix, "ba", true) {
            Ok(parsed) => parsed,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let Some(spec_str) = parsed.access_spec.as_deref() else {
            error!("ba: missing access/size");
            return Ok(());
        };
        let addr_str = parsed.target.as_str();

        let (access, len) = match parse_hw_breakpoint_spec(spec_str) {
            Ok(parsed) => parsed,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };
        let address = match Expr::eval_with_radix(addr_str, &self.ctx.target, self.radix) {
            Ok(a) => a,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };
        let condition = parsed.condition.clone();
        let config = match self.breakpoint_config(parsed) {
            Ok(config) => config,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };

        let symbol = self
            .ctx
            .target
            .symbols
            .format_closest_symbol_for_address(self.ctx.target.current_dtb(), address);

        match self.ctx.breakpoints.add_hardware_configured(
            &mut *self.ctx.backend,
            &self.ctx.target,
            address,
            access,
            len,
            symbol.clone(),
            config,
        ) {
            Ok(id) => {
                self.caches.refresh_breakpoints(&self.ctx.breakpoints);
                let condition_label = condition
                    .as_ref()
                    .map(|condition| format!(" if {condition}"))
                    .unwrap_or_default();
                outln!(
                    "hardware breakpoint {} ({} {}b) set at {}{}{}\n",
                    ui::bp_id(id),
                    access.label(),
                    len,
                    ui::addr(address.0),
                    symbol
                        .map(|s| format!(" ({})", ui::symbol(&s)))
                        .unwrap_or_default(),
                    condition_label.bright_black(),
                );
            }
            Err(e) => {
                error!("{}", e);
            }
        }

        Ok(())
    }

    fn cmd_bp(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let args = match self.code_breakpoint_args(&invocation, "bp") {
            Ok(args) => args,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let address = match Expr::eval_with_radix(&args.spec, &self.ctx.target, self.radix) {
            Ok(address) => address,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let symbol = self
            .ctx
            .target
            .symbols
            .format_closest_symbol_for_address(self.ctx.target.current_dtb(), address);
        match self.ctx.breakpoints.add_configured(
            &mut *self.ctx.backend,
            &self.ctx.target,
            address,
            symbol.clone(),
            args.config,
        ) {
            Ok(id) => {
                self.caches.refresh_breakpoints(&self.ctx.breakpoints);
                outln!(
                    "breakpoint {} set at {}{}{}\n",
                    ui::bp_id(id),
                    ui::addr(address.0),
                    symbol
                        .map(|symbol| format!(" ({})", ui::symbol(&symbol)))
                        .unwrap_or_default(),
                    self.ctx
                        .breakpoints
                        .list()
                        .into_iter()
                        .find(|bp| bp.id == id)
                        .map(|bp| format!(" ({})", bp.scope.label()))
                        .unwrap_or_default()
                        .bright_black(),
                );
            }
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn selected_breakpoint_ids(
        &self,
        invocation: &CommandInvocation<'_>,
        command: &str,
    ) -> Option<Vec<u32>> {
        let args = invocation
            .argv
            .iter()
            .map(|arg| arg.as_ref())
            .collect::<Vec<_>>();
        let selection = match parse_breakpoint_id_selectors(&args) {
            Ok(selection) => selection,
            Err(error) => {
                if args.is_empty() {
                    outln!("{}\n", command_help(command));
                } else {
                    error!("{error}");
                }
                return None;
            }
        };
        let managed = self.ctx.breakpoints.managed_ids();
        let managed_set = managed.iter().copied().collect::<HashSet<_>>();
        Some(match selection {
            BreakpointIdSelection::All => managed,
            BreakpointIdSelection::Ids(ids) => ids
                .into_iter()
                .filter(|id| managed_set.contains(id))
                .collect(),
        })
    }

    fn cmd_bl(&mut self) -> Result<()> {
        let bps = self.ctx.breakpoints.list();
        if bps.is_empty() {
            outln!("no breakpoints set\n");
            return Ok(());
        }

        let mut builder = Builder::default();
        builder.push_record(vec![
            "ID".to_string(),
            "Status".to_string(),
            "Address".to_string(),
            "Pass Count".to_string(),
            "Process/Thread".to_string(),
            "Symbol".to_string(),
            "Condition".to_string(),
            "Action".to_string(),
        ]);

        for bp in bps {
            let pass_count = format!(
                "{:04} ({:04})",
                bp.remaining_pass_count.saturating_add(1),
                bp.pass_count.max(1)
            );
            let symbol = match bp.hardware {
                Some(hw) => format!(
                    "watch {}{} {}",
                    hw.access.letter(),
                    hw.len,
                    bp.specification().or(bp.symbol.as_deref()).unwrap_or("-")
                ),
                None => bp
                    .specification()
                    .or(bp.symbol.as_deref())
                    .unwrap_or("-")
                    .to_string(),
            };
            builder.push_record(vec![
                ui::bp_id(bp.id),
                if bp.enabled { "e" } else { "d" }.to_string(),
                bp.resolved_address()
                    .map(|address| ui::addr(address.0))
                    .unwrap_or_else(|| "-".to_string()),
                pass_count,
                bp.scope.label(),
                symbol,
                bp.condition.as_deref().unwrap_or("-").to_string(),
                bp.action.as_deref().unwrap_or("-").to_string(),
            ]);
        }

        let mut table = builder.build();
        table
            .with(tabled::settings::Style::empty())
            .with(Padding::new(0, 2, 0, 0));
        outln!("{table}\n");
        Ok(())
    }

    fn cmd_bc(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(ids) = self.selected_breakpoint_ids(&invocation, "bc") else {
            return Ok(());
        };
        let backend = &mut *self.ctx.backend;
        let target = &self.ctx.target;
        apply_breakpoint_updates(
            ids,
            &mut self.ctx.breakpoints,
            &self.caches,
            "cleared",
            |breakpoints, id| breakpoints.remove(backend, target, id),
        )
    }

    fn cmd_bd(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(ids) = self.selected_breakpoint_ids(&invocation, "bd") else {
            return Ok(());
        };
        let backend = &mut *self.ctx.backend;
        let target = &self.ctx.target;
        apply_breakpoint_updates(
            ids,
            &mut self.ctx.breakpoints,
            &self.caches,
            "disabled",
            |breakpoints, id| breakpoints.disable(backend, target, id),
        )
    }

    fn cmd_be(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(ids) = self.selected_breakpoint_ids(&invocation, "be") else {
            return Ok(());
        };
        let backend = &mut *self.ctx.backend;
        let target = &self.ctx.target;
        apply_breakpoint_updates(
            ids,
            &mut self.ctx.breakpoints,
            &self.caches,
            "enabled",
            |breakpoints, id| breakpoints.enable(backend, target, id),
        )
    }
    fn cmd_bpc(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(id) = Self::breakpoint_id_arg(&invocation, "bpc") else {
            return Ok(());
        };
        let text = invocation.join_args(1);
        if text.is_empty() {
            outln!("{}\n", command_help("bpc"));
            return Ok(());
        }
        let (condition, expr) = if text.eq_ignore_ascii_case("clear") {
            (None, None)
        } else {
            let expr = match compile_repl_condition(Some(&text), self.radix) {
                Ok(Some(expr)) => expr,
                Ok(None) => unreachable!(),
                Err(error) => {
                    error!("{error}");
                    return Ok(());
                }
            };
            (Some(text), Some(expr))
        };
        match self.ctx.breakpoints.set_condition(id, condition, expr) {
            Ok(()) => outln!("breakpoint {} condition updated\n", ui::bp_id(id)),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_bs(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(id) = Self::breakpoint_id_arg(&invocation, invocation.name) else {
            return Ok(());
        };
        let text = invocation.join_args(1);
        if text.is_empty() {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        }
        let action = (!text.eq_ignore_ascii_case("clear")).then_some(text);
        match self.ctx.breakpoints.set_action(id, action) {
            Ok(()) => outln!("breakpoint {} action updated\n", ui::bp_id(id)),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_br(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(old_id) = Self::breakpoint_id_arg(&invocation, "br") else {
            return Ok(());
        };
        let Some(new_text) = invocation.arg(1) else {
            outln!("{}\n", command_help("br"));
            return Ok(());
        };
        let new_id = match new_text.parse::<u32>() {
            Ok(id) => id,
            Err(_) => {
                error!("invalid breakpoint ID: {new_text}");
                return Ok(());
            }
        };
        match self.ctx.breakpoints.renumber(old_id, new_id) {
            Ok(()) => {
                self.caches.refresh_breakpoints(&self.ctx.breakpoints);
                outln!(
                    "breakpoint {} renumbered to {}\n",
                    ui::bp_id(old_id),
                    ui::bp_id(new_id)
                );
            }
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_bpp(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(id) = Self::breakpoint_id_arg(&invocation, "bpp") else {
            return Ok(());
        };
        let Some(text) = invocation.arg(1) else {
            outln!("{}\n", command_help("bpp"));
            return Ok(());
        };
        let passes = match self.parse_radix_u64(text, "pass count") {
            Ok(passes) => passes,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        match self.ctx.breakpoints.set_pass_count(id, passes) {
            Ok(()) => outln!("breakpoint {} pass count reset\n", ui::bp_id(id)),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn breakpoint_id_selectors_accept_lists_and_ranges() {
        assert_eq!(
            parse_breakpoint_id_selectors(&["0", "2", "5"]).unwrap(),
            BreakpointIdSelection::Ids(vec![0, 2, 5])
        );
        assert_eq!(
            parse_breakpoint_id_selectors(&["1-3"]).unwrap(),
            BreakpointIdSelection::Ids(vec![1, 2, 3])
        );
        assert_eq!(
            parse_breakpoint_id_selectors(&["1-3", "2", "5"]).unwrap(),
            BreakpointIdSelection::Ids(vec![1, 2, 3, 5])
        );
        assert_eq!(
            parse_breakpoint_id_selectors(&["*"]).unwrap(),
            BreakpointIdSelection::All
        );
    }
}
