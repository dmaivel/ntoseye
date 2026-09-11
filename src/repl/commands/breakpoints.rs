use tabled::builder::Builder;
use tabled::settings::Padding;

use owo_colors::OwoColorize;

use crate::dbg_backend::HwBreakpointAccess;
use crate::error::{Error, Result};
use crate::expr::{Expr, NumberRadix};
use std::sync::Arc;

use crate::gdb::breakpoints::{BreakpointConfig, BreakpointScope, BreakpointSpec};
use crate::ui;

use crate::repl::*;

repl_command! {
    cmd_bp;
    names: ["bp"],
    usage: "bp <address> [<expr>]",
    summary: "Set a breakpoint.",
    completion: Expression,
    run_state: Halted,
}
repl_command! {
    cmd_bu;
    names: ["bu"],
    usage: "bu [/1] [/p <pid>] <symbol> [<passes>] [if <expr>] [do <commands>]",
    summary: "Set a deferred symbolic breakpoint.",
    completion: Expression,
    run_state: Halted,
}

repl_command! {
    cmd_bm;
    names: ["bm"],
    usage: "bm [/1] [/p <pid>] <symbol-pattern> [<passes>] [if <expr>] [do <commands>]",
    summary: "Set deferred symbolic breakpoints for matching symbols.",
    completion: Expression,
    run_state: Halted,
}

repl_command! {
    cmd_ba;
    names: ["ba"],
    usage: "ba <access><size> <address> [<expr>]",
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
    usage: "bc <id>",
    summary: "Clear a breakpoint by ID.",
    completion: Breakpoint,
    run_state: Halted,
}

repl_command! {
    cmd_bd;
    names: ["bd"],
    usage: "bd <id>",
    summary: "Disable a breakpoint by ID.",
    completion: Breakpoint,
    run_state: Halted,
}

repl_command! {
    cmd_be;
    names: ["be"],
    usage: "be <id>",
    summary: "Enable a breakpoint by ID.",
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
    cmd_bpa;
    names: ["bpa"],
    usage: "bpa <id> <commands|clear>",
    summary: "Update or clear a breakpoint command action.",
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

fn breakpoint_condition(invocation: &CommandInvocation<'_>, start: usize) -> Option<String> {
    (invocation.argv.len() > start).then(|| invocation.join_args(start))
}

struct CodeBreakpointArgs {
    spec: String,
    config: BreakpointConfig,
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

impl ReplState<'_> {
    fn breakpoint_id_arg(invocation: &CommandInvocation<'_>, command: &str) -> Option<u32> {
        let Some(id_str) = invocation.arg(0) else {
            println!("{}\n", command_help(command));
            return None;
        };

        match id_str.parse() {
            Ok(id) => Some(id),
            Err(_) => {
                error!("invalid breakpoint ID: {}", id_str);
                None
            }
        }
    }
    fn parse_radix_u64(&self, value: &str, what: &str) -> Result<u64> {
        let value = value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
            .unwrap_or(value);
        u64::from_str_radix(value, self.radix.value())
            .map_err(|_| Error::Rsp(format!("invalid {what}: {value}")))
    }

    fn code_breakpoint_args(
        &self,
        invocation: &CommandInvocation<'_>,
        command: &str,
    ) -> Result<CodeBreakpointArgs> {
        let mut index = 0;
        let mut one_shot = false;
        let mut scope = None;
        while let Some(arg) = invocation.arg(index) {
            match arg.to_ascii_lowercase().as_str() {
                "/1" => {
                    one_shot = true;
                    index += 1;
                }
                "/p" => {
                    let pid_text = invocation
                        .arg(index + 1)
                        .ok_or_else(|| Error::Rsp(format!("{command}: /p requires a PID")))?;
                    let pid = self.parse_radix_u64(pid_text, "PID")?;
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
                    scope = Some(BreakpointScope::process(&process));
                    index += 2;
                }
                "/t" => {
                    return Err(Error::Rsp(
                        "thread-scoped breakpoints are not supported by the current backends"
                            .into(),
                    ));
                }
                _ => break,
            }
        }

        let spec = invocation
            .arg(index)
            .ok_or_else(|| Error::Rsp(format!("{command}: missing breakpoint target")))?
            .to_string();
        index += 1;

        let mut pass_count = 0;
        if let Some(value) = invocation.arg(index)
            && !value.eq_ignore_ascii_case("if")
            && !value.eq_ignore_ascii_case("do")
            && let Ok(parsed) = self.parse_radix_u64(value, "pass count")
        {
            pass_count = parsed;
            index += 1;
        }

        let mut condition = None;
        let mut action = None;
        if invocation
            .arg(index)
            .is_some_and(|arg| arg.eq_ignore_ascii_case("if"))
        {
            index += 1;
            let action_index = invocation.argv[index..]
                .iter()
                .position(|arg| arg.eq_ignore_ascii_case("do"))
                .map(|offset| index + offset);
            let condition_end = action_index.unwrap_or(invocation.argv.len());
            if condition_end == index {
                return Err(Error::Rsp("missing breakpoint condition after 'if'".into()));
            }
            condition = Some(invocation.argv[index..condition_end].join(" "));
            index = condition_end;
        } else if invocation
            .arg(index)
            .is_some_and(|arg| !arg.eq_ignore_ascii_case("do"))
        {
            // Preserve the historical `bp address condition` form.
            condition = Some(invocation.argv[index..].join(" "));
            index = invocation.argv.len();
        }
        if invocation
            .arg(index)
            .is_some_and(|arg| arg.eq_ignore_ascii_case("do"))
        {
            index += 1;
            if index == invocation.argv.len() {
                return Err(Error::Rsp("missing breakpoint commands after 'do'".into()));
            }
            action = Some(invocation.argv[index..].join(" "));
        }

        let condition_expr = compile_repl_condition(condition.as_deref(), self.radix)?;
        Ok(CodeBreakpointArgs {
            spec,
            config: BreakpointConfig {
                condition,
                condition_expr,
                pass_count,
                one_shot,
                action,
                scope,
            },
        })
    }

    fn report_breakpoint_result(&mut self, result: Result<u32>, label: &str) -> Option<u32> {
        match result {
            Ok(id) => {
                self.caches.refresh_breakpoints(&self.ctx.breakpoints);
                println!("{label} {}\n", ui::bp_id(id));
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
                            println!(
                                "source breakpoint {} deferred until '{}' resolves\n",
                                ui::bp_id(ids[0]),
                                spec
                            );
                        } else {
                            println!(
                                "source breakpoint {} set for '{}'\n",
                                ui::bp_id(ids[0]),
                                spec
                            );
                        }
                    } else {
                        println!("{} source breakpoints set for '{}'\n", ids.len(), spec);
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
                println!(
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
            println!("no symbols match '{}'\n", args.spec);
        } else {
            let suffix = if names.len() >= BM_LIMIT {
                "; results limited to 256, refine the pattern"
            } else {
                ""
            };
            println!("{created} symbolic breakpoint(s) set{suffix}\n");
        }
        Ok(())
    }

    fn cmd_ba(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let spec_str = require_arg!(invocation, 0, "ba");
        let addr_str = require_arg!(invocation, 1, "ba");

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
        let condition = breakpoint_condition(&invocation, 2);
        let condition_expr = match compile_repl_condition(condition.as_deref(), self.radix) {
            Ok(expr) => expr,
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
            BreakpointConfig {
                condition: condition.clone(),
                condition_expr,
                ..BreakpointConfig::default()
            },
        ) {
            Ok(id) => {
                self.caches.refresh_breakpoints(&self.ctx.breakpoints);
                let condition_label = condition
                    .as_ref()
                    .map(|condition| format!(" if {condition}"))
                    .unwrap_or_default();
                println!(
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
                println!(
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

    fn cmd_bl(&mut self) -> Result<()> {
        let bps = self.ctx.breakpoints.list();
        if bps.is_empty() {
            println!("no breakpoints set\n");
        } else {
            let mut builder = Builder::default();
            builder.push_record(vec![
                "ID".to_string(),
                "Status".to_string(),
                "Type".to_string(),
                "Address".to_string(),
                "Symbol".to_string(),
                "Condition".to_string(),
                "Passes".to_string(),
                "Hits".to_string(),
                "Remain".to_string(),
                "One-shot".to_string(),
                "Action".to_string(),
                "Scope".to_string(),
            ]);

            for bp in bps {
                let status = if !bp.enabled {
                    "disabled"
                } else if bp.deferred() {
                    "deferred"
                } else {
                    "enabled"
                };
                let scope = bp.scope.label();
                let kind = match bp.hardware {
                    Some(hw) => format!("hw {}{}", hw.access.letter(), hw.len),
                    None => "sw".to_string(),
                };

                builder.push_record(vec![
                    bp.id.to_string(),
                    status.to_string(),
                    kind,
                    bp.resolved_address()
                        .map(|address| ui::addr(address.0))
                        .unwrap_or_else(|| "-".to_string()),
                    bp.specification()
                        .or(bp.symbol.as_deref())
                        .unwrap_or("-")
                        .to_string(),
                    bp.condition.as_deref().unwrap_or("-").to_string(),
                    bp.pass_count.to_string(),
                    bp.hit_count.to_string(),
                    bp.remaining_pass_count.to_string(),
                    if bp.one_shot { "yes" } else { "-" }.to_string(),
                    bp.action.as_deref().unwrap_or("-").to_string(),
                    scope,
                ]);
            }

            let mut table = builder.build();
            table
                .with(tabled::settings::Style::empty())
                .with(Padding::new(0, 2, 0, 0));
            println!("{table}\n");
        }

        Ok(())
    }

    fn cmd_bc(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(id) = Self::breakpoint_id_arg(&invocation, "bc") else {
            return Ok(());
        };

        match self
            .ctx
            .breakpoints
            .remove(&mut *self.ctx.backend, &self.ctx.target, id)
        {
            Ok(()) => {
                self.caches.refresh_breakpoints(&self.ctx.breakpoints);
                println!("breakpoint {} cleared\n", ui::bp_id(id));
            }
            Err(e) => {
                error!("{}", e);
            }
        }

        Ok(())
    }

    fn cmd_bd(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(id) = Self::breakpoint_id_arg(&invocation, "bd") else {
            return Ok(());
        };

        match self
            .ctx
            .breakpoints
            .disable(&mut *self.ctx.backend, &self.ctx.target, id)
        {
            Ok(()) => {
                self.caches.refresh_breakpoints(&self.ctx.breakpoints);
                println!("breakpoint {} disabled\n", ui::bp_id(id));
            }
            Err(e) => {
                error!("{}", e);
            }
        }

        Ok(())
    }

    fn cmd_be(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(id) = Self::breakpoint_id_arg(&invocation, "be") else {
            return Ok(());
        };

        match self
            .ctx
            .breakpoints
            .enable(&mut *self.ctx.backend, &self.ctx.target, id)
        {
            Ok(()) => {
                self.caches.refresh_breakpoints(&self.ctx.breakpoints);
                println!("breakpoint {} enabled\n", ui::bp_id(id));
            }
            Err(e) => {
                error!("{}", e);
            }
        }

        Ok(())
    }
    fn cmd_bpc(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(id) = Self::breakpoint_id_arg(&invocation, "bpc") else {
            return Ok(());
        };
        let text = invocation.join_args(1);
        if text.is_empty() {
            println!("{}\n", command_help("bpc"));
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
            Ok(()) => println!("breakpoint {} condition updated\n", ui::bp_id(id)),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_bpa(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(id) = Self::breakpoint_id_arg(&invocation, "bpa") else {
            return Ok(());
        };
        let text = invocation.join_args(1);
        if text.is_empty() {
            println!("{}\n", command_help("bpa"));
            return Ok(());
        }
        let action = (!text.eq_ignore_ascii_case("clear")).then_some(text);
        match self.ctx.breakpoints.set_action(id, action) {
            Ok(()) => println!("breakpoint {} action updated\n", ui::bp_id(id)),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_bpp(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(id) = Self::breakpoint_id_arg(&invocation, "bpp") else {
            return Ok(());
        };
        let Some(text) = invocation.arg(1) else {
            println!("{}\n", command_help("bpp"));
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
            Ok(()) => println!("breakpoint {} pass count reset\n", ui::bp_id(id)),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::*;
    use crate::expr::ExprBinaryOp;
    use crate::types::VirtAddr;

    fn bp_invocation<'a>(argv: &'a [&'a str]) -> CommandInvocation<'a> {
        CommandInvocation {
            name: "bp",
            argv: argv.iter().copied().map(Cow::Borrowed).collect(),
            raw_tail: "",
        }
    }

    #[test]
    fn breakpoint_condition_accepts_comparison_tail() {
        let invocation = bp_invocation(&["nt!Foo", "$rax", "==", "1"]);

        assert_eq!(
            breakpoint_condition(&invocation, 1).as_deref(),
            Some("$rax == 1")
        );
    }

    #[test]
    fn breakpoint_condition_preserves_chained_expression_tail() {
        let invocation = bp_invocation(&["nt!Foo", "$rax", "==", "1", "&&", "$rcx", "!=", "0"]);

        assert_eq!(
            breakpoint_condition(&invocation, 1).as_deref(),
            Some("$rax == 1 && $rcx != 0")
        );
    }
    #[test]
    fn repl_condition_compiles_with_creation_time_radix() {
        let expr = compile_repl_condition(Some("10 == 0x10"), NumberRadix::Hexadecimal)
            .unwrap()
            .unwrap();
        assert!(matches!(
            expr.as_ref(),
            Expr::Binary(left, ExprBinaryOp::Equal, right)
                if matches!(left.as_ref(), Expr::Literal(VirtAddr(0x10)))
                    && matches!(right.as_ref(), Expr::Literal(VirtAddr(0x10)))
        ));
    }
}
