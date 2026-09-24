//! Debugger execution state: vCPUs, breakpoints, stacks, disassembly,
//! expression values, registers, and run status.

use super::Args;
use crate::error::Result;
use crate::view::{self, View};

pub(super) fn command(name: &str, args: &mut Args<'_, '_>) -> Option<Result<View>> {
    let argv = args.argv;
    Some(match name {
        "~" | "vcpus" if argv.is_empty() => args
            .state
            .ctx
            .vcpus()
            .map(|vcpus| View::List(vcpus.iter().map(view::execution::vcpu).collect())),
        "bl" => Ok(View::List(
            args.state
                .ctx
                .list_breakpoints()
                .into_iter()
                .map(view::execution::breakpoint)
                .collect(),
        )),
        "k" | "kn" | "kb" | "kp" | "kv" => args.opt_value(0).and_then(|count| {
            let trace = args
                .state
                .ctx
                .backtrace(count.map_or(64, |count| count as usize))?;
            Ok(View::List(
                trace
                    .frames
                    .iter()
                    .map(view::execution::stack_frame)
                    .collect(),
            ))
        }),
        "u" | "disasm" => args.addr(0).and_then(|address| {
            let count = argv
                .get(1)
                .and_then(|arg| arg.strip_prefix(['L', 'l']))
                .and_then(|count| usize::from_str_radix(count, 16).ok())
                .unwrap_or(8);
            let rows = args.state.ctx.disassemble(address, count)?;
            Ok(View::List(
                rows.iter().map(view::execution::disasm_row).collect(),
            ))
        }),
        "?" | "ev" if !args.raw_tail.is_empty() => args.eval(args.raw_tail).map(|value| {
            View::Object(vec![
                ("expression", View::Str(args.raw_tail.to_string())),
                ("value", View::Hex(value.0)),
            ])
        }),
        "r" | "registers" if argv.is_empty() => args.state.ctx.read_registers().map(|regs| {
            let register_map = &args.state.ctx.register_map;
            let mut entries: Vec<(String, View)> = register_map
                .to_hashmap(&regs)
                .into_iter()
                .map(|(name, value)| (name, View::Hex(value)))
                .chain(
                    register_map
                        .wide_values(&regs)
                        .into_iter()
                        .map(|(name, value)| (name, View::Str(format!("{value:#034x}")))),
                )
                .collect();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            View::List(
                entries
                    .into_iter()
                    .map(|(name, value)| {
                        View::Object(vec![("name", View::Str(name)), ("value", value)])
                    })
                    .collect(),
            )
        }),
        ".process" if argv.is_empty() => {
            Ok(view::execution::run_status(&args.state.ctx.run_status()))
        }
        _ => return None,
    })
}
