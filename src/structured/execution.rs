//! Debugger execution state: vCPUs, breakpoints, stacks, disassembly,
//! expression values, registers, and run status.

use super::Args;
use crate::error::Result;
use crate::view::execution::{ExpressionValue, RegisterContent, RegisterValue};
use crate::view::{self, View};

pub(super) fn command(name: &str, args: &mut Args<'_, '_>) -> Option<Result<View>> {
    let argv = args.argv;
    Some(match name {
        "~" | "vcpus" if argv.is_empty() => args
            .state
            .ctx
            .vcpus()
            .map(|vcpus| View::list(vcpus.iter().map(view::execution::vcpu))),
        "bl" => Ok(View::list(
            args.state
                .ctx
                .list_breakpoints()
                .into_iter()
                .map(view::execution::breakpoint),
        )),
        "k" | "kn" | "kb" | "kp" | "kv" | "kf" => args.opt_value(0).and_then(|count| {
            let trace = args
                .state
                .ctx
                .backtrace(count.map_or(64, |count| count as usize))?;
            Ok(View::list(
                trace.frames.iter().map(view::execution::stack_frame),
            ))
        }),
        "u" | "disasm" => args.addr(0).and_then(|address| {
            let count = argv
                .get(1)
                .and_then(|arg| arg.strip_prefix(['L', 'l']))
                .and_then(|count| usize::from_str_radix(count, 16).ok())
                .unwrap_or(8);
            let rows = args.state.ctx.disassemble(address, count)?;
            Ok(View::list(rows.iter().map(view::execution::disasm_row)))
        }),
        "?" | "ev" if !args.raw_tail.is_empty() => args.eval(args.raw_tail).map(|value| {
            ExpressionValue {
                expression: args.raw_tail.to_string(),
                value,
            }
            .into_view()
        }),
        ".fnent" => args.addr(0).and_then(|address| {
            let detail = args.state.ctx.function_entry(address)?;
            Ok(view::execution::function_entry(&detail).into_view())
        }),
        "r" | "registers" if argv.is_empty() => args.state.ctx.read_registers().map(|regs| {
            let register_map = &args.state.ctx.register_map;
            let mut registers: Vec<RegisterValue> = register_map
                .to_hashmap(&regs)
                .into_iter()
                .map(|(name, value)| RegisterValue {
                    name,
                    value: RegisterContent::Scalar(value),
                })
                .chain(
                    register_map
                        .wide_values(&regs)
                        .into_iter()
                        .map(|(name, value)| RegisterValue {
                            name,
                            value: RegisterContent::Wide(format!("{value:#034x}")),
                        }),
                )
                .collect();
            registers.sort_by(|left, right| left.name.cmp(&right.name));
            View::list(registers)
        }),
        ".process" if argv.is_empty() => {
            Ok(view::execution::run_status(&args.state.ctx.run_status()).into_view())
        }
        _ => return None,
    })
}
