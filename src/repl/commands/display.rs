//! `display` and `undisplay`: expressions the stop display shows at every
//! stop, as gdb's `display` does, each value marked when it changed since
//! the last stop.

use crate::error::Result;
use crate::expr::Expr;
use crate::output::strip_ansi;
use crate::repl::*;
use crate::session::{Display, Session};
use crate::typeview::TypeView;
use crate::ui;
use crate::unwind::try_format_symbol_at;

repl_command! {
    cmd_display;
    names: ["display"],
    usage: "display [<expression>]",
    summary: "Show an expression's value at every stop.",
    details: "Each stop then ends with the display's value, marked when it changed since the last stop. The expression keeps the radix it was entered in. Without an expression, display lists the displays with their values now. undisplay removes them.",
    completion: Expression,
    style: ExpressionTail,
}

repl_command! {
    cmd_undisplay;
    names: ["undisplay"],
    usage: "undisplay <number>... | *",
    summary: "Stop showing displays at every stop.",
    completion: None,
}

/// A display's value as the stop shows it.
pub struct Shown {
    pub id: u32,
    pub expr: String,
    pub value: std::result::Result<Value, String>,
    /// Whether it differs from the value shown at the last stop.
    pub changed: bool,
}

/// What a display evaluated to.
pub enum Value {
    /// A raw expression: a number, and the symbol it points into.
    Raw { value: u64, symbol: Option<String> },
    /// A typed expression: its type and the value `dt` shows.
    Typed { type_name: String, text: String },
    /// An aggregate, which has no number: its type and where it is.
    Aggregate { type_name: String, address: u64 },
}

/// Evaluate every display. At a stop, `record` keeps each value for the
/// next stop's change marks; a listing only compares with them.
pub fn evaluate(session: &mut Session, record: bool) -> Vec<Shown> {
    let mut shown = Vec::with_capacity(session.displays.len());
    for index in 0..session.displays.len() {
        let display = &session.displays[index];
        let (value, number) = match value(session, display) {
            Ok((value, number)) => (Ok(value), number),
            Err(error) => (Err(error), None),
        };
        let display = &session.displays[index];
        let changed = matches!((display.last, number), (Some(last), Some(now)) if last != now);
        shown.push(Shown {
            id: display.id,
            expr: display.expr.clone(),
            value,
            changed,
        });
        if record {
            session.displays[index].last = number;
        }
    }
    shown
}

/// A display's value and the number its change is judged by.
fn value(
    session: &Session,
    display: &Display,
) -> std::result::Result<(Value, Option<u64>), String> {
    let target = &session.target;
    let value = Expr::parse_with_radix(&display.expr, display.radix)
        .and_then(|expr| expr.evaluate(target))
        .map_err(|error| error.to_string())?;
    let Some(type_data) = value.type_data() else {
        let raw = value.scalar(target).map_err(|error| error.to_string())?;
        let symbol = try_format_symbol_at(target, target.current_dtb(), raw.0);
        return Ok((
            Value::Raw {
                value: raw.0,
                symbol,
            },
            Some(raw.0),
        ));
    };
    let type_name = type_data.to_string();
    let byte_size = value.byte_size();
    match value.scalar(target) {
        Ok(scalar) => {
            let text = TypeView::new(session).scalar_text(scalar.0, type_data, byte_size);
            Ok((Value::Typed { type_name, text }, Some(scalar.0)))
        }
        Err(scalar_error) => {
            let address = value.address().map_err(|_| scalar_error.to_string())?;
            Ok((
                Value::Aggregate {
                    type_name,
                    address: address.0,
                },
                Some(address.0),
            ))
        }
    }
}

/// The displays as text rows: number, expression, value; a changed value
/// in yellow, an error muted.
pub fn print(shown: &[Shown]) {
    let width = shown
        .iter()
        .map(|shown| shown.expr.chars().count())
        .max()
        .unwrap_or(0)
        .min(40);
    for shown in shown {
        let text = match &shown.value {
            Ok(Value::Raw { value, symbol }) => {
                let number = ui::addr(*value);
                let number = if shown.changed {
                    ui::changed(&number)
                } else {
                    number
                };
                match symbol {
                    Some(symbol) => format!("{number}  {}", ui::symbol(symbol)),
                    None => number,
                }
            }
            Ok(Value::Typed { type_name, text }) => {
                let text = if shown.changed {
                    ui::changed(&strip_ansi(text))
                } else {
                    text.clone()
                };
                format!("{} {text}", ui::muted(type_name))
            }
            Ok(Value::Aggregate { type_name, address }) => {
                let address = ui::addr(*address);
                let address = if shown.changed {
                    ui::changed(&address)
                } else {
                    address
                };
                format!("{} at {address}", ui::muted(type_name))
            }
            Err(error) => ui::muted(error),
        };
        outln!(
            "  {}  {:<width$}  {text}",
            ui::muted(&format!("{:>2}", shown.id)),
            shown.expr
        );
    }
}

/// A listing of displays: a table in Tern, else text rows.
fn show(shown: &[Shown]) {
    #[cfg(feature = "cli")]
    crate::repl::native::render(
        || tern_sdk::View::new().main([crate::repl::native::frames::displays(shown)]),
        || {
            print(shown);
            outln!();
        },
    );
    #[cfg(not(feature = "cli"))]
    {
        print(shown);
        outln!();
    }
}

impl ReplState<'_> {
    fn cmd_display(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let expr = invocation.raw_tail.trim();
        if expr.is_empty() {
            if self.ctx.displays.is_empty() {
                outln!("no displays; display <expression> adds one\n");
                return Ok(());
            }
            let shown = evaluate(self.ctx, false);
            show(&shown);
            return Ok(());
        }
        if let Err(error) = Expr::parse_with_radix(expr, self.radix) {
            error!("{error}");
            return Ok(());
        }
        let id = self
            .ctx
            .displays
            .iter()
            .map(|display| display.id)
            .max()
            .map_or(1, |id| id + 1);
        self.ctx.displays.push(Display {
            id,
            expr: expr.to_owned(),
            radix: self.radix,
            last: None,
        });
        // Its value now, which the next stop compares with.
        let shown = evaluate(self.ctx, true);
        show(&shown[shown.len() - 1..]);
        Ok(())
    }

    fn cmd_undisplay(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let args: Vec<&str> = invocation.argv.iter().map(|arg| arg.as_ref()).collect();
        if args.is_empty() {
            outln!("{}\n", command_help("undisplay"));
            return Ok(());
        }
        if args == ["*"] {
            let count = self.ctx.displays.len();
            self.ctx.displays.clear();
            outln!(
                "removed {count} display{}\n",
                if count == 1 { "" } else { "s" }
            );
            return Ok(());
        }
        for arg in args {
            let Ok(id) = arg.parse::<u32>() else {
                error!("not a display number: {arg}");
                continue;
            };
            let before = self.ctx.displays.len();
            self.ctx.displays.retain(|display| display.id != id);
            if self.ctx.displays.len() == before {
                error!("no display {id}");
            } else {
                outln!("removed display {id}");
            }
        }
        outln!();
        Ok(())
    }
}
