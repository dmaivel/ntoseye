//! The Debug Console and expression evaluation, and invalidating the
//! client's view when a console command moves the inspection context.

use std::result;

use serde_json::{Value, json};

use crate::expr::{Expr, ExprValue, NumberRadix};
use crate::layout::{FieldInfo, ParsedType};
use crate::output;
use crate::repl::{DispatchContext, Flow, RemoteClient, ReplState, ReplStore};
use crate::target::Target;
use crate::typeview::{Expand, TypeView};

use super::{Handled, Server, VarRef, arg_str};

impl Server {
    pub(super) fn on_evaluate(&mut self, args: &Value) -> Handled {
        let expression = arg_str(args, "expression").unwrap_or_default();
        if expression.trim().is_empty() {
            return Ok(Some(json!({"result": "", "variablesReference": 0})));
        }
        let context = arg_str(args, "context").unwrap_or_else(|| "repl".to_string());
        self.select_named_frame(args, "frameId")?;
        if context == "repl" {
            let before = self.inspection_context();
            let text = self.run_console_command(&expression)?;
            if self.inspection_context() != before {
                self.invalidate_context();
            }
            return Ok(Some(json!({
                "result": text,
                "variablesReference": 0,
            })));
        }
        // A watch or hover on a frame reads that frame's address space, as its
        // Locals do; only the Debug Console follows a `.process` scope.
        let attached = match args.get("frameId") {
            Some(_) => self.session()?.target.take_attached_process(),
            None => None,
        };
        let evaluated = self.evaluate_value(&expression);
        if attached.is_some() {
            self.session()?.target.restore_attached_process(attached);
        }
        evaluated
    }

    /// Evaluate a watch, hover or clipboard expression into a response body
    /// with its type, memory reference and expandable children.
    fn evaluate_value(&mut self, expression: &str) -> Handled {
        let (expr, value) = self.parse_and_evaluate(expression)?;
        let (result, type_name, memory_reference, expansion, indexed_variables) = {
            let session = self.session()?;
            let type_data = value.type_data().cloned();
            let byte_size = value.byte_size();
            let scalar = value.scalar(&session.target);
            let storage = value.address().ok();
            let register = direct_register_expression(&expr, &session.target);
            // A typed pointer rvalue has no storage of its own, but its scalar
            // is a pointee address clients can inspect or watch.
            let pointer_value = matches!(type_data, Some(ParsedType::Pointer(_)));
            let view = TypeView::new(session);
            let expansion = type_data.as_ref().and_then(|type_data| {
                view.expand_for_with_size(
                    type_data,
                    storage,
                    scalar.as_ref().ok().map(|value| value.0),
                    byte_size,
                )
            });
            let indexed_variables = match expansion.as_ref() {
                Some(Expand::Elements { count, .. }) => Some(*count),
                _ => None,
            };
            let result = match (&type_data, scalar.as_ref(), storage) {
                (Some(type_data), Ok(value), _) => view.scalar_text(value.0, type_data, byte_size),
                (Some(type_data), Err(_), Some(address)) => {
                    let field = FieldInfo {
                        offset: 0,
                        size: byte_size.unwrap_or_default(),
                        type_data: type_data.clone(),
                    };
                    view.value_text(address, &field)
                }
                (Some(_), Err(error), None) => format!("<unavailable: {error}>"),
                (None, Ok(value), _) => format!("{:#x} ({})", value.0, value.0),
                (None, Err(error), _) => return Err(error.to_string()),
            };
            let result = if result.is_empty() {
                match expansion.as_ref() {
                    Some(Expand::Fields { .. }) => "{...}".to_string(),
                    Some(Expand::Elements { count, .. }) => format!("[{count}]"),
                    None => result,
                }
            } else {
                result
            };
            let memory_reference = storage.or_else(|| {
                (!register && (type_data.is_none() || pointer_value))
                    .then(|| scalar.as_ref().ok().copied())
                    .flatten()
            });
            (
                result,
                type_data.map(|type_data| type_data.to_string()),
                memory_reference,
                expansion,
                indexed_variables,
            )
        };
        // An evaluated expression reads the inspection context, and so do
        // its children.
        let dtb = self.session()?.target.current_dtb();
        let reference = expansion
            .map(|expansion| self.var_ref(VarRef::aggregate(expansion, dtb)))
            .unwrap_or(0);
        let mut response = json!({
            "result": result,
            "variablesReference": reference,
        });
        if let Some(type_name) = type_name {
            response["type"] = json!(type_name);
        }
        if let Some(memory_reference) = memory_reference {
            response["memoryReference"] = json!(format!("{:#x}", memory_reference.0));
        }
        if let Some(indexed_variables) = indexed_variables {
            response["indexedVariables"] = json!(indexed_variables);
        }
        Ok(Some(response))
    }

    /// Parse and evaluate one expression against the selected frame.  Keeping
    /// the parsed tree alongside the value lets DAP distinguish a raw register
    /// from a typed value when resolving data-breakpoint storage.
    pub(super) fn parse_and_evaluate(
        &mut self,
        expression: &str,
    ) -> result::Result<(Expr, ExprValue), String> {
        let radix = self.repl_radix();
        let expr = Expr::parse_with_radix(expression, radix).map_err(|error| error.to_string())?;
        let session = self.session()?;
        let value = expr
            .evaluate(&session.target)
            .map_err(|error| error.to_string())?;
        Ok((expr, value))
    }

    pub(super) fn evaluate_expression(&mut self, expression: &str) -> result::Result<u64, String> {
        let radix = self.repl_radix();
        let session = self.session()?;
        Expr::eval_with_radix(expression, &session.target, radix)
            .map(|address| address.0)
            .map_err(|error| error.to_string())
    }

    fn repl_radix(&mut self) -> NumberRadix {
        self.repl
            .as_ref()
            .map(ReplStore::radix)
            .unwrap_or(NumberRadix::Hexadecimal)
    }

    /// What the console can repoint underneath the client: the selected
    /// Windows thread, the address space, and the backend vCPU. `.thread`,
    /// `.process` and `.cxr` all move one of these.
    fn inspection_context(&mut self) -> (Option<u64>, u64, String) {
        let Some(session) = self.session.as_mut() else {
            return (None, 0, String::new());
        };
        (
            session
                .parked_windows_thread()
                .map(|thread| thread.ethread.0),
            session.target.current_dtb(),
            session.current_thread.clone(),
        )
    }

    /// Tell the client its frames and variables are stale after a console
    /// command moved the inspection context. Frame ids and variable references
    /// belong to the context they were built in, so they are dropped here too.
    pub(super) fn invalidate_context(&mut self) {
        self.invalidate_stop_state();
        if self.supports_invalidated {
            self.send_event(
                "invalidated",
                json!({"areas": ["stacks", "variables", "registers"]}),
            );
            return;
        }
        self.emit_output(
            "console",
            "ntoseye: inspection context changed; this client does not support the invalidated \
             event, so the call stack and variables panes refresh at the next stop\n",
        );
    }

    /// Run one REPL command line for the Debug Console. Run-control commands
    /// are refused by [`DispatchContext::Remote`]; the client's step/continue
    /// buttons own the target.
    fn run_console_command(&mut self, line: &str) -> result::Result<String, String> {
        let session = self
            .session
            .as_mut()
            .ok_or_else(|| "no target is attached".to_string())?;
        let store = self
            .repl
            .take()
            .unwrap_or_else(|| ReplStore::new(session, DispatchContext::Remote(RemoteClient::Dap)));
        let mut state = ReplState::attach(session, store);
        state.line = line.trim().to_string();
        let (result, text) = output::capture(|| state.dispatch_line(line));
        self.repl = Some(state.detach());
        match result {
            Ok(Flow::Continue | Flow::Quit) => Ok(text),
            Ok(Flow::Denied) => Err(if text.is_empty() {
                "the debug console cannot move the target; use the client's run controls"
                    .to_string()
            } else {
                text
            }),
            Err(error) => Err(if text.is_empty() {
                error.to_string()
            } else {
                format!("{text}{error}")
            }),
        }
    }
}

/// Whether an expression names an actual CPU register directly.  Result slots,
/// convenience variables, and builtins also use the sigiled AST form but are
/// numeric address/u64 values and remain usable as memory references.
pub(super) fn direct_register_expression(expr: &Expr, target: &Target) -> bool {
    match expr {
        Expr::Register(name) => target.register_value(name).is_some(),
        Expr::Symbol(name) => {
            target
                .symbols
                .find_symbol_across_modules(target.current_dtb(), name)
                .ok()
                .flatten()
                .is_none()
                && target.register_value(name).is_some()
        }
        _ => false,
    }
}
