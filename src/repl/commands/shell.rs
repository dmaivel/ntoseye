//! Host commands (`.shell`), which only the interactive prompt may run.

use std::io::Write;
use std::process::{Command, Stdio};
use std::thread;

use crate::error::Result;
use crate::output;
use crate::repl::*;

const SHELL: &str = ".shell";

repl_command! {
    cmd_shell -> Flow;
    names: [".shell"],
    usage: ".shell [-ci \"<debugger commands>\"] <host command>",
    summary: "Run a host command, and optionally send debugger output to it.",
    details: "The command runs <host command> with the shell of the host (sh -c). It shows what the host command writes to standard output and standard error. Then it shows the exit status if the status is not zero. The debugger waits until the host command exits. With -ci, the quoted debugger commands (separated by `;`) run first. Their output becomes the standard input of the host command. For example, `.shell -ci \"lm\" grep nt` filters the module list, and `.shell -ci \"!process 0 0\" sort` sorts the process list. ntoseye shows errors from the debugger commands and does not send them to the host command. Without -ci, the host command reads an empty standard input. The rest of the line, `;` included, is the host command. Only the interactive prompt can run .shell. ntoseye does not permit it in a line from MCP, DAP, the Python SDK, a GDB client monitor command, a breakpoint action, or an exception command, because none of these can start host programs.",
    style: RawTail,
}

impl ReplState<'_> {
    /// Why `spec` is refused here when it starts host programs: anywhere
    /// but the interactive prompt.
    pub fn host_command_denial(&self, spec: &CommandSpec) -> Option<String> {
        if spec.names[0] != SHELL {
            return None;
        }
        let source = match self.context {
            DispatchContext::Interactive => return None,
            DispatchContext::BreakpointAction => "a breakpoint action",
            DispatchContext::ExceptionCommand => "an exception command",
            DispatchContext::Remote(RemoteClient::Mcp) => "an MCP client",
            DispatchContext::Remote(RemoteClient::Dap) => "a DAP client",
            DispatchContext::Remote(RemoteClient::Sdk) => "the Python SDK",
            DispatchContext::Remote(RemoteClient::Gdb) => "a GDB client",
        };
        Some(format!(
            "'{SHELL}' runs host programs, which {source} may not start; run it at the \
             interactive prompt"
        ))
    }

    fn cmd_shell(&mut self, invocation: CommandInvocation<'_>) -> Result<Flow> {
        let tail = invocation.raw_tail.trim();
        let (commands, host_command) = match tail.strip_prefix("-ci") {
            Some(rest) if rest.is_empty() || rest.starts_with(char::is_whitespace) => {
                let Some((commands, rest)) = take_quoted(rest.trim_start()) else {
                    error!("{SHELL}: -ci takes the debugger commands in quotes");
                    return Ok(Flow::Continue);
                };
                (Some(commands), rest.trim())
            }
            _ => (None, tail),
        };
        if host_command.is_empty() {
            outln!("{}\n", command_help(invocation.name));
            return Ok(Flow::Continue);
        }
        let input = match commands {
            Some(commands) => {
                let (flow, text) = output::capture_output(|| self.dispatch_line(&commands));
                match flow? {
                    Flow::Continue => Some(text),
                    flow => return Ok(flow),
                }
            }
            None => None,
        };
        run_host_command(host_command, input);
        Ok(Flow::Continue)
    }
}

/// Run `command` with `sh -c`, `input` on its standard input, and print what
/// it writes.
fn run_host_command(command: &str, input: Option<String>) {
    let child = Command::new("sh")
        // `--` so a command starting with `-` is not read as sh options.
        .args(["-c", "--", command])
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match child {
        Ok(child) => child,
        Err(error) => {
            error!("{SHELL}: failed to start sh: {error}");
            return;
        }
    };
    // Fed from its own thread so a filter that writes as it reads cannot
    // deadlock against a full output pipe. A filter that exits early (`head`)
    // closes the pipe; the rest of the input is dropped.
    let writer = child
        .stdin
        .take()
        .zip(input)
        .map(|(mut stdin, input)| thread::spawn(move || stdin.write_all(input.as_bytes())));
    let result = child.wait_with_output();
    if let Some(writer) = writer {
        let _ = writer.join();
    }
    let output = match result {
        Ok(output) => output,
        Err(error) => {
            error!("{SHELL}: {error}");
            return;
        }
    };
    for stream in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(stream);
        if text.is_empty() {
            continue;
        }
        out!("{text}");
        if !text.ends_with('\n') {
            outln!();
        }
    }
    if !output.status.success() {
        match output.status.code() {
            Some(code) => outln!("{SHELL}: '{command}' exited with status {code}"),
            None => outln!("{SHELL}: '{command}' was terminated by a signal"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::capture;
    use crate::session::session_over_memory;

    fn run(line: &str, context: DispatchContext) -> (Flow, String) {
        let mut session = session_over_memory(0x1000, &[0u8; 8]);
        let mut state = ReplState::for_oneshot(&mut session);
        state.context = context;
        let (flow, text) = capture(|| state.dispatch_line(line));
        (flow.unwrap(), text)
    }

    #[test]
    fn debugger_output_is_piped_through_the_host_filter() {
        let (flow, text) = run(
            ".shell -ci \".echo b; .echo a; .echo c\" sort -r",
            DispatchContext::Interactive,
        );
        assert_eq!(flow, Flow::Continue);
        assert_eq!(text, "c\nb\na\n");
    }

    #[test]
    fn only_the_interactive_prompt_starts_host_programs() {
        let marker = std::env::temp_dir().join(format!("ntoseye-shell-{}", std::process::id()));
        let _ = std::fs::remove_file(&marker);
        for context in [
            DispatchContext::BreakpointAction,
            DispatchContext::ExceptionCommand,
            DispatchContext::Remote(RemoteClient::Mcp),
            DispatchContext::Remote(RemoteClient::Dap),
            DispatchContext::Remote(RemoteClient::Sdk),
            DispatchContext::Remote(RemoteClient::Gdb),
        ] {
            // Nested in a loop too, which runs its body in the same context.
            let line = format!(
                ".foreach /s (x \"1\") {{.shell touch {0}}}; .shell touch {0}",
                marker.display()
            );
            let (flow, text) = run(&line, context);
            assert_eq!(flow, Flow::Denied, "{context:?}: {text}");
            assert!(!marker.exists(), "{context:?} started a host program");
        }
        let (flow, _) = run(
            &format!(".shell touch {}", marker.display()),
            DispatchContext::Interactive,
        );
        assert_eq!(flow, Flow::Continue);
        assert!(marker.exists());
        let _ = std::fs::remove_file(&marker);
    }
}
