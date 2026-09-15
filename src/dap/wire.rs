//! Debug Adapter Protocol framing: `Content-Length: N\r\n\r\n{json}` over any
//! byte stream (stdio or a TCP socket).
//!
//! The reader runs on its own thread and forwards decoded messages over a
//! channel, because the session it drives is `!Send` and must stay on the
//! thread that created it.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::thread;

use serde_json::{Value, from_slice, json, to_vec};

/// Bound allocations from client-supplied frame lengths.
const MAX_CONTENT_LENGTH: usize = 64 * 1024 * 1024;

/// Raise cancellation on the reader thread while the server is blocked in run control.
const CANCELING_COMMANDS: [&str; 3] = ["pause", "disconnect", "terminate"];

/// What the reader thread hands to the server loop.
pub enum ClientMessage {
    /// A decoded protocol message (always a request in practice; the adapter
    /// issues no reverse requests).
    Message(Value),
    /// The client closed the stream.
    Eof,
    /// The stream broke or carried an undecodable message.
    Error(String),
}

/// One client request, projected out of the raw message.
pub struct Request {
    pub seq: i64,
    pub command: String,
    pub arguments: Value,
}

impl Request {
    /// Project a `{"type":"request"}` message. Anything else (a response to a
    /// reverse request we never send) yields `None`.
    pub fn from_message(message: &Value) -> Option<Self> {
        if message.get("type").and_then(Value::as_str) != Some("request") {
            return None;
        }
        Some(Self {
            seq: message.get("seq").and_then(Value::as_i64).unwrap_or(0),
            command: message.get("command").and_then(Value::as_str)?.to_string(),
            arguments: message
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({})),
        })
    }
}

/// Read one framed message. `Ok(None)` is a clean end of stream.
pub fn read_message<R: BufRead>(input: &mut R) -> io::Result<Option<Value>> {
    let mut length: Option<usize> = None;
    let mut line = String::new();
    loop {
        line.clear();
        if input.read_line(&mut line)? == 0 {
            return Ok(None);
        }
        let header = line.trim_end_matches(['\r', '\n']);
        if header.is_empty() {
            break;
        }
        let Some((name, value)) = header.split_once(':') else {
            return Err(invalid(format!("malformed DAP header {header:?}")));
        };
        if !name.trim().eq_ignore_ascii_case("content-length") {
            continue;
        }
        let parsed = value
            .trim()
            .parse::<usize>()
            .map_err(|_| invalid(format!("invalid Content-Length {:?}", value.trim())))?;
        if parsed > MAX_CONTENT_LENGTH {
            return Err(invalid(format!("Content-Length {parsed} too large")));
        }
        length = Some(parsed);
    }

    let Some(length) = length else {
        return Err(invalid("DAP message without a Content-Length header"));
    };
    let mut body = vec![0u8; length];
    input.read_exact(&mut body)?;
    from_slice(&body)
        .map(Some)
        .map_err(|error| invalid(format!("undecodable DAP message: {error}")))
}

/// Write one framed message.
pub fn write_message<W: Write>(out: &mut W, message: &Value) -> io::Result<()> {
    let body = to_vec(message)?;
    write!(out, "Content-Length: {}\r\n\r\n", body.len())?;
    out.write_all(&body)?;
    out.flush()
}

/// Decode messages off `input` until it ends, forwarding each to `tx`. The
/// thread exits when the stream ends, the stream breaks, or the receiver is
/// dropped.
///
/// `cancel` is the run-control cancel flag the server shares with the session.
/// It is raised here, before the message is queued, so a `pause` cannot be
/// stuck behind the very run it is meant to interrupt. A stream that ends or
/// breaks raises it too: there is no client left to answer, and a step over a
/// call that never returns would otherwise run the guest forever.
pub fn spawn_reader<R: Read + Send + 'static>(
    input: R,
    tx: Sender<ClientMessage>,
    cancel: Arc<AtomicBool>,
) {
    thread::spawn(move || {
        let mut input = BufReader::new(input);
        loop {
            let message = match read_message(&mut input) {
                Ok(Some(message)) => {
                    if cancels_a_run(&message) {
                        cancel.store(true, Ordering::Relaxed);
                    }
                    ClientMessage::Message(message)
                }
                Ok(None) => {
                    cancel.store(true, Ordering::Relaxed);
                    let _ = tx.send(ClientMessage::Eof);
                    return;
                }
                Err(error) => {
                    cancel.store(true, Ordering::Relaxed);
                    let _ = tx.send(ClientMessage::Error(error.to_string()));
                    return;
                }
            };
            if tx.send(message).is_err() {
                return;
            }
        }
    });
}

/// Whether this message is one of the requests that must interrupt a blocking
/// run instead of waiting for it.
fn cancels_a_run(message: &Value) -> bool {
    Request::from_message(message)
        .is_some_and(|request| CANCELING_COMMANDS.contains(&request.command.as_str()))
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::mpsc;

    fn frame(body: &str) -> String {
        format!("Content-Length: {}\r\n\r\n{}", body.len(), body)
    }

    #[test]
    fn reads_consecutive_messages() {
        let stream = format!(
            "{}{}",
            frame(r#"{"seq":1,"type":"request","command":"initialize"}"#),
            frame(r#"{"seq":2,"type":"request","command":"threads"}"#)
        );
        let mut input = Cursor::new(stream.into_bytes());

        let first = read_message(&mut input).unwrap().unwrap();
        let second = read_message(&mut input).unwrap().unwrap();

        assert_eq!(first["command"], "initialize");
        assert_eq!(second["seq"], 2);
        assert!(read_message(&mut input).unwrap().is_none());
    }

    #[test]
    fn tolerates_extra_headers_and_header_case() {
        let body = r#"{"seq":7,"type":"request","command":"threads"}"#;
        let stream = format!(
            "content-length: {}\r\nContent-Type: application/vscode-jsonrpc\r\n\r\n{}",
            body.len(),
            body
        );
        let mut input = Cursor::new(stream.into_bytes());

        let message = read_message(&mut input).unwrap().unwrap();

        assert_eq!(message["seq"], 7);
    }

    #[test]
    fn body_bytes_are_read_exactly() {
        // A body containing a header-looking line must not confuse framing.
        let body = r#"{"seq":1,"type":"request","command":"evaluate","arguments":{"expression":"Content-Length: 5\r\n\r\n"}}"#;
        let stream = format!(
            "{}{}",
            frame(body),
            frame(r#"{"seq":2,"type":"request","command":"threads"}"#)
        );
        let mut input = Cursor::new(stream.into_bytes());

        let first = read_message(&mut input).unwrap().unwrap();
        let second = read_message(&mut input).unwrap().unwrap();

        assert_eq!(
            first["arguments"]["expression"],
            "Content-Length: 5\r\n\r\n"
        );
        assert_eq!(second["command"], "threads");
    }

    #[test]
    fn missing_content_length_is_an_error() {
        let mut input = Cursor::new(b"X-Thing: 1\r\n\r\n{}".to_vec());
        assert!(read_message(&mut input).is_err());
    }

    #[test]
    fn oversized_content_length_is_rejected_without_allocating() {
        let mut input = Cursor::new(b"Content-Length: 99999999999\r\n\r\n".to_vec());
        assert!(read_message(&mut input).is_err());
    }

    #[test]
    fn written_frames_round_trip() {
        let mut buffer = Vec::new();
        write_message(
            &mut buffer,
            &json!({"seq": 3, "type": "event", "event": "stopped"}),
        )
        .unwrap();

        let mut input = Cursor::new(buffer);
        let message = read_message(&mut input).unwrap().unwrap();

        assert_eq!(message["event"], "stopped");
    }

    #[test]
    fn non_requests_are_not_projected() {
        let message = json!({"seq": 5, "type": "response", "command": "runInTerminal"});
        assert!(Request::from_message(&message).is_none());
    }

    #[test]
    fn pause_raises_the_cancel_flag_before_the_loop_sees_it() {
        // The server loop is blocked inside run control while the target runs,
        // so the flag must already be set by the time the message is queued.
        let stream = frame(r#"{"seq":9,"type":"request","command":"pause"}"#);
        let (tx, rx) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));

        spawn_reader(Cursor::new(stream.into_bytes()), tx, Arc::clone(&cancel));
        let message = rx.recv().unwrap();

        assert!(cancel.load(Ordering::Relaxed));
        assert!(matches!(message, ClientMessage::Message(_)));
    }

    #[test]
    fn only_run_control_requests_cancel_a_run() {
        for command in ["pause", "disconnect", "terminate"] {
            let message = json!({"seq": 1, "type": "request", "command": command});
            assert!(cancels_a_run(&message), "{command}");
        }
        for command in ["stackTrace", "variables", "evaluate", "setBreakpoints"] {
            let message = json!({"seq": 1, "type": "request", "command": command});
            assert!(!cancels_a_run(&message), "{command}");
        }
    }

    #[test]
    fn a_closed_stream_cancels_the_run_it_left_behind() {
        let (tx, rx) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));

        spawn_reader(Cursor::new(Vec::new()), tx, Arc::clone(&cancel));

        assert!(matches!(rx.recv().unwrap(), ClientMessage::Eof));
        assert!(cancel.load(Ordering::Relaxed));
    }
}
