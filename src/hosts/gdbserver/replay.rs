//! Recorded client sessions replayed against the server over the same dump.
//!
//! The traces are `NTOSEYE_TRACE=gdb` captures of gdb, lldb, IDA and
//! Binary Ninja against the gdbstub-based server this one replaced
//! (ntoseye 6eac3d04), on a kernel dump, under `traces/dump/` of the
//! directory `NTOSEYE_GDB_TRACES` names; each trace's `.cmd` file holds the
//! server's command line, which names the dump. Every request a client sent
//! is sent again, in order, and the replies are compared with the recorded
//! ones. A reply may differ only as [`DIFFERENCES`] lists, each for a
//! reason; anything else fails the test.
//!
//! A trace cuts a packet at 200 bytes and gives its length: such a reply is
//! compared by its first 200 bytes and its length. The one request cut so
//! is gdb's `qSupported`, which is replayed without its last, cut, feature
//! (the server reads none past `multiprocess+`).

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc;
use std::thread;

use gdb_remote::frame::{Decoder, Frame, write_packet};
use gdb_remote::hex;
use gdb_remote::reply::{FileReply, ThreadList, XferChunk};
use gdb_remote::stop::StopReply;
use gdb_remote::xfer::Libraries;

use crate::TargetSpec;
use crate::backend::gdb::trace_text;
use crate::hosts::repl::open_session;

use super::Server;
use super::connection::Connection;
use super::dispatch::Flow;
use super::run_control::Wait;

/// The body the replay sends after each reply, to know where it ends.
const SYNC: &[u8] = b"replay:end-of-reply";

/// One request and the replies the baseline server sent it.
struct Exchange {
    request: Vec<u8>,
    replies: Vec<Recorded>,
}

/// A packet as a trace line gives it: its framed bytes, or the first 200
/// of them and how many there were.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Recorded {
    bytes: Vec<u8>,
    total: usize,
}

impl Recorded {
    fn complete(&self) -> bool {
        self.bytes.len() == self.total
    }

    /// The body, if the line gives all of it.
    fn body(&self) -> Option<&[u8]> {
        let framed = self.complete().then_some(&self.bytes[..])?;
        let body = framed.strip_prefix(b"$")?;
        Some(&body[..body.len().checked_sub(3)?])
    }

    /// Whether `framed`, a packet the server sent, is this one.
    fn matches(&self, framed: &[u8]) -> bool {
        framed.len() == self.total && framed.starts_with(&self.bytes)
    }
}

/// The bytes a trace line shows: `\xNN` is the byte, anything else itself;
/// a line cut at 200 bytes ends `... (N bytes)`.
fn unshow(text: &str) -> Recorded {
    let (shown, total) = match text.rsplit_once("... (") {
        Some((shown, rest)) if rest.ends_with(" bytes)") => {
            (shown, rest.trim_end_matches(" bytes)").parse().ok())
        }
        _ => (text, None),
    };
    let mut bytes = Vec::new();
    let raw = shown.as_bytes();
    let mut at = 0;
    while at < raw.len() {
        let mut escaped = Vec::new();
        if raw[at..].starts_with(b"\\x")
            && let Some(digits) = raw.get(at + 2..at + 4)
            && hex::read_bytes(&mut escaped, digits).is_ok()
        {
            bytes.extend(escaped);
            at += 4;
        } else {
            bytes.push(raw[at]);
            at += 1;
        }
    }
    let total = total.unwrap_or(bytes.len());
    Recorded { bytes, total }
}

/// The exchanges of the trace at `path`.
fn exchanges(path: &Path) -> Vec<Exchange> {
    let text = fs::read_to_string(path).unwrap();
    let mut exchanges: Vec<Exchange> = Vec::new();
    for line in text.lines() {
        if let Some((_, request)) = line.split_once(" client <- ") {
            let recorded = unshow(request);
            let framed = &recorded.bytes;
            let body = if recorded.complete() {
                framed[1..framed.len() - 3].to_vec()
            } else {
                // Only gdb's `qSupported` is long enough to be cut: drop
                // the feature the cut went through.
                assert!(framed.starts_with(b"$qSupported:"), "{line}");
                let end = framed.iter().rposition(|&byte| byte == b';').unwrap();
                framed[1..end].to_vec()
            };
            exchanges.push(Exchange {
                request: body,
                replies: Vec::new(),
            });
        } else if let Some((_, reply)) = line.split_once(" client -> ") {
            let reply = reply.strip_prefix('+').unwrap_or(reply);
            if !reply.is_empty() {
                exchanges
                    .last_mut()
                    .expect("a reply before any request")
                    .replies
                    .push(unshow(reply));
            }
        }
    }
    exchanges
}

/// The dump the trace's server ran on, from its `.cmd` file.
fn dump_of(trace: &Path) -> PathBuf {
    let command = fs::read_to_string(trace.with_extension("trace.cmd")).unwrap();
    let dump = command
        .split_whitespace()
        .skip_while(|word| *word != "--dump")
        .nth(1)
        .expect("a dump trace");
    PathBuf::from(dump)
}

/// The kind of a request, for the summary: its name or letter.
fn kind(request: &[u8]) -> String {
    let text = String::from_utf8_lossy(request);
    for prefix in ["qXfer:", "vFile:"] {
        if let Some(rest) = text.strip_prefix(prefix) {
            let name = rest.split(':').next().unwrap_or_default();
            return format!("{prefix}{name}");
        }
    }
    match text.chars().next() {
        Some(
            letter @ ('m' | 'M' | 'p' | 'P' | 'Z' | 'z' | 'H' | 'D' | 'T' | 'x' | 'X' | 'g' | 'G'
            | 'k' | '?' | '!'),
        ) => letter.to_string(),
        _ => text
            .split([':', ';', ','])
            .next()
            .unwrap_or_default()
            .to_string(),
    }
}

/// `recorded`, a `vFile` reply, as the server writes its numbers: without
/// leading zeros. `None` if it is not one.
fn file_reply_respelled(recorded: &Recorded) -> Option<Recorded> {
    let rest = recorded.bytes.strip_prefix(b"$F")?;
    let mut out = b"F".to_vec();
    let mut at = 0;
    // The result, and the errno after a comma.
    for (field, sign) in [(0, true), (1, false)] {
        if field == 1 {
            if rest.get(at) != Some(&b',') {
                break;
            }
            out.push(b',');
            at += 1;
        }
        if sign && rest.get(at) == Some(&b'-') {
            out.push(b'-');
            at += 1;
        }
        let end = at
            + rest[at..]
                .iter()
                .position(|byte| matches!(byte, b';' | b',' | b'#'))
                .unwrap_or(rest.len() - at);
        hex::write_number(&mut out, hex::read_number(&rest[at..end]).ok()?);
        at = end;
    }
    // `at` digits and signs became `out` past its `F`.
    let removed = at + 1 - out.len();
    if recorded.complete() {
        // The checksum follows the digits.
        out.extend_from_slice(&rest[at..rest.len().checked_sub(3)?]);
        let bytes = framed(&out);
        let total = bytes.len();
        return Some(Recorded { bytes, total });
    }
    out.extend_from_slice(&rest[at..]);
    let mut bytes = b"$".to_vec();
    bytes.extend(out);
    Some(Recorded {
        bytes,
        total: recorded.total - removed,
    })
}

/// Whether `new` (packet bodies the server sent) is the reply a reason
/// expects where the baseline sent `recorded` to `request`.
type Applies = fn(request: &[u8], recorded: &[Recorded], new: &[Vec<u8>]) -> bool;

/// A difference from the baseline the replacement makes on purpose: its
/// reason, and when it applies.
struct Difference {
    reason: &'static str,
    applies: Applies,
}

fn framed(body: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();
    write_packet(&mut packet, body);
    packet
}

/// The one reply each side sent, if each sent one.
fn single<'r, 'n>(
    recorded: &'r [Recorded],
    new: &'n [Vec<u8>],
) -> Option<(&'r Recorded, &'n [u8])> {
    match (recorded, new) {
        ([recorded], [new]) => Some((recorded, new)),
        _ => None,
    }
}

/// Every intended difference, by the reason for it.
const DIFFERENCES: &[Difference] = &[
    Difference {
        reason: "qSupported also offers qXfer:osdata:read+, the process list",
        applies: |request, recorded, new| {
            let Some((recorded, new)) = single(recorded, new) else {
                return false;
            };
            request.starts_with(b"qSupported")
                && recorded
                    .body()
                    .is_some_and(|body| [body, b";qXfer:osdata:read+"].concat() == new)
        },
    },
    Difference {
        reason: "thread ids and numbers are written without leading zeros (p1.1, not p01.01)",
        applies: |_, recorded, new| {
            let Some((recorded, new)) = single(recorded, new) else {
                return false;
            };
            let Some(body) = recorded.body() else {
                return false;
            };
            let same_stop = StopReply::parse(body)
                .ok()
                .zip(StopReply::parse(new).ok())
                .is_some_and(|(old, new)| old == new);
            let same_list = ThreadList::parse(body)
                .ok()
                .zip(ThreadList::parse(new).ok())
                .is_some_and(|(old, new)| old == new);
            same_stop || same_list
        },
    },
    Difference {
        reason: "vFile results are written without leading zeros (F0, F400;)",
        applies: |request, recorded, new| {
            request.starts_with(b"vFile:")
                && single(recorded, new).is_some_and(|(old, new)| {
                    file_reply_respelled(old).is_some_and(|old| old.matches(&framed(new)))
                })
        },
    },
    Difference {
        reason: "extended mode is accepted (`!`), for `attach PID`",
        applies: |request, recorded, new| {
            request == b"!"
                && single(recorded, new)
                    .is_some_and(|(old, new)| old.body() == Some(b"") && new == b"OK")
        },
    },
    Difference {
        reason: "lldb's queries are answered: qHostInfo, qProcessInfo, qC, qMemoryRegionInfo, \
                 qThreadStopInfo, x (binary memory, LLDB's way), where the baseline sent the \
                 empty reply",
        applies: |request, recorded, new| {
            let answered = [
                &b"qHostInfo"[..],
                b"qProcessInfo",
                b"qC",
                b"qMemoryRegionInfo:",
                b"qThreadStopInfo",
                b"x",
            ];
            answered.iter().any(|prefix| request.starts_with(prefix))
                && single(recorded, new)
                    .is_some_and(|(old, new)| old.body() == Some(b"") && !new.is_empty())
        },
    },
    Difference {
        reason: "vFile:lstat and vFile:readlink are answered (no such file), where the \
                 baseline sent the empty reply",
        applies: |request, recorded, new| {
            (request.starts_with(b"vFile:lstat:") || request.starts_with(b"vFile:readlink:"))
                && single(recorded, new).is_some_and(|(old, new)| {
                    old.body() == Some(b"")
                        && FileReply::parse(new).is_ok_and(|reply| reply.result == -1)
                })
        },
    },
    Difference {
        reason: "a memory read reaching unreadable memory returns the bytes before it, \
                 where the baseline failed the read (E0e)",
        applies: |request, recorded, new| {
            let Some((old, new)) = single(recorded, new) else {
                return false;
            };
            let Some(length) = request
                .strip_prefix(b"m")
                .and_then(|range| range.split(|&b| b == b',').nth(1))
                .and_then(|length| hex::read_number(length).ok())
            else {
                return false;
            };
            let mut data = Vec::new();
            old.body() == Some(b"E0e")
                && hex::read_bytes(&mut data, new).is_ok()
                && !data.is_empty()
                && (data.len() as u64) < length
        },
    },
    Difference {
        reason: "`g` of a processor the dump saved no context for reads every register as \
                 unavailable (xx), where the baseline failed the read (E79); `p` still fails, \
                 which lldb takes for unavailable",
        applies: |request, recorded, new| {
            request == b"g"
                && single(recorded, new).is_some_and(|(old, new)| {
                    old.body() == Some(b"E79") && !new.is_empty() && new.iter().all(|&b| b == b'x')
                })
        },
    },
    Difference {
        reason: "the library list is written by gdb-remote (a version attribute, one element \
                 a line), so its windows hold other bytes",
        applies: |request, recorded, new| {
            request.starts_with(b"qXfer:libraries:read:")
                && single(recorded, new).is_some_and(|(_, new)| XferChunk::parse(new).is_ok())
        },
    },
    Difference {
        reason: "a qXfer window is as long as the client asks, where gdbstub cut it to its \
                 own buffer, and one reaching the object's end says so (`l`), where gdbstub \
                 sent `m` and an empty `l` after it",
        applies: |request, recorded, new| {
            let Some((old, new)) = single(recorded, new) else {
                return false;
            };
            // The baseline's window, as far as the trace shows it, starts
            // the server's, which is no shorter.
            let old_data = match old.bytes.strip_prefix(b"$m") {
                Some(data) if old.complete() => &data[..data.len().saturating_sub(3)],
                Some(data) => data,
                None => return false,
            };
            let old_len = old.total.saturating_sub(5);
            request.starts_with(b"qXfer:")
                && matches!(new.first(), Some(b'm' | b'l'))
                && new[1..].starts_with(old_data)
                && new.len() > old_len
        },
    },
    Difference {
        reason: "monitor output is split into O packets that fit the packet size, and `lm`'s \
                 Symbols column follows the symbol cache",
        applies: |request, recorded, new| {
            let Some(command) = request.strip_prefix(b"qRcmd,") else {
                return false;
            };
            let mut command_text = Vec::new();
            let _ = hex::read_bytes(&mut command_text, command);
            let (Some((old_ok, old_output)), Some((new_ok, new_output))) =
                (recorded.split_last(), new.split_last())
            else {
                return false;
            };
            if old_ok.body() != Some(b"OK") || new_ok.as_slice() != b"OK" {
                return false;
            }
            let mut text = Vec::new();
            for packet in new_output {
                let Ok(StopReply::Output(chunk)) = StopReply::parse(packet) else {
                    return false;
                };
                text.extend(chunk);
            }
            // The baseline's one O packet, likely cut: its text's start,
            // and its length from the packet's (`$O`, digits, `#xx`).
            let [old] = old_output else {
                return false;
            };
            let Some(digits) = old.bytes.strip_prefix(b"$O") else {
                return false;
            };
            let digits = if old.complete() {
                &digits[..digits.len().saturating_sub(3)]
            } else {
                digits
            };
            let mut old_text = Vec::new();
            if hex::read_bytes(&mut old_text, &digits[..digits.len() & !1]).is_err() {
                return false;
            }
            let old_len = (old.total - 5) / 2;
            text.starts_with(&old_text)
                && (old_len == text.len() || command_text.starts_with(b"lm"))
        },
    },
];

/// Replay the dump trace `name` (`traces/dump/<name>.trace`).
fn replay(name: &str) {
    let root = std::env::var("NTOSEYE_GDB_TRACES").expect("NTOSEYE_GDB_TRACES");
    let trace = Path::new(&root).join(format!("traces/dump/{name}.trace"));
    let exchanges = exchanges(&trace);
    let spec = TargetSpec::Dump(dump_of(&trace));
    let mut session = open_session(&spec, &mut |_| {}).unwrap();
    // As the server does at start, so IDA's open of the kernel finds it.
    let _ = session.target.module_image_or_fetch_later("nt");

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (stream, _) = listener.accept().unwrap();
    let flag = || Arc::new(AtomicBool::new(false));
    let mut connection = Connection::new(stream, flag()).unwrap();

    // The client side: each reply's packets, up to the marker after it.
    let (replies_tx, replies) = mpsc::channel::<Vec<Vec<u8>>>();
    let reader = thread::spawn(move || {
        let mut decoder = Decoder::new();
        let mut buffer = vec![0u8; 1 << 16];
        let mut current = Vec::new();
        loop {
            let Ok(read @ 1..) = client.read(&mut buffer) else {
                return;
            };
            for frame in decoder.decode(&buffer[..read]) {
                match frame {
                    Frame::Packet(body) if body == SYNC => {
                        if replies_tx.send(std::mem::take(&mut current)).is_err() {
                            return;
                        }
                    }
                    Frame::Packet(body) => current.push(body),
                    _ => {}
                }
            }
        }
    });

    let mut server = Server::new(&mut session, flag(), flag());
    let mut tally: BTreeMap<(String, &'static str), usize> = BTreeMap::new();
    let mut unexpected = String::new();
    for exchange in &exchanges {
        let flow = server.handle(&mut connection, &exchange.request).unwrap();
        if let Flow::Running = flow {
            let reply = match server.wait(&mut connection).unwrap() {
                Wait::Stopped(reply) => reply,
                Wait::Interrupted => server.interrupt(),
                Wait::Terminating => unreachable!("nothing terminates a replay"),
            };
            server.flush_console(&mut connection).unwrap();
            connection.send(&reply).unwrap();
        }
        connection.send(SYNC).unwrap();
        let new = replies.recv().unwrap();
        let kind = kind(&exchange.request);
        let identical = exchange.replies.len() == new.len()
            && exchange
                .replies
                .iter()
                .zip(&new)
                .all(|(old, new)| old.matches(&framed(new)));
        let verdict = if identical {
            Some("identical")
        } else {
            DIFFERENCES
                .iter()
                .find(|difference| (difference.applies)(&exchange.request, &exchange.replies, &new))
                .map(|difference| difference.reason)
        };
        match verdict {
            Some(verdict) => *tally.entry((kind, verdict)).or_default() += 1,
            None => {
                let _ = writeln!(
                    unexpected,
                    "request {}\n  baseline: {:?}\n  now:      {:?}",
                    trace_text(&exchange.request),
                    exchange
                        .replies
                        .iter()
                        .map(|reply| trace_text(&reply.bytes))
                        .collect::<Vec<_>>(),
                    new.iter()
                        .map(|reply| trace_text(&framed(reply)))
                        .collect::<Vec<_>>(),
                );
            }
        }
        if let Flow::Leave(_) = flow {
            break;
        }
    }
    server.release();
    drop(server);
    drop(connection);
    let _ = reader.join();

    println!("{name}: {} requests", exchanges.len());
    for ((kind, verdict), count) in &tally {
        println!("  {kind:<24} {count:>6}  {verdict}");
    }
    assert!(
        unexpected.is_empty(),
        "{name}: unexpected replies:\n{unexpected}"
    );
}

#[test]
#[ignore = "needs the dump and traces named by NTOSEYE_GDB_TRACES"]
fn replay_gdb_dump() {
    replay("gdb");
}

#[test]
#[ignore = "needs the dump and traces named by NTOSEYE_GDB_TRACES"]
fn replay_lldb_dump() {
    replay("lldb");
}

/// Ghidra drives gdb, so its requests are gdb's.
#[test]
#[ignore = "needs the dump and traces named by NTOSEYE_GDB_TRACES"]
fn replay_ghidra_dump() {
    replay("ghidra");
}

#[test]
#[ignore = "needs the dump and traces named by NTOSEYE_GDB_TRACES"]
fn replay_lldb_rsp_expression_dump() {
    replay("lldb-crash-rsp-expr");
}

#[test]
#[ignore = "needs the dump and traces named by NTOSEYE_GDB_TRACES"]
fn replay_ida_dump() {
    replay("ida");
}

#[test]
#[ignore = "needs the dump and traces named by NTOSEYE_GDB_TRACES"]
fn replay_ida_rflow_dump() {
    replay("ida-rflow");
}

#[test]
#[ignore = "needs the dump and traces named by NTOSEYE_GDB_TRACES"]
fn replay_binja_dump() {
    replay("binja");
}

#[test]
#[ignore = "needs the dump and traces named by NTOSEYE_GDB_TRACES"]
fn replay_binja_detach_dump() {
    replay("binja-detach");
}

/// Libraries the replay must keep publishing: checked once, on the full
/// document, as the trace cuts every window of it.
#[test]
#[ignore = "needs the dump and traces named by NTOSEYE_GDB_TRACES"]
fn replay_library_list_names_the_kernel() {
    let root = std::env::var("NTOSEYE_GDB_TRACES").expect("NTOSEYE_GDB_TRACES");
    let trace = Path::new(&root).join("traces/dump/gdb.trace");
    let mut session = open_session(&TargetSpec::Dump(dump_of(&trace)), &mut |_| {}).unwrap();
    let mut server = Server::new(&mut session, Arc::default(), Arc::default());
    let mut xml = String::new();
    let document = server.document("libraries", "").unwrap();
    xml.push_str(std::str::from_utf8(&document).unwrap());
    let libraries = Libraries::parse(&xml).unwrap().libraries;
    assert_eq!(libraries[0].name, "/ntoskrnl.exe");
    assert!(libraries.iter().any(|library| library.name == "/hal.dll"));
}
