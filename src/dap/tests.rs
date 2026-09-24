use std::cell::RefCell;
use std::io::Cursor;
use std::rc::Rc;

use super::memory::MAX_DISASSEMBLE_INSTRUCTIONS;
use super::variables::VARIABLES_BASE;
use super::*;
use crate::expr::Expr;
use crate::guest::ProcessInfo;
use crate::layout::{FieldInfo, TypeInfo};
use crate::session::session_over_memory;
use crate::symbols::{LocalVariableLocation, ProcedureLocal};

#[test]
fn a_disassembly_request_cannot_ask_for_unbounded_work() {
    let session = session_over_memory(0x1000, &[0x90u8; 0x40]);
    let (_tx, rx) = mpsc::channel();
    let (mut server, _sink) = server_with_sink(Some(session), rx);

    let answer = server
        .on_disassemble(&json!({
            "memoryReference": "0x1000",
            "instructionCount": i64::MAX,
            "instructionOffset": i64::MIN,
        }))
        .expect("the request is answered, not refused")
        .expect("a body is returned");

    let instructions = answer["instructions"].as_array().expect("instructions");
    assert_eq!(instructions.len(), MAX_DISASSEMBLE_INSTRUCTIONS);
}

#[test]
fn a_short_backward_decode_keeps_the_reference_at_its_offset() {
    // Nothing is mapped below 0x1000, so the eight instructions before
    // the reference cannot be decoded. The client takes the reference's
    // address from row `-instructionOffset`, so the hole goes in front.
    let session = session_over_memory(0x1000, &[0x90u8; 0x1000]);
    let (_tx, rx) = mpsc::channel();
    let (mut server, _sink) = server_with_sink(Some(session), rx);

    let answer = server
        .on_disassemble(&json!({
            "memoryReference": "0x1000",
            "instructionOffset": -8,
            "instructionCount": 16,
        }))
        .unwrap()
        .unwrap();

    let instructions = answer["instructions"].as_array().unwrap();
    assert_eq!(instructions.len(), 16);
    for row in &instructions[..8] {
        assert_eq!(row["address"], "-1", "{row}");
        assert_eq!(row["presentationHint"], "invalid");
    }
    assert_eq!(instructions[8]["address"], "0x1000");
    assert_eq!(instructions[9]["address"], "0x1001");
}

#[test]
fn a_cancelled_run_that_left_the_target_halted_is_a_pause_stop() {
    // `run_to` halts the target to lift its temporary breakpoint before
    // reporting `Running` for a cancelled step; that halt is the stop the
    // client's `pause` asked for.
    let session = session_over_memory(0x1000, &[0x90u8; 0x40]);
    let (_tx, rx) = mpsc::channel();
    let (mut server, sink) = server_with_sink(Some(session), rx);
    server.state = RunState::Running;

    server.report_stop(ContinueOutcome::Running);

    assert!(matches!(server.state, RunState::Halted));
    let messages = decode_sink(&sink);
    let stopped = messages
        .iter()
        .find(|message| message["event"] == "stopped")
        .unwrap_or_else(|| panic!("no stopped event in {messages:?}"));
    assert_eq!(stopped["body"]["reason"], "pause");
}

#[test]
fn terminate_keeps_serving_until_the_client_disconnects() {
    // The client follows `terminated` with its own `disconnect`.
    let session = session_over_memory(0x1000, &[0u8; 0x40]);
    let messages = serve_script_with(
        Some(session),
        &[
            request(1, "terminate"),
            request(2, "threads"),
            request(3, "disconnect"),
        ],
    );

    let responses: Vec<&Value> = messages
        .iter()
        .filter(|message| message["type"] == "response")
        .collect();
    assert_eq!(responses.len(), 3, "{messages:?}");
    assert_eq!(responses[0]["command"], "terminate");
    assert_eq!(responses[0]["success"], true);
    assert_eq!(responses[1]["command"], "threads");
    assert_eq!(responses[1]["success"], false, "the target was released");
    assert_eq!(responses[2]["command"], "disconnect");
    assert_eq!(
        messages
            .iter()
            .filter(|message| message["event"] == "terminated")
            .count(),
        1,
        "{messages:?}"
    );
}

#[test]
fn one_object_keeps_one_reference_however_often_it_is_asked_for() {
    const COUNT: u32 = 2048;
    let mut memory = vec![0u8; COUNT as usize * 8];
    for index in 0..COUNT as usize {
        // Distinct pointees, so each row names a different guest object.
        memory[index * 8..index * 8 + 8]
            .copy_from_slice(&(0x1000u64 + index as u64 * 8).to_le_bytes());
    }
    let session = session_over_memory(0x1000, &memory);
    let dtb = session.target.current_dtb();
    session.target.symbols.set_kernel(Some(1), dtb);
    session.target.symbols.inject_module_for_test(
        1,
        vec![TypeInfo {
            name: "_NODE".to_string(),
            pointer_size: 8,
            size: 8,
            fields: HashMap::new(),
        }],
        &[],
    );
    let (_tx, rx) = mpsc::channel();
    let (mut server, _sink) = server_with_sink(Some(session), rx);
    let array = server.var_ref(VarRef::Elements {
        element: ParsedType::Pointer(Box::new(ParsedType::Struct("_NODE".to_string()))),
        count: COUNT,
        element_size: 8,
        address: VirtAddr(0x1000),
        dtb,
    });
    let page = |server: &mut Server| {
        let body = server
            .on_variables(&json!({
                "variablesReference": array,
                "filter": "indexed",
                "start": 0,
                "count": 64,
            }))
            .unwrap()
            .unwrap();
        body["variables"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["variablesReference"].as_i64().unwrap())
            .collect::<Vec<_>>()
    };

    let first = page(&mut server);
    assert_eq!(first.len(), 64);
    let after_first = server.vars.len();

    // The same 64 rows, asked for four more times.
    for _ in 0..4 {
        assert_eq!(page(&mut server), first, "a row changed reference");
    }
    assert_eq!(
        server.vars.len(),
        after_first,
        "re-reading one window grew the reference table"
    );

    server.invalidate_stop_state();
    assert!(server.vars.is_empty());
}

#[test]
fn addresses_parse_from_hex_and_decimal() {
    assert_eq!(
        parse_address("0xfffff80012345678").unwrap(),
        0xfffff800_12345678
    );
    assert_eq!(parse_address(" 0X10 ").unwrap(), 0x10);
    assert_eq!(parse_address("4096").unwrap(), 4096);
    assert!(parse_address("nt!KeBugCheckEx").is_err());
}

#[test]
fn source_without_a_local_file_is_not_advertised_as_openable() {
    let location = SourceLocation {
        file: "d:\\src\\driver.c".to_string(),
        line: 42,
        column: None,
        local_path: Some(PathBuf::from("/tmp/nonexistent/driver.c")),
        local_exists: false,
    };
    let value = source_value(&location);
    assert!(value.get("path").is_none());
    assert_eq!(value["name"], json!("driver.c"));
}

#[test]
fn dump_targets_take_precedence_over_live_backend_arguments() {
    let spec = target_spec(&json!({"dump": "/tmp/crash.dmp", "backend": "gdb"})).unwrap();
    assert!(matches!(spec, TargetSpec::Dump(path) if path.ends_with("crash.dmp")));
}

/// A `Write` the loop can own while the test keeps reading what it wrote.
struct Sink(Rc<RefCell<Vec<u8>>>);

impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Run the server loop over a scripted client with no target attached and
/// return the messages it wrote back, decoded.
fn serve_script(requests: &[Value]) -> Vec<Value> {
    serve_script_with(None, requests)
}

/// Run the server loop over a scripted client and return the messages it
/// wrote back, decoded, in the order they were written.
fn serve_script_with(session: Option<Session>, requests: &[Value]) -> Vec<Value> {
    let (tx, rx) = mpsc::channel();
    for request in requests {
        tx.send(ClientMessage::Message(request.clone())).unwrap();
    }
    tx.send(ClientMessage::Eof).unwrap();

    let (mut server, sink) = server_with_sink(session, rx);
    server.serve();
    decode_sink(&sink)
}

/// A server writing into a buffer the test can read, for handlers driven
/// directly instead of through the loop.
fn server_with_sink(
    session: Option<Session>,
    rx: Receiver<ClientMessage>,
) -> (Server, Rc<RefCell<Vec<u8>>>) {
    let sink = Rc::new(RefCell::new(Vec::new()));
    let server = Server::new(
        session,
        Box::new(Sink(Rc::clone(&sink))),
        rx,
        Arc::new(AtomicBool::new(false)),
    );
    (server, sink)
}

fn decode_sink(sink: &Rc<RefCell<Vec<u8>>>) -> Vec<Value> {
    let written = sink.borrow().clone();
    let mut input = Cursor::new(written);
    let mut messages = Vec::new();
    while let Some(message) = wire::read_message(&mut input).unwrap() {
        messages.push(message);
    }
    messages
}

fn request(seq: i64, command: &str) -> Value {
    json!({"seq": seq, "type": "request", "command": command})
}

#[test]
fn a_termination_signal_releases_the_target_before_the_loop_exits() {
    // The loop must detach before exiting.
    let session = session_over_memory(0x1000, &[0u8; 0x40]);
    let (_tx, rx) = mpsc::channel();
    let (mut server, sink) = server_with_sink(Some(session), rx);
    server.terminating.store(true, Ordering::SeqCst);

    server.serve();

    assert!(server.session.is_none(), "the target was not released");
    let messages = decode_sink(&sink);
    assert!(
        messages.iter().any(|message| {
            message["event"] == "output"
                && message["body"]["output"]
                    .as_str()
                    .is_some_and(|text| text.contains("detached"))
        }),
        "{messages:?}"
    );
    assert!(
        messages
            .iter()
            .any(|message| message["event"] == "terminated"),
        "{messages:?}"
    );
}

#[test]
fn a_console_context_change_invalidates_the_clients_view() {
    // `.thread` in the console repoints the stack and variables; frame ids
    // and variable references from the previous context must die with it.
    let (_tx, rx) = mpsc::channel();
    let (mut server, sink) = server_with_sink(None, rx);
    server.supports_invalidated = true;
    server.frames.push(FrameRef {
        thread: 1,
        index: 0,
        ip: 0x1000,
        sp: 0x2000,
        symbol: "0x1000".to_string(),
        source_location: None,
        frame_base: None,
        registers: HashMap::new(),
        seed_registers: HashMap::new(),
        dtb: 0,
    });
    server.vars.push(VarRef::Locals(0));

    server.invalidate_context();

    let messages = decode_sink(&sink);
    assert_eq!(messages.len(), 1, "{messages:?}");
    assert_eq!(messages[0]["event"], "invalidated");
    assert_eq!(
        messages[0]["body"]["areas"],
        json!(["stacks", "variables", "registers"])
    );
    assert!(server.frames.is_empty() && server.vars.is_empty());
}

#[test]
fn stack_frames_use_recovered_symbol_and_source_metadata() {
    let (_tx, rx) = mpsc::channel();
    let (mut server, _sink) = server_with_sink(None, rx);
    server.lines_start_at_1 = true;
    server.columns_start_at_1 = true;
    server.frames.push(FrameRef {
        thread: 1,
        index: 0,
        ip: 0x1234,
        sp: 0x2000,
        symbol: "driver!RecoveredRoutine+0x4".to_string(),
        source_location: Some(SourceLocation {
            file: r"C:\build\driver.c".to_string(),
            line: 42,
            column: Some(7),
            local_path: None,
            local_exists: false,
        }),
        frame_base: None,
        registers: HashMap::new(),
        seed_registers: HashMap::new(),
        dtb: 0,
    });

    let frame = server.frame_value(0);

    assert_eq!(frame["name"], "driver!RecoveredRoutine+0x4");
    assert_eq!(frame["line"], 42);
    assert_eq!(frame["column"], 7);
    assert_eq!(frame["source"]["origin"], "recorded as C:\\build\\driver.c");
}

/// A frame's locals live where the frame was recovered. A parked thread's
/// stack is walked in its own process, which need not be the console's
/// inspection context.
#[test]
fn locals_come_from_the_address_space_the_frame_was_recovered_in() {
    let session = session_over_memory(0x1000, &[0u8; 0x40]);
    let inspection_dtb = session.target.current_dtb();
    let process_dtb = 0x1a_b000;
    assert_ne!(inspection_dtb, process_dtb);
    session.target.symbols.set_kernel(Some(1), inspection_dtb);
    session
        .target
        .symbols
        .register_module_for_test(2, "driver", process_dtb);
    let base = 0x3000_0000;
    session.target.symbols.inject_procedure_locals_for_test(
        2,
        0x10,
        vec![ProcedureLocal {
            name: "count".to_string(),
            type_name: "ULONG".to_string(),
            type_data: ParsedType::Primitive("ULONG".to_string()),
            byte_size: Some(4),
            is_parameter: false,
            location: LocalVariableLocation::Register {
                register: "rbx".to_string(),
            },
        }],
    );
    let (_tx, rx) = mpsc::channel();
    let (mut server, _sink) = server_with_sink(Some(session), rx);
    let ip = base + 0x10;
    server.frames.push(FrameRef {
        thread: 1,
        index: 1,
        ip,
        sp: 0x2000,
        symbol: "driver!Routine+0x10".to_string(),
        source_location: None,
        frame_base: None,
        registers: HashMap::from([("rip".to_string(), ip), ("rbx".to_string(), 0x2a)]),
        seed_registers: HashMap::new(),
        dtb: process_dtb,
    });

    let locals = rows(server.local_variables(0).unwrap());

    let value = row(&locals, "count")["value"].as_str().unwrap();
    assert!(value.starts_with("0x2a"), "{value}");
}

#[test]
fn watches_evaluate_in_the_address_space_the_frame_was_recovered_in() {
    let mut session = session_over_memory(0x1000, &[0u8; 0x40]);
    let inspection_dtb = session.target.current_dtb();
    let process_dtb = 0x1a_b000;
    session.target.symbols.set_kernel(Some(1), inspection_dtb);
    session
        .target
        .symbols
        .register_module_for_test(2, "driver", process_dtb);
    let base = 0x3000_0000;
    session.target.symbols.inject_procedure_locals_for_test(
        2,
        0x10,
        vec![ProcedureLocal {
            name: "count".to_string(),
            type_name: "ULONG".to_string(),
            type_data: ParsedType::Primitive("ULONG".to_string()),
            byte_size: Some(4),
            is_parameter: false,
            location: LocalVariableLocation::Register {
                register: "rbx".to_string(),
            },
        }],
    );
    // The console is scoped to an unrelated process; the watch still reads
    // the frame's.
    let attached_dtb = 0x2c_d000;
    session.target.enter_process_scope(ProcessInfo {
        pid: 8,
        name: "other.exe".to_string(),
        dtb: attached_dtb,
        eprocess_va: VirtAddr(0),
        wow64_peb: None,
    });
    let (_tx, rx) = mpsc::channel();
    let (mut server, _sink) = server_with_sink(Some(session), rx);
    let ip = base + 0x10;
    server.frames.push(FrameRef {
        thread: 1,
        index: 1,
        ip,
        sp: 0x2000,
        symbol: "driver!Routine+0x10".to_string(),
        source_location: None,
        frame_base: None,
        registers: HashMap::from([("rip".to_string(), ip), ("rbx".to_string(), 0x2a)]),
        seed_registers: HashMap::new(),
        dtb: process_dtb,
    });

    let response = server
        .on_evaluate(&json!({
            "expression": "count",
            "context": "watch",
            "frameId": 1,
        }))
        .unwrap()
        .unwrap();

    assert!(
        response["result"].as_str().unwrap().starts_with("0x2a"),
        "{response}"
    );
    let target = &server.session.as_ref().unwrap().target;
    assert_eq!(target.current_dtb(), attached_dtb);
}

#[test]
fn requests_before_an_attach_fail_instead_of_going_unanswered() {
    // Every request must produce exactly one response, or the client hangs
    // waiting for one.
    let messages = serve_script(&[
        request(1, "initialize"),
        request(2, "threads"),
        request(3, "modules"),
        request(4, "restart"),
    ]);

    let responses: Vec<&Value> = messages
        .iter()
        .filter(|message| message["type"] == "response")
        .collect();
    assert_eq!(responses.len(), 4, "{messages:?}");
    assert_eq!(responses[1]["success"], false);
    assert!(
        responses[1]["message"].as_str().unwrap().contains("attach"),
        "{:?}",
        responses[1]
    );
    assert_eq!(responses[2]["success"], false);
    assert_eq!(responses[3]["success"], false);
    assert!(
        responses[3]["message"]
            .as_str()
            .unwrap()
            .contains("restart"),
        "{:?}",
        responses[3]
    );
}

#[test]
fn disconnect_is_answered_before_the_loop_exits() {
    let messages = serve_script(&[request(1, "disconnect")]);

    assert!(
        messages
            .iter()
            .any(|message| message["event"] == "terminated"),
        "{messages:?}"
    );
    assert!(
        messages.iter().any(|message| message["type"] == "response"
            && message["command"] == "disconnect"
            && message["success"] == true),
        "{messages:?}"
    );
}

#[test]
fn instruction_and_data_breakpoints_honor_hit_conditions() {
    let session = session_over_memory(0x1000, &[0u8; 0x40]);
    let (_tx, rx) = mpsc::channel();
    let (mut server, _sink) = server_with_sink(Some(session), rx);

    // Reject non-decimal pass counts for both breakpoint kinds.
    for (request, args) in [
        (
            "instruction",
            json!({"breakpoints": [{"instructionReference": "0x1000", "hitCondition": ">5"}]}),
        ),
        (
            "data",
            json!({"breakpoints": [{"dataId": "0x1000:4", "hitCondition": ">5"}]}),
        ),
    ] {
        let body = match request {
            "instruction" => server.on_set_instruction_breakpoints(&args),
            _ => server.on_set_data_breakpoints(&args),
        }
        .expect("handler answers")
        .expect("body");
        let entry = &body["breakpoints"][0];
        assert_eq!(entry["verified"], json!(false), "{request}: {body}");
        assert!(
            entry["message"]
                .as_str()
                .is_some_and(|text| text.contains("decimal pass count")),
            "{request} breakpoint ignored its hit condition: {body}"
        );
    }
}

#[test]
fn disconnect_releases_the_target_before_answering() {
    // Detach must precede the disconnect response.
    let session = session_over_memory(0x1000, &[0u8; 0x40]);
    let messages = serve_script_with(Some(session), &[request(1, "disconnect")]);

    let detached = messages
        .iter()
        .position(|message| {
            message["event"] == "output"
                && message["body"]["output"]
                    .as_str()
                    .is_some_and(|text| text.contains("detached"))
        })
        .unwrap_or_else(|| panic!("no detach notice in {messages:?}"));
    let answered = messages
        .iter()
        .position(|message| message["type"] == "response" && message["command"] == "disconnect")
        .unwrap_or_else(|| panic!("no disconnect response in {messages:?}"));

    assert!(
        detached < answered,
        "target was released after the response: {messages:?}"
    );
}

#[test]
fn variable_windows_follow_the_requested_page_and_filter() {
    let memory: Vec<u8> = (0..64u8).collect();
    let session = session_over_memory(0x1000, &memory);
    let dtb = session.target.current_dtb();
    let (_tx, rx) = mpsc::channel();
    let (mut server, _sink) = server_with_sink(Some(session), rx);
    let elements = server.var_ref(VarRef::Elements {
        element: ParsedType::Primitive("UCHAR".to_string()),
        count: 64,
        element_size: 1,
        address: VirtAddr(0x1000),
        dtb,
    });

    let page = |server: &mut Server, args: Value| -> Vec<(String, String)> {
        server
            .on_variables(&args)
            .expect("handler answers")
            .expect("body")["variables"]
            .as_array()
            .expect("variables array")
            .iter()
            .map(|row| {
                (
                    row["name"].as_str().unwrap_or_default().to_string(),
                    row["value"].as_str().unwrap_or_default().to_string(),
                )
            })
            .collect()
    };

    let second = page(
        &mut server,
        json!({"variablesReference": elements, "filter": "indexed", "start": 16, "count": 4}),
    );
    assert_eq!(
        second,
        vec![
            ("[16]".to_string(), "0x10".to_string()),
            ("[17]".to_string(), "0x11".to_string()),
            ("[18]".to_string(), "0x12".to_string()),
            ("[19]".to_string(), "0x13".to_string()),
        ]
    );

    // A window past the end is empty, not wrapped around to the start.
    assert!(
        page(
            &mut server,
            json!({"variablesReference": elements, "start": 64, "count": 4})
        )
        .is_empty()
    );

    // Array children are indexed, so a request for the named half of the
    // same reference has nothing to answer with.
    assert!(
        page(
            &mut server,
            json!({"variablesReference": elements, "filter": "named"})
        )
        .is_empty()
    );
}

#[test]
fn named_children_honor_the_requested_window() {
    let mut server = server_with_node_layout();
    let dtb = inspection_dtb(&server);
    let fields = server.var_ref(VarRef::Fields {
        type_name: "_NODE".to_string(),
        address: VirtAddr(0x1000),
        dtb,
    });

    let all = rows(
        server
            .on_variables(&json!({"variablesReference": fields}))
            .unwrap(),
    );
    assert!(all.len() >= 3, "expected several fields, got {all:?}");

    let windowed = rows(
        server
            .on_variables(&json!({"variablesReference": fields, "start": 1, "count": 1}))
            .unwrap(),
    );
    assert_eq!(windowed.len(), 1);
    assert_eq!(windowed[0]["name"], all[1]["name"]);

    // An `indexed` request against named children answers empty rather
    // than handing back the fields again.
    assert!(
        rows(
            server
                .on_variables(&json!({"variablesReference": fields, "filter": "indexed"}))
                .unwrap()
        )
        .is_empty()
    );
}

/// A server over a synthetic dump target carrying one `_NODE` layout:
/// `Value` = 0x2a, `Next` pointing back at the node, `Nil` null.
fn server_with_node_layout() -> Server {
    let mut memory = [0u8; 0x40];
    memory[0..4].copy_from_slice(&0x2au32.to_le_bytes());
    memory[8..16].copy_from_slice(&0x1000u64.to_le_bytes());
    let session = session_over_memory(0x1000, &memory);
    let dtb = session.target.current_dtb();
    session.target.symbols.set_kernel(Some(1), dtb);
    let pointer = ParsedType::Pointer(Box::new(ParsedType::Struct("_NODE".to_string())));
    let fields = [
        (
            "Value".to_string(),
            FieldInfo {
                offset: 0,
                size: 4,
                type_data: ParsedType::Primitive("ULONG".to_string()),
            },
        ),
        (
            "Next".to_string(),
            FieldInfo {
                offset: 8,
                size: 8,
                type_data: pointer.clone(),
            },
        ),
        (
            "Nil".to_string(),
            FieldInfo {
                offset: 16,
                size: 8,
                type_data: pointer,
            },
        ),
    ];
    session.target.symbols.inject_module_for_test(
        1,
        vec![TypeInfo {
            name: "_NODE".to_string(),
            pointer_size: 8,
            size: 24,
            fields: fields.into_iter().collect(),
        }],
        &[],
    );

    let (_, rx) = mpsc::channel();
    Server::new(
        Some(session),
        Box::new(Sink(Rc::new(RefCell::new(Vec::new())))),
        rx,
        Arc::new(AtomicBool::new(false)),
    )
}

fn inspection_dtb(server: &Server) -> Dtb {
    server.session.as_ref().unwrap().target.current_dtb()
}

fn rows(body: Option<Value>) -> Vec<Value> {
    body.unwrap()["variables"].as_array().unwrap().clone()
}

fn row<'a>(rows: &'a [Value], name: &str) -> &'a Value {
    rows.iter()
        .find(|row| row["name"] == name)
        .unwrap_or_else(|| panic!("no row named {name} in {rows:?}"))
}

#[test]
fn structs_open_into_field_rows_with_decoded_values() {
    let mut server = server_with_node_layout();

    let dtb = inspection_dtb(&server);
    let fields = rows(
        server
            .field_variables("_NODE", VirtAddr(0x1000), dtb)
            .unwrap(),
    );

    assert_eq!(row(&fields, "Value")["value"], "0x2a");
    assert_eq!(row(&fields, "Value")["memoryReference"], "0x1000");
    // A scalar is a leaf: no expander arrow.
    assert_eq!(row(&fields, "Value")["variablesReference"], 0);
    assert_eq!(row(&fields, "Next")["value"], "0x1000");
}

#[test]
fn evaluated_members_read_values_but_data_watches_select_storage() {
    let mut server = server_with_node_layout();
    let expression = "((_NODE*)0x1000)->Next->Value";
    let response = server
        .on_evaluate(&json!({
            "expression": expression,
            "context": "watch",
        }))
        .unwrap()
        .unwrap();
    assert_eq!(response["result"], "0x2a");
    assert_eq!(
        server.data_expression_target(expression).unwrap(),
        (0x1000, 4)
    );
    assert_eq!(
        server
            .data_expression_target("&((_NODE*)0x1000)->Value")
            .unwrap(),
        (0x1000, 4)
    );
    assert_eq!(
        server
            .data_expression_target("((_NODE*)0x1000)->Next")
            .unwrap(),
        (0x1008, 8)
    );
    let target = &server.session.as_ref().unwrap().target;
    assert_eq!(
        Expr::eval("((_NODE*)0x1000)->Value == 0n42", target)
            .unwrap()
            .0,
        1
    );
    assert!(Expr::eval("((_NODE*)0x1000).Value", target).is_err());
    assert!(Expr::eval("(*((_NODE*)0x1000))->Value", target).is_err());
    assert_eq!(
        Expr::eval("(*((_NODE*)0x1000)).Value", target).unwrap().0,
        42
    );
}

#[test]
fn a_pointer_row_opens_its_pointee_and_a_null_one_does_not() {
    let mut server = server_with_node_layout();
    let dtb = inspection_dtb(&server);
    let fields = rows(
        server
            .field_variables("_NODE", VirtAddr(0x1000), dtb)
            .unwrap(),
    );

    // A null pointer has nothing to open: an expander arrow there would
    // lead to an empty list the user cannot tell from an empty struct.
    assert_eq!(row(&fields, "Nil")["variablesReference"], 0);

    let reference = row(&fields, "Next")["variablesReference"].as_i64().unwrap();
    assert!(reference >= VARIABLES_BASE);
    let pointee = rows(
        server
            .on_variables(&json!({"variablesReference": reference}))
            .unwrap(),
    );

    assert_eq!(row(&pointee, "Value")["value"], "0x2a");
}

#[test]
fn stale_and_unknown_references_are_refused_rather_than_answered_empty() {
    let mut server = server_with_node_layout();
    let dtb = inspection_dtb(&server);

    assert!(
        server
            .on_variables(&json!({"variablesReference": VARIABLES_BASE + 7}))
            .is_err()
    );
    assert!(
        server
            .field_variables("_MISSING", VirtAddr(0x1000), dtb)
            .is_err()
    );
}

/// A server whose guest holds `code` at 0x1000, recorded by the PDB as one
/// source line covering exactly those bytes.
fn server_over_one_line(code: &[u8]) -> Server {
    let session = session_over_memory(0x1000, code);
    let dtb = session.target.current_dtb();
    session.target.symbols.set_kernel(Some(1), dtb);
    session.target.symbols.inject_source_lines_for_test(
        1,
        dtb,
        VirtAddr(0x1000),
        0x1000,
        "driver.c",
        &[(0, Some(code.len() as u32), 42)],
    );

    let (_, rx) = mpsc::channel();
    Server::new(
        Some(session),
        Box::new(Sink(Rc::new(RefCell::new(Vec::new())))),
        rx,
        Arc::new(AtomicBool::new(false)),
    )
}

#[test]
fn a_branch_free_line_is_covered_by_one_run_instead_of_many_steps() {
    // mov rax, rcx / add rax, 1 / mov rcx, rax / xor edx, edx
    let code = [
        0x48, 0x89, 0xc8, 0x48, 0x83, 0xc0, 0x01, 0x48, 0x89, 0xc1, 0x31, 0xd2,
    ];
    let mut server = server_over_one_line(&code);

    assert_eq!(
        server.coalescible_line_end(0x1000).unwrap(),
        Some(VirtAddr(0x1000 + code.len() as u64))
    );
    // From inside the line, only the remainder is covered.
    assert_eq!(
        server.coalescible_line_end(0x1003).unwrap(),
        Some(VirtAddr(0x1000 + code.len() as u64))
    );
}

#[test]
fn a_line_is_only_covered_up_to_its_first_control_flow_instruction() {
    // mov rax, rcx / add rax, 1 / call rax / mov rcx, rax
    let code = [
        0x48, 0x89, 0xc8, 0x48, 0x83, 0xc0, 0x01, 0xff, 0xd0, 0x48, 0x89, 0xc1,
    ];
    let mut server = server_over_one_line(&code);

    // Running past the call would skip the callee the client may step into.
    assert_eq!(
        server.coalescible_line_end(0x1000).unwrap(),
        Some(VirtAddr(0x1007))
    );
    // Standing on the call itself: nothing to coalesce, so step it.
    assert_eq!(server.coalescible_line_end(0x1007).unwrap(), None);
}

#[test]
fn one_instruction_and_unmapped_addresses_are_left_to_the_stepper() {
    let code = [0x48, 0x89, 0xc8, 0x48, 0x83, 0xc0, 0x01];
    let mut server = server_over_one_line(&code);

    // A single remaining instruction: a step costs less than planting and
    // removing a breakpoint.
    assert_eq!(server.coalescible_line_end(0x1003).unwrap(), None);
    // No line record covers this address at all.
    assert_eq!(server.coalescible_line_end(0x9000).unwrap(), None);
}
