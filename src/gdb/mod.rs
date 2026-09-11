use std::io::{self, Read, Write};
use std::mem;
use std::net::TcpStream;
use std::time::Duration;

use crate::dbg_backend::{DebugBackend, StopEvent};
use crate::error::{Error, Result};

pub mod breakpoints;
pub mod registers;

pub use breakpoints::{
    BreakpointConfig, BreakpointHitDisposition, BreakpointHitResult, BreakpointManager,
    BreakpointSpec,
};
pub use registers::{RegisterInfo, RegisterMap};

#[derive(Debug, Default, Clone)]
struct StubFeatures {
    no_ack_mode: bool,
    qxfer_features_read: bool,
}

#[derive(Debug, Default)]
enum PacketReadState {
    #[default]
    SeekingStart,
    ReadingData(Vec<u8>),
    ReadingChecksum {
        data: Vec<u8>,
        checksum: [u8; 2],
        len: usize,
    },
}

#[derive(Debug)]
enum AckResult {
    Ack,
    Nack,
    ReplyStarted,
}

#[derive(Debug)]
struct RawPacket {
    data: Vec<u8>,
    checksum: [u8; 2],
}

impl StubFeatures {
    fn parse(response: &str) -> Self {
        let mut features = StubFeatures::default();

        for item in response.split(';') {
            match item {
                "QStartNoAckMode+" => features.no_ack_mode = true,
                "qXfer:features:read+" => features.qxfer_features_read = true,
                _ => {}
            }
        }

        features
    }
}

pub struct GdbClient {
    stream: TcpStream,
    features: StubFeatures,
    rx_state: PacketReadState,
    no_ack_mode: bool,
    register_map: RegisterMap,
    is_running: bool,
}

fn gdb_connect_error(addr: &str, err: io::Error) -> Error {
    let message = match err.kind() {
        io::ErrorKind::ConnectionRefused => format!(
            "GDB stub at '{addr}' is not accepting connections.\n\
             Start the VM with QEMU gdbstub enabled (-s -S), or pass --connect <addr> if the stub listens elsewhere.\n\
             For supported hypervisors, run `ntoseye configure` and choose GDB.\n\
             If this guest is configured for Windows KD instead, use the default KD backend."
        ),
        io::ErrorKind::TimedOut => format!(
            "timed out connecting to GDB stub at '{addr}'.\n\
             Check that the VM is running with QEMU gdbstub enabled (-s -S), or pass --connect <addr> if the stub listens elsewhere."
        ),
        _ => format!(
            "failed to connect to GDB stub at '{addr}': {err}.\n\
             Start the VM with QEMU gdbstub enabled (-s -S), or pass --connect <addr> if the stub listens elsewhere."
        ),
    };
    Error::DebugInfo(message)
}

impl GdbClient {
    pub fn connect(addr: &str) -> Result<Self> {
        let stream = TcpStream::connect(addr).map_err(|err| gdb_connect_error(addr, err))?;

        let mut client = GdbClient {
            stream,
            features: StubFeatures::default(),
            rx_state: PacketReadState::default(),
            no_ack_mode: false,
            register_map: RegisterMap::default(),
            is_running: false, // NOTE if the user toys with VM via GUI, this value goes bad
        };

        client.force_stop_and_resync()?;

        let supported =
            client.send_packet("qSupported:multiprocess+;swbreak+;qRelocInsn+;vContSupported+")?;
        client.features = StubFeatures::parse(&supported);

        if client.features.no_ack_mode {
            let _ = client.enable_no_ack_mode();
        }

        let _ = client.send_packet("?")?;

        client.register_map = client.fetch_register_map()?;
        client.register_map.require_amd64_target()?;

        Ok(client)
    }

    fn force_stop_and_resync(&mut self) -> Result<()> {
        self.stream
            .set_read_timeout(Some(Duration::from_millis(100)))?;
        self.rx_state = PacketReadState::default();

        self.stream.write_all(&[0x03])?;
        self.stream.flush()?;

        while self.read_response_packet().is_ok() {}

        self.stream.set_read_timeout(None)?;
        self.rx_state = PacketReadState::default();

        self.is_running = false;

        Ok(())
    }

    pub fn send_packet(&mut self, data: &str) -> Result<String> {
        let packet = Self::encode_packet(data);
        self.send_raw_command(&packet)?;
        self.read_response_packet()
    }

    fn enable_no_ack_mode(&mut self) -> Result<()> {
        let response = self.send_packet("QStartNoAckMode")?;
        if response == "OK" {
            self.no_ack_mode = true;
            Ok(())
        } else {
            Err(Error::NotSupported)
        }
    }

    pub fn query_halt_reason(&mut self) -> Result<String> {
        self.send_packet("?")
    }

    fn encode_packet(data: &str) -> Vec<u8> {
        let checksum: u8 = data.bytes().fold(0u8, |acc, b| acc.wrapping_add(b));
        format!("${}#{:02x}", data, checksum).into_bytes()
    }

    fn send_raw_command(&mut self, packet: &[u8]) -> Result<()> {
        loop {
            self.stream.write_all(packet)?;
            self.stream.flush()?;

            if self.no_ack_mode {
                return Ok(());
            }

            match self.wait_for_ack()? {
                AckResult::Ack => return Ok(()),
                AckResult::Nack => continue,
                AckResult::ReplyStarted => return Ok(()),
            }
        }
    }

    fn wait_for_ack(&mut self) -> Result<AckResult> {
        let mut buf = [0u8; 1];

        loop {
            self.stream.read_exact(&mut buf)?;
            match buf[0] {
                b'+' => return Ok(AckResult::Ack),
                b'-' => return Ok(AckResult::Nack),
                b'$' => {
                    self.rx_state = PacketReadState::ReadingData(Vec::new());
                    return Ok(AckResult::ReplyStarted);
                }
                _ => continue,
            }
        }
    }

    fn read_response_packet(&mut self) -> Result<String> {
        loop {
            let packet = self.read_raw_packet()?;
            let expected = Self::parse_checksum(packet.checksum)?;
            let actual = packet
                .data
                .iter()
                .fold(0u8, |acc, byte| acc.wrapping_add(*byte));

            if actual != expected {
                if self.no_ack_mode {
                    return Err(Error::Rsp(format!(
                        "bad checksum from stub: expected {:02x}, got {:02x}",
                        expected, actual
                    )));
                }

                self.stream.write_all(b"-")?;
                self.stream.flush()?;
                continue;
            }

            if !self.no_ack_mode {
                self.stream.write_all(b"+")?;
                self.stream.flush()?;
            }

            let decoded = Self::decode_packet_data(&packet.data)?;
            let response = String::from_utf8(decoded)
                .map_err(|e| Error::Rsp(format!("non-utf8 packet payload: {}", e)))?;
            return Ok(response);
        }
    }

    fn read_raw_packet(&mut self) -> Result<RawPacket> {
        loop {
            let mut buf = [0u8; 1];
            self.stream.read_exact(&mut buf)?;
            if let Some(packet) = self.consume_packet_byte(buf[0])? {
                return Ok(packet);
            }
        }
    }

    fn consume_packet_byte(&mut self, byte: u8) -> Result<Option<RawPacket>> {
        match &mut self.rx_state {
            PacketReadState::SeekingStart => {
                if byte == b'$' {
                    self.rx_state = PacketReadState::ReadingData(Vec::new());
                }
                Ok(None)
            }
            PacketReadState::ReadingData(data) => {
                if byte == b'#' {
                    let raw_data = mem::take(data);
                    self.rx_state = PacketReadState::ReadingChecksum {
                        data: raw_data,
                        checksum: [0u8; 2],
                        len: 0,
                    };
                } else {
                    data.push(byte);
                }
                Ok(None)
            }
            PacketReadState::ReadingChecksum {
                data,
                checksum,
                len,
            } => {
                checksum[*len] = byte;
                *len += 1;

                if *len == 2 {
                    let raw_data = mem::take(data);
                    let raw_checksum = *checksum;
                    self.rx_state = PacketReadState::SeekingStart;
                    return Ok(Some(RawPacket {
                        data: raw_data,
                        checksum: raw_checksum,
                    }));
                }

                Ok(None)
            }
        }
    }

    fn parse_checksum(checksum: [u8; 2]) -> Result<u8> {
        let checksum_str = std::str::from_utf8(&checksum)
            .map_err(|e| Error::Rsp(format!("invalid checksum encoding: {}", e)))?;
        u8::from_str_radix(checksum_str, 16)
            .map_err(|e| Error::Rsp(format!("invalid checksum value '{}': {}", checksum_str, e)))
    }

    fn decode_packet_data(data: &[u8]) -> Result<Vec<u8>> {
        let mut decoded = Vec::with_capacity(data.len());
        let mut index = 0;

        while index < data.len() {
            match data[index] {
                b'}' => {
                    index += 1;
                    if index >= data.len() {
                        return Err(Error::Rsp("truncated escaped packet data".into()));
                    }
                    decoded.push(data[index] ^ 0x20);
                    index += 1;
                }
                b'*' => {
                    let Some(last) = decoded.last().copied() else {
                        return Err(Error::Rsp("invalid run-length packet data".into()));
                    };
                    index += 1;
                    if index >= data.len() {
                        return Err(Error::Rsp("truncated run-length packet data".into()));
                    }
                    let repeat_count = data[index]
                        .checked_sub(29)
                        .ok_or_else(|| Error::Rsp("invalid run-length repeat count".into()))?;
                    decoded.extend(std::iter::repeat_n(last, repeat_count as usize));
                    index += 1;
                }
                byte => {
                    decoded.push(byte);
                    index += 1;
                }
            }
        }

        Ok(decoded)
    }

    fn set_breakpoint(&mut self, addr: u64) -> Result<()> {
        let response = self.send_packet(&format!("Z0,{:x},1", addr))?;
        if response == "OK" {
            Ok(())
        } else if response.starts_with('E') {
            Err(Error::Rsp(format!(
                "failed to set breakpoint at {:#x}: {}",
                addr, response
            )))
        } else {
            Err(Error::NotSupported)
        }
    }

    fn remove_breakpoint(&mut self, addr: u64) -> Result<()> {
        let response = self.send_packet(&format!("z0,{:x},1", addr))?;
        if response == "OK" {
            Ok(())
        } else if response.starts_with('E') {
            Err(Error::Rsp(format!(
                "failed to remove breakpoint at {:#x}: {}",
                addr, response
            )))
        } else {
            Err(Error::NotSupported)
        }
    }

    fn read_registers(&mut self) -> Result<Vec<u8>> {
        let response = self.send_packet("g")?;

        if response.starts_with('E') {
            return Err(Error::Rsp(format!(
                "failed to read registers: {}",
                response
            )));
        }

        let bytes = hex::decode(&response)?;
        Ok(bytes)
    }

    fn write_registers(&mut self, data: &[u8]) -> Result<()> {
        let response = self.send_packet(&format!("G{}", hex::encode(data)))?;

        if response == "OK" {
            Ok(())
        } else {
            Err(Error::Rsp(format!(
                "failed to write registers: {}",
                response
            )))
        }
    }

    fn send_command_no_reply(&mut self, data: &str) -> Result<()> {
        let packet = Self::encode_packet(data);
        self.send_raw_command(&packet)
    }

    fn continue_execution(&mut self) -> Result<()> {
        // set continue thread to -1 (all threads)
        let _ = self.send_packet("Hc-1")?;
        self.send_command_no_reply("c")?;
        self.is_running = true;
        Ok(())
    }

    fn step(&mut self) -> Result<()> {
        self.send_command_no_reply("s")?;
        self.is_running = true;
        Ok(())
    }

    fn wait_for_stop(&mut self) -> Result<String> {
        if !self.is_running {
            return self.query_halt_reason();
        }

        let response = self.read_stop_reply()?;
        self.is_running = false;
        Ok(response)
    }

    fn try_wait_for_stop(&mut self) -> Result<Option<String>> {
        if !self.is_running {
            return Ok(Some(self.query_halt_reason()?));
        }

        match self.read_stop_reply() {
            Ok(response) => {
                self.is_running = false;
                Ok(Some(response))
            }
            Err(Error::Io(ref e))
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    fn read_stop_reply(&mut self) -> Result<String> {
        loop {
            let response = self.read_response_packet()?;
            match response.as_bytes().first().copied() {
                Some(b'S' | b'T' | b'W' | b'X' | b'N') => return Ok(response),
                Some(b'O') => continue,
                Some(b'F') => {
                    return Err(Error::Rsp(
                        "remote file I/O packets are unsupported while waiting for stop".into(),
                    ));
                }
                Some(b'E') => {
                    return Err(Error::Rsp(format!(
                        "run-control command failed: {}",
                        response
                    )));
                }
                _ => {
                    return Err(Error::Rsp(format!(
                        "unexpected packet while waiting for stop: {}",
                        response
                    )));
                }
            }
        }
    }

    fn interrupt(&mut self) -> Result<String> {
        if !self.is_running {
            return Ok(String::new());
        }

        self.stream.write_all(&[0x03])?;
        self.stream.flush()?;

        let stop = self.read_stop_reply()?;

        self.is_running = false;

        Ok(stop)
    }

    fn thread_list(&mut self) -> Result<Vec<String>> {
        let mut threads = Vec::new();
        let mut response = self.send_packet("qfThreadInfo")?;

        loop {
            if response == "l" {
                break;
            }

            if let Some(list) = response.strip_prefix('m') {
                for id in list.split(',') {
                    if !id.is_empty() {
                        threads.push(id.to_string());
                    }
                }
            } else if response.starts_with('E') {
                return Err(Error::Rsp(format!(
                    "failed to enumerate threads: {}",
                    response
                )));
            } else {
                return Err(Error::Rsp(format!(
                    "unexpected qThreadInfo response: {}",
                    response
                )));
            }

            response = self.send_packet("qsThreadInfo")?;
        }

        Ok(threads)
    }

    fn set_current_thread(&mut self, thread_id: &str) -> Result<()> {
        let resp_g = self.send_packet(&format!("Hg{}", thread_id))?;
        if resp_g != "OK" {
            return Err(Error::Rsp(format!(
                "failed to set general thread: {}",
                resp_g
            )));
        }

        let resp_c = self.send_packet(&format!("Hc{}", thread_id))?;
        if resp_c != "OK" {
            return Err(Error::Rsp(format!(
                "failed to set control thread: {}",
                resp_c
            )));
        }

        Ok(())
    }

    fn stopped_thread_id(&mut self) -> Result<String> {
        let response = self.send_packet("?")?;
        if let Some(thread_id) = Self::parse_stop_reply_thread_id(&response) {
            return Ok(thread_id);
        }

        let response = self.send_packet("qC")?;
        if let Some(thread_id) = response.strip_prefix("QC") {
            return Ok(thread_id.to_string());
        }

        Err(Error::Rsp(
            "could not determine thread from stop reply".into(),
        ))
    }

    fn parse_stop_reply_thread_id(response: &str) -> Option<String> {
        if !response.starts_with('T') {
            return None;
        }

        let start = response.find("thread:")?;
        let remainder = &response[start + 7..];
        let end = remainder.find(';').unwrap_or(remainder.len());
        Some(remainder[..end].to_string())
    }

    fn fetch_register_map(&mut self) -> Result<RegisterMap> {
        if !self.features.qxfer_features_read {
            return Err(Error::NotSupported);
        }

        let mut xml = String::new();
        let mut offset = 0;

        loop {
            let query = format!("qXfer:features:read:target.xml:{:x},fff", offset);
            let response = self.send_packet(&query)?;

            if response.is_empty() {
                return Err(Error::NotSupported);
            }

            let (marker, data) = response.split_at(1);
            xml.push_str(data);
            offset += data.len();

            match marker {
                "l" => break,    // last chunk
                "m" => continue, // more data
                _ => {
                    return Err(Error::Rsp(format!(
                        "unexpected qXfer response: {}",
                        response
                    )));
                }
            }
        }

        let full_xml = self.resolve_xml_includes(&xml)?;

        Ok(RegisterMap::parse_target_xml(&full_xml))
    }

    fn resolve_xml_includes(&mut self, xml: &str) -> Result<String> {
        let mut result = xml.to_string();

        while let Some(start) = result.find("<xi:include") {
            let end = match result[start..].find("/>") {
                Some(e) => start + e + 2,
                None => break,
            };

            let element = &result[start..end];
            let href = RegisterMap::extract_attr(element, "href");

            if let Some(filename) = href {
                // fetch the included file
                let included_xml = self.fetch_feature_file(filename)?;
                result = format!("{}{}{}", &result[..start], included_xml, &result[end..]);
            } else {
                // no href, just remove the include element
                result = format!("{}{}", &result[..start], &result[end..]);
            }
        }

        Ok(result)
    }

    fn fetch_feature_file(&mut self, filename: &str) -> Result<String> {
        let mut xml = String::new();
        let mut offset = 0;

        loop {
            let query = format!("qXfer:features:read:{}:{:x},fff", filename, offset);
            let response = self.send_packet(&query)?;

            if response.is_empty() {
                return Err(Error::NotSupported);
            }

            let (marker, data) = response.split_at(1);
            xml.push_str(data);
            offset += data.len();

            match marker {
                "l" => break,
                "m" => continue,
                _ => {
                    return Err(Error::Rsp(format!(
                        "unexpected qXfer response for {}: {}",
                        filename, response
                    )));
                }
            }
        }

        Ok(xml)
    }
}

impl DebugBackend for GdbClient {
    fn register_map(&self) -> &RegisterMap {
        &self.register_map
    }
    fn name(&self) -> &'static str {
        "gdb"
    }

    fn read_registers(&mut self) -> Result<Vec<u8>> {
        GdbClient::read_registers(self)
    }

    fn write_registers(&mut self, data: &[u8]) -> Result<()> {
        GdbClient::write_registers(self, data)
    }

    fn set_breakpoint(&mut self, addr: u64) -> Result<()> {
        GdbClient::set_breakpoint(self, addr)
    }

    fn remove_breakpoint(&mut self, addr: u64) -> Result<()> {
        GdbClient::remove_breakpoint(self, addr)
    }

    fn continue_execution(&mut self) -> Result<()> {
        GdbClient::continue_execution(self)
    }

    fn step(&mut self) -> Result<()> {
        GdbClient::step(self)
    }

    fn interrupt(&mut self) -> Result<StopEvent> {
        let response = GdbClient::interrupt(self)?;
        Ok(StopEvent {
            thread_id: Self::parse_stop_reply_thread_id(&response),
            exception_code: None,
            first_chance: None,
            exception_address: None,
            program_counter: None,
            is_bugcheck: false,
            bugcheck: None,
            target_reloaded: false,
            target_kernel_base_hint: None,
            assisted_breakin: false,
        })
    }

    fn wait_for_stop(&mut self) -> Result<StopEvent> {
        let response = GdbClient::wait_for_stop(self)?;
        Ok(StopEvent {
            thread_id: Self::parse_stop_reply_thread_id(&response),
            exception_code: None,
            first_chance: None,
            exception_address: None,
            program_counter: None,
            is_bugcheck: false,
            bugcheck: None,
            target_reloaded: false,
            target_kernel_base_hint: None,
            assisted_breakin: false,
        })
    }

    fn try_wait_for_stop(&mut self, timeout: Duration) -> Result<Option<StopEvent>> {
        self.stream.set_read_timeout(Some(timeout))?;
        let result = GdbClient::try_wait_for_stop(self);
        // restore blocking mode regardless of outcome
        let _ = self.stream.set_read_timeout(None);
        Ok(result?.map(|response| StopEvent {
            thread_id: Self::parse_stop_reply_thread_id(&response),
            exception_code: None,
            first_chance: None,
            exception_address: None,
            program_counter: None,
            is_bugcheck: false,
            bugcheck: None,
            target_reloaded: false,
            target_kernel_base_hint: None,
            assisted_breakin: false,
        }))
    }

    fn thread_list(&mut self) -> Result<Vec<String>> {
        GdbClient::thread_list(self)
    }

    fn set_current_thread(&mut self, thread_id: &str) -> Result<()> {
        GdbClient::set_current_thread(self, thread_id)
    }

    fn stopped_thread_id(&mut self) -> Result<String> {
        GdbClient::stopped_thread_id(self)
    }

    fn is_running(&self) -> bool {
        self.is_running
    }
}

#[cfg(test)]
mod tests {
    use super::{GdbClient, StubFeatures};

    #[test]
    fn decodes_escaped_and_run_length_packet_data() {
        let decoded = GdbClient::decode_packet_data(b"A* }\x03").unwrap();
        assert_eq!(decoded, b"AAAA#");
    }

    #[test]
    fn rejects_truncated_escape_sequences() {
        let err = GdbClient::decode_packet_data(b"}").unwrap_err();
        assert!(err.to_string().contains("truncated escaped packet data"));
    }

    #[test]
    fn parses_stub_features_from_qsupported() {
        let features = StubFeatures::parse(
            "PacketSize=1000;QStartNoAckMode+;multiprocess+;qXfer:features:read+",
        );
        assert!(features.no_ack_mode);
        assert!(features.qxfer_features_read);
    }

    #[test]
    fn parses_thread_id_from_stop_reply() {
        let thread_id = GdbClient::parse_stop_reply_thread_id("T05thread:p1.2;core:1;");
        assert_eq!(thread_id.as_deref(), Some("p1.2"));
    }

    #[test]
    fn ignores_non_stop_reply_when_parsing_thread_id() {
        assert!(GdbClient::parse_stop_reply_thread_id("S05").is_none());
    }
}
