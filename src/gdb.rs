use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::types::VirtAddr;

#[derive(Debug, Clone)]
pub struct RegisterInfo {
    pub name: String,
    pub offset: usize,
    pub size: usize,
    #[allow(dead_code)]
    pub regnum: usize,
}

#[derive(Debug, Default)]
pub struct RegisterMap {
    by_name: HashMap<String, RegisterInfo>,
    ordered: Vec<RegisterInfo>,
}

#[derive(Debug, Clone)]
pub struct Breakpoint {
    pub id: u32,
    pub address: VirtAddr,
    pub enabled: bool,
    pub target_cr3: Option<u64>,
    pub symbol: Option<String>,
}

pub struct BreakpointManager {
    breakpoints: HashMap<u32, Breakpoint>,
    next_id: u32,
}

impl BreakpointManager {
    pub fn new() -> Self {
        Self {
            breakpoints: HashMap::new(),
            next_id: 0,
        }
    }

    pub fn add(
        &mut self,
        client: &mut GdbClient,
        address: VirtAddr,
        target_cr3: Option<u64>,
        symbol: Option<String>,
    ) -> Result<u32> {
        let id = self.next_id;
        self.next_id += 1;

        client.set_breakpoint(address.0, 1)?;

        let bp = Breakpoint {
            id,
            address,
            enabled: true,
            target_cr3,
            symbol,
        };

        self.breakpoints.insert(id, bp);
        Ok(id)
    }

    pub fn remove(&mut self, client: &mut GdbClient, id: u32) -> Result<()> {
        let bp = self.breakpoints.remove(&id).ok_or(Error::BPNotFound(id))?;

        if bp.enabled {
            client.remove_breakpoint(bp.address.0, 1)?;
        }

        Ok(())
    }

    pub fn enable(&mut self, client: &mut GdbClient, id: u32) -> Result<()> {
        let bp = self.breakpoints.get_mut(&id).ok_or(Error::BPNotFound(id))?;

        if bp.enabled {
            return Ok(());
        }

        client.set_breakpoint(bp.address.0, 1)?;

        bp.enabled = true;
        Ok(())
    }

    pub fn disable(&mut self, client: &mut GdbClient, id: u32) -> Result<()> {
        let bp = self.breakpoints.get_mut(&id).ok_or(Error::BPNotFound(id))?;

        if !bp.enabled {
            return Ok(());
        }

        client.remove_breakpoint(bp.address.0, 1)?;

        bp.enabled = false;
        Ok(())
    }

    pub fn list(&self) -> Vec<&Breakpoint> {
        let mut bps: Vec<_> = self.breakpoints.values().collect();
        bps.sort_by_key(|bp| bp.id);
        bps
    }

    pub fn has_enabled_breakpoints(&self) -> bool {
        self.breakpoints.values().any(|bp| bp.enabled)
    }

    // NOTE refreshing ensures local breakpoint state matches target state in case they were cleared,
    // this should fix single stepping breaking every breakpoint proceeding the step..
    pub fn refresh_enabled(&self, client: &mut GdbClient) -> Result<()> {
        let mut enabled: Vec<_> = self.breakpoints.values().filter(|bp| bp.enabled).collect();
        enabled.sort_by_key(|bp| bp.id);

        for bp in enabled {
            let _ = client.remove_breakpoint(bp.address.0, 1);
            client.set_breakpoint(bp.address.0, 1)?;
        }

        Ok(())
    }

    pub fn check_breakpoint_hit(&self, rip: u64, cr3: u64) -> BreakpointHitResult {
        let cr3_masked = cr3 & 0x000F_FFFF_FFFF_F000;

        for bp in self.breakpoints.values() {
            if bp.address.0 == rip && bp.enabled {
                match bp.target_cr3 {
                    None => return BreakpointHitResult::Hit(bp.clone()),
                    Some(target) => {
                        let target_masked = target & 0x000F_FFFF_FFFF_F000;
                        if target_masked == cr3_masked {
                            return BreakpointHitResult::Hit(bp.clone());
                        } else {
                            return BreakpointHitResult::WrongProcess(bp.clone());
                        }
                    }
                }
            }
        }

        BreakpointHitResult::NotBreakpoint
    }
}

#[derive(Debug)]
pub enum BreakpointHitResult {
    /// Breakpoint hit and CR3 matches (or is global)
    Hit(Breakpoint),
    /// Breakpoint hit but CR3 doesn't match - should single-step and continue
    WrongProcess(Breakpoint),
    /// RIP doesn't match any breakpoint
    NotBreakpoint,
}

impl RegisterMap {
    // pub fn get(&self, name: &str) -> Option<&RegisterInfo> {
    //     self.by_name.get(name)
    // }

    // pub fn get_range(&self, name: &str) -> Option<std::ops::Range<usize>> {
    //     self.by_name.get(name).map(|r| r.offset..r.offset + r.size)
    // }

    pub fn read_u64<S>(&self, name: S, data: &[u8]) -> Result<u64>
    where
        S: Into<String> + AsRef<str>,
    {
        let info = self
            .by_name
            .get(name.as_ref())
            .ok_or(Error::RegisterNotFound(name.into()))?;
        if info.offset + info.size > data.len() {
            return Err(Error::BufferNotEnough);
        }
        let slice = &data[info.offset..info.offset + info.size];

        let mut buf = [0u8; 8];
        let copy_len = slice.len().min(8);
        buf[..copy_len].copy_from_slice(&slice[..copy_len]);
        Ok(u64::from_le_bytes(buf))
    }

    // pub fn iter(&self) -> impl Iterator<Item = &RegisterInfo> {
    //     self.ordered.iter()
    // }

    // pub fn is_empty(&self) -> bool {
    //     self.ordered.is_empty()
    // }

    fn parse_target_xml(xml: &str) -> Self {
        let mut map = RegisterMap::default();
        let mut current_offset: usize = 0;
        let mut next_regnum: Option<usize> = None;

        let xml = Self::strip_xml_comments(xml);

        for line in xml.lines() {
            let line = line.trim();
            if !line.starts_with("<reg ") {
                continue;
            }

            let name = Self::extract_attr(line, "name");
            let bitsize = Self::extract_attr(line, "bitsize");
            let explicit_regnum = Self::extract_attr(line, "regnum");

            if let (Some(name), Some(bitsize)) = (name, bitsize) {
                let size_bits: usize = bitsize.parse().unwrap_or(0);
                let size_bytes = size_bits / 8;

                let regnum: usize =
                    if let Some(explicit) = explicit_regnum.and_then(|s| s.parse().ok()) {
                        next_regnum = Some(explicit + 1);
                        explicit
                    } else {
                        let num = next_regnum.unwrap_or(0);
                        next_regnum = Some(num + 1);
                        num
                    };

                let reg = RegisterInfo {
                    name: name.to_string(),
                    offset: current_offset,
                    size: size_bytes,
                    regnum,
                };

                current_offset += size_bytes;
                map.by_name.insert(reg.name.clone(), reg.clone());
                map.ordered.push(reg);
            }
        }

        map
    }

    fn strip_xml_comments(xml: &str) -> String {
        let mut result = xml.to_string();
        while let Some(start) = result.find("<!--") {
            if let Some(end_offset) = result[start..].find("-->") {
                let end = start + end_offset + 3; // +3 for "-->"
                result = format!("{}{}", &result[..start], &result[end..]);
            } else {
                break;
            }
        }
        result
    }

    fn extract_attr<'a>(element: &'a str, attr: &str) -> Option<&'a str> {
        let pattern = format!("{}=\"", attr);
        let start = element.find(&pattern)?;
        let value_start = start + pattern.len();
        let rest = &element[value_start..];
        let end = rest.find('"')?;
        Some(&rest[..end])
    }
}

pub struct GdbClient {
    stream: TcpStream,
    no_ack_mode: bool,
    pub is_running: bool,
}

impl GdbClient {
    pub fn connect(addr: &str) -> Result<Self> {
        let stream = TcpStream::connect(addr)?;

        let mut client = GdbClient {
            stream,
            no_ack_mode: false,
            is_running: false, // NOTE if the user toys with VM via GUI, this value goes bad
        };

        client.force_stop_and_resync()?;

        let _ = client.send_packet(
            "qSupported:multiprocess+;swbreak+;hwbreak+;qRelocInsn+;vContSupported+",
        )?;

        let _ = client.enable_no_ack_mode();

        let _ = client.send_packet("?")?;

        Ok(client)
    }

    fn force_stop_and_resync(&mut self) -> Result<()> {
        self.stream
            .set_read_timeout(Some(Duration::from_millis(100)))?;

        self.stream.write_all(&[0x03])?;
        self.stream.flush()?;

        while self.read_packet().is_ok() {}

        self.stream.set_read_timeout(None)?;

        self.is_running = false;

        Ok(())
    }

    pub fn send_packet(&mut self, data: &str) -> Result<String> {
        let checksum: u8 = data.bytes().fold(0u8, |acc, b| acc.wrapping_add(b));

        let packet = format!("${}#{:02x}", data, checksum);

        self.stream.write_all(packet.as_bytes())?;
        self.stream.flush()?;

        self.read_packet()
    }

    fn read_packet(&mut self) -> Result<String> {
        let mut buf = [0u8; 1];
        let mut response = String::new();

        loop {
            self.stream.read_exact(&mut buf)?;
            if buf[0] == b'$' {
                break;
            }
            if buf[0] == b'+' || buf[0] == b'-' {
                continue;
            }
        }

        loop {
            self.stream.read_exact(&mut buf)?;
            if buf[0] == b'#' {
                break;
            }
            response.push(buf[0] as char);
        }

        let mut checksum_buf = [0u8; 2];
        self.stream.read_exact(&mut checksum_buf)?;

        if !self.no_ack_mode {
            self.stream.write_all(b"+")?;
            self.stream.flush()?;
        }

        Ok(response)
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

    pub fn set_breakpoint(&mut self, addr: u64, kind: u32) -> Result<()> {
        let response = self.send_packet(&format!("Z0,{:x},{:x}", addr, kind))?;
        if response == "OK" || response.is_empty() {
            Ok(())
        } else if response.starts_with('E') {
            Err(Error::Rsp(format!(
                "failed to set breakpoint: {}",
                response
            )))
        } else {
            Err(Error::NotSupported)
        }
    }

    pub fn remove_breakpoint(&mut self, addr: u64, kind: u32) -> Result<()> {
        let response = self.send_packet(&format!("z0,{:x},{:x}", addr, kind))?;
        if response == "OK" || response.is_empty() {
            Ok(())
        } else if response.starts_with('E') {
            Err(Error::Rsp(format!(
                "failed to remove breakpoint: {}",
                response
            )))
        } else {
            Err(Error::NotSupported)
        }
    }

    pub fn read_registers(&mut self) -> Result<Vec<u8>> {
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

    #[allow(dead_code)]
    pub fn write_registers(&mut self, data: &[u8]) -> Result<()> {
        let hex_data: String = data.iter().map(|b| format!("{:02x}", b)).collect();

        let response = self.send_packet(&format!("G{}", hex_data))?;

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
        let checksum: u8 = data.bytes().fold(0u8, |acc, b| acc.wrapping_add(b));
        let packet = format!("${}#{:02x}", data, checksum);

        self.stream.write_all(packet.as_bytes())?;
        self.stream.flush()?;

        // In no-ack mode, no response expected immediately
        // In ack mode, read the ACK
        if !self.no_ack_mode {
            let mut buf = [0u8; 1];
            self.stream.read_exact(&mut buf)?;
            if buf[0] != b'+' {
                return Err(Error::Rsp(format!("expected ACK, got 0x{:02x}", buf[0])));
            }
        }

        Ok(())
    }

    pub fn continue_execution(&mut self) -> Result<()> {
        // set continue thread to -1 (all threads)
        let _ = self.send_packet("Hc-1")?;
        self.send_command_no_reply("c")?;
        self.is_running = true;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn continue_at(&mut self, addr: u64) -> Result<()> {
        self.send_command_no_reply(&format!("c{:x}", addr))
    }

    pub fn step(&mut self) -> Result<()> {
        self.send_command_no_reply("s")?;
        self.is_running = true;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn step_at(&mut self, addr: u64) -> Result<()> {
        self.send_command_no_reply(&format!("s{:x}", addr))?;
        self.is_running = true;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn step_and_wait(&mut self) -> Result<String> {
        self.step()?;
        self.wait_for_stop()
    }

    pub fn wait_for_stop(&mut self) -> Result<String> {
        if !self.is_running {
            return self.query_halt_reason();
        }

        let response = self.read_packet()?;
        self.is_running = false;
        Ok(response)
    }

    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) -> Result<()> {
        self.stream.set_read_timeout(timeout)?;
        Ok(())
    }

    pub fn try_wait_for_stop(&mut self) -> Result<Option<String>> {
        if !self.is_running {
            return Ok(Some(self.query_halt_reason()?));
        }

        match self.read_packet() {
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

    pub fn interrupt(&mut self) -> Result<()> {
        if !self.is_running {
            return Ok(());
        }

        self.stream.write_all(&[0x03])?;
        self.stream.flush()?;

        let _ = self.read_packet()?;

        self.is_running = false;

        Ok(())
    }

    pub fn get_thread_list(&mut self) -> Result<Vec<String>> {
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
            }

            response = self.send_packet("qsThreadInfo")?;
        }

        Ok(threads)
    }

    pub fn set_current_thread(&mut self, thread_id: &str) -> Result<()> {
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

    pub fn get_stopped_thread_id(&mut self) -> Result<String> {
        let response = self.send_packet("?")?;

        if response.starts_with('T')
            && let Some(start) = response.find("thread:")
        {
            let remainder = &response[start + 7..];
            if let Some(end) = remainder.find(';') {
                return Ok(remainder[0..end].to_string());
            }
        }

        Err(Error::Rsp(
            "could not determine thread from stop reply".into(),
        ))
    }

    pub fn get_register_map(&mut self) -> Result<RegisterMap> {
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
