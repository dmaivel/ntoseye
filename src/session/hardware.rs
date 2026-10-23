//! The halted processors' and devices' state the backend reads: MSRs, I/O
//! ports, descriptor-table registers, the local APIC, and PCI
//! configuration space.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::arch::Family;
use crate::backend::dbg_backend::{PciConfigAddress, processor_index_from_backend_thread_id};
use crate::base::error::{Error, Result};
use crate::base::types::{MAX_PROCESSORS, VirtAddr};
use crate::nt::cpu_state;
use crate::nt::target::DiagnosticValue;
use crate::nt::target::apic::{IA32_APIC_BASE, LocalApic, apic_read_error};
use crate::nt::target::cpu::{
    DescriptorRegister, DescriptorTable, Gdt, Idt, Pcr, Processor, cpu_location, decode_gdt,
    decode_idt, descriptor_from_target, validate_idt_vector,
};
use crate::nt::target::pci::{
    EcamWindow, PCI_EXTENDED_CONFIG_SIZE, PCI_MAX_DEVICES, PCI_MAX_FUNCTIONS, PciFunction,
    PciQuery, PciScan, function_absent, parse_header,
};
use crate::session::Session;

/// [`Error::TargetRunning`] payload for MSR access.
const MSRS_NEED_HALT: &str = "MSRs are read on a halted processor.";
/// [`Error::TargetRunning`] payload for I/O-port access.
const PORTS_NEED_HALT: &str = "I/O ports are accessed on a halted target.";
/// [`Error::TargetRunning`] payload for configuration-space reads.
const PCI_CONFIG_NEEDS_HALT: &str = "PCI configuration space is read on a halted target.";

impl Session {
    /// The number of processors: `KeNumberProcessors`, else the backend's
    /// vCPUs.
    pub fn processor_count(&mut self) -> u16 {
        if let Ok(count) = cpu_state::processor_count(&self.target) {
            return count.max(1);
        }
        // cpu_state intentionally only depends on Target. A live backend is the
        // second source of truth when KeNumberProcessors is absent from a dump.
        self.backend
            .thread_list()
            .ok()
            .map(|threads| threads.len().clamp(1, usize::from(MAX_PROCESSORS)) as u16)
            .unwrap_or(1)
    }

    /// `processor`, or the current vCPU's, checked against the processor
    /// count.
    pub fn processor(&mut self, processor: Option<Processor>) -> Result<u16> {
        let count = self.processor_count();
        let processor = processor.map_or_else(
            || processor_index_from_backend_thread_id(&self.current_thread).unwrap_or(0),
            |processor| processor.0,
        );
        if processor >= count {
            return Err(Error::DebugInfo(format!(
                "processor {processor} out of range (target has {count} processor(s))"
            )));
        }
        Ok(processor)
    }

    fn current_processor_for_cpu(&self) -> u16 {
        processor_index_from_backend_thread_id(&self.current_thread).unwrap_or(0)
    }

    fn backend_descriptor(&mut self, name: &str) -> Result<DescriptorRegister> {
        let names = self.register_map.names();
        if !names
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(name))
        {
            return Err(Error::FieldNotFound(name.to_string()));
        }
        let registers = self.read_registers()?;
        let base = self.register_map.read_u64(name, &registers)?;
        let limit_name = format!("{name}_limit");
        let limit = self
            .register_map
            .read_u64(&limit_name, &registers)
            .unwrap_or(0);
        Ok(DescriptorRegister {
            base: VirtAddr(base),
            limit,
        })
    }

    fn descriptor_for_cpu(
        &mut self,
        processor: u16,
        table: DescriptorTable,
    ) -> Result<DescriptorRegister> {
        if processor != self.current_processor_for_cpu() {
            return Err(Error::DebugInfo(
                "IDTR/GDTR ProcessorState is valid only for the halting processor".into(),
            ));
        }
        let location = cpu_location(&self.target, processor)?;
        match descriptor_from_target(&self.target, &location, table) {
            Ok(descriptor) => Ok(descriptor),
            Err(error) => self.backend_descriptor(table.register()).or(Err(error)),
        }
    }

    /// Decode KPCR/KPRCB essentials, using halted backend descriptor registers
    /// only when target-memory descriptor fields are unavailable; all other
    /// diagnostic values retain their target-memory layout/read errors.
    pub fn inspect_pcr(&mut self, processor: u16) -> Result<Pcr> {
        let mut detail = self.target.inspect_pcr(processor)?;
        let idtr = self.descriptor_for_cpu(processor, DescriptorTable::Idt);
        detail.idtr = DiagnosticValue::from_result(idtr);
        let gdtr = self.descriptor_for_cpu(processor, DescriptorTable::Gdt);
        detail.gdtr = DiagnosticValue::from_result(gdtr);
        Ok(detail)
    }

    /// Decode one IDT vector or all 256 vectors from the halted processor's
    /// IDTR, falling back to backend register reads when PDB state is absent;
    /// each entry field preserves its own memory/symbol diagnostic.
    pub fn inspect_idt(&mut self, processor: u16, vector: Option<u16>) -> Result<Idt> {
        match self.target.arch().family() {
            Family::X86 => {}
            Family::Arm => {
                return Err(Error::DebugInfo(
                    "!idt is not defined on ARM64 targets".into(),
                ));
            }
        }
        validate_idt_vector(vector)?;
        let descriptor = self.descriptor_for_cpu(processor, DescriptorTable::Idt)?;
        Ok(decode_idt(&self.target, processor, descriptor, vector))
    }

    /// Decode the halted processor's bounded GDT, falling back to backend GDTR
    /// registers when PDB state is absent; each entry field preserves its own
    /// raw/descriptor diagnostic.
    pub fn inspect_gdt(&mut self, processor: u16) -> Result<Gdt> {
        match self.target.arch().family() {
            Family::X86 => {}
            Family::Arm => {
                return Err(Error::DebugInfo(
                    "!gdt is not defined on ARM64 targets".into(),
                ));
            }
        }
        let descriptor = self.descriptor_for_cpu(processor, DescriptorTable::Gdt)?;
        Ok(decode_gdt(&self.target, processor, descriptor))
    }

    /// Read one MSR on a halted processor after enforcing the backend MSR
    /// capability. The backend error is returned unchanged to the caller.
    pub fn read_msr(&mut self, processor: u16, msr: u32) -> Result<u64> {
        if self.backend.is_running() {
            return Err(Error::TargetRunning(MSRS_NEED_HALT));
        }
        if !self.backend.supports_msr() {
            return Err(Error::NotSupported);
        }
        self.backend.read_msr(processor, msr)
    }

    /// Write one MSR on a halted processor after enforcing the backend MSR
    /// capability. The backend error is returned unchanged to the caller.
    pub fn write_msr(&mut self, processor: u16, msr: u32, value: u64) -> Result<()> {
        if self.backend.is_running() {
            return Err(Error::TargetRunning(MSRS_NEED_HALT));
        }
        // Hosts write the selected vCPU's MSRs; a vCPU stopped in VTL1 is
        // inspection-only, like its register file.
        if processor_index_from_backend_thread_id(&self.current_thread) == Some(processor)
            && self
                .read_registers()
                .ok()
                .and_then(|regs| {
                    self.register_map
                        .read_u64(self.target.arch().dtb_register(), &regs)
                        .ok()
                })
                .is_some_and(|dtb| self.target.recognize_secure_root(dtb))
        {
            return Err(Error::DebugInfo("VTL1 MSRs are read-only".into()));
        }
        if !self.backend.supports_msr() {
            return Err(Error::NotSupported);
        }
        self.backend.write_msr(processor, msr, value)
    }

    /// Refuse an I/O-port access the backend cannot make, saying why, or one
    /// the target cannot take while running.
    fn check_io_ports(&self) -> Result<()> {
        match self.target.arch().family() {
            Family::X86 => {}
            Family::Arm => {
                return Err(Error::DebugInfo(
                    "ARM64 has no I/O-port space; devices are memory-mapped".into(),
                ));
            }
        }
        if !self.backend.supports_io_ports() {
            return Err(Error::DebugInfo(format!(
                "the {} backend has no I/O-port access; ports are read and written through \
                 the Windows KD protocol (the kd and kdnet backends)",
                self.backend.name()
            )));
        }
        if self.backend.is_running() {
            return Err(Error::TargetRunning(PORTS_NEED_HALT));
        }
        Ok(())
    }

    /// Read `size` (1, 2, or 4) bytes from I/O port `port` on the current
    /// processor (`ib`/`iw`/`id`).
    pub fn read_io_port(&mut self, port: u64, size: u8) -> Result<u32> {
        validate_io_port(port, size)?;
        self.check_io_ports()?;
        self.backend.read_io_port(port, size)
    }

    /// Write `value` as `size` (1, 2, or 4) bytes to I/O port `port` on the
    /// current processor (`ob`/`ow`/`od`).
    pub fn write_io_port(&mut self, port: u64, size: u8, value: u64) -> Result<()> {
        validate_io_port(port, size)?;
        if value >> (u32::from(size) * 8) != 0 {
            return Err(Error::InvalidArgument(format!(
                "{value:#x} does not fit in {size} byte(s)"
            )));
        }
        self.check_io_ports()?;
        self.backend.write_io_port(port, size, value as u32)
    }

    /// The local APIC of `processor`, which needs a backend that reads MSRs
    /// and device registers on a given processor (KD): in x2APIC mode
    /// through its MSRs, in xAPIC mode through its registers at the
    /// physical base `IA32_APIC_BASE` names, read uncached.
    pub fn local_apic(&mut self, processor: u16) -> Result<LocalApic> {
        match self.target.arch().family() {
            Family::X86 => {}
            Family::Arm => {
                return Err(Error::DebugInfo(
                    "!apic reads an x86 local APIC; an ARM64 target has a GIC".into(),
                ));
            }
        }
        if self.backend.is_running() {
            return Err(Error::TargetRunning(
                "the local APIC is read on a halted processor.",
            ));
        }
        let apic_base = self
            .read_msr(processor, IA32_APIC_BASE)
            .map_err(|error| match error {
                Error::NotSupported => Error::DebugInfo(
                    "!apic reads the local APIC through MSRs, which this backend cannot read; \
                 attach over KD (kd or kdnet)"
                        .into(),
                ),
                other => other,
            })?;
        let results = self
            .backend
            .read_on_processor(processor, &LocalApic::reads(apic_base))
            .map_err(|error| apic_read_error(apic_base, error))?;
        LocalApic::decode(processor, apic_base, results)
    }

    /// Refuse a configuration-space read the backend cannot make, saying why,
    /// or one the target cannot take while running.
    fn check_pci_config(&self) -> Result<()> {
        if !self.backend.supports_pci_config() {
            return Err(Error::DebugInfo(format!(
                "the {} backend cannot read PCI configuration space: it is device registers \
                 (the ECAM window or ports 0xcf8/0xcfc), not the RAM this backend reads; use \
                 the gdb backend (QEMU) or kd/kdnet",
                self.backend.name()
            )));
        }
        if self.backend.is_running() {
            return Err(Error::TargetRunning(PCI_CONFIG_NEEDS_HALT));
        }
        Ok(())
    }

    /// Read `len` bytes of a function's configuration space from `offset`.
    fn read_function_config(
        &mut self,
        windows: &[EcamWindow],
        segment: u16,
        bus: u8,
        device: u8,
        function: u8,
        offset: u16,
        len: usize,
    ) -> Result<Vec<u8>> {
        let ecam = windows
            .iter()
            .find_map(|window| window.function_page(segment, bus, device, function));
        let mut config = vec![0; len];
        self.backend.read_pci_config(
            PciConfigAddress {
                segment,
                bus,
                device,
                function,
                ecam,
            },
            offset,
            &mut config,
        )?;
        Ok(config)
    }

    /// Scan configuration space as `!pci` does: each device's function 0,
    /// and functions 1-7 of a multi-function device, reading `query.size`
    /// bytes of every function whose vendor ID is not all-ones. A named
    /// function is read whatever function 0 says.
    pub fn scan_pci(&mut self, query: &PciQuery) -> Result<PciScan> {
        if let Some(device) = query.device.filter(|device| *device >= PCI_MAX_DEVICES) {
            return Err(Error::InvalidArgument(format!(
                "PCI device {device:#x} is out of range (0-0x1f)"
            )));
        }
        if let Some(function) = query
            .function
            .filter(|function| *function >= PCI_MAX_FUNCTIONS)
        {
            return Err(Error::InvalidArgument(format!(
                "PCI function {function:#x} is out of range (0-7)"
            )));
        }
        if query.first_bus > query.last_bus {
            return Err(Error::InvalidArgument(format!(
                "bus range {:#x}-{:#x} is empty",
                query.first_bus, query.last_bus
            )));
        }
        self.check_pci_config()?;
        let size = query.size.clamp(0x40, PCI_EXTENDED_CONFIG_SIZE);
        // Only the gdb backend needs them; a missing table is its error then.
        let windows = self.target.pci_ecam_windows().unwrap_or_default();
        let interrupt = Arc::clone(&self.target.interrupt);
        let mut scan = PciScan {
            functions: Vec::new(),
            interrupted: false,
        };
        for bus in query.first_bus..=query.last_bus {
            let devices = match query.device {
                Some(device) => device..=device,
                None => 0..=PCI_MAX_DEVICES - 1,
            };
            for device in devices {
                if interrupt.load(Ordering::Relaxed) {
                    scan.interrupted = true;
                    return Ok(scan);
                }
                let functions = match query.function {
                    Some(function) => function..=function,
                    None => {
                        let head = self.read_function_config(
                            &windows,
                            query.segment,
                            bus,
                            device,
                            0,
                            0,
                            0x10,
                        )?;
                        if function_absent(&head) {
                            continue;
                        }
                        let last = if head[0x0e] & 0x80 != 0 {
                            PCI_MAX_FUNCTIONS - 1
                        } else {
                            0
                        };
                        0..=last
                    }
                };
                for function in functions {
                    let config = self.read_function_config(
                        &windows,
                        query.segment,
                        bus,
                        device,
                        function,
                        0,
                        size,
                    )?;
                    if function_absent(&config) {
                        continue;
                    }
                    let Some(header) = parse_header(&config) else {
                        return Err(Error::DebugInfo(format!(
                            "PCI {bus:02x}:{device:02x}.{function} returned {} bytes of \
                             configuration space, short of its 64-byte header",
                            config.len()
                        )));
                    };
                    scan.functions.push(PciFunction {
                        segment: query.segment,
                        bus,
                        device,
                        function,
                        header,
                        config,
                    });
                }
            }
        }
        Ok(scan)
    }
}

/// An x86 I/O-port access: 1, 2, or 4 bytes inside the 64 KiB port space,
/// aligned to its size as the kernel's `KdpReadIoSpace` requires.
fn validate_io_port(port: u64, size: u8) -> Result<()> {
    if !matches!(size, 1 | 2 | 4) {
        return Err(Error::InvalidArgument(format!(
            "I/O access size must be 1, 2, or 4 bytes, not {size}"
        )));
    }
    if port
        .checked_add(u64::from(size))
        .is_none_or(|end| end > 0x1_0000)
    {
        return Err(Error::InvalidArgument(format!(
            "port {port:#x} is outside the 64 KiB I/O space"
        )));
    }
    if !port.is_multiple_of(u64::from(size)) {
        return Err(Error::InvalidArgument(format!(
            "port {port:#x} is not aligned to a {size}-byte access"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_io_port;

    #[test]
    fn io_port_accesses_stay_aligned_inside_the_port_space() {
        assert!(validate_io_port(0xfffc, 4).is_ok());
        assert!(validate_io_port(0xffff, 1).is_ok());
        assert!(validate_io_port(0xfffe, 4).is_err());
        assert!(validate_io_port(0x1_0000, 1).is_err());
        assert!(validate_io_port(0xcf9, 2).is_err());
        assert!(validate_io_port(0xcfa, 2).is_ok());
        assert!(validate_io_port(0x80, 3).is_err());
        assert!(validate_io_port(u64::MAX, 1).is_err());
    }
}
