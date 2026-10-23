//! What ntoseye knows about each CPU architecture a Windows target runs on,
//! one module per architecture, each answering [`Architecture`].
//!
//! Shared code asks semantic questions (which register holds the program
//! counter, how wide a pointer is, which instruction a breakpoint plants)
//! and never names an architecture: an [`Arch`] dereferences to its
//! [`Architecture`], so `arch.pc_register()` asks it. A new architecture is
//! a new module implementing the trait, plus a variant here.
//!
//! This module is part of the base layer: the base reads page tables and
//! decodes instructions through it, and every layer above may use it.

use std::collections::HashMap;
use std::ops::Deref;

use crate::base::bytes::get_u32;
use crate::base::types::VirtAddr;

pub mod amd64;
pub mod arm64;
pub mod registers;

pub use registers::{RegisterFile, RegisterInfo, RegisterMap};

/// A target's CPU architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    Amd64,
    Arm64,
}

impl Arch {
    /// Every architecture, in the order kernel discovery tries them (AMD64,
    /// the historical default, first). A new variant goes here too: the
    /// reverse lookups below and discovery read this list.
    pub const ALL: [Self; 2] = [Self::Amd64, Self::Arm64];

    pub fn from_machine_type(machine: u16) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|arch| arch.machine_type() == machine)
    }

    pub fn from_gdb_architecture(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|arch| arch.gdb_architecture() == name)
    }

    /// Bytes in [`Architecture::breakpoint_instruction`]: how far the
    /// program counter must move to step past one, and the kind an RSP `Z0`
    /// packet names.
    pub fn breakpoint_size(self) -> u8 {
        self.breakpoint_instruction().len() as u8
    }

    /// The kernel pointer at the start of `bytes`, which holds at least
    /// [`Architecture::pointer_size`] bytes, zero-extended. Panics when it
    /// does not: the caller sized the buffer from the layout.
    #[track_caller]
    pub fn decode_pointer(self, bytes: &[u8]) -> VirtAddr {
        let size = self.pointer_size() as usize;
        let mut value = [0u8; 8];
        value[..size].copy_from_slice(&bytes[..size]);
        VirtAddr(u64::from_le_bytes(value))
    }

    /// The register buffer holding the raw `CONTEXT` `record`, as a dump, a
    /// minidump thread or a PRCB stores it. A short record and the synthetic
    /// slots past it stay zero.
    pub fn register_buffer(self, record: &[u8]) -> Vec<u8> {
        let mut buffer = vec![0u8; self.register_buffer_size()];
        let length = record.len().min(self.context_size());
        buffer[..length].copy_from_slice(&record[..length]);
        buffer
    }

    /// The registers a raw `CONTEXT` record records, by name: its own
    /// fields only (none of the synthetic slots past it), and of those only
    /// the groups its `ContextFlags` mark present, so an unrecorded register
    /// is unknown rather than whatever the structure holds there.
    pub fn context_registers(self, record: &[u8]) -> HashMap<String, u64> {
        let record = &record[..record.len().min(self.context_size())];
        let flags = get_u32(record, self.context_flags().offset).unwrap_or(0);
        let mut values = self.register_map().to_hashmap(record);
        values.retain(|name, _| {
            self.context_group(name)
                .is_none_or(|group| flags & group == group)
        });
        values
    }
}

impl Deref for Arch {
    type Target = dyn Architecture;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Amd64 => &amd64::Amd64,
            Self::Arm64 => &arm64::Arm64,
        }
    }
}

/// What an architecture answers. Every method is a question shared code
/// asks; each architecture's module answers all of them, so a new one is
/// complete when it compiles.
pub trait Architecture: Sync {
    /// The name WinDbg prints for it: `AMD64`, `ARM64`.
    fn label(&self) -> &'static str;

    /// The PE and dump-header machine type (`IMAGE_FILE_MACHINE_*`).
    fn machine_type(&self) -> u16;

    /// The `<architecture>` a GDB target description names it by.
    fn gdb_architecture(&self) -> &'static str;

    /// Bytes in a kernel pointer: a `LIST_ENTRY` link, a slot of a pointer
    /// array, a stack slot.
    fn pointer_size(&self) -> u64;

    /// The software breakpoint instruction a site holds, the one the kernel
    /// debugger uses, so the guest reports a hit as a KD break.
    fn breakpoint_instruction(&self) -> &'static [u8];

    /// Register holding the current address space's page-table base.
    fn dtb_register(&self) -> &'static str;

    /// Bits of the DTB register that select the page-table base frame (PCID,
    /// ASID, and reserved/canonical bits masked out), for comparing address
    /// spaces.
    fn dtb_page_mask(&self) -> u64;

    /// Register holding the address of the next instruction.
    fn pc_register(&self) -> &'static str;

    /// Register holding the stack pointer.
    fn sp_register(&self) -> &'static str;

    /// Register a frame-pointer chain links through.
    fn frame_register(&self) -> &'static str;

    /// Register holding the processor's status flags.
    fn flags_register(&self) -> &'static str;

    /// The general registers in the order the register grid and a step's
    /// changed-register line show them, flags last.
    fn general_registers(&self) -> &'static [&'static str];

    /// The integer registers in the order the instruction set numbers them,
    /// which is how unwind codes name them.
    fn encoded_registers(&self) -> &'static [&'static str];

    /// Pairs of names for one register: the name a listing shows, then the
    /// other name it also answers to (ARM64's `fp` for `x29`).
    fn register_synonyms(&self) -> &'static [(&'static str, &'static str)];

    /// Bytes in the architecture's `CONTEXT` record.
    fn context_size(&self) -> usize;

    /// Where its `CONTEXT` record keeps `ContextFlags`, and the groups the
    /// flags mark present.
    fn context_flags(&self) -> ContextFlags;

    /// Bytes in its register buffer: the `CONTEXT` record, then synthetic
    /// slots for what the record does not carry (control and system
    /// registers, page-table roots).
    fn register_buffer_size(&self) -> usize;

    /// The register-buffer slot holding the kernel's page-table root.
    fn kernel_dtb_register(&self) -> &'static str;

    /// The register map over the register buffer.
    fn register_map(&self) -> &'static RegisterMap;

    /// The `ContextFlags` group a `CONTEXT` record must mark present for
    /// `register` to hold a value; `None` for the control and integer state
    /// every record carries.
    fn context_group(&self, register: &str) -> Option<u32>;
}

/// A `CONTEXT` record's `ContextFlags`: where it sits, and the bits that
/// mark each register group present (each including the architecture's
/// own bit, as Windows defines them; 0 for a group the architecture lacks).
#[derive(Debug, Clone, Copy)]
pub struct ContextFlags {
    pub offset: usize,
    /// The bit naming the architecture, which every group includes.
    pub architecture: u32,
    pub control: u32,
    pub integer: u32,
    pub segments: u32,
    pub floating_point: u32,
    pub debug_registers: u32,
}

pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
pub const IMAGE_FILE_MACHINE_ARM64: u16 = 0xaa64;

/// A machine type as kernel dumps and `vertarget` name it: `I386`, `AMD64`,
/// `ARM64`, or `Unknown`. A PE header's richer naming is
/// [`crate::nt::pe::headers::machine_name`].
pub fn machine_name(machine: u16) -> &'static str {
    match machine {
        IMAGE_FILE_MACHINE_I386 => "I386",
        IMAGE_FILE_MACHINE_AMD64 => "AMD64",
        IMAGE_FILE_MACHINE_ARM64 => "ARM64",
        _ => "Unknown",
    }
}
