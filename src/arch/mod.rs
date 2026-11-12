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
use crate::base::types::{CodeMachine, VirtAddr};

// First, so its `unwind_trace!` reaches each architecture's unwinder.
#[macro_use]
pub mod unwind;
pub mod amd64;
pub mod arm64;
pub mod debug_registers;
pub mod paging;
pub mod registers;

pub use debug_registers::{DebugRegisters, HardwareWatch, HwBreakpointAccess};
pub use paging::{MappingPermissions, Paging, TableEntry};
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

    /// The other name of the register `name` names, by
    /// [`Architecture::register_synonyms`]: ARM64's `fp` for `x29`, `x29`
    /// for `fp`.
    pub fn other_register_name(self, name: &str) -> Option<&'static str> {
        self.register_synonyms().iter().find_map(|&(shown, other)| {
            if name == other {
                Some(shown)
            } else if name == shown {
                Some(other)
            } else {
                None
            }
        })
    }

    /// The name a listing shows the register `name` names under: AMD64's
    /// `rfl` for `eflags`.
    pub fn shown_register_name(self, name: &str) -> &str {
        self.register_synonyms()
            .iter()
            .find_map(|&(shown, other)| (other == name).then_some(shown))
            .unwrap_or(name)
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
        values.retain(|name, _| self.context_group_present(flags, name));
        values
    }

    /// Whether a raw `CONTEXT` `record` records `register`: a field of the
    /// record whose group its `ContextFlags` mark present.
    pub fn context_records(self, record: &[u8], register: &str) -> bool {
        let within = self
            .register_map()
            .info(register)
            .is_some_and(|info| info.offset + info.size <= record.len().min(self.context_size()));
        let flags = get_u32(record, self.context_flags().offset).unwrap_or(0);
        within && self.context_group_present(flags, register)
    }

    /// Whether `ContextFlags` `flags` mark the group of `register` present;
    /// a register in no group is in every record.
    fn context_group_present(self, flags: u32, register: &str) -> bool {
        self.context_group(register)
            .is_none_or(|group| flags & group == group)
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

    /// The number [`Self::encoded_registers`] gives the stack pointer, when
    /// the encoding numbers it among the integer registers (AMD64's `rsp`
    /// is 4; ARM64 numbers `sp` apart from x0-x30).
    fn encoded_sp(&self) -> Option<u8>;

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

    /// The processor state Windows keeps beside the `CONTEXT`, in
    /// `KSPECIAL_REGISTERS` (control, descriptor-table and debug
    /// registers): its layout, under the register map's names.
    fn special_register_map(&self) -> &'static RegisterMap;

    /// The `ContextFlags` group a `CONTEXT` record must mark present for
    /// `register` to hold a value; `None` for the control and integer state
    /// every record carries.
    fn context_group(&self, register: &str) -> Option<u32>;

    /// Whether a return pops its address off the stack (x86's `ret`) rather
    /// than taking it from a register (AArch64's `ret` through `lr`).
    fn return_pops_address(&self) -> bool;

    /// Where a Windows function finds argument `index` (from 0) on entry.
    fn argument(&self, index: usize) -> ArgumentLocation;

    /// The register a function's integer return value arrives in.
    fn return_register(&self) -> &'static str;

    /// The processor family it belongs to, which decides what its members
    /// share whatever their width.
    fn family(&self) -> Family;

    /// The instruction set the processor runs natively.
    fn code_machine(&self) -> CodeMachine;

    /// The instruction set it also runs in a compatibility mode, for a
    /// WOW64 process's 32-bit code (x86 on AMD64); `None` where Windows
    /// emulates other code instead (ARM64).
    fn compatibility_machine(&self) -> Option<CodeMachine>;

    /// How its address space divides and its page tables translate.
    fn paging(&self) -> &'static dyn Paging;

    /// Its hardware breakpoint registers.
    fn debug_registers(&self) -> &'static dyn DebugRegisters;

    /// Whether a Windows target on this processor runs code of `machine`:
    /// its own, a WOW64 process's x86, or what Windows emulates (x64 and x86
    /// on ARM64).
    fn runs_code(&self, machine: CodeMachine) -> bool;

    /// The name Windows gives interrupt request level `irql` on this
    /// processor (`DISPATCH_LEVEL`); a level devices interrupt at is
    /// `DIRQL`.
    fn irql_name(&self, irql: u64) -> &'static str;

    /// The names of the flags `flags`, the value of the last of
    /// [`Self::general_registers`] (`rfl`, `cpsr`), has set.
    fn flag_names(&self, flags: u64) -> Vec<&'static str>;

    /// How many of [`Self::general_registers`] a row of the register grid
    /// shows: three for AMD64, four for ARM64, as WinDbg lays them out.
    fn register_columns(&self) -> usize;

    /// The system registers `r` shows below the general ones when the
    /// backend reads them, row by row.
    fn control_registers(&self) -> &'static [&'static [ShownRegister]];

    /// The segment selectors `r` shows below the general ones, row by row.
    fn selector_registers(&self) -> &'static [&'static [ShownRegister]];

    /// The part of a wider register `name` (lowercase) names: x86's `eax`
    /// and `r8d`, ARM64's `w0`.
    fn subregister(&self, name: &str) -> Option<Subregister>;
}

/// Bits of a register under a name of their own: `bits` wide, `shift`
/// above the bottom of `register` (`ah` is 8 bits 8 up in `rax`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Subregister {
    pub register: &'static str,
    pub shift: u32,
    pub bits: u32,
}

impl Subregister {
    /// Its value within `value`, the whole register's.
    pub fn of(self, value: u64) -> u64 {
        (value >> self.shift) & (u64::MAX >> (64 - self.bits))
    }
}

/// A register `r` shows beside the general ones: under `label`, the
/// register the map knows as `name`, in `digits` hex digits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShownRegister {
    pub label: &'static str,
    pub name: &'static str,
    pub digits: usize,
}

impl ShownRegister {
    pub const fn new(label: &'static str, name: &'static str, digits: usize) -> Self {
        Self {
            label,
            name,
            digits,
        }
    }
}

/// Where a function's argument is on entry, by the calling convention.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArgumentLocation {
    Register(&'static str),
    /// The pointer-sized slot this many bytes above the stack pointer.
    Stack(u64),
}

/// A processor family: what its 32- and 64-bit members share, such as how
/// a breakpoint traps and which debug registers report it. Code that holds
/// for a whole family matches on this rather than on [`Arch`], so a new
/// member of a family inherits it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// x86 and AMD64: DR0-DR7, `int3`, RF, descriptor tables, I/O ports and
    /// the local APIC.
    X86,
    /// AArch64: BVR/BCR and WVR/WCR, `brk`, and no descriptor tables, I/O
    /// ports or APIC (a GIC instead).
    Arm,
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
    /// Every group a debugger reads.
    pub all: u32,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The stack pointer's number is where the encoding lists it, so a
    /// context's `sp` and its numbered slot never disagree.
    #[test]
    fn the_encoded_stack_pointer_is_where_the_encoding_lists_it() {
        for arch in Arch::ALL {
            let listed = arch
                .encoded_registers()
                .iter()
                .position(|name| *name == arch.sp_register())
                .map(|index| index as u8);
            assert_eq!(arch.encoded_sp(), listed, "{arch:?}");
        }
    }

    #[test]
    fn kernel_space_is_classified_per_architecture() {
        for (arch, kernel, user) in [
            (
                Arch::Amd64,
                VirtAddr(0xfffff80000001000),
                VirtAddr(0x00007ff000001000),
            ),
            (
                Arch::Arm64,
                VirtAddr(0xffff800000001000),
                VirtAddr(0x00007ff000001000),
            ),
        ] {
            assert!(
                arch.paging().is_kernel_address(kernel),
                "{arch:?} rejected its own kernel address {:#x}",
                kernel.0
            );
            assert!(
                !arch.paging().is_kernel_address(user),
                "{arch:?} accepted a user address {:#x} as kernel space",
                user.0
            );
        }
        // An AArch64 kernel address is below the AMD64 canonical bound, so the
        // bit-55 rule is doing real work rather than agreeing by accident.
        assert!(
            !Arch::Amd64
                .paging()
                .is_kernel_address(VirtAddr(0x0080000000001000))
        );
        assert!(
            Arch::Arm64
                .paging()
                .is_kernel_address(VirtAddr(0x0080000000001000))
        );
    }
}
