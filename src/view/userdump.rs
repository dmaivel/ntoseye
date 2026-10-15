//! userdump: [`View`] builders for what a user-mode minidump records beside
//! its memory and threads: the exception, handles, memory regions, and
//! unloaded modules.

use ntoseye_macros::record;

use crate::ntstatus::ntstatus_name;
use crate::target::Target;
use crate::target::mm::{memory_state_name, memory_type_name, page_protection_name};
use crate::target::usermode::address::UserRegion;
use crate::target::usermode::handles::handle_attribute_names;
use crate::types::VirtAddr;
use crate::unwind::{resolve_thread_trace_context, try_format_symbol};
use crate::userdump::{UnloadedModule, UserException, UserHandle};

/// The exception a user-mode minidump was written for (`ExceptionStream`).
#[record]
pub struct UserDumpException {
    /// The thread that raised it.
    pub thread_id: u32,
    /// The exception code (an NTSTATUS, or an application's own code).
    #[record(hex)]
    pub code: u32,
    /// The NTSTATUS name of `code`, when it is one ntoseye knows.
    pub code_name: Option<String>,
    #[record(hex)]
    pub flags: u32,
    /// The address of a chained `EXCEPTION_RECORD`, 0 for none.
    pub record: VirtAddr,
    /// Where the exception was raised.
    pub address: VirtAddr,
    /// `address` as `module!function+offset`, when it resolves.
    pub symbol: Option<String>,
    #[record(hex)]
    pub parameters: Vec<u64>,
    /// Why the exception's CONTEXT is unusable, `None` when it is.
    pub context_error: Option<String>,
}

/// A handle the process held, as `HandleDataStream` records it. The dump
/// names no object address.
#[record]
pub struct UserDumpHandle {
    #[record(hex)]
    pub handle: u64,
    pub type_name: Option<String>,
    pub object_name: Option<String>,
    /// `OBJ_*` attribute flags.
    #[record(hex)]
    pub attributes: u32,
    /// `attributes` as `OBJ_*` names.
    pub attribute_names: Vec<String>,
    #[record(hex)]
    pub granted_access: u32,
    pub handle_count: u32,
    pub pointer_count: u32,
}

/// A region of the process's address space, as `VirtualQueryEx`
/// reported it (`MemoryInfoListStream`), with what the dump shows uses it
/// (`!address`).
#[record]
pub struct UserDumpRegion {
    pub base: VirtAddr,
    pub allocation_base: VirtAddr,
    #[record(hex)]
    pub allocation_protect: u32,
    /// `allocation_protect` as `PAGE_*` names.
    pub allocation_protect_name: String,
    #[record(hex)]
    pub size: u64,
    #[record(hex)]
    pub state: u32,
    /// `MEM_COMMIT`, `MEM_RESERVE`, or `MEM_FREE`.
    pub state_name: &'static str,
    #[record(hex)]
    pub protect: u32,
    /// `protect` as `PAGE_*` names; empty for a free or reserved region.
    pub protect_name: String,
    /// The region's type: `MEM_IMAGE`, `MEM_MAPPED`, or `MEM_PRIVATE`; 0 for
    /// a free region.
    #[record(hex)]
    pub kind: u32,
    /// `kind`'s name, empty for a free region.
    pub kind_name: &'static str,
    /// What uses the region: `Image`, `Stack`, `TEB`, `PEB`, `Heap`,
    /// `Free`, or `<unknown>`.
    pub usage: &'static str,
    /// The module, thread, or heap `usage` names.
    pub detail: Option<String>,
    /// How many of the region's bytes the dump captured; the rest do not
    /// read.
    #[record(hex)]
    pub captured: u64,
}

/// A module the process had unloaded (`UnloadedModuleListStream`).
#[record]
pub struct UserDumpUnloadedModule {
    pub name: String,
    pub base: VirtAddr,
    #[record(hex)]
    pub size: u32,
    #[record(hex)]
    pub checksum: u32,
    #[record(hex)]
    pub time_date_stamp: u32,
}

/// The dump's exception, its address named in the dump's modules.
pub fn exception(target: &Target, exception: &UserException) -> UserDumpException {
    let trace = resolve_thread_trace_context(target, 0);
    UserDumpException {
        thread_id: exception.thread_id,
        code: exception.code,
        code_name: ntstatus_name(exception.code).map(str::to_string),
        flags: exception.flags,
        record: VirtAddr(exception.record),
        address: VirtAddr(exception.address),
        symbol: try_format_symbol(target, &trace, exception.address),
        parameters: exception.parameters.clone(),
        context_error: exception.context.as_ref().err().cloned(),
    }
}

pub fn handle(handle: &UserHandle) -> UserDumpHandle {
    UserDumpHandle {
        handle: handle.handle,
        type_name: handle.type_name.clone(),
        object_name: handle.object_name.clone(),
        attributes: handle.attributes,
        attribute_names: handle_attribute_names(handle.attributes),
        granted_access: handle.granted_access,
        handle_count: handle.handle_count,
        pointer_count: handle.pointer_count,
    }
}

pub fn region(user: &UserRegion) -> UserDumpRegion {
    let region = &user.region;
    UserDumpRegion {
        base: VirtAddr(region.base),
        allocation_base: VirtAddr(region.allocation_base),
        allocation_protect: region.allocation_protect,
        allocation_protect_name: page_protection_name(region.allocation_protect),
        size: region.size,
        state: region.state,
        state_name: memory_state_name(region.state),
        protect: region.protect,
        protect_name: page_protection_name(region.protect),
        kind: region.kind,
        kind_name: memory_type_name(region.kind),
        usage: user.usage.label(),
        detail: user.detail.clone(),
        captured: user.captured,
    }
}

pub fn unloaded_module(module: &UnloadedModule) -> UserDumpUnloadedModule {
    UserDumpUnloadedModule {
        name: module.name.clone(),
        base: VirtAddr(module.base),
        size: module.size,
        checksum: module.checksum,
        time_date_stamp: module.time_date_stamp,
    }
}
