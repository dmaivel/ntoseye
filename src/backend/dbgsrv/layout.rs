//! Multi-field `IUserDebugServices` wire structures, one per C structure or
//! contiguous argument run the generated proxy marshals together.
//!
//! Single-scalar arguments (`u32`, `u64`) are written and read directly via
//! [`super::wire::Writer`] and [`super::wire::Reader`]. Every structure here
//! states the exact C size the server expects so a layout change fails the
//! build rather than the protocol.

use super::wire::wire_struct;

// Target and connection queries.

wire_struct! {
    /// `GetTargetInfo` buffer sizes, always zero here: nothing reads the
    /// server's CSD or build strings.
    pub struct GetTargetInfoArgs {
        csd_string_size: u32,
        build_string_size: u32,
    } = 8
}

wire_struct! {
    /// `GetTargetInfo`'s reply: eight `ULONG`s, the two (empty) version
    /// strings, then three more.
    pub struct TargetInfoRet {
        machine_type: u32,
        number_processors: u32,
        platform_id: u32,
        major_version: u32,
        minor_version: u32,
        build_number: u32,
        checked_build: u32,
        reserved: u32,
        product_type: u32,
        suite_mask: u32,
        reserved2: u32,
    } = 44
}

wire_struct! {
    /// `_DEBUG_THREAD_BASIC_INFORMATION`, which `GetThreadBasicInfo` fills.
    pub struct ThreadBasicInformation {
        valid: u32,
        exit_status: u32,
        priority_class: u32,
        priority: u32,
        create_time: u64,
        exit_time: u64,
        kernel_time: u64,
        user_time: u64,
        start_offset: u64,
        affinity: u64,
    } = 64
}

wire_struct! {
    /// `_DEBUG_CREATE_PROCESS_OPTIONS`, passed to `CreateProcessW`.
    pub struct CreateProcessOptions {
        create_flags: u32,
        eng_create_flags: u32,
        verifier_flags: u32,
        reserved: u32,
    } = 16
}

wire_struct! {
    /// `GetConnectionInfo`: the byte sizes of the three names the caller
    /// wants back. The reply is their UTF-16 text, in that order.
    pub struct GetConnectionInfoArgs {
        machine_name_size: u32,
        client_identity_size: u32,
        transport_identity_size: u32,
    } = 12
}

// Process enumeration and attachment.

wire_struct! {
    /// `GetProcessInfo`: the process, the `DBGSVC_PROC_INFO_*` flags, and how
    /// many thread records the caller's array holds.
    pub struct GetProcessInfoArgs {
        process_id: u32,
        flags: u32,
        info_count: u32,
    } = 12
}

wire_struct! {
    /// `USER_THREAD_INFO`.
    pub struct UserThreadInfo {
        handle: u64,
        id: u32,
        reserved: u32,
    } = 16
}

wire_struct! {
    /// `AttachProcess`: the process, and the `DEBUG_ATTACH_*` flags.
    pub struct AttachProcessArgs {
        process_id: u32,
        attach_flags: u32,
    } = 8
}

wire_struct! {
    /// `CreateProcessW`'s reply.
    pub struct CreatedProcessRet {
        process_id: u32,
        thread_id: u32,
        process_handle: u64,
        thread_handle: u64,
    } = 24
}

// Memory, contexts, events, and breakpoints.

wire_struct! {
    /// `ReadVirtual`, `WriteVirtual` and `QueryVirtual`: the process and the
    /// address, followed by the buffer size.
    pub struct AddressArgs {
        process: u64,
        offset: u64,
    } = 16
}

wire_struct! {
    /// `GetContext`: the `CONTEXT` flags to ask for, where in the record they
    /// go, and how large the caller's record is.
    pub struct GetContextArgs {
        flags: u32,
        flags_offset: u32,
        context_size: u32,
    } = 12
}

wire_struct! {
    /// `WaitForEvent`: how long to wait, and how large the caller's event
    /// buffer is.
    pub struct WaitForEventArgs {
        timeout: u32,
        buffer_size: u32,
    } = 8
}

wire_struct! {
    /// `InsertCodeBreakpoint` and `RemoveCodeBreakpoint`: the process, the
    /// site, the machine type, and the size of the storage buffer.
    pub struct CodeBreakpointArgs {
        process: u64,
        offset: u64,
        machine_type: u32,
        storage_size: u32,
    } = 24
}
