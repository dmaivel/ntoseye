//! The fixed parts of every `IUserDebugServices` call body, one structure per
//! run of arguments the generated proxy marshals together.
//!
//! The proxy aligns each argument to its own size, so a run is only one
//! structure when its C layout puts every field where the proxy puts it: a
//! `ULONG64` followed by a `ULONG` is two structures here, because `repr(C)`
//! would pad the second to offset 8 while the proxy puts it at 8 only if the
//! `ULONG64` ended there. Writing them as separate [`super::wire::Writer`]
//! segments keeps the bytes right and the layout compiler-checked.
//!
//! Every structure states the size the server expects, so a field added or
//! reordered fails the build rather than the protocol.

use super::wire::wire_struct;

// GetTargetInfo.

wire_struct! {
    /// The two buffer sizes, which this client always passes zero: nothing
    /// reads the server's CSD or build strings.
    pub struct GetTargetInfoArgs {
        csd_string_size: u32,
        build_string_size: u32,
    } = 8
}

wire_struct! {
    /// `GetTargetInfo`'s reply: eight `ULONG`s, the two (empty) version
    /// strings, then three more. The middle four are the OS identity the
    /// older interface packed into one build number.
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
    /// `_DEBUG_THREAD_BASIC_INFORMATION`, which `GetThreadBasicInfo` fills:
    /// the times, then the address the thread's function starts at.
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
    /// `_DEBUG_CREATE_PROCESS_OPTIONS`: what `CreateProcessW` takes besides
    /// the command line.
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
    /// `GetProcessIds`: how many ids the caller's array holds.
    pub struct GetProcessIdsArgs {
        count: u32,
    } = 4
}

wire_struct! {
    /// The count of ids the server actually listed, after the array.
    pub struct ActualCountRet {
        actual: u32,
    } = 4
}

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
    /// `DetachProcess`'s only argument.
    pub struct DetachProcessArgs {
        process_id: u32,
    } = 4
}

wire_struct! {
    /// The `DEBUG_*` options the process was created with.
    pub struct ProcessOptionsRet {
        options: u32,
    } = 4
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

// Handles and options.

wire_struct! {
    /// A single `ULONG64` handle argument: the process, thread, or object a
    /// call names.
    pub struct HandleArg {
        handle: u64,
    } = 8
}

wire_struct! {
    /// The second half of `QueryInterface`'s request: the revision code the
    /// generator derived for the interface, which the server compares with
    /// the one it was built against.
    pub struct InterfaceVersion {
        code: u32,
    } = 4
}

wire_struct! {
    /// `Initialize`'s reply: the `DBGSVC_*` flags the service implements.
    pub struct InitializeRet {
        flags: u32,
    } = 4
}

wire_struct! {
    /// A `BOOL` argument, which the interface marshals as a 32-bit field.
    pub struct BoolArg {
        value: u32,
    } = 4
}

wire_struct! {
    /// One id of a `size_is` array: a process id, or its count.
    pub struct ProcessId {
        process_id: u32,
    } = 4
}

wire_struct! {
    /// A single `ULONG` option or flag argument, after a handle.
    pub struct OptionsArg {
        options: u32,
    } = 4
}

wire_struct! {
    /// The one `ULONG` reply of a call that reports how many bytes it moved.
    pub struct UsedRet {
        used: u32,
    } = 4
}

wire_struct! {
    /// A single `ULONG` reply that names a process's exit status.
    pub struct ExitCodeRet {
        exit_code: u32,
    } = 4
}

wire_struct! {
    /// A single `ULONG64` reply: an offset or address.
    pub struct OffsetRet {
        offset: u64,
    } = 8
}

// Memory.

wire_struct! {
    /// `ReadVirtual`, `WriteVirtual` and `QueryVirtual`: the process and the
    /// address, which the buffer size follows.
    pub struct AddressArgs {
        process: u64,
        offset: u64,
    } = 16
}

wire_struct! {
    /// The buffer size of a memory call, as `IN ULONG`: it precedes the
    /// buffer it describes.
    pub struct SizeArg {
        size: u32,
    } = 4
}

// Threads and contexts.

wire_struct! {
    /// `SuspendThreads` and `ResumeThreads`: the count, and the `size_is`
    /// count the same call's layout repeats.
    pub struct ThreadCountArgs {
        count: u32,
        array_count: u32,
    } = 8
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

// Events.

wire_struct! {
    /// `WaitForEvent`: how long to wait, and how large the caller's event
    /// buffer is.
    pub struct WaitForEventArgs {
        timeout: u32,
        buffer_size: u32,
    } = 8
}

wire_struct! {
    /// `ContinueEvent`: `DBG_CONTINUE` or `DBG_EXCEPTION_NOT_HANDLED`.
    pub struct ContinueEventArgs {
        status: u32,
    } = 4
}

// Breakpoints.

wire_struct! {
    /// `InsertCodeBreakpoint` and `RemoveCodeBreakpoint`: the process, the
    /// site, the machine type, and the size of the storage the caller
    /// expects (insert) or sends back (remove).
    pub struct CodeBreakpointArgs {
        process: u64,
        offset: u64,
        machine_type: u32,
        storage_size: u32,
    } = 24
}

wire_struct! {
    /// The data breakpoint calls: the process, the thread, and the watched
    /// address.
    pub struct WatchedAddressArgs {
        process: u64,
        thread: u64,
        offset: u64,
    } = 24
}

wire_struct! {
    /// The watched range and access of a data breakpoint.
    pub struct WatchArgs {
        access_length: u32,
        access_type: u32,
        machine_type: u32,
    } = 12
}

wire_struct! {
    /// The access type `GetLastDataBreakpointHit` reports after its address.
    pub struct AccessTypeRet {
        access_type: u32,
    } = 4
}
