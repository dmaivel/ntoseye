//! Decoding the `DEBUG_EVENT` a process server hands back from
//! `WaitForEvent`.
//!
//! The server is a 64-bit Windows program, so the union it fills is the
//! 64-bit one: handles are eight bytes, and the exception record's
//! `ExceptionInformation` array holds `ULONG64`s. Each member of the union is
//! a `#[repr(C)]` structure of its own, read out of the event's payload by
//! the code that names it; the padding fields between members are named so
//! the sizes are the ones Windows defines.

use zerocopy::{FromBytes, IntoBytes, KnownLayout};

use crate::backend::dbg_backend::ExceptionRecord;
use crate::base::error::{Error, Result};

use super::wire::wire_struct;

/// Header bytes before the 8-byte-aligned union inside `DEBUG_EVENT`.
pub const DEBUG_EVENT_HEADER_SIZE: usize = 16;

/// Windows `DEBUG_EVENT`:
/// `{ DWORD dwDebugEventCode; DWORD dwProcessId; DWORD dwThreadId; union { .. } }`,
/// with the union eight-byte aligned, so it starts at offset
/// [`DEBUG_EVENT_HEADER_SIZE`].
pub const DEBUG_EVENT_SIZE: usize = 176;

/// Bytes of the event's payload, the union.
const PAYLOAD_SIZE: usize = DEBUG_EVENT_SIZE - DEBUG_EVENT_HEADER_SIZE;

/// `EXCEPTION_MAXIMUM_PARAMETERS` in `EXCEPTION_RECORD64`.
pub const EXCEPTION_MAXIMUM_PARAMETERS: usize = 15;

// `dwDebugEventCode` values.
pub const EXCEPTION_DEBUG_EVENT: u32 = 1;
pub const CREATE_THREAD_DEBUG_EVENT: u32 = 2;
pub const CREATE_PROCESS_DEBUG_EVENT: u32 = 3;
pub const EXIT_THREAD_DEBUG_EVENT: u32 = 4;
pub const EXIT_PROCESS_DEBUG_EVENT: u32 = 5;
pub const LOAD_DLL_DEBUG_EVENT: u32 = 6;
pub const UNLOAD_DLL_DEBUG_EVENT: u32 = 7;
pub const OUTPUT_DEBUG_STRING_EVENT: u32 = 8;
pub const RIP_EVENT: u32 = 9;

wire_struct! {
    /// The event's name: its code, the process, and the thread that reported
    /// it, before the union's alignment padding.
    pub struct DebugEventName {
        code: u32,
        process_id: u32,
        thread_id: u32,
        /// The hole before the eight-byte-aligned union.
        alignment: u32,
    } = DEBUG_EVENT_HEADER_SIZE
}

wire_struct! {
    /// `DEBUG_EVENT` itself: the name and the union's bytes, which the event
    /// code chooses a layout for.
    pub struct DebugEventRecord {
        name: DebugEventName,
        payload: [u8; PAYLOAD_SIZE],
    } = DEBUG_EVENT_SIZE
}

wire_struct! {
    /// `EXCEPTION_RECORD64` as the union holds it.
    pub struct ExceptionRecord64 {
        code: u32,
        flags: u32,
        /// The record this one is chained to.
        record: u64,
        address: u64,
        number_parameters: u32,
        /// The hole before the eight-byte-aligned parameter array.
        alignment: u32,
        parameters: [u64; EXCEPTION_MAXIMUM_PARAMETERS],
    } = 152
}

wire_struct! {
    /// `EXCEPTION_DEBUG_INFO`.
    pub struct ExceptionDebugInfo {
        record: ExceptionRecord64,
        first_chance: u32,
        /// The structure is padded to eight bytes.
        alignment: u32,
    } = 160
}

wire_struct! {
    /// `CREATE_THREAD_DEBUG_INFO`.
    pub struct CreateThreadDebugInfo {
        handle: u64,
        teb: u64,
        start_address: u64,
    } = 24
}

wire_struct! {
    /// `CREATE_PROCESS_DEBUG_INFO`. `hFile` is dropped for a remote debugger,
    /// which is why it is first and always null here.
    pub struct CreateProcessDebugInfo {
        file: u64,
        process_handle: u64,
        thread_handle: u64,
        image_base: u64,
        debug_info_offset: u32,
        debug_info_size: u32,
        teb: u64,
        start_address: u64,
        image_name: u64,
        image_name_wide: u16,
        alignment: [u8; 6],
    } = 72
}

wire_struct! {
    /// `EXIT_THREAD_DEBUG_INFO` and `EXIT_PROCESS_DEBUG_INFO`.
    pub struct ExitDebugInfo {
        exit_code: u32,
    } = 4
}

wire_struct! {
    /// `LOAD_DLL_DEBUG_INFO`, whose `hFile` is null for a remote debugger.
    pub struct LoadDllDebugInfo {
        file: u64,
        base: u64,
        debug_info_offset: u32,
        debug_info_size: u32,
        image_name: u64,
        image_name_wide: u16,
        alignment: [u8; 6],
    } = 40
}

wire_struct! {
    /// `UNLOAD_DLL_DEBUG_INFO`.
    pub struct UnloadDllDebugInfo {
        base: u64,
    } = 8
}

wire_struct! {
    /// `OUTPUT_DEBUG_STRING_INFO`.
    pub struct OutputDebugStringInfo {
        address: u64,
        wide: u16,
        /// The string's length in characters, without its terminator.
        length: u16,
        alignment: u32,
    } = 16
}

wire_struct! {
    /// `RIP_INFO`.
    pub struct RipInfo {
        error: u32,
        kind: u32,
    } = 8
}

/// One decoded `DEBUG_EVENT`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DebugEvent {
    Exception {
        process_id: u32,
        thread_id: u32,
        record: ExceptionRecord,
        first_chance: bool,
    },
    /// The new thread's handle, its TEB, and the address it starts at.
    CreateThread {
        process_id: u32,
        thread_id: u32,
        handle: u64,
        teb: u64,
        start_address: u64,
    },
    /// The created process: its image, the handles a remote debugger is
    /// given for it and its first thread, and where its name is.
    CreateProcess {
        process_id: u32,
        thread_id: u32,
        process_handle: u64,
        thread_handle: u64,
        image_base: u64,
        teb: u64,
        image_name: u64,
        image_name_wide: bool,
    },
    ExitThread {
        process_id: u32,
        thread_id: u32,
        exit_code: u32,
    },
    ExitProcess {
        process_id: u32,
        thread_id: u32,
        exit_code: u32,
    },
    LoadDll {
        process_id: u32,
        thread_id: u32,
        base: u64,
        debug_info_offset: u32,
        debug_info_size: u32,
        image_name: u64,
        image_name_wide: bool,
    },
    UnloadDll {
        process_id: u32,
        thread_id: u32,
        base: u64,
    },
    OutputDebugString {
        process_id: u32,
        thread_id: u32,
        address: u64,
        wide: bool,
        length: u16,
    },
    /// `RIP_INFO`: the process died and the server could not report its exit.
    Rip {
        process_id: u32,
        thread_id: u32,
        error: u32,
        kind: u32,
    },
}

impl DebugEvent {
    pub fn process_id(&self) -> u32 {
        match self {
            Self::Exception { process_id, .. }
            | Self::CreateThread { process_id, .. }
            | Self::CreateProcess { process_id, .. }
            | Self::ExitThread { process_id, .. }
            | Self::ExitProcess { process_id, .. }
            | Self::LoadDll { process_id, .. }
            | Self::UnloadDll { process_id, .. }
            | Self::OutputDebugString { process_id, .. }
            | Self::Rip { process_id, .. } => *process_id,
        }
    }
}

/// Decode the `DEBUG_EVENT` bytes `WaitForEvent` returned. Trailing bytes
/// past the event are ignored: `WaitForEvent` reports the buffer's size, not
/// the event's.
pub fn decode(bytes: &[u8]) -> Result<DebugEvent> {
    let event =
        DebugEventRecord::read_from_bytes(bytes.get(..DEBUG_EVENT_SIZE).ok_or_else(|| {
            Error::Dbgsrv(format!(
                "the server returned {} bytes of a debug event, {DEBUG_EVENT_SIZE} expected",
                bytes.len()
            ))
        })?)
        .map_err(|_| Error::Dbgsrv("the debug event does not decode".to_string()))?;
    let payload = &event.payload;
    let (process_id, thread_id) = (event.name.process_id, event.name.thread_id);
    Ok(match event.name.code {
        EXCEPTION_DEBUG_EVENT => {
            let info = read::<ExceptionDebugInfo>(payload, "exception record")?;
            let count = (info.record.number_parameters as usize).min(EXCEPTION_MAXIMUM_PARAMETERS);
            DebugEvent::Exception {
                process_id,
                thread_id,
                record: ExceptionRecord {
                    code: info.record.code,
                    flags: info.record.flags,
                    record: info.record.record,
                    address: info.record.address,
                    parameters: info.record.parameters[..count].to_vec(),
                },
                first_chance: info.first_chance != 0,
            }
        }
        CREATE_THREAD_DEBUG_EVENT => {
            let info = read::<CreateThreadDebugInfo>(payload, "create-thread record")?;
            DebugEvent::CreateThread {
                process_id,
                thread_id,
                handle: info.handle,
                teb: info.teb,
                start_address: info.start_address,
            }
        }
        CREATE_PROCESS_DEBUG_EVENT => {
            let info = read::<CreateProcessDebugInfo>(payload, "create-process record")?;
            DebugEvent::CreateProcess {
                process_id,
                thread_id,
                process_handle: info.process_handle,
                thread_handle: info.thread_handle,
                image_base: info.image_base,
                teb: info.teb,
                image_name: info.image_name,
                image_name_wide: info.image_name_wide != 0,
            }
        }
        EXIT_THREAD_DEBUG_EVENT => DebugEvent::ExitThread {
            process_id,
            thread_id,
            exit_code: read::<ExitDebugInfo>(payload, "exit-thread record")?.exit_code,
        },
        EXIT_PROCESS_DEBUG_EVENT => DebugEvent::ExitProcess {
            process_id,
            thread_id,
            exit_code: read::<ExitDebugInfo>(payload, "exit-process record")?.exit_code,
        },
        LOAD_DLL_DEBUG_EVENT => {
            let info = read::<LoadDllDebugInfo>(payload, "load-dll record")?;
            DebugEvent::LoadDll {
                process_id,
                thread_id,
                base: info.base,
                debug_info_offset: info.debug_info_offset,
                debug_info_size: info.debug_info_size,
                image_name: info.image_name,
                image_name_wide: info.image_name_wide != 0,
            }
        }
        UNLOAD_DLL_DEBUG_EVENT => DebugEvent::UnloadDll {
            process_id,
            thread_id,
            base: read::<UnloadDllDebugInfo>(payload, "unload-dll record")?.base,
        },
        OUTPUT_DEBUG_STRING_EVENT => {
            let info = read::<OutputDebugStringInfo>(payload, "debug-string record")?;
            DebugEvent::OutputDebugString {
                process_id,
                thread_id,
                address: info.address,
                wide: info.wide != 0,
                length: info.length,
            }
        }
        RIP_EVENT => {
            let info = read::<RipInfo>(payload, "rip record")?;
            DebugEvent::Rip {
                process_id,
                thread_id,
                error: info.error,
                kind: info.kind,
            }
        }
        other => {
            return Err(Error::Dbgsrv(format!("unknown debug event code {other}")));
        }
    })
}

/// Read the union member `T` out of an event's payload.
fn read<T: FromBytes + KnownLayout + IntoBytes>(payload: &[u8], what: &'static str) -> Result<T> {
    let bytes = payload
        .get(..core::mem::size_of::<T>())
        .ok_or_else(|| Error::Dbgsrv(format!("the debug event holds no {what}")))?;
    T::read_from_bytes(bytes)
        .map_err(|_| Error::Dbgsrv(format!("the debug event's {what} does not decode")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::ntstatus::STATUS_BREAKPOINT;

    fn event(code: u32, process: u32, thread: u32) -> [u8; DEBUG_EVENT_SIZE] {
        let name = DebugEventName {
            code,
            process_id: process,
            thread_id: thread,
            alignment: 0,
        };
        let mut bytes = [0u8; DEBUG_EVENT_SIZE];
        bytes[..DEBUG_EVENT_HEADER_SIZE].copy_from_slice(name.as_bytes());
        bytes
    }

    #[test]
    fn an_exception_event_carries_its_record_and_first_chance() {
        let mut bytes = event(EXCEPTION_DEBUG_EVENT, 0x1234, 0x5678);
        let mut parameters = [0u64; EXCEPTION_MAXIMUM_PARAMETERS];
        parameters[0] = 7;
        parameters[1] = 9;
        let info = ExceptionDebugInfo {
            record: ExceptionRecord64 {
                code: STATUS_BREAKPOINT,
                flags: 1,
                record: 0,
                address: 0x7ff6_1234_5678,
                number_parameters: 2,
                alignment: 0,
                parameters,
            },
            first_chance: 1,
            alignment: 0,
        };
        bytes[DEBUG_EVENT_HEADER_SIZE..].copy_from_slice(info.as_bytes());
        assert_eq!(
            decode(&bytes).unwrap(),
            DebugEvent::Exception {
                process_id: 0x1234,
                thread_id: 0x5678,
                record: ExceptionRecord {
                    code: STATUS_BREAKPOINT,
                    flags: 1,
                    record: 0,
                    address: 0x7ff6_1234_5678,
                    parameters: vec![7, 9],
                },
                first_chance: true,
            }
        );
    }

    #[test]
    fn a_load_dll_event_names_the_image_and_where_its_debug_directory_is() {
        let mut bytes = event(LOAD_DLL_DEBUG_EVENT, 1, 2);
        let info = LoadDllDebugInfo {
            file: 0,
            base: 0x1000_0000,
            debug_info_offset: 0x200,
            debug_info_size: 0x1c,
            image_name: 0x3000,
            image_name_wide: 1,
            alignment: [0; 6],
        };
        bytes[DEBUG_EVENT_HEADER_SIZE
            ..DEBUG_EVENT_HEADER_SIZE + core::mem::size_of::<LoadDllDebugInfo>()]
            .copy_from_slice(info.as_bytes());
        assert_eq!(
            decode(&bytes).unwrap(),
            DebugEvent::LoadDll {
                process_id: 1,
                thread_id: 2,
                base: 0x1000_0000,
                debug_info_offset: 0x200,
                debug_info_size: 0x1c,
                image_name: 0x3000,
                image_name_wide: true,
            }
        );
    }

    #[test]
    fn a_short_event_is_an_error_rather_than_a_panic() {
        assert!(decode(&[1, 0, 0, 0]).is_err());
        assert!(decode(&event(RIP_EVENT, 1, 1)[..DEBUG_EVENT_HEADER_SIZE]).is_err());
    }

    #[test]
    fn an_unknown_event_code_is_refused() {
        assert!(decode(&event(0x1234, 1, 1)).is_err());
    }
}
