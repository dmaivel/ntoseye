//! A process's critical sections (`!cs`): the `RTL_CRITICAL_SECTION`s ntdll
//! keeps on `RtlCriticalSectionList`, through each one's debug record, with
//! whether it is held, by which thread, and how many threads wait for it. A
//! section initialized without a debug record (`DebugInfo` -1, as
//! `ntdll!FastPebLock` is) is on no list; only its address finds it.

use ntoseye_macros::record;

use super::{UserModeTypes, current_process};
use crate::base::error::{Error, Result};
use crate::base::types::{Dtb, VirtAddr};
use crate::nt::target::list::bounded_record_list_walk;
use crate::nt::target::{DiagnosticValue, ListTermination, Target, TargetKind};

/// The most critical sections `!cs` walks: a guard against a corrupt list.
const MAX_CRITICAL_SECTIONS: usize = 1 << 16;

/// An `RTL_CRITICAL_SECTION` (`!cs <address>`).
#[record(impl)]
#[derive(Debug, Clone)]
pub struct CriticalSection {
    pub address: VirtAddr,
    /// The symbol at its address (`ntdll!LdrpLoaderLock`), when it is a
    /// global.
    pub symbol: Option<String>,
    pub debug_info: DiagnosticValue<VirtAddr>,
    /// `LockCount`: from Windows Server 2003 SP1, bit 0 is clear while the
    /// section is held, bit 1 clear when a waiter was woken, and the bits
    /// above count the waiters, inverted.
    pub lock_count: DiagnosticValue<i32>,
    pub recursion_count: DiagnosticValue<i32>,
    /// The thread that holds it, by its TID (`OwningThread`).
    pub owning_thread: DiagnosticValue<u64>,
    pub lock_semaphore: DiagnosticValue<VirtAddr>,
    pub spin_count: DiagnosticValue<u64>,
    /// How many times threads waited for it (the debug record's
    /// `ContentionCount`).
    pub contention_count: DiagnosticValue<u32>,
}

#[record]
impl CriticalSection {
    /// Whether a thread holds it.
    #[record(getter)]
    pub fn locked(&self) -> Option<bool> {
        match self.lock_count {
            DiagnosticValue::Available(count) => Some(count & 1 == 0),
            DiagnosticValue::Unavailable(_) => None,
        }
    }

    /// How many threads wait for it.
    #[record(getter)]
    pub fn waiters(&self) -> Option<u32> {
        match self.lock_count {
            DiagnosticValue::Available(count) => Some(((-1i64 - i64::from(count)) >> 2) as u32),
            DiagnosticValue::Unavailable(_) => None,
        }
    }
}

/// A process's critical sections, from `ntdll!RtlCriticalSectionList`
/// (`!cs`).
#[record]
pub struct CriticalSections {
    pub list_head: VirtAddr,
    pub sections: Vec<CriticalSection>,
    pub termination: ListTermination,
}

impl Target {
    /// The root and layouts of the current process: the one .process
    /// selected, else the owner of the current thread; a user-mode
    /// minidump's one process.
    fn critical_section_view(&self) -> Result<(Dtb, UserModeTypes<'_>)> {
        let dtb = match self.kind() {
            TargetKind::Kernel => current_process(self)?.dtb,
            TargetKind::UserDump => self.current_dtb(),
        };
        Ok((dtb, self.user_mode_types(dtb)?))
    }

    /// The critical sections of the current process, as ntdll lists them.
    pub fn critical_sections(&self) -> Result<CriticalSections> {
        let (dtb, types) = self.critical_section_view()?;
        let head = self
            .symbols
            .find_symbol_across_modules(dtb, "ntdll!RtlCriticalSectionList")?
            .ok_or_else(|| {
                Error::DebugInfo(
                    "ntdll!RtlCriticalSectionList is not known: ntdll's symbols are not loaded \
                     for this process"
                        .into(),
                )
            })?;
        let debug_layout = types
            .types
            .layout(types.qualified("_RTL_CRITICAL_SECTION_DEBUG"))?;
        let link_offset = debug_layout.field_offset("ProcessLocksList")?;
        let memory = self.address_space(dtb);
        let (records, termination) =
            bounded_record_list_walk(head, link_offset, MAX_CRITICAL_SECTIONS, |link| {
                memory.read_pointer(link)
            });
        let sections = records
            .into_iter()
            .filter_map(|debug| {
                let section = types
                    .struct_at("_RTL_CRITICAL_SECTION_DEBUG", debug)
                    .and_then(|record| record.read_pointer("CriticalSection"))
                    .ok()
                    .filter(|section| !section.is_zero())?;
                Some(self.read_critical_section(dtb, types, section))
            })
            .collect();
        Ok(CriticalSections {
            list_head: head,
            sections,
            termination,
        })
    }

    /// The critical section at `address` in the current process.
    pub fn critical_section(&self, address: VirtAddr) -> Result<CriticalSection> {
        let (dtb, types) = self.critical_section_view()?;
        types.struct_at("_RTL_CRITICAL_SECTION", address)?;
        Ok(self.read_critical_section(dtb, types, address))
    }

    fn read_critical_section(
        &self,
        dtb: Dtb,
        types: UserModeTypes<'_>,
        address: VirtAddr,
    ) -> CriticalSection {
        let symbol = self
            .symbols
            .find_closest_symbol_for_address(dtb, address)
            .filter(|(_, _, offset)| *offset == 0)
            .map(|(module, name, _)| format!("{module}!{name}"));
        let section = match types.struct_at("_RTL_CRITICAL_SECTION", address) {
            Ok(section) => section,
            Err(error) => {
                let error = error.to_string();
                return CriticalSection {
                    address,
                    symbol,
                    debug_info: DiagnosticValue::unavailable(&error),
                    lock_count: DiagnosticValue::unavailable(&error),
                    recursion_count: DiagnosticValue::unavailable(&error),
                    owning_thread: DiagnosticValue::unavailable(&error),
                    lock_semaphore: DiagnosticValue::unavailable(&error),
                    spin_count: DiagnosticValue::unavailable(&error),
                    contention_count: DiagnosticValue::unavailable(&error),
                };
            }
        };
        let field = |name: &str| section.read_uint(name);
        let debug_info = section.read_pointer("DebugInfo");
        // A section initialized without debug information
        // (RTL_CRITICAL_SECTION_FLAG_NO_DEBUG_INFO) has -1 there, and is on
        // no list.
        let contention_count = match &debug_info {
            Ok(debug) if !debug.is_zero() && debug.0 != u64::MAX => types
                .struct_at("_RTL_CRITICAL_SECTION_DEBUG", *debug)
                .and_then(|record| record.read_uint("ContentionCount"))
                .map(|count| count as u32),
            Ok(_) => Err(Error::DebugInfo("the section has no debug record".into())),
            Err(error) => Err(Error::DebugInfo(error.to_string())),
        };
        CriticalSection {
            address,
            symbol,
            debug_info: DiagnosticValue::from_result(debug_info),
            lock_count: DiagnosticValue::from_result(field("LockCount").map(|v| v as u32 as i32)),
            recursion_count: DiagnosticValue::from_result(
                field("RecursionCount").map(|v| v as u32 as i32),
            ),
            owning_thread: DiagnosticValue::from_result(field("OwningThread")),
            lock_semaphore: DiagnosticValue::from_result(field("LockSemaphore").map(VirtAddr)),
            spin_count: DiagnosticValue::from_result(field("SpinCount")),
            contention_count: DiagnosticValue::from_result(contention_count),
        }
    }
}
