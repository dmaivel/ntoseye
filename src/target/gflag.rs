//! Global flags (`!gflag`): `nt!NtGlobalFlag` and the current process's
//! `_PEB.NtGlobalFlag`, decoded by the GFlags table's names.

use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::guest::ProcessInfo;
use crate::target::{DiagnosticValue, Target};
use crate::types::VirtAddr;

/// One global flag: its bit, GFlags abbreviation, and description.
#[derive(Debug, Clone, Copy)]
pub struct GlobalFlag {
    pub bit: u32,
    pub abbreviation: &'static str,
    pub description: &'static str,
}

const fn flag(bit: u32, abbreviation: &'static str, description: &'static str) -> GlobalFlag {
    GlobalFlag {
        bit,
        abbreviation,
        description,
    }
}

/// The GFlags flag table, in bit order; 0x200 has no abbreviation.
pub const GLOBAL_FLAGS: [GlobalFlag; 32] = [
    flag(0x0000_0001, "soe", "Stop on exception"),
    flag(0x0000_0002, "sls", "Show loader snaps"),
    flag(0x0000_0004, "dic", "Debug initial command"),
    flag(0x0000_0008, "shg", "Stop on hung GUI"),
    flag(0x0000_0010, "htc", "Enable heap tail checking"),
    flag(0x0000_0020, "hfc", "Enable heap free checking"),
    flag(0x0000_0040, "hpc", "Enable heap parameter checking"),
    flag(0x0000_0080, "hvc", "Enable heap validation on call"),
    flag(0x0000_0100, "vrf", "Enable application verifier"),
    flag(0x0000_0200, "", "Enable silent process exit monitoring"),
    flag(0x0000_0400, "ptg", "Enable pool tagging"),
    flag(0x0000_0800, "htg", "Enable heap tagging"),
    flag(0x0000_1000, "ust", "Create user mode stack trace database"),
    flag(
        0x0000_2000,
        "kst",
        "Create kernel mode stack trace database",
    ),
    flag(
        0x0000_4000,
        "otl",
        "Maintain a list of objects for each type",
    ),
    flag(0x0000_8000, "htd", "Enable heap tagging by DLL"),
    flag(0x0001_0000, "dse", "Disable stack extension"),
    flag(0x0002_0000, "d32", "Enable debugging of Win32 subsystem"),
    flag(
        0x0004_0000,
        "ksl",
        "Enable loading of kernel debugger symbols",
    ),
    flag(0x0008_0000, "dps", "Disable paging of kernel stacks"),
    flag(0x0010_0000, "scb", "Enable system critical breaks"),
    flag(0x0020_0000, "dhc", "Disable heap coalesce on free"),
    flag(0x0040_0000, "ece", "Enable close exception"),
    flag(0x0080_0000, "eel", "Enable exception logging"),
    flag(0x0100_0000, "eot", "Enable object handle type tagging"),
    flag(0x0200_0000, "hpa", "Enable page heap"),
    flag(0x0400_0000, "dwl", "Debug WinLogon"),
    flag(0x0800_0000, "ddp", "Buffer DbgPrint output"),
    flag(0x1000_0000, "cse", "Early critical section event creation"),
    flag(0x2000_0000, "sue", "Stop on unhandled user-mode exception"),
    flag(0x4000_0000, "bhd", "Enable bad handles detection"),
    flag(0x8000_0000, "dpd", "Disable protected DLL verification"),
];

/// The flags set in `value`, in bit order.
pub fn global_flags_set(value: u32) -> impl Iterator<Item = &'static GlobalFlag> {
    GLOBAL_FLAGS
        .iter()
        .filter(move |flag| value & flag.bit != 0)
}

/// A `!gflag` change to `NtGlobalFlag`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlobalFlagChange {
    /// `+value` or `+abbreviation`.
    Set(u32),
    /// `-value` or `-abbreviation`.
    Clear(u32),
    /// A bare value replaces the whole word.
    Replace(u32),
}

impl GlobalFlagChange {
    /// Parse `!gflag`'s argument: `+`/`-` then a GFlags abbreviation or a
    /// value, or a bare value; `eval` evaluates a value.
    pub fn parse(text: &str, eval: impl Fn(&str) -> Result<u64>) -> Result<Self> {
        let value = |text: &str| -> Result<u32> {
            let value = eval(text)?;
            u32::try_from(value).map_err(|_| {
                Error::InvalidArgument(format!(
                    "global flag value {value:#x} is wider than 32 bits"
                ))
            })
        };
        let bits = |text: &str| match GLOBAL_FLAGS.iter().find(|flag| {
            !flag.abbreviation.is_empty() && flag.abbreviation.eq_ignore_ascii_case(text)
        }) {
            Some(flag) => Ok(flag.bit),
            None => value(text).map_err(|error| {
                Error::InvalidArgument(format!(
                    "'{text}' is neither a global flag abbreviation (!gflag -? lists them) nor a \
                     value: {error}"
                ))
            }),
        };
        if let Some(rest) = text.strip_prefix('+') {
            Ok(Self::Set(bits(rest)?))
        } else if let Some(rest) = text.strip_prefix('-') {
            Ok(Self::Clear(bits(rest)?))
        } else {
            Ok(Self::Replace(value(text)?))
        }
    }

    pub fn apply(self, current: u32) -> u32 {
        match self {
            Self::Set(bits) => current | bits,
            Self::Clear(bits) => current & !bits,
            Self::Replace(value) => value,
        }
    }
}

/// `nt!NtGlobalFlag` and the current process's `_PEB.NtGlobalFlag`.
#[derive(Debug, Clone)]
pub struct GlobalFlagsDetail {
    pub kernel_address: VirtAddr,
    pub kernel: u32,
    /// The current process, when there is one.
    pub process: Option<ProcessInfo>,
    /// Its PEB's flags; unavailable for a process without a PEB (System) or
    /// with its PEB paged out.
    pub process_flags: DiagnosticValue<u32>,
}

impl Target {
    fn nt_global_flag_address(&self) -> Result<VirtAddr> {
        Ok(self.guest()?.ntoskrnl.symbol("NtGlobalFlag")?.address())
    }

    /// Read `nt!NtGlobalFlag` and the current process's PEB copy.
    pub fn global_flags(&self) -> Result<GlobalFlagsDetail> {
        let guest = self.guest()?;
        let kernel_address = self.nt_global_flag_address()?;
        let kernel: u32 = guest.ntoskrnl.memory().read(kernel_address)?;
        let process = self.selected_process_info().ok();
        let process_flags = match &process {
            None => DiagnosticValue::Unavailable("no current process".to_string()),
            Some(process) => DiagnosticValue::from_result((|| {
                let types = guest.ntoskrnl.types_in(process.dtb);
                let peb = types
                    .struct_at("_EPROCESS", process.eprocess_va)?
                    .read_pointer("Peb")?;
                if peb.is_zero() {
                    return Err(Error::DebugInfo(format!("{} has no PEB", process.name)));
                }
                types
                    .struct_at("_PEB", peb)?
                    .read_field::<u32>("NtGlobalFlag")
            })()),
        };
        Ok(GlobalFlagsDetail {
            kernel_address,
            kernel,
            process,
            process_flags,
        })
    }

    /// Apply `change` to `nt!NtGlobalFlag` with one 4-byte write, as `ed`
    /// would; returns the old and new values.
    pub fn change_global_flag(&self, change: GlobalFlagChange) -> Result<(u32, u32)> {
        let address = self.nt_global_flag_address()?;
        let old: u32 = self.guest()?.ntoskrnl.memory().read(address)?;
        let new = change.apply(old);
        if new != old {
            self.context_memory()
                .write_bytes(address, &new.to_le_bytes())?;
        }
        Ok((old, new))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eval(text: &str) -> Result<u64> {
        u64::from_str_radix(text.trim_start_matches("0x"), 16)
            .map_err(|_| Error::InvalidArgument(text.to_string()))
    }

    #[test]
    fn abbreviations_and_values_parse_to_the_same_change() {
        assert_eq!(
            GlobalFlagChange::parse("+HPA", eval).unwrap(),
            GlobalFlagChange::Set(0x0200_0000)
        );
        assert_eq!(
            GlobalFlagChange::parse("-2000000", eval).unwrap(),
            GlobalFlagChange::Clear(0x0200_0000)
        );
        // A bare word is a value, never an abbreviation: `ust` is not hex.
        assert!(GlobalFlagChange::parse("ust", eval).is_err());
        assert_eq!(
            GlobalFlagChange::parse("400", eval).unwrap(),
            GlobalFlagChange::Replace(0x400)
        );
        assert!(GlobalFlagChange::parse("+100000000", eval).is_err());
        // An abbreviation wins over the hex value it also spells.
        assert_eq!(
            GlobalFlagChange::parse("+ece", eval).unwrap(),
            GlobalFlagChange::Set(0x0040_0000)
        );
    }
}
