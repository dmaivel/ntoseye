//! Names of the hypercalls the Hyper-V TLFS documents, by call code, with
//! whether each is a rep call. From the TLFS hypercall reference and its
//! page for each hypercall, and HvCallGetPartitionId (0x0046), which the
//! current pages name without a code, from TLFS 6.0b.

use super::hv_layout::HypercallEntry;
use super::hypercall_input::{DecodedHypercall, HypercallControl};

/// `(code, name, rep)`, in code order.
pub const TLFS_HYPERCALLS: &[(u16, &str, bool)] = &[
    (0x0001, "HvCallSwitchVirtualAddressSpace", false),
    (0x0002, "HvCallFlushVirtualAddressSpace", false),
    (0x0003, "HvCallFlushVirtualAddressList", true),
    (0x0008, "HvCallNotifyLongSpinWait", false),
    (0x000b, "HvCallSendSyntheticClusterIpi", false),
    (0x000c, "HvCallModifyVtlProtectionMask", true),
    (0x000d, "HvCallEnablePartitionVtl", false),
    (0x000f, "HvCallEnableVpVtl", false),
    (0x0011, "HvCallVtlCall", false),
    (0x0012, "HvCallVtlReturn", false),
    (0x0013, "HvCallFlushVirtualAddressSpaceEx", false),
    (0x0014, "HvCallFlushVirtualAddressListEx", true),
    (0x0015, "HvCallSendSyntheticClusterIpiEx", false),
    (0x0040, "HvCallCreatePartition", false),
    (0x0041, "HvCallInitializePartition", false),
    (0x0042, "HvCallFinalizePartition", false),
    (0x0043, "HvCallDeletePartition", false),
    (0x0044, "HvCallGetPartitionProperty", false),
    (0x0045, "HvCallSetPartitionProperty", false),
    (0x0046, "HvCallGetPartitionId", false),
    (0x0047, "HvCallGetNextChildPartition", false),
    (0x0048, "HvCallDepositMemory", true),
    (0x0049, "HvCallWithdrawMemory", true),
    (0x004a, "HvCallGetMemoryBalance", false),
    (0x004b, "HvCallMapGpaPages", true),
    (0x004c, "HvCallUnmapGpaPages", true),
    (0x004d, "HvCallInstallIntercept", false),
    (0x004e, "HvCallCreateVp", false),
    (0x004f, "HvCallDeleteVp", false),
    (0x0050, "HvCallGetVpRegisters", true),
    (0x0051, "HvCallSetVpRegisters", true),
    (0x0052, "HvCallTranslateVirtualAddress", false),
    (0x0058, "HvCallDeletePort", false),
    (0x005b, "HvCallDisconnectPort", false),
    (0x005c, "HvCallPostMessage", false),
    (0x005d, "HvCallSignalEvent", false),
    (0x006d, "HvCallUnmapStatsPage", false),
    (0x006e, "HvCallMapSparseGpaPages", true),
    (0x007e, "HvCallRetargetDeviceInterrupt", false),
    (0x0090, "HvCallModifySparseGpaPages", true),
    (0x0091, "HvCallRegisterInterceptResult", false),
    (0x0092, "HvCallUnregisterInterceptResult", false),
    (0x0094, "HvCallAssertVirtualInterrupt", false),
    (0x0095, "HvCallCreatePort", false),
    (0x0096, "HvCallConnectPort", false),
    (0x0099, "HvCallStartVirtualProcessor", false),
    (0x009a, "HvCallGetVpIndexFromApicId", true),
    (0x00ac, "HvCallTranslateVirtualAddressEx", false),
    (0x00ad, "HvCallCheckForIoIntercept", false),
    (0x00af, "HvCallFlushGuestPhysicalAddressSpace", false),
    (0x00b0, "HvCallFlushGuestPhysicalAddressList", true),
    (0x00c0, "HvCallSignalEventDirect", false),
    (0x00c1, "HvCallPostMessageDirect", false),
    (0x00e1, "HvCallMapVpStatePage", false),
    (0x00e2, "HvCallUnmapVpStatePage", false),
    (0x00e5, "HvCallGetVpSetFromMda", false),
    (0x00f4, "HvCallGetVpCpuidValues", true),
    (0x010a, "HvCallSetPartitionPropertyEx", false),
    (0x0110, "HvCallInstallInterceptEx", true),
    (0x011f, "HvCallSetVirtualInterruptTarget", false),
    (0x0131, "HvCallMapStatsPage2", false),
    (0x8001, "HvExtCallQueryCapabilities", false),
    (0x8002, "HvExtCallGetBootZeroedMemory", false),
];

/// The TLFS name of hypercall `code`, and whether it is a rep call.
pub fn tlfs_hypercall(code: u16) -> Option<(&'static str, bool)> {
    TLFS_HYPERCALLS
        .binary_search_by_key(&code, |&(known, _, _)| known)
        .ok()
        .map(|index| (TLFS_HYPERCALLS[index].1, TLFS_HYPERCALLS[index].2))
}

/// The call code a name gives: the TLFS name (`HvCallPostMessage`) or the
/// name `x hv!*` gives a code the TLFS does not name (`HvCall0004`), with
/// or without `hv!`, in any case. `HvCallUnimplemented` names no single
/// code, so it gives none.
pub fn hypercall_code(name: &str) -> Option<u16> {
    let name = name.strip_prefix("hv!").unwrap_or(name);
    if let Some(&(code, _, _)) = TLFS_HYPERCALLS
        .iter()
        .find(|(_, known, _)| known.eq_ignore_ascii_case(name))
    {
        return Some(code);
    }
    let digits = name
        .get(..6)
        .filter(|prefix| prefix.eq_ignore_ascii_case("HvCall"))
        .and(name.get(6..))?;
    (digits.len() == 4 && digits.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| u16::from_str_radix(digits, 16).ok())
        .flatten()
}

/// The name ntoseye gives the handler of call code `code`: that of the
/// lowest code it serves (see [`hypervisor_symbols`]).
pub fn handler_name(table: &[HypercallEntry], code: u16) -> Option<String> {
    let handler = table.get(usize::from(code))?.handler;
    let lowest = table.iter().position(|entry| entry.handler == handler)?;
    Some(code_name(lowest))
}

/// The name of the handler whose lowest call code is `code`.
fn code_name(code: usize) -> String {
    match (code, tlfs_hypercall(code as u16)) {
        (0, _) => "HvCallUnimplemented".to_string(),
        (_, Some((name, _))) => name.to_string(),
        (_, None) => format!("HvCall{code:04X}"),
    }
}

/// The virtual processor whose exit a processor in the Windows hypervisor
/// handles, as a hypercall's caller: its partition, its index, the VTL it
/// runs in, and what its exit says of the call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HypercallCaller {
    pub partition: u64,
    /// The partition is the root partition.
    pub root: bool,
    pub vp: u32,
    pub vtl: u8,
    pub input: HypercallInput,
    /// Its registers at its VMCALL, as `.vtlcxr` selects a saved state's:
    /// RIP, RSP, flags, control and segment registers from its eVMCS, and
    /// the general-purpose registers when they are known. A hypercall
    /// breakpoint's condition sees these.
    pub registers: std::collections::HashMap<String, u64>,
}

impl HypercallCaller {
    /// `root partition VP 2 VTL0`, or `partition 0x4 VP 1 VTL0`.
    pub fn label(&self) -> String {
        if self.root {
            format!("root partition VP {} VTL{}", self.vp, self.vtl)
        } else {
            format!(
                "partition {:#x} VP {} VTL{}",
                self.partition, self.vp, self.vtl
            )
        }
    }
}

/// What a VP's current exit says of the hypercall the hypervisor handles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HypercallInput {
    /// A VMCALL whose registers are known: the call, with its input decoded.
    Known(Box<DecodedHypercall>),
    /// The exit is not a VMCALL, so the VP made no hypercall.
    NotHypercall,
    /// The exit's state or registers are not known, and why.
    Unknown(String),
}

impl HypercallInput {
    /// The call, when the exit is a VMCALL whose registers are known.
    pub fn call(&self) -> Option<&DecodedHypercall> {
        match self {
            Self::Known(call) => Some(call),
            Self::NotHypercall | Self::Unknown(_) => None,
        }
    }
}

/// A hypercall input value (the TLFS's, in RCX at a VMCALL), as
/// `hypercall 0x0003 HvCallFlushVirtualAddressList rep 0/12`: the call code
/// and its TLFS name, then `fast` (register input), a rep call's start index
/// and count, and `nested` (for the hypervisor a nested guest runs).
pub fn describe_hypercall_input(value: u64) -> String {
    let control = HypercallControl::new(value);
    let code = control.code;
    let mut text = match tlfs_hypercall(code) {
        Some((name, _)) => format!("hypercall {code:#06x} {name}"),
        None => format!("hypercall {code:#06x}"),
    };
    if control.fast {
        text.push_str(" fast");
    }
    if control.rep_count != 0 {
        text.push_str(&format!(" rep {}/{}", control.rep_start, control.rep_count));
    }
    if control.nested {
        text.push_str(" nested");
    }
    text
}

/// The names ntoseye gives the Windows hypervisor's code, and the length of
/// the function each begins, by RVA, where the image's `.pdata` gives it;
/// with where its functions begin and where its stacks start, which a walk
/// of its stacks needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HypervisorSymbols {
    pub names: Vec<(String, u32)>,
    pub extents: std::collections::HashMap<u32, u32>,
    /// The RVAs functions begin at, sorted: the image's `.pdata` when its
    /// file supplies it, direct call targets and code after padding (see
    /// [`crate::unwind::prolog::function_starts`]), the hypercall handlers,
    /// and the VM-exit entry points. The address space maps no `.pdata`, so
    /// without the file this is the only way to find a frame's function.
    pub starts: Vec<u32>,
    /// The VM-exit entry points (each eVMCS's host RIP), sorted, by RVA. The
    /// code at one runs on the bottom frame of a stack (host RSP is its base).
    pub exit_entries: Vec<u32>,
}

impl HypervisorSymbols {
    /// The function containing `rva`, as `start..end`: from the closest
    /// start at or below it to the next start (or the end of the address
    /// space when there is none). `None` below every start.
    pub fn function_at(&self, rva: u32) -> Option<std::ops::Range<u32>> {
        let next = self.starts.partition_point(|&start| start <= rva);
        let start = *self.starts.get(next.checked_sub(1)?)?;
        Some(start..self.starts.get(next).copied().unwrap_or(u32::MAX))
    }

    /// Whether `rva` is in the code of a VM-exit entry point, where a stack
    /// begins: no function starts between the entry and it. The entries lie
    /// inside larger `.pdata` functions, whose unwind data describes no
    /// caller, so the walk must stop at one rather than unwind it.
    pub fn in_exit_entry(&self, rva: u32) -> bool {
        self.function_at(rva)
            .is_some_and(|function| self.exit_entries.binary_search(&function.start).is_ok())
    }
}

/// The hypercall page's code sequences that ntoseye names: the hypercall
/// itself (`vmcall; ret`, which the TLFS puts at the page's start), and VTL
/// call (code 0x11) and VTL return (0x12) for x64 (input in RCX) and x86
/// callers (in EAX), which the TLFS places where `HvRegisterVsmCodeOffsets`
/// says, so they are found by their bytes.
const HYPERCALL_PAGE_SEQUENCES: [(&str, &[u8]); 5] = [
    ("Hypercall", &[0x0f, 0x01, 0xc1, 0xc3]),
    (
        "VtlCall64",
        &[
            0x48, 0x8b, 0xc1, 0x48, 0xc7, 0xc1, 0x11, 0, 0, 0, 0x0f, 0x01, 0xc1, 0xc3,
        ],
    ),
    (
        "VtlCall32",
        &[0x8b, 0xc8, 0xb8, 0x11, 0, 0, 0, 0x0f, 0x01, 0xc1, 0xc3],
    ),
    (
        "VtlReturn64",
        &[
            0x48, 0x8b, 0xc1, 0x48, 0xc7, 0xc1, 0x12, 0, 0, 0, 0x0f, 0x01, 0xc1, 0xc3,
        ],
    ),
    (
        "VtlReturn32",
        &[0x8b, 0xc8, 0xb8, 0x12, 0, 0, 0, 0x0f, 0x01, 0xc1, 0xc3],
    ),
];

/// Names for the code of a hypercall page, from its first bytes `code`, as
/// `(name, offset, length)`: none unless the page starts with the Intel
/// hypercall (`vmcall; ret`), so a pointer to anything else names nothing.
pub fn hypercall_page_symbols(code: &[u8]) -> Vec<(&'static str, u32, u32)> {
    let (_, hypercall) = HYPERCALL_PAGE_SEQUENCES[0];
    if !code.starts_with(hypercall) {
        return Vec::new();
    }
    let mut names = vec![("Hypercall", 0, hypercall.len() as u32)];
    for (name, bytes) in &HYPERCALL_PAGE_SEQUENCES[1..] {
        if let Some(offset) = code
            .windows(bytes.len())
            .position(|window| window == *bytes)
        {
            names.push((name, offset as u32, bytes.len() as u32));
        }
    }
    names.sort_by_key(|&(_, offset, _)| offset);
    names
}

/// Names for the Windows hypervisor's code, as `(name, rva)` in the image at
/// `base`: each hypercall handler by the lowest call code it serves (its TLFS
/// name, or `HvCall` and the code when the TLFS does not name it), the
/// handler of the reserved code 0 and of every unimplemented code
/// `HvCallUnimplemented`, and each VM-exit entry point in `exit_entries`
/// `VmExitEntry`, numbered after the first.
pub fn hypervisor_symbols(
    base: u64,
    table: &[HypercallEntry],
    exit_entries: &[u64],
) -> Vec<(String, u32)> {
    let rva = |address: u64| u32::try_from(address.checked_sub(base)?).ok();
    let mut named: Vec<(String, u32)> = Vec::new();
    let mut taken = std::collections::HashSet::new();
    for (code, entry) in table.iter().enumerate() {
        let Some(offset) = rva(entry.handler) else {
            continue;
        };
        if !taken.insert(offset) {
            continue;
        }
        named.push((code_name(code), offset));
    }
    let mut entries = 0;
    for entry in exit_entries {
        let Some(offset) = rva(*entry) else { continue };
        if taken.insert(offset) {
            entries += 1;
            let suffix = if entries == 1 {
                String::new()
            } else {
                entries.to_string()
            };
            named.push((format!("VmExitEntry{suffix}"), offset));
        }
    }
    named
}

/// The length of the function each of `names` begins, by RVA, from
/// `functions`, the image's `.pdata` (the length of each function by the RVA
/// it begins at). `.pdata` lists no leaf function, so a name it has no entry
/// for ends where the next function it lists begins; a name above every
/// listed function gets no length.
pub fn symbol_extents(
    names: &[(String, u32)],
    functions: &std::collections::HashMap<u32, u32>,
    image: &[u8],
) -> std::collections::HashMap<u32, u32> {
    let mut begins: Vec<u32> = functions.keys().copied().collect();
    begins.sort_unstable();
    names
        .iter()
        .filter_map(|&(_, rva)| {
            let length = match functions.get(&rva) {
                Some(&length) => length,
                None => {
                    let next = match begins.get(begins.partition_point(|&begin| begin <= rva)) {
                        Some(&next) => next,
                        None => u32::try_from(image.len()).ok()?,
                    };
                    let code = image.get(rva as usize..next as usize)?;
                    leaf_length(code, u64::from(rva)).unwrap_or(next - rva)
                }
            };
            Some((rva, length))
        })
        .collect()
}

/// The length of the leaf function (one with no `.pdata` entry) at the
/// start of `code`, mapped at `ip`: through the first instruction that ends
/// its control flow (`ret`, `jmp`, `int3`, `ud2`) past which no forward
/// conditional branch of it jumps. Leaves are packed 16 bytes apart with no
/// entry between them, so the next `.pdata` function can be several leaves
/// away. An unconditional `jmp` forward is taken as a tail call, so a leaf
/// laid out past one is cut short, which leaves the rest unnamed rather than
/// misnamed. `None` when the code does not decode to such an end.
fn leaf_length(code: &[u8], ip: u64) -> Option<u32> {
    use iced_x86::{Decoder, DecoderOptions, FlowControl};
    let mut decoder = Decoder::with_ip(64, code, ip, DecoderOptions::NONE);
    let mut furthest = ip;
    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            return None;
        }
        let end = instruction.next_ip();
        match instruction.flow_control() {
            FlowControl::ConditionalBranch => {
                furthest = furthest.max(instruction.near_branch_target());
            }
            FlowControl::Return
            | FlowControl::UnconditionalBranch
            | FlowControl::IndirectBranch
            | FlowControl::Interrupt
            | FlowControl::Exception
                if end > furthest =>
            {
                return u32::try_from(end - ip).ok();
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u64 = 0xffff_f840_b140_0000;

    /// The hypercall page as read live (Win11 26200): the hypercall at 0,
    /// then VTL call and return for x86 and x64 callers. A page that does
    /// not start with the hypercall names nothing, whatever follows.
    #[test]
    fn a_hypercall_page_is_named_by_its_code() {
        let mut page = vec![0x0f, 0x01, 0xc1, 0xc3];
        page.extend([0x8b, 0xc8, 0xb8, 0x11, 0, 0, 0, 0x0f, 0x01, 0xc1, 0xc3]);
        page.extend([
            0x48, 0x8b, 0xc1, 0x48, 0xc7, 0xc1, 0x11, 0, 0, 0, 0x0f, 0x01, 0xc1, 0xc3,
        ]);
        page.extend([0x8b, 0xc8, 0xb8, 0x12, 0, 0, 0, 0x0f, 0x01, 0xc1, 0xc3]);
        page.extend([
            0x48, 0x8b, 0xc1, 0x48, 0xc7, 0xc1, 0x12, 0, 0, 0, 0x0f, 0x01, 0xc1, 0xc3,
        ]);
        page.resize(0x40, 0xcc);
        assert_eq!(
            hypercall_page_symbols(&page),
            [
                ("Hypercall", 0, 4),
                ("VtlCall32", 0x4, 11),
                ("VtlCall64", 0xf, 14),
                ("VtlReturn32", 0x1d, 11),
                ("VtlReturn64", 0x28, 14),
            ]
        );
        page[2] = 0xd9;
        assert!(hypercall_page_symbols(&page).is_empty(), "AMD's vmmcall");
    }

    /// RCX at a VMCALL: the code by TLFS name, fast, a rep call's start
    /// index and count, nested. 0x1000b is NT's synthetic IPI, seen live.
    #[test]
    fn a_hypercall_input_names_its_call_and_its_flags() {
        assert_eq!(
            describe_hypercall_input(0x1_000b),
            "hypercall 0x000b HvCallSendSyntheticClusterIpi fast"
        );
        assert_eq!(
            describe_hypercall_input(0x0002_000c_0000_0003),
            "hypercall 0x0003 HvCallFlushVirtualAddressList rep 2/12"
        );
        assert_eq!(
            describe_hypercall_input(0x8000_00c2),
            "hypercall 0x00c2 nested"
        );
    }

    fn entry(rva: u64) -> HypercallEntry {
        HypercallEntry {
            handler: BASE + rva,
            flags: 0,
            input: 0,
            input_element: 0,
            output: 0,
            output_element: 0,
        }
    }

    #[test]
    fn handlers_take_the_name_of_the_first_code_they_serve() {
        // Code 0 and the unimplemented 0x0004 share a handler; 0x0046 and
        // 0x0047 share another, named for the lower code.
        let mut table = vec![entry(0x100); 0x48];
        table[0x0001] = entry(0x200);
        table[0x0005] = entry(0x300);
        table[0x0046] = entry(0x400);
        table[0x0047] = entry(0x400);
        let names = hypervisor_symbols(BASE, &table, &[BASE + 0x500, BASE + 0x100, BASE + 0x600]);
        assert_eq!(
            names,
            [
                ("HvCallUnimplemented".to_string(), 0x100),
                ("HvCallSwitchVirtualAddressSpace".to_string(), 0x200),
                ("HvCall0005".to_string(), 0x300),
                ("HvCallGetPartitionId".to_string(), 0x400),
                ("VmExitEntry".to_string(), 0x500),
                ("VmExitEntry2".to_string(), 0x600),
            ]
        );
    }

    /// A name gives the code `x hv!*` names it for, so a code the TLFS does
    /// not name is reached as `x` shows it; the handler many codes share
    /// names none of them.
    #[test]
    fn a_hypercall_name_gives_its_call_code() {
        assert_eq!(
            hypercall_code("HvCallSendSyntheticClusterIpi"),
            Some(0x000b)
        );
        assert_eq!(hypercall_code("hv!hvcallpostmessage"), Some(0x005c));
        assert_eq!(hypercall_code("HvCall0004"), Some(0x0004));
        assert_eq!(hypercall_code("hv!HvCall000b"), Some(0x000b));
        assert_eq!(hypercall_code("HvCallUnimplemented"), None);
        assert_eq!(hypercall_code("HvCall99"), None);
        assert_eq!(hypercall_code("nt!NtClose"), None);
    }

    #[test]
    fn a_code_s_handler_is_named_for_the_lowest_code_it_serves() {
        let mut table = vec![entry(0x100); 0x48];
        table[0x0046] = entry(0x400);
        table[0x0047] = entry(0x400);
        assert_eq!(
            handler_name(&table, 0x47).as_deref(),
            Some("HvCallGetPartitionId")
        );
        assert_eq!(
            handler_name(&table, 0x30).as_deref(),
            Some("HvCallUnimplemented")
        );
        assert_eq!(handler_name(&table, 0x48), None);
    }

    #[test]
    fn a_leaf_function_ends_with_its_own_code() {
        // 0x100, 0x300 and 0x420 are in `.pdata`. The leaf at 0x200 returns
        // at once and another leaf follows it at 0x210, before 0x300; the
        // one at 0x400 branches over its first return to a second.
        let functions =
            std::collections::HashMap::from([(0x100, 0x40), (0x300, 0x80), (0x420, 0x60)]);
        let mut image = vec![0xccu8; 0x600];
        image[0x200..0x206].copy_from_slice(&[0xb8, 2, 0, 0, 0, 0xc3]);
        image[0x210..0x213].copy_from_slice(&[0x33, 0xc0, 0xc3]);
        image[0x400..0x40d].copy_from_slice(&[
            0x85, 0xc9, 0x74, 0x03, 0x33, 0xc0, 0xc3, 0xb8, 1, 0, 0, 0, 0xc3,
        ]);
        let names = [
            ("HvCallSwitchVirtualAddressSpace".to_string(), 0x100),
            ("HvCallUnimplemented".to_string(), 0x200),
            ("HvCallGetPartitionId".to_string(), 0x400),
        ];
        assert_eq!(
            symbol_extents(&names, &functions, &image),
            std::collections::HashMap::from([(0x100, 0x40), (0x200, 6), (0x400, 0xd)])
        );
    }
}
