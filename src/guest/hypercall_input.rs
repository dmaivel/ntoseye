//! The input of a hypercall, decoded field by field as the Hyper-V TLFS lays
//! it out, for a VP that exited to the hypervisor on a VMCALL. RCX holds the
//! hypercall input value; RDX and R8 hold the GPAs of the input and output
//! parameters, or, for a fast call, the first 16 bytes of the input, whose
//! rest an XMM fast call passes in XMM0 to XMM5 (TLFS "Hypercall Interface":
//! Hypercall Inputs, Hypercall Register Conventions (x86/x64), XMM Fast
//! Hypercall Input).
//!
//! The layouts are those of the TLFS page of each call
//! (<https://learn.microsoft.com/virtualization/hyper-v-on-windows/tlfs/hypercalls/overview>)
//! and of Linux's `include/asm-generic/hyperv-tlfs.h`, which Linux 6.14
//! replaced with `include/hyperv/hvgdk_mini.h` and `hvhdk_mini.h`. Where
//! the two disagree, the one that the hypervisor's own hypercall table
//! agrees with is used: [`LAYOUTS`] holds the sizes that table gives, which
//! the real-build test in `hv_layout` checks.

use std::collections::HashMap;

use super::hypercalls::{describe_hypercall_input, tlfs_hypercall};

/// The bytes of a page, which an input in memory cannot cross (TLFS
/// "Alignment Requirements").
const PAGE_BYTES: usize = 0x1000;

/// How many qwords of input a call whose layout ntoseye does not know
/// shows, when the input is in memory: the TLFS gives no size for it.
pub const RAW_QWORDS: usize = 8;

/// `(code, fixed input bytes, rep element bytes)` of each call whose input
/// ntoseye decodes, in code order: the sizes that hvix64's hypercall table
/// gives. A variable header (the `...Ex` calls' processor sets) follows the
/// fixed input, and the rep list follows that.
pub const LAYOUTS: &[(u16, u16, u16)] = &[
    (FLUSH_VIRTUAL_ADDRESS_SPACE, 0x18, 0),
    (FLUSH_VIRTUAL_ADDRESS_LIST, 0x18, 8),
    (NOTIFY_LONG_SPIN_WAIT, 8, 0),
    (SEND_SYNTHETIC_CLUSTER_IPI, 0x10, 0),
    (MODIFY_VTL_PROTECTION_MASK, 0x10, 8),
    (ENABLE_PARTITION_VTL, 0x10, 0),
    (ENABLE_VP_VTL, 0xf0, 0),
    (VTL_CALL, 0, 0),
    (VTL_RETURN, 0, 0),
    (FLUSH_VIRTUAL_ADDRESS_SPACE_EX, 0x20, 0),
    (FLUSH_VIRTUAL_ADDRESS_LIST_EX, 0x20, 8),
    (SEND_SYNTHETIC_CLUSTER_IPI_EX, 0x18, 0),
    (GET_VP_REGISTERS, 0x10, 4),
    (SET_VP_REGISTERS, 0x10, 0x20),
    (POST_MESSAGE, 0x100, 0),
    (SIGNAL_EVENT, 8, 0),
    (RETARGET_DEVICE_INTERRUPT, 0x38, 0),
    (START_VIRTUAL_PROCESSOR, 0xf0, 0),
    (GET_VP_INDEX_FROM_APIC_ID, 0x10, 4),
    (FLUSH_GUEST_PHYSICAL_ADDRESS_SPACE, 0x10, 0),
    (FLUSH_GUEST_PHYSICAL_ADDRESS_LIST, 0x10, 8),
];

const FLUSH_VIRTUAL_ADDRESS_SPACE: u16 = 0x0002;
const FLUSH_VIRTUAL_ADDRESS_LIST: u16 = 0x0003;
const NOTIFY_LONG_SPIN_WAIT: u16 = 0x0008;
const SEND_SYNTHETIC_CLUSTER_IPI: u16 = 0x000b;
const MODIFY_VTL_PROTECTION_MASK: u16 = 0x000c;
const ENABLE_PARTITION_VTL: u16 = 0x000d;
const ENABLE_VP_VTL: u16 = 0x000f;
const VTL_CALL: u16 = 0x0011;
const VTL_RETURN: u16 = 0x0012;
const FLUSH_VIRTUAL_ADDRESS_SPACE_EX: u16 = 0x0013;
const FLUSH_VIRTUAL_ADDRESS_LIST_EX: u16 = 0x0014;
const SEND_SYNTHETIC_CLUSTER_IPI_EX: u16 = 0x0015;
const GET_VP_REGISTERS: u16 = 0x0050;
const SET_VP_REGISTERS: u16 = 0x0051;
const POST_MESSAGE: u16 = 0x005c;
const SIGNAL_EVENT: u16 = 0x005d;
const RETARGET_DEVICE_INTERRUPT: u16 = 0x007e;
const START_VIRTUAL_PROCESSOR: u16 = 0x0099;
const GET_VP_INDEX_FROM_APIC_ID: u16 = 0x009a;
const FLUSH_GUEST_PHYSICAL_ADDRESS_SPACE: u16 = 0x00af;
const FLUSH_GUEST_PHYSICAL_ADDRESS_LIST: u16 = 0x00b0;

/// `HV_FLUSH_*` (hyperv-tlfs.h), by bit.
const FLUSH_FLAGS: &[(u64, &str)] = &[
    (1 << 0, "HV_FLUSH_ALL_PROCESSORS"),
    (1 << 1, "HV_FLUSH_ALL_VIRTUAL_ADDRESS_SPACES"),
    (1 << 2, "HV_FLUSH_NON_GLOBAL_MAPPINGS_ONLY"),
    (1 << 3, "HV_FLUSH_USE_EXTENDED_RANGE_FORMAT"),
];
const FLUSH_ALL_PROCESSORS: u64 = 1 << 0;
const FLUSH_ALL_VIRTUAL_ADDRESS_SPACES: u64 = 1 << 1;
/// Selects the small/large-page encoding described by [`extended_gva_range`].
const FLUSH_USE_EXTENDED_RANGE_FORMAT: u64 = 1 << 3;

/// `HV_MAP_GPA_FLAGS` (TLFS datatypes `HV_MAP_GPA_FLAGS`), by bit, but for
/// the encodings in bits 17:16, which [`MAP_GPA_SPECIAL`] names.
const MAP_GPA_FLAGS: &[(u64, &str)] = &[
    (0x1, "HV_MAP_GPA_READABLE"),
    (0x2, "HV_MAP_GPA_WRITABLE"),
    (0x4, "HV_MAP_GPA_KERNEL_EXECUTABLE"),
    (0x8, "HV_MAP_GPA_USER_EXECUTABLE"),
    (0x0010_0000, "HV_MAP_GPA_NO_OVERLAY"),
    (0x0020_0000, "HV_MAP_GPA_NOT_CACHED"),
    (0x0100_0000, "HV_MAP_GPA_CLEAR_ACCESSED"),
    (0x0200_0000, "HV_MAP_GPA_SET_ACCESSED"),
    (0x0400_0000, "HV_MAP_GPA_CLEAR_DIRTY"),
    (0x0800_0000, "HV_MAP_GPA_SET_DIRTY"),
    (0x1000_0000, "HV_MAP_GPA_DONT_SET_RANGE_ACCESSED"),
    (0x8000_0000, "HV_MAP_GPA_LARGE_PAGE"),
];
/// The mutually exclusive values of `HV_MAP_GPA_FLAGS` bits 17:16.
const MAP_GPA_SPECIAL: &[(u64, &str)] = &[
    (0x1_0000, "HV_MAP_GPA_NO_ACCESS"),
    (0x2_0000, "HV_MAP_GPA_ZEROED"),
    (0x3_0000, "HV_MAP_GPA_ONES"),
];
const MAP_GPA_SPECIAL_MASK: u64 = 0x3_0000;

/// `HV_DEVICE_INTERRUPT_TARGET` flags (TLFS datatypes).
const INTERRUPT_TARGET_FLAGS: &[(u64, &str)] = &[
    (1, "HV_DEVICE_INTERRUPT_TARGET_MULTICAST"),
    (2, "HV_DEVICE_INTERRUPT_TARGET_PROCESSOR_SET"),
];
const INTERRUPT_TARGET_PROCESSOR_SET: u64 = 2;

/// `HV_INTERRUPT_SOURCE` (TLFS `HV_INTERRUPT_ENTRY`; the IOAPIC source from
/// Linux's `enum hv_interrupt_source`).
const INTERRUPT_SOURCE_MSI: u64 = 1;
const INTERRUPT_SOURCE_IOAPIC: u64 = 2;

/// The common `HV_REGISTER_NAME` values, the TLFS names by identifier, in
/// order: its architecture-neutral registers (suspend, version and
/// features, crash, pending events, runtime, SynIC, synthetic timers, VSM)
/// and its x64 interrupt state, general-purpose, floating point and SIMD,
/// control, debug, segment, and table registers and core virtualized MSRs
/// (TLFS datatypes `HV_REGISTER_NAME`). The MTRR, APIC, performance
/// monitoring, nested, and SEV registers are left out.
const REGISTER_NAMES: &[(u32, &str)] = &[
    (0x0000_0000, "HvRegisterExplicitSuspend"),
    (0x0000_0001, "HvRegisterInterceptSuspend"),
    (0x0000_0002, "HvRegisterInstructionEmulationHints"),
    (0x0000_0003, "HvRegisterDispatchSuspend"),
    (0x0000_0004, "HvRegisterInternalActivityState"),
    (0x0000_0100, "HvRegisterHypervisorVersion"),
    (0x0000_0200, "HvRegisterPrivilegesAndFeaturesInfo"),
    (0x0000_0201, "HvRegisterFeaturesInfo"),
    (0x0000_0202, "HvRegisterImplementationLimitsInfo"),
    (0x0000_0203, "HvRegisterHardwareFeaturesInfo"),
    (0x0000_0204, "HvRegisterCpuManagementFeaturesInfo"),
    (0x0000_0205, "HvRegisterPasidFeaturesInfo"),
    (0x0000_0207, "HvRegisterNestedVirtFeaturesInfo"),
    (0x0000_0208, "HvRegisterIptFeaturesInfo"),
    (0x0000_0210, "HvRegisterGuestCrashP0"),
    (0x0000_0211, "HvRegisterGuestCrashP1"),
    (0x0000_0212, "HvRegisterGuestCrashP2"),
    (0x0000_0213, "HvRegisterGuestCrashP3"),
    (0x0000_0214, "HvRegisterGuestCrashP4"),
    (0x0000_0215, "HvRegisterGuestCrashCtl"),
    (0x0001_0002, "HvRegisterPendingInterruption"),
    (0x0001_0003, "HvRegisterInterruptState"),
    (0x0001_0004, "HvRegisterPendingEvent0"),
    (0x0001_0005, "HvRegisterPendingEvent1"),
    (0x0001_0006, "HvRegisterDeliverabilityNotifications"),
    (0x0001_0007, "HvX64RegisterPendingDebugException"),
    (0x0001_0008, "HvRegisterPendingEvent2"),
    (0x0001_0009, "HvRegisterPendingEvent3"),
    (0x0002_0000, "HvX64RegisterRax"),
    (0x0002_0001, "HvX64RegisterRcx"),
    (0x0002_0002, "HvX64RegisterRdx"),
    (0x0002_0003, "HvX64RegisterRbx"),
    (0x0002_0004, "HvX64RegisterRsp"),
    (0x0002_0005, "HvX64RegisterRbp"),
    (0x0002_0006, "HvX64RegisterRsi"),
    (0x0002_0007, "HvX64RegisterRdi"),
    (0x0002_0008, "HvX64RegisterR8"),
    (0x0002_0009, "HvX64RegisterR9"),
    (0x0002_000a, "HvX64RegisterR10"),
    (0x0002_000b, "HvX64RegisterR11"),
    (0x0002_000c, "HvX64RegisterR12"),
    (0x0002_000d, "HvX64RegisterR13"),
    (0x0002_000e, "HvX64RegisterR14"),
    (0x0002_000f, "HvX64RegisterR15"),
    (0x0002_0010, "HvX64RegisterRip"),
    (0x0002_0011, "HvX64RegisterRflags"),
    (0x0003_0000, "HvX64RegisterXmm0"),
    (0x0003_0001, "HvX64RegisterXmm1"),
    (0x0003_0002, "HvX64RegisterXmm2"),
    (0x0003_0003, "HvX64RegisterXmm3"),
    (0x0003_0004, "HvX64RegisterXmm4"),
    (0x0003_0005, "HvX64RegisterXmm5"),
    (0x0003_0006, "HvX64RegisterXmm6"),
    (0x0003_0007, "HvX64RegisterXmm7"),
    (0x0003_0008, "HvX64RegisterXmm8"),
    (0x0003_0009, "HvX64RegisterXmm9"),
    (0x0003_000a, "HvX64RegisterXmm10"),
    (0x0003_000b, "HvX64RegisterXmm11"),
    (0x0003_000c, "HvX64RegisterXmm12"),
    (0x0003_000d, "HvX64RegisterXmm13"),
    (0x0003_000e, "HvX64RegisterXmm14"),
    (0x0003_000f, "HvX64RegisterXmm15"),
    (0x0003_0010, "HvX64RegisterFpMmx0"),
    (0x0003_0011, "HvX64RegisterFpMmx1"),
    (0x0003_0012, "HvX64RegisterFpMmx2"),
    (0x0003_0013, "HvX64RegisterFpMmx3"),
    (0x0003_0014, "HvX64RegisterFpMmx4"),
    (0x0003_0015, "HvX64RegisterFpMmx5"),
    (0x0003_0016, "HvX64RegisterFpMmx6"),
    (0x0003_0017, "HvX64RegisterFpMmx7"),
    (0x0003_0018, "HvX64RegisterFpControlStatus"),
    (0x0003_0019, "HvX64RegisterXmmControlStatus"),
    (0x0004_0000, "HvX64RegisterCr0"),
    (0x0004_0001, "HvX64RegisterCr2"),
    (0x0004_0002, "HvX64RegisterCr3"),
    (0x0004_0003, "HvX64RegisterCr4"),
    (0x0004_0004, "HvX64RegisterCr8"),
    (0x0004_0005, "HvX64RegisterXfem"),
    (0x0004_1000, "HvX64RegisterIntermediateCr0"),
    (0x0004_1003, "HvX64RegisterIntermediateCr4"),
    (0x0004_1004, "HvX64RegisterIntermediateCr8"),
    (0x0005_0000, "HvX64RegisterDr0"),
    (0x0005_0001, "HvX64RegisterDr1"),
    (0x0005_0002, "HvX64RegisterDr2"),
    (0x0005_0003, "HvX64RegisterDr3"),
    (0x0005_0004, "HvX64RegisterDr6"),
    (0x0005_0005, "HvX64RegisterDr7"),
    (0x0006_0000, "HvX64RegisterEs"),
    (0x0006_0001, "HvX64RegisterCs"),
    (0x0006_0002, "HvX64RegisterSs"),
    (0x0006_0003, "HvX64RegisterDs"),
    (0x0006_0004, "HvX64RegisterFs"),
    (0x0006_0005, "HvX64RegisterGs"),
    (0x0006_0006, "HvX64RegisterLdtr"),
    (0x0006_0007, "HvX64RegisterTr"),
    (0x0007_0000, "HvX64RegisterIdtr"),
    (0x0007_0001, "HvX64RegisterGdtr"),
    (0x0008_0000, "HvX64RegisterTsc"),
    (0x0008_0001, "HvX64RegisterEfer"),
    (0x0008_0002, "HvX64RegisterKernelGsBase"),
    (0x0008_0003, "HvX64RegisterApicBase"),
    (0x0008_0004, "HvX64RegisterPat"),
    (0x0008_0005, "HvX64RegisterSysenterCs"),
    (0x0008_0006, "HvX64RegisterSysenterEip"),
    (0x0008_0007, "HvX64RegisterSysenterEsp"),
    (0x0008_0008, "HvX64RegisterStar"),
    (0x0008_0009, "HvX64RegisterLstar"),
    (0x0008_000a, "HvX64RegisterCstar"),
    (0x0008_000b, "HvX64RegisterSfmask"),
    (0x0008_000c, "HvX64RegisterInitialApicId"),
    (0x0009_0000, "HvRegisterVpRuntime"),
    (0x0009_0002, "HvRegisterGuestOsId"),
    (0x0009_0003, "HvRegisterVpIndex"),
    (0x0009_0004, "HvRegisterTimeRefCount"),
    (0x0009_0007, "HvRegisterCpuManagementVersion"),
    (0x0009_0013, "HvRegisterVpAssistPage"),
    (0x0009_0014, "HvRegisterVpRootSignalCount"),
    (0x0009_0017, "HvRegisterReferenceTsc"),
    (0x0009_001a, "HvRegisterReferenceTscSequence"),
    (0x0009_1003, "HvRegisterNestedVpIndex"),
    (0x000a_0000, "HvRegisterSint0"),
    (0x000a_0001, "HvRegisterSint1"),
    (0x000a_0002, "HvRegisterSint2"),
    (0x000a_0003, "HvRegisterSint3"),
    (0x000a_0004, "HvRegisterSint4"),
    (0x000a_0005, "HvRegisterSint5"),
    (0x000a_0006, "HvRegisterSint6"),
    (0x000a_0007, "HvRegisterSint7"),
    (0x000a_0008, "HvRegisterSint8"),
    (0x000a_0009, "HvRegisterSint9"),
    (0x000a_000a, "HvRegisterSint10"),
    (0x000a_000b, "HvRegisterSint11"),
    (0x000a_000c, "HvRegisterSint12"),
    (0x000a_000d, "HvRegisterSint13"),
    (0x000a_000e, "HvRegisterSint14"),
    (0x000a_000f, "HvRegisterSint15"),
    (0x000a_0010, "HvRegisterScontrol"),
    (0x000a_0011, "HvRegisterSversion"),
    (0x000a_0012, "HvRegisterSifp"),
    (0x000a_0013, "HvRegisterSipp"),
    (0x000a_0014, "HvRegisterEom"),
    (0x000a_0015, "HvRegisterSirbp"),
    (0x000b_0000, "HvRegisterStimer0Config"),
    (0x000b_0001, "HvRegisterStimer0Count"),
    (0x000b_0002, "HvRegisterStimer1Config"),
    (0x000b_0003, "HvRegisterStimer1Count"),
    (0x000b_0004, "HvRegisterStimer2Config"),
    (0x000b_0005, "HvRegisterStimer2Count"),
    (0x000b_0006, "HvRegisterStimer3Config"),
    (0x000b_0007, "HvRegisterStimer3Count"),
    (0x000b_0100, "HvRegisterStimeUnhaltedTimerConfig"),
    (0x000b_0101, "HvRegisterStimeUnhaltedTimerCount"),
    (0x000d_0002, "HvRegisterVsmCodePageOffsets"),
    (0x000d_0003, "HvRegisterVsmVpStatus"),
    (0x000d_0004, "HvRegisterVsmPartitionStatus"),
    (0x000d_0005, "HvRegisterVsmVina"),
    (0x000d_0006, "HvRegisterVsmCapabilities"),
    (0x000d_0007, "HvRegisterVsmPartitionConfig"),
    (0x000d_0010, "HvRegisterVsmVpSecureConfigVtl0"),
    (0x000d_0011, "HvRegisterVsmVpSecureConfigVtl1"),
    (0x000d_0012, "HvRegisterVsmVpSecureConfigVtl2"),
    (0x000d_0013, "HvRegisterVsmVpSecureConfigVtl3"),
    (0x000d_0014, "HvRegisterVsmVpSecureConfigVtl4"),
    (0x000d_0015, "HvRegisterVsmVpSecureConfigVtl5"),
    (0x000d_0016, "HvRegisterVsmVpSecureConfigVtl6"),
    (0x000d_0017, "HvRegisterVsmVpSecureConfigVtl7"),
    (0x000d_0018, "HvRegisterVsmVpSecureConfigVtl8"),
    (0x000d_0019, "HvRegisterVsmVpSecureConfigVtl9"),
    (0x000d_001a, "HvRegisterVsmVpSecureConfigVtl10"),
    (0x000d_001b, "HvRegisterVsmVpSecureConfigVtl11"),
    (0x000d_001c, "HvRegisterVsmVpSecureConfigVtl12"),
    (0x000d_001d, "HvRegisterVsmVpSecureConfigVtl13"),
    (0x000d_001e, "HvRegisterVsmVpSecureConfigVtl14"),
    (0x000d_0020, "HvRegisterVsmVpWaitForTlbLock"),
    (0x000d_0100, "HvRegisterIsolationCapabilities"),
];

/// The TLFS name of register `name` (`HV_REGISTER_NAME`), for the common
/// registers [`REGISTER_NAMES`] holds.
pub fn register_name(name: u32) -> Option<&'static str> {
    REGISTER_NAMES
        .binary_search_by_key(&name, |&(known, _)| known)
        .ok()
        .map(|index| REGISTER_NAMES[index].1)
}

/// The fixed input size and rep element size of hypercall `code`, as
/// [`LAYOUTS`] gives them, when ntoseye decodes its input.
pub fn input_layout(code: u16) -> Option<(u16, u16)> {
    LAYOUTS
        .binary_search_by_key(&code, |&(known, _, _)| known)
        .ok()
        .map(|index| (LAYOUTS[index].1, LAYOUTS[index].2))
}

/// A hypercall input value (RCX at a VMCALL) split into its fields (TLFS
/// "Hypercall Inputs").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HypercallControl {
    /// Bits 15:0.
    pub code: u16,
    /// Bit 16: the input is in registers rather than in memory.
    pub fast: bool,
    /// Bits 26:17: the size of the variable input header, in qwords.
    pub variable_header_qwords: u16,
    /// Bit 31: the call is for the L0 hypervisor of a nested environment.
    pub nested: bool,
    /// Bits 43:32: the number of rep elements.
    pub rep_count: u16,
    /// Bits 59:48: the first rep element still to process; those before it
    /// are done.
    pub rep_start: u16,
}

impl HypercallControl {
    pub fn new(value: u64) -> Self {
        Self {
            code: value as u16,
            fast: value & (1 << 16) != 0,
            variable_header_qwords: ((value >> 17) & 0x3ff) as u16,
            nested: value & (1 << 31) != 0,
            rep_count: ((value >> 32) & 0xfff) as u16,
            rep_start: ((value >> 48) & 0xfff) as u16,
        }
    }
}

/// One field of a hypercall's input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HypercallField {
    /// The TLFS parameter name, with its member for a structure
    /// (`ProcessorSet.ValidBanksMask`) and its index for an array
    /// (`Message[2]`).
    pub name: String,
    /// The offset in the input, from its first byte, rep list included.
    pub offset: u16,
    /// In bytes, at most 8.
    pub size: u8,
    pub value: u64,
    /// What the value means, where it has a name or stands for a set:
    /// `HV_PARTITION_ID_SELF`, `VPs 0-3`, a register's TLFS name.
    pub meaning: Option<String>,
}

/// One element of a rep call's input list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HypercallElement {
    pub index: u16,
    pub fields: Vec<HypercallField>,
}

/// The hypercall of a VMCALL exit with its input decoded: the one data model
/// that the REPL (`!hvcall`), the views, the MCP trailer, and the SDK show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedHypercall {
    /// The hypercall input value (RCX).
    pub input_value: u64,
    pub control: HypercallControl,
    /// The TLFS name of the call code.
    pub name: Option<&'static str>,
    /// The GPA of the input parameters (RDX), for a call whose input is in
    /// memory.
    pub input_gpa: Option<u64>,
    /// The GPA of the output parameters (R8), for a call whose input is in
    /// memory.
    pub output_gpa: Option<u64>,
    /// Whether ntoseye knows the layout of the call's input. When it does
    /// not, `fields` holds the input as raw qwords, `Input[0]` on: RDX and
    /// R8 for a fast call, else the first [`RAW_QWORDS`] of the input page.
    pub decoded: bool,
    pub fields: Vec<HypercallField>,
    /// A rep call's input list, every element up to the rep count, those
    /// before the rep start (done already) included.
    pub elements: Vec<HypercallElement>,
    /// Why some of the input is not shown: the input page is unreadable, the
    /// input is in XMM registers, or it runs past the end of its page.
    pub unavailable: Option<String>,
}

impl DecodedHypercall {
    /// The call on one line, as the stop header shows it:
    /// `hypercall 0x0003 HvCallFlushVirtualAddressList rep 0/12`.
    pub fn summary(&self) -> String {
        describe_hypercall_input(self.input_value)
    }
}

/// The hypercall input value and the two parameter registers of a VMCALL,
/// from the caller's general-purpose registers `registers` (named as
/// [`super::EXIT_GPRS`]): RCX, RDX, and R8 for a 64-bit caller, else
/// EDX:EAX, EBX:ECX, and EDI:ESI (TLFS Hypercall Register Conventions
/// (x86/x64)). The hypervisor takes a caller in long mode with a 64-bit
/// code segment as 64-bit; `long_mode` says the caller is one.
pub fn hypercall_registers(
    registers: &HashMap<&'static str, u64>,
    long_mode: bool,
) -> Option<(u64, u64, u64)> {
    let register = |name: &str| registers.get(name).copied();
    if long_mode {
        return Some((register("rcx")?, register("rdx")?, register("r8")?));
    }
    let pair = |high: &str, low: &str| {
        Some((register(high)? & 0xffff_ffff) << 32 | (register(low)? & 0xffff_ffff))
    };
    Some((
        pair("rdx", "rax")?,
        pair("rbx", "rcx")?,
        pair("rdi", "rsi")?,
    ))
}

/// Decode a hypercall from the registers of its VMCALL exit, as
/// [`hypercall_registers`] gives them: `value` is the hypercall input value,
/// and `input` and `output` are the GPAs of the input and output
/// parameters, or the input itself for a fast call, whose input continues in
/// `xmm`, the caller's XMM0 to XMM5 (or why they are not known), for an XMM
/// fast call. `read_input` reads the caller's guest physical memory, for an
/// input in memory: from its GPA to the end of its page, which the input
/// cannot cross.
pub fn decode_hypercall(
    value: u64,
    input: u64,
    output: u64,
    xmm: std::result::Result<[u128; 6], String>,
    read_input: impl FnOnce(u64, &mut [u8]) -> std::result::Result<(), String>,
) -> DecodedHypercall {
    let control = HypercallControl::new(value);
    let layout = input_layout(control.code);
    let mut call = DecodedHypercall {
        input_value: value,
        control,
        name: tlfs_hypercall(control.code).map(|(name, _)| name),
        input_gpa: None,
        output_gpa: None,
        decoded: layout.is_some(),
        fields: Vec::new(),
        elements: Vec::new(),
        unavailable: None,
    };
    // A call without parameters ignores RDX and R8 (TLFS "Alignment
    // Requirements").
    if layout == Some((0, 0)) {
        return call;
    }
    let (bytes, short) = if control.fast {
        let mut bytes = [input.to_le_bytes(), output.to_le_bytes()].concat();
        // TLFS "XMM Fast Hypercalls": the input continues in XMM0 to XMM5,
        // 112 bytes in all.
        let short = match xmm {
            Ok(registers) => {
                bytes.extend(registers.iter().flat_map(|register| register.to_le_bytes()));
                "the input runs past the 112 bytes that an XMM fast hypercall passes".to_string()
            }
            Err(reason) => format!(
                "the input past RDX and R8 is in XMM0 to XMM5 (an XMM fast hypercall), whose \
                 saved values are not known: {reason}"
            ),
        };
        (bytes, short)
    } else {
        call.input_gpa = Some(input);
        call.output_gpa = Some(output);
        let mut page = vec![0u8; PAGE_BYTES - (input as usize & (PAGE_BYTES - 1))];
        if let Err(error) = read_input(input, &mut page) {
            call.unavailable = Some(format!(
                "the input page at GPA {input:#x} is unreadable: {error}"
            ));
            return call;
        }
        (page, "the input runs past the end of its page".to_string())
    };
    let mut reader = Input::new(&bytes);
    match layout {
        Some((fixed, _)) => decode_known(&mut reader, control, usize::from(fixed)),
        None => {
            let count = if control.fast {
                bytes.len() / 8
            } else {
                RAW_QWORDS
            };
            for index in 0..count {
                reader.plain(format!("Input[{index}]"), index * 8, 8);
            }
        }
    }
    if reader.short {
        call.unavailable = Some(short);
    }
    call.fields = reader.fields;
    call.elements = reader.elements;
    call
}

/// The bytes of an input as they are read, field by field, into the fields
/// and rep elements decoded so far. A field past the bytes is left out and
/// marks the input `short`.
struct Input<'a> {
    bytes: &'a [u8],
    fields: Vec<HypercallField>,
    elements: Vec<HypercallElement>,
    short: bool,
}

impl<'a> Input<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            fields: Vec::new(),
            elements: Vec::new(),
            short: false,
        }
    }

    /// The little-endian value of `size` bytes at `offset`.
    fn read(&mut self, offset: usize, size: usize) -> Option<u64> {
        let Some(bytes) = self.bytes.get(offset..offset + size) else {
            self.short = true;
            return None;
        };
        let mut value = [0u8; 8];
        value[..size].copy_from_slice(bytes);
        Some(u64::from_le_bytes(value))
    }

    fn field(
        &mut self,
        name: impl Into<String>,
        offset: usize,
        size: usize,
        meaning: impl FnOnce(u64) -> Option<String>,
    ) -> Option<u64> {
        let value = self.read(offset, size)?;
        self.fields.push(HypercallField {
            name: name.into(),
            offset: offset as u16,
            size: size as u8,
            value,
            meaning: meaning(value),
        });
        Some(value)
    }

    fn plain(&mut self, name: impl Into<String>, offset: usize, size: usize) -> Option<u64> {
        self.field(name, offset, size, |_| None)
    }

    /// The rep list of `control`'s call: its elements of `size` bytes from
    /// `start`, each decoded by `element` at its offset, up to the first that
    /// is not all there.
    fn rep_list(
        &mut self,
        control: HypercallControl,
        start: usize,
        size: usize,
        mut element: impl FnMut(&mut Self, usize),
    ) {
        for index in 0..control.rep_count {
            let at = start + usize::from(index) * size;
            if at + size > self.bytes.len() {
                self.short = true;
                return;
            }
            let outer = std::mem::take(&mut self.fields);
            element(self, at);
            let fields = std::mem::replace(&mut self.fields, outer);
            self.elements.push(HypercallElement { index, fields });
        }
    }
}

/// The fields of a call [`LAYOUTS`] lists, whose fixed input is `fixed`
/// bytes; its rep list follows the variable header.
fn decode_known(input: &mut Input<'_>, control: HypercallControl, fixed: usize) {
    let list = fixed + usize::from(control.variable_header_qwords) * 8;
    match control.code {
        // TLFS HvCallFlushVirtualAddressSpace and ...List; Linux
        // `struct hv_tlb_flush`.
        FLUSH_VIRTUAL_ADDRESS_SPACE | FLUSH_VIRTUAL_ADDRESS_LIST => {
            let flags = flush_header(input);
            let all = flags.is_some_and(|flags| flags & FLUSH_ALL_PROCESSORS != 0);
            input.field("ProcessorMask", 16, 8, |mask| {
                Some(if all {
                    "ignored: HV_FLUSH_ALL_PROCESSORS".to_string()
                } else {
                    vp_list(0, mask)
                })
            });
            if control.code == FLUSH_VIRTUAL_ADDRESS_LIST {
                gva_ranges(input, control, list, flags);
            }
        }
        // TLFS ...SpaceEx and ...ListEx; `struct hv_tlb_flush_ex`: the
        // processor set at 16.
        FLUSH_VIRTUAL_ADDRESS_SPACE_EX | FLUSH_VIRTUAL_ADDRESS_LIST_EX => {
            let flags = flush_header(input);
            vp_set(input, "ProcessorSet", 16);
            if control.code == FLUSH_VIRTUAL_ADDRESS_LIST_EX {
                gva_ranges(input, control, list, flags);
            }
        }
        // TLFS HvCallSendSyntheticClusterIpi: the vector, the HV_INPUT_VTL
        // at 4 (reserved in Linux's `struct hv_send_ipi`), the mask at 8.
        SEND_SYNTHETIC_CLUSTER_IPI => {
            input.plain("Vector", 0, 4);
            input.field("TargetVtl", 4, 1, input_vtl);
            input.field("ProcessorMask", 8, 8, |mask| Some(vp_list(0, mask)));
        }
        // TLFS HvCallSendSyntheticClusterIpiEx; `struct hv_send_ipi_ex`.
        SEND_SYNTHETIC_CLUSTER_IPI_EX => {
            input.plain("Vector", 0, 4);
            input.field("TargetVtl", 4, 1, input_vtl);
            vp_set(input, "ProcessorSet", 8);
        }
        // TLFS HvCallNotifyLongSpinWait.
        NOTIFY_LONG_SPIN_WAIT => {
            input.plain("SpinCount", 0, 4);
        }
        // TLFS HvCallPostMessage: only the payload's first PayloadSize
        // bytes are sent, at most 240.
        POST_MESSAGE => {
            input.field("ConnectionId", 0, 4, connection_id);
            input.plain("MessageType", 8, 4);
            if let Some(size) = input.plain("PayloadSize", 12, 4) {
                for index in 0..(size.min(240) as usize).div_ceil(8) {
                    input.plain(format!("Message[{index}]"), 16 + index * 8, 8);
                }
            }
        }
        // TLFS HvCallSignalEvent.
        SIGNAL_EVENT => {
            input.field("ConnectionId", 0, 4, connection_id);
            input.plain("FlagNumber", 4, 2);
        }
        // TLFS HvCallGetVpRegisters; `struct hv_input_get_vp_registers`: a
        // 4-byte register name per element.
        GET_VP_REGISTERS => {
            vp_header(input, "PartitionId", input_vtl);
            input.rep_list(control, list, 4, |input, at| {
                input.field("RegisterName", at, 4, register_meaning);
            });
        }
        // TLFS HvCallSetVpRegisters; `struct hv_register_assoc`: the name,
        // 12 reserved bytes, the 16-byte value.
        SET_VP_REGISTERS => {
            vp_header(input, "PartitionId", input_vtl);
            input.rep_list(control, list, 0x20, |input, at| {
                input.field("RegisterName", at, 4, register_meaning);
                input.plain("RegisterValue.Low", at + 16, 8);
                input.plain("RegisterValue.High", at + 24, 8);
            });
        }
        // TLFS HvCallFlushGuestPhysicalAddressSpace and ...List; Linux
        // `struct hv_guest_mapping_flush(_list)`.
        FLUSH_GUEST_PHYSICAL_ADDRESS_SPACE | FLUSH_GUEST_PHYSICAL_ADDRESS_LIST => {
            input.plain("AddressSpace", 0, 8);
            input.plain("Flags", 8, 8);
            if control.code == FLUSH_GUEST_PHYSICAL_ADDRESS_LIST {
                input.rep_list(control, list, 8, |input, at| {
                    input.field("GpaRange", at, 8, |range| Some(gpa_range(range)));
                });
            }
        }
        // TLFS HvCallModifyVtlProtectionMask.
        MODIFY_VTL_PROTECTION_MASK => {
            input.field("TargetPartitionId", 0, 8, partition_meaning);
            input.field("MapFlags", 8, 4, |flags| {
                flag_names(flags, MAP_GPA_FLAGS, MAP_GPA_SPECIAL, MAP_GPA_SPECIAL_MASK)
            });
            input.field("TargetVtl", 12, 1, input_vtl);
            input.rep_list(control, list, 8, |input, at| {
                input.field("GpaPageList", at, 8, |page| {
                    Some(format!("GPA {:#x}", page << 12))
                });
            });
        }
        // TLFS HvCallEnablePartitionVtl: HV_ENABLE_PARTITION_VTL_FLAGS bit 0
        // is EnableMbec.
        ENABLE_PARTITION_VTL => {
            input.field("TargetPartitionId", 0, 8, partition_meaning);
            input.field("TargetVtl", 8, 1, vtl);
            input.field("Flags", 9, 1, |flags| {
                flag_names(flags, &[(1, "EnableMbec")], &[], 0)
            });
        }
        // TLFS HvCallEnableVpVtl, x64 layout.
        ENABLE_VP_VTL => {
            vp_header(input, "TargetPartitionId", vtl);
            initial_context(input, "VpVtlContext", 16);
        }
        // TLFS HvCallStartVirtualProcessor, x64 layout.
        START_VIRTUAL_PROCESSOR => {
            vp_header(input, "PartitionId", vtl);
            initial_context(input, "VpContext", 16);
        }
        // TLFS HvCallGetVpIndexFromApicId takes an HV_VTL. Its x64 element
        // is the 4-byte APIC ID that Linux's `struct
        // hv_get_vp_from_apic_id_in` and hvix64's table give, not the 8 bytes
        // with padding of the TLFS page.
        GET_VP_INDEX_FROM_APIC_ID => {
            input.field("PartitionId", 0, 8, partition_meaning);
            input.field("TargetVtl", 8, 1, vtl);
            input.rep_list(control, list, 4, |input, at| {
                input.plain("ProcessorHwId", at, 4);
            });
        }
        // TLFS HvCallRetargetDeviceInterrupt; `struct
        // hv_retarget_device_interrupt`: the HV_INTERRUPT_ENTRY at 16,
        // reserved at 32, the HV_DEVICE_INTERRUPT_TARGET at 40.
        RETARGET_DEVICE_INTERRUPT => {
            input.field("PartitionId", 0, 8, partition_meaning);
            input.plain("DeviceId", 8, 8);
            let source = input.field(
                "InterruptEntry.InterruptSource",
                16,
                4,
                |source| match source {
                    INTERRUPT_SOURCE_MSI => Some("HvInterruptSourceMsi".to_string()),
                    INTERRUPT_SOURCE_IOAPIC => Some("HV_INTERRUPT_SOURCE_IOAPIC".to_string()),
                    _ => None,
                },
            );
            if source == Some(INTERRUPT_SOURCE_MSI) {
                // Linux `union hv_msi_address_register` (destination ID in
                // bits 19:12) and `union hv_msi_data_register` (vector in
                // bits 7:0), x86.
                input.field("InterruptEntry.MsiEntry.Address", 24, 4, |address| {
                    Some(format!("destination {:#x}", (address >> 12) & 0xff))
                });
                input.field("InterruptEntry.MsiEntry.Data", 28, 4, |data| {
                    Some(format!("vector {:#x}", data & 0xff))
                });
            } else {
                input.plain("InterruptEntry.Data", 24, 8);
            }
            input.plain("InterruptTarget.Vector", 40, 4);
            let flags = input.field("InterruptTarget.Flags", 44, 4, |flags| {
                flag_names(flags, INTERRUPT_TARGET_FLAGS, &[], 0)
            });
            if flags.is_some_and(|flags| flags & INTERRUPT_TARGET_PROCESSOR_SET != 0) {
                vp_set(input, "InterruptTarget.ProcessorSet", 48);
            } else if flags.is_some() {
                input.field("InterruptTarget.ProcessorMask", 48, 8, |mask| {
                    Some(vp_list(0, mask))
                });
            }
        }
        _ => {}
    }
}

/// `AddressSpace` and `Flags` of a virtual address flush, and the flags.
fn flush_header(input: &mut Input<'_>) -> Option<u64> {
    let flags = input.read(8, 8);
    input.field("AddressSpace", 0, 8, |_| {
        flags
            .filter(|flags| flags & FLUSH_ALL_VIRTUAL_ADDRESS_SPACES != 0)
            .map(|_| "ignored: HV_FLUSH_ALL_VIRTUAL_ADDRESS_SPACES".to_string())
    });
    input.field("Flags", 8, 8, |flags| {
        flag_names(flags, FLUSH_FLAGS, &[], 0)
    })
}

/// A flush's list of GVA ranges, using the format its flags select.
fn gva_ranges(input: &mut Input<'_>, control: HypercallControl, start: usize, flags: Option<u64>) {
    input.rep_list(control, start, 8, |input, at| {
        input.field("GvaRange", at, 8, |range| match flags {
            Some(flags) if flags & FLUSH_USE_EXTENDED_RANGE_FORMAT != 0 => {
                Some(extended_gva_range(range))
            }
            // The TLFS's layout: bits 11:0 count the pages after the first.
            Some(_) => Some(format!(
                "{:#x}, {}",
                range & !0xfff,
                pages((range & 0xfff) + 1)
            )),
            None => None,
        });
    });
}

/// A GVA range in the extended format that `HV_FLUSH_USE_EXTENDED_RANGE_FORMAT`
/// selects, which the TLFS does not describe: bits 10:0 count the pages
/// after the first, and bit 11 selects large pages. A 4 KiB page's GVA is
/// bits 63:12; a large page's size is bit 12 (2 MiB or 1 GiB), and its GVA
/// bits 63:21 (20:13 are reserved).
///
/// Microsoft's OpenVMM defines it as `HvGvaRangeExtended` and
/// `HvGvaRangeExtendedLargePage`
/// (<https://github.com/microsoft/openvmm/blob/b018341376ca9a34afc3502b1b605f8f8da2ecaa/vm/hv1/hvdef/src/lib.rs#L2413-L2444>),
/// and hvix64.exe 10.0.26100.9444 reads it so: the page counter at RVA
/// 0x32b974 masks each range with 0x7ff for this format and 0xfff for the
/// TLFS's, and the INVVPID loop at 0x354340 takes its page size from bits
/// 12:11 (shifts 12, 21, 12 and 30 out of 0x1e0c150c).
fn extended_gva_range(range: u64) -> String {
    let count = (range & 0x7ff) + 1;
    if range & (1 << 11) == 0 {
        format!("{:#x}, {}", range & !0xfff, pages(count))
    } else {
        let size = if range & (1 << 12) == 0 {
            "2 MiB"
        } else {
            "1 GiB"
        };
        format!("{:#x}, {count} of {size}", range & !0x1f_ffff)
    }
}

/// A GPA range of a guest physical flush, as Linux's `union
/// hv_gpa_page_range` lays it out: bits 10:0 count the pages after the
/// first and bit 11 selects large pages, whose size bit 12 gives (2 MiB or
/// 1 GiB) and whose base PFN is bits 63:21; a 4 KiB page's PFN is bits
/// 63:12.
fn gpa_range(range: u64) -> String {
    let count = (range & 0x7ff) + 1;
    if range & (1 << 11) == 0 {
        format!("GPA {:#x}, {}", range & !0xfff, pages(count))
    } else {
        let size = if range & (1 << 12) == 0 {
            "2 MiB"
        } else {
            "1 GiB"
        };
        format!("large page PFN {:#x}, {count} of {size}", range >> 21)
    }
}

fn pages(count: u64) -> String {
    if count == 1 {
        "1 page".to_string()
    } else {
        format!("{count} pages")
    }
}

/// The partition ID, VP index, and target VTL that begin the inputs of the
/// VP register calls (an HV_INPUT_VTL, TLFS HvCallGetVpRegisters) and of
/// the calls that start a VP or enable its VTL (an HV_VTL, TLFS
/// HvCallEnableVpVtl, HvCallStartVirtualProcessor).
fn vp_header(input: &mut Input<'_>, partition: &str, target_vtl: fn(u64) -> Option<String>) {
    input.field(partition, 0, 8, partition_meaning);
    input.field("VpIndex", 8, 4, |index| match index {
        0xffff_fffe => Some("HV_VP_INDEX_SELF".to_string()),
        0xffff_ffff => Some("HV_ANY_VP".to_string()),
        _ => None,
    });
    input.field("TargetVtl", 12, 1, target_vtl);
}

/// `HV_INITIAL_VP_CONTEXT` (x64) at `at` (TLFS datatypes): RIP, RSP,
/// RFLAGS, the segment registers CS, DS, ES, FS, GS, SS, TR, and LDTR
/// (`HV_X64_SEGMENT_REGISTER`, 16 bytes: base, limit, selector,
/// attributes), the IDTR and GDTR (`HV_X64_TABLE_REGISTER`, 16 bytes: 6 of
/// padding, limit, base), then EFER, CR0, CR3, CR4, and PAT. Each segment's
/// selector is shown, and the base of those long mode uses.
fn initial_context(input: &mut Input<'_>, prefix: &str, at: usize) {
    for (name, offset) in [("Rip", 0), ("Rsp", 8), ("Rflags", 16)] {
        input.plain(format!("{prefix}.{name}"), at + offset, 8);
    }
    for (index, segment) in ["Cs", "Ds", "Es", "Fs", "Gs", "Ss", "Tr", "Ldtr"]
        .into_iter()
        .enumerate()
    {
        let base = at + 24 + index * 16;
        input.plain(format!("{prefix}.{segment}.Selector"), base + 12, 2);
        if matches!(segment, "Fs" | "Gs" | "Tr") {
            input.plain(format!("{prefix}.{segment}.Base"), base, 8);
        }
    }
    for (table, base) in [("Idtr", at + 152), ("Gdtr", at + 168)] {
        input.plain(format!("{prefix}.{table}.Limit"), base + 6, 2);
        input.plain(format!("{prefix}.{table}.Base"), base + 8, 8);
    }
    for (name, offset) in [
        ("Efer", 184),
        ("Cr0", 192),
        ("Cr3", 200),
        ("Cr4", 208),
        ("MsrCrPat", 216),
    ] {
        input.plain(format!("{prefix}.{name}"), at + offset, 8);
    }
}

/// An `HV_VP_SET` at `offset` (TLFS datatypes `HV_VP_SET`): its format,
/// then, for a sparse set (format 0), the mask of its valid banks of 64 VPs
/// and the contents of each valid bank, in bank order. Format 1 is every VP.
fn vp_set(input: &mut Input<'_>, prefix: &str, offset: usize) {
    let Some(format) = input.field(
        format!("{prefix}.Format"),
        offset,
        8,
        |format| match format {
            0 => Some("sparse".to_string()),
            1 => Some("all VPs".to_string()),
            _ => None,
        },
    ) else {
        return;
    };
    let Some(banks) = input.field(format!("{prefix}.ValidBanksMask"), offset + 8, 8, |mask| {
        (format == 0).then(|| bank_list(mask))
    }) else {
        return;
    };
    if format != 0 {
        return;
    }
    for (slot, bank) in (0..64u32).filter(|bank| banks >> bank & 1 != 0).enumerate() {
        let contents = input.field(
            format!("{prefix}.BankContents[{slot}]"),
            offset + 16 + slot * 8,
            8,
            |mask| Some(format!("bank {bank}: {}", vp_list(bank * 64, mask))),
        );
        if contents.is_none() {
            return;
        }
    }
}

/// The VPs of a 64-bit mask whose bit 0 is VP `first`, as `VPs 0-3,8`.
fn vp_list(first: u32, mask: u64) -> String {
    if mask == 0 {
        return "no VPs".to_string();
    }
    format!("VPs {}", runs(first, mask))
}

fn bank_list(mask: u64) -> String {
    if mask == 0 {
        return "no banks".to_string();
    }
    format!("banks {}", runs(0, mask))
}

/// The set bits of `mask`, numbered from `first`, as runs: `0-3,8`.
fn runs(first: u32, mask: u64) -> String {
    let mut runs = Vec::new();
    let mut bit = 0u32;
    while bit < 64 {
        if mask >> bit & 1 == 0 {
            bit += 1;
            continue;
        }
        let start = bit;
        while bit < 64 && mask >> bit & 1 != 0 {
            bit += 1;
        }
        let (low, high) = (first + start, first + bit - 1);
        runs.push(if low == high {
            low.to_string()
        } else {
            format!("{low}-{high}")
        });
    }
    runs.join(",")
}

/// The names of the flags set in `value`, by `names`, and of the value of
/// the bits under `special_mask`, by `special`, with any bits neither names
/// as `+0x..`. `None` for 0.
fn flag_names(
    value: u64,
    names: &[(u64, &str)],
    special: &[(u64, &str)],
    special_mask: u64,
) -> Option<String> {
    if value == 0 {
        return None;
    }
    let mut parts = Vec::new();
    let mut rest = value;
    if let Some(&(bits, name)) = special
        .iter()
        .find(|(bits, _)| value & special_mask == *bits)
    {
        parts.push(name.to_string());
        rest &= !bits;
    }
    for &(bit, name) in names {
        if value & bit != 0 {
            parts.push(name.to_string());
            rest &= !bit;
        }
    }
    if rest != 0 {
        parts.push(format!("+{rest:#x}"));
    }
    Some(parts.join(" | "))
}

fn partition_meaning(id: u64) -> Option<String> {
    (id == u64::MAX).then(|| "HV_PARTITION_ID_SELF".to_string())
}

/// An `HV_CONNECTION_ID` (TLFS datatypes): the ID is bits 23:0, and the
/// rest is reserved.
fn connection_id(value: u64) -> Option<String> {
    (value >> 24 != 0).then(|| format!("ID {:#x}, reserved bits set", value & 0xff_ffff))
}

/// An `HV_VTL`.
fn vtl(level: u64) -> Option<String> {
    Some(format!("VTL{level}"))
}

/// An `HV_INPUT_VTL` (TLFS datatypes): bits 3:0 the target VTL, which bit 4
/// (UseTargetVtl) says to use; clear, the call targets the caller's VTL or
/// all VTLs, as the call defines.
fn input_vtl(value: u64) -> Option<String> {
    Some(if value & 0x10 != 0 {
        format!("VTL{}", value & 0xf)
    } else {
        "UseTargetVtl clear".to_string()
    })
}

fn register_meaning(name: u64) -> Option<String> {
    register_name(name as u32).map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A hypercall input value: `code`, the variable header size, and a
    /// rep's start and count.
    fn value(code: u16, varhead: u64, start: u64, count: u64) -> u64 {
        u64::from(code) | varhead << 17 | count << 32 | start << 48
    }

    /// An input page whose bytes are `parts`, each `(offset, value, size)`.
    fn page(parts: &[(usize, u64, usize)]) -> Vec<u8> {
        let mut page = vec![0u8; PAGE_BYTES];
        for &(offset, value, size) in parts {
            page[offset..offset + size].copy_from_slice(&value.to_le_bytes()[..size]);
        }
        page
    }

    /// The call `value` with its input in memory at GPA `0x5000 + offset`,
    /// where `memory` is that page from `offset` on.
    fn slow(value: u64, offset: u64, memory: &[u8]) -> DecodedHypercall {
        decode_hypercall(
            value,
            0x5000 + offset,
            0x6000,
            Err(String::new()),
            |gpa, buf| {
                assert_eq!(gpa, 0x5000 + offset);
                assert_eq!(buf.len(), PAGE_BYTES - offset as usize);
                buf.copy_from_slice(&memory[..buf.len()]);
                Ok(())
            },
        )
    }

    fn fast(value: u64, rdx: u64, r8: u64) -> DecodedHypercall {
        fast_with(value, rdx, r8, Err("not saved".to_string()))
    }

    /// [`fast`] with the caller's saved XMM0 to XMM5, or why they are not
    /// known.
    fn fast_with(
        value: u64,
        rdx: u64,
        r8: u64,
        xmm: std::result::Result<[u128; 6], String>,
    ) -> DecodedHypercall {
        decode_hypercall(value | 1 << 16, rdx, r8, xmm, |_, _| {
            panic!("a fast call's input is not read from memory")
        })
    }

    /// `(name, offset, value, meaning)` of each field.
    fn fields(fields: &[HypercallField]) -> Vec<(&str, u16, u64, Option<&str>)> {
        fields
            .iter()
            .map(|field| {
                (
                    field.name.as_str(),
                    field.offset,
                    field.value,
                    field.meaning.as_deref(),
                )
            })
            .collect()
    }

    #[test]
    fn layout_tables_are_sorted_for_their_binary_searches() {
        assert!(LAYOUTS.windows(2).all(|pair| pair[0].0 < pair[1].0));
        assert!(REGISTER_NAMES.windows(2).all(|pair| pair[0].0 < pair[1].0));
        assert_eq!(register_name(0x0009_0003), Some("HvRegisterVpIndex"));
        assert_eq!(register_name(0x0008_000d), None);
    }

    #[test]
    fn the_input_value_splits_into_the_tlfs_fields() {
        assert_eq!(
            HypercallControl::new(0x0fff_0fff_8000_0000 | 0x3ff << 17 | 1 << 16 | 0x1234),
            HypercallControl {
                code: 0x1234,
                fast: true,
                variable_header_qwords: 0x3ff,
                nested: true,
                rep_count: 0xfff,
                rep_start: 0xfff,
            }
        );
    }

    /// The GVA list follows the 24-byte header; each range's low 12 bits
    /// count the pages after its first. With HV_FLUSH_ALL_PROCESSORS the
    /// mask is ignored. Elements before the rep start are still listed.
    #[test]
    fn flush_virtual_address_list_decodes_its_header_and_gva_ranges() {
        let memory = page(&[
            (0, 0x1ad000, 8),
            (8, FLUSH_ALL_PROCESSORS, 8),
            (16, 0xf, 8),
            (24, 0xffff_f804_1234_5000, 8),
            (32, 0x7ff6_0000_0003, 8),
        ]);
        let call = slow(value(FLUSH_VIRTUAL_ADDRESS_LIST, 0, 1, 2), 0, &memory);
        assert_eq!(call.name, Some("HvCallFlushVirtualAddressList"));
        assert_eq!(
            (call.input_gpa, call.output_gpa),
            (Some(0x5000), Some(0x6000))
        );
        assert!(call.decoded && call.unavailable.is_none());
        assert_eq!(
            fields(&call.fields),
            [
                ("AddressSpace", 0, 0x1ad000, None),
                ("Flags", 8, 1, Some("HV_FLUSH_ALL_PROCESSORS")),
                (
                    "ProcessorMask",
                    16,
                    0xf,
                    Some("ignored: HV_FLUSH_ALL_PROCESSORS")
                ),
            ]
        );
        let ranges: Vec<_> = call
            .elements
            .iter()
            .map(|element| (element.index, fields(&element.fields)))
            .collect();
        assert_eq!(
            ranges,
            [
                (
                    0,
                    vec![(
                        "GvaRange",
                        24,
                        0xffff_f804_1234_5000,
                        Some("0xfffff80412345000, 1 page")
                    )]
                ),
                (
                    1,
                    vec![(
                        "GvaRange",
                        32,
                        0x7ff6_0000_0003,
                        Some("0x7ff600000000, 4 pages")
                    )]
                ),
            ]
        );
    }

    #[test]
    fn flush_virtual_address_space_names_its_processors() {
        let memory = page(&[
            (8, FLUSH_ALL_VIRTUAL_ADDRESS_SPACES, 8),
            (16, 0b1011_0001, 8),
        ]);
        let call = slow(value(FLUSH_VIRTUAL_ADDRESS_SPACE, 0, 0, 0), 0, &memory);
        assert_eq!(
            fields(&call.fields),
            [
                (
                    "AddressSpace",
                    0,
                    0,
                    Some("ignored: HV_FLUSH_ALL_VIRTUAL_ADDRESS_SPACES")
                ),
                ("Flags", 8, 2, Some("HV_FLUSH_ALL_VIRTUAL_ADDRESS_SPACES")),
                ("ProcessorMask", 16, 0xb1, Some("VPs 0,4-5,7")),
            ]
        );
        assert!(call.elements.is_empty());
    }

    /// In the extended format, a range with bit 11 clear is 4 KiB pages:
    /// bits 10:0 count the pages after the first, up to 2048, and bit 12 is
    /// part of the address.
    #[test]
    fn extended_gva_ranges_decode_small_pages_and_the_maximum_count() {
        let memory = page(&[
            (8, FLUSH_USE_EXTENDED_RANGE_FORMAT, 8),
            (24, 0xffff_cc0c_335e_7010, 8),
            (32, 0x7ff6_0000_17ff, 8),
        ]);
        let call = slow(value(FLUSH_VIRTUAL_ADDRESS_LIST, 0, 0, 2), 0, &memory);
        assert_eq!(
            fields(&call.elements[0].fields),
            [(
                "GvaRange",
                24,
                0xffff_cc0c_335e_7010,
                Some("0xffffcc0c335e7000, 17 pages")
            )]
        );
        assert_eq!(
            fields(&call.elements[1].fields),
            [(
                "GvaRange",
                32,
                0x7ff6_0000_17ff,
                Some("0x7ff600001000, 2048 pages")
            )]
        );
    }

    /// Bit 11 makes a range large pages, 2 MiB or with bit 12 1 GiB, at the
    /// address in bits 63:21, where the TLFS's layout would read those bits
    /// as part of the page count. Here past the variable header of an XMM
    /// fast Ex call.
    #[test]
    fn extended_gva_ranges_decode_large_pages_after_an_xmm_fast_ex_header() {
        let two_mib = 0xffff_f804_1240_0800u64;
        let one_gib = 0xffff_f804_4000_1fffu64;
        let call = fast_with(
            value(FLUSH_VIRTUAL_ADDRESS_LIST_EX, 1, 0, 2),
            0,
            FLUSH_USE_EXTENDED_RANGE_FORMAT,
            Ok([
                1u128 << 64,
                u128::from(two_mib) << 64 | 1,
                u128::from(one_gib),
                0,
                0,
                0,
            ]),
        );
        assert_eq!(
            fields(&call.elements[0].fields),
            [(
                "GvaRange",
                40,
                two_mib,
                Some("0xfffff80412400000, 1 of 2 MiB")
            )]
        );
        assert_eq!(
            fields(&call.elements[1].fields),
            [(
                "GvaRange",
                48,
                one_gib,
                Some("0xfffff80440000000, 2048 of 1 GiB")
            )]
        );
    }

    /// The TLFS's own example: VPs {0, 5, 130} are banks 0 and 2 (mask
    /// 0x5) with contents 0x21 and 0x4. The two bank qwords are the
    /// variable header, so the GVA list starts after them.
    #[test]
    fn a_sparse_vp_set_names_each_valid_bank_and_moves_the_rep_list() {
        let memory = page(&[
            (16, 0, 8),
            (24, 0x5, 8),
            (32, 0x21, 8),
            (40, 0x4, 8),
            (48, 0x1000, 8),
        ]);
        let call = slow(value(FLUSH_VIRTUAL_ADDRESS_LIST_EX, 2, 0, 1), 0, &memory);
        assert_eq!(
            fields(&call.fields)[2..],
            [
                ("ProcessorSet.Format", 16, 0, Some("sparse")),
                ("ProcessorSet.ValidBanksMask", 24, 5, Some("banks 0,2")),
                (
                    "ProcessorSet.BankContents[0]",
                    32,
                    0x21,
                    Some("bank 0: VPs 0,5")
                ),
                (
                    "ProcessorSet.BankContents[1]",
                    40,
                    0x4,
                    Some("bank 2: VPs 130")
                ),
            ]
        );
        assert_eq!(
            fields(&call.elements[0].fields),
            [("GvaRange", 48, 0x1000, Some("0x1000, 1 page"))]
        );
    }

    #[test]
    fn an_all_vps_set_has_no_banks() {
        let memory = page(&[(0, 0xd1, 4), (4, 0x11, 1), (8, 1, 8), (16, 0x5, 8)]);
        let call = slow(value(SEND_SYNTHETIC_CLUSTER_IPI_EX, 0, 0, 0), 0, &memory);
        assert_eq!(
            fields(&call.fields),
            [
                ("Vector", 0, 0xd1, None),
                ("TargetVtl", 4, 0x11, Some("VTL1")),
                ("ProcessorSet.Format", 8, 1, Some("all VPs")),
                ("ProcessorSet.ValidBanksMask", 16, 5, None),
            ]
        );
    }

    /// A fast call's 16 bytes of input are RDX and R8.
    #[test]
    fn a_fast_ipi_takes_its_input_from_rdx_and_r8() {
        let call = fast(value(SEND_SYNTHETIC_CLUSTER_IPI, 0, 0, 0), 0x2f, 0xf0);
        assert_eq!((call.input_gpa, call.output_gpa), (None, None));
        assert_eq!(
            fields(&call.fields),
            [
                ("Vector", 0, 0x2f, None),
                ("TargetVtl", 4, 0, Some("UseTargetVtl clear")),
                ("ProcessorMask", 8, 0xf0, Some("VPs 4-7")),
            ]
        );
        assert!(call.unavailable.is_none());
    }

    /// Past RDX and R8 a fast call's input is in XMM registers: without
    /// their saved values, what is left is said to be missing, not guessed.
    #[test]
    fn an_xmm_fast_call_shows_what_rdx_and_r8_hold_and_says_the_rest_is_missing() {
        let call = fast(value(SEND_SYNTHETIC_CLUSTER_IPI_EX, 1, 0, 0), 0x2f, 0);
        assert_eq!(
            fields(&call.fields),
            [
                ("Vector", 0, 0x2f, None),
                ("TargetVtl", 4, 0, Some("UseTargetVtl clear")),
                ("ProcessorSet.Format", 8, 0, Some("sparse")),
            ]
        );
        assert!(call.unavailable.as_deref().unwrap().contains("not saved"));
    }

    /// With the saved XMM0 to XMM5, an XMM fast call's input runs on past R8
    /// in order: the sparse VP set's bank mask is XMM0's low qword and its
    /// banks follow, as they would in an input page.
    #[test]
    fn an_xmm_fast_call_reads_on_into_the_saved_xmm_registers() {
        let xmm0 = 0x21u128 << 64 | 0x5;
        let call = fast_with(
            value(SEND_SYNTHETIC_CLUSTER_IPI_EX, 0, 0, 0),
            0x2f,
            0,
            Ok([xmm0, 0x4, 0, 0, 0, 0]),
        );
        assert_eq!(
            fields(&call.fields)[2..],
            [
                ("ProcessorSet.Format", 8, 0, Some("sparse")),
                ("ProcessorSet.ValidBanksMask", 16, 5, Some("banks 0,2")),
                (
                    "ProcessorSet.BankContents[0]",
                    24,
                    0x21,
                    Some("bank 0: VPs 0,5")
                ),
                (
                    "ProcessorSet.BankContents[1]",
                    32,
                    0x4,
                    Some("bank 2: VPs 130")
                ),
            ]
        );
        assert!(call.unavailable.is_none());
    }

    #[test]
    fn notify_long_spin_wait_and_signal_event_decode_their_fields() {
        let call = fast(value(NOTIFY_LONG_SPIN_WAIT, 0, 0, 0), 0xffff_0000_0400, 0);
        assert_eq!(fields(&call.fields), [("SpinCount", 0, 0x400, None)]);
        let call = fast(value(SIGNAL_EVENT, 0, 0, 0), 0xffff_0003_0001_0004, 0);
        assert_eq!(
            fields(&call.fields),
            [
                ("ConnectionId", 0, 0x0001_0004, None),
                ("FlagNumber", 4, 3, None),
            ]
        );
    }

    /// Only the payload's first PayloadSize bytes are sent, so only the
    /// qwords that hold them are shown, never past 240 bytes.
    #[test]
    fn post_message_shows_the_payload_it_sends() {
        let memory = page(&[
            (0, 0x0100_0002, 4),
            (8, 1, 4),
            (12, 20, 4),
            (16, 0x1111, 8),
            (24, 0x2222, 8),
            (32, 0x3333, 8),
        ]);
        let call = slow(value(POST_MESSAGE, 0, 0, 0), 0, &memory);
        assert_eq!(
            fields(&call.fields),
            [
                (
                    "ConnectionId",
                    0,
                    0x0100_0002,
                    Some("ID 0x2, reserved bits set")
                ),
                ("MessageType", 8, 1, None),
                ("PayloadSize", 12, 20, None),
                ("Message[0]", 16, 0x1111, None),
                ("Message[1]", 24, 0x2222, None),
                ("Message[2]", 32, 0x3333, None),
            ]
        );
        let memory = page(&[(12, 0xffff, 4)]);
        let call = slow(value(POST_MESSAGE, 0, 0, 0), 0, &memory);
        assert_eq!(call.fields.last().unwrap().name, "Message[29]");
    }

    #[test]
    fn get_vp_registers_names_each_register_it_reads() {
        let memory = page(&[
            (0, u64::MAX, 8),
            (8, 0xffff_fffe, 4),
            (12, 0x11, 1),
            (16, 0x0002_0010, 4),
            (20, 0x000d_0007, 4),
            (24, 0x0008_00ff, 4),
        ]);
        let call = slow(value(GET_VP_REGISTERS, 0, 0, 3), 0, &memory);
        assert_eq!(
            fields(&call.fields),
            [
                ("PartitionId", 0, u64::MAX, Some("HV_PARTITION_ID_SELF")),
                ("VpIndex", 8, 0xffff_fffe, Some("HV_VP_INDEX_SELF")),
                ("TargetVtl", 12, 0x11, Some("VTL1")),
            ]
        );
        let names: Vec<_> = call
            .elements
            .iter()
            .flat_map(|element| fields(&element.fields))
            .collect();
        assert_eq!(
            names,
            [
                ("RegisterName", 16, 0x0002_0010, Some("HvX64RegisterRip")),
                (
                    "RegisterName",
                    20,
                    0x000d_0007,
                    Some("HvRegisterVsmPartitionConfig")
                ),
                ("RegisterName", 24, 0x0008_00ff, None),
            ]
        );
    }

    /// Each element is an `hv_register_assoc`: the name, 12 reserved bytes,
    /// then the 16-byte value.
    #[test]
    fn set_vp_registers_pairs_each_name_with_its_value() {
        let memory = page(&[
            (8, 2, 4),
            (16, 0x0004_0002, 4),
            (32, 0x1ad000, 8),
            (40, 0, 8),
            (48, 0x0009_0013, 4),
            (64, 0x1234_5001, 8),
            (72, 0x99, 8),
        ]);
        let call = slow(value(SET_VP_REGISTERS, 0, 0, 2), 0, &memory);
        let elements: Vec<_> = call
            .elements
            .iter()
            .map(|element| fields(&element.fields))
            .collect();
        assert_eq!(
            elements,
            [
                vec![
                    ("RegisterName", 16, 0x0004_0002, Some("HvX64RegisterCr3")),
                    ("RegisterValue.Low", 32, 0x1ad000, None),
                    ("RegisterValue.High", 40, 0, None),
                ],
                vec![
                    (
                        "RegisterName",
                        48,
                        0x0009_0013,
                        Some("HvRegisterVpAssistPage")
                    ),
                    ("RegisterValue.Low", 64, 0x1234_5001, None),
                    ("RegisterValue.High", 72, 0x99, None),
                ],
            ]
        );
    }

    #[test]
    fn guest_physical_flushes_decode_small_and_large_page_ranges() {
        let memory = page(&[(0, 0x2_0000_101e, 8)]);
        let call = slow(
            value(FLUSH_GUEST_PHYSICAL_ADDRESS_SPACE, 0, 0, 0),
            0,
            &memory,
        );
        assert_eq!(
            fields(&call.fields),
            [
                ("AddressSpace", 0, 0x2_0000_101e, None),
                ("Flags", 8, 0, None)
            ]
        );
        let memory = page(&[
            (16, 0x1234_5000 | 0x7ff, 8),
            (24, 0x40_0000 << 21 | 1 << 12 | 1 << 11 | 2, 8),
            (32, 0x3 << 21 | 1 << 11, 8),
        ]);
        let call = slow(
            value(FLUSH_GUEST_PHYSICAL_ADDRESS_LIST, 0, 0, 3),
            0,
            &memory,
        );
        let ranges: Vec<_> = call
            .elements
            .iter()
            .map(|element| element.fields[0].meaning.clone().unwrap())
            .collect();
        assert_eq!(
            ranges,
            [
                "GPA 0x12345000, 2048 pages",
                "large page PFN 0x400000, 3 of 1 GiB",
                "large page PFN 0x3, 1 of 2 MiB",
            ]
        );
    }

    #[test]
    fn modify_vtl_protection_mask_names_its_flags_and_pages() {
        let memory = page(&[
            (0, u64::MAX, 8),
            (8, 0x1_0005 | 0x40, 4),
            (12, 0x10, 1),
            (16, 0x1234, 8),
        ]);
        let call = slow(value(MODIFY_VTL_PROTECTION_MASK, 0, 0, 1), 0, &memory);
        assert_eq!(
            fields(&call.fields)[1..],
            [
                (
                    "MapFlags",
                    8,
                    0x1_0045,
                    Some(
                        "HV_MAP_GPA_NO_ACCESS | HV_MAP_GPA_READABLE | \
                         HV_MAP_GPA_KERNEL_EXECUTABLE | +0x40"
                    )
                ),
                ("TargetVtl", 12, 0x10, Some("VTL0")),
            ]
        );
        assert_eq!(
            fields(&call.elements[0].fields),
            [("GpaPageList", 16, 0x1234, Some("GPA 0x1234000"))]
        );
    }

    #[test]
    fn enable_partition_vtl_decodes_its_flags() {
        let memory = page(&[(0, 3, 8), (8, 1, 1), (9, 1, 1)]);
        let call = slow(value(ENABLE_PARTITION_VTL, 0, 0, 0), 0, &memory);
        assert_eq!(
            fields(&call.fields),
            [
                ("TargetPartitionId", 0, 3, None),
                ("TargetVtl", 8, 1, Some("VTL1")),
                ("Flags", 9, 1, Some("EnableMbec")),
            ]
        );
    }

    /// The x64 HV_INITIAL_VP_CONTEXT begins at 16: CS's selector is 12
    /// bytes into the segment at 24, the GDTR's base 8 into the table at
    /// 168, and CR3 at 200.
    #[test]
    fn start_vp_and_enable_vp_vtl_decode_the_initial_context() {
        let memory = page(&[
            (8, 3, 4),
            (12, 1, 1),
            (16, 0xffff_f800_0000_1000, 8),
            (16 + 24 + 12, 0x10, 2),
            (16 + 24 + 4 * 16, 0xffff_f800_1234_0000, 8),
            (16 + 168 + 6, 0x57, 2),
            (16 + 168 + 8, 0xffff_f800_0040_0000, 8),
            (16 + 200, 0x1ad000, 8),
        ]);
        for (code, prefix) in [
            (START_VIRTUAL_PROCESSOR, "VpContext"),
            (ENABLE_VP_VTL, "VpVtlContext"),
        ] {
            let call = slow(value(code, 0, 0, 0), 0, &memory);
            let find = |name: &str| {
                let name = format!("{prefix}.{name}");
                call.fields
                    .iter()
                    .find(|field| field.name == name)
                    .map(|field| (field.offset, field.value))
            };
            assert_eq!(
                fields(&call.fields)[1..3],
                [("VpIndex", 8, 3, None), ("TargetVtl", 12, 1, Some("VTL1")),]
            );
            assert_eq!(find("Rip"), Some((16, 0xffff_f800_0000_1000)));
            assert_eq!(find("Cs.Selector"), Some((52, 0x10)));
            assert_eq!(find("Gs.Base"), Some((104, 0xffff_f800_1234_0000)));
            assert_eq!(find("Gdtr.Limit"), Some((190, 0x57)));
            assert_eq!(find("Gdtr.Base"), Some((192, 0xffff_f800_0040_0000)));
            assert_eq!(find("Cr3"), Some((216, 0x1ad000)));
            assert_eq!(call.fields.last().unwrap().offset, 16 + 216);
            assert!(call.unavailable.is_none());
        }
    }

    #[test]
    fn get_vp_index_from_apic_id_lists_four_byte_apic_ids() {
        let memory = page(&[(0, u64::MAX, 8), (16, 0, 4), (20, 6, 4)]);
        let call = slow(value(GET_VP_INDEX_FROM_APIC_ID, 0, 0, 2), 0, &memory);
        assert_eq!(fields(&call.fields)[1], ("TargetVtl", 8, 0, Some("VTL0")));
        let ids: Vec<_> = call
            .elements
            .iter()
            .flat_map(|element| fields(&element.fields))
            .collect();
        assert_eq!(
            ids,
            [
                ("ProcessorHwId", 16, 0, None),
                ("ProcessorHwId", 20, 6, None)
            ]
        );
    }

    /// An MSI entry's address and data are dwords at 24 and 28, and with
    /// HV_DEVICE_INTERRUPT_TARGET_PROCESSOR_SET the target is an HV_VP_SET
    /// at 48 rather than a mask.
    #[test]
    fn retarget_device_interrupt_decodes_its_msi_entry_and_target() {
        let memory = page(&[
            (0, u64::MAX, 8),
            (8, 0xbeef, 8),
            (16, INTERRUPT_SOURCE_MSI, 4),
            (24, 0xfee0_3000, 4),
            (28, 0x41, 4),
            (40, 0x41, 4),
            (44, 3, 4),
            (48, 0, 8),
            (56, 1, 8),
            (64, 0x3, 8),
        ]);
        let call = slow(value(RETARGET_DEVICE_INTERRUPT, 1, 0, 0), 0, &memory);
        assert_eq!(
            fields(&call.fields)[2..],
            [
                (
                    "InterruptEntry.InterruptSource",
                    16,
                    1,
                    Some("HvInterruptSourceMsi")
                ),
                (
                    "InterruptEntry.MsiEntry.Address",
                    24,
                    0xfee0_3000,
                    Some("destination 0x3")
                ),
                (
                    "InterruptEntry.MsiEntry.Data",
                    28,
                    0x41,
                    Some("vector 0x41")
                ),
                ("InterruptTarget.Vector", 40, 0x41, None),
                (
                    "InterruptTarget.Flags",
                    44,
                    3,
                    Some(
                        "HV_DEVICE_INTERRUPT_TARGET_MULTICAST | \
                         HV_DEVICE_INTERRUPT_TARGET_PROCESSOR_SET"
                    )
                ),
                ("InterruptTarget.ProcessorSet.Format", 48, 0, Some("sparse")),
                (
                    "InterruptTarget.ProcessorSet.ValidBanksMask",
                    56,
                    1,
                    Some("banks 0")
                ),
                (
                    "InterruptTarget.ProcessorSet.BankContents[0]",
                    64,
                    3,
                    Some("bank 0: VPs 0-1")
                ),
            ]
        );
        let memory = page(&[(16, 2, 4), (24, 0x1_0000_0031, 8), (44, 0, 4), (48, 0x2, 8)]);
        let call = slow(value(RETARGET_DEVICE_INTERRUPT, 0, 0, 0), 0, &memory);
        assert_eq!(
            fields(&call.fields)[3..],
            [
                ("InterruptEntry.Data", 24, 0x1_0000_0031, None),
                ("InterruptTarget.Vector", 40, 0, None),
                ("InterruptTarget.Flags", 44, 0, None),
                ("InterruptTarget.ProcessorMask", 48, 2, Some("VPs 1")),
            ]
        );
    }

    /// A call without a known layout shows its raw input: eight qwords of
    /// its page, or RDX and R8 for a fast call.
    #[test]
    fn an_unknown_call_shows_raw_qwords() {
        let memory = page(&[(0, 0x11, 8), (56, 0x88, 8), (64, 0x99, 8)]);
        let call = slow(value(0x0046, 0, 0, 0), 0, &memory);
        assert_eq!(call.name, Some("HvCallGetPartitionId"));
        assert!(!call.decoded);
        let raw = fields(&call.fields);
        assert_eq!(raw.len(), RAW_QWORDS);
        assert_eq!(raw[0], ("Input[0]", 0, 0x11, None));
        assert_eq!(raw[7], ("Input[7]", 56, 0x88, None));
        let call = fast(value(0x7777, 0, 0, 0), 1, 2);
        assert_eq!((call.name, call.decoded), (None, false));
        assert_eq!(
            fields(&call.fields),
            [("Input[0]", 0, 1, None), ("Input[1]", 8, 2, None)]
        );
        assert!(call.unavailable.is_none());
    }

    /// An input cannot cross its page, so one that would is cut at the end
    /// of the page and said to be, and a rep list stops at the first
    /// element that is not all there.
    #[test]
    fn an_input_is_read_only_to_the_end_of_its_page() {
        let mut memory = vec![0u8; 0x18];
        memory[8..16].copy_from_slice(&0x5u64.to_le_bytes());
        let call = slow(value(FLUSH_VIRTUAL_ADDRESS_LIST, 0, 0, 3), 0xfe8, &memory);
        assert_eq!(call.fields.len(), 3);
        assert!(call.elements.is_empty());
        assert!(call.unavailable.is_some());
        let memory = vec![0u8; 0x20];
        let call = slow(value(GET_VP_REGISTERS, 0, 0, 5), 0xfe0, &memory);
        assert_eq!(
            call.elements
                .iter()
                .map(|element| element.index)
                .collect::<Vec<_>>(),
            [0, 1, 2, 3]
        );
        assert!(call.unavailable.is_some());
    }

    #[test]
    fn an_unreadable_input_page_keeps_the_call_and_says_why() {
        let call = decode_hypercall(
            value(GET_VP_REGISTERS, 0, 0, 1),
            0x9008,
            0,
            Err(String::new()),
            |_, _| Err("not mapped".to_string()),
        );
        assert_eq!(call.name, Some("HvCallGetVpRegisters"));
        assert_eq!(call.input_gpa, Some(0x9008));
        assert!(call.fields.is_empty());
        assert!(call.unavailable.unwrap().contains("not mapped"));
    }

    /// HvCallVtlCall and HvCallVtlReturn take no parameters, so RDX and R8
    /// are not their GPAs and nothing is read.
    #[test]
    fn a_call_without_parameters_reads_nothing() {
        let call = decode_hypercall(
            value(VTL_CALL, 0, 0, 0),
            0x1234,
            0x5678,
            Err(String::new()),
            |_, _| panic!("read"),
        );
        assert_eq!(call.name, Some("HvCallVtlCall"));
        assert_eq!((call.input_gpa, call.output_gpa), (None, None));
        assert!(call.decoded && call.fields.is_empty() && call.unavailable.is_none());
    }

    /// A 32-bit caller passes each register pair as high:low.
    #[test]
    fn a_32_bit_caller_passes_register_pairs() {
        let registers: HashMap<&'static str, u64> = [
            ("rax", 0xdead_0000_0003),
            ("rdx", 0x0002_0001),
            ("rcx", 0x1000),
            ("rbx", 0),
            ("rsi", 0x2000),
            ("rdi", 0),
            ("r8", 0x7777),
        ]
        .into_iter()
        .collect();
        assert_eq!(
            hypercall_registers(&registers, false),
            Some((0x0002_0001_0000_0003, 0x1000, 0x2000))
        );
        assert_eq!(
            hypercall_registers(&registers, true),
            Some((0x1000, 0x0002_0001, 0x7777))
        );
    }
}
