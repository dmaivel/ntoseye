//! Names of the hypercalls the Hyper-V TLFS documents, by call code, with
//! whether each is a rep call. From the TLFS hypercall reference and its
//! page for each hypercall, and HvCallGetPartitionId (0x0046), which the
//! current pages name without a code, from TLFS 6.0b.

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
    (0x0050, "HvCallGetVpRegisters", true),
    (0x0051, "HvCallSetVpRegisters", true),
    (0x0052, "HvCallTranslateVirtualAddress", false),
    (0x0058, "HvCallDeletePort", false),
    (0x005b, "HvCallDisconnectPort", false),
    (0x005c, "HvCallPostMessage", false),
    (0x005d, "HvCallSignalEvent", false),
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
    (0x00c1, "HvCallPostMessageDirect", false),
    (0x00e1, "HvCallMapVpStatePage", false),
    (0x00e2, "HvCallUnmapVpStatePage", false),
    (0x00f4, "HvCallGetVpCpuidValues", true),
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
