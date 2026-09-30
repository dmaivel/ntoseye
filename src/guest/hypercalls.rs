//! Names of the hypercalls the Hyper-V TLFS documents, by call code, with
//! whether each is a rep call. From the TLFS hypercall reference and its
//! page for each hypercall, and HvCallGetPartitionId (0x0046), which the
//! current pages name without a code, from TLFS 6.0b.

use super::hv_layout::HypercallEntry;

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

/// The names ntoseye gives the Windows hypervisor's code, and the length of
/// the function each begins, by RVA, where the image's `.pdata` gives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HypervisorSymbols {
    pub names: Vec<(String, u32)>,
    pub extents: std::collections::HashMap<u32, u32>,
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
        let name = match (code, tlfs_hypercall(code as u16)) {
            (0, _) => "HvCallUnimplemented".to_string(),
            (_, Some((name, _))) => name.to_string(),
            (_, None) => format!("HvCall{code:04X}"),
        };
        named.push((name, offset));
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

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u64 = 0xffff_f840_b140_0000;

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
}
