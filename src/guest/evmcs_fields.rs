//! The fields of an Enlightened VMCS, by name, offset, and size: the Hyper-V
//! TLFS layout (Linux `struct hv_enlightened_vmcs`), padding left out.

use crate::error::{Error, Result};

/// `(name, offset, size in bytes)`, in offset order.
pub const EVMCS_FIELDS: &[(&str, u16, u8)] = &[
    ("revision_id", 0x000, 4),
    ("abort", 0x004, 4),
    ("host_es_selector", 0x008, 2),
    ("host_cs_selector", 0x00a, 2),
    ("host_ss_selector", 0x00c, 2),
    ("host_ds_selector", 0x00e, 2),
    ("host_fs_selector", 0x010, 2),
    ("host_gs_selector", 0x012, 2),
    ("host_tr_selector", 0x014, 2),
    ("host_ia32_pat", 0x018, 8),
    ("host_ia32_efer", 0x020, 8),
    ("host_cr0", 0x028, 8),
    ("host_cr3", 0x030, 8),
    ("host_cr4", 0x038, 8),
    ("host_ia32_sysenter_esp", 0x040, 8),
    ("host_ia32_sysenter_eip", 0x048, 8),
    ("host_rip", 0x050, 8),
    ("host_ia32_sysenter_cs", 0x058, 4),
    ("pin_based_vm_exec_control", 0x05c, 4),
    ("vm_exit_controls", 0x060, 4),
    ("secondary_vm_exec_control", 0x064, 4),
    ("io_bitmap_a", 0x068, 8),
    ("io_bitmap_b", 0x070, 8),
    ("msr_bitmap", 0x078, 8),
    ("guest_es_selector", 0x080, 2),
    ("guest_cs_selector", 0x082, 2),
    ("guest_ss_selector", 0x084, 2),
    ("guest_ds_selector", 0x086, 2),
    ("guest_fs_selector", 0x088, 2),
    ("guest_gs_selector", 0x08a, 2),
    ("guest_ldtr_selector", 0x08c, 2),
    ("guest_tr_selector", 0x08e, 2),
    ("guest_es_limit", 0x090, 4),
    ("guest_cs_limit", 0x094, 4),
    ("guest_ss_limit", 0x098, 4),
    ("guest_ds_limit", 0x09c, 4),
    ("guest_fs_limit", 0x0a0, 4),
    ("guest_gs_limit", 0x0a4, 4),
    ("guest_ldtr_limit", 0x0a8, 4),
    ("guest_tr_limit", 0x0ac, 4),
    ("guest_gdtr_limit", 0x0b0, 4),
    ("guest_idtr_limit", 0x0b4, 4),
    ("guest_es_ar_bytes", 0x0b8, 4),
    ("guest_cs_ar_bytes", 0x0bc, 4),
    ("guest_ss_ar_bytes", 0x0c0, 4),
    ("guest_ds_ar_bytes", 0x0c4, 4),
    ("guest_fs_ar_bytes", 0x0c8, 4),
    ("guest_gs_ar_bytes", 0x0cc, 4),
    ("guest_ldtr_ar_bytes", 0x0d0, 4),
    ("guest_tr_ar_bytes", 0x0d4, 4),
    ("guest_es_base", 0x0d8, 8),
    ("guest_cs_base", 0x0e0, 8),
    ("guest_ss_base", 0x0e8, 8),
    ("guest_ds_base", 0x0f0, 8),
    ("guest_fs_base", 0x0f8, 8),
    ("guest_gs_base", 0x100, 8),
    ("guest_ldtr_base", 0x108, 8),
    ("guest_tr_base", 0x110, 8),
    ("guest_gdtr_base", 0x118, 8),
    ("guest_idtr_base", 0x120, 8),
    ("vm_exit_msr_store_addr", 0x140, 8),
    ("vm_exit_msr_load_addr", 0x148, 8),
    ("vm_entry_msr_load_addr", 0x150, 8),
    ("cr3_target_value0", 0x158, 8),
    ("cr3_target_value1", 0x160, 8),
    ("cr3_target_value2", 0x168, 8),
    ("cr3_target_value3", 0x170, 8),
    ("page_fault_error_code_mask", 0x178, 4),
    ("page_fault_error_code_match", 0x17c, 4),
    ("cr3_target_count", 0x180, 4),
    ("vm_exit_msr_store_count", 0x184, 4),
    ("vm_exit_msr_load_count", 0x188, 4),
    ("vm_entry_msr_load_count", 0x18c, 4),
    ("tsc_offset", 0x190, 8),
    ("virtual_apic_page_addr", 0x198, 8),
    ("vmcs_link_pointer", 0x1a0, 8),
    ("guest_ia32_debugctl", 0x1a8, 8),
    ("guest_ia32_pat", 0x1b0, 8),
    ("guest_ia32_efer", 0x1b8, 8),
    ("guest_pdptr0", 0x1c0, 8),
    ("guest_pdptr1", 0x1c8, 8),
    ("guest_pdptr2", 0x1d0, 8),
    ("guest_pdptr3", 0x1d8, 8),
    ("guest_pending_dbg_exceptions", 0x1e0, 8),
    ("guest_sysenter_esp", 0x1e8, 8),
    ("guest_sysenter_eip", 0x1f0, 8),
    ("guest_activity_state", 0x1f8, 4),
    ("guest_sysenter_cs", 0x1fc, 4),
    ("cr0_guest_host_mask", 0x200, 8),
    ("cr4_guest_host_mask", 0x208, 8),
    ("cr0_read_shadow", 0x210, 8),
    ("cr4_read_shadow", 0x218, 8),
    ("guest_cr0", 0x220, 8),
    ("guest_cr3", 0x228, 8),
    ("guest_cr4", 0x230, 8),
    ("guest_dr7", 0x238, 8),
    ("host_fs_base", 0x240, 8),
    ("host_gs_base", 0x248, 8),
    ("host_tr_base", 0x250, 8),
    ("host_gdtr_base", 0x258, 8),
    ("host_idtr_base", 0x260, 8),
    ("host_rsp", 0x268, 8),
    ("ept_pointer", 0x270, 8),
    ("virtual_processor_id", 0x278, 2),
    ("guest_physical_address", 0x2a8, 8),
    ("vm_instruction_error", 0x2b0, 4),
    ("vm_exit_reason", 0x2b4, 4),
    ("vm_exit_intr_info", 0x2b8, 4),
    ("vm_exit_intr_error_code", 0x2bc, 4),
    ("idt_vectoring_info_field", 0x2c0, 4),
    ("idt_vectoring_error_code", 0x2c4, 4),
    ("vm_exit_instruction_len", 0x2c8, 4),
    ("vmx_instruction_info", 0x2cc, 4),
    ("exit_qualification", 0x2d0, 8),
    ("exit_io_instruction_ecx", 0x2d8, 8),
    ("exit_io_instruction_esi", 0x2e0, 8),
    ("exit_io_instruction_edi", 0x2e8, 8),
    ("exit_io_instruction_eip", 0x2f0, 8),
    ("guest_linear_address", 0x2f8, 8),
    ("guest_rsp", 0x300, 8),
    ("guest_rflags", 0x308, 8),
    ("guest_interruptibility_info", 0x310, 4),
    ("cpu_based_vm_exec_control", 0x314, 4),
    ("exception_bitmap", 0x318, 4),
    ("vm_entry_controls", 0x31c, 4),
    ("vm_entry_intr_info_field", 0x320, 4),
    ("vm_entry_exception_error_code", 0x324, 4),
    ("vm_entry_instruction_len", 0x328, 4),
    ("tpr_threshold", 0x32c, 4),
    ("guest_rip", 0x330, 8),
    ("hv_clean_fields", 0x338, 4),
    ("hv_synthetic_controls", 0x340, 4),
    ("hv_enlightenments_control", 0x344, 4),
    ("hv_vp_id", 0x348, 4),
    ("hv_vm_id", 0x350, 8),
    ("partition_assist_page", 0x358, 8),
    ("guest_bndcfgs", 0x380, 8),
    ("guest_ia32_perf_global_ctrl", 0x388, 8),
    ("guest_ia32_s_cet", 0x390, 8),
    ("guest_ssp", 0x398, 8),
    ("guest_ia32_int_ssp_table_addr", 0x3a0, 8),
    ("guest_ia32_lbr_ctl", 0x3a8, 8),
    ("xss_exit_bitmap", 0x3c0, 8),
    ("encls_exiting_bitmap", 0x3c8, 8),
    ("host_ia32_perf_global_ctrl", 0x3d0, 8),
    ("tsc_multiplier", 0x3d8, 8),
    ("host_ia32_s_cet", 0x3e0, 8),
    ("host_ssp", 0x3e8, 8),
    ("host_ia32_int_ssp_table_addr", 0x3f0, 8),
];

/// The value of each field of the eVMCS `page`, in offset order.
pub fn field_values(page: &[u8]) -> Vec<(&'static str, u16, u8, u64)> {
    EVMCS_FIELDS
        .iter()
        .filter_map(|&(name, offset, size)| {
            let bytes = page.get(usize::from(offset)..usize::from(offset) + usize::from(size))?;
            let mut value = [0u8; 8];
            value[..bytes.len()].copy_from_slice(bytes);
            Some((name, offset, size, u64::from_le_bytes(value)))
        })
        .collect()
}

/// The value of the field `name` of the eVMCS `page`.
pub fn field(page: &[u8], name: &str) -> Option<u64> {
    field_values(page)
        .into_iter()
        .find(|&(field, ..)| field == name)
        .map(|(.., value)| value)
}

/// Architectural MSRs (Intel SDM Vol. 4) an MSR intercept list is most
/// often read for, each as its first and last number: one MSR, or a block
/// of them under one name. All are in the ranges an MSR bitmap covers.
const MSR_NAMES: &[(u32, u32, &str)] = &[
    (0x10, 0x10, "IA32_TIME_STAMP_COUNTER"),
    (0x1b, 0x1b, "IA32_APIC_BASE"),
    (0x3a, 0x3a, "IA32_FEATURE_CONTROL"),
    (0x48, 0x48, "IA32_SPEC_CTRL"),
    (0x49, 0x49, "IA32_PRED_CMD"),
    (0x8b, 0x8b, "IA32_BIOS_SIGN_ID"),
    (0x9b, 0x9b, "IA32_SMM_MONITOR_CTL"),
    (0xc1, 0xc8, "IA32_PMCx"),
    (0xe7, 0xe7, "IA32_MPERF"),
    (0xe8, 0xe8, "IA32_APERF"),
    (0xfe, 0xfe, "IA32_MTRRCAP"),
    (0x10a, 0x10a, "IA32_ARCH_CAPABILITIES"),
    (0x174, 0x174, "IA32_SYSENTER_CS"),
    (0x175, 0x175, "IA32_SYSENTER_ESP"),
    (0x176, 0x176, "IA32_SYSENTER_EIP"),
    (0x186, 0x18d, "IA32_PERFEVTSELx"),
    (0x1a0, 0x1a0, "IA32_MISC_ENABLE"),
    (0x1d9, 0x1d9, "IA32_DEBUGCTL"),
    (0x200, 0x21f, "IA32_MTRR_PHYSBASE/MASKx"),
    (0x250, 0x26f, "IA32_MTRR_FIXx"),
    (0x277, 0x277, "IA32_PAT"),
    (0x2ff, 0x2ff, "IA32_MTRR_DEF_TYPE"),
    (0x38f, 0x38f, "IA32_PERF_GLOBAL_CTRL"),
    (0x400, 0x47f, "IA32_MCi"),
    (0x480, 0x493, "IA32_VMX_*"),
    (0x6a0, 0x6a0, "IA32_U_CET"),
    (0x6a2, 0x6a2, "IA32_S_CET"),
    (0x6a4, 0x6a7, "IA32_PLx_SSP"),
    (0x6a8, 0x6a8, "IA32_INTERRUPT_SSP_TABLE_ADDR"),
    (0x6e0, 0x6e0, "IA32_TSC_DEADLINE"),
    (0x800, 0x8ff, "x2APIC"),
    (0xda0, 0xda0, "IA32_XSS"),
    (0xc000_0080, 0xc000_0080, "IA32_EFER"),
    (0xc000_0081, 0xc000_0081, "IA32_STAR"),
    (0xc000_0082, 0xc000_0082, "IA32_LSTAR"),
    (0xc000_0083, 0xc000_0083, "IA32_CSTAR"),
    (0xc000_0084, 0xc000_0084, "IA32_FMASK"),
    (0xc000_0100, 0xc000_0100, "IA32_FS_BASE"),
    (0xc000_0101, 0xc000_0101, "IA32_GS_BASE"),
    (0xc000_0102, 0xc000_0102, "IA32_KERNEL_GS_BASE"),
    (0xc000_0103, 0xc000_0103, "IA32_TSC_AUX"),
];

/// The names [`MSR_NAMES`] has for any MSR in `first..=last`.
pub fn msr_names(first: u32, last: u32) -> Vec<&'static str> {
    MSR_NAMES
        .iter()
        .filter(|&&(low, high, _)| low <= last && first <= high)
        .map(|&(.., name)| name)
        .collect()
}

/// The names [`MSR_NAMES`] has whose every MSR is in none of the inclusive
/// `intercepted` ranges: those the guest accesses without an exit.
pub fn msr_names_outside(intercepted: &[(u32, u32)]) -> Vec<&'static str> {
    MSR_NAMES
        .iter()
        .filter(|&&(low, high, _)| {
            intercepted
                .iter()
                .all(|&(first, last)| high < first || last < low)
        })
        .map(|&(.., name)| name)
        .collect()
}

/// The runs of set bits in `bitmap`, as inclusive `(first, last)` numbers,
/// bit 0 of byte 0 being `base`.
pub fn set_ranges(bitmap: &[u8], base: u32) -> Vec<(u32, u32)> {
    let mut ranges: Vec<(u32, u32)> = Vec::new();
    for (index, byte) in bitmap.iter().enumerate() {
        for bit in 0..8 {
            if byte & (1 << bit) == 0 {
                continue;
            }
            let number = base + (index as u32) * 8 + bit;
            match ranges.last_mut() {
                Some((_, last)) if *last + 1 == number => *last = number,
                _ => ranges.push((number, number)),
            }
        }
    }
    ranges
}

/// The primary processor-based controls (Intel SDM 25.6.2) that decide which
/// MSR and I/O accesses exit.
const UNCONDITIONAL_IO_EXITING: u64 = 1 << 24;
const USE_IO_BITMAPS: u64 = 1 << 25;
const USE_MSR_BITMAPS: u64 = 1 << 28;
/// The first MSR of the high half the MSR bitmap covers (0xc0000000-0xc0001fff).
const HIGH_MSRS: u32 = 0xc000_0000;

/// Which RDMSRs and WRMSRs exit, by an eVMCS's controls and MSR bitmap.
#[derive(Debug, PartialEq, Eq)]
pub enum MsrIntercepts {
    /// The controls use no MSR bitmap: every RDMSR and WRMSR exits.
    Every,
    /// The MSR bitmap at physical address `bitmap`: the inclusive ranges of
    /// MSRs whose reads, and whose writes, exit. MSRs outside the two halves
    /// it covers (0x0-0x1fff and 0xc0000000-0xc0001fff) always exit.
    Bitmap {
        bitmap: u64,
        read: Vec<(u32, u32)>,
        write: Vec<(u32, u32)>,
    },
}

/// Which I/O instructions exit, by an eVMCS's controls and I/O bitmaps.
#[derive(Debug, PartialEq, Eq)]
pub enum IoIntercepts {
    /// No I/O bitmaps and no unconditional I/O exiting: none exits.
    None,
    /// No I/O bitmaps, but unconditional I/O exiting: every one exits.
    Every,
    /// I/O bitmaps A (ports 0-0x7fff) and B: the inclusive port ranges whose
    /// accesses exit.
    Bitmaps { ports: Vec<(u32, u32)> },
}

/// The RDMSR and WRMSR intercepts of the eVMCS `vmcs`, whose MSR bitmap
/// `read_physical` reads.
pub fn msr_intercepts(
    vmcs: &[u8],
    read_physical: impl FnOnce(u64, &mut [u8]) -> Result<()>,
) -> Result<MsrIntercepts> {
    let controls = field(vmcs, "cpu_based_vm_exec_control").unwrap_or(0);
    if controls & USE_MSR_BITMAPS == 0 {
        return Ok(MsrIntercepts::Every);
    }
    let bitmap = field(vmcs, "msr_bitmap").unwrap_or(0);
    let mut page = vec![0u8; 0x1000];
    read_physical(bitmap, &mut page)
        .map_err(|error| Error::DebugInfo(format!("the MSR bitmap at {bitmap:#x}: {error}")))?;
    // Read low, read high, write low, write high (Intel SDM 25.6.9).
    let quarter = |index: usize, base| set_ranges(&page[index * 0x400..][..0x400], base);
    let mut read = quarter(0, 0);
    read.extend(quarter(1, HIGH_MSRS));
    let mut write = quarter(2, 0);
    write.extend(quarter(3, HIGH_MSRS));
    Ok(MsrIntercepts::Bitmap {
        bitmap,
        read,
        write,
    })
}

/// The I/O instruction intercepts of the eVMCS `vmcs`, whose I/O bitmaps
/// `read_physical` reads.
pub fn io_intercepts(
    vmcs: &[u8],
    mut read_physical: impl FnMut(u64, &mut [u8]) -> Result<()>,
) -> Result<IoIntercepts> {
    let controls = field(vmcs, "cpu_based_vm_exec_control").unwrap_or(0);
    if controls & USE_IO_BITMAPS == 0 {
        return Ok(if controls & UNCONDITIONAL_IO_EXITING == 0 {
            IoIntercepts::None
        } else {
            IoIntercepts::Every
        });
    }
    let mut ports = Vec::new();
    for (name, base) in [("io_bitmap_a", 0u32), ("io_bitmap_b", 0x8000)] {
        let address = field(vmcs, name).unwrap_or(0);
        let mut page = vec![0u8; 0x1000];
        read_physical(address, &mut page)
            .map_err(|error| Error::DebugInfo(format!("{name} at {address:#x}: {error}")))?;
        ports.extend(set_ranges(&page, base));
    }
    Ok(IoIntercepts::Bitmaps { ports })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An eVMCS page with `fields` set.
    fn vmcs_with(fields: &[(&str, u64)]) -> Vec<u8> {
        let mut page = vec![0u8; 0x1000];
        for (name, value) in fields {
            let &(_, offset, size) = EVMCS_FIELDS
                .iter()
                .find(|(field, ..)| field == name)
                .unwrap();
            let offset = usize::from(offset);
            page[offset..offset + usize::from(size)]
                .copy_from_slice(&value.to_le_bytes()[..usize::from(size)]);
        }
        page
    }

    /// The MSR bitmap's four kilobyte quarters are read low, read high,
    /// write low and write high, so one bit in each lands in its own list
    /// at its own half; without the control, every access exits.
    #[test]
    fn msr_bitmap_quarters_split_reads_from_writes_and_low_from_high() {
        let vmcs = vmcs_with(&[
            ("cpu_based_vm_exec_control", USE_MSR_BITMAPS),
            ("msr_bitmap", 0x5000),
        ]);
        let intercepts = msr_intercepts(&vmcs, |address, page| {
            assert_eq!(address, 0x5000);
            page[0x10 / 8] = 1 << (0x10 % 8); // read 0x10 (IA32_TIME_STAMP_COUNTER)
            page[0x400 + 0x80 / 8] = 1; // read 0xc0000080 (IA32_EFER)
            page[0x800 + 0x1b] = 1 << 3; // write 0xdb
            page[0xc00 + 0x20] = 1; // write 0xc0000100 (IA32_FS_BASE)
            Ok(())
        })
        .unwrap();
        assert_eq!(
            intercepts,
            MsrIntercepts::Bitmap {
                bitmap: 0x5000,
                read: vec![(0x10, 0x10), (0xc000_0080, 0xc000_0080)],
                write: vec![(0xdb, 0xdb), (0xc000_0100, 0xc000_0100)],
            }
        );
        let no_bitmap = vmcs_with(&[("msr_bitmap", 0x5000)]);
        assert_eq!(
            msr_intercepts(&no_bitmap, |_, _| panic!("no bitmap to read")).unwrap(),
            MsrIntercepts::Every
        );
    }

    /// Bitmap B starts at port 0x8000; without bitmaps, unconditional I/O
    /// exiting decides between every port and none.
    #[test]
    fn io_bitmap_b_covers_the_upper_ports_and_the_controls_decide_without_bitmaps() {
        let vmcs = vmcs_with(&[
            ("cpu_based_vm_exec_control", USE_IO_BITMAPS),
            ("io_bitmap_a", 0x6000),
            ("io_bitmap_b", 0x7000),
        ]);
        let intercepts = io_intercepts(&vmcs, |address, page| {
            match address {
                0x6000 => page[0x60 / 8] = 0b0001_0001, // 0x60 and 0x64
                0x7000 => page[0] = 1,                  // 0x8000
                other => panic!("read of {other:#x}"),
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(
            intercepts,
            IoIntercepts::Bitmaps {
                ports: vec![(0x60, 0x60), (0x64, 0x64), (0x8000, 0x8000)],
            }
        );
        let read = |_: u64, _: &mut [u8]| -> Result<()> { panic!("no bitmap to read") };
        let unconditional = vmcs_with(&[("cpu_based_vm_exec_control", UNCONDITIONAL_IO_EXITING)]);
        assert_eq!(
            io_intercepts(&unconditional, read).unwrap(),
            IoIntercepts::Every
        );
        assert_eq!(
            io_intercepts(&vmcs_with(&[]), read).unwrap(),
            IoIntercepts::None
        );
    }

    /// An intercepted range is named by every known MSR or block it
    /// touches, a block it covers only part of included, but not by one it
    /// only borders.
    #[test]
    fn an_msr_range_is_named_by_what_it_overlaps() {
        assert_eq!(msr_names(0x7, 0x16), ["IA32_TIME_STAMP_COUNTER"]);
        assert_eq!(msr_names(0x802, 0x83f), ["x2APIC"]);
        assert_eq!(msr_names(0x8ff, 0x900), ["x2APIC"]);
        assert!(msr_names(0x11, 0x1a).is_empty());
        assert_eq!(
            msr_names(0xc000_0080, 0xc000_0081),
            ["IA32_EFER", "IA32_STAR"]
        );
        let intercepted = [(0x0, 0x47), (0x4a, 0x8ff), (0xc000_0000, 0xc000_00ff)];
        assert_eq!(
            msr_names_outside(&intercepted)[..3],
            ["IA32_SPEC_CTRL", "IA32_PRED_CMD", "IA32_XSS"]
        );
        assert!(!msr_names_outside(&intercepted).contains(&"x2APIC"));
    }

    #[test]
    fn set_bits_become_runs_offset_by_the_base() {
        let mut bitmap = [0u8; 4];
        bitmap[0] = 0b1000_0110;
        bitmap[1] = 0b0000_0001;
        bitmap[3] = 0b1000_0000;
        assert_eq!(
            set_ranges(&bitmap, 0xc000_0000),
            [
                (0xc000_0001, 0xc000_0002),
                (0xc000_0007, 0xc000_0008),
                (0xc000_001f, 0xc000_001f)
            ]
        );
    }
}
