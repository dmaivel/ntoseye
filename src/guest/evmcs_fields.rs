//! The fields of an Enlightened VMCS, by name, offset, and size: the Hyper-V
//! TLFS layout (Linux `struct hv_enlightened_vmcs`), padding left out.

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

#[cfg(test)]
mod tests {
    use super::*;

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
