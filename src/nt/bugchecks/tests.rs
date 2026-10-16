use super::*;

fn info(code: u32, parameters: [u64; 4]) -> BugcheckInfo {
    BugcheckInfo {
        code,
        parameters,
        driver: None,
    }
}

#[test]
fn trap_frame_parameter_mapping_matches_descriptors() {
    let frame = 0xffff_b000_1234_5000u64;
    // PANIC_STACK_SWITCH: arg1.
    assert_eq!(
        bugcheck_trap_frame_address(&info(0x2b, [frame, 0, 0, 0])),
        Some(frame)
    );
    // SET_OF_INVALID_CONTEXT: arg3.
    assert_eq!(
        bugcheck_trap_frame_address(&info(0x30, [1, 2, frame, 0])),
        Some(frame)
    );
    // KERNEL_MODE_EXCEPTION_NOT_HANDLED: arg3.
    assert_eq!(
        bugcheck_trap_frame_address(&info(0x8e, [0xc0000005, 0, frame, 0])),
        Some(frame)
    );
    // KERNEL_SECURITY_CHECK_FAILURE: arg2.
    assert_eq!(
        bugcheck_trap_frame_address(&info(0x139, [3, frame, 0, 0])),
        Some(frame)
    );
    // KERNEL_MODE_EXCEPTION_NOT_HANDLED_M: arg3.
    assert_eq!(
        bugcheck_trap_frame_address(&info(0x1000008e, [0xc0000005, 0, frame, 0])),
        Some(frame)
    );
    // UNSUPPORTED_INSTRUCTION_MODE: arg2.
    assert_eq!(
        bugcheck_trap_frame_address(&info(0x151, [0, frame, 0, 0])),
        Some(frame)
    );
}

#[test]
fn trap_frame_requires_kernel_pointer() {
    assert_eq!(
        bugcheck_trap_frame_address(&info(0x139, [3, 0, 0, 0])),
        None
    );
    assert_eq!(
        bugcheck_trap_frame_address(&info(0x8e, [0xc0000005, 0, 0x7ffe_0000, 0])),
        None
    );
}

#[test]
fn codes_without_documented_trap_frames_yield_none() {
    let kernel_ptr = 0xffff_b000_1234_5000u64;
    for code in [0x0a, 0x1e, 0x3b, 0x50, 0x7e, 0xd1] {
        assert_eq!(
            bugcheck_trap_frame_address(&info(code, [kernel_ptr; 4])),
            None,
            "code {code:#x} must not claim a trap frame"
        );
    }
}

#[test]
fn fault_ip_parameter_mapping_matches_descriptors() {
    let parameters = [0x1111, 0x2222, 0x3333, 0x4444];
    assert_eq!(bugcheck_fault_ip(&info(0x151, parameters)), Some(0x1111));
    for code in [0x1e, 0x3b, 0x7e, 0x8e, 0x1000007e, 0x1000008e] {
        assert_eq!(bugcheck_fault_ip(&info(code, parameters)), Some(0x2222));
    }
    for code in [0x50, 0xcc, 0xcd, 0xce, 0xcf, 0xd5, 0xd6] {
        assert_eq!(bugcheck_fault_ip(&info(code, parameters)), Some(0x3333));
    }
    for code in [0x0a, 0x2e, 0xc5, 0xd0, 0xd1, 0xd3, 0xd4, 0x1ea] {
        assert_eq!(bugcheck_fault_ip(&info(code, parameters)), Some(0x4444));
    }
    assert_eq!(bugcheck_fault_ip(&info(0xdead, parameters)), None);
}

#[test]
fn conditional_argument_descriptions_follow_parameter_values() {
    assert_eq!(
        bugcheck_argument_descriptions(&info(0x77, [1, 0, 0, 0]))[1],
        "value where the kernel-stack signature should be"
    );
    assert_eq!(
        bugcheck_argument_descriptions(&info(0x77, [0xc000000e, 0, 0, 0]))[1],
        "I/O status code"
    );
    assert_eq!(
        bugcheck_argument_descriptions(&info(0x7a, [3, 0, 0, 0]))[2],
        "current process when parameter 1 is 1; zero when it is 2 or 3"
    );
    assert_eq!(
        bugcheck_argument_descriptions(&info(0x7a, [3, 0, 1, 0]))[2],
        "address of the InPageSupport structure"
    );
    assert_eq!(
        bugcheck_argument_descriptions(&info(0x7a, [5, 0, 0, 0]))[0],
        "address of the page-table entry (PTE)"
    );
    assert_eq!(
        bugcheck_argument_descriptions(&info(0x9f, [4, 0, 0, 0]))[1],
        "timeout in seconds"
    );
    assert_eq!(
        bugcheck_argument_descriptions(&info(0x12b, [0, 0, 1, 1]))[0],
        "compressed-store failure status"
    );
    assert_eq!(
        bugcheck_argument_descriptions(&info(0x131, [3, 0, 0, 0]))[1],
        "saved thread"
    );
    assert_eq!(
        bugcheck_argument_descriptions(&info(0x133, [1, 0, 0, 0]))[1],
        "watchdog period"
    );
    assert_eq!(
        bugcheck_argument_descriptions(&info(0x143, [2, 0, 0, 0]))[1],
        "invalid-state subtype"
    );
    assert_eq!(
        bugcheck_argument_descriptions(&info(0x159, [0x3001, 0, 0, 0]))[2],
        "PASID"
    );
    assert_eq!(
        bugcheck_argument_descriptions(&info(0xc4, [0xf6, 0, 0, 0]))[3],
        "address inside the driver that referenced the handle"
    );
    assert_eq!(
        bugcheck_argument_descriptions(&info(0xe6, [0x26, 0, 0, 0]))[2],
        "fault information (usually the physical address)"
    );
}

#[test]
fn minidump_aliases_reuse_base_parameter_schemas() {
    for (alias, base) in [
        (0x1000007e, 0x7e),
        (0x1000007f, 0x7f),
        (0x1000008e, 0x8e),
        (0x100000ea, 0xea),
    ] {
        assert_eq!(
            bugcheck_descriptor(alias).unwrap().arguments,
            bugcheck_descriptor(base).unwrap().arguments
        );
    }
}
