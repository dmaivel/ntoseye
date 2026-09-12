use crate::target::Target;
use crate::types::VirtAddr;

const KUSER_SHARED_DATA: VirtAddr = VirtAddr::from_u64(0xffff_f780_0000_0000);

fn read_u64_field(target: &Target, name: &str) -> Option<u64> {
    target
        .guest()
        .ok()?
        .ntoskrnl
        .types()
        .struct_at("_KUSER_SHARED_DATA", KUSER_SHARED_DATA)
        .ok()?
        .read_field::<u64>(name)
        .ok()
}

fn read_u32_field(target: &Target, name: &str) -> Option<u64> {
    target
        .guest()
        .ok()?
        .ntoskrnl
        .types()
        .struct_at("_KUSER_SHARED_DATA", KUSER_SHARED_DATA)
        .ok()?
        .read_field::<u32>(name)
        .ok()
        .map(u64::from)
}

pub fn read_interrupt_time(target: &Target) -> Option<u64> {
    read_u64_field(target, "InterruptTime")
}

pub fn read_system_time(target: &Target) -> Option<u64> {
    read_u64_field(target, "SystemTime")
}

pub fn read_nt_major_version(target: &Target) -> Option<u64> {
    read_u32_field(target, "NtMajorVersion")
}

pub fn read_nt_minor_version(target: &Target) -> Option<u64> {
    read_u32_field(target, "NtMinorVersion")
}

pub fn read_nt_build_number(target: &Target) -> Option<u64> {
    read_u32_field(target, "NtBuildNumber")
}

pub fn read_nt_product_type(target: &Target) -> Option<u64> {
    read_u32_field(target, "NtProductType")
}
