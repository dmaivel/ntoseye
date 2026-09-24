use crate::layout::StructRef;
use crate::target::Target;
use crate::types::VirtAddr;

const KUSER_SHARED_DATA: VirtAddr = VirtAddr::from_u64(0xffff_f780_0000_0000);

/// The kernel's `KUSER_SHARED_DATA` page, resolved once for a batch of
/// reads. Every read is best-effort: a missing kernel, layout, field or
/// mapping yields `None` for that field alone.
pub struct KuserSharedData<'a>(Option<StructRef<'a>>);

impl<'a> KuserSharedData<'a> {
    pub fn new(target: &'a Target) -> Self {
        Self(target.guest().ok().and_then(|guest| {
            guest
                .ntoskrnl
                .types()
                .struct_at("_KUSER_SHARED_DATA", KUSER_SHARED_DATA)
                .ok()
        }))
    }

    fn u64_field(&self, name: &str) -> Option<u64> {
        self.0.as_ref()?.read_field::<u64>(name).ok()
    }

    fn u32_field(&self, name: &str) -> Option<u64> {
        self.0.as_ref()?.read_field::<u32>(name).ok().map(u64::from)
    }

    pub fn interrupt_time(&self) -> Option<u64> {
        self.u64_field("InterruptTime")
    }

    pub fn system_time(&self) -> Option<u64> {
        self.u64_field("SystemTime")
    }

    pub fn nt_major_version(&self) -> Option<u64> {
        self.u32_field("NtMajorVersion")
    }

    pub fn nt_minor_version(&self) -> Option<u64> {
        self.u32_field("NtMinorVersion")
    }

    pub fn nt_build_number(&self) -> Option<u64> {
        self.u32_field("NtBuildNumber")
    }

    pub fn nt_product_type(&self) -> Option<u64> {
        self.u32_field("NtProductType")
    }
}
