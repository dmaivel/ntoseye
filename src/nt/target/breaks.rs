//! The breaks Windows makes on purpose: an `int3` in its own code that it
//! executes to get the debugger's attention, when something it watches for
//! happens. A stop there says what that is.

use crate::base::memory::MemoryOps;
use crate::base::types::VirtAddr;
use crate::nt::unwind::nearest_symbol;

use super::Target;

/// The kernel functions whose own `int3` is a deliberate break, and why it
/// is made.
const WINDOWS_BREAKS: [(&str, &str); 1] = [(
    "ExpWaitForResource",
    "Windows broke in because a thread waited for an executive resource (ERESOURCE) longer \
     than the resource timeout; !locks shows the resources that are held, and their owners",
)];

impl Target {
    /// Why Windows broke in at `rip`, when it is an `int3` in one of the
    /// kernel functions that make one on purpose; `None` anywhere else.
    pub fn windows_break_reason(&self, rip: VirtAddr) -> Option<&'static str> {
        if !self.arch().paging().is_kernel_address(rip) {
            return None;
        }
        let opcode = self.arch().breakpoint_instruction();
        let mut bytes = vec![0u8; opcode.len()];
        self.kernel_address_space()
            .read_bytes(rip, &mut bytes)
            .ok()?;
        if bytes != opcode {
            return None;
        }
        let (module, function, _) = nearest_symbol(self, self.kernel_dtb(), rip)?;
        if !module.eq_ignore_ascii_case("nt") {
            return None;
        }
        WINDOWS_BREAKS
            .iter()
            .find(|(name, _)| *name == function)
            .map(|(_, reason)| *reason)
    }
}
