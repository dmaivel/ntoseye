//! Kernel code where a debug trap that Windows takes itself, as it takes
//! KD's single steps and breakpoints, brings the kernel down instead of
//! reaching the debugger.

use std::collections::{HashSet, VecDeque};
use std::ops::Range;

use iced_x86::{Decoder, DecoderOptions, OpKind};

use super::Target;
use crate::base::disasm::function_extent;
use crate::base::memory::MemoryOps;
use crate::base::types::{Arch, CodeMachine, VirtAddr};
use crate::nt::unwind::{ThreadTraceContext, function_range, resolve_thread_trace_context};

/// The trap handlers a breakpoint or single-step trap enters, and the
/// dispatcher they hand it to, which reports it to the debugger.
const DISPATCH_ROOTS: [&str; 4] = [
    "KiBreakpointTrap",
    "KiDebugTrapOrFault",
    "KiExceptionDispatch",
    "KiDispatchException",
];

/// Where the dispatch hands a trap to the debugger. Its own code is on the
/// path, but what it calls is KD's, which runs only for a trap; and the
/// dispatcher's code after it runs once the debugger let the trap go.
const DEBUGGER_ENTRY: &str = "KdTrap";

/// Paths the dispatch takes only to bugcheck, on which a trap is fatal anyway.
const BUGCHECK: [&str; 2] = ["KeBugCheckEx", "KeBugCheck2"];

/// Bounds on the walk for the dispatch code: a few dozen functions are on it.
const MAX_DISPATCH_FUNCTIONS: usize = 256;
const MAX_FUNCTION_BYTES: u64 = 64 * 1024;

impl Target {
    /// Why a debug trap at `address` must not reach Windows, for `what`
    /// takes one there ("a single step", "a breakpoint"): the address is in
    /// the kernel's user/kernel transition code (see
    /// [`Guest::kernel_transition_code`]). `None` anywhere else.
    ///
    /// [`Guest::kernel_transition_code`]: crate::nt::guest::Guest::kernel_transition_code
    pub fn kernel_transition_refusal(&self, address: VirtAddr, what: &str) -> Option<String> {
        if !self
            .guest
            .as_ref()?
            .kernel_transition_code()?
            .contains(&address)
        {
            return None;
        }
        Some(format!(
            "{} is in ntoskrnl's KVASCODE section, the code that switches between user and \
             kernel mode; Windows cannot take a debug exception there (it bugchecks with \
             UNEXPECTED_KERNEL_MODE_TRAP), so {what} cannot be taken over KD. Resume with g, or \
             stop before the transition or in user mode",
            self.trap_site_name(address)
        ))
    }

    /// Why a breakpoint at `address`, software or a debug register, must not
    /// reach Windows: the address is in the kernel's transition code (see
    /// [`Self::kernel_transition_refusal`]), or in the code that Windows runs
    /// to dispatch a trap before it reports the trap to the debugger. Every
    /// trap runs that code, a trap on the breakpoint too, which then traps
    /// again, until the kernel stack overflows into a double fault. A single
    /// step there is taken: the trap flag is clear while the trap is
    /// dispatched.
    pub fn breakpoint_site_refusal(&self, address: VirtAddr) -> Option<String> {
        if let Some(refusal) = self.kernel_transition_refusal(address, "a breakpoint") {
            return Some(refusal);
        }
        let code = self
            .guest
            .as_ref()?
            .trap_dispatch_code(|| self.find_trap_dispatch_code());
        let index = code.partition_point(|range| range.end <= address);
        code.get(index).filter(|range| range.contains(&address))?;
        Some(format!(
            "{} is in code that Windows runs to dispatch a debug trap before it reports the trap \
             to KD (from nt!KiBreakpointTrap and nt!KiDebugTrapOrFault to nt!KdTrap); a \
             breakpoint there traps again while each trap is dispatched, until the stack \
             overflows (bugcheck UNEXPECTED_KERNEL_MODE_TRAP), so it cannot be set over KD",
            self.trap_site_name(address)
        ))
    }

    fn trap_site_name(&self, address: VirtAddr) -> String {
        self.symbols
            .format_closest_symbol_for_address(self.kernel_dtb(), address)
            .map_or_else(
                || format!("{:#x}", address.0),
                |symbol| format!("{symbol} ({:#x})", address.0),
            )
    }

    /// The code a trap runs through before the dispatch reports it to the
    /// debugger, as sorted, disjoint ranges: the functions of
    /// [`DISPATCH_ROOTS`] and every function they branch to directly, and
    /// those functions' own, with the bugcheck paths left out, and
    /// [`DEBUGGER_ENTRY`] without what it calls. The dispatcher's branches
    /// count only up to its first call of the debugger. Empty without the
    /// kernel's symbols, or on ARM64, whose traps go through other code.
    fn find_trap_dispatch_code(&self) -> Vec<Range<VirtAddr>> {
        let Ok(guest) = self.guest() else {
            return Vec::new();
        };
        match self.arch() {
            Arch::Amd64 => {}
            Arch::Arm64 => return Vec::new(),
        }
        let address = |name: &str| guest.ntoskrnl.symbol(name).ok().map(|s| s.address().0);
        let debugger_entry = address(DEBUGGER_ENTRY);
        let dispatcher = address("KiDispatchException");
        let excluded: HashSet<u64> = BUGCHECK.into_iter().filter_map(address).collect();
        let trace = resolve_thread_trace_context(self, self.kernel_dtb());
        let memory = self.address_space(self.kernel_dtb());
        let mut queue: VecDeque<u64> = DISPATCH_ROOTS
            .into_iter()
            .chain([DEBUGGER_ENTRY])
            .filter_map(address)
            .collect();
        let mut seen = HashSet::new();
        let mut ranges = Vec::new();
        while let Some(entry) = queue.pop_front() {
            if ranges.len() >= MAX_DISPATCH_FUNCTIONS || !seen.insert(entry) {
                continue;
            }
            let Some(function) = self.kernel_function_at(&trace, entry) else {
                continue;
            };
            let mut code = vec![0u8; (function.end - function.start) as usize];
            ranges.push(function.clone());
            if memory
                .read_bytes(VirtAddr(function.start), &mut code)
                .is_err()
                || Some(entry) == debugger_entry
            {
                continue;
            }
            let decoder = Decoder::with_ip(64, &code, function.start, DecoderOptions::NONE);
            for instruction in decoder {
                if instruction.op0_kind() != OpKind::NearBranch64 {
                    continue;
                }
                let target = instruction.near_branch_target();
                if Some(function.start) == dispatcher && Some(target) == debugger_entry {
                    break;
                }
                if !function.contains(&target) && !excluded.contains(&target) {
                    queue.push_back(target);
                }
            }
        }
        ranges.sort_by_key(|range| range.start);
        let mut merged: Vec<Range<u64>> = Vec::with_capacity(ranges.len());
        for range in ranges {
            match merged.last_mut() {
                Some(last) if range.start <= last.end => last.end = last.end.max(range.end),
                _ => merged.push(range),
            }
        }
        merged
            .into_iter()
            .map(|range| VirtAddr(range.start)..VirtAddr(range.end))
            .collect()
    }

    /// The kernel function `address` is in: its runtime function entry, or
    /// for a leaf, which has none, the code its symbol's control flow reaches.
    fn kernel_function_at(&self, trace: &ThreadTraceContext, address: u64) -> Option<Range<u64>> {
        if let Some((start, end)) = function_range(self, trace, address)
            && end > start
            && end - start <= MAX_FUNCTION_BYTES
        {
            return Some(start..end);
        }
        let (start, limit) = self
            .symbols
            .symbol_span(self.kernel_dtb(), VirtAddr(address))?;
        let mut code = vec![0u8; (limit.0 - start.0).min(MAX_FUNCTION_BYTES) as usize];
        self.address_space(self.kernel_dtb())
            .read_bytes(start, &mut code)
            .ok()?;
        let length = function_extent(&code, start.0, CodeMachine::Amd64)?;
        let end = start.0 + length as u64;
        (address < end).then_some(start.0..end)
    }
}
