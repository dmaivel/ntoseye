//! Breakpoint specifications and resolution state: parsing `file:line` and
//! `[module!]symbol[+off]` specs, resolving them to addresses, and what a
//! code breakpoint is planted on.

use super::{Breakpoint, BreakpointSpec};
use crate::error::Result;
use crate::expr::{Expr, NumberRadix};
use crate::target::Target;
use crate::types::{Dtb, VirtAddr};

/// What a code breakpoint is planted on, which decides whether it can wait
/// for a module to load and whether it outlives its first hit.
pub(super) enum CodeSite {
    /// A fixed address, labelled with the symbol it was typed as, if any.
    Address {
        address: VirtAddr,
        symbol: Option<String>,
    },
    /// A symbol or source line, installed at `address` once it resolves and
    /// deferred until then.
    Spec {
        spec: BreakpointSpec,
        address: Option<VirtAddr>,
    },
    /// An internal stop the debugger removes once it is hit.
    Temporary(VirtAddr),
}

impl BreakpointSpec {
    pub fn source(raw: &str, address_index: usize) -> Option<Self> {
        let (file, line) = raw.rsplit_once(':')?;
        let line = line.parse().ok()?;
        (!file.is_empty()).then(|| Self::Source {
            raw: raw.to_string(),
            file: file.to_string(),
            line,
            address_index,
        })
    }

    pub fn label(&self) -> &str {
        match self {
            Self::Symbol { name, .. } => name,
            Self::Source { raw, .. } => raw,
        }
    }

    pub(super) fn resolve(&self, debugger: &Target, dtb: Dtb) -> Result<Option<VirtAddr>> {
        match self {
            Self::Symbol {
                name,
                skip_prologue,
            } => {
                let Some((address, offset)) = Self::resolve_symbol_offset(debugger, dtb, name)?
                else {
                    return Ok(None);
                };
                // An explicit offset names the exact instruction, so the
                // prologue skip a host asked for does not apply to it.
                if !skip_prologue || offset != 0 {
                    return Ok(Some(address));
                }
                Ok(Some(
                    debugger
                        .post_prologue_address(dtb, address)
                        .unwrap_or(address),
                ))
            }
            Self::Source {
                file,
                line,
                address_index,
                ..
            } => Ok(debugger
                .symbols
                .source_addresses(dtb, file, *line)
                .get(*address_index)
                .copied()),
        }
    }

    /// Resolve a deferred name, which WinDbg allows to carry an offset
    /// (`bu mod!sym+0x29`). The symbol half is what a module load makes
    /// available, so it is looked up in the breakpoint's own address space
    /// and the offset applied afterwards. Returns the resolved address and
    /// the offset that was applied. Hosts resolving a `[module!]symbol[+off]`
    /// spec (the SDK's `run_to`, watchpoints) share it.
    pub fn resolve_symbol_offset(
        debugger: &Target,
        dtb: Dtb,
        name: &str,
    ) -> Result<Option<(VirtAddr, i64)>> {
        if let Some(address) = debugger.symbols.find_symbol_across_modules(dtb, name)? {
            return Ok(Some((address, 0)));
        }
        let Some((symbol, offset)) = Self::split_symbol_offset(name) else {
            return Ok(None);
        };
        let Some(base) = debugger
            .symbols
            .find_symbol_across_modules(dtb, symbol.trim())?
        else {
            return Ok(None);
        };
        Ok(Some((VirtAddr(base.0.wrapping_add(offset as u64)), offset)))
    }

    /// Split `symbol+0x29` or `symbol-8` into its symbol and signed offset.
    /// The offset is a hexadecimal numeric literal.
    fn split_symbol_offset(name: &str) -> Option<(&str, i64)> {
        let (separator, position) = ['+', '-']
            .into_iter()
            .filter_map(|separator| name.rfind(separator).map(|at| (separator, at)))
            .max_by_key(|(_, at)| *at)?;
        if position == 0 {
            return None;
        }
        let (symbol, tail) = name.split_at(position);
        let literal = &tail[separator.len_utf8()..];
        // Only a literal offset: a deferred breakpoint has to mean the same
        // address every time its module loads, so registers and memory reads
        // have no business here.
        let offset = match Expr::parse_with_radix(literal, NumberRadix::Hexadecimal).ok()? {
            Expr::Literal(value) => i64::try_from(value.0).ok()?,
            _ => return None,
        };
        Some((symbol, if separator == '-' { -offset } else { offset }))
    }
}

impl Breakpoint {
    pub fn resolved_address(&self) -> Option<VirtAddr> {
        self.resolved.then_some(self.address)
    }

    pub fn deferred(&self) -> bool {
        self.spec.is_some() && !self.resolved
    }

    pub fn specification(&self) -> Option<&str> {
        self.spec.as_ref().map(BreakpointSpec::label)
    }
}

#[cfg(test)]
mod tests {
    use crate::breakpoints::BreakpointSpec;
    use crate::session::session_over_memory;
    use crate::types::VirtAddr;

    #[test]
    fn deferred_symbol_specs_apply_their_offset() {
        let session = session_over_memory(0x1000, &[0u8; 0x80]);
        let dtb = session.target.current_dtb();
        session.target.symbols.set_kernel(Some(1), dtb);
        session
            .target
            .symbols
            .inject_module_for_test(1, Vec::new(), &[("DriverEntry", 0)]);
        session.target.symbols.inject_source_lines_for_test(
            1,
            dtb,
            VirtAddr(0x1000),
            0x1000,
            "driver.c",
            &[],
        );

        let resolve = |name: &str| {
            BreakpointSpec::Symbol {
                name: name.to_string(),
                skip_prologue: false,
            }
            .resolve(&session.target, dtb)
            .unwrap()
        };

        assert_eq!(resolve("driver!DriverEntry"), Some(VirtAddr(0x1000)));
        assert_eq!(resolve("driver!DriverEntry+0x29"), Some(VirtAddr(0x1029)));
        // Deferred offsets are hexadecimal even without an explicit prefix.
        assert_eq!(resolve("driver!DriverEntry+29"), Some(VirtAddr(0x1029)));
        assert_eq!(resolve("driver!DriverEntry+0n16"), Some(VirtAddr(0x1010)));
        assert_eq!(resolve("driver!DriverEntry-8"), Some(VirtAddr(0xff8)));
        // An absent symbol stays deferred rather than resolving to the bare
        // offset.
        assert_eq!(resolve("driver!Missing+0x10"), None);
        assert_eq!(resolve("absent!DriverEntry+0x10"), None);
    }
}
