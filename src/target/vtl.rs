//! Explicit secure-kernel inspection. Selecting a VTL changes address-space
//! reads and symbol scope, not the executing processor's VTL or registers.

use std::sync::Arc;

use super::Target;
use crate::{
    error::{Error, Result},
    guest::{Guest, ModuleSymbolLoadReport, SecureKernel, SessionSpace, TrustletInfo},
};

impl Target {
    /// Whether inspection is rooted in the secure kernel or a trustlet.
    pub fn in_secure_scope(&self) -> bool {
        self.secure_root.is_some()
    }

    /// Return inspection to VTL0 without touching the process or register
    /// selection, for a stop whose context now belongs to the halted vCPU.
    pub fn leave_secure_scope(&mut self) {
        self.secure_root = None;
    }

    /// Discover the secure kernel from host RAM on first use. No target state
    /// is changed; unsupported sources and architectures return an error.
    pub fn secure_kernel(&self) -> Result<Arc<SecureKernel>> {
        self.guest()?
            .secure_kernel(&self.phys, &self.symbols, &self.interrupt)
    }

    /// Validated secure processes, correlated with the NT process list.
    pub fn trustlets(&self) -> Result<Vec<TrustletInfo>> {
        let secure = self.secure_kernel()?;
        let processes = secure.trustlets(self.guest()?)?;
        self.symbols
            .set_secure_roots(secure.image.dtb(), processes.iter().map(|p| p.dtb));
        Ok(processes)
    }

    /// Enter VTL1's system space, or a trustlet by its NT PID. The selection
    /// commits only after discovery and module loading succeed. Register and
    /// thread selections are cleared: VTL0 context is not VTL1 context.
    pub fn select_secure_scope(&mut self, pid: Option<u64>) -> Result<ModuleSymbolLoadReport> {
        let secure = self.secure_kernel()?;
        let root = if let Some(pid) = pid {
            self.trustlets()?
                .into_iter()
                .find(|p| p.pid == pid)
                .ok_or_else(|| Error::SecureKernel(format!("no trustlet with NT PID {pid}")))?
                .dtb
        } else {
            self.symbols.set_secure_roots(secure.image.dtb(), []);
            secure.image.dtb()
        };
        let modules = secure.modules(self.guest()?)?;
        let report = Guest::load_module_symbols(
            &self.phys,
            &self.symbols,
            modules,
            secure.image.dtb(),
            SessionSpace::Load,
            self.arch(),
        )?;
        self.detach();
        self.registers = None;
        self.secure_root = Some(root);
        Ok(report)
    }
}
