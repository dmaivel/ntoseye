use tabled::builder::Builder;

use crate::error::{Error, Result};
use crate::repl::*;
use crate::ui;

repl_command! {
    cmd_vtl;
    names: [".vtl"],
    usage: ".vtl [0|1 [pid]]",
    summary: "Select NT (VTL0) or secure-kernel (VTL1) inspection.",
    details: "VTL1 requires AMD64 direct host memory. It changes reads and symbol scope, not the CPU's VTL. An optional decimal NT PID selects a trustlet's root. VTL1 scope supports read-only inspection; use .vtl 0 before registers, execution control, breakpoints, or NT-specific extensions.",
}

repl_command! {
    cmd_trustlets();
    names: ["!trustlets"],
    usage: "!trustlets",
    summary: "List validated VTL1 processes with their NT identities and translation roots.",
    details: "Reads SkpsProcessList through the secure kernel's page tables. Unsupported internal layouts fail rather than guessing offsets. Does not switch scope.",
}

/// VTL1 is an explicit inspection scope, not a claim that the backend is
/// stopped in VTL1. Only scope-aware readers and debugger-local commands are
/// admitted; in particular, no VTL0 register file or mediated write may be
/// interpreted as belonging to the secure kernel. Aliases pass this same gate.
pub(super) fn secure_inspection_command(spec: &CommandSpec) -> bool {
    matches!(
        spec.names[0],
        ".vtl"
            | "!trustlets"
            | ".process"
            | "attach"
            | "detach"
            | ".context"
            | "db"
            | "dw"
            | "dW"
            | "dc"
            | "dd"
            | "dq"
            | "dp"
            | "dds"
            | "dqs"
            | "dyb"
            | "dpp"
            | "da"
            | "du"
            | "ds"
            | "dS"
            | "u"
            | "uf"
            | "ub"
            | "dt"
            | "dl"
            | "!list"
            | "x"
            | "ln"
            | "?"
            | "set"
            | "vars"
            | "unset"
            | "lm"
            | "lmv"
            | ".reload"
            | "ld"
            | ".fetchimage"
            | ".sympath"
            | ".sympath+"
            | ".symfix"
            | ".srcpath"
            | ".srcpath+"
            | "n"
            | ".effmach"
            | ".echo"
            | ".printf"
            | ".cls"
            | ".logopen"
            | ".logappend"
            | ".logclose"
            | ".hh"
            | "!error"
            | "q"
            | "capabilities"
    )
}

impl ReplState<'_> {
    /// Return to VTL0 before a VTL0 selection (`.vtl 0`, `.process`, `attach`,
    /// `detach`, `.context`). Entering VTL1 dropped the register cache so no
    /// VTL0 register could be read as VTL1 state; put the live file back.
    pub(super) fn leave_vtl1(&mut self) {
        if self.ctx.target.in_secure_scope() {
            self.ctx.target.leave_secure_scope();
            self.ctx.restore_live_register_cache();
            self.caches.refresh_symbol_context(&self.ctx.target);
        }
    }

    fn cmd_vtl(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if let Err(error) = self.select_vtl(invocation) {
            error!("{error}");
        }
        Ok(())
    }

    fn select_vtl(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        match (invocation.arg(0), invocation.arg(1), invocation.argv.len()) {
            (None, _, _) => {}
            (Some("0"), None, 1) => {
                self.leave_vtl1();
            }
            (Some("1"), pid, count) if count <= 2 => {
                let pid = pid
                    .map(|text| {
                        text.parse::<u64>().map_err(|_| {
                            Error::InvalidArgument("trustlet PID must be decimal".to_string())
                        })
                    })
                    .transpose()?;
                let report = self.ctx.target.select_secure_scope(pid)?;
                print_module_symbol_report(&report);
                self.clear_selected_frame();
                self.caches.refresh_symbol_context(&self.ctx.target);
            }
            _ => {
                return Err(Error::InvalidArgument(
                    "usage: .vtl [0|1 [pid]]".to_string(),
                ));
            }
        }
        let target = &self.ctx.target;
        if target.in_secure_scope() {
            let secure = target.secure_kernel()?;
            outln!(
                "VTL1 inspection: DTB {}, securekernel {} (system DTB {})\n",
                ui::addr(target.current_dtb()),
                ui::addr(secure.image.base_address.0),
                ui::addr(secure.image.dtb())
            );
        } else {
            outln!("VTL0 inspection: DTB {}\n", ui::addr(target.current_dtb()));
        }
        Ok(())
    }

    fn cmd_trustlets(&mut self) -> Result<()> {
        let processes = match self.ctx.target.trustlets() {
            Ok(processes) => processes,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let mut table = Builder::default();
        table.push_record(["SK process", "NT PID", "Image", "Trustlet ID", "DTB"]);
        for process in processes {
            table.push_record([
                ui::addr(process.process.0),
                process.pid.to_string(),
                process.name,
                process.trustlet_id.to_string(),
                ui::addr(process.dtb),
            ]);
        }
        print_padded_table(table);
        Ok(())
    }
}
