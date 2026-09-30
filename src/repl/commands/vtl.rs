use tabled::builder::Builder;

use crate::error::{Error, Result};
use crate::guest::privilege_names;
use crate::repl::*;
use crate::ui;
use crate::unwind::halted_in_windows_hypervisor;

repl_command! {
    cmd_vtl;
    names: [".vtl"],
    usage: ".vtl [0|1 [pid]]",
    summary: "Select NT (VTL0) or secure-kernel (VTL1) memory inspection, or show which one is active.",
    details: "VTL1 requires AMD64 direct host memory. `.vtl 1` changes the scope of reads and symbols, but does not change the VTL of the CPU. With no argument, `.vtl` shows the current scope. `.vtl 0` goes back to the NT kernel or, at a stop in VTL1 or in the Windows hypervisor, to the address space of the vCPU, where you use `.vtlcxr` or `.thread` to select NT. `.vtl 1` selects the system address space of the secure kernel, and `.vtl 1 <pid>` selects the address space of a trustlet by its NT PID, which is always decimal. The VTL1 scope is a read-only memory view. Registers, stepping, software breakpoints, writes, and NT-specific extensions need .vtl 0. To stop in VTL1, set a hardware execute breakpoint there (`ba e1 securekernel!<function>`, GDB backends), and then resume with a plain `g`, which first goes back to the live context. A vCPU stopped in VTL1 shows its real registers, stack, and memory. With no argument, `.vtl` also shows whether reads follow such a live stop or the manual view.",
}

repl_command! {
    cmd_trustlets();
    names: ["!trustlets"],
    usage: "!trustlets",
    summary: "List the validated VTL1 processes with their NT identities and address-space roots.",
    details: "Reads SkpsProcessList through the page tables of the secure kernel. Each row shows the secure-kernel process object, the NT PID and image name, the trustlet ID, and the address-space root. If the internal layout is not supported, the command gives an error and does not guess offsets. The command does not change the scope.",
}

repl_command! {
    cmd_hvpartitions();
    names: ["!hvpartitions"],
    usage: "!hvpartitions",
    summary: "List the partitions of the Windows hypervisor, root first.",
    details: "Walks the hypervisor's partition objects from its processor blocks, which come from the eVMCS pages (the VM's hv-evmcs enlightenment) or from a vCPU stopped in the hypervisor. Each row shows the partition object, its partition ID, the parent's ID, the number of virtual processors, and the privilege mask (HV_PARTITION_PRIVILEGE_MASK). hvix64 has no public symbols, so the offsets are read off the hypervisor's own code and each object is validated before it is shown; if the layout is not recognized, the command gives an error and does not guess offsets. Intel hosts only.",
}

repl_command! {
    cmd_hvvps;
    names: ["!hvvps"],
    usage: "!hvvps [partition-id]",
    summary: "List the virtual processors of a Windows hypervisor partition (the root by default).",
    details: "Each row is one VTL enabled on a VP, and * marks the VTL the VP runs or last ran in. The row shows the hypervisor's context object for the VTL and, when found, the physical address of the VTL's eVMCS with the EPT pointer (the root of the VTL's second-level address translation), the guest RIP where the VTL left off, and why it last left for the hypervisor. The eVMCS columns need the VM's hv-evmcs enlightenment. The partition ID uses the current radix. See !hvpartitions for where the objects come from.",
}

/// Commands that only read memory through the current root or are
/// debugger-local, so they mean the same in any VTL1 address space. No VTL0
/// register file or mediated write may be interpreted as belonging to the
/// secure kernel. Aliases pass this same gate.
fn secure_inspection_command(spec: &CommandSpec) -> bool {
    matches!(
        spec.names[0],
        ".vtl"
            | "!trustlets"
            | "!hvpartitions"
            | "!hvvps"
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
            // An explicit root and a page walk; no NT state.
            | "!vtop"
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
            // Each command it runs passes this gate itself.
            | ".foreach"
            // Walks `lm`'s list, the secure kernel's in VTL1.
            | "!for_each_module"
            // Script control flow; each command it runs passes this gate.
            | ".if"
            | ".elsif"
            | ".else"
            | ".while"
            | ".for"
            | ".do"
            | ".break"
            | ".continue"
            | ".block"
            | "j"
            | "$<"
            | "$$"
            | ".sleep"
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

/// Breakpoint bookkeeping and the one resume a VTL1 stop can be reached and
/// left with. The core accepts only GDB hardware execute breakpoints in a
/// VTL1 space; software sites (`bp`, `g <address>`, stepping) would patch or
/// trap code VTL0 cannot see. `g` is refused with an address by its handler.
fn secure_hardware_workflow_command(spec: &CommandSpec) -> bool {
    matches!(
        spec.names[0],
        "ba" | "bl" | ".bpcmds" | "bc" | "bd" | "be" | "bpc" | "bs" | "br" | "bpp" | "g" | "gc"
    )
}

/// vCPU state that is genuinely VTL1's when the backend is stopped there:
/// the live register file (read-only: `r` refuses assignment), its stack,
/// frames, and the processor list. NT structures (KPCR, threads, processes)
/// stay refused because the secure kernel's state is not laid out as NT's.
fn live_secure_vcpu_command(spec: &CommandSpec) -> bool {
    matches!(
        spec.names[0],
        "r" | "kn"
            | ".frame"
            | "!for_each_frame"
            | "dv"
            | "~"
            | "vcpu"
            | "rdmsr"
            | "break"
            | "status"
            | ".lastevent"
    )
}

/// Whether the explicit `.vtl 1` scope admits `spec`. The scope is a memory
/// view, not a claim that the backend is stopped in VTL1, so it has no
/// register file: only reads, the hardware breakpoint workflow, and a plain
/// `g` (which leaves the scope before resuming) run in it.
pub fn secure_scope_admits(spec: &CommandSpec) -> bool {
    secure_inspection_command(spec) || secure_hardware_workflow_command(spec)
}

/// Whether a live stop whose read root is a VTL1 root admits `spec`: what
/// the explicit scope admits plus the real vCPU state.
pub fn live_secure_admits(spec: &CommandSpec) -> bool {
    secure_scope_admits(spec) || live_secure_vcpu_command(spec) || secure_step_command(spec)
}

/// Run control a live VTL1 stop can take without writing secure-kernel code:
/// steps run the vCPU alone to debug-register sites on an instruction's
/// successors, and run-to targets (`p` over a call, `gu`, `g <address>`)
/// in secure-kernel code take a debug-register site too. A software site
/// anywhere in VTL1 is still refused by the breakpoint core.
fn secure_step_command(spec: &CommandSpec) -> bool {
    matches!(spec.names[0], "t" | "p" | "gu" | "pa" | "ta" | "wt")
}

impl ReplState<'_> {
    /// Why the current VTL1 address space refuses `spec`, if it does. Decided
    /// on the resolved command, after alias expansion, so an alias cannot
    /// reach a write or an NT extension from VTL1.
    pub fn secure_denial(&self, spec: &CommandSpec) -> Option<String> {
        let target = &self.ctx.target;
        let name = spec.names[0];
        if target.in_secure_scope() {
            return (!secure_scope_admits(spec)).then(|| {
                format!(
                    "'{name}' is unavailable in the .vtl 1 memory view (reads, `ba e1`, and plain g \
                     only); use .vtl 0 first"
                )
            });
        }
        if target.in_secure_address_space() && !live_secure_admits(spec) {
            return Some(format!(
                "'{name}' is unavailable while the vCPU is stopped in VTL1: it needs NT state, \
                 or writes VTL1 memory, registers, or code"
            ));
        }
        None
    }

    /// Leave the explicit VTL1 scope before a VTL0 selection (`.vtl 0`,
    /// `.process`, `attach`, `detach`, `.context`) or a resume. The live
    /// register file and the root it implies come back, which is a VTL1 root
    /// again when the vCPU is stopped there.
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
        let mut live_hint = false;
        match (invocation.arg(0), invocation.arg(1), invocation.argv.len()) {
            (None, _, _) => {}
            (Some("0"), None, 1) => {
                // A live VTL1 stop has no explicit scope to leave; its root
                // follows the vCPU. Say how to read NT instead.
                live_hint = !self.ctx.target.in_secure_scope();
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
                self.ctx.clear_selected_frame();
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
                "VTL1 memory view (.vtl 1, no registers): DTB {}, securekernel {} (system DTB {})\n",
                ui::addr(target.current_dtb()),
                ui::addr(secure.image.base_address.0),
                ui::addr(secure.image.dtb())
            );
        } else if target.in_secure_address_space() {
            let secure = target.secure_kernel()?;
            outln!(
                "VTL1 live stop on vCPU {}: DTB {}, securekernel {} (system DTB {}); registers and stack are VTL1 state",
                self.ctx.current_thread,
                ui::addr(target.current_dtb()),
                ui::addr(secure.image.base_address.0),
                ui::addr(secure.image.dtb())
            );
            if live_hint {
                outln!(
                    "{}",
                    ui::muted(
                        "the vCPU is stopped in VTL1; .process or attach reads an NT address space"
                    )
                );
            }
            outln!();
        } else if let Some(rip) = target.register_value("rip")
            && halted_in_windows_hypervisor(target, target.current_dtb(), rip)
        {
            // Not VTL0: the vCPU halted in the Windows hypervisor, whose root
            // maps no NT memory.
            outln!(
                "hypervisor stop on vCPU {}: DTB {} is the Windows hypervisor's and maps no NT memory",
                self.ctx.current_thread,
                ui::addr(target.current_dtb())
            );
            outln!(
                "{}\n",
                ui::muted(".vtlcxr selects where VTL0 left off; .thread <tid> a Windows thread")
            );
        } else {
            outln!("VTL0 inspection: DTB {}\n", ui::addr(target.current_dtb()));
        }
        Ok(())
    }

    fn cmd_hvpartitions(&mut self) -> Result<()> {
        let partitions = match self.ctx.target.hypervisor_partitions() {
            Ok(partitions) => partitions,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let mut table = Builder::default();
        table.push_record(["Partition", "ID", "Parent", "VPs", "Privileges"]);
        for partition in &partitions {
            table.push_record([
                ui::addr(partition.address),
                format!("{:#x}", partition.id),
                partition
                    .parent
                    .map_or_else(|| "root".to_string(), |id| format!("{id:#x}")),
                partition.virtual_processors.len().to_string(),
                format!("{:016x}", partition.privileges),
            ]);
        }
        print_padded_table(table);
        for partition in &partitions {
            let (names, unnamed) = privilege_names(partition.privileges);
            let mut line = names.join(" ");
            if unnamed != 0 {
                line.push_str(&format!(" (+{unnamed:#x})"));
            }
            outln!("{} {}", ui::muted(&format!("{:#x}:", partition.id)), line);
        }
        outln!();
        Ok(())
    }

    fn cmd_hvvps(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if invocation.argv.len() > 1 {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        }
        let id = match invocation.arg(0) {
            Some(text) => match self.eval_or_report(text) {
                Some(value) => Some(value.0),
                None => return Ok(()),
            },
            None => None,
        };
        let partitions = match self.ctx.target.hypervisor_partitions() {
            Ok(partitions) => partitions,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let partition = match id {
            Some(id) => partitions.into_iter().find(|p| p.id == id),
            None => partitions.into_iter().next(),
        };
        let Some(partition) = partition else {
            error!("no partition with ID {:#x}", id.unwrap_or_default());
            return Ok(());
        };
        let mut table = Builder::default();
        table.push_record([
            "VP",
            "Address",
            "VTL",
            "Context",
            "eVMCS",
            "EPT pointer",
            "Guest RIP",
            "Last exit",
        ]);
        for vp in &partition.virtual_processors {
            for (row, vtl) in vp.vtls.iter().enumerate() {
                let current = if vtl.level == vp.vtl { "*" } else { "" };
                let state = vtl.state.as_ref();
                table.push_record([
                    if row == 0 {
                        vp.index.to_string()
                    } else {
                        String::new()
                    },
                    if row == 0 {
                        ui::addr(vp.address)
                    } else {
                        String::new()
                    },
                    format!("{}{current}", vtl.level),
                    ui::addr(vtl.context),
                    vtl.vmcs
                        .map_or_else(String::new, |page| format!("{page:x}")),
                    state.map_or_else(String::new, |state| format!("{:x}", state.ept_pointer)),
                    state.map_or_else(String::new, |state| ui::addr(state.rip)),
                    state
                        .and_then(|state| state.exit_reason_name())
                        .unwrap_or_default()
                        .to_string(),
                ]);
            }
        }
        print_padded_table(table);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::capture;
    use crate::session::tests::{MockBackend, session_with_mock};

    fn spec(name: &str) -> &'static CommandSpec {
        command_registry()
            .get(name)
            .unwrap_or_else(|| panic!("'{name}' is not registered"))
    }

    #[test]
    fn memory_view_admits_the_hardware_breakpoint_workflow_without_registers_or_writes() {
        for name in [
            "ba", "bl", "bc", "bd", "be", "g", "continue", "db", "u", "x", "!vtop", ".vtl",
        ] {
            assert!(secure_scope_admits(spec(name)), "'{name}' refused");
        }
        for name in [
            "bp", "bu", "bm", "gh", "gn", "t", "p", "gu", "pa", "wt", "r", "k", ".frame", "~",
            "vcpu", "eb", "ed", "f", ".readmem", "!eb", "wrmsr", "!process", "!thread", "!pcr",
        ] {
            assert!(!secure_scope_admits(spec(name)), "'{name}' admitted");
        }
    }

    #[test]
    fn live_vtl1_stop_admits_vcpu_state_and_steps_but_not_nt_extensions_or_writes() {
        for name in [
            "r", "k", "kb", ".frame", "~", "vcpu", "break", "status", "ba", "bl", "g", "db", "u",
            ".vtl", "t", "p", "gu", "pa", "ta", "wt",
        ] {
            assert!(live_secure_admits(spec(name)), "'{name}' refused");
        }
        for name in [
            "bp", "bu", "bm", "gh", "gn", "eb", "eq", "f", ".readmem", "!eb", "wrmsr", "!process",
            "!thread", ".thread", "!pcr", "!prcb", "!irql", "!idt", ".cxr", ".trap", "!peb",
            "!pte",
        ] {
            assert!(!live_secure_admits(spec(name)), "'{name}' admitted");
        }
    }

    /// Only run control whose temporary sites become debug-register sites
    /// in VTL1 may leave a VTL1 stop, so a new run command stays refused
    /// until someone decides it is VTL1-safe.
    #[test]
    fn only_g_and_hardware_steps_move_the_target_from_a_vtl1_address_space() {
        for spec in COMMANDS.iter() {
            if spec.run != RunEffect::None && live_secure_admits(spec) {
                assert!(
                    matches!(spec.names[0], "g" | "t" | "p" | "gu" | "pa" | "ta" | "wt"),
                    "'{}' admitted",
                    spec.names[0]
                );
            }
        }
    }

    /// A stop whose root is a VTL1 root: a run-to that would need a software
    /// site in VTL1, and writes, leave the target exactly as stopped; plain
    /// `g` still resumes it.
    #[test]
    fn vtl1_stop_refuses_patching_run_to_and_writes_but_resumes_on_plain_g() {
        let mut session = session_with_mock(MockBackend::default());
        let root = session.target.current_dtb();
        session.target.symbols.set_secure_roots(root, []);
        let mut state = ReplState::for_oneshot(&mut session);
        state.stop_wait = Some(StopWaitBudget::new(
            std::time::Duration::from_millis(150),
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        ));
        assert!(state.ctx.target.in_secure_address_space());
        assert!(!state.ctx.target.in_secure_scope());

        let (result, _) = capture(|| state.dispatch_line("g 1000"));
        result.unwrap();
        assert!(!state.ctx.backend.is_running(), "g <address> resumed");

        let (result, _) = capture(|| state.dispatch_line("eb 1000 cc"));
        assert_eq!(result.unwrap(), Flow::Denied);
        let (result, _) = capture(|| state.dispatch_line("bp 1000"));
        assert_eq!(result.unwrap(), Flow::Denied);
        assert!(!state.ctx.backend.is_running(), "bp resumed");

        let (result, _) = capture(|| state.dispatch_line("g"));
        result.unwrap();
        assert!(state.ctx.backend.is_running(), "plain g did not resume");
    }
}
