use tabled::builder::Builder;

use super::memory::MAX_DISPLAY_BYTES;
use crate::error::{Error, Result};
use crate::guest::{
    HvProcessor, HvVirtualProcessor,
    ept::{self, Access, EptTranslation},
    evmcs_fields,
    hypercalls::tlfs_hypercall,
    privilege_names,
};
use crate::repl::memory_view::{MemoryDisplayMode, display_memory_with_validity, eval_range};
use crate::repl::*;
use crate::types::VirtAddr;
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
    details: "Each row is one VTL enabled on a VP, and * marks the VTL the VP runs or last ran in. CPU is the processor whose current VP it is (the one that runs it, or ran it last), by number, or by processor block on builds before 10.0.19041, which keep no number there. The row shows the hypervisor's context object for the VTL and, when found, the physical address of the VTL's eVMCS with the EPT pointer (the root of the VTL's second-level address translation), the guest RIP where the VTL left off, and why it last left for the hypervisor. The eVMCS columns need the VM's hv-evmcs enlightenment. The partition ID uses the current radix. See !hvpartitions for where the objects come from.",
}

repl_command! {
    cmd_hvept;
    names: ["!hvept"],
    usage: "!hvept [-v] <address> [partition-id [vp-index]]",
    summary: "Translate a guest physical address through each VTL's EPT (second-level address translation) of a Windows hypervisor VP.",
    details: "Walks the extended page tables that each enabled VTL's eVMCS names, for the root partition's VP 0 by default. The address is guest physical, or with -v virtual in the current address space (the .process or VTL1 scope), which the command translates through the guest's page tables first. Each row shows the VTL, its EPT pointer, the host physical address, the access that every level of the walk allows (r, w, and x, where x is supervisor-mode execute when the VTL uses mode-based execute control), user-mode execute under that control, the page size, and the memory type, or the level where the walk found no entry. This is how memory integrity (HVCI) and the secure kernel set page permissions that NT cannot change. The address and IDs use the current radix. Needs the VM's hv-evmcs enlightenment. See !hvpartitions for where the objects come from.",
}

repl_command! {
    cmd_hveptdiff;
    names: ["!hveptdiff"],
    usage: "!hveptdiff [partition-id [vp-index]]",
    summary: "List the guest physical ranges that VTL0's and VTL1's EPTs of a Windows hypervisor VP map differently.",
    details: "Walks the whole EPT of VTL0 and of VTL1 of a VP, the root partition's VP 0 by default, and lists each range of guest physical memory that the two map with different access, or that only one of them maps, with the access in each (r, w, x, and u for user-mode execute under mode-based execute control). Adjacent ranges that differ the same way are merged. These are the pages that the secure kernel and memory integrity (HVCI) protect from NT. The IDs use the current radix. Needs VBS and the VM's hv-evmcs enlightenment.",
}

repl_command! {
    cmd_hvcalls;
    names: ["!hvcalls"],
    usage: "!hvcalls [-a]",
    summary: "List the hypercalls the Windows hypervisor implements, from its hypercall table.",
    details: "Reads the hypervisor's hypercall table and shows, for each call code, the name the Hyper-V TLFS gives it (when the TLFS documents it), whether it is a simple or a rep call (var marks a variable-size input header), the sizes of its fixed input and output and of each rep element, and its handler in the hv image. Codes that share the handler of the reserved code 0 are not implemented; -a lists them too. Needs the VM's hv-evmcs enlightenment or a vCPU stopped in the hypervisor.",
}

repl_command! {
    cmd_hvvmcs;
    names: ["!hvvmcs"],
    usage: "!hvvmcs [-msr|-io] [partition-id [vp-index [vtl]]]",
    summary: "Show the eVMCS of a VTL of a Windows hypervisor VP, or the MSRs and I/O ports it intercepts.",
    details: "Reads the Enlightened VMCS of a VTL, the root partition's VP 0 and the VTL it runs in by default, and shows each field with its offset and value. With -msr, it shows the MSRs whose reads and writes the VTL's MSR bitmap intercepts, and with -io the I/O ports its I/O bitmaps intercept, or that every access is intercepted when the VM-execution controls do not use the bitmaps. The layout is the Hyper-V TLFS's, so this does not depend on the hypervisor build. The IDs use the current radix. Needs the VM's hv-evmcs enlightenment.",
}

repl_command! {
    cmd_hvd;
    names: ["!hvd"],
    usage: "!hvd [-p] [-b|-d|-q] <partition-id> <vp-index> <address> [range]",
    summary: "Display the memory of a Windows hypervisor partition's guest (a Hyper-V VM, WSL2, Windows Sandbox).",
    details: "Reads the guest's memory through the EPT of the VTL its VP runs in, as its eVMCS names them: guest virtual memory through the VP's page tables (its CR3), or with -p guest physical memory. -b shows bytes (the default), -d dwords, and -q qwords. The range is L<count>, an end address, or a byte length, as for db. Unreadable pages show as ??. The memory is read-only, and ntoseye has no symbols for the guest. The numbers use the current radix. Needs the VM's hv-evmcs enlightenment.",
}

/// How two VTLs' access to a range differs: VTL0's, then VTL1's.
type DifferenceKind = (Option<Access>, Option<Access>);

/// `access` as `rwx`, or `none` for no mapping.
fn access_text(access: Option<Access>) -> String {
    access.map_or_else(|| "none".to_string(), |access| access.to_string())
}

/// `bytes` in the largest of K, M, and G it reaches, with one decimal when
/// it is not a whole number of them.
fn size_text(bytes: u64) -> String {
    let (unit, name) = match bytes {
        b if b >= 1 << 30 => (1u64 << 30, 'G'),
        b if b >= 1 << 20 => (1 << 20, 'M'),
        _ => (1 << 10, 'K'),
    };
    if bytes.is_multiple_of(unit) {
        format!("{}{name}", bytes / unit)
    } else {
        format!("{:.1}{name}", bytes as f64 / unit as f64)
    }
}

/// The processors whose current VP a VP is, by number, or by processor
/// block where the build keeps no number.
fn processors_text(processors: &[HvProcessor]) -> String {
    processors
        .iter()
        .map(|processor| match processor.number {
            Some(number) => number.to_string(),
            None => format!("{:x}", processor.block),
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// The name of an EPT memory type (Intel SDM 29.3.7).
fn memory_type_name(memory_type: u8) -> &'static str {
    match memory_type {
        0 => "UC",
        1 => "WC",
        4 => "WT",
        5 => "WP",
        6 => "WB",
        _ => "?",
    }
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
            | "!hvept"
            | "!hveptdiff"
            | "!hvcalls"
            | "!hvvmcs"
            | "!hvd"
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
            "CPU",
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
                    if row == 0 {
                        processors_text(&vp.processors)
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

    fn cmd_hvept(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let virtual_address = matches!(invocation.arg(0), Some("-v" | "/v"));
        let arguments = &invocation.argv[usize::from(virtual_address)..];
        if arguments.is_empty() || arguments.len() > 3 {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        }
        let Some(values) = self.eval_all(arguments) else {
            return Ok(());
        };
        let gpa = if virtual_address {
            match self.ctx.target.virt_to_phys(None, VirtAddr(values[0])) {
                Ok(Some(gpa)) => {
                    outln!(
                        "{} {} {} {:x}",
                        ui::muted("virtual"),
                        ui::addr(values[0]),
                        ui::muted("-> guest physical"),
                        gpa
                    );
                    gpa
                }
                Ok(None) => {
                    error!(
                        "{} is not mapped in the current address space",
                        ui::addr(values[0])
                    );
                    return Ok(());
                }
                Err(error) => {
                    error!("{error}");
                    return Ok(());
                }
            }
        } else {
            values[0]
        };
        let Some((_, vp)) = self.hypervisor_vp(values.get(1).copied(), values.get(2).copied())
        else {
            return Ok(());
        };
        let mut table = Builder::default();
        table.push_record([
            "VTL",
            "EPT pointer",
            "Host physical",
            "Access",
            "User exec",
            "Page",
            "Type",
        ]);
        for vtl in &vp.vtls {
            let Some(state) = &vtl.state else {
                table.push_record([vtl.level.to_string(), "no eVMCS state".to_string()]);
                continue;
            };
            let mut row = vec![vtl.level.to_string(), format!("{:x}", state.ept_pointer)];
            match self.ctx.target.translate_guest_physical(state, gpa) {
                Some(EptTranslation::Mapped(mapping)) => {
                    let bit = |allowed: bool, letter: char| if allowed { letter } else { '-' };
                    row.extend([
                        format!("{:x}", mapping.host_physical),
                        [
                            bit(mapping.read, 'r'),
                            bit(mapping.write, 'w'),
                            bit(mapping.execute, 'x'),
                        ]
                        .iter()
                        .collect(),
                        mapping
                            .user_execute
                            .map_or_else(String::new, |allowed| bit(allowed, 'x').to_string()),
                        match mapping.page_size {
                            0x1000 => "4K".to_string(),
                            0x20_0000 => "2M".to_string(),
                            _ => "1G".to_string(),
                        },
                        memory_type_name(mapping.memory_type).to_string(),
                    ]);
                }
                Some(EptTranslation::NotPresent { level }) => {
                    row.push(format!("not mapped (no level-{level} entry)"));
                }
                None => row.push("unreadable EPT".to_string()),
            }
            table.push_record(row);
        }
        print_padded_table(table);
        Ok(())
    }

    fn cmd_hveptdiff(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if invocation.argv.len() > 2 {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        }
        let Some(values) = self.eval_all(&invocation.argv) else {
            return Ok(());
        };
        let Some((id, vp)) = self.hypervisor_vp(values.first().copied(), values.get(1).copied())
        else {
            return Ok(());
        };
        let states: Vec<_> = [0, 1]
            .iter()
            .map(|level| {
                vp.vtls
                    .iter()
                    .find(|vtl| vtl.level == *level)
                    .and_then(|vtl| vtl.state)
            })
            .collect();
        let (Some(vtl0), Some(vtl1)) = (states[0], states[1]) else {
            error!(
                "VP {} of partition {id:#x} has no eVMCS state for both VTL0 and VTL1",
                vp.index
            );
            return Ok(());
        };
        let mut mappings = Vec::new();
        for (level, state) in [(0, &vtl0), (1, &vtl1)] {
            let Some(leaves) = self.ctx.target.guest_physical_mappings(state) else {
                error!("VTL{level}'s EPT is unreadable or not a 4-level walk");
                return Ok(());
            };
            let bytes: u64 = leaves.iter().map(|leaf| leaf.size).sum();
            outln!(
                "{} EPT {:x}: {} mappings, {}",
                ui::muted(&format!("VTL{level}")),
                state.ept_pointer,
                leaves.len(),
                size_text(bytes)
            );
            mappings.push(leaves);
        }
        let differences = ept::differences(&mappings[0], &mappings[1]);
        // How the VTLs differ, largest first, before the ranges themselves.
        let mut kinds: Vec<(DifferenceKind, usize, u64)> = Vec::new();
        for difference in &differences {
            let kind = (difference.first, difference.second);
            match kinds.iter_mut().find(|(seen, _, _)| *seen == kind) {
                Some((_, ranges, bytes)) => {
                    *ranges += 1;
                    *bytes += difference.end - difference.start;
                }
                None => kinds.push((kind, 1, difference.end - difference.start)),
            }
        }
        kinds.sort_by_key(|&(_, _, bytes)| std::cmp::Reverse(bytes));
        let mut summary = Builder::default();
        summary.push_record(["VTL0", "VTL1", "Ranges", "Size"]);
        for ((first, second), ranges, bytes) in &kinds {
            summary.push_record([
                access_text(*first),
                access_text(*second),
                ranges.to_string(),
                size_text(*bytes),
            ]);
        }
        outln!();
        print_padded_table(summary);
        let mut table = Builder::default();
        table.push_record(["Start", "End", "Size", "VTL0", "VTL1"]);
        for difference in &differences {
            table.push_record([
                format!("{:x}", difference.start),
                format!("{:x}", difference.end - 1),
                size_text(difference.end - difference.start),
                access_text(difference.first),
                access_text(difference.second),
            ]);
        }
        let total: u64 = differences.iter().map(|d| d.end - d.start).sum();
        print_padded_table(table);
        outln!(
            "{} ranges differ, {} in all\n",
            differences.len(),
            size_text(total)
        );
        Ok(())
    }

    fn cmd_hvcalls(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let all = match invocation.argv.as_slice() {
            [] => false,
            [flag] if matches!(flag.as_ref(), "-a" | "/a") => true,
            _ => {
                outln!("{}\n", command_help(invocation.name));
                return Ok(());
            }
        };
        let (base, table) = match self.ctx.target.hypercalls() {
            Ok(found) => found,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let unassigned = table[0].handler;
        let mut table_out = Builder::default();
        table_out.push_record([
            "Code", "Name", "Kind", "Input", "Rep in", "Output", "Rep out", "Handler",
        ]);
        let mut implemented = 0;
        for (code, entry) in table.iter().enumerate() {
            let assigned = entry.handler != unassigned || code == 0;
            implemented += usize::from(entry.handler != unassigned);
            if !assigned && !all {
                continue;
            }
            let name = tlfs_hypercall(code as u16).map_or("", |(name, _)| name);
            let mut kind = if entry.rep() { "rep" } else { "simple" }.to_string();
            if entry.variable_header() {
                kind.push_str("+var");
            }
            let size = |bytes: u16| {
                if bytes == 0 {
                    String::new()
                } else {
                    format!("{bytes:#x}")
                }
            };
            table_out.push_record([
                format!("{code:#06x}"),
                name.to_string(),
                kind,
                size(entry.input),
                size(entry.input_element),
                size(entry.output),
                size(entry.output_element),
                format!("hv+{:#x}", entry.handler - base),
            ]);
        }
        print_padded_table(table_out);
        outln!(
            "{implemented} of {} codes implemented; code 0's handler serves the rest\n",
            table.len()
        );
        Ok(())
    }

    fn cmd_hvvmcs(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let view = match invocation.arg(0) {
            Some("-msr" | "/msr") => "msr",
            Some("-io" | "/io") => "io",
            _ => "fields",
        };
        let arguments = &invocation.argv[usize::from(view != "fields")..];
        if arguments.len() > 3 {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        }
        let Some(values) = self.eval_all(arguments) else {
            return Ok(());
        };
        let Some((id, vp)) = self.hypervisor_vp(values.first().copied(), values.get(1).copied())
        else {
            return Ok(());
        };
        let level = values.get(2).map_or(vp.vtl, |&level| level as u8);
        let Some(page) = vp
            .vtls
            .iter()
            .find(|vtl| vtl.level == level)
            .and_then(|vtl| vtl.vmcs)
        else {
            error!(
                "VP {} of partition {id:#x} has no eVMCS for VTL{level}",
                vp.index
            );
            return Ok(());
        };
        let mut vmcs = vec![0u8; 0x400];
        if let Err(error) = self.ctx.target.read_physical(page, &mut vmcs) {
            error!("{error}");
            return Ok(());
        }
        outln!(
            "{} {page:x}\n",
            ui::muted(&format!(
                "VP {} of partition {id:#x}, VTL{level}: eVMCS",
                vp.index
            ))
        );
        match view {
            "msr" => self.print_msr_intercepts(&vmcs),
            "io" => self.print_io_intercepts(&vmcs),
            _ => {
                let mut table = Builder::default();
                table.push_record(["Field", "Offset", "Value"]);
                for (name, offset, size, value) in evmcs_fields::field_values(&vmcs) {
                    table.push_record([
                        name.to_string(),
                        format!("{offset:#05x}"),
                        format!("{value:0width$x}", width = usize::from(size) * 2),
                    ]);
                }
                print_padded_table(table);
            }
        }
        Ok(())
    }

    /// The MSRs the eVMCS `vmcs` intercepts: through its MSR bitmap when the
    /// primary controls use one (bit 28), else every MSR.
    fn print_msr_intercepts(&mut self, vmcs: &[u8]) {
        let controls = evmcs_fields::field(vmcs, "cpu_based_vm_exec_control").unwrap_or(0);
        if controls & (1 << 28) == 0 {
            outln!("every RDMSR and WRMSR exits: the controls use no MSR bitmap\n");
            return;
        }
        let address = evmcs_fields::field(vmcs, "msr_bitmap").unwrap_or(0);
        let mut bitmap = vec![0u8; 0x1000];
        if let Err(error) = self.ctx.target.read_physical(address, &mut bitmap) {
            error!("MSR bitmap {address:x}: {error}");
            return;
        }
        let mut table = Builder::default();
        table.push_record(["Access", "First MSR", "Last MSR"]);
        // Read low, read high, write low, write high (Intel SDM 25.6.9).
        for (index, access, base) in [
            (0, "read", 0u32),
            (1, "read", 0xc000_0000),
            (2, "write", 0),
            (3, "write", 0xc000_0000),
        ] {
            for (first, last) in evmcs_fields::set_ranges(&bitmap[index * 0x400..][..0x400], base) {
                table.push_record([
                    access.to_string(),
                    format!("{first:#x}"),
                    format!("{last:#x}"),
                ]);
            }
        }
        outln!("{} {address:x}", ui::muted("MSR bitmap"));
        print_padded_table(table);
    }

    /// The I/O ports the eVMCS `vmcs` intercepts: through its I/O bitmaps A
    /// (ports 0-0x7fff) and B when the primary controls use them (bit 25),
    /// else every port or none (unconditional I/O exiting, bit 24).
    fn print_io_intercepts(&mut self, vmcs: &[u8]) {
        let controls = evmcs_fields::field(vmcs, "cpu_based_vm_exec_control").unwrap_or(0);
        if controls & (1 << 25) == 0 {
            if controls & (1 << 24) == 0 {
                outln!("no I/O instruction exits: the controls use no I/O bitmaps\n");
            } else {
                outln!("every I/O instruction exits: the controls use no I/O bitmaps\n");
            }
            return;
        }
        let mut table = Builder::default();
        table.push_record(["First port", "Last port"]);
        for (field, base) in [("io_bitmap_a", 0u32), ("io_bitmap_b", 0x8000)] {
            let address = evmcs_fields::field(vmcs, field).unwrap_or(0);
            let mut bitmap = vec![0u8; 0x1000];
            if let Err(error) = self.ctx.target.read_physical(address, &mut bitmap) {
                error!("{field} {address:x}: {error}");
                return;
            }
            for (first, last) in evmcs_fields::set_ranges(&bitmap, base) {
                table.push_record([format!("{first:#x}"), format!("{last:#x}")]);
            }
        }
        print_padded_table(table);
    }

    fn cmd_hvd(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let mut physical = false;
        let (mut mode, mut item) = (MemoryDisplayMode::bytes(), 1);
        let mut arguments = invocation.argv.as_slice();
        while let Some(flag) = arguments.first().filter(|text| text.starts_with('-')) {
            match flag.as_ref() {
                "-p" => physical = true,
                "-b" => (mode, item) = (MemoryDisplayMode::bytes(), 1),
                "-d" => (mode, item) = (MemoryDisplayMode::dwords(), 4),
                "-q" => (mode, item) = (MemoryDisplayMode::qwords(), 8),
                _ => break,
            }
            arguments = &arguments[1..];
        }
        if !(3..=4).contains(&arguments.len()) {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        }
        let Some(values) = self.eval_all(&arguments[..3]) else {
            return Ok(());
        };
        let start = VirtAddr(values[2]);
        let range = match arguments.get(3) {
            Some(text) => eval_range(text, &self.ctx.target, self.radix, start, item),
            None => eval_range("L80", &self.ctx.target, NumberRadix::Hexadecimal, start, 1),
        };
        let range = match range {
            Ok(range) if range.len() <= MAX_DISPLAY_BYTES => range,
            Ok(_) => {
                error!("display range exceeds the maximum of {MAX_DISPLAY_BYTES:#x} bytes");
                return Ok(());
            }
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let Some((id, vp)) = self.hypervisor_vp(Some(values[0]), Some(values[1])) else {
            return Ok(());
        };
        let Some(state) = vp
            .vtls
            .iter()
            .find(|vtl| vtl.level == vp.vtl)
            .and_then(|vtl| vtl.state)
        else {
            error!(
                "VP {} of partition {id:#x} has no eVMCS state; it may not have started",
                vp.index
            );
            return Ok(());
        };
        // Page by page, so an unmapped page does not hide the rest.
        let mut data = vec![0u8; range.len()];
        let mut valid = vec![false; range.len()];
        let mut offset = 0;
        while offset < data.len() {
            let address = range.start.0 + offset as u64;
            let chunk = ((0x1000 - (address & 0xfff)) as usize).min(data.len() - offset);
            let target = &mut data[offset..offset + chunk];
            if self
                .ctx
                .target
                .read_guest_partition(&state, !physical, address, target)
                .is_ok()
            {
                valid[offset..offset + chunk].fill(true);
            }
            offset += chunk;
        }
        display_memory_with_validity(range.start, &data, Some(&valid), &mode);
        Ok(())
    }

    /// Each of `arguments` evaluated, or `None` after reporting the first
    /// that does not evaluate.
    fn eval_all(&mut self, arguments: &[std::borrow::Cow<'_, str>]) -> Option<Vec<u64>> {
        arguments
            .iter()
            .map(|text| self.eval_or_report(text).map(|value| value.0))
            .collect()
    }

    /// VP `index` (0 by default) of partition `id` (the root by default), with
    /// its partition's ID, or `None` after reporting why there is none.
    fn hypervisor_vp(
        &mut self,
        id: Option<u64>,
        index: Option<u64>,
    ) -> Option<(u64, HvVirtualProcessor)> {
        let partitions = match self.ctx.target.hypervisor_partitions() {
            Ok(partitions) => partitions,
            Err(error) => {
                error!("{error}");
                return None;
            }
        };
        let partition = match id {
            Some(id) => partitions.into_iter().find(|p| p.id == id),
            None => partitions.into_iter().next(),
        };
        let Some(partition) = partition else {
            error!("no partition with ID {:#x}", id.unwrap_or_default());
            return None;
        };
        let index = index.unwrap_or(0);
        let Some(vp) = partition
            .virtual_processors
            .into_iter()
            .find(|vp| u64::from(vp.index) == index)
        else {
            error!("partition {:#x} has no VP {index}", partition.id);
            return None;
        };
        Some((partition.id, vp))
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
