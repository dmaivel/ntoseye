//! Pseudo-registers: the `$` names resolved from target and thread state,
//! the `vars` inventory of them, and the result slots commands fill.

use super::{BuiltinVar, Target, ThreadInfo};
use crate::{
    backend::MemoryOps,
    memory::PAGE_SIZE,
    types::{Arch, VirtAddr},
    unwind::return_address_for_register_values,
};

impl ThreadInfo {
    /// A thread pseudo-register: `None` when this thread has no such name,
    /// `Some(None)` when it has the name but not the state behind it (a
    /// kernel thread has no TEB, an unwalked thread no trap frame). Telling
    /// the two apart is what lets the evaluator say "not available here"
    /// instead of "no such register".
    pub fn pseudo_register(&self, name: &str) -> Option<Option<u64>> {
        let register = THREAD_PSEUDO_REGISTERS.iter().find(|register| {
            register
                .names
                .iter()
                .any(|known| known.eq_ignore_ascii_case(name))
        })?;
        Some((register.read)(self))
    }

    pub fn pseudo_register_value(&self, name: &str) -> Option<u64> {
        self.pseudo_register(name).flatten()
    }
}

/// A thread pseudo-register: the names it answers to, the `vars` source
/// text, and the thread state it reads.
struct ThreadPseudoRegister {
    names: &'static [&'static str],
    source: &'static str,
    read: fn(&ThreadInfo) -> Option<u64>,
}

const THREAD_PSEUDO_REGISTERS: &[ThreadPseudoRegister] = &[
    ThreadPseudoRegister {
        names: &["thread", "ethread"],
        source: "current Windows ETHREAD",
        read: |thread| Some(thread.ethread.0),
    },
    ThreadPseudoRegister {
        names: &["kthread"],
        source: "current Windows KTHREAD",
        read: |thread| Some(thread.kthread.0),
    },
    ThreadPseudoRegister {
        names: &["tid"],
        source: "current Windows TID",
        read: |thread| thread.tid,
    },
    ThreadPseudoRegister {
        names: &["pid"],
        source: "current Windows PID",
        read: |thread| thread.pid,
    },
    ThreadPseudoRegister {
        names: &["proc", "process", "eprocess"],
        source: "current thread EPROCESS",
        read: |thread| thread.eprocess.map(|address| address.0),
    },
    ThreadPseudoRegister {
        names: &["teb"],
        source: "current thread TEB",
        read: |thread| thread.teb.map(|address| address.0),
    },
    ThreadPseudoRegister {
        names: &["threadstart", "startaddress"],
        source: "current thread start address",
        read: |thread| thread.start_address.map(|address| address.0),
    },
    ThreadPseudoRegister {
        names: &["win32start", "win32startaddress"],
        source: "current thread Win32 start address",
        read: |thread| thread.win32_start_address.map(|address| address.0),
    },
    ThreadPseudoRegister {
        names: &["kernelstack"],
        source: "current thread kernel stack",
        read: |thread| thread.kernel_stack.map(|address| address.0),
    },
    ThreadPseudoRegister {
        names: &["stackbase"],
        source: "current thread stack base",
        read: |thread| thread.stack_base.map(|address| address.0),
    },
    ThreadPseudoRegister {
        names: &["stacklimit"],
        source: "current thread stack limit",
        read: |thread| thread.stack_limit.map(|address| address.0),
    },
    ThreadPseudoRegister {
        names: &["trapframe"],
        source: "current thread trap frame",
        read: |thread| thread.trap_frame.map(|address| address.0),
    },
    ThreadPseudoRegister {
        names: &["priority"],
        source: "current thread priority",
        read: |thread| thread.priority.map(u64::from),
    },
    ThreadPseudoRegister {
        names: &["basepriority"],
        source: "current thread base priority",
        read: |thread| thread.base_priority.map(u64::from),
    },
    ThreadPseudoRegister {
        names: &["waitirql"],
        source: "current thread wait IRQL",
        read: |thread| thread.wait_irql.map(u64::from),
    },
    ThreadPseudoRegister {
        names: &["stackresident", "kernelstackresident"],
        source: "current thread kernel stack residency",
        read: |thread| thread.kernel_stack_resident.map(u64::from),
    },
];

impl Target {
    pub fn current_thread_pseudo_register(&self, name: &str) -> Option<u64> {
        self.current_thread_pseudo_register_slot(name).flatten()
    }

    fn current_thread_pseudo_register_slot(&self, name: &str) -> Option<Option<u64>> {
        let thread = self.windows_thread_selection.as_ref()?;
        thread.pseudo_register(name)
    }

    pub fn builtin_variable_value(&self, name: &str) -> Option<u64> {
        self.builtin_variable(name).flatten()
    }

    /// A pseudo-register: `None` when no such name exists, `Some(None)` when
    /// the name exists but the state behind it does not (`$process` with no
    /// process context, `$bug_code` outside a bugcheck). The evaluator needs
    /// the distinction to report an unavailable pseudo-register as such rather
    /// than as a register that does not exist.
    pub fn builtin_variable(&self, name: &str) -> Option<Option<u64>> {
        let name = name.trim_start_matches('$').to_ascii_lowercase();
        // A selected thread answers first, but only when it has the value:
        // otherwise the attached inspection context below may still know it.
        let thread = self.current_thread_pseudo_register_slot(&name);
        if let Some(Some(value)) = thread {
            return Some(Some(value));
        }

        let target = match name.as_str() {
            "dtb" => Some(self.current_dtb()),
            // WinDbg's automatic pseudo-registers. Each is an alias for state
            // this target already tracks; a name whose state is unavailable
            // stays `None` so the expression reports an error instead of
            // inventing a number.
            // WinDbg's `$ip` is the whole instruction pointer, not x86's
            // 16-bit IP: `? $ip` on a kernel address must not truncate.
            "ip" => self.register_value(self.instruction_pointer_register()),
            // The caller of the current scope, one unwind step away.
            "ra" => self.scope_return_address(),
            "csp" => self.register_value(self.stack_pointer_register()),
            "retreg" => self.register_value(self.return_value_register()),
            // Both supported architectures are LP64.
            "ptrsize" => Some(8),
            "pagesize" => Some(
                self.debugger_data
                    .as_ref()
                    .and_then(|data| data.mm_page_size())
                    .map(|page_size| page_size.value)
                    .filter(|page_size| *page_size != 0)
                    .unwrap_or(PAGE_SIZE as u64),
            ),
            "tpid" => self.current_thread_pseudo_register("pid"),
            // Frame 0 is the innermost frame, which is also what an
            // unselected context is looking at.
            "frame" => Some(
                self.selected_frame
                    .as_ref()
                    .map(|frame| frame.index as u64)
                    .unwrap_or(0),
            ),
            "scopeip" => self
                .selected_frame
                .as_ref()
                .map(|frame| frame.ip)
                .or_else(|| self.register_value(self.instruction_pointer_register())),
            "exp" => self.results.first().copied(),
            "exr_code" => self.last_exception_code.map(u64::from),
            // `nt!KiBugCheckData` holds the code and its four parameters; the
            // REPL's `!analyze` decodes the same array in detail.
            "bug_code" => self.bugcheck_data(0),
            "bug_param1" => self.bugcheck_data(1),
            "bug_param2" => self.bugcheck_data(2),
            "bug_param3" => self.bugcheck_data(3),
            "bug_param4" => self.bugcheck_data(4),
            "ntbase" | "kernelbase" => self.guest.as_ref().map(|g| g.ntoskrnl.base_address.0),
            "processbase" | "imagebase" => self.current_process_image_base(),
            "processdtb" => self.process.as_ref().map(|p| p.dtb),
            "attachedeprocess" | "attachedprocess" => {
                self.process.as_ref().map(|p| p.eprocess_va.0)
            }
            "attachedpid" => self.process.as_ref().map(|p| p.pid),
            "eprocess" | "process" => self.process.as_ref().map(|p| p.eprocess_va.0),
            "peb" => self.current_process_peb(),
            "pid" => self.process.as_ref().map(|p| p.pid),
            // `$t0`-`$t19` are WinDbg's twenty writable slots. An assigned
            // value already wins in the evaluator's user-variable lookup, so
            // only the documented default of zero belongs here.
            _ => {
                return match Self::user_pseudo_register_slot(&name) {
                    Some(_) => Some(Some(0)),
                    // Not a name either side knows.
                    None => thread.map(|_| None),
                };
            }
        };
        // A named arm with no value knows the name but not the state behind it.
        Some(target)
    }

    /// The stack-pointer register this architecture calls its own, behind
    /// WinDbg's `$csp`.
    pub fn stack_pointer_register(&self) -> &'static str {
        match self.arch() {
            Arch::Amd64 => "rsp",
            Arch::Arm64 => "sp",
        }
    }

    /// Caller of the current scope, behind WinDbg's `$ra`. A selected frame
    /// unwinds from its own recovered context, so `.frame 2` then `$ra`
    /// names frame 3.
    fn scope_return_address(&self) -> Option<u64> {
        let registers = self
            .selected_frame
            .as_ref()
            .map(|frame| &frame.registers)
            .or(self.registers.as_ref())?;
        return_address_for_register_values(self, registers)
    }

    /// `$peb`: the user-mode PEB of the process context, read from its
    /// `_EPROCESS`. A System-context stop has none, which stays `None` so the
    /// expression reports an error rather than handing back zero.
    fn current_process_peb(&self) -> Option<u64> {
        let eprocess_va = self.process.as_ref()?.eprocess_va;
        let peb: VirtAddr = self
            .guest()
            .ok()?
            .ntoskrnl
            .types_in(self.kernel_dtb())
            .struct_at("_EPROCESS", eprocess_va)
            .ok()?
            .read_field("Peb")
            .ok()?;
        (!peb.is_zero()).then_some(peb.0)
    }

    /// `$processbase`: the attached process's main image base, from its PEB's
    /// `ImageBaseAddress`. `None` for a kernel-only process.
    fn current_process_image_base(&self) -> Option<u64> {
        let peb = VirtAddr(self.current_process_peb()?);
        let base: VirtAddr = self
            .types_in(self.process_dtb())
            .struct_at("_PEB", peb)
            .ok()?
            .read_field("ImageBaseAddress")
            .ok()?;
        Some(base.0)
    }

    /// One entry of `nt!KiBugCheckData`: the bugcheck code at index 0 and its
    /// four parameters after it. Zero when the target has not bugchecked,
    /// which is what the array itself reports.
    fn bugcheck_data(&self, index: u64) -> Option<u64> {
        let address = self
            .symbols
            .find_symbol_across_modules(self.kernel_dtb(), "nt!KiBugCheckData")
            .ok()
            .flatten()?;
        self.address_space(self.kernel_dtb())
            .read::<u64>(address + index * 8)
            .ok()
    }

    /// The instruction pointer this architecture calls its own, behind `$ip`
    /// and `$scopeip`.
    pub fn instruction_pointer_register(&self) -> &'static str {
        match self.arch() {
            Arch::Amd64 => "rip",
            Arch::Arm64 => "pc",
        }
    }

    /// The register a function's return value arrives in, behind `$retreg`.
    fn return_value_register(&self) -> &'static str {
        match self.arch() {
            Arch::Amd64 => "rax",
            Arch::Arm64 => "x0",
        }
    }

    /// `t0`..`t19` and nothing else: `t20`, `t007`, and `ta` are not slots.
    fn user_pseudo_register_slot(name: &str) -> Option<u8> {
        let digits = name.strip_prefix('t')?;
        if digits.is_empty() || (digits.len() > 1 && digits.starts_with('0')) {
            return None;
        }
        digits.parse::<u8>().ok().filter(|slot| *slot <= 19)
    }

    pub fn builtin_variables(&self) -> Vec<BuiltinVar> {
        let mut vars = vec![BuiltinVar {
            name: "dtb",
            value: self.current_dtb(),
            source: "current address space",
        }];

        for (name, source) in [
            ("ptrsize", "target pointer size"),
            ("pagesize", "target page size"),
            ("frame", "selected frame index"),
            ("csp", "call stack pointer"),
            ("retreg", "return value register"),
            ("scopeip", "local context instruction pointer"),
            ("ip", "instruction pointer"),
            ("exp", "last expression result"),
            ("exr_code", "last exception code"),
            ("tpid", "current Windows PID"),
        ] {
            if let Some(value) = self.builtin_variable_value(name) {
                vars.push(BuiltinVar {
                    name,
                    value,
                    source,
                });
            }
        }

        if let Some(ref guest) = self.guest {
            vars.push(BuiltinVar {
                name: "ntbase",
                value: guest.ntoskrnl.base_address.0,
                source: "kernel base",
            });
        }

        if let Some(process) = &self.process {
            vars.extend([
                BuiltinVar {
                    name: "processbase",
                    value: self.current_process_image_base().unwrap_or(0),
                    source: "attached process image base",
                },
                BuiltinVar {
                    name: "processdtb",
                    value: process.dtb,
                    source: "attached process DTB",
                },
                BuiltinVar {
                    name: "attachedeprocess",
                    value: process.eprocess_va.0,
                    source: "attached process EPROCESS",
                },
                BuiltinVar {
                    name: "attachedpid",
                    value: process.pid,
                    source: "attached process PID",
                },
            ]);
            // pid/eprocess fall back to the attached process when no thread
            // context shadows them; keep the listing in sync with evaluation
            if self.windows_thread_selection.is_none() {
                vars.extend([
                    BuiltinVar {
                        name: "eprocess",
                        value: process.eprocess_va.0,
                        source: "attached process EPROCESS",
                    },
                    BuiltinVar {
                        name: "pid",
                        value: process.pid,
                        source: "attached process PID",
                    },
                ]);
            }
        }

        if let Some(thread) = &self.windows_thread_selection {
            for register in THREAD_PSEUDO_REGISTERS {
                if let Some(value) = (register.read)(thread) {
                    vars.extend(register.names.iter().map(|&name| BuiltinVar {
                        name,
                        value,
                        source: register.source,
                    }));
                }
            }
        }

        vars
    }

    pub fn set_results(&mut self, results: Vec<u64>, origin: impl Into<String>) {
        self.results = results;
        self.results_origin = Some(origin.into());
    }
}

#[cfg(test)]
mod tests {
    use crate::session::session_over_memory;
    use crate::target::sample_thread;

    #[test]
    fn windbg_pseudo_register_slots_and_exception_code() {
        let mut session = session_over_memory(0x1000, &[0u8; 0x80]);
        let target = &session.target;

        // Unassigned slots read zero, as WinDbg documents; names outside the
        // range are not slots at all.
        assert_eq!(target.builtin_variable_value("t0"), Some(0));
        assert_eq!(target.builtin_variable_value("$t19"), Some(0));
        assert_eq!(target.builtin_variable_value("t20"), None);
        assert_eq!(target.builtin_variable_value("t007"), None);
        assert_eq!(target.builtin_variable_value("ta"), None);

        // `$exr_code` follows the recorded stop, so it is absent until one
        // has been observed rather than reading as zero.
        assert_eq!(target.builtin_variable_value("exr_code"), None);
        session.target.last_exception_code = Some(0x8000_0003);
        assert_eq!(
            session.target.builtin_variable_value("exr_code"),
            Some(0x8000_0003)
        );
    }

    #[test]
    fn thread_pseudo_registers_are_case_insensitive_and_optional() {
        let mut thread = sample_thread();
        assert_eq!(
            thread.pseudo_register_value("TrapFrame"),
            thread.trap_frame.map(|addr| addr.0)
        );
        thread.teb = None;
        assert_eq!(thread.pseudo_register_value("TEB"), None);
        assert_eq!(thread.pseudo_register_value("unknown"), None);
    }

    #[test]
    fn thread_pseudo_register_inventory_matches_lookup_names() {
        const NAMES: &[&str] = &[
            "thread",
            "ethread",
            "kthread",
            "tid",
            "pid",
            "proc",
            "process",
            "eprocess",
            "teb",
            "threadstart",
            "startaddress",
            "win32start",
            "win32startaddress",
            "kernelstack",
            "stackbase",
            "stacklimit",
            "trapframe",
            "priority",
            "basepriority",
            "waitirql",
            "stackresident",
            "kernelstackresident",
        ];
        let thread = sample_thread();
        let mut session = session_over_memory(0x1000, &[0u8; 0x80]);
        session
            .target
            .set_current_windows_thread_context(thread.clone());
        let variables = session.target.builtin_variables();

        for name in NAMES {
            let value = thread
                .pseudo_register_value(name)
                .unwrap_or_else(|| panic!("{name} should resolve for the sample thread"));
            assert_eq!(session.target.builtin_variable_value(name), Some(value));
            assert!(
                variables
                    .iter()
                    .any(|variable| variable.name == *name && variable.value == value),
                "{name} should be listed with its resolved value"
            );
        }
        for variable in variables.iter().filter(|variable| {
            variable.source.starts_with("current Windows")
                || variable.source.starts_with("current thread")
        }) {
            assert_eq!(
                session.target.builtin_variable_value(variable.name),
                Some(variable.value)
            );
        }
    }
}
