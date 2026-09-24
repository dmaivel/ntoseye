//! REPL command line → structured [`View`], for hosts that want typed values
//! (the MCP `command` tool's `format=json`). Each arm evaluates the line's
//! arguments with the REPL's expression grammar and radix, then calls the same
//! core function and `view` builder the Python SDK method uses, so the three
//! surfaces cannot drift. Commands without a structured decoding return
//! `None` and the caller falls back to the text renderer.

use crate::error::{Error, Result};
use crate::expr::Expr;
use crate::repl::{CommandStyle, ReplState, parse_command};
use crate::session::processor_index_from_backend_thread_id;
use crate::target::Target;
use crate::target::heap::HeapSelector;
use crate::target::meta::decode_error_code;
use crate::target::mm::{PfnSelector, PoolType, PoolUsageSort};
use crate::target::sched::ApcSelector;
use crate::triage_report::TriageReport;
use crate::types::VirtAddr;
use crate::view::{self, View};

/// Dispatch `line` to its structured decoding, if it has one.
pub fn structured_command(state: &mut ReplState<'_>, line: &str) -> Option<Result<View>> {
    let parsed = match parse_command(line) {
        Ok(Some(parsed)) => parsed,
        _ => return None,
    };
    let invocation = parsed.invocation(CommandStyle::StructuredArgs).ok()?;
    let argv: Vec<&str> = invocation.argv.iter().map(|arg| arg.as_ref()).collect();
    let name = parsed.name;
    let mut args = Args {
        state,
        argv: &argv,
        raw_tail: parsed.raw_tail.trim(),
    };
    Some(match name {
        "!irp" | "irp" => args.addr(0).and_then(|address| {
            let irp = args.target().inspect_irp(address)?;
            Ok(view::irp(&irp))
        }),
        "!drvobj" | "drvobj" => args.driver_object().and_then(|address| {
            let detail = args.target().inspect_driver_object(address)?;
            Ok(view::driver_object(args.target(), &detail))
        }),
        "!devobj" | "devobj" => args.addr(0).and_then(|address| {
            let detail = args.target().inspect_device_object(address)?;
            Ok(view::device_object(&detail))
        }),
        "!object" | "object" => args.addr(0).and_then(|address| {
            let detail = args.target().inspect_object_header(address)?;
            Ok(view::object_header(&detail))
        }),
        "!handle" => match args.opt_value(0) {
            Ok(Some(handle)) => args
                .target()
                .inspect_handle(handle)
                .map(|detail| view::handle_entry(&detail)),
            Ok(None) => args
                .target()
                .enumerate_handles(256)
                .map(|summary| view::handle_table(&summary)),
            Err(error) => Err(error),
        },
        "!token" => args
            .target()
            .inspect_process_token()
            .map(|token| view::token(&token)),
        "!fileobj" => args.addr(0).and_then(|address| {
            let detail = args.target().inspect_file_object(address)?;
            Ok(view::file_object(&detail))
        }),
        "!locks" => match args.opt_addr(0) {
            Ok(Some(address)) => args
                .target()
                .inspect_resource(address)
                .map(|resource| view::resource(&resource)),
            Ok(None) => args
                .target()
                .enumerate_resources(256)
                .map(|list| view::resource_list(&list)),
            Err(error) => Err(error),
        },
        "callbacks" => args
            .target()
            .enumerate_notify_callbacks()
            .and_then(|callbacks| {
                let target = args.target();
                let dtb = target.guest()?.ntoskrnl.dtb();
                Ok(View::List(
                    callbacks
                        .iter()
                        .map(|callback| {
                            let symbol = target
                                .symbols
                                .format_closest_symbol_for_address(dtb, callback.function);
                            view::notify_callback(callback, symbol)
                        })
                        .collect(),
                ))
            }),
        "ssdt" => args
            .target()
            .dump_ssdt()
            .map(|tables| View::List(tables.iter().map(view::ssdt_table).collect())),
        "!memusage" => args.opt_value(0).and_then(|limit| {
            let summary = args
                .target()
                .memory_use_summary(limit.map_or(64, |limit| limit as usize))?;
            Ok(view::memory_usage(&summary))
        }),
        "irps" => args
            .target()
            .discover_irps(argv.first().copied())
            .map(|hits| View::List(hits.iter().map(view::irp_hit).collect())),
        "!pte" | "pte" => args.addr(0).and_then(|address| {
            let walk = args.target().pte_traverse(address)?;
            Ok(view::pte_walk(&walk))
        }),
        "address" => args.addr(0).and_then(|address| {
            let description = args.target().describe_address(address)?;
            Ok(view::address_description(&description))
        }),
        "lm" => {
            let kernel_only = argv.contains(&"k");
            let modules = if kernel_only {
                args.target().kernel_modules_with_versions()
            } else {
                args.target().modules_with_versions()
            };
            modules.map(|modules| View::List(modules.iter().map(view::module).collect()))
        }
        "drivers" => args
            .target()
            .enumerate_driver_objects()
            .map(|drivers| View::List(drivers.iter().map(view::driver_object_info).collect())),
        "ps" => args
            .target()
            .matching_processes(argv.first().copied())
            .map(|processes| View::List(processes.iter().map(view::process).collect())),
        "!process" if argv.first().is_some_and(|arg| *arg == "0") => args
            .target()
            .matching_processes(argv.get(2).copied())
            .map(|processes| View::List(processes.iter().map(view::process).collect())),
        "threads" => args.state.ctx.windows_threads().map(|(threads, active)| {
            View::List(
                threads
                    .iter()
                    .map(|thread| {
                        view::thread(thread, active.get(&thread.ethread.0).map(String::as_str))
                    })
                    .collect(),
            )
        }),
        "~" | "vcpus" if argv.is_empty() => args
            .state
            .ctx
            .vcpus()
            .map(|vcpus| View::List(vcpus.iter().map(view::vcpu).collect())),
        "bl" => Ok(View::List(
            args.state
                .ctx
                .list_breakpoints()
                .into_iter()
                .map(view::breakpoint)
                .collect(),
        )),
        "k" | "kn" | "kb" | "kp" | "kv" => args.opt_value(0).and_then(|count| {
            let trace = args
                .state
                .ctx
                .backtrace(count.map_or(64, |count| count as usize))?;
            Ok(View::List(
                trace.frames.iter().map(view::stack_frame).collect(),
            ))
        }),
        "u" | "disasm" => args.addr(0).and_then(|address| {
            let count = argv
                .get(1)
                .and_then(|arg| arg.strip_prefix(['L', 'l']))
                .and_then(|count| usize::from_str_radix(count, 16).ok())
                .unwrap_or(8);
            let rows = args.state.ctx.disassemble(address, count)?;
            Ok(View::List(rows.iter().map(view::disasm_row).collect()))
        }),
        "dt" if argv.len() == 1 && !argv[0].starts_with('-') => {
            let target = args.target();
            let dtb = target.current_dtb();
            match target.symbols.find_type_across_modules(dtb, argv[0]) {
                Some(info) => Ok(view::type_layout(argv[0], &info)),
                None => Err(Error::DebugInfo(
                    target.symbols.unresolved_type_message(dtb, argv[0]),
                )),
            }
        }
        "ln" => args.addr(0).map(|address| {
            view::nearest_symbol(
                address,
                args.target().nearest_symbol_current_context(address),
            )
        }),
        "x" if !args.raw_tail.is_empty() => Ok(View::List(
            args.target()
                .search_symbols(args.raw_tail, 50)
                .iter()
                .map(view::symbol_search_match)
                .collect(),
        )),
        "?" | "ev" if !args.raw_tail.is_empty() => args.eval(args.raw_tail).map(|value| {
            View::Object(vec![
                ("expression", View::Str(args.raw_tail.to_string())),
                ("value", View::Hex(value.0)),
            ])
        }),
        "r" | "registers" if argv.is_empty() => args.state.ctx.read_registers().map(|regs| {
            let register_map = &args.state.ctx.register_map;
            let mut entries: Vec<(String, View)> = register_map
                .to_hashmap(&regs)
                .into_iter()
                .map(|(name, value)| (name, View::Hex(value)))
                .chain(
                    register_map
                        .wide_values(&regs)
                        .into_iter()
                        .map(|(name, value)| (name, View::Str(format!("{value:#034x}")))),
                )
                .collect();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            View::List(
                entries
                    .into_iter()
                    .map(|(name, value)| {
                        View::Object(vec![("name", View::Str(name)), ("value", value)])
                    })
                    .collect(),
            )
        }),
        "!analyze" | "analyze" if !argv.iter().any(|arg| *arg == "-show" || *arg == "-hang") => {
            let report = TriageReport::build(args.state.ctx);
            Ok(view::triage_report(&report, 64))
        }
        ".process" if argv.is_empty() => Ok(view::run_status(&args.state.ctx.run_status())),

        "!pcr" | "pcr" => args.processor(0).and_then(|processor| {
            let detail = args.state.ctx.inspect_pcr(processor)?;
            Ok(view::cpu::pcr(&detail))
        }),
        "!prcb" | "prcb" => args.processor(0).and_then(|processor| {
            let detail = args.target().inspect_prcb(processor)?;
            Ok(view::cpu::prcb(&detail))
        }),
        "!irql" | "irql" => args.processor(0).and_then(|processor| {
            let detail = args.target().inspect_irql(processor)?;
            Ok(view::cpu::irql(&detail))
        }),
        "!idt" | "idt" => args.opt_value(0).and_then(|vector| {
            let processor = args.current_processor();
            let vector = vector.map(|v| v as u16);
            let detail = args.state.ctx.inspect_idt(processor, vector)?;
            Ok(view::cpu::idt(&detail))
        }),
        "!gdt" | "gdt" => {
            let processor = args.current_processor();
            args.state
                .ctx
                .inspect_gdt(processor)
                .map(|detail| view::cpu::gdt(&detail))
        }
        "!cpuinfo" | "cpuinfo" => args
            .target()
            .inspect_cpuinfo(args.current_processor())
            .map(|detail| view::cpu::cpuinfo(&detail)),

        "!running" | "running" => {
            let include_idle = argv.contains(&"-i");
            let include_stacks = argv.contains(&"-t");
            args.state
                .ctx
                .inspect_running(include_idle, include_stacks)
                .map(|detail| view::sched::running(&detail))
        }
        "!ready" | "ready" => args.opt_value(0).and_then(|processor| {
            let detail = args
                .target()
                .inspect_ready_queues(processor.map(|p| p as u16))?;
            Ok(view::sched::ready_queues(&detail))
        }),
        "!dpcs" | "dpcs" => args
            .target()
            .inspect_dpc_queues()
            .map(|detail| view::sched::dpc_queues(&detail)),
        "!timer" | "timer" => match args.opt_addr(0) {
            Ok(Some(address)) => args
                .target()
                .inspect_timer(address)
                .map(|detail| view::sched::timer(&detail)),
            Ok(None) => args
                .target()
                .timer_list()
                .map(|detail| view::sched::timer_list(&detail)),
            Err(error) => Err(error),
        },
        "!apc" | "apc" => args.apc_selector().and_then(|selector| {
            let detail = args.state.ctx.inspect_apcs(selector)?;
            Ok(view::sched::apcs(&detail))
        }),
        "!stacks" | "stacks" => {
            let (level, filter) = match argv.first() {
                Some(&"0") | None => (0, argv.get(1..).map(|rest| rest.join(" "))),
                Some(&"1") => (1, argv.get(1..).map(|rest| rest.join(" "))),
                Some(&"2") => (2, argv.get(1..).map(|rest| rest.join(" "))),
                Some(_) => (0, Some(argv.join(" "))),
            };
            let filter = filter.filter(|text| !text.is_empty());
            args.state
                .ctx
                .inspect_stacks(level, filter.as_deref())
                .map(|detail| view::sched::stacks(&detail))
        }

        "!peb" | "peb" => args.opt_addr(0).and_then(|address| {
            let detail = args.target().inspect_peb(address)?;
            Ok(view::usermode::peb(&detail))
        }),
        "!teb" | "teb" => args.opt_addr(0).and_then(|address| {
            let detail = args.target().inspect_teb(address)?;
            Ok(view::usermode::teb(&detail))
        }),
        "!dlls" | "dlls" => {
            let containing = match argv.iter().position(|arg| *arg == "-c") {
                Some(index) => match argv.get(index + 1) {
                    Some(text) => args.eval(text).map(Some),
                    None => Err(Error::DebugInfo("-c requires an address".into())),
                },
                None => Ok(None),
            };
            containing.and_then(|containing| {
                let detail = args.target().loader_modules(containing)?;
                Ok(view::usermode::loader_modules(&detail))
            })
        }
        "!gle" | "gle" => args
            .target()
            .last_error()
            .map(|detail| view::usermode::last_error(&detail)),
        "!chkimg" | "chkimg" => {
            let include_diffs = argv.contains(&"-d");
            match argv.iter().find(|arg| !arg.starts_with('-')) {
                Some(module) => args
                    .target()
                    .check_image(module, include_diffs)
                    .map(|detail| view::usermode::image_check(&detail)),
                None => Err(Error::DebugInfo("missing module name".into())),
            }
        }

        "!heap" | "heap" => args.heap(),

        "!vm" | "vm" => args.opt_value(0).and_then(|flags| {
            let detail = args.target().inspect_vm(flags.unwrap_or(0) & 1 == 0)?;
            Ok(view::mm::vm(&detail))
        }),
        "!pfn" | "pfn" => {
            let physical = argv.first().is_some_and(|arg| *arg == "-a" || *arg == "/a");
            args.value(usize::from(physical)).and_then(|value| {
                let selector = if physical {
                    PfnSelector::PhysicalAddress(value)
                } else {
                    PfnSelector::Pfn(value)
                };
                let detail = args.target().inspect_pfn(selector)?;
                Ok(view::mm::pfn(&detail))
            })
        }
        "!vtop" | "vtop" => args.value(0).and_then(|dtb| {
            let address = args.addr(1)?;
            let detail = args.target().vtop(dtb, address)?;
            Ok(view::mm::vtop(&detail))
        }),
        "!ptov" | "ptov" => args.value(0).and_then(|physical| {
            let detail = args.target().ptov(physical)?;
            Ok(view::mm::ptov(&detail))
        }),
        "!pool" | "pool" => args.addr(0).and_then(|address| {
            let detail = args.target().inspect_pool(address)?;
            Ok(view::mm::pool_page(&detail))
        }),
        "!poolused" | "poolused" => {
            let (flags, tag) = match argv.first() {
                Some(first) => match args.eval(first) {
                    Ok(flags) => (flags.0, argv.get(1).copied()),
                    Err(_) => (0, Some(*first)),
                },
                None => (0, None),
            };
            let sort = if flags & 2 != 0 {
                PoolUsageSort::NonPagedBytes
            } else if flags & 4 != 0 {
                PoolUsageSort::PagedBytes
            } else {
                PoolUsageSort::Tag
            };
            args.target()
                .pool_usage(sort, tag, flags & 1 != 0)
                .map(|detail| view::mm::pool_usage(&detail))
        }
        "!poolfind" | "poolfind" => match argv.first() {
            Some(tag) => {
                let pool_type = match argv.get(1) {
                    Some(&"0") => Some(PoolType::NonPaged),
                    Some(&"1") => Some(PoolType::Paged),
                    _ => None,
                };
                args.target()
                    .pool_find(tag, pool_type)
                    .map(|detail| view::mm::pool_find(&detail))
            }
            None => Err(Error::DebugInfo("missing pool tag".into())),
        },
        "!lookaside" | "lookaside" => match args.opt_addr(0) {
            Ok(Some(address)) => args
                .target()
                .inspect_lookaside(address)
                .map(|detail| view::mm::lookaside(&detail)),
            Ok(None) => args
                .target()
                .lookaside_lists()
                .map(|detail| view::mm::lookaside_lists(&detail)),
            Err(error) => Err(error),
        },

        "!sd" | "sd" => args.addr(0).and_then(|address| {
            let annotate = argv.get(1).is_some_and(|arg| *arg == "1");
            let detail = args
                .target()
                .inspect_security_descriptor(address, annotate)?;
            Ok(view::security::security_descriptor(&detail))
        }),
        "!acl" | "acl" => args.addr(0).and_then(|address| {
            let detail = args.target().inspect_acl(address)?;
            Ok(view::security::acl(&detail))
        }),
        "!sid" | "sid" => args.addr(0).and_then(|address| {
            let detail = args.target().inspect_sid(address)?;
            Ok(view::security::sid(&detail))
        }),
        "!objsd" | "objsd" => args.addr(0).and_then(|object| {
            let detail = args.target().inspect_object_security(object)?;
            Ok(view::security::object_security(&detail))
        }),
        "!session" | "session" => {
            let session = argv
                .iter()
                .position(|arg| *arg == "-s")
                .and_then(|index| argv.get(index + 1))
                .and_then(|text| text.parse::<i64>().ok());
            args.target()
                .sessions(session)
                .map(|detail| view::security::sessions(&detail))
        }
        "!sprocess" | "sprocess" => {
            let session = argv.first().and_then(|text| text.parse::<i64>().ok());
            let detailed = argv
                .get(1)
                .and_then(|text| args.eval(text).ok())
                .is_some_and(|flags| flags.0 != 0);
            args.target()
                .session_processes(session, detailed, argv.get(2).copied())
                .map(|detail| view::security::session_processes(&detail))
        }

        "!devnode" | "devnode" => {
            let recurse = argv.iter().any(|arg| *arg == "-r" || *arg == "1");
            let node = argv
                .iter()
                .find(|arg| **arg != "-r" && **arg != "1")
                .map(|text| args.eval(text))
                .transpose();
            node.and_then(|node| {
                let node = node.filter(|address| !address.is_zero());
                let detail = args.target().inspect_devnode(node, recurse)?;
                Ok(view::pnp::devnode(&detail))
            })
        }
        "!devstack" | "devstack" => args.addr(0).and_then(|address| {
            let detail = args.target().inspect_device_stack(address)?;
            Ok(view::pnp::device_stack(&detail))
        }),
        "!pnptriage" | "pnptriage" => args
            .target()
            .pnp_triage()
            .map(|detail| view::pnp::pnp_triage(&detail)),

        "!verifier" | "verifier" => match argv.first() {
            Some(module) => args
                .target()
                .verifier_driver(module)
                .map(|detail| view::meta::verifier_driver(&detail)),
            None => args
                .target()
                .verifier_status()
                .map(|detail| view::meta::verifier(&detail)),
        },
        "vertarget" | "version" => args
            .state
            .ctx
            .target_version()
            .map(|detail| view::meta::target_version(&detail)),
        ".time" => args
            .target()
            .target_time()
            .map(|detail| view::meta::target_time(&detail)),
        "!error" | "!ntstatus" => args
            .value(0)
            .map(|code| view::meta::error_code(&decode_error_code(code))),
        _ => return None,
    })
}

/// The parsed line plus the evaluation context its arguments need.
struct Args<'s, 'a> {
    state: &'s mut ReplState<'a>,
    argv: &'s [&'s str],
    raw_tail: &'s str,
}

impl Args<'_, '_> {
    fn target(&self) -> &Target {
        &self.state.ctx.target
    }

    fn eval(&self, text: &str) -> Result<VirtAddr> {
        Expr::eval_with_radix(text, &self.state.ctx.target, self.state.radix)
    }

    fn addr(&self, index: usize) -> Result<VirtAddr> {
        match self.argv.get(index) {
            Some(text) => self.eval(text),
            None => Err(Error::DebugInfo(format!(
                "missing argument {} (an address expression)",
                index + 1
            ))),
        }
    }

    fn opt_addr(&self, index: usize) -> Result<Option<VirtAddr>> {
        self.argv.get(index).map(|text| self.eval(text)).transpose()
    }

    fn opt_value(&self, index: usize) -> Result<Option<u64>> {
        Ok(self.opt_addr(index)?.map(|value| value.0))
    }

    fn value(&self, index: usize) -> Result<u64> {
        self.addr(index).map(|value| value.0)
    }

    fn current_processor(&self) -> u16 {
        processor_index_from_backend_thread_id(&self.state.ctx.current_thread).unwrap_or(0)
    }

    /// An optional processor-index argument, defaulting to the current vCPU's.
    fn processor(&self, index: usize) -> Result<u16> {
        Ok(self
            .opt_value(index)?
            .map(|value| value as u16)
            .unwrap_or_else(|| self.current_processor()))
    }

    /// `!apc [.|*|<thread|process>]`, resolved like the REPL: threads first,
    /// then a pid/EPROCESS, then a process-name substring.
    fn apc_selector(&mut self) -> Result<ApcSelector> {
        let Some(text) = self.argv.first() else {
            return Ok(ApcSelector::CurrentThread);
        };
        match *text {
            "." => return Ok(ApcSelector::CurrentThread),
            "*" => return Ok(ApcSelector::All),
            _ => {}
        }
        if let Ok(value) = self.eval(text) {
            if self.state.ctx.find_windows_thread(value.0).is_ok() {
                return Ok(ApcSelector::Thread(value));
            }
            return Ok(ApcSelector::Process(value.0));
        }
        let processes = self.target().matching_processes(Some(text))?;
        match processes.as_slice() {
            [process] => Ok(ApcSelector::Process(process.pid)),
            [] => Err(Error::DebugInfo(format!("no process matches '{text}'"))),
            many => Err(Error::DebugInfo(format!(
                "ambiguous process '{text}': {} matches",
                many.len()
            ))),
        }
    }

    /// `!heap [-s] | [-h|-a] <heap> | -x <address> | -p -a <address>`.
    fn heap(&self) -> Result<View> {
        let target = self.target();
        let argv = self.argv;
        if argv.is_empty() || argv == ["-s"] {
            return target
                .heap_summary()
                .map(|detail| view::heap::heap_summary(&detail));
        }
        if argv.first().is_some_and(|arg| *arg == "-x")
            || (argv.first().is_some_and(|arg| *arg == "-p")
                && argv.get(1).is_some_and(|arg| *arg == "-a"))
        {
            let text = argv
                .iter()
                .find(|arg| !arg.starts_with('-'))
                .ok_or_else(|| Error::DebugInfo("missing address".into()))?;
            let address = self.eval(text)?;
            return target
                .find_heap_block(address)
                .map(|detail| view::heap::heap_block_search(&detail));
        }
        let list_entries = argv.first().is_some_and(|arg| *arg == "-a");
        let text = argv
            .iter()
            .find(|arg| !arg.starts_with('-'))
            .ok_or_else(|| Error::DebugInfo("missing heap index or address".into()))?;
        let value = self.eval(text)?.0;
        let summary = target.heap_summary()?;
        let selector = if (value as usize) < summary.heaps.len() {
            HeapSelector::Index(value as usize)
        } else {
            HeapSelector::Address(VirtAddr(value))
        };
        target
            .inspect_heap(selector, list_entries)
            .map(|detail| view::heap::heap(&detail))
    }

    /// `!drvobj` takes an address expression or a driver name (`\\Driver\\Foo`
    /// or `Foo`).
    fn driver_object(&self) -> Result<VirtAddr> {
        let Some(text) = self.argv.first() else {
            return Err(Error::DebugInfo(
                "missing argument 1 (a DRIVER_OBJECT address or driver name)".into(),
            ));
        };
        if let Ok(address) = self.eval(text) {
            return Ok(address);
        }
        let wanted = text.rsplit('\\').next().unwrap_or(text);
        self.target()
            .enumerate_driver_objects()?
            .into_iter()
            .find(|driver| {
                driver
                    .name
                    .rsplit('\\')
                    .next()
                    .is_some_and(|name| name.eq_ignore_ascii_case(wanted))
            })
            .map(|driver| driver.object)
            .ok_or_else(|| Error::DebugInfo(format!("no driver object named '{text}'")))
    }
}
