//! Object- and I/O-manager commands: IRPs, driver and device objects,
//! object headers, handles, file objects, resources, notification
//! callbacks, and service tables.

use super::Args;
use crate::error::{Error, Result};
use crate::target::irpfind::IrpFindArgs;
use crate::types::VirtAddr;
use crate::view::{self, View};

pub(super) fn command(name: &str, args: &mut Args<'_, '_>) -> Option<Result<View>> {
    let argv = args.argv;
    Some(match name {
        "!irp" | "irp" => args.addr(0).and_then(|address| {
            let irp = args.target().inspect_irp(address)?;
            Ok(view::object::irp(&irp))
        }),
        "!drvobj" | "drvobj" => args.driver_object().and_then(|address| {
            let detail = args.target().inspect_driver_object(address)?;
            Ok(view::object::driver_object(args.target(), &detail))
        }),
        "!devobj" | "devobj" => args.addr(0).and_then(|address| {
            let detail = args.target().inspect_device_object(address)?;
            Ok(view::object::device_object(&detail))
        }),
        "!object" | "object" => match argv.first() {
            Some(text) => args
                .target()
                .object_argument(text, args.state.radix)
                .and_then(|address| args.target().inspect_object(address))
                .map(|detail| view::object::object(&detail)),
            None => Err(Error::DebugInfo(
                "missing argument 1 (an object path or address expression)".into(),
            )),
        },
        "!handle" => match args.opt_value(0) {
            Ok(Some(handle)) => args
                .target()
                .inspect_handle(handle)
                .map(|detail| view::object::handle_entry(&detail)),
            Ok(None) => args
                .target()
                .enumerate_handles(256)
                .map(|summary| view::object::handle_table(&summary)),
            Err(error) => Err(error),
        },
        "!fileobj" => args.addr(0).and_then(|address| {
            let detail = args.target().inspect_file_object(address)?;
            Ok(view::object::file_object(&detail))
        }),
        "!locks" => match args.opt_addr(0) {
            Ok(Some(address)) => args
                .target()
                .inspect_resource(address)
                .map(|resource| view::object::resource(&resource)),
            Ok(None) => args
                .target()
                .enumerate_resources(256)
                .map(|list| view::object::resource_list(&list)),
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
                            view::object::notify_callback(callback, symbol)
                        })
                        .collect(),
                ))
            }),
        "ssdt" => args
            .target()
            .dump_ssdt()
            .map(|tables| View::List(tables.iter().map(view::object::ssdt_table).collect())),
        "!irpfind" | "irpfind" => {
            IrpFindArgs::parse(argv, |text| args.eval(text).map(|value| value.0)).and_then(
                |parsed| {
                    let detail =
                        args.target()
                            .irp_find(parsed.pool, parsed.restart, parsed.criteria)?;
                    Ok(view::object::irp_find(&detail))
                },
            )
        }
        "!htrace" | "htrace" => args.handle_traces(),
        "irps" => args
            .target()
            .discover_irps(argv.first().copied())
            .map(|hits| View::List(hits.iter().map(view::object::irp_hit).collect())),
        "drivers" => args.target().enumerate_driver_objects().map(|drivers| {
            View::List(
                drivers
                    .iter()
                    .map(view::object::driver_object_info)
                    .collect(),
            )
        }),
        _ => return None,
    })
}

impl Args<'_, '_> {
    /// `!htrace [handle [process [max-traces]]]`, 0 standing for an omitted
    /// handle or process as in the REPL.
    fn handle_traces(&self) -> Result<View> {
        let handle = self.opt_value(0)?.filter(|handle| *handle != 0);
        let max_traces = self.opt_value(2)?.map(|max| max as usize);
        let target = self.target();
        let process = match self.argv.get(1).filter(|text| **text != "0") {
            Some(selector) => self
                .state
                .process_for_selector_or_name(selector, &target.matching_processes(None)?)?,
            None => target.selected_process_info()?,
        };
        let detail = target.handle_traces(&process, handle, max_traces)?;
        Ok(view::object::handle_traces(&detail))
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
