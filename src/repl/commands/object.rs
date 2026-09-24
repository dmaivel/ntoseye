//! Driver object commands: the `\Driver` object directory listing.

use tabled::builder::Builder;

use owo_colors::OwoColorize;

use crate::error::Result;
use crate::ui;

use crate::repl::*;

repl_command! {
    cmd_drivers;
    names: ["drivers"],
    usage: "drivers [filter]",
    summary: "List driver objects from the \\Driver object directory.",
}

impl ReplState<'_> {
    fn cmd_drivers(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let filter = invocation.arg(0).map(|s| s.to_lowercase());

        match self.ctx.target.enumerate_driver_objects() {
            Ok(drivers) => {
                let mut builder = Builder::default();
                builder.push_record(vec![
                    "DriverObject".to_string(),
                    "Name".to_string(),
                    "DriverStart".to_string(),
                    "Size".to_string(),
                    "Module".to_string(),
                    "DeviceObject".to_string(),
                    "DriverUnload".to_string(),
                ]);

                let mut count = 0;
                for driver in &drivers {
                    if let Some(ref f) = filter
                        && !driver.name.to_lowercase().contains(f)
                        && !format!("{:#x}", driver.object.0).starts_with(f)
                    {
                        continue;
                    }
                    count += 1;
                    let module = self
                        .ctx
                        .target
                        .symbols
                        .find_module_for_address(self.ctx.target.kernel_dtb(), driver.driver_start)
                        .map(|module| module.name)
                        .unwrap_or_else(|| "-".to_string());
                    builder.push_record(vec![
                        ui::addr(driver.object.0).to_string(),
                        driver.name.to_string(),
                        ui::addr(driver.driver_start.0).to_string(),
                        format!("0x{:x}", driver.driver_size),
                        module.to_string(),
                        ui::addr(driver.device_object.0).to_string(),
                        ui::addr(driver.driver_unload.0),
                    ]);
                }

                if count == 0 {
                    outln!("{}\n", "no matching drivers".bright_black());
                } else {
                    print_padded_table(builder);
                }
                *self.caches.drivers.write().unwrap() = drivers;
            }
            Err(e) => {
                error!("failed to list drivers: {}", e);
            }
        }

        Ok(())
    }
}
