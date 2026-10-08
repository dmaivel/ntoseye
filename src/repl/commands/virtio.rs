//! Virtio devices and virtqueues (`!virtio`, `!vring`).

use tabled::builder::Builder;

use crate::error::Result;
use crate::target::virtio::{
    DescChain, MAX_LISTED_CHAINS, SplitRing, VRING_AVAIL_F_NO_INTERRUPT, VRING_DESC_F_INDIRECT,
    VRING_DESC_F_NEXT, VRING_DESC_F_WRITE, VRING_USED_F_NO_NOTIFY, VirtQueue, VirtioDriver,
    VirtioFunction, queue_verdict, virtio_type_name,
};
use crate::types::VirtAddr;
use crate::ui;

use crate::repl::*;

repl_command! {
    cmd_virtio;
    names: ["!virtio", "virtio"],
    usage: "!virtio [<virtio_device> [module]]",
    summary: "List the virtio devices and the state of their virtqueues.",
    details: "Without an argument, lists the virtio PCI functions that pci.sys knows, with the device type and the service that drives each, so it works on every backend. For a virtio-win driver whose private PDB is loaded, it finds the driver's virtio_device in the context of the device's WDFDEVICE and shows each queue: its size, the avail index the driver published, the used index the device returned, the used index up to which the driver took buffers back, the free descriptors, and a state: the buffers the device holds, the ones it returned that the driver has not taken back, the ones the driver added but has not published, and the ones it did not kick (notify the device about). A queue that stops moving while it has buffers with the device points to the device, and one with buffers returned but not taken back points to the driver's interrupt or DPC. With an address, shows the virtio_device there, typed by the module you give or by a loaded module whose PDB has the virtio-win types. !vring shows one queue's ring and its buffers.",
    completion: Expression,
}

repl_command! {
    cmd_vring;
    names: ["!vring", "vring"],
    usage: "!vring <virtqueue> [module] | !vring /r <size> <desc> <avail> <used>",
    summary: "Show a split virtqueue's ring and the buffers the device holds.",
    details: "Shows the ring of the virtio-win virtqueue at the address (a virtqueue_split, as !virtio lists them), typed by the module you give or by a loaded module whose PDB has the virtio-win types: the ring addresses, the flags (the driver's NO_INTERRUPT, the device's NO_NOTIFY), the indexes and the state as !virtio shows them, and each buffer the device holds, from its avail entry, with its descriptor chain: each descriptor's guest-physical address, length, and flags (W for a buffer the device writes, N for one that continues, I for an indirect table). With /r, it reads a ring of the size at the kernel addresses of its descriptor table, avail ring, and used ring, for a driver without a PDB. It lists at most 64 buffers.",
    completion: Expression,
}

impl ReplState<'_> {
    fn cmd_virtio(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(address) = invocation.arg(0) else {
            match self.ctx.target.virtio_functions() {
                Ok(functions) => print_virtio_functions(&functions),
                Err(error) => error!("!virtio: pci.sys's device tree: {error}"),
            }
            return Ok(());
        };
        let Some(address) = self.eval_or_report(address) else {
            return Ok(());
        };
        let Some(module) = self.virtio_module(invocation.arg(1)) else {
            return Ok(());
        };
        match self.ctx.target.virtio_device(&module, address) {
            Ok(driver) => {
                print_driver_header(&driver);
                print_queues(&driver.queues, true);
            }
            Err(error) => error!("!virtio: {error}"),
        }
        Ok(())
    }

    fn cmd_vring(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let args: Vec<&str> = invocation.argv.iter().map(|arg| arg.as_ref()).collect();
        let (queue, ring) = match args.as_slice() {
            ["/r", size, desc, avail, used] => {
                let mut values = Vec::new();
                for text in [size, desc, avail, used] {
                    let Some(VirtAddr(value)) = self.eval_or_report(text) else {
                        return Ok(());
                    };
                    values.push(value);
                }
                let Ok(size) = u32::try_from(values[0]) else {
                    error!("!vring: {:#x} is no ring size", values[0]);
                    return Ok(());
                };
                match self.ctx.target.split_ring(
                    size,
                    VirtAddr(values[1]),
                    VirtAddr(values[2]),
                    VirtAddr(values[3]),
                ) {
                    Ok(ring) => (None, ring),
                    Err(error) => {
                        error!("!vring: {error}");
                        return Ok(());
                    }
                }
            }
            [address] | [address, _] => {
                let Some(address) = self.eval_or_report(address) else {
                    return Ok(());
                };
                let Some(module) = self.virtio_module(args.get(1).copied()) else {
                    return Ok(());
                };
                let queue = self.ctx.target.virtqueue(&module, address, false, 0);
                match (queue.ring, &queue.error) {
                    (Some(ring), _) => (Some(queue), ring),
                    (None, error) => {
                        error!(
                            "!vring: {:#x} is not a virtqueue_split of {module}: {}",
                            address.0,
                            error.as_deref().unwrap_or("the queue has no split ring")
                        );
                        return Ok(());
                    }
                }
            }
            _ => {
                outln!("{}\n", command_help(invocation.name));
                return Ok(());
            }
        };
        print_ring(&self.ctx.target, queue.as_ref(), &ring);
        Ok(())
    }

    /// The module whose PDB types virtio-win structures: `named`, or the
    /// first loaded module that has them. `None` after saying why not.
    fn virtio_module(&self, named: Option<&str>) -> Option<String> {
        if let Some(named) = named {
            return Some(named.to_string());
        }
        let modules = self.ctx.target.virtio_modules();
        match modules.first() {
            Some(module) => Some(module.clone()),
            None => {
                error!(
                    "no loaded module's symbols have the virtio-win types (virtio_device); load \
                     the driver's private PDB (.sympath+ <directory>), or name the module after \
                     the address"
                );
                None
            }
        }
    }
}

fn location(function: &VirtioFunction) -> String {
    format!(
        "{:02x}:{:02x}.{}",
        function.bus, function.device, function.function
    )
}

fn print_virtio_functions(functions: &[VirtioFunction]) {
    if functions.is_empty() {
        outln!("{}\n", ui::muted("no virtio PCI functions"));
        return;
    }
    for function in functions {
        let kind = if function.transitional {
            format!("{} (transitional)", virtio_type_name(function.virtio_id))
        } else {
            virtio_type_name(function.virtio_id).to_string()
        };
        outln!(
            "{}  {}  1af4:{:04x}  {}  {}",
            location(function),
            ui::label(&kind),
            function.device_id,
            function.service.as_deref().unwrap_or("-"),
            ui::muted(&format!("pdo {:#x}", function.pdo.0)),
        );
        match (&function.driver, &function.driver_missing) {
            (Some(driver), _) => {
                print_driver_header(driver);
                print_queues(&driver.queues, false);
            }
            (None, Some(why)) => outln!("  {}\n", ui::muted(&format!("no queues: {why}"))),
            (None, None) => outln!(),
        }
    }
}

fn print_driver_header(driver: &VirtioDriver) {
    outln!(
        "  virtio_device {} ({}), {} rings",
        ui::addr(driver.device.0),
        driver.module,
        if driver.packed { "packed" } else { "split" }
    );
}

fn print_queues(queues: &[VirtQueue], with_rings: bool) {
    if queues.is_empty() {
        outln!("  {}", ui::muted("no queues set up"));
        return;
    }
    let mut builder = Builder::default();
    let mut header = vec![
        "  #",
        "Size",
        "Avail",
        "Used",
        "Driver",
        "Free",
        "State",
        "virtqueue",
    ];
    if with_rings {
        header.extend(["desc", "avail", "used"]);
    }
    builder.push_record(header);
    for queue in queues {
        let mut row = vec![format!("  {}", queue.index), queue.size.to_string()];
        match (&queue.ring, &queue.packed, &queue.error) {
            (Some(ring), _, _) => {
                let driver = queue.driver.as_ref();
                row.extend([
                    ring.avail_idx.to_string(),
                    ring.used_idx.to_string(),
                    driver.map_or("-".into(), |driver| driver.last_used.to_string()),
                    driver.map_or("-".into(), |driver| driver.free.to_string()),
                    queue_verdict(ring, driver),
                ]);
            }
            (None, Some(packed), _) => row.extend([
                "-".into(),
                "-".into(),
                packed.last_used.to_string(),
                packed.free.to_string(),
                ui::muted("packed ring"),
            ]),
            (None, None, error) => row.extend([
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                ui::muted(error.as_deref().unwrap_or("unreadable")),
            ]),
        }
        row.push(ui::addr(queue.address.0));
        if with_rings && let Some(ring) = &queue.ring {
            row.extend([
                ui::addr(ring.desc.0),
                ui::addr(ring.avail.0),
                ui::addr(ring.used.0),
            ]);
        }
        builder.push_record(row);
    }
    print_padded_table(builder);
}

fn flag_names(flags: u16) -> String {
    let mut names = String::new();
    for (bit, letter) in [
        (VRING_DESC_F_WRITE, 'W'),
        (VRING_DESC_F_NEXT, 'N'),
        (VRING_DESC_F_INDIRECT, 'I'),
    ] {
        if flags & bit != 0 {
            names.push(letter);
        }
    }
    if names.is_empty() { "-".into() } else { names }
}

fn print_ring(target: &crate::target::Target, queue: Option<&VirtQueue>, ring: &SplitRing) {
    let mut flags = Vec::new();
    if ring.avail_flags & VRING_AVAIL_F_NO_INTERRUPT != 0 {
        flags.push("driver wants no interrupts (NO_INTERRUPT)");
    }
    if ring.used_flags & VRING_USED_F_NO_NOTIFY != 0 {
        flags.push("device wants no notifications (NO_NOTIFY)");
    }
    if let Some(queue) = queue {
        outln!(
            "virtqueue {}  queue {}  size {}",
            ui::addr(queue.address.0),
            queue.index,
            ring.size
        );
    } else {
        outln!("ring of {} entries", ring.size);
    }
    outln!(
        "  desc {}  avail {}  used {}",
        ui::addr(ring.desc.0),
        ui::addr(ring.avail.0),
        ui::addr(ring.used.0)
    );
    let driver = queue.and_then(|queue| queue.driver.as_ref());
    outln!(
        "  avail idx {}  used idx {}{}",
        ring.avail_idx,
        ring.used_idx,
        driver.map_or(String::new(), |driver| format!(
            "  driver: published {}  taken back to {}  {} free  {} not kicked",
            driver.avail_idx, driver.last_used, driver.free, driver.unkicked
        ))
    );
    if !flags.is_empty() {
        outln!("  {}", flags.join(", "));
    }
    outln!("  state: {}", queue_verdict(ring, driver));
    let chains = target.split_ring_outstanding(ring, MAX_LISTED_CHAINS);
    if chains.is_empty() {
        outln!();
        return;
    }
    outln!();
    outln!("{}", ui::label("Buffers with the device"));
    for chain in &chains {
        print_chain(chain);
    }
    if usize::from(ring.with_device()) > chains.len() {
        outln!(
            "  {}",
            ui::muted(&format!(
                "... {} more",
                usize::from(ring.with_device()) - chains.len()
            ))
        );
    }
    outln!();
}

fn print_chain(chain: &DescChain) {
    let descriptors: Vec<String> = chain
        .descriptors
        .iter()
        .map(|(index, desc)| {
            format!(
                "[{index}] {:#x} len {:#x} {}",
                desc.addr,
                desc.len,
                flag_names(desc.flags)
            )
        })
        .collect();
    outln!(
        "  avail[{}] head {}: {}{}",
        chain.avail_index,
        chain.head,
        descriptors.join(" -> "),
        chain
            .broken
            .as_ref()
            .map(|why| ui::muted(&format!("  ({why})")))
            .unwrap_or_default()
    );
}
