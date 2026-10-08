//! Virtio devices and virtqueues (`!virtio`, `!vring`).

use tabled::builder::Builder;

use crate::error::Result;
use crate::target::virtio::{
    DescChain, MAX_LISTED_CHAINS, PackedQueueState, PackedRing, SplitRing,
    VRING_AVAIL_F_NO_INTERRUPT, VRING_DESC_F_INDIRECT, VRING_DESC_F_NEXT, VRING_DESC_F_WRITE,
    VRING_USED_F_NO_NOTIFY, VirtQueue, VirtioDriver, VirtioFunction, packed_verdict, queue_verdict,
    virtio_type_name,
};
use crate::types::VirtAddr;
use crate::ui;

use crate::repl::*;

repl_command! {
    cmd_virtio;
    names: ["!virtio", "virtio"],
    usage: "!virtio [<virtio_device> [module]]",
    summary: "List the virtio devices and the state of their virtqueues.",
    details: "Without an argument, lists the virtio PCI functions that pci.sys knows, with the device type and the service that drives each, so it works on every backend. For a virtio-win driver whose private PDB is loaded, it finds the driver's virtio_device in its per-device state (a KMDF device context, a StorPort miniport's device extension, or an NDIS adapter context) and shows each queue: its size, the avail index or position the driver published, the used index the device returned (split rings), where the driver takes buffers back next, the free descriptors, and a state: the buffers the device holds, the ones it returned that the driver has not taken back, and for split rings the ones the driver added but has not published or kicked (notified the device about). A queue that stops moving while it has buffers with the device points to the device, and one with buffers returned but not taken back points to the driver's interrupt or DPC. With an address, shows the virtio_device there, typed by the module you give or by the driver its operations table is in. !vring shows one queue's ring and its buffers.",
    completion: Expression,
}

repl_command! {
    cmd_vring;
    names: ["!vring", "vring"],
    usage: "!vring <virtqueue> [module] | !vring /r <size> <desc> <avail> <used>",
    summary: "Show a virtqueue's ring and its outstanding buffers.",
    details: "Shows the ring of the virtio-win virtqueue at the address, as !virtio lists them, typed by the module you give or by the driver its add_buf routine is in, split or packed as its device negotiated. For a split ring: the ring addresses, the flags (the driver's NO_INTERRUPT, the device's NO_NOTIFY), the indexes and the state as !virtio shows them, each buffer the device holds, from its avail entry, and each buffer it returned that the driver has not taken back, from its used element, with the bytes the device wrote. For a packed ring: the descriptor ring and event structures, the driver's positions and wrap counters, and the buffers the device holds, read from the position where the driver takes buffers back next. Each descriptor shows its guest-physical address, length, and flags (W for a buffer the device writes, N for one that continues, I for an indirect table, whose descriptors and bytes out and in it sums). With /r, it reads a split ring of the size at the kernel addresses of its descriptor table, avail ring, and used ring, for a driver without a PDB. It lists at most 64 buffers of each kind.",
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
        let Some(module) =
            self.virtio_module(invocation.arg(1), address, "virtio_device", "device")
        else {
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
                let Some(module) =
                    self.virtio_module(args.get(1).copied(), address, "virtqueue", "add_buf")
                else {
                    return Ok(());
                };
                let packed = self
                    .ctx
                    .target
                    .virtqueue_is_packed(&module, address)
                    .unwrap_or(false);
                let queue = self.ctx.target.virtqueue(&module, address, packed, 0);
                if let (Some(state), Some(ring)) = (&queue.packed, &queue.packed_ring) {
                    print_packed_ring(&self.ctx.target, &queue, state, ring);
                    return Ok(());
                }
                match (queue.ring, &queue.error) {
                    (Some(ring), _) => (Some(queue), ring),
                    (None, error) => {
                        error!(
                            "!vring: {:#x} is not a virtqueue of {module}: {}",
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

    /// The module whose PDB types the virtio-win `type_name` at `address`:
    /// `named`, else the driver its `pointer` field leads into, else the
    /// first loaded module with the types. `None` after saying why not.
    fn virtio_module(
        &self,
        named: Option<&str>,
        address: VirtAddr,
        type_name: &str,
        pointer: &str,
    ) -> Option<String> {
        if let Some(named) = named {
            return Some(named.to_string());
        }
        if let Some(owner) = self
            .ctx
            .target
            .virtio_module_of(address, type_name, pointer)
        {
            return Some(owner);
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
        // A device's queues are all split or all packed.
        if queues.iter().any(|queue| queue.packed.is_some()) {
            header.extend(["desc", "driver event", "device event"]);
        } else {
            header.extend(["desc", "avail", "used"]);
        }
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
                packed.next_avail.to_string(),
                "-".into(),
                packed.last_used.to_string(),
                packed.free.to_string(),
                queue
                    .packed_ring
                    .as_ref()
                    .map_or_else(|| ui::muted("packed ring"), packed_verdict),
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
        if with_rings {
            if let Some(ring) = &queue.ring {
                row.extend([
                    ui::addr(ring.desc.0),
                    ui::addr(ring.avail.0),
                    ui::addr(ring.used.0),
                ]);
            } else if let Some(packed) = &queue.packed {
                row.extend([
                    ui::addr(packed.desc.0),
                    ui::addr(packed.driver_event.0),
                    ui::addr(packed.device_event.0),
                ]);
            }
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

/// A packed queue: the driver's positions and lap bits, the ring's state,
/// and the buffers the device holds.
fn print_packed_ring(
    target: &crate::target::Target,
    queue: &VirtQueue,
    state: &PackedQueueState,
    ring: &PackedRing,
) {
    let lap = |wrap: bool| if wrap { 1 } else { 0 };
    outln!(
        "virtqueue {}  queue {}  size {}  packed",
        ui::addr(queue.address.0),
        queue.index,
        queue.size
    );
    outln!(
        "  desc {}  driver event {}  device event {}",
        ui::addr(state.desc.0),
        ui::addr(state.driver_event.0),
        ui::addr(state.device_event.0)
    );
    outln!(
        "  driver: next avail {} (lap {})  taken back to {} (lap {})  {} free",
        state.next_avail,
        lap(state.avail_wrap),
        state.last_used,
        lap(state.used_wrap),
        state.free
    );
    outln!("  state: {}", packed_verdict(ring));
    if let Some(why) = &ring.broken {
        outln!(
            "  {}",
            ui::muted(&format!("the ring stopped reading: {why}"))
        );
    }
    if ring.chains.is_empty() {
        outln!();
        return;
    }
    outln!();
    outln!("{}", ui::label("Buffers with the device"));
    for chain in &ring.chains {
        let descriptors: Vec<String> = chain
            .descriptors
            .iter()
            .map(|(position, desc)| {
                format!(
                    "[{position}] id {} {:#x} len {:#x} {}{}",
                    desc.id,
                    desc.addr,
                    desc.len,
                    flag_names(desc.flags),
                    indirect_note(target, desc.flags, desc.addr, desc.len, true)
                )
            })
            .collect();
        outln!("  {}", descriptors.join(" -> "));
    }
    if ring.with_device as usize > ring.chains.len() {
        outln!(
            "  {}",
            ui::muted(&format!(
                "... {} more",
                ring.with_device as usize - ring.chains.len()
            ))
        );
    }
    outln!();
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
    if !chains.is_empty() {
        outln!();
        outln!("{}", ui::label("Buffers with the device"));
        for chain in &chains {
            print_chain(target, &format!("avail[{}]", chain.avail_index), chain);
        }
        print_more(usize::from(ring.with_device()), chains.len());
    }
    if let Some(driver) = driver {
        let returned = target.split_ring_returned(ring, driver.last_used, MAX_LISTED_CHAINS);
        if !returned.is_empty() {
            outln!();
            outln!("{}", ui::label("Returned, not yet taken back"));
            for buffer in &returned {
                print_chain(
                    target,
                    &format!("used[{}] wrote {:#x}", buffer.used_index, buffer.written),
                    &buffer.chain,
                );
            }
            print_more(
                usize::from(ring.used_idx.wrapping_sub(driver.last_used)),
                returned.len(),
            );
        }
    }
    outln!();
}

/// The count past the `shown` of `total` that a list left out.
fn print_more(total: usize, shown: usize) {
    if total > shown {
        outln!("  {}", ui::muted(&format!("... {} more", total - shown)));
    }
}

/// What the indirect table an `I` descriptor names holds, or nothing for
/// a direct descriptor.
fn indirect_note(
    target: &crate::target::Target,
    flags: u16,
    addr: u64,
    len: u32,
    packed: bool,
) -> String {
    if flags & VRING_DESC_F_INDIRECT == 0 {
        return String::new();
    }
    match target.read_indirect_table(addr, len, packed) {
        Ok(table) => format!(
            " ({} descriptor{}, out {:#x}, in {:#x})",
            table.descriptors,
            if table.descriptors == 1 { "" } else { "s" },
            table.out_bytes,
            table.in_bytes
        ),
        Err(error) => ui::muted(&format!(" (table unreadable: {error})")),
    }
}

/// One buffer: `label`, its head, and its descriptors.
fn print_chain(target: &crate::target::Target, label: &str, chain: &DescChain) {
    let descriptors: Vec<String> = chain
        .descriptors
        .iter()
        .map(|(index, desc)| {
            format!(
                "[{index}] {:#x} len {:#x} {}{}",
                desc.addr,
                desc.len,
                flag_names(desc.flags),
                indirect_note(target, desc.flags, desc.addr, desc.len, false)
            )
        })
        .collect();
    outln!(
        "  {label} head {}: {}{}",
        chain.head,
        descriptors.join(" -> "),
        chain
            .broken
            .as_ref()
            .map(|why| ui::muted(&format!("  ({why})")))
            .unwrap_or_default()
    );
}
