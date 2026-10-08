//! Virtio devices and virtqueues (`!virtio`, `!vring`).

use std::collections::HashMap;
use std::time::Instant;

use tabled::builder::Builder;

use crate::error::Result;
use crate::target::Target;
use crate::target::virtio::{
    DescChain, MAX_LISTED_CHAINS, PackedQueueState, PackedRing, QueueMovement, QueueProgress,
    QueueRole, Signal, SplitRing, VRING_DESC_F_INDIRECT, VRING_DESC_F_NEXT, VRING_DESC_F_WRITE,
    VirtQueue, VirtioDriver, VirtioFunction, packed_verdict, queue_count, queue_movement,
    queue_role, queue_verdict, split_signals, virtio_type_name,
};
use crate::target::virtio_request::{RequestKind, request_kind, request_kind_named};
use crate::types::VirtAddr;
use crate::ui;

use crate::repl::*;

repl_command! {
    cmd_virtio;
    names: ["!virtio", "virtio"],
    usage: "!virtio [<virtio_device> [module]]",
    summary: "List the virtio devices and the state of their virtqueues.",
    details: "Lists the virtio PCI functions with their device type and driver. With a virtio-win driver's private PDB loaded, it also shows each queue's indexes and state: what the device holds, what it returned that the driver has not taken back, and what the driver has not published or kicked. Moved compares with the previous look in guest time, and from the second look the state names a queue that did not move. With an address, shows the virtio_device there, typed by the module you give or by the driver that owns it. See the virtio devices guide.",
    completion: Expression,
}

repl_command! {
    cmd_vring;
    names: ["!vring", "vring"],
    usage: "!vring <virtqueue> [module] | !vring /r <size> <desc> <avail> <used> [/t <kind>]",
    summary: "Show a virtqueue's ring, its signalling, and its outstanding buffers.",
    details: "Give a virtqueue address that !virtio lists. Shows the ring's indexes and state, when the driver wants interrupts and the device wants notifications (and for a split ring whether an interrupt was due), and up to 64 buffers the device holds or returned, with their descriptors (W device-writable, N continues, I indirect table). Under each buffer, a line decodes the request and the device's answer from the virtio specification's layouts, such as a block sector and status or a SCSI command and its sense. /r reads a split ring from its size and kernel addresses for a driver without a PDB, and /t names what its buffers hold: blk, scsi, scsi-control, scsi-event, net, net-control, gpu, or vsock. See the virtio devices guide.",
    completion: Expression,
}

/// What `!virtio` and `!vring` last saw of each queue, by [`ring_key`],
/// with the time of that look, so the next look can say what moved.
#[derive(Default)]
pub struct VirtioSeen(HashMap<(u64, u64), (LookTime, QueueProgress)>);

/// A queue as the last-look record knows it: its address and its
/// descriptor ring's. A driver that sets its device up again, after a
/// reset or a reinstall, can get a queue at the same address, and its
/// counts start over; the new ring rarely lands where the old one was,
/// so the next look starts afresh instead of comparing with the old one.
fn ring_key(queue: &VirtQueue) -> (u64, u64) {
    let desc = match (&queue.ring, &queue.packed) {
        (Some(ring), _) => ring.desc.0,
        (None, Some(packed)) => packed.desc.0,
        (None, None) => 0,
    };
    (queue.address.0, desc)
}

/// When a look was: the guest's interrupt time, which advances only while
/// the guest runs, else the host's clock.
#[derive(Clone, Copy)]
enum LookTime {
    Guest(u64),
    Host(Instant),
}

impl LookTime {
    fn now(target: &Target) -> Self {
        match target.interrupt_time() {
            crate::target::DiagnosticValue::Available(time) => Self::Guest(time),
            _ => Self::Host(Instant::now()),
        }
    }

    /// Seconds from `self` to `now`, in the guest's time when both have it.
    fn seconds_until(self, now: Self) -> f64 {
        match (self, now) {
            (Self::Guest(before), Self::Guest(after)) => {
                after.saturating_sub(before) as f64 / 10_000_000.0
            }
            (Self::Host(before), _) => before.elapsed().as_secs_f64(),
            (Self::Guest(_), Self::Host(after)) => after.elapsed().as_secs_f64(),
        }
    }
}

/// A queue as one look shows it beyond its ring: its name and role, and
/// what moved since the last look.
struct QueueLook {
    name: Option<(String, QueueRole)>,
    /// How long ago the last look was, and what moved since.
    movement: Option<(f64, QueueMovement)>,
}

impl VirtioSeen {
    /// Look at `queue` of a device of type `virtio_id` that set up
    /// `queues` queues at `now`, recording this look for the next. A stall
    /// needs the guest to have run between the looks.
    fn look(
        &mut self,
        queue: &VirtQueue,
        virtio_id: Option<u16>,
        queues: u32,
        now: LookTime,
    ) -> QueueLook {
        let name = virtio_id.and_then(|id| queue_role(id, queue.index, queues));
        let interrupt_due = queue.ring.as_ref().is_some_and(|ring| {
            split_signals(ring, queue.driver.as_ref(), queue.event_idx).interrupt_due
        });
        let movement = QueueProgress::of(queue).and_then(|progress| {
            let (at, before) = self.0.insert(ring_key(queue), (now, progress))?;
            let seconds = at.seconds_until(now);
            let role = name.as_ref().map(|(_, role)| *role);
            let mut moved = queue_movement(&before, &progress, role, interrupt_due, seconds);
            if seconds < MIN_STALL_SECONDS {
                moved.stall = None;
            }
            Some((seconds, moved))
        });
        QueueLook { name, movement }
    }
}

/// Below this much guest time between two looks, nothing is called stuck:
/// the guest barely ran, or not at all (stopped at a breakpoint).
const MIN_STALL_SECONDS: f64 = 0.5;

impl ReplState<'_> {
    fn cmd_virtio(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(address) = invocation.arg(0) else {
            match self.ctx.target.virtio_functions() {
                Ok(functions) => {
                    let now = LookTime::now(&self.ctx.target);
                    print_virtio_functions(&functions, &mut self.virtio_seen, now)
                }
                Err(error) => error!("!virtio: pci.sys's device tree: {error}"),
            }
            return Ok(());
        };
        let Some(address) = self.eval_or_report(address) else {
            return Ok(());
        };
        let module = match self.ctx.target.virtio_module_for(
            invocation.arg(1),
            address,
            "virtio_device",
            "device",
        ) {
            Ok(module) => module,
            Err(error) => {
                error!("!virtio: {error}");
                return Ok(());
            }
        };
        match self.ctx.target.virtio_device(&module, address) {
            Ok(driver) => {
                let virtio_id = device_type_of(&self.ctx.target, |driver| driver.device == address);
                print_driver_header(&driver);
                let now = LookTime::now(&self.ctx.target);
                let seen =
                    print_queues(&driver.queues, true, virtio_id, &mut self.virtio_seen, now);
                print_moved_note(seen, driver.packed);
                outln!();
            }
            Err(error) => error!("!virtio: {error}"),
        }
        Ok(())
    }

    fn cmd_vring(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let args: Vec<&str> = invocation.argv.iter().map(|arg| arg.as_ref()).collect();
        let queue = match args.as_slice() {
            ["/r", size, desc, avail, used, rest @ ..] => {
                let kind = match rest {
                    [] => None,
                    ["/t", name] => match request_kind_named(name) {
                        Some(kind) => Some(kind),
                        None => {
                            error!(
                                "!vring: unknown request kind '{name}'; use blk, scsi, \
                                 scsi-control, scsi-event, net, net-control, gpu or vsock"
                            );
                            return Ok(());
                        }
                    },
                    _ => {
                        outln!("{}\n", command_help(invocation.name));
                        return Ok(());
                    }
                };
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
                    Ok(ring) => print_ring(&self.ctx.target, None, &ring, None, kind),
                    Err(error) => error!("!vring: {error}"),
                }
                return Ok(());
            }
            [address] | [address, _] => {
                let Some(address) = self.eval_or_report(address) else {
                    return Ok(());
                };
                match self.ctx.target.virtqueue_at(args.get(1).copied(), address) {
                    Ok(queue) => queue,
                    Err(error) => {
                        error!("!vring: {error}");
                        return Ok(());
                    }
                }
            }
            _ => {
                outln!("{}\n", command_help(invocation.name));
                return Ok(());
            }
        };
        let device = self.ctx.target.virtqueue_device(queue.address);
        let virtio_id = device.map(|(id, _, _)| id);
        let queues = device.map_or(0, |(_, _, queues)| queues);
        let kind = device.and_then(|(id, transitional, queues)| {
            request_kind(id, queue.index, queues, transitional)
        });
        let now = LookTime::now(&self.ctx.target);
        let look = self.virtio_seen.look(&queue, virtio_id, queues, now);
        match (&queue.ring, &queue.packed, &queue.packed_ring) {
            (Some(ring), _, _) => {
                print_ring(&self.ctx.target, Some(&queue), ring, Some(&look), kind)
            }
            (None, Some(state), Some(ring)) => {
                print_packed_ring(&self.ctx.target, &queue, state, ring, &look, kind)
            }
            _ => error!(
                "!vring: {:#x} has neither a split nor a packed ring",
                queue.address.0
            ),
        }
        Ok(())
    }
}

/// The virtio device type of the function whose driver `matches`.
fn device_type_of(target: &Target, matches: impl Fn(&VirtioDriver) -> bool) -> Option<u16> {
    target
        .virtio_functions()
        .ok()?
        .into_iter()
        .find(|function| function.driver.as_ref().is_some_and(&matches))
        .map(|function| function.virtio_id)
}

fn location(function: &VirtioFunction) -> String {
    format!(
        "{:02x}:{:02x}.{}",
        function.bus, function.device, function.function
    )
}

fn print_virtio_functions(functions: &[VirtioFunction], seen: &mut VirtioSeen, now: LookTime) {
    if functions.is_empty() {
        outln!("{}\n", ui::muted("no virtio PCI functions"));
        return;
    }
    let mut first_look = true;
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
                let since =
                    print_queues(&driver.queues, false, Some(function.virtio_id), seen, now);
                first_look &= since.is_none();
                print_moved_note(since, driver.packed);
                outln!();
            }
            (None, Some(why)) => outln!("  {}\n", ui::muted(&format!("no queues: {why}"))),
            (None, None) => outln!(),
        }
    }
    if first_look && functions.iter().any(|function| function.driver.is_some()) {
        outln!(
            "{}\n",
            ui::muted("Moved compares with the previous look; run !virtio again to see it.")
        );
    }
}

fn print_driver_header(driver: &VirtioDriver) {
    let mut traits = vec![if driver.packed {
        "packed rings"
    } else {
        "split rings"
    }];
    if driver.event_idx {
        traits.push("event index");
    }
    if driver.msix {
        traits.push("MSI-X");
    }
    outln!(
        "  virtio_device {} ({}), {}",
        ui::addr(driver.device.0),
        driver.module,
        traits.join(", ")
    );
}

/// After a device's queues, how long ago the look that Moved compares
/// with was.
fn print_moved_note(since: Option<f64>, packed: bool) {
    if let Some(seconds) = since {
        let counts = if packed {
            "positions filled/taken back"
        } else {
            "avail/used"
        };
        outln!(
            "  {}",
            ui::muted(&format!(
                "Moved: {counts} since the last look, {seconds:.1} s of guest time ago"
            ))
        );
    }
}

/// The queues of a device of type `virtio_id`, each recorded in `seen`
/// for the next look. Returns how long ago the last look at them was, when
/// there was one.
fn print_queues(
    queues: &[VirtQueue],
    with_rings: bool,
    virtio_id: Option<u16>,
    seen: &mut VirtioSeen,
    now: LookTime,
) -> Option<f64> {
    if queues.is_empty() {
        outln!("  {}", ui::muted("no queues set up"));
        return None;
    }
    let count = queue_count(queues);
    let mut since = None::<f64>;
    let mut builder = Builder::default();
    let mut header = vec![
        "  #",
        "Queue",
        "Size",
        "Avail",
        "Used",
        "Driver",
        "Free",
        "Moved",
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
    let mut index = 0;
    while index < queues.len() {
        // A device such as virtio-serial sets up dozens of queues it never
        // uses; in the list, a run of them is one row.
        let unused = queues[index..]
            .iter()
            .take_while(|queue| never_used(queue))
            .count();
        if !with_rings && unused >= 3 {
            let run = &queues[index..index + unused];
            let size = run[0].size;
            builder.push_record(vec![
                format!("  {}-{}", run[0].index, run[unused - 1].index),
                String::new(),
                if run.iter().all(|queue| queue.size == size) {
                    size.to_string()
                } else {
                    "-".into()
                },
                "0".into(),
                "-".into(),
                "0".into(),
                "-".into(),
                "-".into(),
                format!("never used ({unused} queues)"),
                "-".into(),
            ]);
            index += unused;
            continue;
        }
        let queue = &queues[index];
        index += 1;
        let look = seen.look(queue, virtio_id, count, now);
        if let Some((seconds, _)) = look.movement {
            since = Some(since.map_or(seconds, |since| since.max(seconds)));
        }
        let mut row = vec![
            format!("  {}", queue.index),
            look.name
                .as_ref()
                .map_or_else(String::new, |(name, _)| name.clone()),
            queue.size.to_string(),
        ];
        let state = match (&queue.ring, &queue.packed, &queue.error) {
            (Some(ring), _, _) => {
                let driver = queue.driver.as_ref();
                row.extend([
                    ring.avail_idx.to_string(),
                    ring.used_idx.to_string(),
                    driver.map_or("-".into(), |driver| driver.last_used.to_string()),
                    driver.map_or("-".into(), |driver| driver.free.to_string()),
                ]);
                queue_verdict(ring, driver)
            }
            (None, Some(packed), _) => {
                row.extend([
                    packed.next_avail.to_string(),
                    "-".into(),
                    packed.last_used.to_string(),
                    packed.free.to_string(),
                ]);
                queue
                    .packed_ring
                    .as_ref()
                    .map_or_else(|| ui::muted("packed ring"), packed_verdict)
            }
            (None, None, error) => {
                row.extend([String::new(), String::new(), String::new(), String::new()]);
                ui::muted(error.as_deref().unwrap_or("unreadable"))
            }
        };
        row.push(moved_text(look.movement.as_ref()));
        row.push(
            match look
                .movement
                .as_ref()
                .and_then(|(_, moved)| moved.stall.as_ref())
            {
                Some(stall) => format!("{state}; {stall}"),
                None => state,
            },
        );
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
    since
}

/// The Moved column: what the driver published and the device returned
/// (a split ring) or the driver took back (a packed ring) since the last
/// look; `-` on the first.
fn moved_text(movement: Option<&(f64, QueueMovement)>) -> String {
    movement.map_or_else(
        || "-".into(),
        |(_, moved)| {
            format!(
                "+{}/+{}",
                moved.published,
                moved.completed.unwrap_or(moved.taken_back)
            )
        },
    )
}

/// Whether no buffer has gone through the queue since the driver set it
/// up.
fn never_used(queue: &VirtQueue) -> bool {
    match (
        &queue.ring,
        &queue.driver,
        &queue.packed,
        &queue.packed_ring,
    ) {
        (Some(ring), Some(driver), _, _) => {
            ring.avail_idx == 0 && ring.used_idx == 0 && driver.avail_idx == 0
        }
        (None, _, Some(packed), Some(ring)) => {
            packed.next_avail == 0
                && packed.last_used == 0
                && packed.free == queue.size
                && ring.with_device == 0
                && ring.returned == 0
        }
        _ => false,
    }
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

/// When one side asks the other to signal it, in words.
fn signal_text(signal: Signal, index: &str, off: &str) -> String {
    match signal {
        Signal::On => "on".into(),
        Signal::Off => format!("off ({off})"),
        Signal::After(value) => format!("after {index} {value} (event index)"),
        Signal::At { position, lap } => {
            format!("at position {position} in lap {}", u8::from(lap))
        }
    }
}

/// The queue's name and number for a detail view's first line.
fn queue_title(queue: &VirtQueue, look: &QueueLook) -> String {
    match &look.name {
        Some((name, _)) => format!("queue {} ({name})", queue.index),
        None => format!("queue {}", queue.index),
    }
}

/// What moved since the last look at the queue, for a detail view.
fn print_movement(look: &QueueLook, packed: bool) {
    let Some((seconds, moved)) = &look.movement else {
        outln!(
            "  {}",
            ui::muted("moved: this is the first look; run !vring again to see what moves")
        );
        return;
    };
    let mut parts = vec![format!(
        "{} +{}",
        if packed { "filled" } else { "avail" },
        moved.published
    )];
    if let Some(completed) = moved.completed {
        parts.push(format!("used +{completed}"));
    }
    parts.push(format!("taken back +{}", moved.taken_back));
    outln!(
        "  moved since the last look {seconds:.1} s of guest time ago: {}",
        parts.join(", ")
    );
    if let Some(stall) = &moved.stall {
        outln!("  {stall}");
    }
}

/// A packed queue: the driver's positions and lap bits, its signalling,
/// the ring's state, and the buffers the device holds.
fn print_packed_ring(
    target: &Target,
    queue: &VirtQueue,
    state: &PackedQueueState,
    ring: &PackedRing,
    look: &QueueLook,
    kind: Option<RequestKind>,
) {
    let lap = |wrap: bool| if wrap { 1 } else { 0 };
    outln!(
        "virtqueue {}  {}  size {}  packed",
        ui::addr(queue.address.0),
        queue_title(queue, look),
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
    outln!(
        "  interrupts: {}",
        signal_text(state.interrupts, "position", "the driver disabled them")
    );
    outln!(
        "  notifications: {}",
        signal_text(state.notifications, "position", "the device disabled them")
    );
    outln!("  state: {}", packed_verdict(ring));
    print_movement(look, true);
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
        let parts = chain
            .descriptors
            .iter()
            .map(|(_, desc)| (desc.addr, desc.len, desc.flags));
        print_request(target, kind, parts, true, false, None);
    }
    print_more(ring.with_device as usize, ring.chains.len());
    outln!();
}

/// A split ring: its addresses and indexes, and with the driver's queue,
/// its signalling, state, movement, and the buffers outstanding.
fn print_ring(
    target: &Target,
    queue: Option<&VirtQueue>,
    ring: &SplitRing,
    look: Option<&QueueLook>,
    kind: Option<RequestKind>,
) {
    match (queue, look) {
        (Some(queue), Some(look)) => outln!(
            "virtqueue {}  {}  size {}",
            ui::addr(queue.address.0),
            queue_title(queue, look),
            ring.size
        ),
        _ => outln!("ring of {} entries", ring.size),
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
    let event_idx = queue.is_some_and(|queue| queue.event_idx);
    let signals = split_signals(ring, driver, event_idx);
    outln!(
        "  interrupts: {}{}",
        signal_text(
            signals.interrupts,
            "used idx",
            "the driver set NO_INTERRUPT"
        ),
        if signals.interrupt_due {
            "; one was due for the returned buffers"
        } else {
            ""
        }
    );
    outln!(
        "  notifications: {}",
        signal_text(
            signals.notifications,
            "avail idx",
            "the device set NO_NOTIFY"
        )
    );
    outln!("  state: {}", queue_verdict(ring, driver));
    if let Some(look) = look {
        print_movement(look, false);
    }
    let chains = target.split_ring_outstanding(ring, MAX_LISTED_CHAINS);
    if !chains.is_empty() {
        outln!();
        outln!("{}", ui::label("Buffers with the device"));
        for chain in &chains {
            print_chain(target, &format!("avail[{}]", chain.avail_index), chain);
            print_request(target, kind, split_parts(chain), false, false, None);
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
                print_request(
                    target,
                    kind,
                    split_parts(&buffer.chain),
                    false,
                    true,
                    Some(buffer.written),
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

/// A split chain's descriptors as (address, length, flags).
fn split_parts(chain: &DescChain) -> impl Iterator<Item = (u64, u32, u16)> + '_ {
    chain
        .descriptors
        .iter()
        .map(|(_, desc)| (desc.addr, desc.len, desc.flags))
}

/// Under a buffer's descriptors, what the request asks and, once the
/// device `returned` it, what it answered.
fn print_request(
    target: &Target,
    kind: Option<RequestKind>,
    descriptors: impl IntoIterator<Item = (u64, u32, u16)>,
    packed: bool,
    returned: bool,
    written: Option<u32>,
) {
    let Some(kind) = kind else {
        return;
    };
    if let Some(text) = target.describe_request(kind, descriptors, packed, returned, written) {
        outln!("      {text}");
    }
}

/// What the indirect table an `I` descriptor names holds, or nothing for
/// a direct descriptor.
fn indirect_note(target: &Target, flags: u16, addr: u64, len: u32, packed: bool) -> String {
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
fn print_chain(target: &Target, label: &str, chain: &DescChain) {
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

#[cfg(test)]
mod tests {
    use super::{LookTime, VirtioSeen};
    use crate::target::virtio::{DriverQueueState, SplitRing, VirtQueue};
    use crate::types::VirtAddr;

    /// An idle queue at a fixed address whose ring is at `desc`, with
    /// every index at `index`.
    fn queue(desc: u64, index: u16) -> VirtQueue {
        VirtQueue {
            index: 0,
            address: VirtAddr(0xffff_b482_5525_1000),
            size: 256,
            driver: Some(DriverQueueState {
                avail_idx: index,
                last_used: index,
                free: 256,
                unkicked: 0,
            }),
            ring: Some(SplitRing {
                size: 256,
                desc: VirtAddr(desc),
                avail: VirtAddr(desc + 0x1000),
                used: VirtAddr(desc + 0x1240),
                avail_flags: 0,
                avail_idx: index,
                used_flags: 0,
                used_idx: index,
                used_event: None,
                avail_event: None,
            }),
            packed: None,
            packed_ring: None,
            event_idx: false,
            error: None,
        }
    }

    /// A queue set up again at the same address, its counts back at zero,
    /// is a first look, not some 60,000 buffers moved.
    #[test]
    fn a_queue_set_up_again_at_the_same_address_starts_afresh() {
        let mut seen = VirtioSeen::default();
        seen.look(&queue(0x1000_0000, 5000), Some(2), 1, LookTime::Guest(0));
        let later = seen.look(
            &queue(0x1000_0000, 5100),
            Some(2),
            1,
            LookTime::Guest(10_000_000),
        );
        assert_eq!(later.movement.map(|(_, moved)| moved.published), Some(100));
        let reset = seen.look(
            &queue(0x2000_0000, 0),
            Some(2),
            1,
            LookTime::Guest(20_000_000),
        );
        assert!(reset.movement.is_none());
    }
}
