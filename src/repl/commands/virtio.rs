//! Virtio devices and virtqueues (`!virtio`, `!vring`).

use std::collections::HashMap;
use std::time::Instant;

use ntoseye_macros::command;
use tabled::builder::Builder;

use crate::error::{Error, Result};
use crate::repl::args::{ArgCursor, ArgCx, ArgError};
use crate::session::Session;
use crate::target::Target;
use crate::target::virtio::{
    PackedQueueState, PackedRing, QueueMovement, QueueProgress, Signal, SplitRing,
    VRING_DESC_F_INDIRECT, VRING_DESC_F_NEXT, VRING_DESC_F_WRITE, VirtQueue, VirtioBuffer,
    VirtioDescriptor, VirtioDriver, VirtioFunction, VirtioRing, name_queues, packed_verdict,
    queue_movement, queue_verdict, split_signals, virtio_type_name,
};
use crate::target::virtio_request::{RequestKind, request_kind, request_kind_named};
use crate::types::VirtAddr;
use crate::ui;

use crate::repl::*;

/// List the virtio devices and the state of their virtqueues.
///
/// Lists the virtio PCI functions with their device type and driver. With a
/// virtio-win driver's private PDB loaded, it also shows each queue's
/// indexes and state: what the device holds, what it returned that the
/// driver has not taken back, and what the driver has not published or
/// kicked. Moved compares with the previous look in guest time, and from the
/// second look the state names a queue that did not move. With an address,
/// shows the virtio_device there, typed by the module you give or by the
/// driver that owns it. See the virtio devices guide.
#[command(
    names = ["!virtio", "virtio"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    forms = [virtio, virtio_driver],
    usage = "!virtio [<virtio_device> [module]]",
    completion = [Expression, Expression]
)]
fn virtio_command(
    session: &Session,
    address: Option<VirtAddr>,
    module: Option<String>,
) -> Result<Virtio> {
    match address {
        None => virtio(session)
            .map(Virtio::Functions)
            .map_err(|error| Error::DebugInfo(format!("!virtio: pci.sys's device tree: {error}"))),
        Some(address) => virtio_driver(session, address, module)
            .map(Virtio::Device)
            .map_err(|error| Error::DebugInfo(format!("!virtio: {error}"))),
    }
}

/// List the virtio PCI functions (`!virtio`), with the state of each
/// queue where the driver's private PDB types it. A queue's `progress`
/// counters only grow, so two calls show what moved in between.
#[command(form_of = virtio_command, python = Inspect)]
fn virtio(session: &Session) -> Result<Vec<VirtioFunction>> {
    session.target.virtio_functions()
}

/// Read the `virtio_device` at `address` as its virtio-win driver sees it,
/// with its queues, named when its PCI function is found
/// (`!virtio <address> [module]`). `module` names the driver whose PDB
/// types it, by default the one that owns it.
#[command(form_of = virtio_command, python = Inspect)]
fn virtio_driver(
    session: &Session,
    #[arg(name = "virtio_device")] address: VirtAddr,
    module: Option<String>,
) -> Result<VirtioDriver> {
    let target = &session.target;
    let module = target.virtio_module_for(module.as_deref(), address, "virtio_device", "device")?;
    let mut driver = target.virtio_device(&module, address)?;
    if let Some(virtio_id) = device_type_of(target, |driver| driver.device == address) {
        name_queues(&mut driver.queues, virtio_id);
    }
    Ok(driver)
}

/// What `!virtio` shows: every virtio PCI function, or the `virtio_device`
/// at an address, its queues named when its function is found.
enum Virtio {
    Functions(Vec<VirtioFunction>),
    Device(VirtioDriver),
}

impl Render for Virtio {
    fn render(&self, repl: &mut ReplState<'_>, (): ()) {
        let now = LookTime::now(&repl.ctx.target);
        match self {
            Self::Functions(functions) => {
                print_virtio_functions(functions, &mut repl.virtio_seen, now)
            }
            Self::Device(driver) => {
                print_driver_header(driver);
                let seen = print_queues(&driver.queues, true, &mut repl.virtio_seen, now);
                print_moved_note(seen, driver.packed);
                outln!();
            }
        }
    }
}

/// Show a virtqueue's ring, its signalling, and its outstanding buffers.
///
/// Give a virtqueue address that !virtio lists. Shows the ring's indexes and
/// state, when the driver wants interrupts and the device wants
/// notifications (and for a split ring whether an interrupt was due), and up
/// to 64 buffers the device holds or returned, with their descriptors (W
/// device-writable, N continues, I indirect table). Under each buffer, a line
/// decodes the request and the device's answer from the virtio
/// specification's layouts, such as a block sector and status or a SCSI
/// command and its sense. /r reads a split ring from its size and kernel
/// addresses for a driver without a PDB, and /t names what its buffers hold:
/// blk, scsi, scsi-control, scsi-event, net, net-control, gpu, or vsock. See
/// the virtio devices guide.
#[command(
    names = ["!vring", "vring"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    forms = [vring, vring_raw],
    usage = "!vring <virtqueue> [module] | !vring /r <size> <desc> <avail> <used> [/t <kind>]",
    completion = [Expression, Expression, Expression, Expression, Expression, Expression, Expression]
)]
fn vring_command(
    session: &Session,
    #[arg(parse = vring_address)] address: Option<VirtAddr>,
    #[arg(parse = vring_module)] module: Option<String>,
    #[arg(parse = vring_kind)] kind: Option<RequestKind>,
    #[arg(parse = raw_ring_words)] raw: Option<RawRing>,
) -> Result<VirtioRing> {
    let fail = |error: Error| Error::DebugInfo(format!("!vring: {error}"));
    match (address, raw) {
        (Some(address), _) => vring(session, address, module, kind).map_err(fail),
        (None, Some(raw)) => {
            vring_raw(session, raw.size, raw.desc, raw.avail, raw.used, kind).map_err(fail)
        }
        (None, None) => Err(Error::DebugInfo(
            "!vring: give a virtqueue address, or a raw ring's size and addresses".into(),
        )),
    }
}

/// Read the virtio-win virtqueue at `address` (`!vring`): its ring, the
/// buffers the device holds or returned, and the request each carries.
/// `module` names the driver whose PDB types it, by default the one its
/// `add_buf` routine is in. `kind` says what its buffers hold, by default
/// what its device's type and the queue's index say.
#[command(form_of = vring_command, python = Inspect)]
fn vring(
    session: &Session,
    #[arg(name = "virtqueue")] address: VirtAddr,
    module: Option<String>,
    #[arg(sdk, default = None)] kind: Option<RequestKind>,
) -> Result<VirtioRing> {
    let target = &session.target;
    let mut queue = target.virtqueue_at(module.as_deref(), address)?;
    let device = target.virtqueue_device(queue.address);
    if let Some((virtio_id, _, queues)) = device {
        queue.name_as(virtio_id, queues);
    }
    let kind = kind.or_else(|| {
        device.and_then(|(virtio_id, transitional, queues)| {
            request_kind(virtio_id, queue.index, queues, transitional)
        })
    });
    if queue.ring.is_none() && (queue.packed.is_none() || queue.packed_ring.is_none()) {
        return Err(Error::DebugInfo(format!(
            "{:#x} has neither a split nor a packed ring",
            queue.address.0
        )));
    }
    Ok(target.virtio_ring(Some(queue), None, kind))
}

/// Read a split ring from its size and the kernel addresses of its
/// descriptor table, avail ring and used ring (`!vring /r`), for a driver
/// without a PDB. `kind` says what its buffers hold, for decoding their
/// requests (`/t`).
#[command(form_of = vring_command, python = Inspect, word = "/r")]
fn vring_raw(
    session: &Session,
    size: u32,
    desc: VirtAddr,
    avail: VirtAddr,
    used: VirtAddr,
    #[arg(name = "/t <kind>")] kind: Option<RequestKind>,
) -> Result<VirtioRing> {
    let target = &session.target;
    let ring = target.split_ring(size, desc, avail, used)?;
    Ok(target.virtio_ring(None, Some(ring), kind))
}

/// A split ring named by its size and the kernel addresses of its
/// descriptor table, avail ring and used ring (`!vring /r`), for a driver
/// without a PDB.
#[derive(Debug, Clone, Copy)]
pub struct RawRing {
    size: u32,
    desc: VirtAddr,
    avail: VirtAddr,
    used: VirtAddr,
}

/// The SDK's `kind`: what a ring's buffers hold, as a
/// [`VirtioRequestKind`] (`!vring /t` spells it with hyphens).
#[cfg(feature = "python")]
impl crate::python::command::PyArg for RequestKind {
    type Py = crate::target::virtio_request::VirtioRequestKind;
    fn from_py(value: Self::Py) -> Self {
        value.into()
    }
}

fn unknown_kind(name: &str) -> String {
    format!(
        "!vring: unknown request kind '{name}'; use blk, scsi, scsi-control, scsi-event, net, \
         net-control, gpu or vsock"
    )
}

/// `!vring <virtqueue> [module]`'s address; `/r` and four more words
/// start a raw ring instead.
fn vring_address(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<Option<VirtAddr>, ArgError> {
    let words = cursor.remaining();
    let Some(first) = cursor.word() else {
        return Err(ArgError::Missing);
    };
    match words {
        _ if words >= 5 && first == "/r" => Ok(None),
        1 | 2 => cx.eval(&first).map(Some),
        _ => Err(ArgError::Missing),
    }
}

/// The module after a virtqueue's address.
fn vring_module(
    _: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<Option<String>, ArgError> {
    Ok(match cursor.remaining() {
        1 => cursor.word().map(|word| word.into_owned()),
        _ => None,
    })
}

/// A raw ring's `/t <kind>`, after its four words, checked before they are
/// evaluated.
fn vring_kind(
    _: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<Option<RequestKind>, ArgError> {
    match cursor.remaining() {
        0..=4 => Ok(None),
        6 => {
            if cursor.word_at(4).as_deref() != Some("/t") {
                return Err(ArgError::Missing);
            }
            let name = cursor.word_at(4).ok_or(ArgError::Missing)?;
            match request_kind_named(&name) {
                Some(kind) => Ok(Some(kind)),
                None => Err(ArgError::Message(unknown_kind(&name))),
            }
        }
        _ => Err(ArgError::Missing),
    }
}

/// A raw ring's size and addresses.
fn raw_ring_words(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<Option<RawRing>, ArgError> {
    if cursor.remaining() != 4 {
        return Ok(None);
    }
    let mut values = [0u64; 4];
    for value in &mut values {
        let word = cursor.word().ok_or(ArgError::Missing)?;
        *value = cx.eval(&word)?.0;
    }
    let size = u32::try_from(values[0])
        .map_err(|_| ArgError::Message(format!("!vring: {:#x} is no ring size", values[0])))?;
    Ok(Some(RawRing {
        size,
        desc: VirtAddr(values[1]),
        avail: VirtAddr(values[2]),
        used: VirtAddr(values[3]),
    }))
}

impl Render for VirtioRing {
    fn render(&self, repl: &mut ReplState<'_>, (): ()) {
        let target = &repl.ctx.target;
        match (&self.queue, &self.raw_ring) {
            (Some(queue), _) => {
                let now = LookTime::now(target);
                let movement = repl.virtio_seen.look(queue, now);
                match (&queue.ring, &queue.packed, &queue.packed_ring) {
                    (Some(ring), _, _) => print_ring(
                        Some((queue, movement.as_ref())),
                        ring,
                        &self.with_device,
                        &self.returned,
                    ),
                    (None, Some(state), Some(ring)) => {
                        print_packed_ring(queue, state, ring, movement.as_ref(), &self.with_device)
                    }
                    _ => {}
                }
            }
            (None, Some(ring)) => print_ring(None, ring, &self.with_device, &self.returned),
            (None, None) => {}
        }
    }
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

/// How long ago the last look at a queue was, and what moved since.
type Movement = (f64, QueueMovement);

impl VirtioSeen {
    /// Look at `queue` at `now`, recording this look for the next, and say
    /// what moved since the last one. A stall needs the guest to have run
    /// between the looks.
    fn look(&mut self, queue: &VirtQueue, now: LookTime) -> Option<Movement> {
        let progress = QueueProgress::of(queue)?;
        let (at, before) = self.0.insert(ring_key(queue), (now, progress))?;
        let seconds = at.seconds_until(now);
        let mut moved = queue_movement(
            &before,
            &progress,
            queue.role,
            queue.interrupt_due(),
            seconds,
        );
        if seconds < MIN_STALL_SECONDS {
            moved.stall = None;
        }
        Some((seconds, moved))
    }
}

/// Below this much guest time between two looks, nothing is called stuck:
/// the guest barely ran, or not at all (stopped at a breakpoint).
const MIN_STALL_SECONDS: f64 = 0.5;

/// The virtio device type of the function whose driver `matches`.
fn device_type_of(target: &Target, matches: impl Fn(&VirtioDriver) -> bool) -> Option<u16> {
    target
        .virtio_functions()
        .ok()?
        .into_iter()
        .find(|function| function.driver.as_ref().is_some_and(&matches))
        .map(|function| function.virtio_id)
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
            function.location(),
            ui::label(&kind),
            function.device_id,
            function.service.as_deref().unwrap_or("-"),
            ui::muted(&format!("pdo {:#x}", function.pdo.0)),
        );
        match (&function.driver, &function.driver_missing) {
            (Some(driver), _) => {
                print_driver_header(driver);
                let since = print_queues(&driver.queues, false, seen, now);
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

/// The queues of a device, each recorded in `seen` for the next look.
/// Returns how long ago the last look at them was, when there was one.
fn print_queues(
    queues: &[VirtQueue],
    with_rings: bool,
    seen: &mut VirtioSeen,
    now: LookTime,
) -> Option<f64> {
    if queues.is_empty() {
        outln!("  {}", ui::muted("no queues set up"));
        return None;
    }
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
        let movement = seen.look(queue, now);
        if let Some((seconds, _)) = movement {
            since = Some(since.map_or(seconds, |since| since.max(seconds)));
        }
        let mut row = vec![
            format!("  {}", queue.index),
            queue.name.clone().unwrap_or_default(),
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
        row.push(moved_text(movement.as_ref()));
        row.push(
            match movement
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
fn moved_text(movement: Option<&Movement>) -> String {
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
fn queue_title(queue: &VirtQueue) -> String {
    match &queue.name {
        Some(name) => format!("queue {} ({name})", queue.index),
        None => format!("queue {}", queue.index),
    }
}

/// What moved since the last look at the queue, for a detail view.
fn print_movement(movement: Option<&Movement>, packed: bool) {
    let Some((seconds, moved)) = movement else {
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
    queue: &VirtQueue,
    state: &PackedQueueState,
    ring: &PackedRing,
    movement: Option<&Movement>,
    buffers: &[VirtioBuffer],
) {
    let lap = |wrap: bool| if wrap { 1 } else { 0 };
    outln!(
        "virtqueue {}  {}  size {}  packed",
        ui::addr(queue.address.0),
        queue_title(queue),
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
    print_movement(movement, true);
    if let Some(why) = &ring.broken {
        outln!(
            "  {}",
            ui::muted(&format!("the ring stopped reading: {why}"))
        );
    }
    if buffers.is_empty() {
        outln!();
        return;
    }
    outln!();
    outln!("{}", ui::label("Buffers with the device"));
    for buffer in buffers {
        let descriptors: Vec<String> = buffer
            .descriptors
            .iter()
            .map(|desc| {
                format!(
                    "[{}] id {} {:#x} len {:#x} {}{}",
                    desc.index,
                    desc.id.unwrap_or_default(),
                    desc.address,
                    desc.length,
                    flag_names(desc.flags),
                    indirect_note(desc)
                )
            })
            .collect();
        outln!("  {}", descriptors.join(" -> "));
        print_request(buffer);
    }
    print_more(ring.with_device as usize, buffers.len());
    outln!();
}

/// A split ring: its addresses and indexes, and with the driver's queue
/// (and what moved since the last look at it), its signalling, state,
/// movement, and the buffers outstanding.
fn print_ring(
    queue: Option<(&VirtQueue, Option<&Movement>)>,
    ring: &SplitRing,
    with_device: &[VirtioBuffer],
    returned: &[VirtioBuffer],
) {
    match queue {
        Some((queue, _)) => outln!(
            "virtqueue {}  {}  size {}",
            ui::addr(queue.address.0),
            queue_title(queue),
            ring.size
        ),
        None => outln!("ring of {} entries", ring.size),
    }
    outln!(
        "  desc {}  avail {}  used {}",
        ui::addr(ring.desc.0),
        ui::addr(ring.avail.0),
        ui::addr(ring.used.0)
    );
    let driver = queue.and_then(|(queue, _)| queue.driver.as_ref());
    outln!(
        "  avail idx {}  used idx {}{}",
        ring.avail_idx,
        ring.used_idx,
        driver.map_or(String::new(), |driver| format!(
            "  driver: published {}  taken back to {}  {} free  {} not kicked",
            driver.avail_idx, driver.last_used, driver.free, driver.unkicked
        ))
    );
    let event_idx = queue.is_some_and(|(queue, _)| queue.event_idx);
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
    if let Some((_, movement)) = queue {
        print_movement(movement, false);
    }
    if !with_device.is_empty() {
        outln!();
        outln!("{}", ui::label("Buffers with the device"));
        for buffer in with_device {
            print_chain(&format!("avail[{}]", buffer.position), buffer);
            print_request(buffer);
        }
        print_more(usize::from(ring.with_device()), with_device.len());
    }
    if let Some(driver) = driver
        && !returned.is_empty()
    {
        outln!();
        outln!("{}", ui::label("Returned, not yet taken back"));
        for buffer in returned {
            print_chain(
                &format!(
                    "used[{}] wrote {:#x}",
                    buffer.position,
                    buffer.written.unwrap_or_default()
                ),
                buffer,
            );
            print_request(buffer);
        }
        print_more(
            usize::from(ring.used_idx.wrapping_sub(driver.last_used)),
            returned.len(),
        );
    }
    outln!();
}

/// The count past the `shown` of `total` that a list left out.
fn print_more(total: usize, shown: usize) {
    if total > shown {
        outln!("  {}", ui::muted(&format!("... {} more", total - shown)));
    }
}

/// Under a buffer's descriptors, what the request asks and, once the
/// device returned it, what it answered.
fn print_request(buffer: &VirtioBuffer) {
    if let Some(text) = &buffer.request {
        outln!("      {text}");
    }
}

/// What the indirect table an `I` descriptor names holds, or nothing for
/// a direct descriptor.
fn indirect_note(desc: &VirtioDescriptor) -> String {
    match (&desc.indirect, &desc.indirect_error) {
        (Some(table), _) => format!(
            " ({} descriptor{}, out {:#x}, in {:#x})",
            table.descriptors,
            if table.descriptors == 1 { "" } else { "s" },
            table.out_bytes,
            table.in_bytes
        ),
        (None, Some(error)) => ui::muted(&format!(" (table unreadable: {error})")),
        (None, None) => String::new(),
    }
}

/// One buffer: `label`, its head, and its descriptors.
fn print_chain(label: &str, buffer: &VirtioBuffer) {
    let descriptors: Vec<String> = buffer
        .descriptors
        .iter()
        .map(|desc| {
            format!(
                "[{}] {:#x} len {:#x} {}{}",
                desc.index,
                desc.address,
                desc.length,
                flag_names(desc.flags),
                indirect_note(desc)
            )
        })
        .collect();
    outln!(
        "  {label} head {}: {}{}",
        buffer.head,
        descriptors.join(" -> "),
        buffer
            .broken
            .as_ref()
            .map(|why| ui::muted(&format!("  ({why})")))
            .unwrap_or_default()
    );
}

#[cfg(test)]
mod tests {
    use super::{LookTime, VirtioSeen};
    use crate::target::virtio::{DriverQueueState, QueueRole, SplitRing, VirtQueue};
    use crate::types::VirtAddr;

    /// An idle queue at a fixed address whose ring is at `desc`, with
    /// every index at `index`.
    fn queue(desc: u64, index: u16) -> VirtQueue {
        VirtQueue {
            index: 0,
            name: Some("request 0".into()),
            role: Some(QueueRole::Requests),
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
        seen.look(&queue(0x1000_0000, 5000), LookTime::Guest(0));
        let later = seen.look(&queue(0x1000_0000, 5100), LookTime::Guest(10_000_000));
        assert_eq!(later.map(|(_, moved)| moved.published), Some(100));
        let reset = seen.look(&queue(0x2000_0000, 0), LookTime::Guest(20_000_000));
        assert!(reset.is_none());
    }
}
