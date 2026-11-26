//! Where guest RAM sits, for the Linux and Windows host backends: which of
//! the hypervisor process's regions holds it, and how guest-physical
//! addresses map into that region. The guest architecture and QEMU's
//! arguments decide both, not the host.

use super::MemoryRegion;
use crate::base::error::{Error, Result};
use crate::base::types::PhysAddr;

/// How guest RAM sits in the guest-physical address space. This follows
/// the guest architecture, not the hypervisor: x86 machines map RAM from
/// 0 around a 32-bit MMIO hole, while QEMU's aarch64 `virt` machine puts
/// one contiguous block at 1 GiB with firmware and MMIO below it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RamLayout {
    X86 { hole_start: u64 },
    Aarch64Virt,
}

/// Base of the `virt` machine's RAM. Everything below is flash and MMIO.
const AARCH64_VIRT_RAM_BASE: u64 = 0x4000_0000;

/// Top of the 32-bit MMIO hole on x86 machines; RAM resumes at 4 GiB.
const X86_MMIO_HOLE_END: u64 = 0x1_0000_0000;

impl RamLayout {
    /// A VMware x86 guest, which keeps 3 GiB below the 32-bit MMIO hole.
    pub(super) const VMWARE: Self = Self::X86 {
        hole_start: 0xC000_0000,
    };

    /// A QEMU guest with `ram_size` bytes of RAM: the `virt` machine for an
    /// AArch64 emulator, else the x86 machine its arguments name.
    pub(super) fn qemu<S: AsRef<str>>(aarch64: bool, args: &[S], ram_size: u64) -> Self {
        if aarch64 {
            return Self::Aarch64Virt;
        }
        Self::X86 {
            hole_start: qemu_x86_hole_start(qemu_x86_machine(args), ram_size),
        }
    }

    pub(super) fn ram_base(self) -> u64 {
        match self {
            Self::X86 { .. } => 0,
            Self::Aarch64Virt => AARCH64_VIRT_RAM_BASE,
        }
    }

    /// Guest-physical RAM as `(base, len)` runs for `size` bytes of RAM: on
    /// x86, low RAM up to the 32-bit MMIO hole and the remainder from 4 GiB;
    /// on AArch64, one run from the RAM base. Inverse of
    /// [`offset`](Self::offset).
    pub(super) fn ram_runs(self, size: u64) -> Vec<(u64, u64)> {
        match self {
            Self::X86 { hole_start } if size > hole_start => {
                vec![(0, hole_start), (X86_MMIO_HOLE_END, size - hole_start)]
            }
            Self::X86 { .. } => vec![(0, size)],
            Self::Aarch64Virt => vec![(AARCH64_VIRT_RAM_BASE, size)],
        }
    }

    /// Offset of a guest-physical address into the VM's RAM mapping, or
    /// `None` where no RAM backs it: the x86 32-bit MMIO hole, or anything
    /// below an AArch64 guest's RAM base. Mapping either one anywhere would
    /// alias real pages.
    fn offset(self, gpa: PhysAddr) -> Option<u64> {
        match self {
            // Low RAM is identity-mapped up to the hole; RAM above 4 GiB
            // follows it in the mapping, so the hole's size is subtracted.
            Self::X86 { hole_start } => {
                if gpa < hole_start {
                    Some(gpa)
                } else if gpa < X86_MMIO_HOLE_END {
                    None
                } else {
                    Some(gpa - (X86_MMIO_HOLE_END - hole_start))
                }
            }
            Self::Aarch64Virt => gpa.checked_sub(AARCH64_VIRT_RAM_BASE),
        }
    }

    /// Host address of the `len` guest-physical bytes at `addr` in `memory`.
    pub(super) fn host_address(
        self,
        memory: &MemoryRegion,
        addr: PhysAddr,
        len: usize,
    ) -> Result<u64> {
        // The mapping places high RAM right after low RAM, so a range
        // crossing the MMIO hole would silently continue into high RAM;
        // both ends must sit in the same RAM run.
        let last = (len as u64).saturating_sub(1);
        self.offset(addr)
            .filter(|&offset| {
                addr.checked_add(last).and_then(|end| self.offset(end)) == offset.checked_add(last)
            })
            .and_then(|offset| memory.host_range(offset, len))
            .ok_or(Error::BadPhysicalAddress(addr))
    }
}

/// The region that holds guest RAM: the one `expected_size` long when the
/// hypervisor's arguments give a size, else the largest. The largest alone
/// can be something else, such as an ASan shadow reservation orders of
/// magnitude bigger than the guest.
pub(super) fn guest_ram_region(
    regions: impl IntoIterator<Item = MemoryRegion>,
    expected_size: Option<u64>,
) -> Option<MemoryRegion> {
    let regions: Vec<MemoryRegion> = regions.into_iter().collect();
    expected_size
        .and_then(|size| regions.iter().find(|region| region.length == size).copied())
        .or_else(|| regions.into_iter().max_by_key(|region| region.length))
}

/// QEMU's two x86 PC machines, which split RAM around the 32-bit MMIO
/// hole differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QemuX86Machine {
    Q35,
    /// `pc`, QEMU's default machine.
    I440fx,
}

/// The machine QEMU was started with (`-machine`/`-M`, its type first
/// or as `type=`), from its arguments.
fn qemu_x86_machine<S: AsRef<str>>(args: &[S]) -> QemuX86Machine {
    let mut args = args.iter().map(AsRef::as_ref);
    let mut machine = None;
    while let Some(arg) = args.next() {
        if matches!(arg, "-machine" | "--machine" | "-M")
            && let Some(value) = args.next()
        {
            let mut parts = value.split(',');
            let first = parts.next().filter(|part| !part.contains('='));
            machine = first
                .or_else(|| value.split(',').find_map(|part| part.strip_prefix("type=")))
                .or(machine);
        }
    }
    match machine {
        Some(name) if name.contains("q35") => QemuX86Machine::Q35,
        _ => QemuX86Machine::I440fx,
    }
}

/// Where QEMU ends RAM below 4 GiB (`pc_q35_init`, `pc_init1`): q35
/// keeps 2 GiB there once the guest has 2.75 GiB, i440fx 3 GiB once it
/// has 3.5 GiB; a smaller guest's RAM all fits below.
fn qemu_x86_hole_start(machine: QemuX86Machine, ram_size: u64) -> u64 {
    let (threshold, low) = match machine {
        QemuX86Machine::Q35 => (0xB000_0000, 0x8000_0000),
        QemuX86Machine::I440fx => (0xE000_0000, 0xC000_0000),
    };
    if ram_size >= threshold {
        low
    } else {
        threshold
    }
}

/// A size from a QEMU command line, with an optional `k`, `M`, `G` or
/// `T` suffix. A plain number is `default_unit` bytes: `-m` counts MiB,
/// while an `-object` `size=` counts bytes.
fn qemu_size(value: &str, default_unit: u64) -> Option<u64> {
    let value = value.trim();
    let (digits, unit) = match value.as_bytes().last()?.to_ascii_lowercase() {
        b'k' => (&value[..value.len() - 1], 1 << 10),
        b'm' => (&value[..value.len() - 1], 1 << 20),
        b'g' => (&value[..value.len() - 1], 1 << 30),
        b't' => (&value[..value.len() - 1], 1 << 40),
        _ => (value, default_unit),
    };
    digits.parse::<u64>().ok()?.checked_mul(unit)
}

/// One field of a QEMU `-object` argument, in either the `key=value`
/// form or the JSON form (`{"qom-type":...}`).
fn qemu_option_field<'a>(value: &'a str, key: &str) -> Option<&'a str> {
    let value = value.trim_start_matches('{').trim_end_matches('}');
    for field in value.split(',') {
        let (name, value) = match field.split_once('=') {
            Some(pair) => pair,
            None => match field.split_once(':') {
                Some(pair) => pair,
                None => continue,
            },
        };
        if name.trim().trim_matches('"') == key {
            return Some(value.trim().trim_matches('"'));
        }
    }
    None
}

/// Guest RAM size from QEMU's arguments: the memory backend that
/// `-machine memory-backend=` names when there is one, else `-m`. The
/// size tells the RAM mapping apart from the process's other large
/// mappings, such as an ASan shadow reservation.
pub(super) fn qemu_ram_size<S: AsRef<str>>(args: &[S]) -> Option<u64> {
    let mut memory_backend = None;
    let mut backends: Vec<(&str, u64)> = Vec::new();
    let mut m_size = None;
    let mut i = 0;
    while i < args.len() {
        let value = args.get(i + 1).map(AsRef::as_ref);
        match args[i].as_ref() {
            "-m" | "--m" => {
                if let Some(value) = value {
                    let size = value.split(',').next().unwrap_or(value);
                    let size = size.strip_prefix("size=").unwrap_or(size);
                    m_size = qemu_size(size, 1 << 20);
                }
                i += 2;
                continue;
            }
            "-object" | "--object" => {
                if let Some(value) = value
                    && let Some(id) = qemu_option_field(value, "id")
                    && let Some(size) =
                        qemu_option_field(value, "size").and_then(|size| qemu_size(size, 1))
                {
                    backends.push((id, size));
                }
                i += 2;
                continue;
            }
            "-machine" | "--machine" | "-M" => {
                if let Some(value) = value
                    && let Some(id) = qemu_option_field(value, "memory-backend")
                {
                    memory_backend = Some(id);
                }
                i += 2;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    memory_backend
        .and_then(|id| backends.into_iter().find(|(name, _)| *name == id))
        .map(|(_, size)| size)
        .or(m_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1 << 30;

    fn region(start: u64, length: u64) -> MemoryRegion {
        MemoryRegion {
            start,
            end: start + length,
            length,
        }
    }

    /// ASan reserves a ~15 TiB read-write shadow mapping. The guest RAM
    /// region is the one whose size the QEMU arguments report.
    #[test]
    fn guest_ram_is_the_region_of_the_reported_size() {
        let shadow = region(0x200_8fff_7000, 0x1000_7fff_8000 - 0x200_8fff_7000);
        let ram = region(0x7baa_1840_0000, 8 * GIB);
        let small = region(0x7baa_0000_0000, 0x10_0000);

        assert_eq!(
            guest_ram_region([shadow, ram, small], Some(8 * GIB)),
            Some(ram)
        );
        // Without the size, or with one no region has, the largest wins.
        assert_eq!(guest_ram_region([shadow, ram, small], None), Some(shadow));
        assert_eq!(
            guest_ram_region([shadow, ram, small], Some(4 * GIB)),
            Some(shadow)
        );
    }

    #[test]
    fn qemu_ram_size_reads_the_memory_backend_and_m() {
        let keyval = [
            "qemu-system-x86_64",
            "-machine",
            "pc-q35-10.2,usb=off,memory-backend=pc.ram",
            "-m",
            "size=8388608k",
            "-object",
            "memory-backend-ram,id=pc.ram,size=8G",
        ];
        assert_eq!(qemu_ram_size(&keyval), Some(8 * GIB));

        let json = [
            "qemu-system-x86_64",
            "-machine",
            "pc-q35-10.2,memory-backend=pc.ram",
            "-m",
            "size=8388608k",
            "-object",
            r#"{"qom-type":"memory-backend-memfd","id":"pc.ram","share":true,"size":8589934592}"#,
        ];
        assert_eq!(qemu_ram_size(&json), Some(8 * GIB));

        assert_eq!(
            qemu_ram_size(&["qemu-system-x86_64", "-m", "4G"]),
            Some(4 * GIB)
        );
        assert_eq!(
            qemu_ram_size(&["qemu-system-x86_64", "-m", "512"]),
            Some(512 << 20)
        );
        assert_eq!(qemu_ram_size::<&str>(&[]), None);
    }

    #[test]
    fn qemu_sizes_accept_units() {
        assert_eq!(qemu_size("8G", 1), Some(8 << 30));
        assert_eq!(qemu_size("512M", 1), Some(512 << 20));
        assert_eq!(qemu_size("1024k", 1), Some(1 << 20));
        // `-m` counts MiB without a suffix; an object's size counts bytes.
        assert_eq!(qemu_size("512", 1 << 20), Some(512 << 20));
        assert_eq!(qemu_size("512", 1), Some(512));
    }

    #[test]
    fn x86_guest_ram_skips_the_32_bit_mmio_hole() {
        let layout = RamLayout::X86 {
            hole_start: 0x8000_0000,
        };

        assert_eq!(layout.offset(0), Some(0));
        assert_eq!(layout.offset(0x7FFF_FFFF), Some(0x7FFF_FFFF));
        // No RAM backs the hole; mapping it would alias real pages.
        assert_eq!(layout.offset(0x8000_0000), None);
        assert_eq!(layout.offset(0xFFFF_FFFF), None);
        // RAM resumes at 4 GiB, packed against the low RAM before it.
        assert_eq!(layout.offset(0x1_0000_0000), Some(0x8000_0000));
    }

    /// A read that runs into the hole would continue into high RAM in the
    /// mapping, which is not where the guest's next bytes are.
    #[test]
    fn a_read_across_the_hole_is_refused() {
        let layout = RamLayout::X86 {
            hole_start: 0x8000_0000,
        };
        let memory = region(0x7F00_0000_0000, 4 * GIB);

        assert_eq!(
            layout.host_address(&memory, 0x7FFF_F000, 0x1000).unwrap(),
            0x7F00_7FFF_F000
        );
        assert!(matches!(
            layout.host_address(&memory, 0x7FFF_F800, 0x1000),
            Err(Error::BadPhysicalAddress(0x7FFF_F800))
        ));
        assert_eq!(
            layout.host_address(&memory, 0x1_0000_0000, 8).unwrap(),
            0x7F00_8000_0000
        );
    }

    /// An 8 GiB i440fx guest (libvirt's `pc`) keeps 3 GiB below the
    /// hole, so its high RAM sits 1 GiB later in the mapping than a q35
    /// guest's; a q35 guest under 2.75 GiB has no RAM moved above 4 GiB.
    #[test]
    fn the_hole_starts_where_the_qemu_machine_ends_low_ram() {
        let args = |line: &'static str| line.split(' ').collect::<Vec<_>>();
        let machine = |line| qemu_x86_machine(&args(line));
        assert_eq!(
            machine("qemu-system-x86_64 -name guest=winvista -machine pc-i440fx-11.1,usb=off"),
            QemuX86Machine::I440fx
        );
        assert_eq!(
            machine("qemu-system-x86_64 -machine pc-q35-11.1,usb=off,dump-guest-core=off"),
            QemuX86Machine::Q35
        );
        assert_eq!(
            machine("qemu-system-x86_64 -M accel=kvm,type=q35"),
            QemuX86Machine::Q35
        );
        // No -machine: QEMU's default, `pc`.
        assert_eq!(machine("qemu-system-x86_64 -m 4G"), QemuX86Machine::I440fx);

        let hole = qemu_x86_hole_start;
        assert_eq!(hole(QemuX86Machine::I440fx, 8 * GIB), 3 * GIB);
        assert_eq!(hole(QemuX86Machine::Q35, 8 * GIB), 2 * GIB);
        assert_eq!(hole(QemuX86Machine::Q35, 2 * GIB + GIB / 2), 0xB000_0000);
        assert_eq!(hole(QemuX86Machine::I440fx, 3 * GIB), 0xE000_0000);
        let layout = RamLayout::qemu(false, &args("qemu-system-x86_64 -m 8G"), 8 * GIB);
        assert_eq!(layout.offset(0x1_3d3d_7cf8), Some(0xfd3d_7cf8));
        // The emulator's architecture decides before any machine argument.
        assert_eq!(
            RamLayout::qemu(true, &args("qemu-system-aarch64 -M q35"), 8 * GIB),
            RamLayout::Aarch64Virt
        );
    }

    #[test]
    fn aarch64_guest_ram_starts_at_the_virt_machine_base() {
        let layout = RamLayout::Aarch64Virt;

        // Flash and MMIO live below the base, not RAM.
        assert_eq!(layout.offset(0x3FFF_FFFF), None);
        assert_eq!(layout.offset(0x4000_0000), Some(0));
        assert_eq!(layout.offset(0x4000_1000), Some(0x1000));
    }

    #[test]
    fn ram_runs_report_where_each_layout_puts_its_memory() {
        let x86 = RamLayout::X86 {
            hole_start: 0x8000_0000,
        };

        // 1 GiB fits below the hole, so it is one run from 0.
        assert_eq!(x86.ram_runs(0x4000_0000), vec![(0, 0x4000_0000)]);
        // 4 GiB does not, so the top 2 GiB moves above the hole.
        assert_eq!(
            x86.ram_runs(0x1_0000_0000),
            vec![(0, 0x8000_0000), (0x1_0000_0000, 0x8000_0000)]
        );
        assert_eq!(
            RamLayout::Aarch64Virt.ram_runs(0x1_0000_0000),
            vec![(0x4000_0000, 0x1_0000_0000)]
        );
    }
}
