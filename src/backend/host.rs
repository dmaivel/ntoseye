struct MemoryRegion {
    start: u64,
    end: u64,
    length: u64,
}

impl MemoryRegion {
    /// Host address of the `len` bytes at `offset` into the region, if they
    /// all lie inside it.
    fn host_range(&self, offset: u64, len: usize) -> Option<u64> {
        let hva = self.start.checked_add(offset)?;
        (hva.checked_add(len as u64)? <= self.end).then_some(hva)
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use nix::sys::uio::{RemoteIoVec, process_vm_readv, process_vm_writev};
    use nix::unistd::Pid;
    use std::ffi::OsStr;
    use std::fs;
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use std::io::{IoSlice, IoSliceMut};

    use super::MemoryRegion;
    use crate::base::error::{Error, Result};
    use crate::base::memory::MemoryOps;
    use crate::base::types::PhysAddr;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum HvKind {
        Kvm,
        Vmware,
    }

    /// How guest RAM sits in the guest-physical address space. This follows
    /// the guest architecture, not the hypervisor: x86 machines map RAM from
    /// 0 around a 32-bit MMIO hole, while QEMU's aarch64 `virt` machine puts
    /// one contiguous block at 1 GiB with firmware and MMIO below it.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum RamLayout {
        X86 { hole_start: u64 },
        Aarch64Virt,
    }

    /// Base of the `virt` machine's RAM. Everything below is flash and MMIO.
    const AARCH64_VIRT_RAM_BASE: u64 = 0x4000_0000;

    /// Top of the 32-bit MMIO hole on x86 machines; RAM resumes at 4 GiB.
    const X86_MMIO_HOLE_END: u64 = 0x1_0000_0000;

    pub struct VmHandle {
        memory: MemoryRegion,
        pid: Pid,
        layout: RamLayout,
    }

    fn read_comm(pid: i32) -> Option<String> {
        fs::read_to_string(format!("/proc/{}/comm", pid))
            .ok()
            .map(|s| s.trim().to_string())
    }

    fn parse_pid(name: &OsStr) -> Option<i32> {
        name.to_str()?.parse().ok()
    }

    fn find_kvm_pid() -> Option<i32> {
        for entry in fs::read_dir("/proc").ok()?.flatten() {
            let Some(pid) = parse_pid(&entry.file_name()) else {
                continue;
            };

            let fd_dir = entry.path().join("fd");
            let fd_iter = match fs::read_dir(&fd_dir) {
                Ok(it) => it,
                Err(_) => continue, // permission denied or not a process dir
            };

            let has_kvm = fd_iter.flatten().any(|fd_entry| {
                fs::read_link(fd_entry.path())
                    .ok()
                    .map(|t| t.to_str() == Some("/dev/kvm"))
                    .unwrap_or(false)
            });

            if has_kvm {
                return Some(pid);
            }
        }
        None
    }

    fn find_vmware_pid() -> Option<i32> {
        for entry in fs::read_dir("/proc").ok()?.flatten() {
            let Some(pid) = parse_pid(&entry.file_name()) else {
                continue;
            };
            if read_comm(pid).as_deref() == Some("vmware-vmx") {
                return Some(pid);
            }
        }
        None
    }

    /// Whether the VM process is an AArch64 QEMU. The guest architecture is
    /// not discoverable from the mapping itself, and reading guest RAM is
    /// what discovery needs first, so the emulator binary's name decides it.
    fn is_aarch64_qemu(pid: i32) -> bool {
        let named_aarch64 = |name: &str| name.contains("aarch64");
        if let Ok(exe) = fs::read_link(format!("/proc/{}/exe", pid))
            && let Some(name) = exe.file_name().and_then(|name| name.to_str())
        {
            return named_aarch64(name);
        }
        // `comm` is truncated to 15 bytes ("qemu-system-aar"), which still
        // carries enough of the name to tell the emulators apart.
        read_comm(pid).is_some_and(|comm| named_aarch64(&comm))
    }

    fn ram_layout(pid: i32, hv: HvKind) -> RamLayout {
        match hv {
            HvKind::Kvm if is_aarch64_qemu(pid) => RamLayout::Aarch64Virt,
            HvKind::Kvm => RamLayout::X86 {
                hole_start: 0x8000_0000,
            },
            HvKind::Vmware => RamLayout::X86 {
                hole_start: 0xC000_0000,
            },
        }
    }

    fn find_vm_pid() -> Result<(i32, HvKind)> {
        if let Some(pid) = find_kvm_pid() {
            return Ok((pid, HvKind::Kvm));
        }
        if let Some(pid) = find_vmware_pid() {
            return Ok((pid, HvKind::Vmware));
        }
        Err(Error::VmNotFound)
    }

    fn primary_memory_region(pid: i32) -> Result<MemoryRegion> {
        let maps = File::open(format!("/proc/{}/maps", pid)).map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                Error::PtraceDenied {
                    pid,
                    scope: read_ptrace_scope(),
                }
            } else {
                Error::Io(e)
            }
        })?;
        let reader = BufReader::new(maps);
        let region = primary_memory_region_from_maps(reader.lines().map_while(|line| line.ok()))
            .ok_or(Error::NoVmMemoryRegion)?;

        Ok(region)
    }

    fn primary_memory_region_from_maps<I, S>(lines: I) -> Option<MemoryRegion>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        lines
            .into_iter()
            .filter_map(|line| {
                let mut parts = line.as_ref().split_whitespace();
                let addresses = parts.next()?;
                let permissions = parts.next()?;
                if !permissions.starts_with("rw") {
                    return None;
                }
                let (start, end) = addresses.split_once('-')?;
                let start = u64::from_str_radix(start, 16).ok()?;
                let end = u64::from_str_radix(end, 16).ok()?;
                Some(MemoryRegion {
                    start,
                    end,
                    length: end.checked_sub(start)?,
                })
            })
            .max_by_key(|region| region.length)
    }

    /// Offset of a guest-physical address into the VM's RAM mapping, or
    /// `None` where no RAM backs it: the x86 32-bit MMIO hole, or anything
    /// below an AArch64 guest's RAM base. Mapping either one anywhere would
    /// alias real pages.
    fn gpa_to_offset(layout: RamLayout, gpa: PhysAddr) -> Option<u64> {
        match layout {
            // Low RAM is identity-mapped up to the hole; RAM above 4 GiB
            // follows it in the mapping, so the hole's size is subtracted.
            RamLayout::X86 { hole_start } => {
                if gpa < hole_start {
                    Some(gpa)
                } else if gpa < X86_MMIO_HOLE_END {
                    None
                } else {
                    Some(gpa - (X86_MMIO_HOLE_END - hole_start))
                }
            }
            RamLayout::Aarch64Virt => {
                if gpa < AARCH64_VIRT_RAM_BASE {
                    None
                } else {
                    Some(gpa - AARCH64_VIRT_RAM_BASE)
                }
            }
        }
    }

    fn read_ptrace_scope() -> String {
        fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string())
    }

    fn probe_ptrace_access(pid: Pid, addr: u64) -> Result<()> {
        let mut probe = [0u8; 1];
        let remote_iov = RemoteIoVec {
            base: addr as usize,
            len: 1,
        };
        match process_vm_readv(pid, &mut [IoSliceMut::new(&mut probe)], &[remote_iov]) {
            Err(nix::Error::EPERM) => Err(Error::PtraceDenied {
                pid: pid.as_raw(),
                scope: read_ptrace_scope(),
            }),
            _ => Ok(()),
        }
    }

    impl VmHandle {
        pub fn new() -> Result<Self> {
            let (pid, hv) = find_vm_pid()?;
            let memory = primary_memory_region(pid)?;
            let nix_pid = Pid::from_raw(pid);
            probe_ptrace_access(nix_pid, memory.start)?;
            Ok(Self {
                memory,
                pid: nix_pid,
                layout: ram_layout(pid, hv),
            })
        }

        /// The host mapping guest reads are served from, for diagnostics.
        /// Whether the hypervisor aborts the VM when a debugger enables guest
        /// debugging through its GDB stub; KVM and VMware do not.
        pub fn guest_debug_aborts_vm(&self) -> bool {
            false
        }

        pub fn describe(&self) -> String {
            format!(
                "pid {}, host mapping {:#x}-{:#x}",
                self.pid, self.memory.start, self.memory.end
            )
        }

        pub fn ram_base(&self) -> u64 {
            match self.layout {
                RamLayout::X86 { .. } => 0,
                RamLayout::Aarch64Virt => AARCH64_VIRT_RAM_BASE,
            }
        }

        pub fn ram_size(&self) -> u64 {
            self.memory.length
        }

        /// Guest-physical RAM as `(base, len)` runs: on x86, low RAM up to
        /// the hypervisor's 32-bit MMIO hole and the remainder from 4 GiB;
        /// on AArch64, one run from the RAM base. Inverse of
        /// `gpa_to_offset`.
        pub fn ram_runs(&self) -> Vec<(u64, u64)> {
            let size = self.memory.length;
            match self.layout {
                RamLayout::X86 { hole_start } if size > hole_start => {
                    vec![(0, hole_start), (X86_MMIO_HOLE_END, size - hole_start)]
                }
                RamLayout::X86 { .. } => vec![(0, size)],
                RamLayout::Aarch64Virt => vec![(AARCH64_VIRT_RAM_BASE, size)],
            }
        }
        fn host_address(&self, addr: PhysAddr, len: usize) -> Result<u64> {
            gpa_to_offset(self.layout, addr)
                .and_then(|offset| self.memory.host_range(offset, len))
                .ok_or(Error::BadPhysicalAddress(addr))
        }
    }

    impl MemoryOps<PhysAddr> for VmHandle {
        fn read_bytes(&self, addr: PhysAddr, buf: &mut [u8]) -> Result<()> {
            let hva = self.host_address(addr, buf.len())?;
            let remote_iov = RemoteIoVec {
                base: hva as usize,
                len: buf.len(),
            };
            let bytes_read =
                process_vm_readv(self.pid, &mut [IoSliceMut::new(buf)], &[remote_iov])?;
            if bytes_read != buf.len() {
                return Err(Error::PartialRead(bytes_read));
            }
            Ok(())
        }

        fn write_bytes(&self, addr: PhysAddr, buf: &[u8]) -> Result<()> {
            let hva = self.host_address(addr, buf.len())?;
            let remote_iov = RemoteIoVec {
                base: hva as usize,
                len: buf.len(),
            };
            let bytes_written = process_vm_writev(self.pid, &[IoSlice::new(buf)], &[remote_iov])?;
            if bytes_written != buf.len() {
                return Err(Error::PartialWrite(bytes_written));
            }
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn process_names_must_be_numeric_pids() {
            assert_eq!(parse_pid(OsStr::new("42")), Some(42));
            assert_eq!(parse_pid(OsStr::new("fb")), None);
            assert_eq!(parse_pid(OsStr::new("self")), None);
            assert_eq!(parse_pid(OsStr::new("thread-self")), None);
        }

        #[test]
        fn guest_memory_selection_ignores_non_writable_mappings() {
            let maps = concat!(
                "1000-3000 rw-p 00000000 00:00 0\n",
                "3000-a000 r--p 00000000 00:00 0\n",
                "a000-14000 ---p 00000000 00:00 0\n",
            );
            let region = primary_memory_region_from_maps(maps.lines()).unwrap();

            assert_eq!(region.start, 0x1000);
            assert_eq!(region.end, 0x3000);
            assert_eq!(region.length, 0x2000);
        }

        #[test]
        fn x86_guest_ram_skips_the_32_bit_mmio_hole() {
            let layout = RamLayout::X86 {
                hole_start: 0x8000_0000,
            };

            assert_eq!(gpa_to_offset(layout, 0), Some(0));
            assert_eq!(gpa_to_offset(layout, 0x7FFF_FFFF), Some(0x7FFF_FFFF));
            // No RAM backs the hole; mapping it would alias real pages.
            assert_eq!(gpa_to_offset(layout, 0x8000_0000), None);
            assert_eq!(gpa_to_offset(layout, 0xFFFF_FFFF), None);
            // RAM resumes at 4 GiB, packed against the low RAM before it.
            assert_eq!(gpa_to_offset(layout, 0x1_0000_0000), Some(0x8000_0000));
        }

        #[test]
        fn aarch64_guest_ram_starts_at_the_virt_machine_base() {
            let layout = RamLayout::Aarch64Virt;

            // Flash and MMIO live below the base, not RAM.
            assert_eq!(gpa_to_offset(layout, 0x3FFF_FFFF), None);
            assert_eq!(gpa_to_offset(layout, 0x4000_0000), Some(0));
            assert_eq!(gpa_to_offset(layout, 0x4000_1000), Some(0x1000));
        }

        #[test]
        fn ram_runs_report_where_each_layout_puts_its_memory() {
            let handle = |layout, length| VmHandle {
                memory: MemoryRegion {
                    start: 0x7F00_0000_0000,
                    end: 0x7F00_0000_0000 + length,
                    length,
                },
                pid: Pid::from_raw(1),
                layout,
            };
            let x86 = RamLayout::X86 {
                hole_start: 0x8000_0000,
            };

            // 1 GiB fits below the hole, so it is one run from 0.
            assert_eq!(handle(x86, 0x4000_0000).ram_runs(), vec![(0, 0x4000_0000)]);
            // 4 GiB does not, so the top 2 GiB moves above the hole.
            assert_eq!(
                handle(x86, 0x1_0000_0000).ram_runs(),
                vec![(0, 0x8000_0000), (0x1_0000_0000, 0x8000_0000)]
            );
            assert_eq!(
                handle(RamLayout::Aarch64Virt, 0x1_0000_0000).ram_runs(),
                vec![(0x4000_0000, 0x1_0000_0000)]
            );
        }
    }
}

/// macOS (UTM) host backend: guest RAM is an anonymous mapping in the QEMU
/// process, read through its Mach task port (`task_for_pid` needs root or the
/// `com.apple.security.cs.debugger` entitlement).
#[cfg(target_os = "macos")]
mod platform {
    use super::MemoryRegion;
    use crate::base::error::{Error, Result};
    use crate::base::memory::MemoryOps;
    use crate::base::types::PhysAddr;

    pub struct VmHandle {
        task: u32,
        memory: MemoryRegion,
        pid: i32,
    }

    /// QEMU aarch64 `virt` machine memory map: RAM is one contiguous region
    /// starting at GPA 0x4000_0000 (1 GiB), sized by `-m`. Below that is
    /// flash/MMIO, not RAM.
    const AARCH64_RAM_BASE: u64 = 0x4000_0000;

    /// Smallest mapping that may begin a guest-RAM span. HVF's blocks are
    /// 128 MiB and TCG's single block is the whole guest, so this only ever
    /// rejects an incidental neighbour as a starting point.
    const MIN_RAM_BLOCK: u64 = 64 * 1024 * 1024;

    /// `struct vm_region_submap_info_64` (v2) from xnu
    /// `osfmk/mach/vm_region.h`. Layout is fixed by the MIG boundary; the
    /// count constant is hard-coded at 20 there.
    #[derive(Default)]
    #[repr(C)]
    struct VmRegionSubmapInfo64 {
        protection: i32,
        max_protection: i32,
        inheritance: u32,
        offset: u64,
        user_tag: u32,
        pages_resident: u32,
        pages_shared_now_private: u32,
        pages_swapped_out: u32,
        pages_dirtied: u32,
        ref_count: u32,
        shadow_depth: u16,
        external_pager: u8,
        share_mode: u8,
        is_submap: u32,
        behavior: i32,
        object_id: u32,
        user_wired_count: u16,
        flags: u16,
        pages_reusable: u32,
        object_id_full: u64,
    }
    const _: () = assert!(std::mem::size_of::<VmRegionSubmapInfo64>() == 80);

    /// `VM_REGION_SUBMAP_INFO_COUNT_64` (v2): 80 bytes / 4-byte natural_t.
    const VM_REGION_SUBMAP_INFO_COUNT_64: u32 = 20;

    const KERN_SUCCESS: i32 = 0;

    unsafe extern "C" {
        fn mach_task_self() -> u32;
        fn task_for_pid(target_task: u32, pid: i32, task: *mut u32) -> i32;
        fn mach_port_deallocate(task: u32, name: u32) -> i32;
        fn mach_vm_read_overwrite(
            target_task: u32,
            address: u64,
            size: u64,
            data: *mut u8,
            outsize: *mut u64,
        ) -> i32;
        fn mach_vm_write(target_task: u32, address: u64, data: *const u8, size: u64) -> i32;
        fn mach_vm_region_recurse(
            target_task: u32,
            address: *mut u64,
            size: *mut u64,
            nesting_depth: *mut u32,
            info: *mut VmRegionSubmapInfo64,
            count: *mut u32,
        ) -> i32;
        fn proc_listallpids(buffer: *mut u32, buffersize: i32) -> i32;
        fn proc_pidpath(pid: i32, buffer: *mut u8, buffersize: u32) -> i32;
    }

    /// Find the UTM ARM64 VM process. UTM loads QEMU's `main()` into a
    /// `QEMULauncher` process (the real binary is
    /// `qemu-aarch64-softmmu.framework/qemu-aarch64-softmmu`, dlopen'd in), so
    /// match either the native binary name or the launcher. `QEMUHelper` (the
    /// XPC service, which also matches case-insensitively) is deliberately
    /// excluded — it does not own the guest RAM.
    fn find_qemu_pid() -> Option<i32> {
        // First call with a null buffer returns the pid count.
        let count = unsafe { proc_listallpids(std::ptr::null_mut(), 0) };
        if count <= 0 {
            return None;
        }
        let mut pids = vec![0u32; count as usize];
        let written = unsafe { proc_listallpids(pids.as_mut_ptr(), (count * 4) as i32) };
        if written <= 0 {
            return None;
        }
        let mut path = [0u8; 4096];
        for &pid in pids.iter().take(written as usize) {
            let len = unsafe { proc_pidpath(pid as i32, path.as_mut_ptr(), path.len() as u32) };
            if len <= 0 {
                continue;
            }
            let name = String::from_utf8_lossy(&path[..len as usize]);
            let base = name.rsplit('/').next().unwrap_or("");
            let base_lower = base.to_ascii_lowercase();
            if base_lower == "qemuhelper" {
                continue;
            }
            let native_aarch64 = base_lower.contains("aarch64") && base_lower.contains("qemu");
            let utm_launcher = base_lower == "qemulauncher";
            if native_aarch64 || utm_launcher {
                return Some(pid as i32);
            }
        }
        None
    }

    /// Whether the QEMU process `pid` runs its guest under HVF: `-accel hvf`, or
    /// `accel=hvf` in `-machine`, among its arguments (`KERN_PROCARGS2`: argc,
    /// the executable path, then the arguments, NUL-separated). `false` when
    /// they cannot be read.
    fn runs_under_hvf(pid: i32) -> bool {
        let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
        let mut size: libc::size_t = 0;
        let mut sysctl = |buffer: *mut libc::c_void, size: &mut libc::size_t| unsafe {
            libc::sysctl(mib.as_mut_ptr(), 3, buffer, size, std::ptr::null_mut(), 0)
        };
        if sysctl(std::ptr::null_mut(), &mut size) != 0 {
            return false;
        }
        let mut buffer = vec![0u8; size];
        if sysctl(buffer.as_mut_ptr().cast(), &mut size) != 0 {
            return false;
        }
        buffer.truncate(size);
        let Some(argc) = buffer
            .get(..4)
            .map(|bytes| u32::from_ne_bytes(bytes.try_into().expect("4 bytes")) as usize)
        else {
            return false;
        };
        // The executable path, then argc arguments; the environment follows.
        let args: Vec<&[u8]> = buffer[4..]
            .split(|&byte| byte == 0)
            .filter(|arg| !arg.is_empty())
            .take(argc + 1)
            .collect();
        args.windows(2)
            .any(|pair| pair[0] == b"-accel" && pair[1].starts_with(b"hvf"))
            || args
                .iter()
                .any(|arg| arg.windows(9).any(|window| window == b"accel=hvf"))
    }

    fn task_for_vm_process(pid: i32) -> Result<u32> {
        let self_task = unsafe { mach_task_self() };
        let mut task = 0u32;
        let kr = unsafe { task_for_pid(self_task, pid, &mut task) };
        if kr != KERN_SUCCESS {
            return Err(Error::TaskForPidDenied {
                pid,
                detail: format!("task_for_pid returned mach error {kr}"),
            });
        }
        Ok(task)
    }

    /// The guest RAM is the largest *contiguous run* of read-write regions.
    /// QEMU under HVF maps the aarch64 guest RAM as adjacent 128 MiB blocks
    /// (64 blocks for an 8 GiB guest), so a "largest single region" heuristic
    /// would instead pick one of the process's huge PROT_NONE reservations
    /// (dyld shared cache ranges, hypervisor reservations).
    fn primary_memory_region(task: u32) -> Result<MemoryRegion> {
        let mut spans: Vec<MemoryRegion> = Vec::new();
        let mut address: u64 = 0;
        loop {
            let mut size: u64 = 0;
            let mut depth: u32 = 8;
            let mut info = VmRegionSubmapInfo64::default();
            let mut count = VM_REGION_SUBMAP_INFO_COUNT_64;
            let kr = unsafe {
                mach_vm_region_recurse(
                    task,
                    &mut address,
                    &mut size,
                    &mut depth,
                    &mut info,
                    &mut count,
                )
            };
            if kr != KERN_SUCCESS {
                break;
            }
            if size == 0 {
                break;
            }
            // Merge adjacent read-write regions into a span (the walk is
            // ascending, so the candidate span is always the last one).
            //
            // Only a large mapping may *begin* one. QEMU allocates guest RAM
            // in one big block under TCG and in 128 MiB blocks under HVF,
            // while the heap and JIT allocations that can abut it are far
            // smaller; letting one of those open the span moves its start,
            // which silently shifts every guest-physical address. Anything
            // adjacent still extends a span already under way, so no block
            // of guest RAM is ever dropped.
            if info.protection & 0b11 == 0b11 {
                let start = address;
                let Some(end) = address.checked_add(size) else {
                    break;
                };
                match spans.last_mut() {
                    Some(span) if span.end == start => {
                        span.end = end;
                        span.length = end - span.start;
                    }
                    _ if size >= MIN_RAM_BLOCK => spans.push(MemoryRegion {
                        start,
                        end,
                        length: end - start,
                    }),
                    _ => {}
                }
            }
            let Some(next) = address.checked_add(size) else {
                break;
            };
            address = next;
        }
        spans
            .into_iter()
            .max_by_key(|span| span.length)
            .ok_or(Error::NoVmMemoryRegion)
    }

    impl VmHandle {
        pub fn new() -> Result<Self> {
            let pid = find_qemu_pid().ok_or(Error::VmNotFound)?;
            let task = task_for_vm_process(pid)?;
            let memory = primary_memory_region(task)?;
            // Probe access: a task port without read rights fails here with a
            // clearer message than on the first guest read.
            let mut probe = [0u8; 1];
            let mut out = 0u64;
            let kr = unsafe {
                mach_vm_read_overwrite(task, memory.start, 1, probe.as_mut_ptr(), &mut out)
            };
            if kr != KERN_SUCCESS {
                return Err(Error::TaskForPidDenied {
                    pid,
                    detail: format!("VM process memory is not readable (mach error {kr})"),
                });
            }
            Ok(Self { task, memory, pid })
        }

        /// The host mapping guest reads are served from, for diagnostics.
        /// Whether QEMU may abort this VM when a debugger enables guest
        /// debugging through its GDB stub: QEMU before 10.1 does under HVF
        /// (`hv_vcpu_set_trap_debug_exceptions` fails off the vCPU's thread,
        /// qemu#2895; seen on UTM 4.7.5 and 5.0.5, which ships QEMU 10.0.12).
        /// See the UTM setup guide.
        pub fn guest_debug_aborts_vm(&self) -> bool {
            runs_under_hvf(self.pid)
        }

        pub fn describe(&self) -> String {
            format!(
                "pid {}, host mapping {:#x}-{:#x}",
                self.pid, self.memory.start, self.memory.end
            )
        }

        pub fn ram_base(&self) -> u64 {
            AARCH64_RAM_BASE
        }

        pub fn ram_size(&self) -> u64 {
            self.memory.length
        }

        /// Guest-physical RAM as one contiguous run from the `virt` RAM base.
        pub fn ram_runs(&self) -> Vec<(u64, u64)> {
            vec![(AARCH64_RAM_BASE, self.memory.length)]
        }

        fn gpa_offset(&self, gpa: PhysAddr) -> Result<u64> {
            if gpa < AARCH64_RAM_BASE {
                return Err(Error::BadPhysicalAddress(gpa));
            }
            let offset = gpa - AARCH64_RAM_BASE;
            if offset >= self.memory.length {
                return Err(Error::BadPhysicalAddress(gpa));
            }
            Ok(offset)
        }

        fn host_address(&self, addr: PhysAddr, len: usize) -> Result<u64> {
            self.memory
                .host_range(self.gpa_offset(addr)?, len)
                .ok_or(Error::BadPhysicalAddress(addr))
        }

        fn read_bytes_at(&self, addr: PhysAddr, buf: &mut [u8]) -> Result<()> {
            let hva = self.host_address(addr, buf.len())?;
            let mut out = 0u64;
            let kr = unsafe {
                mach_vm_read_overwrite(self.task, hva, buf.len() as u64, buf.as_mut_ptr(), &mut out)
            };
            if kr != KERN_SUCCESS {
                return Err(Error::BadPhysicalAddress(addr));
            }
            if out != buf.len() as u64 {
                return Err(Error::PartialRead(out as usize));
            }
            Ok(())
        }

        fn write_bytes_at(&self, addr: PhysAddr, buf: &[u8]) -> Result<()> {
            let hva = self.host_address(addr, buf.len())?;
            let kr = unsafe { mach_vm_write(self.task, hva, buf.as_ptr(), buf.len() as u64) };
            if kr != KERN_SUCCESS {
                return Err(Error::BadPhysicalAddress(addr));
            }
            Ok(())
        }
    }

    impl Drop for VmHandle {
        fn drop(&mut self) {
            unsafe {
                mach_port_deallocate(mach_task_self(), self.task);
            }
        }
    }

    impl MemoryOps<PhysAddr> for VmHandle {
        fn read_bytes(&self, addr: PhysAddr, buf: &mut [u8]) -> Result<()> {
            self.read_bytes_at(addr, buf)
        }

        fn write_bytes(&self, addr: PhysAddr, buf: &[u8]) -> Result<()> {
            self.write_bytes_at(addr, buf)
        }
    }
}

/// Windows host backend: guest RAM is one committed `PAGE_READWRITE` region
/// in the QEMU or VMware Workstation process, read and written through
/// `ReadProcessMemory`/`WriteProcessMemory`.
#[cfg(windows)]
mod platform {
    use std::ffi::c_void;
    use std::io;

    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_ACCESS_DENIED, HANDLE, INVALID_HANDLE_VALUE, LUID,
    };
    use windows_sys::Win32::Security::{
        AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_GUARD, PAGE_NOACCESS, PAGE_READWRITE,
        VirtualQueryEx,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_INFORMATION,
        PROCESS_VM_READ, PROCESS_VM_WRITE,
    };

    use super::MemoryRegion;
    use crate::base::error::{Error, Result};
    use crate::base::memory::MemoryOps;
    use crate::base::types::PhysAddr;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum HvKind {
        Qemu,
        Vmware,
    }

    /// How guest RAM sits in the guest-physical address space; the same rules
    /// the Linux backend follows, since the guest architecture decides them.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum RamLayout {
        X86 { hole_start: u64 },
        Aarch64Virt,
    }

    /// Base of the `virt` machine's RAM. Everything below is flash and MMIO.
    const AARCH64_VIRT_RAM_BASE: u64 = 0x4000_0000;

    /// Top of the 32-bit MMIO hole on x86 machines; RAM resumes at 4 GiB.
    const X86_MMIO_HOLE_END: u64 = 0x1_0000_0000;

    /// Guest RAM is at least this large; smaller committed regions belong to
    /// the emulator's own heap and JIT buffers.
    const MIN_RAM_REGION: u64 = 16 << 20;

    pub struct VmHandle {
        handle: HANDLE,
        memory: MemoryRegion,
        pid: u32,
        layout: RamLayout,
    }

    // SAFETY: a process handle is a kernel object usable from any thread, and
    // `ReadProcessMemory`/`WriteProcessMemory` are thread safe; the fields
    // next to it are plain data.
    unsafe impl Send for VmHandle {}
    // SAFETY: as above — and `MemoryOps` takes `&self` without mutating it.
    unsafe impl Sync for VmHandle {}

    /// Whether `name` is an emulator that keeps guest RAM in its own address
    /// space, and which one it is: QEMU (`qemu-system-<arch>.exe`) or VMware
    /// Workstation (`vmware-vmx*.exe`).
    fn hypervisor_of(name: &str) -> Option<HvKind> {
        let name = name.to_ascii_lowercase();
        if name.starts_with("qemu-system-") && name.ends_with(".exe") {
            return Some(HvKind::Qemu);
        }
        if name.starts_with("vmware-vmx") && name.ends_with(".exe") {
            return Some(HvKind::Vmware);
        }
        None
    }

    fn ram_layout(kind: HvKind, name: &str) -> RamLayout {
        match kind {
            // The guest architecture is not discoverable from the mapping
            // itself, so the emulator binary's name decides it, as on Linux.
            HvKind::Qemu if name.to_ascii_lowercase().contains("aarch64") => RamLayout::Aarch64Virt,
            HvKind::Qemu => RamLayout::X86 {
                hole_start: 0x8000_0000,
            },
            HvKind::Vmware => RamLayout::X86 {
                hole_start: 0xC000_0000,
            },
        }
    }

    /// A `szExeFile` image name, which the entry pads with NULs.
    fn exe_name(wide: &[u16]) -> String {
        let len = wide
            .iter()
            .position(|&unit| unit == 0)
            .unwrap_or(wide.len());
        String::from_utf16_lossy(&wide[..len])
    }

    /// The running emulator: QEMU before VMware, as on Linux, and the first
    /// of either that the snapshot lists.
    fn find_vm_process() -> Option<(u32, HvKind, String)> {
        // SAFETY: a process snapshot needs no input beyond its flags.
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut found = None;
        let mut entry = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        // SAFETY: the snapshot and entry are live for every call below.
        let mut more = unsafe { Process32FirstW(snapshot, &mut entry) } != 0;
        while more {
            let name = exe_name(&entry.szExeFile);
            if let Some(kind) = hypervisor_of(&name) {
                found = Some((entry.th32ProcessID, kind, name));
                if kind == HvKind::Qemu {
                    break;
                }
            }
            // SAFETY: as above.
            more = unsafe { Process32NextW(snapshot, &mut entry) } != 0;
        }
        // SAFETY: the snapshot came from the call above and is closed once.
        unsafe { CloseHandle(snapshot) };
        found
    }

    /// Enable `SeDebugPrivilege` in this process, once.
    ///
    /// An elevated token *holds* the privilege but leaves it disabled, and a hypervisor's VM
    /// process runs at a higher integrity level than an unelevated caller, so neither
    /// `OpenProcess` nor `ReadProcessMemory` works until the privilege is explicitly enabled.
    /// A normal (unelevated) token does not hold it at all; the attempt is then a no-op and
    /// `open_process` reports the access-denied error.
    fn enable_debug_privilege() {
        use std::sync::Once;
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            // SAFETY: the token handle is closed below; `LUID`, `TOKEN_PRIVILEGES` and the
            // privilege name outlive every call that reads them.
            unsafe {
                let mut token: HANDLE = std::ptr::null_mut();
                if OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                    &mut token,
                ) == 0
                {
                    return;
                }
                let name: Vec<u16> = "SeDebugPrivilege\0".encode_utf16().collect();
                let mut luid = LUID {
                    LowPart: 0,
                    HighPart: 0,
                };
                if LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), &mut luid) != 0 {
                    let privileges = TOKEN_PRIVILEGES {
                        PrivilegeCount: 1,
                        Privileges: [LUID_AND_ATTRIBUTES {
                            Luid: luid,
                            Attributes: SE_PRIVILEGE_ENABLED,
                        }],
                    };
                    AdjustTokenPrivileges(
                        token,
                        0,
                        &privileges,
                        0,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                    );
                }
                CloseHandle(token);
            }
        });
    }

    fn open_process(pid: u32) -> Result<HANDLE> {
        enable_debug_privilege();
        // SAFETY: no attributes are needed to open a process by id.
        let handle = unsafe {
            OpenProcess(
                PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION,
                0,
                pid,
            )
        };
        if handle.is_null() {
            let error = io::Error::last_os_error();
            return Err(
                if error.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) {
                    Error::VmProcessDenied {
                        pid,
                        detail: error.to_string(),
                    }
                } else {
                    Error::Io(error)
                },
            );
        }
        Ok(handle)
    }

    /// The process's next memory region, with `address` advanced past it.
    /// `None` at the end of the address space or at a region the query cannot
    /// describe, so a caller cannot spin on one address.
    fn next_region(handle: HANDLE, address: &mut usize) -> Option<MEMORY_BASIC_INFORMATION> {
        let mut info = MEMORY_BASIC_INFORMATION::default();
        // SAFETY: `info` is sized for the call and written only by it.
        let written = unsafe {
            VirtualQueryEx(
                handle,
                *address as *const c_void,
                &mut info,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if written == 0 {
            return None;
        }
        let next = (info.BaseAddress as u64).checked_add(info.RegionSize as u64)?;
        // A zero-sized or wrapped region would leave `address` where it was.
        if next as usize <= *address {
            return None;
        }
        *address = next as usize;
        Some(info)
    }

    /// Whether a region can hold guest RAM: committed, writable, unguarded,
    /// and large enough not to be the emulator's own allocation. The type is
    /// not filtered: QEMU uses `MEM_PRIVATE` and VMware may use `MEM_MAPPED`.
    fn is_ram_region(info: &MEMORY_BASIC_INFORMATION) -> bool {
        info.State == MEM_COMMIT
            && info.RegionSize as u64 >= MIN_RAM_REGION
            && info.Protect & (PAGE_GUARD | PAGE_NOACCESS) == 0
            && info.Protect & PAGE_READWRITE != 0
    }

    /// The largest region that can hold guest RAM, as `(start, size)`.
    fn pick_ram_region(
        regions: impl IntoIterator<Item = MEMORY_BASIC_INFORMATION>,
    ) -> Option<(u64, u64)> {
        regions
            .into_iter()
            .filter(is_ram_region)
            .map(|info| (info.BaseAddress as u64, info.RegionSize as u64))
            .max_by_key(|&(_, size)| size)
    }

    fn read_process(handle: HANDLE, address: u64, buf: &mut [u8]) -> io::Result<usize> {
        let mut read = 0usize;
        // SAFETY: `buf` is writable for its length, in this or another
        // process's address space.
        let ok = unsafe {
            ReadProcessMemory(
                handle,
                address as *const c_void,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut read,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(read)
    }

    fn write_process(handle: HANDLE, address: u64, buf: &[u8]) -> io::Result<usize> {
        let mut written = 0usize;
        // SAFETY: `buf` is readable for its length.
        let ok = unsafe {
            WriteProcessMemory(
                handle,
                address as *const c_void,
                buf.as_ptr().cast(),
                buf.len(),
                &mut written,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(written)
    }

    fn primary_memory_region(handle: HANDLE, pid: u32) -> Result<MemoryRegion> {
        let mut address = 0usize;
        let regions = std::iter::from_fn(|| next_region(handle, &mut address));
        let (start, length) = pick_ram_region(regions).ok_or(Error::NoVmMemoryRegion)?;
        // Probe access: a handle without read rights fails here with a
        // clearer message than on the first guest read.
        let mut probe = [0u8; 1];
        if read_process(handle, start, &mut probe).is_err() {
            return Err(Error::VmProcessDenied {
                pid,
                detail: io::Error::last_os_error().to_string(),
            });
        }
        Ok(MemoryRegion {
            start,
            end: start + length,
            length,
        })
    }

    /// Offset of a guest-physical address into the VM's RAM mapping, or
    /// `None` where no RAM backs it: the x86 32-bit MMIO hole, or anything
    /// below an AArch64 guest's RAM base. Mapping either one anywhere would
    /// alias real pages.
    fn gpa_to_offset(layout: RamLayout, gpa: PhysAddr) -> Option<u64> {
        match layout {
            // Low RAM is identity-mapped up to the hole; RAM above 4 GiB
            // follows it in the mapping, so the hole's size is subtracted.
            RamLayout::X86 { hole_start } => {
                if gpa < hole_start {
                    Some(gpa)
                } else if gpa < X86_MMIO_HOLE_END {
                    None
                } else {
                    Some(gpa - (X86_MMIO_HOLE_END - hole_start))
                }
            }
            RamLayout::Aarch64Virt => {
                if gpa < AARCH64_VIRT_RAM_BASE {
                    None
                } else {
                    Some(gpa - AARCH64_VIRT_RAM_BASE)
                }
            }
        }
    }

    fn ram_base(layout: RamLayout) -> u64 {
        match layout {
            RamLayout::X86 { .. } => 0,
            RamLayout::Aarch64Virt => AARCH64_VIRT_RAM_BASE,
        }
    }

    /// Guest-physical RAM as `(base, len)` runs: on x86, low RAM up to the
    /// 32-bit MMIO hole and the remainder from 4 GiB; on AArch64, one run
    /// from the RAM base. Inverse of `gpa_to_offset`.
    fn ram_runs(layout: RamLayout, size: u64) -> Vec<(u64, u64)> {
        match layout {
            RamLayout::X86 { hole_start } if size > hole_start => {
                vec![(0, hole_start), (X86_MMIO_HOLE_END, size - hole_start)]
            }
            RamLayout::X86 { .. } => vec![(0, size)],
            RamLayout::Aarch64Virt => vec![(AARCH64_VIRT_RAM_BASE, size)],
        }
    }

    impl VmHandle {
        pub fn new() -> Result<Self> {
            let (pid, kind, name) = find_vm_process().ok_or(Error::VmNotFound)?;
            let handle = open_process(pid)?;
            // Built before the scan so a failure there still closes the
            // handle.
            let mut handle = Self {
                handle,
                memory: MemoryRegion {
                    start: 0,
                    end: 0,
                    length: 0,
                },
                pid,
                layout: ram_layout(kind, &name),
            };
            handle.memory = primary_memory_region(handle.handle, pid)?;
            Ok(handle)
        }

        /// Whether the hypervisor aborts the VM when a debugger enables guest
        /// debugging through its GDB stub; neither QEMU nor VMware does.
        pub fn guest_debug_aborts_vm(&self) -> bool {
            false
        }

        pub fn describe(&self) -> String {
            format!(
                "pid {}, host mapping {:#x}-{:#x}",
                self.pid, self.memory.start, self.memory.end
            )
        }

        pub fn ram_base(&self) -> u64 {
            ram_base(self.layout)
        }

        pub fn ram_size(&self) -> u64 {
            self.memory.length
        }

        pub fn ram_runs(&self) -> Vec<(u64, u64)> {
            ram_runs(self.layout, self.memory.length)
        }

        fn host_address(&self, addr: PhysAddr, len: usize) -> Result<u64> {
            gpa_to_offset(self.layout, addr)
                .and_then(|offset| self.memory.host_range(offset, len))
                .ok_or(Error::BadPhysicalAddress(addr))
        }
    }

    impl Drop for VmHandle {
        fn drop(&mut self) {
            // SAFETY: the handle came from `OpenProcess` and is closed once.
            unsafe { CloseHandle(self.handle) };
        }
    }

    impl MemoryOps<PhysAddr> for VmHandle {
        fn read_bytes(&self, addr: PhysAddr, buf: &mut [u8]) -> Result<()> {
            let hva = self.host_address(addr, buf.len())?;
            let read =
                read_process(self.handle, hva, buf).map_err(|_| Error::BadPhysicalAddress(addr))?;
            if read != buf.len() {
                return Err(Error::PartialRead(read));
            }
            Ok(())
        }

        fn write_bytes(&self, addr: PhysAddr, buf: &[u8]) -> Result<()> {
            let hva = self.host_address(addr, buf.len())?;
            let written = write_process(self.handle, hva, buf)
                .map_err(|_| Error::BadPhysicalAddress(addr))?;
            if written != buf.len() {
                return Err(Error::PartialWrite(written));
            }
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use windows_sys::Win32::System::Memory::PAGE_READONLY;
        use windows_sys::Win32::System::Threading::GetCurrentProcess;

        use super::*;

        /// A region of `size` bytes of `protection` in the given state,
        /// starting at `start`.
        fn region(start: u64, size: u64, state: u32, protection: u32) -> MEMORY_BASIC_INFORMATION {
            MEMORY_BASIC_INFORMATION {
                BaseAddress: start as *mut c_void,
                RegionSize: size as usize,
                State: state,
                Protect: protection,
                ..Default::default()
            }
        }

        #[test]
        fn process_names_select_their_layouts() {
            let layout = |name: &str| {
                let kind = hypervisor_of(name).unwrap();
                ram_layout(kind, name)
            };
            let x86 = RamLayout::X86 {
                hole_start: 0x8000_0000,
            };

            assert_eq!(layout("qemu-system-x86_64.exe"), x86);
            assert_eq!(layout("qemu-system-aarch64.exe"), RamLayout::Aarch64Virt);
            assert_eq!(
                layout("vmware-vmx.exe"),
                RamLayout::X86 {
                    hole_start: 0xC000_0000
                }
            );
            // Anything else is not a VM we can read.
            assert_eq!(hypervisor_of("qemu-system.exe"), None);
            assert_eq!(hypervisor_of("notepad.exe"), None);
        }

        #[test]
        fn x86_guest_ram_skips_the_32_bit_mmio_hole() {
            let layout = RamLayout::X86 {
                hole_start: 0x8000_0000,
            };

            assert_eq!(gpa_to_offset(layout, 0), Some(0));
            assert_eq!(gpa_to_offset(layout, 0x7FFF_FFFF), Some(0x7FFF_FFFF));
            // No RAM backs the hole; mapping it would alias real pages.
            assert_eq!(gpa_to_offset(layout, 0x8000_0000), None);
            assert_eq!(gpa_to_offset(layout, 0xFFFF_FFFF), None);
            // RAM resumes at 4 GiB, packed against the low RAM before it.
            assert_eq!(gpa_to_offset(layout, 0x1_0000_0000), Some(0x8000_0000));
        }

        #[test]
        fn aarch64_guest_ram_starts_at_the_virt_machine_base() {
            let layout = RamLayout::Aarch64Virt;

            // Flash and MMIO live below the base, not RAM.
            assert_eq!(gpa_to_offset(layout, 0x3FFF_FFFF), None);
            assert_eq!(gpa_to_offset(layout, 0x4000_0000), Some(0));
            assert_eq!(gpa_to_offset(layout, 0x4000_1000), Some(0x1000));
            assert_eq!(ram_base(layout), 0x4000_0000);
        }

        #[test]
        fn ram_runs_report_where_each_layout_puts_its_memory() {
            let x86 = RamLayout::X86 {
                hole_start: 0x8000_0000,
            };

            // 1 GiB fits below the hole, so it is one run from 0.
            assert_eq!(ram_runs(x86, 0x4000_0000), vec![(0, 0x4000_0000)]);
            // 4 GiB does not, so the top 2 GiB moves above the hole.
            assert_eq!(
                ram_runs(x86, 0x1_0000_0000),
                vec![(0, 0x8000_0000), (0x1_0000_0000, 0x8000_0000)]
            );
            assert_eq!(
                ram_runs(RamLayout::Aarch64Virt, 0x1_0000_0000),
                vec![(0x4000_0000, 0x1_0000_0000)]
            );
        }

        #[test]
        fn the_largest_writable_region_is_the_guest_ram() {
            const MIB: u64 = 1 << 20;
            let regions = [
                // Small and writable: the emulator's own heap.
                region(0x1000_0000, 4 * MIB, MEM_COMMIT, PAGE_READWRITE),
                // Large but guarded, so touching it would fault the process.
                region(
                    0x2000_0000,
                    4096 * MIB,
                    MEM_COMMIT,
                    PAGE_READWRITE | PAGE_GUARD,
                ),
                // Large but not writable: an image, not RAM.
                region(0x3000_0000, 4096 * MIB, MEM_COMMIT, PAGE_READONLY),
                // The guest RAM.
                region(0x7000_0000, 1024 * MIB, MEM_COMMIT, PAGE_READWRITE),
            ];

            assert_eq!(pick_ram_region(regions), Some((0x7000_0000, 1024 * MIB)));
        }

        #[test]
        fn read_and_write_reach_this_process_memory() {
            // `GetCurrentProcess` is the pseudo-handle for this process, so
            // this exercises the same calls a VM's memory goes through.
            let handle = unsafe { GetCurrentProcess() };
            let mut buffer = vec![0u8; 4096];
            let address = buffer.as_mut_ptr() as u64;
            let pattern = |index: usize| (index % 251) as u8;
            let written: Vec<u8> = (0..buffer.len()).map(pattern).collect();

            assert_eq!(
                write_process(handle, address, &written).unwrap(),
                buffer.len()
            );
            let mut read = vec![0u8; buffer.len()];
            assert_eq!(
                read_process(handle, address, &mut read).unwrap(),
                read.len()
            );

            assert_eq!(read, written);
            assert_eq!(buffer, written);
        }
    }
}

pub use platform::VmHandle;
