struct MemoryRegion {
    start: u64,
    end: u64,
    length: u64,
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
    use crate::backend::MemoryOps;
    use crate::error::{Error, Result};
    use crate::types::PhysAddr;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum HvKind {
        Kvm,
        Vmware,
    }

    pub struct VmHandle {
        memory: MemoryRegion,
        pid: Pid,
        hv: HvKind,
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

        let region = reader
            .lines()
            .map_while(|line| line.ok())
            .filter_map(|line| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.is_empty() {
                    return None;
                }
                let addrs: Vec<&str> = parts[0].split('-').collect();
                if addrs.len() != 2 {
                    return None;
                }
                let start = u64::from_str_radix(addrs[0], 16).ok()?;
                let end = u64::from_str_radix(addrs[1], 16).ok()?;
                Some(MemoryRegion {
                    start,
                    end,
                    length: end - start,
                })
            })
            .max_by_key(|r| r.length)
            .ok_or(Error::NoVmMemoryRegion)?;

        Ok(region)
    }

    /// Offset of a guest-physical address into the VM's RAM mapping, or
    /// `None` inside the 32-bit MMIO hole, which no RAM backs (mapping it
    /// anywhere would alias real pages).
    fn gpa_to_offset(hv: HvKind, gpa: PhysAddr) -> Option<u64> {
        // Low RAM is identity-mapped up to the hole; RAM above 4 GiB follows
        // it in the mapping, so the hole's size is subtracted.
        let hole_start = match hv {
            HvKind::Kvm => 0x8000_0000,    // QEMU: 2 GiB hole
            HvKind::Vmware => 0xC000_0000, // VMware: 1 GiB hole
        };
        const HOLE_END: u64 = 0x1_0000_0000;
        if gpa < hole_start {
            Some(gpa)
        } else if gpa < HOLE_END {
            None
        } else {
            Some(gpa - (HOLE_END - hole_start))
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
                hv,
            })
        }

        pub fn ram_base(&self) -> u64 {
            // x86 QEMU/VMware guests map RAM from GPA 0.
            0
        }

        pub fn ram_size(&self) -> u64 {
            self.memory.length
        }
        fn host_address(&self, addr: PhysAddr, len: usize) -> Result<u64> {
            let hva = gpa_to_offset(self.hv, addr)
                .and_then(|offset| self.memory.start.checked_add(offset))
                .ok_or(Error::BadPhysicalAddress(addr))?;
            let end = hva
                .checked_add(len as u64)
                .ok_or(Error::BadPhysicalAddress(addr))?;
            if end > self.memory.end {
                return Err(Error::BadPhysicalAddress(addr));
            }
            Ok(hva)
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
    }
}

/// macOS (UTM) host backend: guest RAM is an anonymous mapping in the QEMU
/// process, read through its Mach task port (`task_for_pid` needs root or the
/// `com.apple.security.cs.debugger` entitlement).
#[cfg(target_os = "macos")]
mod platform {
    use super::MemoryRegion;
    use crate::backend::MemoryOps;
    use crate::error::{Error, Result};
    use crate::types::PhysAddr;

    pub struct VmHandle {
        task: u32,
        memory: MemoryRegion,
    }

    /// QEMU aarch64 `virt` machine memory map: RAM is one contiguous region
    /// starting at GPA 0x4000_0000 (1 GiB), sized by `-m`. Below that is
    /// flash/MMIO, not RAM.
    const AARCH64_RAM_BASE: u64 = 0x4000_0000;

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
                    _ => spans.push(MemoryRegion {
                        start,
                        end,
                        length: end - start,
                    }),
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
            Ok(Self { task, memory })
        }

        pub fn ram_base(&self) -> u64 {
            AARCH64_RAM_BASE
        }

        pub fn ram_size(&self) -> u64 {
            self.memory.length
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
            let hva = self
                .memory
                .start
                .checked_add(self.gpa_offset(addr)?)
                .ok_or(Error::BadPhysicalAddress(addr))?;
            let end = hva
                .checked_add(len as u64)
                .ok_or(Error::BadPhysicalAddress(addr))?;
            if end > self.memory.end {
                return Err(Error::BadPhysicalAddress(addr));
            }
            Ok(hva)
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

pub use platform::VmHandle;
