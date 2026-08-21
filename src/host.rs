use nix::sys::uio::{RemoteIoVec, process_vm_readv, process_vm_writev};
use nix::unistd::Pid;
use std::ffi::OsStr;
use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::io::{IoSlice, IoSliceMut};

use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::types::PhysAddr;

struct MemoryRegion {
    start: u64,
    end: u64,
    length: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HvKind {
    Kvm,
    Vmware,
}

pub struct KvmHandle {
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
    Err(Error::KvmNotFound)
}

fn kvm_primary_memory(pid: i32) -> Result<MemoryRegion> {
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
        .ok_or(Error::NoKvmRegions)?;

    Ok(region)
}

fn gpa_to_offset(hv: HvKind, gpa: PhysAddr) -> u64 {
    match hv {
        HvKind::Kvm => {
            // QEMU: 2 GiB MMIO hole (0x8000_0000 – 0xFFFF_FFFF)
            if gpa < 0x8000_0000 {
                gpa
            } else {
                gpa - 0x8000_0000
            }
        }
        HvKind::Vmware => {
            // VMware: 3 GiB MMIO hole (0xC000_0000 – 0xFFFF_FFFF)
            if gpa < 0xC000_0000 {
                gpa // low RAM: identity
            } else if gpa >= 0x1_0000_0000 {
                gpa - 0x4000_0000 // high RAM: subtract 1 GiB hole
            } else {
                gpa // inside the hole — no RAM
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

impl KvmHandle {
    pub fn new() -> Result<Self> {
        let (pid, hv) = find_vm_pid()?;
        let memory = kvm_primary_memory(pid)?;
        let nix_pid = Pid::from_raw(pid);
        probe_ptrace_access(nix_pid, memory.start)?;
        Ok(Self {
            memory,
            pid: nix_pid,
            hv,
        })
    }
}

impl MemoryOps<PhysAddr> for KvmHandle {
    fn read_bytes(&self, addr: PhysAddr, buf: &mut [u8]) -> Result<()> {
        let hva = self.memory.start + gpa_to_offset(self.hv, addr);
        if hva + buf.len() as u64 > self.memory.end {
            return Err(Error::BadPhysicalAddress(addr));
        }
        let remote_iov = RemoteIoVec {
            base: hva as usize,
            len: buf.len(),
        };
        let bytes_read = process_vm_readv(self.pid, &mut [IoSliceMut::new(buf)], &[remote_iov])?;
        if bytes_read != buf.len() {
            return Err(Error::PartialRead(bytes_read));
        }
        Ok(())
    }

    fn write_bytes(&self, addr: PhysAddr, buf: &[u8]) -> Result<()> {
        let hva = self.memory.start + gpa_to_offset(self.hv, addr);
        if hva + buf.len() as u64 > self.memory.end {
            return Err(Error::BadPhysicalAddress(addr));
        }
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
