//! Object-manager inspectors: names, directories, driver/device objects, IRPs, handles, file objects, resources, object headers, notify callbacks, SSDT.

use std::sync::Arc;

use crate::backend::MemoryOps;
use crate::bugchecks::looks_like_kernel_pointer;
use crate::error::{Error, Result};
use crate::guest::{Guest, ProcessInfo};
use crate::layout::{StructRef, TypeInfo};
use crate::memory::PAGE_SIZE;
use crate::types::VirtAddr;

use super::{DiagnosticValue, ListTermination, Target, bounded_list_walk};

#[derive(Debug, Clone)]
pub struct DriverObjectInfo {
    pub name: String,
    pub object: VirtAddr,
    pub driver_start: VirtAddr,
    pub driver_size: u64,
    pub device_object: VirtAddr,
    pub driver_unload: VirtAddr,
}

/// A decoded `_IRP` plus its current `_IO_STACK_LOCATION` (when resolvable).
#[derive(Debug, Clone)]
pub struct IrpInfo {
    pub address: VirtAddr,
    pub irp_type: u16,
    pub size: u16,
    pub stack_count: u8,
    pub current_location: u8,
    pub pending_returned: bool,
    pub requestor_mode: u8,
    pub io_status: Option<u32>,
    pub user_event: VirtAddr,
    pub user_buffer: VirtAddr,
    pub mdl_address: VirtAddr,
    pub thread: VirtAddr,
    pub current_stack: Option<IoStackLocationInfo>,
}

#[derive(Debug, Clone)]
pub struct IoStackLocationInfo {
    pub address: VirtAddr,
    pub major_function: u8,
    pub minor_function: u8,
    pub device_object: VirtAddr,
    pub file_object: VirtAddr,
    pub completion_routine: VirtAddr,
    pub context: VirtAddr,
}

/// A decoded `_DRIVER_OBJECT`: header fields, its `DeviceObject`/`NextDevice`
/// chain, and the 28-entry `MajorFunction` dispatch table.
#[derive(Debug, Clone)]
pub struct DriverObjectDetail {
    pub object: VirtAddr,
    /// True when `object` was a pointer to a `_DRIVER_OBJECT` rather than one.
    pub via_pointer: bool,
    pub name: Option<String>,
    pub driver_start: VirtAddr,
    pub driver_size: u64,
    pub driver_section: VirtAddr,
    pub driver_unload: VirtAddr,
    pub device_chain: Vec<DeviceLink>,
    /// `MajorFunction[0..=0x1b]` dispatch routines, indexed by `IRP_MJ_*` code.
    pub dispatch: Vec<VirtAddr>,
}

#[derive(Debug, Clone)]
pub struct DeviceLink {
    pub device: VirtAddr,
    pub device_type: u32,
    pub flags: u32,
    pub characteristics: u32,
    pub attached: VirtAddr,
    pub next: VirtAddr,
}

/// A decoded `_DEVICE_OBJECT` plus its `AttachedDevice` stack.
#[derive(Debug, Clone)]
pub struct DeviceObjectDetail {
    pub object: VirtAddr,
    pub via_pointer: bool,
    pub device_type: u32,
    pub flags: u32,
    pub characteristics: u32,
    pub driver_object: VirtAddr,
    pub attached_device: VirtAddr,
    pub next_device: VirtAddr,
    pub current_irp: VirtAddr,
    pub device_extension: VirtAddr,
    pub attached_stack: Vec<DeviceStackEntry>,
}

#[derive(Debug, Clone)]
pub struct DeviceStackEntry {
    pub device: VirtAddr,
    pub driver_object: VirtAddr,
    pub device_type: u32,
    pub flags: u32,
}

/// A decoded executive `_OBJECT_HEADER` and the body it precedes.
#[derive(Debug, Clone)]
pub struct ObjectHeaderDetail {
    pub input: VirtAddr,
    /// "body" when the input pointed at the object body, "header" when it
    /// pointed at the header itself.
    pub mode: &'static str,
    pub header: VirtAddr,
    pub body: VirtAddr,
    pub pointer_count: i64,
    pub handle_count: i64,
    pub type_index: Option<u64>,
    pub type_object: Option<VirtAddr>,
    pub type_name: Option<String>,
    pub info_mask: Option<u8>,
    pub name_info: Option<VirtAddr>,
    pub name: Option<String>,
}

/// One process/thread/image notification callback registered with the kernel.
#[derive(Debug, Clone)]
pub struct NotifyCallback {
    /// "process", "thread", or "image".
    pub kind: &'static str,
    pub index: usize,
    pub function: VirtAddr,
    pub block: VirtAddr,
    pub raw: VirtAddr,
    pub context: VirtAddr,
}

/// One system-service-table slot resolved to its target routine.
#[derive(Debug, Clone)]
pub struct SsdtEntry {
    pub index: u32,
    pub target: VirtAddr,
    pub symbol: Option<String>,
    pub module: Option<String>,
}

/// A system service descriptor table (the kernel SSDT or the win32k shadow).
#[derive(Debug, Clone)]
pub struct SsdtTable {
    pub label: String,
    pub base: VirtAddr,
    pub limit: u32,
    pub entries: Vec<SsdtEntry>,
}

/// An IRP discovered via an `_ETHREAD` `IrpList` or a `_DEVICE_OBJECT`
/// `CurrentIrp`, with the context it was found in.
#[derive(Debug, Clone)]
pub struct IrpHit {
    pub irp: VirtAddr,
    /// "thread" or "device".
    pub source: &'static str,
    pub stack_count: u8,
    pub current_location: u8,
    pub pid: Option<u64>,
    pub tid: Option<u64>,
    pub ethread: Option<VirtAddr>,
    pub state: Option<u8>,
    pub wait_reason: Option<u8>,
    pub driver: Option<String>,
    pub device: Option<VirtAddr>,
}

#[derive(Debug, Clone)]
pub struct HandleEntryDetail {
    pub handle: u64,
    pub entry: VirtAddr,
    pub object: DiagnosticValue<VirtAddr>,
    pub type_name: DiagnosticValue<Option<String>>,
    pub name: DiagnosticValue<Option<String>>,
    pub granted_access: DiagnosticValue<u32>,
    pub attributes: DiagnosticValue<u32>,
}

#[derive(Debug, Clone)]
pub struct HandleTableSummary {
    pub process: ProcessInfo,
    pub table: VirtAddr,
    pub table_level: u8,
    pub advertised_handles: usize,
    pub scanned_handles: usize,
    pub skipped_entries: usize,
    pub truncated: bool,
    pub entries: Vec<HandleEntryDetail>,
}

#[derive(Debug, Clone)]
pub struct FileObjectDetail {
    pub address: VirtAddr,
    pub file_type: DiagnosticValue<i16>,
    pub size: DiagnosticValue<i16>,
    pub device_object: DiagnosticValue<VirtAddr>,
    pub device_type: DiagnosticValue<u32>,
    pub device_name: DiagnosticValue<Option<String>>,
    pub file_name: DiagnosticValue<String>,
    pub related_file_object: DiagnosticValue<VirtAddr>,
    pub flags: DiagnosticValue<u32>,
    pub current_byte_offset: DiagnosticValue<i64>,
    pub fs_context: DiagnosticValue<VirtAddr>,
    pub fs_context2: DiagnosticValue<VirtAddr>,
    pub section_object_pointer: DiagnosticValue<VirtAddr>,
    pub private_cache_map: DiagnosticValue<VirtAddr>,
    pub final_status: DiagnosticValue<i32>,
    pub lock_operation: DiagnosticValue<bool>,
    pub delete_pending: DiagnosticValue<bool>,
    pub read_access: DiagnosticValue<bool>,
    pub write_access: DiagnosticValue<bool>,
    pub delete_access: DiagnosticValue<bool>,
    pub shared_read: DiagnosticValue<bool>,
    pub shared_write: DiagnosticValue<bool>,
    pub shared_delete: DiagnosticValue<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceOwner {
    pub thread: VirtAddr,
    pub count: i32,
}

#[derive(Debug, Clone)]
pub struct ResourceDetail {
    pub address: VirtAddr,
    pub active_count: DiagnosticValue<i16>,
    pub flags: DiagnosticValue<u16>,
    pub contention_count: DiagnosticValue<u32>,
    pub shared_waiters: DiagnosticValue<u32>,
    pub exclusive_waiters: DiagnosticValue<u32>,
    pub owners: DiagnosticValue<Vec<ResourceOwner>>,
}

#[derive(Debug, Clone)]
pub struct ResourceListSummary {
    pub head: VirtAddr,
    pub resources: Vec<ResourceDetail>,
    pub termination: ListTermination,
}

struct ObjectNameLayout {
    body_offset: u64,
    info_mask_offset: u64,
    creator_info_size: Option<u64>,
    name_info_size: u64,
    name_offset: u64,
}

impl ObjectNameLayout {
    fn name_info_address(&self, header: VirtAddr, info_mask: u8) -> Result<Option<VirtAddr>> {
        const CREATOR_INFO_BIT: u8 = 0x01;
        const NAME_INFO_BIT: u8 = 0x02;

        if info_mask & NAME_INFO_BIT == 0 {
            return Ok(None);
        }

        // Optional headers run backwards from OBJECT_HEADER in increasing bit
        // order. NameInfo is therefore displaced only by lower-bit CreatorInfo,
        // never by HandleInfo or any higher-bit header.
        let creator_size = if info_mask & CREATOR_INFO_BIT != 0 {
            self.creator_info_size
                .ok_or_else(|| Error::StructNotFound("_OBJECT_HEADER_CREATOR_INFO".to_string()))?
        } else {
            0
        };
        let offset = self
            .name_info_size
            .checked_add(creator_size)
            .ok_or_else(|| Error::DebugInfo("object name-info offset overflow".to_string()))?;
        let address =
            header.0.checked_sub(offset).map(VirtAddr).ok_or_else(|| {
                Error::DebugInfo("object name-info address underflow".to_string())
            })?;
        Ok(Some(address))
    }
}

struct ObjectDirectoryLayout {
    buckets_offset: u64,
    bucket_count: u64,
    chain_offset: u64,
    object_offset: u64,
    name_offset: Option<u64>,
}

/// `_IRP.Thread` is a direct field on some builds and inside the `Tail.Overlay`
/// union on others; read whichever is present, else null (never fatal).
fn irp_thread(irp: &StructRef) -> VirtAddr {
    if let Ok(t) = irp.read_field::<VirtAddr>("Thread") {
        return t;
    }
    irp.embedded("Tail")
        .and_then(|tail| tail.embedded("Overlay"))
        .and_then(|ov| ov.read_field::<VirtAddr>("Thread"))
        .unwrap_or(VirtAddr(0))
}

fn select_object_header_candidate(
    input: VirtAddr,
    body_offset: u64,
    body_candidate: Option<VirtAddr>,
    direct_candidate: Option<VirtAddr>,
    body_has_type: bool,
    direct_has_type: bool,
) -> Option<(VirtAddr, VirtAddr, &'static str)> {
    match (body_candidate, direct_candidate) {
        (Some(header), Some(_)) if body_has_type => Some((header, input, "body")),
        (Some(_), Some(header)) if direct_has_type => {
            Some((header, header + body_offset, "header"))
        }
        // Both locations are readable but neither decodes through the type
        // table. Guessing here would make an arbitrary pool address look valid.
        (Some(_), Some(_)) => None,
        (Some(header), None) => Some((header, input, "body")),
        (None, Some(header)) => Some((header, header + body_offset, "header")),
        (None, None) => None,
    }
}

impl Target {
    /// Open a fluent cursor over a kernel struct (ntoskrnl's layout, read
    /// through ntoskrnl's address space).
    fn kernel_struct(&self, name: &str, base: VirtAddr) -> Result<StructRef<'_>> {
        self.guest()?.ntoskrnl.types().struct_at(name, base)
    }

    fn read_kernel_unicode_string(&self, addr: VirtAddr) -> Result<String> {
        self.kernel_struct("_UNICODE_STRING", addr)?
            .read_unicode_string()
    }

    fn object_name_layout(&self) -> Result<ObjectNameLayout> {
        let dtb = self.guest()?.ntoskrnl.dtb();
        let header_type = self
            .symbols
            .find_type_across_modules(dtb, "_OBJECT_HEADER")
            .ok_or_else(|| Error::StructNotFound("_OBJECT_HEADER".to_string()))?;
        let creator_info_size = self
            .symbols
            .find_type_across_modules(dtb, "_OBJECT_HEADER_CREATOR_INFO")
            .map(|ty| ty.size as u64);
        let name_info_type = self
            .symbols
            .find_type_across_modules(dtb, "_OBJECT_HEADER_NAME_INFO")
            .ok_or_else(|| Error::StructNotFound("_OBJECT_HEADER_NAME_INFO".to_string()))?;
        Ok(ObjectNameLayout {
            body_offset: header_type.field_offset("Body")?,
            info_mask_offset: header_type.field_offset("InfoMask")?,
            creator_info_size,
            name_info_size: name_info_type.size as u64,
            name_offset: name_info_type.field_offset("Name")?,
        })
    }

    fn read_kernel_object_name(
        &self,
        object: VirtAddr,
        object_name: &ObjectNameLayout,
    ) -> Result<Option<String>> {
        let memory = self.guest()?.ntoskrnl.memory();
        let header = object - object_name.body_offset;
        let info_mask: u8 = memory.read(header + object_name.info_mask_offset)?;
        let Some(name_info) = object_name.name_info_address(header, info_mask)? else {
            return Ok(None);
        };
        Ok(Some(self.read_kernel_unicode_string(
            name_info + object_name.name_offset,
        )?))
    }

    fn object_directory_layout(&self) -> Result<ObjectDirectoryLayout> {
        let dtb = self.guest()?.ntoskrnl.dtb();
        let dir_type = self
            .symbols
            .find_type_across_modules(dtb, "_OBJECT_DIRECTORY")
            .ok_or_else(|| Error::StructNotFound("_OBJECT_DIRECTORY".to_string()))?;
        let entry_type = self
            .symbols
            .find_type_across_modules(dtb, "_OBJECT_DIRECTORY_ENTRY")
            .ok_or_else(|| Error::StructNotFound("_OBJECT_DIRECTORY_ENTRY".to_string()))?;
        let buckets = dir_type
            .fields
            .get("HashBuckets")
            .ok_or_else(|| Error::FieldNotFound("HashBuckets".to_string()))?;
        Ok(ObjectDirectoryLayout {
            buckets_offset: buckets.offset as u64,
            bucket_count: (buckets.size / 8).max(1),
            chain_offset: entry_type.field_offset("ChainLink")?,
            object_offset: entry_type.field_offset("Object")?,
            name_offset: entry_type.fields.get("Name").map(|f| f.offset as u64),
        })
    }

    fn enumerate_object_directory(
        &self,
        directory: VirtAddr,
        dir: &ObjectDirectoryLayout,
        object_name: &ObjectNameLayout,
    ) -> Result<Vec<(String, VirtAddr)>> {
        let memory = self.guest()?.ntoskrnl.memory();
        let mut out = Vec::new();
        for bucket in 0..dir.bucket_count {
            let mut entry: VirtAddr = memory.read(directory + dir.buckets_offset + bucket * 8)?;
            for _ in 0..4096 {
                if entry.is_zero() {
                    break;
                }
                let object: VirtAddr = memory.read(entry + dir.object_offset)?;
                if !object.is_zero() {
                    let name = match dir.name_offset {
                        Some(offset) => Some(self.read_kernel_unicode_string(entry + offset)?),
                        None => self.read_kernel_object_name(object, object_name)?,
                    };
                    if let Some(name) = name
                        && !name.is_empty()
                    {
                        out.push((name, object));
                    }
                }
                entry = memory.read(entry + dir.chain_offset)?;
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }

    pub fn enumerate_driver_objects(&self) -> Result<Vec<DriverObjectInfo>> {
        let guest = self.guest()?;
        guest.memoized_drivers(|| self.walk_driver_objects(guest))
    }

    fn walk_driver_objects(&self, guest: &Guest) -> Result<Vec<DriverObjectInfo>> {
        let memory = guest.ntoskrnl.memory();
        let object_name = self.object_name_layout()?;
        let dir = self.object_directory_layout()?;
        let root_ptr = guest.ntoskrnl.symbol("ObpRootDirectoryObject")?.address();
        let root: VirtAddr = memory.read(root_ptr)?;
        let driver_dir = self
            .enumerate_object_directory(root, &dir, &object_name)?
            .into_iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("Driver"))
            .map(|(_, object)| object)
            .ok_or_else(|| Error::DebugInfo("\\Driver object directory not found".to_string()))?;

        let mut drivers = Vec::new();
        for (name, object) in self.enumerate_object_directory(driver_dir, &dir, &object_name)? {
            let driver = self.kernel_struct("_DRIVER_OBJECT", object)?;
            drivers.push(DriverObjectInfo {
                name: format!("\\Driver\\{name}"),
                object,
                driver_start: driver.read_field("DriverStart")?,
                driver_size: driver.read_field::<u32>("DriverSize")? as u64,
                device_object: driver.read_field("DeviceObject")?,
                driver_unload: driver.read_field("DriverUnload")?,
            });
        }
        Ok(drivers)
    }

    /// Decode the `_IRP` at `address` along with its current I/O stack
    /// location. Field widths come from the PDB layout; the current stack slot
    /// is `irp + sizeof(_IRP) + (CurrentLocation - 1) * sizeof(_IO_STACK_LOCATION)`.
    pub fn inspect_irp(&self, address: VirtAddr) -> Result<IrpInfo> {
        let irp = self.kernel_struct("_IRP", address)?;

        let io_status = irp
            .embedded("IoStatus")
            .and_then(|s| s.read_field::<u32>("Status"))
            .ok();

        let current_location: u8 = irp.read_field("CurrentLocation")?;
        let current_stack = self
            .read_current_io_stack(address, current_location)
            .ok()
            .flatten();

        Ok(IrpInfo {
            address,
            irp_type: irp.read_field("Type")?,
            size: irp.read_field("Size")?,
            stack_count: irp.read_field("StackCount")?,
            current_location,
            pending_returned: irp.read_field::<u8>("PendingReturned")? != 0,
            requestor_mode: irp.read_field("RequestorMode")?,
            io_status,
            user_event: irp.read_field("UserEvent")?,
            user_buffer: irp.read_field("UserBuffer")?,
            mdl_address: irp.read_field("MdlAddress")?,
            thread: irp_thread(&irp),
            current_stack,
        })
    }

    fn read_current_io_stack(
        &self,
        irp: VirtAddr,
        current_location: u8,
    ) -> Result<Option<IoStackLocationInfo>> {
        // A valid current location is 1..=StackCount; clamp generously so a
        // garbage value can't compute a wild address.
        if current_location == 0 || current_location as u64 > 0x40 {
            return Ok(None);
        }
        let types = self.guest()?.ntoskrnl.types();
        let irp_size = types.layout("_IRP")?.size as u64;
        let stack_size = types.layout("_IO_STACK_LOCATION")?.size as u64;
        let addr = irp + irp_size + (current_location as u64 - 1) * stack_size;

        let Ok(ios) = self.kernel_struct("_IO_STACK_LOCATION", addr) else {
            return Ok(None);
        };
        Ok(Some(IoStackLocationInfo {
            address: addr,
            major_function: ios.read_field("MajorFunction")?,
            minor_function: ios.read_field("MinorFunction")?,
            device_object: ios.read_field("DeviceObject")?,
            file_object: ios.read_field("FileObject")?,
            completion_routine: ios.read_field("CompletionRoutine")?,
            context: ios.read_field("Context")?,
        }))
    }

    fn read_device_link(&self, device: VirtAddr) -> Result<DeviceLink> {
        let d = self.kernel_struct("_DEVICE_OBJECT", device)?;
        Ok(DeviceLink {
            device,
            device_type: d.read_field("DeviceType")?,
            flags: d.read_field("Flags")?,
            characteristics: d.read_field("Characteristics")?,
            attached: d.read_field("AttachedDevice")?,
            next: d.read_field("NextDevice")?,
        })
    }

    /// Decode a `_DRIVER_OBJECT` at `addr` (or at the pointer `addr` points to),
    /// including its device chain and `MajorFunction` dispatch table.
    pub fn inspect_driver_object(&self, addr: VirtAddr) -> Result<DriverObjectDetail> {
        let guest = self.guest()?;
        let mem = guest.ntoskrnl.memory();
        let layout = guest.ntoskrnl.types().layout("_DRIVER_OBJECT")?;
        let size_off = layout.field_offset("Size")?;
        let mf_off = layout.field_offset("MajorFunction")?;
        let name_off = layout.field_offset("DriverName")?;
        let min_size = mf_off + 28 * 8;

        // A `_DRIVER_OBJECT` has Type == 4 (IO_TYPE_DRIVER) and is large enough
        // to hold the dispatch table; use that to tell a direct object from a
        // pointer to one.
        let valid = |a: VirtAddr| -> bool {
            let ty: u16 = match mem.read(a) {
                Ok(v) => v,
                Err(_) => return false,
            };
            let size: u16 = match mem.read(a + size_off) {
                Ok(v) => v,
                Err(_) => return false,
            };
            ty == 4 && size as u64 >= min_size
        };

        let object = if valid(addr) {
            addr
        } else {
            let ptr: VirtAddr = mem.read(addr)?;
            if !ptr.is_zero() && valid(ptr) {
                ptr
            } else {
                return Err(Error::DebugInfo(format!(
                    "{:#x} is not a _DRIVER_OBJECT or a pointer to one",
                    addr.0
                )));
            }
        };

        let drv = self.kernel_struct("_DRIVER_OBJECT", object)?;
        let name = self
            .read_kernel_unicode_string(object + name_off)
            .ok()
            .filter(|s| !s.is_empty());

        let mut device_chain = Vec::new();
        let mut seen = Vec::new();
        let mut cur: VirtAddr = drv.read_field("DeviceObject")?;
        for _ in 0..128 {
            if cur.is_zero() || seen.contains(&cur.0) {
                break;
            }
            seen.push(cur.0);
            let Ok(link) = self.read_device_link(cur) else {
                break;
            };
            let next = link.next;
            device_chain.push(link);
            if next.is_zero() {
                break;
            }
            cur = next;
        }

        let mut dispatch = Vec::with_capacity(28);
        for i in 0..28u64 {
            dispatch.push(
                mem.read::<VirtAddr>(object + mf_off + i * 8)
                    .unwrap_or(VirtAddr(0)),
            );
        }

        Ok(DriverObjectDetail {
            object,
            via_pointer: object != addr,
            name,
            driver_start: drv.read_field("DriverStart")?,
            driver_size: drv.read_field::<u32>("DriverSize")? as u64,
            driver_section: drv.read_field("DriverSection")?,
            driver_unload: drv.read_field("DriverUnload")?,
            device_chain,
            dispatch,
        })
    }

    /// Decode a `_DEVICE_OBJECT` at `addr` (or the pointer `addr` points to) and
    /// walk its `AttachedDevice` stack.
    pub fn inspect_device_object(&self, addr: VirtAddr) -> Result<DeviceObjectDetail> {
        let guest = self.guest()?;
        let mem = guest.ntoskrnl.memory();
        let layout = guest.ntoskrnl.types().layout("_DEVICE_OBJECT")?;
        let size_off = layout.field_offset("Size")?;
        let min_size = layout.size as u64;

        let valid = |a: VirtAddr| -> bool {
            let ty: u16 = match mem.read(a) {
                Ok(v) => v,
                Err(_) => return false,
            };
            let size: u16 = match mem.read(a + size_off) {
                Ok(v) => v,
                Err(_) => return false,
            };
            ty == 3 && size as u64 >= min_size
        };

        let object = if valid(addr) {
            addr
        } else {
            let ptr: VirtAddr = mem.read(addr)?;
            if !ptr.is_zero() && valid(ptr) {
                ptr
            } else {
                return Err(Error::DebugInfo(format!(
                    "{:#x} is not a _DEVICE_OBJECT or a pointer to one",
                    addr.0
                )));
            }
        };

        let dev = self.kernel_struct("_DEVICE_OBJECT", object)?;
        let attached_device: VirtAddr = dev.read_field("AttachedDevice")?;

        let mut attached_stack = Vec::new();
        let mut seen = Vec::new();
        let mut cur = attached_device;
        for _ in 0..64 {
            if cur.is_zero() || seen.contains(&cur.0) {
                break;
            }
            seen.push(cur.0);
            let Ok(d) = self.kernel_struct("_DEVICE_OBJECT", cur) else {
                break;
            };
            let next: VirtAddr = d.read_field("AttachedDevice")?;
            attached_stack.push(DeviceStackEntry {
                device: cur,
                driver_object: d.read_field("DriverObject")?,
                device_type: d.read_field("DeviceType")?,
                flags: d.read_field("Flags")?,
            });
            if next.is_zero() {
                break;
            }
            cur = next;
        }

        Ok(DeviceObjectDetail {
            object,
            via_pointer: object != addr,
            device_type: dev.read_field("DeviceType")?,
            flags: dev.read_field("Flags")?,
            characteristics: dev.read_field("Characteristics")?,
            driver_object: dev.read_field("DriverObject")?,
            attached_device,
            next_device: dev.read_field("NextDevice")?,
            current_irp: dev.read_field("CurrentIrp")?,
            device_extension: dev.read_field("DeviceExtension")?,
            attached_stack,
        })
    }

    fn handle_entry_address(
        &self,
        table_base: VirtAddr,
        level: u8,
        index: usize,
        entry_size: usize,
    ) -> Result<VirtAddr> {
        let memory = self.context_memory();
        let leaf_entries = PAGE_SIZE / entry_size;
        match level {
            0 => Ok(table_base + (index * entry_size) as u64),
            1 => {
                let leaf: VirtAddr =
                    memory.read(table_base + ((index / leaf_entries) * 8) as u64)?;
                if leaf.is_zero() {
                    return Err(Error::DebugInfo(format!(
                        "handle leaf {} is null",
                        index / leaf_entries
                    )));
                }
                Ok(leaf + ((index % leaf_entries) * entry_size) as u64)
            }
            2 => {
                let middle_index = index / (leaf_entries * 512);
                let leaf_index = (index / leaf_entries) % 512;
                let middle: VirtAddr = memory.read(table_base + (middle_index * 8) as u64)?;
                if middle.is_zero() {
                    return Err(Error::DebugInfo(format!(
                        "handle middle table {middle_index} is null"
                    )));
                }
                let leaf: VirtAddr = memory.read(middle + (leaf_index * 8) as u64)?;
                if leaf.is_zero() {
                    return Err(Error::DebugInfo(format!(
                        "handle leaf {middle_index}:{leaf_index} is null"
                    )));
                }
                Ok(leaf + ((index % leaf_entries) * entry_size) as u64)
            }
            _ => Err(Error::DebugInfo(format!(
                "unsupported HANDLE_TABLE level {level}"
            ))),
        }
    }

    fn decode_handle_entry(
        &self,
        entry_layout: &TypeInfo,
        entry: VirtAddr,
        handle: u64,
    ) -> HandleEntryDetail {
        let object = (|| -> Result<VirtAddr> {
            if entry_layout.fields.contains_key("ObjectPointerBits") {
                let bits = self.extract_layout_bits(entry_layout, entry, "ObjectPointerBits")?;
                let mut pointer = bits << 4;
                if pointer & (1 << 47) != 0 {
                    pointer |= 0xffff_0000_0000_0000;
                }
                return Ok(VirtAddr(pointer));
            }
            let raw = self.extract_layout_bits(entry_layout, entry, "Object")?;
            Ok(VirtAddr(raw & !0xf))
        })();

        let granted_access = ["GrantedAccessBits", "GrantedAccess"]
            .into_iter()
            .find_map(|name| {
                entry_layout
                    .fields
                    .contains_key(name)
                    .then(|| self.extract_layout_bits(entry_layout, entry, name))
            })
            .unwrap_or_else(|| Err(Error::FieldNotFound("GrantedAccessBits".to_string())))
            .map(|value| value as u32);
        let attributes = ["ObAttributes", "Attributes"]
            .into_iter()
            .find_map(|name| {
                entry_layout
                    .fields
                    .contains_key(name)
                    .then(|| self.extract_layout_bits(entry_layout, entry, name))
            })
            .unwrap_or_else(|| Err(Error::FieldNotFound("ObAttributes".to_string())))
            .map(|value| value as u32);

        let header = object
            .as_ref()
            .map_err(|error| Error::DebugInfo(error.to_string()))
            .and_then(|object| {
                if object.is_zero() {
                    Err(Error::DebugInfo("handle entry is free".to_string()))
                } else {
                    self.inspect_object_header(*object)
                }
            });
        let type_name = match &header {
            Ok(header) => DiagnosticValue::Available(header.type_name.clone()),
            Err(error) => DiagnosticValue::Unavailable(error.to_string()),
        };
        let name = match &header {
            Ok(header) => DiagnosticValue::Available(header.name.clone()),
            Err(error) => DiagnosticValue::Unavailable(error.to_string()),
        };

        HandleEntryDetail {
            handle,
            entry,
            object: DiagnosticValue::from_result(object),
            type_name,
            name,
            granted_access: DiagnosticValue::from_result(granted_access),
            attributes: DiagnosticValue::from_result(attributes),
        }
    }

    fn handle_table_context(
        &self,
    ) -> Result<(ProcessInfo, VirtAddr, VirtAddr, u8, usize, Arc<TypeInfo>)> {
        let process = self.selected_process_info()?;
        let types = self.guest()?.ntoskrnl.types_in(process.dtb);
        let eprocess = types.struct_at("_EPROCESS", process.eprocess_va)?;
        let table: VirtAddr = eprocess.read_field("ObjectTable")?;
        if table.is_zero() {
            return Err(Error::DebugInfo(
                "_EPROCESS.ObjectTable is null".to_string(),
            ));
        }
        let table_layout = types.layout("_HANDLE_TABLE")?;
        let table_code: u64 = self.read_layout_field(&table_layout, table, "TableCode")?;
        let level = (table_code & 3) as u8;
        if level > 2 {
            return Err(Error::DebugInfo(format!(
                "unsupported HANDLE_TABLE level {level}"
            )));
        }
        let next_handle: u64 =
            self.read_layout_field(&table_layout, table, "NextHandleNeedingPool")?;
        let entry_layout = types.layout("_HANDLE_TABLE_ENTRY")?;
        Ok((
            process,
            table,
            VirtAddr(table_code & !3),
            level,
            (next_handle / 4) as usize,
            entry_layout,
        ))
    }

    /// List non-free handles in the selected/current process.  Both page-table
    /// traversal and slot count are bounded by `limit`.
    pub fn enumerate_handles(&self, limit: usize) -> Result<HandleTableSummary> {
        let limit = limit.clamp(1, 4096);
        let (process, table, table_base, level, advertised, entry_layout) =
            self.handle_table_context()?;
        let scanned = advertised.min(limit);
        let mut entries = Vec::new();
        let mut skipped_entries = 0usize;
        for index in 0..scanned {
            let entry = match self.handle_entry_address(table_base, level, index, entry_layout.size)
            {
                Ok(entry) => entry,
                Err(_) => {
                    skipped_entries += 1;
                    continue;
                }
            };
            let decoded = self.decode_handle_entry(&entry_layout, entry, (index as u64) * 4);
            if !matches!(
                decoded.object,
                DiagnosticValue::Available(address) if address.is_zero()
            ) {
                entries.push(decoded);
            }
        }
        Ok(HandleTableSummary {
            process,
            table,
            table_level: level,
            advertised_handles: advertised,
            scanned_handles: scanned,
            skipped_entries,
            truncated: advertised > scanned,
            entries,
        })
    }

    /// Decode one handle from the same selected/current process handle table.
    pub fn inspect_handle(&self, handle: u64) -> Result<HandleEntryDetail> {
        if handle & 3 != 0 {
            return Err(Error::DebugInfo(format!(
                "handle {handle:#x} is not 4-byte aligned"
            )));
        }
        let (_, _, table_base, level, advertised, entry_layout) = self.handle_table_context()?;
        let index = (handle / 4) as usize;
        if index >= advertised {
            return Err(Error::DebugInfo(format!(
                "handle {handle:#x} is beyond NextHandleNeedingPool ({:#x})",
                advertised * 4
            )));
        }
        let entry = self.handle_entry_address(table_base, level, index, entry_layout.size)?;
        Ok(self.decode_handle_entry(&entry_layout, entry, handle))
    }

    /// Decode a `_FILE_OBJECT` strictly from the loaded kernel PDB layout.
    pub fn inspect_file_object(&self, address: VirtAddr) -> Result<FileObjectDetail> {
        let types = self.guest()?.ntoskrnl.types_in(self.current_dtb());
        let layout = types.layout("_FILE_OBJECT")?;
        let read_ptr =
            |name| DiagnosticValue::from_result(self.read_layout_field(&layout, address, name));
        let read_bool = |name| {
            DiagnosticValue::from_result(
                self.read_layout_field::<u8>(&layout, address, name)
                    .map(|value| value != 0),
            )
        };
        let device_object: Result<VirtAddr> =
            self.read_layout_field(&layout, address, "DeviceObject");
        let device_type = match &device_object {
            Ok(device) if !device.is_zero() => DiagnosticValue::from_result(
                self.inspect_device_object(*device)
                    .map(|detail| detail.device_type),
            ),
            Ok(_) => DiagnosticValue::Unavailable("_FILE_OBJECT.DeviceObject is null".to_string()),
            Err(error) => DiagnosticValue::Unavailable(error.to_string()),
        };
        let device_name = match &device_object {
            Ok(device) if !device.is_zero() => DiagnosticValue::from_result(
                self.inspect_object_header(*device)
                    .map(|detail| detail.name),
            ),
            Ok(_) => DiagnosticValue::Unavailable("_FILE_OBJECT.DeviceObject is null".to_string()),
            Err(error) => DiagnosticValue::Unavailable(error.to_string()),
        };

        Ok(FileObjectDetail {
            address,
            file_type: DiagnosticValue::from_result(
                self.read_layout_field(&layout, address, "Type"),
            ),
            size: DiagnosticValue::from_result(self.read_layout_field(&layout, address, "Size")),
            device_object: DiagnosticValue::from_result(device_object),
            device_type,
            device_name,
            file_name: DiagnosticValue::from_result(
                types
                    .struct_at("_FILE_OBJECT", address)?
                    .unicode_string("FileName"),
            ),
            related_file_object: read_ptr("RelatedFileObject"),
            flags: DiagnosticValue::from_result(self.read_layout_field(&layout, address, "Flags")),
            current_byte_offset: DiagnosticValue::from_result(self.read_layout_field(
                &layout,
                address,
                "CurrentByteOffset",
            )),
            fs_context: read_ptr("FsContext"),
            fs_context2: read_ptr("FsContext2"),
            section_object_pointer: read_ptr("SectionObjectPointer"),
            private_cache_map: read_ptr("PrivateCacheMap"),
            final_status: DiagnosticValue::from_result(self.read_layout_field(
                &layout,
                address,
                "FinalStatus",
            )),
            lock_operation: read_bool("LockOperation"),
            delete_pending: read_bool("DeletePending"),
            read_access: read_bool("ReadAccess"),
            write_access: read_bool("WriteAccess"),
            delete_access: read_bool("DeleteAccess"),
            shared_read: read_bool("SharedRead"),
            shared_write: read_bool("SharedWrite"),
            shared_delete: read_bool("SharedDelete"),
        })
    }

    /// Decode one executive resource at an explicit address.
    pub fn inspect_resource(&self, address: VirtAddr) -> Result<ResourceDetail> {
        const MAX_RESOURCE_OWNERS: usize = 64;
        let types = self.guest()?.ntoskrnl.types_in(self.current_dtb());
        let layout = types.layout("_ERESOURCE")?;
        let owner_layout = types.layout("_OWNER_ENTRY")?;
        let owners = DiagnosticValue::from_result((|| -> Result<Vec<ResourceOwner>> {
            let mut owners = Vec::new();
            let owner_entry = address + layout.field_offset("OwnerEntry")?;
            let thread: u64 = self.read_layout_field(&owner_layout, owner_entry, "OwnerThread")?;
            let count: i32 = self.read_layout_field(&owner_layout, owner_entry, "OwnerCount")?;
            if thread & !3 != 0 && count != 0 {
                owners.push(ResourceOwner {
                    thread: VirtAddr(thread & !3),
                    count,
                });
            }

            let table: VirtAddr = self.read_layout_field(&layout, address, "OwnerTable")?;
            if table.is_zero() {
                return Ok(owners);
            }
            let table_size: u32 = self.read_layout_field(&owner_layout, table, "TableSize")?;
            if table_size as usize > MAX_RESOURCE_OWNERS {
                return Err(Error::DebugInfo(format!(
                    "_OWNER_ENTRY.TableSize {table_size} exceeds bound {MAX_RESOURCE_OWNERS}"
                )));
            }
            for index in 1..table_size as usize {
                let entry = table + (index * owner_layout.size) as u64;
                let thread: u64 = self.read_layout_field(&owner_layout, entry, "OwnerThread")?;
                let count: i32 = self.read_layout_field(&owner_layout, entry, "OwnerCount")?;
                if thread & !3 != 0 && count != 0 {
                    owners.push(ResourceOwner {
                        thread: VirtAddr(thread & !3),
                        count,
                    });
                }
            }
            Ok(owners)
        })());

        Ok(ResourceDetail {
            address,
            active_count: DiagnosticValue::from_result(self.read_layout_field(
                &layout,
                address,
                "ActiveCount",
            )),
            flags: DiagnosticValue::from_result(self.read_layout_field(&layout, address, "Flag")),
            contention_count: DiagnosticValue::from_result(self.read_layout_field(
                &layout,
                address,
                "ContentionCount",
            )),
            shared_waiters: DiagnosticValue::from_result(self.read_layout_field(
                &layout,
                address,
                "NumberOfSharedWaiters",
            )),
            exclusive_waiters: DiagnosticValue::from_result(self.read_layout_field(
                &layout,
                address,
                "NumberOfExclusiveWaiters",
            )),
            owners,
        })
    }

    /// Enumerate the kernel-maintained executive-resource list when the private
    /// list-head symbol and `_ERESOURCE.SystemResourcesList` metadata exist.
    /// There is deliberately no memory-scan fallback.
    pub fn enumerate_resources(&self, limit: usize) -> Result<ResourceListSummary> {
        let limit = limit.clamp(1, 1024);
        let guest = self.guest()?;
        let head = guest.ntoskrnl.symbol("ExpSystemResourcesList")?.address();
        let layout = guest.ntoskrnl.types().layout("_ERESOURCE")?;
        let link_offset = layout.field_offset("SystemResourcesList")?;
        let memory = self.context_memory();
        let (links, termination) =
            bounded_list_walk(head, limit, |link| memory.read::<VirtAddr>(link));
        let resources = links
            .into_iter()
            .map(|link| self.inspect_resource(link - link_offset))
            .collect::<Result<Vec<_>>>()?;
        Ok(ResourceListSummary {
            head,
            resources,
            termination,
        })
    }

    /// Decode the executive `_OBJECT_HEADER` for `addr`, accepting either the
    /// object body or the header itself, and resolve its type and name.
    pub fn inspect_object_header(&self, addr: VirtAddr) -> Result<ObjectHeaderDetail> {
        let guest = self.guest()?;
        let mem = guest.ntoskrnl.memory();
        let layout = guest.ntoskrnl.types().layout("_OBJECT_HEADER")?;
        let header_size = layout.size as u64;
        let body_off = layout.field_offset("Body")?;
        let type_index_off = layout.field_offset("TypeIndex")?;
        let object_name = self.object_name_layout().ok();
        let cookie = match guest.ntoskrnl.symbol("ObHeaderCookie") {
            Ok(symbol) => symbol.read::<u8>()?,
            Err(Error::SymbolNotFound(_)) => 0,
            Err(error) => return Err(error),
        };
        let type_table = guest
            .ntoskrnl
            .symbol("ObTypeIndexTable")
            .ok()
            .map(|symbol| symbol.address());

        let header_ok = |header: VirtAddr| -> bool {
            header_size
                .checked_sub(1)
                .and_then(|last| header.0.checked_add(last))
                .map(VirtAddr)
                .is_some_and(|end| mem.read::<u8>(header).is_ok() && mem.read::<u8>(end).is_ok())
        };
        let candidate_type_object = |header: VirtAddr| -> Option<VirtAddr> {
            let raw: u8 = mem.read(header + type_index_off).ok()?;
            let index = u64::from(raw ^ ((header.0 >> 8) as u8) ^ cookie);
            mem.read::<VirtAddr>(type_table? + index * 8)
                .ok()
                .filter(|object| looks_like_kernel_pointer(object.0))
        };

        // The input is usually the object body. If both possible headers are
        // readable, use the decoded type table to distinguish a real header
        // from unrelated readable pool bytes before it.
        let body_candidate = addr
            .0
            .checked_sub(body_off)
            .map(VirtAddr)
            .filter(|header| header_ok(*header));
        let direct_candidate = header_ok(addr).then_some(addr);
        let body_type = body_candidate.and_then(candidate_type_object);
        let direct_type = direct_candidate.and_then(candidate_type_object);
        let (header, body, mode) = select_object_header_candidate(
            addr,
            body_off,
            body_candidate,
            direct_candidate,
            body_type.is_some(),
            direct_type.is_some(),
        )
        .ok_or_else(|| {
            Error::DebugInfo(format!("no plausible _OBJECT_HEADER for {:#x}", addr.0))
        })?;

        let h = self.kernel_struct("_OBJECT_HEADER", header)?;
        let info_mask: Option<u8> = h.read_field("InfoMask").ok();

        // On Win10+ the stored TypeIndex is obfuscated; the real index is
        // raw ^ (second byte of the header address) ^ nt!ObHeaderCookie. The
        // cookie symbol is absent on older builds (treat as 0 -> raw index).
        let type_index: Option<u64> = h
            .read_field::<u8>("TypeIndex")
            .ok()
            .map(|raw| (raw ^ ((header.0 >> 8) as u8) ^ cookie) as u64);

        // Resolve the type object via ObTypeIndexTable[index] and read its name.
        // ObTypeIndexTable is the array itself, so index it directly.
        let (type_object, type_name) = match (type_table, type_index) {
            (Some(table), Some(index)) => {
                let resolved = mem
                    .read::<VirtAddr>(table + index * 8)
                    .ok()
                    .filter(|object| looks_like_kernel_pointer(object.0));
                let name = resolved.and_then(|t| {
                    let off = guest
                        .ntoskrnl
                        .types()
                        .layout("_OBJECT_TYPE")
                        .ok()?
                        .field_offset("Name")
                        .ok()?;
                    self.read_kernel_unicode_string(t + off)
                        .ok()
                        .filter(|s| !s.is_empty())
                });
                (resolved, name)
            }
            _ => (None, None),
        };

        let name_info = info_mask.and_then(|mask| {
            object_name
                .as_ref()
                .and_then(|layout| layout.name_info_address(header, mask).ok().flatten())
        });
        let name = name_info.and_then(|info| {
            object_name.as_ref().and_then(|layout| {
                self.read_kernel_unicode_string(info + layout.name_offset)
                    .ok()
                    .filter(|name| !name.is_empty())
            })
        });

        Ok(ObjectHeaderDetail {
            input: addr,
            mode,
            header,
            body,
            pointer_count: h.read_field("PointerCount")?,
            handle_count: h.read_field("HandleCount")?,
            type_index,
            type_object,
            type_name,
            info_mask,
            name_info,
            name,
        })
    }

    /// Enumerate the process/thread/image notification callbacks registered in
    /// the `Psp*NotifyRoutine` fast-ref arrays.
    pub fn enumerate_notify_callbacks(&self) -> Result<Vec<NotifyCallback>> {
        const MAX_NOTIFY: u64 = 64;
        let sets: [(&str, &str); 3] = [
            ("process", "PspCreateProcessNotifyRoutine"),
            ("thread", "PspCreateThreadNotifyRoutine"),
            ("image", "PspLoadImageNotifyRoutine"),
        ];

        let guest = self.guest()?;
        let mem = guest.ntoskrnl.memory();
        let ex_callback_size = guest
            .ntoskrnl
            .types()
            .layout("_EX_CALLBACK")
            .ok()
            .map(|l| l.size as u64)
            .filter(|s| (8..=0x40).contains(s))
            .unwrap_or(8);
        let block_layout = guest
            .ntoskrnl
            .types()
            .layout("_EX_CALLBACK_ROUTINE_BLOCK")
            .ok();
        let function_off = block_layout
            .as_ref()
            .and_then(|l| l.field_offset("Function").ok())
            .unwrap_or(8);
        let context_off = block_layout
            .as_ref()
            .and_then(|l| l.field_offset("Context").ok())
            .unwrap_or(16);

        let is_kernel = |a: VirtAddr| a.0 >= 0xffff_0000_0000_0000;
        let mut out = Vec::new();

        for (kind, symbol) in sets {
            let Ok(sym) = guest.ntoskrnl.symbol(symbol) else {
                continue;
            };
            let base = sym.address();
            for i in 0..MAX_NOTIFY {
                let entry = base + i * ex_callback_size;
                let Ok(raw): Result<VirtAddr> = mem.read(entry) else {
                    continue;
                };
                if raw.is_zero() {
                    continue;
                }
                let block = VirtAddr(raw.0 & !0xf);
                if block.is_zero() {
                    continue;
                }
                // Prefer the PDB-described layout; fall back to the stable
                // EX_RUNDOWN_REF / function / context shape when it doesn't
                // point at a kernel routine.
                let mut function = mem
                    .read::<VirtAddr>(block + function_off)
                    .unwrap_or(VirtAddr(0));
                let mut context = mem
                    .read::<VirtAddr>(block + context_off)
                    .unwrap_or(VirtAddr(0));
                if !is_kernel(function) {
                    function = mem.read::<VirtAddr>(block + 8u64).unwrap_or(VirtAddr(0));
                    context = mem.read::<VirtAddr>(block + 16u64).unwrap_or(VirtAddr(0));
                }
                if !is_kernel(function) {
                    continue;
                }
                out.push(NotifyCallback {
                    kind,
                    index: i as usize,
                    function,
                    block,
                    raw,
                    context,
                });
            }
        }

        Ok(out)
    }

    fn dump_ssdt_table(&self, label: &str, base: VirtAddr, limit: u32, guest: &Guest) -> SsdtTable {
        let mem = guest.ntoskrnl.memory();
        let dtb = guest.ntoskrnl.dtb();
        let mut entries = Vec::new();
        // Clamp implausible limits so a garbage descriptor can't spin.
        let limit = limit.min(0x4000);
        for i in 0..limit {
            let Ok(raw) = mem.read::<u32>(base + (i as u64) * 4) else {
                break;
            };
            // Entries encode a signed offset in the high 28 bits: target =
            // base + (entry >> 4) with arithmetic shift.
            let offset = (raw as i32 >> 4) as i64;
            let target = VirtAddr((base.0 as i64 + offset) as u64);
            let resolved = self.symbols.find_closest_symbol_for_address(dtb, target);
            let (symbol, module) = match resolved {
                Some((module, name, off)) => {
                    let sym = if off == 0 {
                        format!("{module}!{name}")
                    } else {
                        format!("{module}!{name}+{off:#x}")
                    };
                    (Some(sym), Some(module))
                }
                None => (None, None),
            };
            entries.push(SsdtEntry {
                index: i,
                target,
                symbol,
                module,
            });
        }
        SsdtTable {
            label: label.to_string(),
            base,
            limit,
            entries,
        }
    }

    /// Dump the kernel SSDT (`KiServiceTable`) and, when initialized, the
    /// win32k shadow table from `KeServiceDescriptorTableShadow`.
    pub fn dump_ssdt(&self) -> Result<Vec<SsdtTable>> {
        let guest = self.guest()?;
        let mem = guest.ntoskrnl.memory();
        let base = guest.ntoskrnl.symbol("KiServiceTable")?.address();
        let limit = guest.ntoskrnl.symbol("KiServiceLimit")?.read::<u32>()?;
        let mut tables = vec![self.dump_ssdt_table("SSDT", base, limit, guest)];

        // Shadow table: [0] is the kernel SSDT, [1] is win32k. Only present once
        // a GUI thread has initialized it.
        if let Ok(sdt) = guest.ntoskrnl.symbol("KeServiceDescriptorTableShadow") {
            let desc = guest.ntoskrnl.types().layout("_KSERVICE_TABLE_DESCRIPTOR");
            let desc_size = desc.as_ref().ok().map(|l| l.size as u64).unwrap_or(0x20);
            let base_off = desc
                .as_ref()
                .ok()
                .and_then(|l| l.field_offset("Base").ok())
                .unwrap_or(0);
            let limit_off = desc
                .as_ref()
                .ok()
                .and_then(|l| l.field_offset("Limit").ok())
                .unwrap_or(0x10);
            let win32k = sdt.address() + desc_size;
            if let Ok(w_base) = mem.read::<VirtAddr>(win32k + base_off)
                && !w_base.is_zero()
            {
                let w_limit = mem.read::<u32>(win32k + limit_off).unwrap_or(0);
                tables.push(self.dump_ssdt_table("shadow SSDT (win32k)", w_base, w_limit, guest));
            }
        }

        Ok(tables)
    }

    /// Read an `_IRP` only if it looks like one (Type == 6, plausible Size),
    /// returning `(stack_count, current_location)`.
    fn plausible_irp(&self, irp: VirtAddr) -> Option<(u8, u8)> {
        let guest = self.guest.as_ref()?;
        let mem = guest.ntoskrnl.memory();
        let layout = guest.ntoskrnl.types().layout("_IRP").ok()?;
        let ty: u16 = mem.read(irp).ok()?;
        if ty != 6 {
            return None;
        }
        let size: u16 = mem.read(irp + layout.field_offset("Size").ok()?).ok()?;
        if (size as u64) < layout.size as u64 || size > 0x1000 {
            return None;
        }
        let sc = mem
            .read::<u8>(irp + layout.field_offset("StackCount").ok()?)
            .unwrap_or(0);
        let cl = mem
            .read::<u8>(irp + layout.field_offset("CurrentLocation").ok()?)
            .unwrap_or(0);
        Some((sc, cl))
    }

    /// Discover in-flight IRPs by walking each thread's `_ETHREAD.IrpList` and
    /// each device's `_DEVICE_OBJECT.CurrentIrp`. `filter` scopes processes
    /// (pid or name substring) and, for the device sweep, driver names.
    pub fn discover_irps(&self, filter: Option<&str>) -> Result<Vec<IrpHit>> {
        let guest = self.guest()?;
        let mem = guest.ntoskrnl.memory();
        let off = |ty: &str, field: &str| -> Option<u64> {
            guest
                .ntoskrnl
                .types()
                .layout(ty)
                .ok()
                .and_then(|l| l.field_offset(field).ok())
        };
        let read_ptr = |a: VirtAddr| mem.read::<VirtAddr>(a).ok();

        let filter_l = filter.map(|f| f.to_ascii_lowercase());
        let numeric_filter = filter.and_then(|f| f.parse::<u64>().ok());
        let mut out = Vec::new();

        let procs = guest.enumerate_processes()?;
        let thread_head_off = off("_EPROCESS", "ThreadListHead");
        let thread_link_off = off("_ETHREAD", "ThreadListEntry");
        let irp_list_off = off("_ETHREAD", "IrpList");
        let irp_link_off = off("_IRP", "ThreadListEntry");
        let cid_off = off("_ETHREAD", "Cid");
        let tcb_off = off("_ETHREAD", "Tcb").unwrap_or(0);
        let unique_thread_off = off("_CLIENT_ID", "UniqueThread");
        let state_off = off("_KTHREAD", "State");
        let wait_off = off("_KTHREAD", "WaitReason");

        for p in &procs {
            let matched = match (&filter_l, numeric_filter) {
                (None, _) => true,
                (Some(_), Some(pid)) => p.pid == pid,
                (Some(f), None) => p.name.to_ascii_lowercase().contains(f.as_str()),
            };
            if !matched {
                continue;
            }
            let (Some(head_off), Some(link_off), Some(list_off), Some(rec_off)) =
                (thread_head_off, thread_link_off, irp_list_off, irp_link_off)
            else {
                break;
            };

            // Walk the process thread list (ETHREAD.ThreadListEntry).
            let head = p.eprocess_va + head_off;
            let mut seen_t = Vec::new();
            let mut cur = read_ptr(head);
            for _ in 0..4096 {
                let Some(node) = cur else { break };
                if node.is_zero() || node == head || seen_t.contains(&node.0) {
                    break;
                }
                seen_t.push(node.0);
                let ethread = node - link_off;

                let tid = cid_off
                    .zip(unique_thread_off)
                    .and_then(|(c, u)| mem.read::<u64>(ethread + c + u).ok());
                let state = state_off.and_then(|o| mem.read::<u8>(ethread + tcb_off + o).ok());
                let wait = wait_off.and_then(|o| mem.read::<u8>(ethread + tcb_off + o).ok());

                // Walk this thread's IrpList (IRP.ThreadListEntry).
                let irp_head = ethread + list_off;
                let mut seen_i = Vec::new();
                let mut icur = read_ptr(irp_head);
                for _ in 0..256 {
                    let Some(inode) = icur else { break };
                    if inode.is_zero() || inode == irp_head || seen_i.contains(&inode.0) {
                        break;
                    }
                    seen_i.push(inode.0);
                    let irp = inode - rec_off;
                    if let Some((sc, cl)) = self.plausible_irp(irp) {
                        out.push(IrpHit {
                            irp,
                            source: "thread",
                            stack_count: sc,
                            current_location: cl,
                            pid: Some(p.pid),
                            tid,
                            ethread: Some(ethread),
                            state,
                            wait_reason: wait,
                            driver: None,
                            device: None,
                        });
                    }
                    icur = read_ptr(inode);
                }
                cur = read_ptr(node);
            }
        }

        if numeric_filter.is_none() {
            let current_irp_off = off("_DEVICE_OBJECT", "CurrentIrp");
            let next_off = off("_DEVICE_OBJECT", "NextDevice");
            if let (Some(cur_off), Some(next_off)) = (current_irp_off, next_off) {
                for driver in self.enumerate_driver_objects()? {
                    if let Some(f) = &filter_l
                        && !driver.name.to_ascii_lowercase().contains(f.as_str())
                    {
                        continue;
                    }
                    let mut seen = Vec::new();
                    let mut cur = Some(driver.device_object);
                    for _ in 0..256 {
                        let Some(dev) = cur else { break };
                        if dev.is_zero() || seen.contains(&dev.0) {
                            break;
                        }
                        seen.push(dev.0);
                        let current_irp = read_ptr(dev + cur_off).unwrap_or(VirtAddr(0));
                        if !current_irp.is_zero()
                            && let Some((sc, cl)) = self.plausible_irp(current_irp)
                        {
                            out.push(IrpHit {
                                irp: current_irp,
                                source: "device",
                                stack_count: sc,
                                current_location: cl,
                                pid: None,
                                tid: None,
                                ethread: None,
                                state: None,
                                wait_reason: None,
                                driver: Some(driver.name.clone()),
                                device: Some(dev),
                            });
                        }
                        cur = read_ptr(dev + next_off);
                    }
                }
            }
        }

        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use crate::types::VirtAddr;

    #[test]
    fn direct_object_header_wins_when_only_it_has_a_valid_type() {
        let input = VirtAddr(0x1000);
        assert_eq!(
            select_object_header_candidate(
                input,
                0x30,
                Some(VirtAddr(0x0fd0)),
                Some(input),
                false,
                true,
            ),
            Some((input, VirtAddr(0x1030), "header"))
        );
    }

    #[test]
    fn ambiguous_readable_object_headers_are_rejected() {
        assert_eq!(
            select_object_header_candidate(
                VirtAddr(0x1000),
                0x30,
                Some(VirtAddr(0x0fd0)),
                Some(VirtAddr(0x1000)),
                false,
                false,
            ),
            None
        );
    }

    #[test]
    fn object_name_info_address_accounts_for_creator_info_only() {
        let layout = ObjectNameLayout {
            body_offset: 0x30,
            info_mask_offset: 0x1a,
            creator_info_size: Some(0x20),
            name_info_size: 0x20,
            name_offset: 0x08,
        };
        let header = VirtAddr(0x1000);

        assert_eq!(layout.name_info_address(header, 0x00).unwrap(), None);
        assert_eq!(
            layout.name_info_address(header, 0x02).unwrap(),
            Some(VirtAddr(0x0fe0))
        );
        assert_eq!(
            layout.name_info_address(header, 0x03).unwrap(),
            Some(VirtAddr(0x0fc0))
        );
        assert_eq!(
            layout.name_info_address(header, 0x7e).unwrap(),
            Some(VirtAddr(0x0fe0))
        );
    }

    #[test]
    fn object_name_info_address_requires_present_creator_layout() {
        let layout = ObjectNameLayout {
            body_offset: 0x30,
            info_mask_offset: 0x1a,
            creator_info_size: None,
            name_info_size: 0x20,
            name_offset: 0x08,
        };

        let error = layout
            .name_info_address(VirtAddr(0x1000), 0x03)
            .unwrap_err();
        assert!(matches!(
            &error,
            Error::StructNotFound(name)
                if name == "_OBJECT_HEADER_CREATOR_INFO"
        ));
    }
}
