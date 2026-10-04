//! Loader-list walks: a process's native and WOW64 module lists, the
//! kernel's `PsLoadedModuleList`, and module version population.

use super::{Guest, ModuleInfo, ProcessInfo, ProcessModulesDetail};
use crate::{
    backend::MemoryOps,
    bytes::{read_u16, read_u32},
    error::{Error, Result},
    layout::{StructRef, utf16le_lossy},
    memory,
    pe::read_pe_version_info,
    target::{ListCursor, ListTermination, links_back_to},
    types::*,
};
use std::collections::HashSet;
use std::sync::Arc;

const MAX_LOADER_MODULES: usize = 1000;
/// The name of a loader entry whose name cannot be read.
const UNKNOWN_MODULE_NAME: &str = "<unknown>";
/// How deep a VAD tree search goes: the AVL tree of even a 65,536-VAD
/// process is at most 23 levels deep, so a longer path is a corrupt tree.
const MAX_VAD_DEPTH: usize = 64;

/// One node of a process's VAD tree, as [`find_vad_starting_at`] reads it.
struct VadNode {
    start_vpn: u64,
    end_vpn: u64,
    left: VirtAddr,
    right: VirtAddr,
}

/// The node of the VAD tree at `root` whose range starts at page `vpn`,
/// found as in the AVL tree it is, keyed by page number. `read` reads a
/// node; `None` when one is unreadable, the range at `vpn` starts below it,
/// or no range holds it.
fn find_vad_starting_at(
    root: VirtAddr,
    vpn: u64,
    read: impl Fn(VirtAddr) -> Option<VadNode>,
) -> Option<VirtAddr> {
    let mut node = root;
    for _ in 0..MAX_VAD_DEPTH {
        if node.is_zero() {
            return None;
        }
        let vad = read(node)?;
        node = if vpn < vad.start_vpn {
            vad.left
        } else if vpn > vad.end_vpn {
            vad.right
        } else {
            return (vpn == vad.start_vpn).then_some(node);
        };
    }
    None
}

fn populate_module_versions<B: MemoryOps<PhysAddr>>(
    modules: &mut [ModuleInfo],
    memory: &memory::AddressSpace<'_, B>,
) {
    for module in modules.iter_mut() {
        if let Some((file_ver, prod_ver)) = read_pe_version_info(module.base_address, memory) {
            module.file_version = Some(file_ver);
            module.product_version = Some(prod_ver);
        }
    }
}

/// Read a loader-table record (`_LDR_DATA_TABLE_ENTRY` / `_KLDR_DATA_TABLE_ENTRY`)
/// into a `ModuleInfo`, or `None` when it has no base address (skip it). Shared
/// by the process- and kernel-module walks, which differ only in their list.
pub(super) fn module_info_from_record(record: &StructRef<'_>) -> Result<Option<ModuleInfo>> {
    let dll_base = record.read_pointer("DllBase")?;
    if dll_base.is_zero() {
        return Ok(None);
    }
    let size_of_image: u32 = record.read_field("SizeOfImage")?;
    let name = record
        .unicode_string("BaseDllName")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| UNKNOWN_MODULE_NAME.to_string());
    let mut info = ModuleInfo::new(name, dll_base, size_of_image);
    info.path = record
        .unicode_string("FullDllName")
        .ok()
        .filter(|path| !path.is_empty());
    if let Ok(entry_point) = record.read_pointer("EntryPoint")
        && !entry_point.is_zero()
    {
        info.entry_point = Some(entry_point);
    }
    if let Ok(tds) = record.read_field::<u32>("TimeDateStamp") {
        info = info.with_time_date_stamp(tds);
    }
    if let Ok(cs) = record.read_field::<u32>("CheckSum") {
        info = info.with_checksum(cs);
    }
    Ok(Some(info))
}

fn read_loader_pointer(
    memory: &impl MemoryOps<VirtAddr>,
    address: VirtAddr,
    pointer_size: usize,
) -> Result<VirtAddr> {
    if pointer_size == 4 {
        memory
            .read::<u32>(address)
            .map(|pointer| VirtAddr(u64::from(pointer)))
    } else {
        memory.read::<u64>(address).map(VirtAddr)
    }
}

fn read_unicode32(memory: &impl MemoryOps<VirtAddr>, length: usize, buffer: u32) -> Option<String> {
    if length == 0 || buffer == 0 {
        return None;
    }
    let mut bytes = vec![0u8; length];
    memory
        .read_bytes(VirtAddr(u64::from(buffer)), &mut bytes)
        .ok()?;
    Some(utf16le_lossy(&bytes))
}

impl Guest {
    pub fn process_modules(&self, info: &ProcessInfo) -> Result<Vec<ModuleInfo>> {
        self.process_modules_detail(info)
            .map(|detail| detail.modules)
    }

    /// One shared native/WOW64 loader-list walk for `lm`, `!dlls`, and the SDK.
    /// Partial entries and each list's termination are preserved for callers
    /// that need to diagnose a corrupt or truncated list.
    pub fn process_modules_detail(&self, info: &ProcessInfo) -> Result<ProcessModulesDetail> {
        self.memoized(
            |memo| memo.process_modules.entry(info.eprocess_va).or_default(),
            || self.walk_process_modules(info),
        )
    }

    fn walk_process_modules(&self, info: &ProcessInfo) -> Result<ProcessModulesDetail> {
        let types = self.ntoskrnl.types_in(info.dtb);
        let eprocess = types.struct_at("_EPROCESS", info.eprocess_va)?;
        let peb = eprocess.follow("Peb")?;
        if peb.addr().is_zero() {
            return Err(Error::MissingPEB);
        }
        let ldr = peb.follow("Ldr")?;
        let mut modules = Vec::new();
        let termination = if ldr.addr().is_zero() {
            ListTermination::Null
        } else {
            let head = ldr.embedded("InLoadOrderModuleList")?.addr();
            let layout = types.layout("_LDR_DATA_TABLE_ENTRY")?;
            let link_offset = layout.field_offset("InLoadOrderLinks")?;
            let pointer_size = usize::from(layout.pointer_size);
            let memory = self.ntoskrnl.memory_in(info.dtb);
            let mut cursor = ListCursor::new(head, MAX_LOADER_MODULES);
            cursor.advance(
                read_loader_pointer(&memory, head, pointer_size).map_err(|error| error.to_string()),
            );
            while let Some(link) = cursor.take_current() {
                let record_address = VirtAddr(link.0.wrapping_sub(link_offset));
                let record = types
                    .struct_with_layout(Arc::clone(&layout), record_address)
                    .prefetch();
                match module_info_from_record(&record) {
                    Ok(Some(module)) => modules.push(module),
                    Ok(None) => {}
                    Err(error) => {
                        cursor.advance(Err(error.to_string()));
                        break;
                    }
                }
                cursor.advance(
                    read_loader_pointer(&memory, record_address + link_offset, pointer_size)
                        .map_err(|error| error.to_string()),
                );
            }
            cursor.finish()
        };
        self.name_from_mapped_images(info, &mut modules);

        let mut wow64_termination = None;
        if let Some(peb32) = info.wow64_peb {
            let (mut modules32, termination32) = self.process_modules32(info.dtb, peb32)?;
            self.name_from_mapped_images(info, &mut modules32);
            wow64_termination = Some(termination32);
            // Both lists carry the executable itself (one mapping, x86 code)
            // and an ntdll (two: the 32-bit copy is addressed as `ntdll32!`,
            // as WinDbg's wow64exts does).
            for mut module in modules32 {
                if let Some(native) = modules
                    .iter_mut()
                    .find(|native| native.base_address == module.base_address)
                {
                    native.is_32bit = true;
                    continue;
                }
                if modules
                    .iter()
                    .any(|native| native.short_name == module.short_name)
                {
                    module.short_name.push_str("32");
                }
                modules.push(module);
            }
        }

        Ok(ProcessModulesDetail {
            modules,
            termination,
            wow64_termination,
        })
    }

    /// Name each of `modules` whose loader entry's names are unreadable after
    /// the file mapped at its base. The loader keeps the names on the process
    /// heap, which is paged out in an idle process (in about 8% of the
    /// modules of a desktop guest), while the kernel's VADs stay resident.
    fn name_from_mapped_images(&self, info: &ProcessInfo, modules: &mut [ModuleInfo]) {
        for module in modules
            .iter_mut()
            .filter(|module| module.name == UNKNOWN_MODULE_NAME)
        {
            if let Some(name) = self.mapped_image_name(info, module.base_address) {
                module.short_name = ModuleInfo::derive_short_name(&name);
                module.name = name;
            }
        }
    }

    /// The name of the image file mapped at `base` in `info`'s address space:
    /// the VAD that starts there leads, through its subsection and the
    /// section's control area, to the file object, as `!vad` follows it.
    fn mapped_image_name(&self, info: &ProcessInfo, base: VirtAddr) -> Option<String> {
        let types = self.ntoskrnl.types_in(info.dtb);
        let memory = self.ntoskrnl.memory_in(info.dtb);
        // Tree links keep balance bits in their low bits.
        let link = |address: VirtAddr| {
            memory
                .read::<u64>(address)
                .ok()
                .map(|link| VirtAddr(link & !0xf))
        };
        let vad_root = types
            .struct_at("_EPROCESS", info.eprocess_va)
            .ok()?
            .embedded("VadRoot")
            .ok()?;
        // `_RTL_AVL_TREE.Root`; before it, the root pointer itself.
        let root = link(vad_root.addr() + vad_root.layout().field_offset("Root").unwrap_or(0))?;
        let short = types.layout("_MMVAD_SHORT").ok()?;
        let vad_node = short.field_offset("VadNode").unwrap_or(0);
        let balanced = types.layout("_RTL_BALANCED_NODE").ok()?;
        let left = balanced.field_offset("Left").unwrap_or(0);
        let right = balanced.field_offset("Right").unwrap_or(8);
        let read_node = |node: VirtAddr| {
            let vad = types.struct_with_layout(Arc::clone(&short), node - vad_node);
            let vpn = |low: &str, high: &str| -> Option<u64> {
                let low = u64::from(vad.read_field::<u32>(low).ok()?);
                Some(low | u64::from(vad.read_field::<u8>(high).unwrap_or(0)) << 32)
            };
            Some(VadNode {
                start_vpn: vpn("StartingVpn", "StartingVpnHigh")?,
                end_vpn: vpn("EndingVpn", "EndingVpnHigh")?,
                left: link(node + left)?,
                right: link(node + right)?,
            })
        };
        let node = find_vad_starting_at(root, base.0 >> 12, read_node)?;
        let nonzero = |address: VirtAddr| (!address.is_zero()).then_some(address);
        let subsection = types
            .struct_at("_MMVAD", node - vad_node)
            .ok()?
            .read_pointer("Subsection")
            .ok()
            .and_then(nonzero)?;
        let control_area = types
            .struct_at("_SUBSECTION", subsection)
            .ok()?
            .read_pointer("ControlArea")
            .ok()
            .and_then(nonzero)?;
        // `FilePointer` is an `_EX_FAST_REF`, a reference count in its low bits.
        let control_area = types.struct_at("_CONTROL_AREA", control_area).ok()?;
        let file_object =
            link(control_area.addr() + control_area.layout().field_offset("FilePointer").ok()?)
                .and_then(nonzero)?;
        let path = types
            .struct_at("_FILE_OBJECT", file_object)
            .ok()?
            .unicode_string("FileName")
            .ok()?;
        let name = path.rsplit(['\\', '/']).next()?;
        (!name.is_empty()).then(|| name.to_string())
    }

    /// The 32-bit loader list of a WOW64 process. `_PEB_LDR_DATA32` and
    /// `_LDR_DATA_TABLE_ENTRY32` are not in the kernel's PDB and the 32-bit
    /// ntdll's is not loaded before this walk finds it, so the entry layout
    /// is the fixed x86 ABI (unchanged since Windows 2000): `DllBase` +0x18,
    /// `EntryPoint` +0x1c, `SizeOfImage` +0x20, `FullDllName` +0x24,
    /// `BaseDllName` +0x2c, `TimeDateStamp` +0x44.
    fn process_modules32(
        &self,
        dtb: Dtb,
        peb32: VirtAddr,
    ) -> Result<(Vec<ModuleInfo>, ListTermination)> {
        const IN_LOAD_ORDER_MODULE_LIST: u64 = 0x0c;
        const ENTRY_LEN: usize = 0x48;

        let types = self.ntoskrnl.types_in(dtb);
        let ldr: u32 = types.struct_at("_PEB32", peb32)?.read_field("Ldr")?;
        if ldr == 0 {
            return Ok((Vec::new(), ListTermination::Null));
        }
        let memory = self.ntoskrnl.memory_in(dtb);
        let head = VirtAddr(u64::from(ldr) + IN_LOAD_ORDER_MODULE_LIST);
        let mut cursor = ListCursor::new(head, MAX_LOADER_MODULES);
        cursor.advance(read_loader_pointer(&memory, head, 4).map_err(|error| error.to_string()));
        let mut modules = Vec::new();
        while let Some(current) = cursor.take_current() {
            let mut entry = [0u8; ENTRY_LEN];
            if let Err(error) = memory.read_bytes(current, &mut entry) {
                cursor.advance(Err(error.to_string()));
                break;
            }
            let u32_at = |offset| read_u32(&entry, offset);
            cursor.advance(Ok(VirtAddr(u64::from(u32_at(0)))));

            let dll_base = u32_at(0x18);
            if dll_base == 0 {
                continue;
            }
            let name = read_unicode32(&memory, usize::from(read_u16(&entry, 0x2c)), u32_at(0x30))
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| UNKNOWN_MODULE_NAME.to_string());
            let mut module = ModuleInfo::new(name, VirtAddr(u64::from(dll_base)), u32_at(0x20))
                .with_time_date_stamp(u32_at(0x44));
            module.path =
                read_unicode32(&memory, usize::from(read_u16(&entry, 0x24)), u32_at(0x28))
                    .filter(|path| !path.is_empty());
            module.is_32bit = true;
            let entry_point = u32_at(0x1c);
            if entry_point != 0 {
                module.entry_point = Some(VirtAddr(u64::from(entry_point)));
            }
            modules.push(module);
        }
        Ok((modules, cursor.finish()))
    }

    pub fn kernel_modules(&self) -> Result<Vec<ModuleInfo>> {
        self.memoized(
            |memo| &mut memo.kernel_modules,
            || self.walk_kernel_modules(),
        )
    }

    fn walk_kernel_modules(&self) -> Result<Vec<ModuleInfo>> {
        let head = self.ntoskrnl.symbol("PsLoadedModuleList")?;
        // At a reboot's first boot notification the list is not built yet,
        // but the kernel itself is loaded; stacks unwind through it.
        if head.read::<VirtAddr>()?.is_zero() {
            return Ok(vec![ModuleInfo::new(
                "ntoskrnl.exe".to_string(),
                self.ntoskrnl.base_address,
                self.ntoskrnl.binary_size() as u32,
            )]);
        }
        let head = head.address();

        // The kernel uses the _KLDR variant; fall back to _LDR if it's absent
        let record_type = if self
            .ntoskrnl
            .types()
            .layout("_KLDR_DATA_TABLE_ENTRY")
            .is_ok()
        {
            "_KLDR_DATA_TABLE_ENTRY"
        } else {
            "_LDR_DATA_TABLE_ENTRY"
        };

        let types = self.ntoskrnl.types();
        let layout = types.layout(record_type)?;
        let link_offset = layout.field_offset("InLoadOrderLinks")?;
        let mut modules = Vec::new();
        let mut reached = HashSet::new();
        let mut broken = None;
        for record in types.list_at(head, record_type, "InLoadOrderLinks")? {
            let record = match record {
                Ok(record) => record,
                Err(error) => {
                    broken = Some(error);
                    break;
                }
            };
            reached.insert(record.addr() + link_offset);
            if let Some(module) = module_info_from_record(&record)? {
                modules.push(module);
            }
        }
        // An entry that cannot be read ends the walk forward; the modules
        // past it are found backward, and only that entry's is missing.
        if let Some(error) = broken {
            let memory = self.ntoskrnl.memory();
            let tail = links_back_to(head, &reached, MAX_LOADER_MODULES, |link| {
                memory.read::<VirtAddr>(link + 8u64)
            });
            for link in tail.into_iter().rev() {
                let record = types
                    .struct_with_layout(Arc::clone(&layout), link - link_offset)
                    .prefetch();
                if let Ok(Some(module)) = module_info_from_record(&record) {
                    modules.push(module);
                }
            }
            if modules.is_empty() {
                return Err(error);
            }
        }

        Ok(modules)
    }

    pub fn populate_kernel_module_versions(&self, modules: &mut [ModuleInfo]) {
        let memory = self.ntoskrnl.memory();
        populate_module_versions(modules, &memory);
    }

    pub fn populate_process_module_versions(&self, modules: &mut [ModuleInfo], info: &ProcessInfo) {
        populate_module_versions(modules, &self.ntoskrnl.memory_in(info.dtb));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// A VAD tree: node address -> (start page, end page, left, right).
    fn tree(nodes: &[(u64, u64, u64, u64, u64)]) -> HashMap<u64, (u64, u64, u64, u64)> {
        nodes
            .iter()
            .map(|&(node, start, end, left, right)| (node, (start, end, left, right)))
            .collect()
    }

    fn find(nodes: &HashMap<u64, (u64, u64, u64, u64)>, vpn: u64) -> Option<u64> {
        let read = |node: VirtAddr| {
            let &(start_vpn, end_vpn, left, right) = nodes.get(&node.0)?;
            Some(VadNode {
                start_vpn,
                end_vpn,
                left: VirtAddr(left),
                right: VirtAddr(right),
            })
        };
        find_vad_starting_at(VirtAddr(0x1000), vpn, read).map(|node| node.0)
    }

    /// The search goes left below a range and right above it, on both sides
    /// of the tree; only a range that starts at the page names an image
    /// there, and a gap, an unreadable node or a cycle finds nothing.
    #[test]
    fn an_image_vad_is_found_by_the_page_it_starts_at() {
        let nodes = tree(&[
            (0x1000, 0x100, 0x1ff, 0x2000, 0x3000),
            (0x2000, 0x10, 0x1f, 0, 0),
            (0x3000, 0x300, 0x3ff, 0x4000, 0x5000),
            (0x4000, 0x250, 0x2ff, 0, 0),
            (0x5000, 0x1_0000_0000, 0x1_0000_00ff, 0, 0),
        ]);
        assert_eq!(find(&nodes, 0x100), Some(0x1000));
        assert_eq!(find(&nodes, 0x10), Some(0x2000));
        assert_eq!(find(&nodes, 0x250), Some(0x4000));
        assert_eq!(find(&nodes, 0x1_0000_0000), Some(0x5000));
        assert_eq!(
            find(&nodes, 0x260),
            None,
            "inside a range that starts below it"
        );
        assert_eq!(find(&nodes, 0x220), None, "in a gap");

        let unreadable = tree(&[(0x1000, 0x100, 0x1ff, 0x2000, 0x3000)]);
        assert_eq!(find(&unreadable, 0x10), None);
        let cycle = tree(&[(0x1000, 0x100, 0x1ff, 0, 0x1000)]);
        assert_eq!(find(&cycle, 0x300), None);
    }
}
