//! The address-space view: VAD-tree enumeration of a process and
//! `describe_address`, which places an address in a module, kernel VA
//! region, or VAD.

use std::collections::HashSet;

use super::{AddressDescription, AddressModule, MemoryRegionInfo, VadProtection, VadType};
use crate::backend::MemoryOps;
use crate::error::Result;
use crate::guest::{ModuleInfo, ProcessInfo};
use crate::layout::{ParsedType, TypeInfo, bitfield_value};
use crate::pe::section_name_at;
use crate::target::Target;
use crate::types::{Dtb, VirtAddr};

impl Target {
    /// Classify `address`: which loaded module (and PE section) it falls in, or
    /// which process VAD region, else unknown. The shared backend for the REPL
    /// `address` command, the MCP tool, and the SDK.
    pub fn describe_address(&self, address: VirtAddr) -> Result<AddressDescription> {
        let dtb = self.current_dtb();
        let is_kernel = address.0 >= 0xffff_0000_0000_0000;

        // 1. Loaded module containment (kernel list for kernel VAs, else the
        // current scope's user modules).
        let modules = if is_kernel {
            self.kernel_modules()
        } else {
            self.modules()
        };
        if let Ok(mods) = modules
            && let Some(m) = mods.into_iter().find(|m| {
                address.0 >= m.base_address.0 && address.0 < m.base_address.0 + m.size as u64
            })
        {
            let memory = self.context_memory();
            let section = section_name_at(&memory, m.base_address, address);
            return Ok(AddressDescription {
                address,
                dtb,
                kind: if is_kernel {
                    "kernel-module"
                } else {
                    "user-image"
                },
                module: Some(AddressModule {
                    name: m.name,
                    base: m.base_address,
                    size: m.size,
                    offset: address.0 - m.base_address.0,
                }),
                section,
                va_type: None,
                region: None,
            });
        }

        // 2. Kernel dynamic-VA region (pool, stacks, PTEs, cache, ...) via the
        // MM SystemVaType map.
        if is_kernel && let Some(va_type) = self.kernel_va_region(address) {
            return Ok(AddressDescription {
                address,
                dtb,
                kind: "kernel-region",
                module: None,
                section: None,
                va_type: Some(va_type),
                region: None,
            });
        }

        // 3. Process VAD region (when attached to a process).
        if let Some(p) = self.attached_process()
            && let Ok(regions) = self.enumerate_vad_regions_for_process_info(p)
            && let Some(r) = regions
                .into_iter()
                .find(|r| address.0 >= r.start.0 && address.0 < r.end.0)
        {
            let kind = match r.private_memory {
                Some(true) => "private",
                _ => "mapped",
            };
            return Ok(AddressDescription {
                address,
                dtb,
                kind,
                module: None,
                section: None,
                va_type: None,
                region: Some(r),
            });
        }

        Ok(AddressDescription {
            address,
            dtb,
            kind: "unknown",
            module: None,
            section: None,
            va_type: None,
            region: None,
        })
    }

    /// Classify a kernel dynamic-VA address via the MM `SystemVaType` map:
    /// `chunk = (va - MmSystemRangeStart) / granularity`, where the granularity
    /// is the kernel half divided into the 256-entry map. Returns the
    /// `MI_SYSTEM_VA_TYPE` name (sans `MiVa` prefix), read from the PDB enum so
    /// it adapts per build. `MiVisibleState` is a pointer to `_MI_VISIBLE_STATE`.
    fn kernel_va_region(&self, address: VirtAddr) -> Option<String> {
        let ntos = &self.guest.as_ref()?.ntoskrnl;
        let range_start: VirtAddr = ntos.symbol("MmSystemRangeStart").ok()?.read().ok()?;
        if address.0 < range_start.0 {
            return None;
        }
        // Kernel-half size / 256 (512GB on 4-level, 256TB on 5-level).
        let granularity = range_start.0.wrapping_neg() / 256;
        if granularity == 0 {
            return None;
        }
        let chunk = (address.0 - range_start.0) / granularity;
        if chunk >= 256 {
            return None;
        }

        let vs: VirtAddr = ntos.symbol("MiVisibleState").ok()?.read().ok()?;
        let type_off = ntos
            .types()
            .layout("_MI_VISIBLE_STATE")
            .ok()?
            .field_offset("SystemVaType")
            .ok()?;
        let type_byte: u8 = ntos.memory().read(vs + type_off + chunk).ok()?;

        let variants = self
            .symbols
            .find_enum_across_modules(ntos.dtb(), "_MI_SYSTEM_VA_TYPE")?;
        let name = variants
            .into_iter()
            .find(|(_, v)| *v == type_byte as i64)
            .map(|(n, _)| n)?;
        Some(name.strip_prefix("MiVa").unwrap_or(&name).to_string())
    }

    pub fn enumerate_vad_regions_for_process_info(
        &self,
        process: &ProcessInfo,
    ) -> Result<Vec<MemoryRegionInfo>> {
        let guest = self.guest()?;
        let memory = self.address_space(process.dtb);
        let types = guest.ntoskrnl.types_in(process.dtb);
        let eprocess_layout = guest.ntoskrnl.types().layout("_EPROCESS")?;
        let vad_root_base = process.eprocess_va + eprocess_layout.field_offset("VadRoot")?;
        let root = self.read_vad_root(process.dtb, vad_root_base)?;
        if root.is_zero() {
            return Ok(Vec::new());
        }

        let vad_layout = types
            .layout("_MMVAD_SHORT")
            .or_else(|_| types.layout("_MMVAD"))?;
        let vad_node_offset = vad_layout.field_offset("VadNode").unwrap_or(0);
        let node_layout = types.layout("_RTL_BALANCED_NODE")?;
        let left_offset = node_layout.field_offset("Left").unwrap_or(0);
        let right_offset = node_layout.field_offset("Right").unwrap_or(8);
        let flags_layout = types.layout("_MMVAD_FLAGS").ok();
        let modules = guest.process_modules(process).unwrap_or_default();

        let mut regions = Vec::new();
        let mut stack = vec![(root, 0usize)];
        let mut visited = HashSet::new();

        while let Some((node, level)) = stack.pop() {
            if node.is_zero() || !visited.insert(node.0) || visited.len() > 65536 {
                continue;
            }

            let left = Self::canonical_vad_link(memory.read::<VirtAddr>(node + left_offset)?);
            let right = Self::canonical_vad_link(memory.read::<VirtAddr>(node + right_offset)?);
            if !right.is_zero() {
                stack.push((right, level.saturating_add(1)));
            }
            if !left.is_zero() {
                stack.push((left, level.saturating_add(1)));
            }

            let vad = node - vad_node_offset;
            if let Some(region) = Self::read_vad_region(
                &memory,
                &vad_layout,
                flags_layout.as_deref(),
                node,
                level,
                vad,
                &modules,
            ) {
                regions.push(region);
            }
        }

        regions.sort_by_key(|region| region.start.0);
        Ok(regions)
    }

    fn read_vad_root(&self, dtb: Dtb, vad_root_base: VirtAddr) -> Result<VirtAddr> {
        let memory = self.address_space(dtb);
        let types = self.guest()?.ntoskrnl.types_in(dtb);

        if let Ok(tree_layout) = types.layout("_RTL_AVL_TREE")
            && let Ok(root_offset) = tree_layout.field_offset("Root")
        {
            let root: VirtAddr = memory.read(vad_root_base + root_offset)?;
            return Ok(Self::canonical_vad_link(root));
        }

        let root: VirtAddr = memory.read(vad_root_base)?;
        Ok(Self::canonical_vad_link(root))
    }

    fn canonical_vad_link(link: VirtAddr) -> VirtAddr {
        VirtAddr(link.0 & !0xf)
    }

    fn read_integer_field(
        memory: &impl MemoryOps<VirtAddr>,
        layout: &TypeInfo,
        base: VirtAddr,
        field: &str,
    ) -> Option<u64> {
        let info = layout.fields.get(field)?;
        let address = base + info.offset as u64;
        match info.size {
            1 => memory.read::<u8>(address).ok().map(u64::from),
            2 => memory.read::<u16>(address).ok().map(u64::from),
            4 => memory.read::<u32>(address).ok().map(u64::from),
            8 => memory.read::<u64>(address).ok(),
            _ => None,
        }
    }

    fn bitfield_value(layout: &TypeInfo, field: &str, raw: u64) -> Option<u64> {
        let info = layout.fields.get(field)?;
        let ParsedType::Bitfield { pos, len, .. } = info.type_data else {
            return None;
        };
        Some(bitfield_value(raw, pos, len))
    }

    fn vad_flags_base_offset(vad_layout: &TypeInfo) -> Option<u64> {
        vad_layout
            .field_offset("u")
            .or_else(|_| vad_layout.field_offset("u1"))
            .or_else(|_| vad_layout.field_offset("VadFlags"))
            .ok()
    }

    fn read_vad_region(
        memory: &impl MemoryOps<VirtAddr>,
        vad_layout: &TypeInfo,
        flags_layout: Option<&TypeInfo>,
        node_address: VirtAddr,
        level: usize,
        vad: VirtAddr,
        modules: &[ModuleInfo],
    ) -> Option<MemoryRegionInfo> {
        let start_low = Self::read_integer_field(memory, vad_layout, vad, "StartingVpn")?;
        let end_low = Self::read_integer_field(memory, vad_layout, vad, "EndingVpn")?;
        let start_high =
            Self::read_integer_field(memory, vad_layout, vad, "StartingVpnHigh").unwrap_or(0);
        let end_high =
            Self::read_integer_field(memory, vad_layout, vad, "EndingVpnHigh").unwrap_or(0);
        let start_vpn = start_low | (start_high << 32);
        let end_vpn = end_low | (end_high << 32);
        let start = VirtAddr(start_vpn.checked_shl(12)?);
        let end = VirtAddr(end_vpn.checked_add(1)?.checked_shl(12)?);

        let flags = Self::vad_flags_base_offset(vad_layout)
            .and_then(|offset| memory.read::<u32>(vad + offset).ok())
            .map(u64::from);
        let protection = flags
            .zip(flags_layout)
            .and_then(|(raw, layout)| Self::bitfield_value(layout, "Protection", raw))
            .map(VadProtection::from_raw);
        let vad_type = flags
            .zip(flags_layout)
            .and_then(|(raw, layout)| Self::bitfield_value(layout, "VadType", raw))
            .map(VadType::from_raw);
        let private_memory = flags.zip(flags_layout).and_then(|(raw, layout)| {
            Self::bitfield_value(layout, "PrivateMemory", raw).map(|v| v != 0)
        });
        let commit_charge = flags
            .zip(flags_layout)
            .and_then(|(raw, layout)| Self::bitfield_value(layout, "CommitCharge", raw));
        let details = modules
            .iter()
            .find(|module| {
                module.base_address.0 >= start.0 && module.base_address.0 < end.0
                    || start.0 >= module.base_address.0 && start.0 < module.end_address().0
            })
            .map(|module| module.name.clone());

        Some(MemoryRegionInfo {
            node_address,
            level,
            start,
            end,
            protection,
            vad_type,
            private_memory,
            commit_charge,
            details,
        })
    }
}
