//! The filter manager (`!fltkd.*`): the frames, minifilters, instances, and
//! volumes fltmgr keeps in `FltGlobals`, decoded with fltmgr's own PDB types.

use std::collections::HashMap;
use std::sync::Arc;

use super::{Target, bounded_list_walk};
use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::layout::{StructRef, TypeInfo, Types};
use crate::types::VirtAddr;

const MAX_FRAMES: usize = 16;
const MAX_FILTERS: usize = 256;
const MAX_VOLUMES: usize = 256;
const MAX_INSTANCES: usize = 256;

/// A filter manager frame and the filters or volumes attached to it.
#[derive(Debug, Clone)]
pub struct FltFrame<T> {
    pub address: VirtAddr,
    pub frame_id: u64,
    pub items: Vec<T>,
    /// Why the frame's list walk stopped short of its head.
    pub stopped: Option<String>,
}

/// The frames in `FltGlobals.FrameList`, each with its filters or volumes.
#[derive(Debug, Clone)]
pub struct FltFrames<T> {
    pub frames: Vec<FltFrame<T>>,
    pub stopped: Option<String>,
}

/// A registered minifilter (`_FLT_FILTER`).
#[derive(Debug, Clone)]
pub struct FltFilterDetail {
    pub address: VirtAddr,
    pub name: String,
    pub altitude: String,
    pub driver_object: VirtAddr,
    pub instances: Vec<FltInstanceDetail>,
    pub instances_stopped: Option<String>,
}

/// A minifilter attached to a volume (`_FLT_INSTANCE`).
#[derive(Debug, Clone)]
pub struct FltInstanceDetail {
    pub address: VirtAddr,
    pub name: String,
    pub altitude: String,
    pub filter: VirtAddr,
    pub filter_name: Option<String>,
    pub volume: VirtAddr,
    pub volume_name: Option<String>,
}

/// A volume the filter manager attached to (`_FLT_VOLUME`).
#[derive(Debug, Clone)]
pub struct FltVolumeDetail {
    pub address: VirtAddr,
    pub device_name: String,
    /// The `_FLT_FILESYSTEM_TYPE` name without its `FLT_FSTYPE_` prefix.
    pub file_system: Option<String>,
    pub instances: Vec<FltInstanceDetail>,
    pub instances_stopped: Option<String>,
}

/// fltmgr's layouts, resolved once per command.
struct FltTypes<'a> {
    types: Types<'a>,
    globals: Arc<TypeInfo>,
    frame: Arc<TypeInfo>,
    list_head: Arc<TypeInfo>,
    object: Arc<TypeInfo>,
    filter: Arc<TypeInfo>,
    instance: Arc<TypeInfo>,
    volume: Arc<TypeInfo>,
}

impl FltTypes<'_> {
    /// The `rList` head of the `_FLT_RESOURCE_LIST_HEAD` field `field` of
    /// `layout` at `base`.
    fn resource_list(&self, layout: &TypeInfo, base: VirtAddr, field: &str) -> Result<VirtAddr> {
        Ok(base + layout.field_offset(field)? + self.list_head.field_offset("rList")?)
    }

    /// Where `_FLT_OBJECT.PrimaryLink` sits in a record that begins with
    /// its `Base` object.
    fn primary_link(&self, layout: &TypeInfo) -> Result<u64> {
        Ok(layout.field_offset("Base")? + self.object.field_offset("PrimaryLink")?)
    }

    fn at(&self, layout: &Arc<TypeInfo>, address: VirtAddr) -> StructRef<'_> {
        self.types
            .struct_with_layout(Arc::clone(layout), address)
            .prefetch()
    }
}

/// Decode each record at `addresses`; a record that does not decode ends the
/// list there, and says why in place of the walk's own reason.
fn decode_all<T>(
    addresses: Vec<VirtAddr>,
    mut stopped: Option<String>,
    mut decode: impl FnMut(VirtAddr) -> Result<T>,
) -> (Vec<T>, Option<String>) {
    let mut items = Vec::with_capacity(addresses.len());
    for address in addresses {
        match decode(address) {
            Ok(item) => items.push(item),
            Err(error) => {
                stopped = Some(format!("{:#x}: {error}", address.0));
                break;
            }
        }
    }
    (items, stopped)
}

impl Target {
    fn flt_types(&self) -> Result<FltTypes<'_>> {
        let types = self.types_in(self.kernel_dtb());
        let layout = |name: &str| {
            types.layout(format!("fltmgr!{name}")).map_err(|_| {
                Error::DebugInfo(format!(
                    "fltmgr's symbols do not describe {name}; is fltmgr loaded with its PDB?"
                ))
            })
        };
        Ok(FltTypes {
            globals: layout("_GLOBALS")?,
            frame: layout("_FLTP_FRAME")?,
            list_head: layout("_FLT_RESOURCE_LIST_HEAD")?,
            object: layout("_FLT_OBJECT")?,
            filter: layout("_FLT_FILTER")?,
            instance: layout("_FLT_INSTANCE")?,
            volume: layout("_FLT_VOLUME")?,
            types,
        })
    }

    /// The records of the `_LIST_ENTRY` ring at `head` whose link sits
    /// `link_offset` into each, and why the walk stopped short, if it did.
    fn flt_list(
        &self,
        head: VirtAddr,
        link_offset: u64,
        limit: usize,
    ) -> (Vec<VirtAddr>, Option<String>) {
        let memory = self.kernel_address_space();
        let (links, termination) =
            bounded_list_walk(head, limit, |link| memory.read::<VirtAddr>(link));
        (
            links.into_iter().map(|link| link - link_offset).collect(),
            termination.diagnostic(),
        )
    }

    /// Walk `FltGlobals.FrameList`, decoding each frame's records with
    /// `records` (given the frame's address).
    fn flt_frames<T>(
        &self,
        flt: &FltTypes<'_>,
        mut records: impl FnMut(VirtAddr) -> Result<(Vec<T>, Option<String>)>,
    ) -> Result<FltFrames<T>> {
        let globals = self
            .symbols
            .find_symbol_across_modules(self.kernel_dtb(), "fltmgr!FltGlobals")?
            .ok_or_else(|| Error::SymbolNotFound("fltmgr!FltGlobals".into()))?;
        let head = flt.resource_list(&flt.globals, globals, "FrameList")?;
        let (frames, stopped) = self.flt_list(head, flt.frame.field_offset("Links")?, MAX_FRAMES);
        let (frames, stopped) = decode_all(frames, stopped, |address| {
            let frame_id = flt.at(&flt.frame, address).read_uint("FrameID")?;
            let (items, stopped) = records(address)?;
            Ok(FltFrame {
                address,
                frame_id,
                items,
                stopped,
            })
        });
        Ok(FltFrames { frames, stopped })
    }

    /// A `_FLT_VOLUME`'s device name.
    fn flt_volume_name(&self, flt: &FltTypes<'_>, volume: VirtAddr) -> Result<String> {
        flt.at(&flt.volume, volume).unicode_string("DeviceName")
    }

    /// The instances on the list at `head` linked through `link_offset`,
    /// naming each one's filter and volume. `volume_names` caches volumes
    /// across calls.
    fn flt_instances_at(
        &self,
        flt: &FltTypes<'_>,
        head: VirtAddr,
        link_offset: u64,
        volume_names: &mut HashMap<VirtAddr, Option<String>>,
    ) -> Result<(Vec<FltInstanceDetail>, Option<String>)> {
        let (addresses, stopped) = self.flt_list(head, link_offset, MAX_INSTANCES);
        Ok(decode_all(addresses, stopped, |address| {
            let instance = flt.at(&flt.instance, address);
            let filter = instance.read_pointer("Filter")?;
            let volume = instance.read_pointer("Volume")?;
            let volume_name = volume_names
                .entry(volume)
                .or_insert_with(|| self.flt_volume_name(flt, volume).ok())
                .clone();
            Ok(FltInstanceDetail {
                address,
                name: instance.unicode_string("Name")?,
                altitude: instance.unicode_string("Altitude")?,
                filter,
                filter_name: flt.at(&flt.filter, filter).unicode_string("Name").ok(),
                volume,
                volume_name,
            })
        }))
    }

    /// `!fltkd.filters`: each frame's registered minifilters with their
    /// instances.
    pub fn flt_filters(&self) -> Result<FltFrames<FltFilterDetail>> {
        let flt = self.flt_types()?;
        let filter_link = flt.primary_link(&flt.filter)?;
        let instance_link = flt.instance.field_offset("FilterLink")?;
        let mut volume_names = HashMap::new();
        self.flt_frames(&flt, |frame| {
            let head = flt.resource_list(&flt.frame, frame, "RegisteredFilters")?;
            let (addresses, stopped) = self.flt_list(head, filter_link, MAX_FILTERS);
            Ok(decode_all(addresses, stopped, |address| {
                let filter = flt.at(&flt.filter, address);
                let (instances, instances_stopped) = self.flt_instances_at(
                    &flt,
                    flt.resource_list(&flt.filter, address, "InstanceList")?,
                    instance_link,
                    &mut volume_names,
                )?;
                Ok(FltFilterDetail {
                    address,
                    name: filter.unicode_string("Name")?,
                    altitude: filter.unicode_string("DefaultAltitude")?,
                    driver_object: filter.read_pointer("DriverObject")?,
                    instances,
                    instances_stopped,
                })
            }))
        })
    }

    /// `!fltkd.instances [filter]`: every minifilter instance, or those of
    /// the filter named `filter` (its name, case-insensitively, or its
    /// `_FLT_FILTER` address).
    pub fn flt_instances(
        &self,
        filter: Option<&str>,
        eval: impl Fn(&str) -> Result<VirtAddr>,
    ) -> Result<FltFrames<FltInstanceDetail>> {
        let filters = self.flt_filters()?;
        let address = filter.and_then(|text| eval(text).ok());
        let selected = |detail: &FltFilterDetail| {
            filter.is_none_or(|text| {
                detail.name.eq_ignore_ascii_case(text) || address == Some(detail.address)
            })
        };
        if filter.is_some()
            && !filters
                .frames
                .iter()
                .any(|frame| frame.items.iter().any(selected))
        {
            return Err(Error::InvalidArgument(format!(
                "no registered minifilter is '{}'",
                filter.unwrap_or_default()
            )));
        }
        Ok(FltFrames {
            frames: filters
                .frames
                .into_iter()
                .map(|frame| {
                    let mut stopped = frame.stopped.into_iter().collect::<Vec<_>>();
                    let mut items = Vec::new();
                    for filter in frame.items.into_iter().filter(selected) {
                        if let Some(reason) = filter.instances_stopped {
                            stopped.push(format!("{}: {reason}", filter.name));
                        }
                        items.extend(filter.instances);
                    }
                    FltFrame {
                        address: frame.address,
                        frame_id: frame.frame_id,
                        items,
                        stopped: (!stopped.is_empty()).then(|| stopped.join("; ")),
                    }
                })
                .collect(),
            stopped: filters.stopped,
        })
    }

    /// `!fltkd.volumes`: each frame's attached volumes with the instances on
    /// them.
    pub fn flt_volumes(&self) -> Result<FltFrames<FltVolumeDetail>> {
        let flt = self.flt_types()?;
        let volume_link = flt.primary_link(&flt.volume)?;
        let instance_link = flt.primary_link(&flt.instance)?;
        let file_systems = self
            .symbols
            .find_enum_across_modules(self.kernel_dtb(), "fltmgr!_FLT_FILESYSTEM_TYPE")
            .unwrap_or_default();
        let mut volume_names = HashMap::new();
        self.flt_frames(&flt, |frame| {
            let head = flt.resource_list(&flt.frame, frame, "AttachedVolumes")?;
            let (addresses, stopped) = self.flt_list(head, volume_link, MAX_VOLUMES);
            Ok(decode_all(addresses, stopped, |address| {
                let volume = flt.at(&flt.volume, address);
                let kind = volume.read_uint("FileSystemType")?;
                let (instances, instances_stopped) = self.flt_instances_at(
                    &flt,
                    flt.resource_list(&flt.volume, address, "InstanceList")?,
                    instance_link,
                    &mut volume_names,
                )?;
                Ok(FltVolumeDetail {
                    address,
                    device_name: volume.unicode_string("DeviceName")?,
                    file_system: file_systems
                        .iter()
                        .find(|(_, value)| *value as u64 == kind)
                        .map(|(name, _)| {
                            name.strip_prefix("FLT_FSTYPE_").unwrap_or(name).to_string()
                        }),
                    instances,
                    instances_stopped,
                })
            }))
        })
    }
}
