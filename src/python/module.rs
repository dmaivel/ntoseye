//! Loaded modules (`dbg.modules`, `proc.modules`) and driver objects
//! (`dbg.drivers`): sections, exports, mapped images, and symbol status.

use pyo3::exceptions::PyKeyError;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes, PyDict};

use super::context::{Context, Space};
use super::handle::Owner;
use super::iter::{DriverIterator, ModuleIterator};
use super::record::{PlainDict, Record};
use super::{MAX_READ_LEN, err, raise, symbol_not_found, view_dict, view_record};
use crate::error::Error;
use crate::guest::{self, ModuleInfo, ProcessInfo};
use crate::memory::PAGE_SIZE;
use crate::target::object::DriverObjectInfo;
use crate::types::VirtAddr;
use crate::view::{self, View};
use pelite::PeView;

/// A module collection: `dbg.modules` (kernel) or `proc.modules` (loader lists).
#[pyclass(module = "ntoseye")]
pub struct Modules {
    pub owner: Owner,
    pub process: Option<ProcessInfo>,
}

impl Modules {
    pub fn kernel(owner: Owner) -> Modules {
        Modules {
            owner,
            process: None,
        }
    }

    /// `owner` should be the process handle's (stamped) owner.
    pub fn process(owner: Owner, info: ProcessInfo) -> Modules {
        Modules {
            owner,
            process: Some(info),
        }
    }

    fn space(&self) -> Space {
        self.process.clone().map_or(Space::Kernel, Space::Process)
    }

    fn infos(&self, py: Python<'_>) -> PyResult<Vec<ModuleInfo>> {
        let process = self.process.is_some();
        self.owner.with_in(py, &self.space().context(), |session| {
            if process {
                session.target.modules_with_versions()
            } else {
                session.target.kernel_modules_with_versions()
            }
            .map_err(err)
        })
    }

    fn handles(&self, py: Python<'_>) -> PyResult<Vec<Module>> {
        let modules = self.infos(py)?;
        let (owner, space) = (self.owner.derive(py), self.space());
        Ok(modules
            .into_iter()
            .map(|info| Module::new(owner.clone_ref(py), space.clone(), info))
            .collect())
    }

    fn handle(&self, py: Python<'_>, found: Option<ModuleInfo>) -> PyResult<Option<Module>> {
        Ok(found.map(|info| Module::new(self.owner.derive(py), self.space(), info)))
    }
}

/// One loaded image in the kernel or a process address space.
#[pyclass(module = "ntoseye")]
pub struct Module {
    pub owner: Owner,
    pub space: Space,
    pub info: ModuleInfo,
}

impl Module {
    /// `owner` should be stamped (use `Owner::derive`).
    pub fn new(owner: Owner, space: Space, info: ModuleInfo) -> Module {
        Module { owner, space, info }
    }

    fn context(&self) -> Context {
        self.space.context()
    }

    /// The owning process's `_EPROCESS`, `None` for a kernel module.
    fn process_key(&self) -> Option<VirtAddr> {
        match &self.space {
            Space::Process(info) => Some(info.eprocess_va),
            Space::Kernel | Space::Physical => None,
        }
    }

    /// The mapped image in memory layout, breakpoint bytes masked back to
    /// the guest's code. `zero_fill` zeroes pages that do not read (a
    /// driver's discarded INIT section, paged-out pages) instead of raising.
    fn image_bytes(&self, py: Python<'_>, zero_fill: bool) -> PyResult<Vec<u8>> {
        let size = self.info.size as usize;
        if size > MAX_READ_LEN {
            return Err(raise(format!(
                "module image is {size:#x} bytes, above the {MAX_READ_LEN:#x}-byte read limit"
            )));
        }
        let base = self.info.base_address;
        self.owner.with_in(py, &self.context(), |session| {
            let mut image = vec![0u8; size];
            if !zero_fill {
                session.read_masked(base, &mut image).map_err(err)?;
                return Ok(image);
            }
            for (index, page) in image.chunks_mut(PAGE_SIZE).enumerate() {
                let address = VirtAddr(base.0 + (index * PAGE_SIZE) as u64);
                if session.read_masked(address, page).is_err() {
                    page.fill(0);
                }
            }
            Ok(image)
        })
    }

    fn section_data(&self, py: Python<'_>) -> PyResult<Vec<Section>> {
        let base = self.info.base_address;
        self.owner.with_in(py, &self.context(), |session| {
            let dtb = self.space.dtb(&session.target)?;
            let memory = session.target.address_space(dtb);
            let headers = guest::read_pe_header_page(base, &memory).map_err(err)?;
            let view = PeView::from_bytes(&headers).map_err(|error| err(Error::from(error)))?;
            Ok(view
                .section_headers()
                .iter()
                .map(|header| {
                    let characteristics = header.Characteristics;
                    let mut permissions = String::with_capacity(3);
                    permissions.push(if characteristics & 0x4000_0000 != 0 {
                        'r'
                    } else {
                        '-'
                    });
                    permissions.push(if characteristics & 0x8000_0000 != 0 {
                        'w'
                    } else {
                        '-'
                    });
                    permissions.push(if characteristics & 0x2000_0000 != 0 {
                        'x'
                    } else {
                        '-'
                    });
                    Section {
                        name: header.name().map(str::to_owned).unwrap_or_default(),
                        rva: u64::from(header.VirtualAddress),
                        size: u64::from(header.VirtualSize.max(header.SizeOfRawData)),
                        permissions,
                    }
                })
                .collect())
        })
    }
}

#[pymethods]
impl Module {
    /// Base address of the loaded image.
    #[getter]
    fn base(&self, py: Python<'_>) -> PyResult<u64> {
        self.owner.check(py)?;
        Ok(self.info.base_address.0)
    }

    /// Size of the mapped image.
    #[getter]
    fn size(&self, py: Python<'_>) -> PyResult<u32> {
        self.owner.check(py)?;
        Ok(self.info.size)
    }

    /// Image name.
    #[getter]
    fn name(&self, py: Python<'_>) -> PyResult<String> {
        self.owner.check(py)?;
        Ok(self.info.name.clone())
    }

    /// Full image path, when the loader recorded one.
    #[getter]
    fn path(&self, py: Python<'_>) -> PyResult<Option<String>> {
        self.owner.check(py)?;
        Ok(self.info.path.clone())
    }

    /// PE timestamp, when present in the loader record.
    #[getter]
    fn timestamp(&self, py: Python<'_>) -> PyResult<Option<u32>> {
        self.owner.check(py)?;
        Ok(self.info.time_date_stamp)
    }

    /// File version from the image's version resource.
    #[getter]
    fn file_version(&self, py: Python<'_>) -> PyResult<Option<String>> {
        self.owner.check(py)?;
        Ok(self.info.file_version.clone())
    }

    /// Product version from the image's version resource.
    #[getter]
    fn product_version(&self, py: Python<'_>) -> PyResult<Option<String>> {
        self.owner.check(py)?;
        Ok(self.info.product_version.clone())
    }

    /// PE sections and their mapped permissions.
    #[getter]
    fn sections(&self, py: Python<'_>) -> PyResult<Vec<Section>> {
        self.section_data(py)
    }

    /// Exports from the mapped PE export directory.
    #[getter]
    fn exports(&self, py: Python<'_>) -> PyResult<Vec<Export>> {
        let base = self.info.base_address;
        let exports = self.owner.with_in(py, &self.context(), |session| {
            let dtb = self.space.dtb(&session.target)?;
            session.target.module_exports(dtb, base).map_err(err)
        })?;
        Ok(exports
            .into_iter()
            .map(|export| Export {
                name: export.name,
                ordinal: export.ordinal,
                address: export.address.map(|address| address.0),
                forwarder: export.forwarder,
            })
            .collect())
    }

    /// Module symbol and PDB identity (`lmv`).
    #[getter]
    fn symbols<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, Record>> {
        let info = self.info.clone();
        let view = self.owner.with_in(py, &self.context(), |session| {
            let dtb = self.space.dtb(&session.target)?;
            Ok(view::module::module_symbols(&session.target, &info, dtb))
        })?;
        view_record(py, &view)
    }

    /// The mapped image in memory layout, for pefile/LIEF. Raises
    /// `MemoryAccessError` on an unreadable page unless `zero_fill` is set,
    /// which zeroes such pages instead (a kernel's discarded INIT section).
    #[pyo3(signature = (zero_fill=false))]
    fn image<'py>(&self, py: Python<'py>, zero_fill: bool) -> PyResult<Bound<'py, PyBytes>> {
        let bytes = self.image_bytes(py, zero_fill)?;
        Ok(PyBytes::new(py, &bytes))
    }

    /// Resolve a symbol from this module to its address.
    fn __getitem__(&self, py: Python<'_>, name: &str) -> PyResult<u64> {
        let query = format!("{}!{name}", self.info.short_name);
        let address = self.owner.with_in(py, &self.context(), |session| {
            session
                .target
                .symbols
                .find_symbol_across_modules(self.space.dtb(&session.target)?, &query)
                .map(|address| address.map(|address| address.0))
                .map_err(err)
        })?;
        address.ok_or_else(|| symbol_not_found(query))
    }

    /// Symbol status, load diagnostics and PDB identity (`lmv`).
    fn inspect<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, Record>> {
        let info = self.info.clone();
        let process = matches!(self.space, Space::Process(_));
        let view = self.owner.with_in(py, &self.context(), |session| {
            let dtb = self.space.dtb(&session.target)?;
            if process {
                let detail = session.target.loader_modules(None).map_err(err)?;
                let module = detail
                    .modules
                    .iter()
                    .find(|module| module.base_address == info.base_address)
                    .ok_or_else(|| {
                        err(Error::DebugInfo(format!(
                            "module {} is no longer in the loader list",
                            info.name
                        )))
                    })?;
                Ok(view::usermode::loader_module(module))
            } else {
                let mut fields = match view::module::module(&info) {
                    View::Object(fields) => fields,
                    _ => unreachable!(),
                };
                fields.push((
                    "symbols",
                    view::module::module_symbols(&session.target, &info, dtb),
                ));
                Ok(View::Object(fields))
            }
        })?;
        view_record(py, &view)
    }

    /// Select, fetch, and index symbols for this module (`ld`, `.reload`).
    fn reload_symbols<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, Record>> {
        let name = self.info.short_name.clone();
        let report = self.owner.with_in(py, &self.context(), |session| {
            session
                .target
                .reload_module_symbols(Some(&name))
                .map_err(err)
        })?;
        view_record(py, &view::module::module_symbol_report(&report))
    }

    /// Fetch the matching image from the symbol server cache (`.fetchimage`).
    fn fetch_image(&self, py: Python<'_>) -> PyResult<String> {
        let name = self.info.name.clone();
        let path = self.owner.with_in(py, &self.context(), |session| {
            session.target.fetch_module_image(&name).map_err(err)
        })?;
        Ok(path.to_string_lossy().into_owned())
    }

    /// Compare executable sections against the cached image (`!chkimg`).
    #[pyo3(signature = (include_diffs=false))]
    fn check_image<'py>(
        &self,
        py: Python<'py>,
        include_diffs: bool,
    ) -> PyResult<Bound<'py, Record>> {
        let name = self.info.short_name.clone();
        let detail = self.owner.with_in(py, &self.context(), |session| {
            session
                .target
                .check_image(&name, include_diffs)
                .map_err(err)
        })?;
        view_record(py, &view::usermode::image_check(&detail))
    }

    /// Return verifier data for this driver module.
    fn verifier<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, Record>> {
        let name = self.info.short_name.clone();
        let detail = self.owner.with_in(py, &self.context(), |session| {
            session.target.verifier_driver(&name).map_err(err)
        })?;
        view_record(py, &view::meta::verifier_driver(&detail))
    }

    /// The module as a plain `dict`, the shape MCP renders.
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<PlainDict<'py>> {
        self.owner.check(py)?;
        view_dict(py, &view::module::module(&self.info))
    }

    fn __eq__(&self, other: &Bound<'_, PyAny>) -> bool {
        other.extract::<PyRef<'_, Module>>().is_ok_and(|other| {
            self.owner.same_debugger(&other.owner)
                && self.process_key() == other.process_key()
                && self.info.base_address == other.info.base_address
        })
    }

    fn __hash__(&self) -> isize {
        self.owner
            .identity_hash((self.process_key(), self.info.base_address))
    }

    fn __repr__(&self) -> String {
        format!(
            "Module(name={:?}, base={:#x}, size={:#x})",
            self.info.name, self.info.base_address.0, self.info.size
        )
    }
}

/// One PE section: its name, RVA, mapped size, and `rwx` permissions.
#[pyclass(frozen, get_all, module = "ntoseye")]
pub struct Section {
    /// The section name (`.text`).
    pub name: String,
    /// Its offset from the image base.
    pub rva: u64,
    /// Its mapped size.
    pub size: u64,
    /// Mapped permissions as `rwx`, `-` for a missing one.
    pub permissions: String,
}

#[pymethods]
impl Section {
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<PlainDict<'py>> {
        let out = PyDict::new(py);
        out.set_item("name", &self.name)?;
        out.set_item("rva", self.rva)?;
        out.set_item("size", self.size)?;
        out.set_item("permissions", &self.permissions)?;
        Ok(PlainDict(out))
    }

    fn __repr__(&self) -> String {
        format!(
            "Section(name={:?}, rva={:#x}, size={:#x}, permissions={:?})",
            self.name, self.rva, self.size, self.permissions
        )
    }
}

/// One PE export, by name or ordinal only; a forwarder has no address.
#[pyclass(frozen, get_all, module = "ntoseye")]
pub struct Export {
    /// The export name, `None` for an ordinal-only export.
    pub name: Option<String>,
    /// The export ordinal.
    pub ordinal: u32,
    /// The exported address, `None` for a forwarder.
    pub address: Option<u64>,
    /// The forwarding target (`OTHER.Function`), for a forwarder.
    pub forwarder: Option<String>,
}

#[pymethods]
impl Export {
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<PlainDict<'py>> {
        let out = PyDict::new(py);
        out.set_item("name", &self.name)?;
        out.set_item("ordinal", self.ordinal)?;
        out.set_item("address", self.address)?;
        out.set_item("forwarder", &self.forwarder)?;
        Ok(PlainDict(out))
    }

    fn __repr__(&self) -> String {
        format!(
            "Export(name={}, ordinal={}, address={}, forwarder={})",
            python_str(self.name.as_deref()),
            self.ordinal,
            self.address
                .map_or_else(|| "None".to_string(), |address| format!("{address:#x}")),
            python_str(self.forwarder.as_deref())
        )
    }
}

#[pymethods]
impl Modules {
    /// Look up a module by short name, case-insensitively (`"nt"` names ntoskrnl).
    fn get(&self, py: Python<'_>, name: &str) -> PyResult<Option<Module>> {
        let found = self
            .infos(py)?
            .into_iter()
            .find(|module| module_matches(module, name));
        self.handle(py, found)
    }

    /// The module containing `addr`, or `None` when no module contains it.
    fn at(&self, py: Python<'_>, addr: u64) -> PyResult<Option<Module>> {
        let found = self
            .infos(py)?
            .into_iter()
            .find(|module| module.contains_address(VirtAddr(addr)));
        self.handle(py, found)
    }

    /// How a process's loader lists ended (`termination` and
    /// `wow64_termination`, each `{kind, address, error}`), to tell a complete
    /// list from a corrupt or truncated one; `None` for kernel modules.
    #[getter]
    fn termination<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, Record>>> {
        let Some(process) = &self.process else {
            return Ok(None);
        };
        let detail = self
            .owner
            .with_in(py, &Context::process(process.clone()), |session| {
                session.target.loader_modules(None).map_err(err)
            })?;
        view_record(py, &view::usermode::loader_terminations(&detail)).map(Some)
    }

    fn __getitem__(&self, py: Python<'_>, name: &str) -> PyResult<Module> {
        self.get(py, name)?
            .ok_or_else(|| PyKeyError::new_err(name.to_string()))
    }

    fn __contains__(&self, py: Python<'_>, name: &str) -> PyResult<bool> {
        Ok(self.get(py, name)?.is_some())
    }

    fn __iter__(&self, py: Python<'_>) -> PyResult<ModuleIterator> {
        Ok(ModuleIterator::new(self.handles(py)?))
    }

    fn __len__(&self, py: Python<'_>) -> PyResult<usize> {
        Ok(self.infos(py)?.len())
    }
}

/// `value` as Python's `repr` shows an optional string.
fn python_str(value: Option<&str>) -> String {
    value.map_or_else(|| "None".to_string(), |value| format!("{value:?}"))
}

fn module_matches(module: &ModuleInfo, query: &str) -> bool {
    module.short_name.eq_ignore_ascii_case(query) || module.name.eq_ignore_ascii_case(query)
}

/// Driver objects from the object manager's `Driver` directory, keyed by
/// name (`dbg.drivers`).
#[pyclass(module = "ntoseye")]
pub struct Drivers {
    pub owner: Owner,
}

impl Drivers {
    pub fn new(owner: Owner) -> Drivers {
        Drivers { owner }
    }

    fn snapshot(&self, py: Python<'_>) -> PyResult<Vec<Driver>> {
        let infos = self.owner.with(py, |session| {
            session.target.enumerate_driver_objects().map_err(err)
        })?;
        let owner = self.owner.derive(py);
        Ok(infos
            .into_iter()
            .map(|info| Driver {
                owner: owner.clone_ref(py),
                info,
            })
            .collect())
    }
}

#[pymethods]
impl Drivers {
    /// Find a driver object by name, with or without its directory prefix.
    fn get(&self, py: Python<'_>, name: &str) -> PyResult<Option<Driver>> {
        Ok(self
            .snapshot(py)?
            .into_iter()
            .find(|driver| driver_name_matches(&driver.info.name, name)))
    }

    /// Find the driver object or image containing `addr`.
    fn at(&self, py: Python<'_>, addr: u64) -> PyResult<Option<Driver>> {
        Ok(self.snapshot(py)?.into_iter().find(|driver| {
            driver.info.object.0 == addr
                || (addr >= driver.info.driver_start.0
                    && addr
                        < driver
                            .info
                            .driver_start
                            .0
                            .saturating_add(driver.info.driver_size))
        }))
    }

    fn __getitem__(&self, py: Python<'_>, name: &str) -> PyResult<Driver> {
        self.get(py, name)?
            .ok_or_else(|| PyKeyError::new_err(name.to_string()))
    }

    fn __contains__(&self, py: Python<'_>, name: &str) -> PyResult<bool> {
        Ok(self.get(py, name)?.is_some())
    }

    fn __iter__(&self, py: Python<'_>) -> PyResult<DriverIterator> {
        Ok(DriverIterator::new(self.snapshot(py)?))
    }

    fn __len__(&self, py: Python<'_>) -> PyResult<usize> {
        Ok(self.snapshot(py)?.len())
    }
}

fn driver_name_matches(name: &str, query: &str) -> bool {
    let query = query.strip_prefix("\\Driver\\").unwrap_or(query);
    name.eq_ignore_ascii_case(query)
        || name
            .strip_prefix("\\Driver\\")
            .is_some_and(|driver| driver.eq_ignore_ascii_case(query))
}

/// One `_DRIVER_OBJECT`, with the device objects it created.
#[pyclass(module = "ntoseye")]
pub struct Driver {
    pub owner: Owner,
    pub info: DriverObjectInfo,
}

#[pymethods]
impl Driver {
    /// The driver object's name.
    #[getter]
    fn name(&self, py: Python<'_>) -> PyResult<String> {
        self.owner.check(py)?;
        Ok(self.info.name.clone())
    }

    /// The `_DRIVER_OBJECT` address.
    #[getter]
    fn object(&self, py: Python<'_>) -> PyResult<u64> {
        self.owner.check(py)?;
        Ok(self.info.object.0)
    }

    /// The driver image's base address.
    #[getter]
    fn start(&self, py: Python<'_>) -> PyResult<u64> {
        self.owner.check(py)?;
        Ok(self.info.driver_start.0)
    }

    /// The driver image's size.
    #[getter]
    fn size(&self, py: Python<'_>) -> PyResult<u64> {
        self.owner.check(py)?;
        Ok(self.info.driver_size)
    }

    /// The device objects this driver created.
    #[getter]
    fn devices(&self, py: Python<'_>) -> PyResult<Vec<Device>> {
        let owner = self.owner.derive(py);
        let addresses: Vec<u64> = self.owner.with(py, |session| {
            session
                .target
                .inspect_driver_object(self.info.object)
                .map(|detail| {
                    detail
                        .device_chain
                        .into_iter()
                        .map(|device| device.device.0)
                        .collect()
                })
                .map_err(err)
        })?;
        Ok(addresses
            .into_iter()
            .map(|address| Device::new(owner.clone_ref(py), address))
            .collect())
    }

    /// Inspect the `_DRIVER_OBJECT`, its devices, and dispatch table.
    fn inspect<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, Record>> {
        let view = self.owner.with(py, |session| {
            let detail = session
                .target
                .inspect_driver_object(self.info.object)
                .map_err(err)?;
            Ok(view::object::driver_object(&session.target, &detail))
        })?;
        view_record(py, &view)
    }

    /// The driver object as a plain `dict`, the shape MCP renders.
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<PlainDict<'py>> {
        self.owner.check(py)?;
        view_dict(py, &view::object::driver_object_info(&self.info))
    }

    fn __eq__(&self, other: &Bound<'_, PyAny>) -> bool {
        other.extract::<PyRef<'_, Driver>>().is_ok_and(|other| {
            self.owner.same_debugger(&other.owner) && self.info.object == other.info.object
        })
    }

    fn __hash__(&self) -> isize {
        self.owner.identity_hash(self.info.object)
    }

    fn __repr__(&self) -> String {
        format!(
            "Driver(name={:?}, object={:#x})",
            self.info.name, self.info.object.0
        )
    }
}

/// One `_DEVICE_OBJECT`.
#[pyclass(module = "ntoseye")]
pub struct Device {
    pub owner: Owner,
    pub address: u64,
}

impl Device {
    /// Store a device address under an already stamped owner.
    pub fn new(owner: Owner, address: u64) -> Device {
        Device { owner, address }
    }
}

#[pymethods]
impl Device {
    /// The `_DEVICE_OBJECT` address.
    #[getter]
    fn address(&self, py: Python<'_>) -> PyResult<u64> {
        self.owner.check(py)?;
        Ok(self.address)
    }

    /// Inspect this `_DEVICE_OBJECT` and its attachment stack.
    fn inspect<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, Record>> {
        let detail = self.owner.with(py, |session| {
            session
                .target
                .inspect_device_object(VirtAddr(self.address))
                .map_err(err)
        })?;
        view_record(py, &view::object::device_object(&detail))
    }

    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<PlainDict<'py>> {
        self.owner.check(py)?;
        let out = PyDict::new(py);
        out.set_item("address", self.address)?;
        Ok(PlainDict(out))
    }

    fn __eq__(&self, other: &Bound<'_, PyAny>) -> bool {
        other.extract::<PyRef<'_, Device>>().is_ok_and(|other| {
            self.owner.same_debugger(&other.owner) && self.address == other.address
        })
    }

    fn __hash__(&self) -> isize {
        self.owner.identity_hash(self.address)
    }

    fn __repr__(&self) -> String {
        format!("Device(address={:#x})", self.address)
    }
}
