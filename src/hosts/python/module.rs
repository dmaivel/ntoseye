//! Loaded modules (`dbg.modules`, `proc.modules`) and driver objects
//! (`dbg.drivers`): sections, exports, mapped images, and symbol status.

use ntoseye_macros::{collection, handle, record};
use pelite::PeView;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use super::command::Bind;
use super::context::{Context, Space};
use super::handle::Owner;
use super::record::Typed;
use super::{MAX_READ_LEN, err, raise, symbol_not_found};
use crate::base::error::Error;
use crate::base::memory::PAGE_SIZE;
use crate::base::types::{Dtb, VirtAddr};
use crate::nt::guest::{ModuleInfo, ProcessInfo};
use crate::nt::pe;
use crate::nt::pe::ModuleExportInfo;
use crate::nt::pe::headers::Section;
use crate::nt::symbols::{ImageSource, ModuleListing, ModuleSymbols};
use crate::nt::target::image::ImageRef;
use crate::nt::target::object::{DriverDeviceLink, DriverObjectInfo};
use crate::session::effects::{Effects, TargetScope};

/// A collection of modules: `dbg.modules` (kernel), `proc.modules` (loader
/// lists), or `dbg.secure_kernel.modules` (secure kernel), keyed by short
/// name or by a `ModuleInfo` record (`stop.module`).
#[pyclass(module = "ntoseye")]
pub struct Modules {
    pub owner: Owner,
    space: Space,
}

impl Modules {
    pub fn kernel(owner: Owner) -> Modules {
        Modules {
            owner,
            space: Space::Kernel,
        }
    }

    /// `owner` should be the process handle's (stamped) owner.
    pub fn process(owner: Owner, info: ProcessInfo) -> Modules {
        Modules {
            owner,
            space: Space::Process(info),
        }
    }

    /// The secure kernel's modules, registered under its system `root`.
    /// `owner` should be the secure-kernel handle's (stamped) owner.
    pub fn secure(owner: Owner, root: Dtb) -> Modules {
        Modules {
            owner,
            space: Space::Secure(root),
        }
    }
}

#[collection(records)]
impl Modules {
    fn enumerate(&self, py: Python<'_>) -> PyResult<Vec<Module>> {
        let kernel = matches!(self.space, Space::Kernel);
        let modules = self.owner.with_in(py, &self.space.context(), |session| {
            // A user-mode minidump's one address space lists the dump's
            // modules, as `lm` does.
            if kernel && session.target.user_dump().is_none() {
                session.target.kernel_modules_with_versions()
            } else {
                // The scope's own list: the process's loader lists, or the
                // secure kernel's.
                session.target.modules_with_versions()
            }
            .map_err(err)
        })?;
        let owner = self.owner.derive(py);
        Ok(modules
            .into_iter()
            .map(|info| Module::new(owner.clone_ref(py), self.space.clone(), info))
            .collect())
    }

    /// The module with a short name, ignoring case (`"nt"` is ntoskrnl),
    /// or the module loaded at the base of a `ModuleInfo` record
    /// (`stop.module`).
    fn lookup(&self, py: Python<'_>, name: &String) -> PyResult<Option<Module>> {
        Ok(self.enumerate(py)?.into_iter().find(|module| {
            module.info.short_name.eq_ignore_ascii_case(name)
                || module.info.name.eq_ignore_ascii_case(name)
        }))
    }

    /// The module that contains `address`, or `None` if no module contains
    /// it.
    #[collection(at)]
    fn holds(module: &Module, address: u64) -> bool {
        module.info.contains_address(VirtAddr(address))
    }
}

/// One loaded image in the kernel address space or in a process address space.
#[handle(
    record = ModuleInfo,
    key = base_address,
    identity = Module::identity,
    context = self.space.context(),
    refuse = self.refuse_kernel(operation, effects),
    impl
)]
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

    pub fn context(&self) -> Context {
        self.space.context()
    }

    /// The module's identity: its base, in its process's address space
    /// (`None` for the kernel's).
    fn identity(&self) -> (Option<VirtAddr>, VirtAddr) {
        let process = match &self.space {
            Space::Process(info) => Some(info.eprocess),
            Space::Kernel | Space::Physical | Space::Secure(_) | Space::Root(_) => None,
        };
        (process, self.info.base_address)
    }

    /// A kernel command reads NT's state about the module, which a
    /// secure-kernel module does not have (Driver Verifier never tracks one).
    fn refuse_kernel(&self, operation: &str, effects: &Effects) -> PyResult<()> {
        if effects.target == TargetScope::Kernel {
            self.space.require_nt(operation)?;
        }
        Ok(())
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
                session.target.read_masked(base, &mut image).map_err(err)?;
                return Ok(image);
            }
            for (index, page) in image.chunks_mut(PAGE_SIZE).enumerate() {
                let address = VirtAddr(base.0 + (index * PAGE_SIZE) as u64);
                if session.target.read_masked(address, page).is_err() {
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
            let headers = pe::read_pe_header_page(base, &memory).map_err(err)?;
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
                        rva: header.VirtualAddress,
                        size: header.VirtualSize.max(header.SizeOfRawData),
                        permissions,
                    }
                })
                .collect())
        })
    }
}

#[handle]
impl Module {
    /// The PE sections and their mapped permissions.
    #[getter]
    fn sections<'py>(&self, py: Python<'py>) -> PyResult<Typed<'py, Vec<Section>>> {
        Typed::new(py, self.section_data(py)?)
    }

    /// The exports from the mapped PE export directory.
    #[getter]
    fn exports<'py>(&self, py: Python<'py>) -> PyResult<Typed<'py, Vec<ModuleExportInfo>>> {
        let base = self.info.base_address;
        let exports = self.owner.with_in(py, &self.context(), |session| {
            let dtb = self.space.dtb(&session.target)?;
            session.target.module_exports(dtb, base).map_err(err)
        })?;
        Typed::new(py, exports)
    }

    /// The symbol status and PDB identity of the module (`lmv`).
    #[getter]
    fn symbols<'py>(&self, py: Python<'py>) -> PyResult<Typed<'py, ModuleSymbols>> {
        let base = self.info.base_address;
        let symbols = self.owner.with_in(py, &self.context(), |session| {
            let dtb = self.space.dtb(&session.target)?;
            Ok(session.target.symbols.module_symbols(dtb, base))
        })?;
        Typed::new(py, symbols)
    }

    /// The mapped image in memory layout, for pefile/LIEF. A page that is not
    /// readable raises `MemoryAccessError`, unless `zero_fill` is set, which
    /// fills such pages with zeros (for example, a kernel's discarded INIT
    /// section).
    #[pyo3(signature = (*, zero_fill=false))]
    fn image<'py>(&self, py: Python<'py>, zero_fill: bool) -> PyResult<Bound<'py, PyBytes>> {
        let bytes = self.image_bytes(py, zero_fill)?;
        Ok(PyBytes::new(py, &bytes))
    }

    /// Get the address of a symbol in this module.
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

    /// The symbol status, load diagnostics, and PDB identity (`lmv`).
    fn inspect<'py>(&self, py: Python<'py>) -> PyResult<Typed<'py, ModuleDetail>> {
        let info = self.info.clone();
        let process = matches!(self.space, Space::Process(_));
        let view = self.owner.with_in(py, &self.context(), |session| {
            let dtb = self.space.dtb(&session.target)?;
            if process {
                let detail = session.target.loader_modules(None).map_err(err)?;
                let module = detail
                    .modules
                    .into_iter()
                    .find(|module| module.base_address == info.base_address)
                    .ok_or_else(|| {
                        err(Error::DebugInfo(format!(
                            "module {} is no longer in the loader list",
                            info.name
                        )))
                    })?;
                Ok(ModuleDetail::Process(module))
            } else {
                Ok(ModuleDetail::Kernel(ModuleListing {
                    symbols: session
                        .target
                        .symbols
                        .module_symbols(dtb, info.base_address),
                    module: info,
                }))
            }
        })?;
        Typed::new(py, view)
    }

    fn __repr__(&self) -> String {
        format!(
            "Module(name={:?}, base={:#x}, size={:#x})",
            self.info.name, self.info.base_address.0, self.info.size
        )
    }
}

/// The driver objects in the `Driver` directory of the object manager, keyed
/// by name (`dbg.drivers`).
#[pyclass(module = "ntoseye")]
pub struct Drivers {
    pub owner: Owner,
}

impl Drivers {
    pub fn new(owner: Owner) -> Drivers {
        Drivers { owner }
    }
}

#[collection(records)]
impl Drivers {
    fn enumerate(&self, py: Python<'_>) -> PyResult<Vec<Driver>> {
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

    /// The driver object with a name, with or without its directory prefix,
    /// or the one a `DriverObjectInfo` record describes.
    fn lookup(&self, py: Python<'_>, name: &String) -> PyResult<Option<Driver>> {
        let query = name.strip_prefix("\\Driver\\").unwrap_or(name);
        Ok(self.enumerate(py)?.into_iter().find(|driver| {
            let name = &driver.info.name;
            name.eq_ignore_ascii_case(query)
                || name
                    .strip_prefix("\\Driver\\")
                    .is_some_and(|driver| driver.eq_ignore_ascii_case(query))
        }))
    }

    /// The driver object at `address`, or the one whose image contains it.
    #[collection(at)]
    fn holds(driver: &Driver, address: u64) -> bool {
        let info = &driver.info;
        info.object.0 == address
            || (address >= info.driver_start.0
                && address < info.driver_start.0.saturating_add(info.driver_size))
    }
}

/// One `_DRIVER_OBJECT` and the device objects that it created.
#[handle(record = DriverObjectInfo, key = object, impl)]
pub struct Driver {
    pub owner: Owner,
    pub info: DriverObjectInfo,
}

#[handle]
impl Driver {
    /// The device objects that this driver created.
    #[getter]
    fn devices(&self, py: Python<'_>) -> PyResult<Vec<Device>> {
        let devices = self.owner.with(py, |session| {
            session
                .target
                .inspect_driver_object(self.info.object)
                .map(|detail| detail.devices)
                .map_err(err)
        })?;
        let owner = self.owner.derive(py);
        Ok(devices
            .into_iter()
            .map(|info| Device {
                owner: owner.clone_ref(py),
                info,
            })
            .collect())
    }

    fn __repr__(&self) -> String {
        format!(
            "Driver(name={:?}, object={:#x})",
            self.info.name, self.info.object.0
        )
    }
}

/// One `_DEVICE_OBJECT`, on its driver's device chain.
#[handle(record = DriverDeviceLink, key = device, impl)]
pub struct Device {
    pub owner: Owner,
    pub info: DriverDeviceLink,
}

#[handle]
impl Device {
    fn __repr__(&self) -> String {
        format!("Device(address={:#x})", self.info.device.0)
    }
}

/// A module as `Module.inspect()` decodes it: a kernel module with its
/// symbols' state, or a process module from its loader list.
#[record]
pub enum ModuleDetail {
    Kernel(ModuleListing),
    Process(crate::nt::target::usermode::LoaderModule),
}

/// A module binds its short name (`!chkimg nt`).
impl Bind<String> for Module {
    fn bind(&self) -> String {
        self.info.short_name.clone()
    }
}

/// A module binds its image (`!dh`, `!lmi`): its base and loader entry, in
/// the address space it was listed in. The kernel's is left to the command,
/// which names it for the session.
impl Bind<ImageRef> for Module {
    fn bind(&self) -> ImageRef {
        ImageRef {
            base: self.info.base_address,
            module: Some(self.info.clone()),
            dtb: match &self.space {
                Space::Process(process) => Some(process.dtb),
                Space::Secure(root) | Space::Root(root) => Some(*root),
                Space::Kernel | Space::Physical => None,
            },
        }
    }
}

/// A module binds its image for `.fetchimage`.
impl Bind<ImageSource> for Module {
    fn bind(&self) -> ImageSource {
        ImageSource::Module(self.info.name.clone())
    }
}

/// `!drvobj` inspects the driver object.
impl Bind<VirtAddr> for Driver {
    fn bind(&self) -> VirtAddr {
        self.info.object
    }
}

/// `!devobj` inspects the device object.
impl Bind<VirtAddr> for Device {
    fn bind(&self) -> VirtAddr {
        self.info.device
    }
}
