use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::types::PyBytes;

use super::command::admit;
use super::context::Context;
use super::handle::Owner;
use super::module::Device;
use super::thread::Frame;
use super::{err, raise};
use crate::session::Session;
use crate::session::effects::Effects;
use crate::target::etw::parse_guid;
use crate::trapframe::{KtrapFrame, read_ktrap_frame};
use crate::types::VirtAddr;
use crate::view::record::{ToView, Typed};

/// System-wide reports and helpers that decode an object at an address
/// (`dbg.inspect`). The results are typed `Record`s. On a user-mode
/// minidump, which has no kernel, only `version`, `time`, `triage`,
/// `bugcheck`, `exception_record`, and `context_record` apply; the others
/// raise `NtoseyeError`.
#[pyclass(module = "ntoseye")]
pub struct Inspect {
    pub owner: Owner,
}

impl Inspect {
    pub fn new(owner: Owner) -> Inspect {
        Inspect { owner }
    }

    /// Run `build` in the session and return its result as the SDK does. It
    /// reads the kernel, so a user-mode minidump refuses it.
    fn typed<'py, T: ToView<M> + Send, M>(
        &self,
        py: Python<'py>,
        build: impl FnOnce(&mut Session) -> PyResult<T> + Send,
    ) -> PyResult<Typed<'py, T, M>> {
        self.typed_any(py, |session| {
            admit(session, &Effects::KERNEL, "Inspect")?;
            build(session)
        })
    }

    /// [`Self::typed`] for a report that applies to every target.
    fn typed_any<'py, T: ToView<M> + Send, M>(
        &self,
        py: Python<'py>,
        build: impl FnOnce(&mut Session) -> PyResult<T> + Send,
    ) -> PyResult<Typed<'py, T, M>> {
        let value = self.owner.with_in(py, &Context::default(), build)?;
        Typed::new(py, value)
    }
}

#[pymethods]
impl Inspect {
    fn __repr__(&self) -> String {
        "<Inspect namespace>".to_string()
    }

    /// Decode a `_KTRAP_FRAME` at `address` (`.trap`).
    fn trap_frame<'py>(&self, py: Python<'py>, address: u64) -> PyResult<Typed<'py, KtrapFrame>> {
        self.typed(py, |session| {
            read_ktrap_frame(&session.target, VirtAddr(address)).map_err(err)
        })
    }

    /// Return a handle for the `_DEVICE_OBJECT` at `address` (`!devobj`).
    fn device(&self, py: Python<'_>, address: u64) -> PyResult<Device> {
        let owner = self.owner.derive(py);
        Ok(Device::new(owner, address))
    }

    /// Decode a CONTEXT record and return its register set as a `Frame` (`.cxr`).
    fn context_record(&self, py: Python<'_>, address: u64) -> PyResult<Frame> {
        let registers = self.owner.with_in(py, &Context::default(), |session| {
            session.read_context_record(VirtAddr(address)).map_err(err)
        })?;
        let ip = registers
            .get("rip")
            .or_else(|| registers.get("pc"))
            .copied()
            .unwrap_or(0);
        let sp = registers
            .get("rsp")
            .or_else(|| registers.get("sp"))
            .copied()
            .unwrap_or(0);
        Frame::new(
            py,
            self.owner.derive(py),
            None,
            0,
            ip,
            sp,
            None,
            None,
            registers,
        )
    }

    /// Read the data of the crash dump's block tagged `tag` (`.enumtag`), a
    /// GUID with or without braces, such as the one a driver passes to
    /// `KeRegisterBugCheckReasonCallback` for its secondary dump data.
    /// `target.dump.tagged_blocks` lists the blocks.
    fn read_tagged<'py>(&self, py: Python<'py>, tag: &str) -> PyResult<Bound<'py, PyBytes>> {
        let Some(guid) = parse_guid(tag) else {
            return Err(raise(format!("{tag:?} is not a GUID")));
        };
        let data = self.owner.with_in(py, &Context::default(), |session| {
            admit(session, &Effects::KERNEL, "Inspect.read_tagged")?;
            let dump = session
                .target
                .phys
                .dmp_info()
                .ok_or_else(|| raise("tagged data is in crash dumps; this target is live"))?;
            dump.tagged_blocks
                .iter()
                .find(|block| block.tag == guid)
                .map(|block| Arc::clone(&block.data))
                .ok_or_else(|| raise(format!("the dump has no block tagged {tag}")))
        })?;
        Ok(PyBytes::new(py, &data))
    }
}
