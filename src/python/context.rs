//! Address-space and execution scoping for SDK handles. A handle never relies
//! on the session's current selection: it names its own [`Context`] and runs
//! its work through [`in_context`], which swaps the user's selection out and
//! back so REPL state (`.process`, `.thread`, `.frame`) is left untouched.

use pyo3::prelude::*;

use super::{err, raise};
use crate::guest::ProcessInfo;
use crate::session::Session;
use crate::target::{Target, ThreadInfo};
use crate::types::Dtb;

/// The address space a memory/symbol/type handle reads through.
#[derive(Clone, Debug)]
pub enum Space {
    /// The kernel's own page tables (`dbg.memory`); user addresses are not
    /// mapped there.
    Kernel,
    /// One process's page tables (`proc.memory`): its user half plus the
    /// kernel.
    Process(ProcessInfo),
    /// Guest-physical memory (`dbg.physical`), untranslated.
    Physical,
    /// A VTL1 root (`dbg.secure_kernel.memory`, `trustlet.memory`): the
    /// secure kernel's system space or a trustlet's. It maps the secure
    /// kernel and never NT's. Read-only.
    Secure(Dtb),
}

impl Space {
    /// Refuse a write: VTL1 is inspection-only, as in the REPL.
    pub fn require_writable(&self) -> PyResult<()> {
        if matches!(self, Space::Secure(_)) {
            Err(raise("VTL1 memory is read-only"))
        } else {
            Ok(())
        }
    }

    /// Refuse an operation that reads NT's own state (memory manager, pager)
    /// about an address: VTL1 memory is not NT's to describe.
    pub fn require_nt(&self, operation: &str) -> PyResult<()> {
        if matches!(self, Space::Secure(_)) {
            Err(raise(format!("{operation} is not available in VTL1")))
        } else {
            Ok(())
        }
    }

    pub fn require_virtual(&self) -> PyResult<()> {
        if matches!(self, Space::Physical) {
            Err(raise("not available on physical memory"))
        } else {
            Ok(())
        }
    }

    /// The context a virtual-address operation in this space runs in.
    /// `Physical` has no virtual context and maps to the kernel's.
    pub fn context(&self) -> Context {
        match self {
            Space::Process(info) => Context::process(info.clone()),
            Space::Secure(root) => Context::secure(*root),
            Space::Kernel | Space::Physical => Context::default(),
        }
    }

    /// This space's page-table root; physical memory has none.
    pub fn dtb(&self, target: &Target) -> PyResult<Dtb> {
        self.require_virtual()?;
        match self {
            Space::Kernel => Ok(target.kernel_dtb()),
            Space::Process(info) => Ok(info.dtb),
            Space::Secure(root) => Ok(*root),
            Space::Physical => unreachable!(),
        }
    }
}

/// Everything an SDK operation can be scoped to. Empty is the kernel address
/// space on the backend's current vCPU.
#[derive(Clone, Debug, Default)]
pub struct Context {
    /// Address space; `None` (with no `secure` root) is the kernel.
    pub process: Option<ProcessInfo>,
    /// A VTL1 root to inspect instead of an NT address space.
    pub secure: Option<Dtb>,
    /// Backend vCPU (registers, stepping); `None` keeps the backend's current.
    pub vcpu: Option<String>,
    /// Windows thread to inspect: one running on a vCPU switches to it, any
    /// other is parked (stack only, no live register file).
    pub thread: Option<ThreadInfo>,
    /// Frame of that thread whose recovered registers shadow the live ones.
    pub frame: Option<usize>,
}

impl Context {
    /// `info`'s address space on the current vCPU.
    pub fn process(info: ProcessInfo) -> Context {
        Context {
            process: Some(info),
            ..Context::default()
        }
    }

    /// The VTL1 address space rooted at `root`.
    pub fn secure(root: Dtb) -> Context {
        Context {
            secure: Some(root),
            ..Context::default()
        }
    }

    /// Backend vCPU `id`, in the kernel address space.
    pub fn vcpu(id: String) -> Context {
        Context {
            vcpu: Some(id),
            ..Context::default()
        }
    }
}

/// Run `f` with the session scoped to `ctx`, then put the user's selection
/// back, even when `f` fails.
pub fn in_context<R>(
    session: &mut Session,
    ctx: &Context,
    f: impl FnOnce(&mut Session) -> PyResult<R>,
) -> PyResult<R> {
    let mut saved = session.take_selection();
    // Same vCPU, no thread/frame: lend the operation the live register file
    // rather than reading the registers again for every scoped call.
    // A VTL1 scope gets none: the live file is VTL0 state.
    let same_vcpu =
        ctx.vcpu.is_none() && ctx.thread.is_none() && ctx.frame.is_none() && ctx.secure.is_none();
    if same_vcpu {
        session.target.registers = saved.take_live_registers();
    }
    let result = apply(session, ctx).and_then(|()| f(session));
    if same_vcpu {
        saved.put_live_registers(session.target.registers.take());
    }
    let restored = session.restore_selection(saved).map_err(err);
    let value = result?;
    restored?;
    Ok(value)
}

/// Install `ctx` on a session whose selection was just taken. Order matters:
/// a process scope detaches (clearing frame and thread), so it goes first.
fn apply(session: &mut Session, ctx: &Context) -> PyResult<()> {
    if let Some(process) = &ctx.process {
        session.target.enter_process_scope(process.clone());
    }
    if let Some(root) = ctx.secure {
        session.target.enter_secure_scope(root);
    }
    if let Some(vcpu) = &ctx.vcpu {
        session.set_current_thread(vcpu).map_err(err)?;
    }
    if let Some(thread) = &ctx.thread {
        session.select_windows_thread(thread).map_err(err)?;
    }
    if let Some(index) = ctx.frame {
        session.select_frame_index(index).map_err(err)?;
    }
    Ok(())
}
