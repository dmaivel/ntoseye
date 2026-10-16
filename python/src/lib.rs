//! The wheel's extension module: `PyInit__ntoseye` for the SDK's module,
//! which lives in core (`ntoseye::python::_ntoseye`) so the REPL embeds the
//! same one.

/// The allocator the `ntoseye` binary uses, for the debugger's own memory;
/// Python's objects keep Python's allocator.
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

pub use ntoseye_core::python::_ntoseye;
