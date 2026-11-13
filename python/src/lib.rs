//! The wheel's extension module: `PyInit__ntoseye` for the SDK's module,
//! which lives in core (`ntoseye::hosts::python::_ntoseye`) so the REPL embeds the
//! same one.

// On MSVC, link.exe prints "Creating library ..." for this cdylib; rustc
// reports that as `linker_messages`, and the line says nothing about the
// build.
#![allow(linker_messages)]

/// The allocator the `ntoseye` binary uses, for the debugger's own memory;
/// Python's objects keep Python's allocator.
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

pub use ntoseye_core::hosts::python::_ntoseye;
